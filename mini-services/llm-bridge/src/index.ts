/**
 * AuditForge — Pont LLM OpenAI-compatible v2 (proxy multi-modèles rotatif)
 * =========================================================================
 * Expose /v1/chat/completions (protocole OpenAI) et répartit les requêtes,
 * à tours de rôle (round-robin), sur TOUS les modèles réellement disponibles
 * de ses upstreams — plus aucun quota de modèle ne s'épuise isolément.
 *
 * Principe : le pont est un PROXY TRANSPARENT. Le corps de la requête
 * (messages, tools, temperature, stream…) est transmis tel quel à l'upstream
 * choisi, seul le champ `model` est réécrit. Les réponses sont relayées en
 * flux (SSE réel quand stream:true) ou en JSON. En cas d'échec d'un modèle
 * (quota, rate-limit, 5xx, timeout), il passe en cooldown exponentiel et la
 * requête est rejouée immédiatement sur le modèle suivant du pool.
 *
 * Endpoints :
 *   GET  /health                → {ok, pool:{healthy,total}} (sans auth)
 *   GET  /v1/models             → modèles du pool (+ alias auditforge-auto)
 *   POST /v1/chat/completions   → complétion avec rotation + failover
 *   GET  /v1/pool               → état détaillé du pool (ops)
 *   POST /v1/pool/refresh       → force une re-découverte
 *
 * Auth : si LLM_BRIDGE_KEY est défini, `Authorization: Bearer <key>` est
 * exigé (comparaison à temps constant). Sinon endpoint ouvert (réseau
 * interne uniquement).
 *
 * Configuration :
 *   AF_UPSTREAMS      nom|base|clé|role;nom2|base2|clé2|role2  (role: primary|fallback)
 *   AF_STATIC_MODELS  liste de secours (virgules) ajoutée comme « unverified »
 *   AF_REFRESH_MS     période de re-découverte (défaut 15 min)
 *   AF_ATTEMPTS       tentatives max par requête (défaut 5)
 *   LLM_BRIDGE_KEY    clé Bearer exigée des clients (défaut : ouverte)
 *
 * Port : 3031 (convention AuditForge). Bind : BIND_HOST (0.0.0.0 en Docker).
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { timingSafeEqual } from "node:crypto";
import {
  ModelPool,
  classifyFailure,
  normalizePreferred,
  parseUpstreams,
  type PickResult,
} from "./pool";

// ── Configuration ────────────────────────────────────────────────────────────

const PORT = 3031;
const BIND_HOST = process.env.BIND_HOST ?? "127.0.0.1";
const BRIDGE_KEY = process.env.LLM_BRIDGE_KEY ?? "";
const REFRESH_MS = clampInt(process.env.AF_REFRESH_MS, 60_000, 6 * 3_600_000, 900_000);
const ATTEMPTS = clampInt(process.env.AF_ATTEMPTS, 1, 10, 5);
const PROBE_TIMEOUT_MS = clampInt(process.env.AF_PROBE_TIMEOUT_MS, 5_000, 120_000, 30_000);
/** Délai avant premiers octets de l'upstream (grands prompts → raisonnement long). */
const TTFB_TIMEOUT_MS = clampInt(process.env.AF_TTFB_TIMEOUT_MS, 10_000, 900_000, 180_000);
/** Silence maximal en flux (reset à chaque chunk). */
const IDLE_TIMEOUT_MS = clampInt(process.env.AF_IDLE_TIMEOUT_MS, 10_000, 3_600_000, 600_000);
/**
 * Tempête de cooldown : attente avant une 2e (et dernière) balayage du pool.
 * 0 désactive. Les cooldowns de base (90 s) expirant vite, une attente unique
 * de 45 s sauve un appel d'agent qui mourrait sinon d'un pool momentanément
 * à sec (403 quota transitoires en rafale sur les upstreams gratuits).
 */
const POOL_WAIT_MS = clampInt(process.env.AF_POOL_WAIT_MS, 0, 300_000, 45_000);

/** Spécialisés (OCR/vision-lone/traduction) exclus de la rotation agentique. */
const DISCOVERY_EXCLUDE =
  /realtime|audio|asr|tts|s2s|livetranslate|tingwu|image|z-image|wan\d|embedding|omni|mock|(^|[-/.])(vl|ocr)([-.]|$)|(^|[-.])mt[-.]|character/i;

const UPSTREAMS = parseUpstreams(process.env.AF_UPSTREAMS ?? "");
const STATIC_MODELS = (process.env.AF_STATIC_MODELS ?? "")
  .split(",")
  .map((m) => m.trim())
  .filter(Boolean);

if (UPSTREAMS.length === 0) {
  console.error(
    "[llm-bridge] AUCUN upstream configuré — renseignez AF_UPSTREAMS (nom|base|clé|role;…)",
  );
}

const pool = new ModelPool(UPSTREAMS, {
  probeTimeoutMs: PROBE_TIMEOUT_MS,
  excludeRe: DISCOVERY_EXCLUDE,
  logger: (m) => console.log(`[llm-bridge] ${m}`),
});

// Liste statique de secours : disponible IMMÉDIATEMENT au boot (avant la fin
// de la découverte), en « unverified » — un premier échec la mettra en
// cooldown, la découverte confirmera/écartera ensuite.
const firstPrimary = UPSTREAMS.find((u) => u.role === "primary") ?? UPSTREAMS[0];
if (firstPrimary) for (const m of STATIC_MODELS) pool.ensureEntry(firstPrimary.name, m);

// ── Utilitaires HTTP ─────────────────────────────────────────────────────────

function clampInt(v: string | undefined, min: number, max: number, def: number): number {
  const n = Number.parseInt(v ?? "", 10);
  if (!Number.isFinite(n)) return def;
  return Math.min(max, Math.max(min, n));
}

function json(res: ServerResponse, status: number, body: unknown, extraHeaders?: Record<string, string>): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
    ...extraHeaders,
  });
  res.end(payload);
}

function readBody(req: IncomingMessage, maxBytes = 32 * 1024 * 1024): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > maxBytes) {
        reject(new Error("payload too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function authorized(req: IncomingMessage): boolean {
  if (!BRIDGE_KEY) return true;
  const header = req.headers.authorization ?? "";
  const expected = `Bearer ${BRIDGE_KEY}`;
  const a = Buffer.from(header);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

function completionId(): string {
  return `chatcmpl-bridge-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

// ── Tentative upstream (proxy transparent) ───────────────────────────────────

type AttemptResult =
  | { ok: true; status: number; json: Record<string, unknown>; latencyMs: number }
  | { ok: false; status: number; errText: string; retriable: boolean; streamBroken?: boolean };

async function attemptUpstream(
  c: PickResult,
  parsed: Record<string, unknown>,
  wantsStream: boolean,
  clientRes: ServerResponse,
  clientReq: IncomingMessage,
): Promise<AttemptResult> {
  const ctrl = new AbortController();
  let ttfb: NodeJS.Timeout | null = setTimeout(
    () => ctrl.abort(new DOMException("ttfb timeout", "TimeoutError")),
    TTFB_TIMEOUT_MS,
  );
  let idle: NodeJS.Timeout | null = null;
  const clearTimers = (): void => {
    if (ttfb) {
      clearTimeout(ttfb);
      ttfb = null;
    }
    if (idle) {
      clearTimeout(idle);
      idle = null;
    }
  };
  const armIdle = (): void => {
    if (idle) clearTimeout(idle);
    idle = setTimeout(() => ctrl.abort(new DOMException("idle timeout", "TimeoutError")), IDLE_TIMEOUT_MS);
  };
  // Le client déconnecté → on coupe l'upstream immédiatement.
  const onClientClose = (): void => ctrl.abort(new DOMException("client gone", "AbortError"));
  clientRes.on("close", onClientClose);

  const body = JSON.stringify({ ...parsed, model: c.model });
  const t0 = Date.now();
  try {
    const res = await fetch(`${c.upstream.base}/chat/completions`, {
      method: "POST",
      headers: { Authorization: `Bearer ${c.upstream.key}`, "Content-Type": "application/json" },
      body,
      signal: ctrl.signal,
    });

    if (!res.ok) {
      clearTimers();
      const errText = (await res.text().catch(() => "")).slice(0, 8192);
      const cls = classifyFailure(res.status);
      if (cls.cooldown) pool.markFailure(c, res.status, errText.slice(0, 160));
      else pool.markSoftFail(c, errText.slice(0, 160));
      // Journal corps d'erreur upstream : sans lui, un 400/403 amont est
      // indistinguible d'un autre (« dernière erreur HTTP 400 » ne dit pas
      // POURQUOI). 300 c. suffisent pour diagnostiquer (quota, contexte,
      // champ refusé…) sans polluer les logs.
      console.warn(
        `[llm-bridge] échec amont ${c.upstream.name}/${c.model} HTTP ${res.status} — ${errText.replace(/\s+/g, " ").slice(0, 300)}`,
      );
      return { ok: false, status: res.status, errText, retriable: cls.retry };
    }

    // ── Succès ──
    if (!wantsStream) {
      const payload = (await res.json()) as Record<string, unknown>;
      clearTimers();
      const latency = Date.now() - t0;
      pool.markSuccess(c, latency);
      payload.model = c.model; // vérité : le modèle qui a réellement servi
      return { ok: true, status: 200, json: payload, latencyMs: latency };
    }

    // Flux SSE : relais transparent. En-têtes reçus → premier octet imminent.
    clearTimers();
    clientRes.writeHead(200, {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
      "X-Af-Served-By": c.model,
    });
    armIdle();
    if (res.body) {
      for await (const chunk of res.body as unknown as AsyncIterable<Uint8Array>) {
        if (!clientRes.write(chunk)) {
          // backpressure : attendre le drain sans geler la lecture amont
          await new Promise<void>((r) => clientRes.once("drain", r));
        }
        armIdle();
      }
    }
    clearTimers();
    clientRes.end();
    pool.markSuccess(c, Date.now() - t0);
    return { ok: true, status: 200, json: {}, latencyMs: Date.now() - t0 };
  } catch (err) {
    clearTimers();
    const msg = err instanceof Error ? `${err.name}: ${err.message}` : "erreur réseau";
    const headersSent = clientRes.headersSent;
    if (!headersSent) {
      pool.markFailure(c, 0, msg);
      return { ok: false, status: 0, errText: msg, retriable: true };
    }
    // Le flux a cassé en pleine réponse : impossible de failover après
    // émission des en-têtes — clôturer proprement (le client SSE verra EOF).
    pool.markFailure(c, 0, `flux interrompu: ${msg}`);
    try {
      clientRes.end();
    } catch {
      /* déjà fermée */
    }
    return { ok: false, status: 0, errText: msg, retriable: false, streamBroken: true };
  } finally {
    clientRes.off("close", onClientClose);
  }
}

// ── Route : chat completions (rotation + failover) ───────────────────────────

async function handleChatCompletions(req: IncomingMessage, res: ServerResponse): Promise<void> {
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(await readBody(req)) as Record<string, unknown>;
  } catch {
    json(res, 400, { error: { message: "Corps de requête JSON invalide", type: "invalid_request_error" } });
    return;
  }
  if (!Array.isArray(parsed.messages) || parsed.messages.length === 0) {
    json(res, 400, { error: { message: "`messages` est requis (tableau non vide)", type: "invalid_request_error" } });
    return;
  }

  const wantsStream = parsed.stream === true;
  const preferred = normalizePreferred(parsed.model);

  if (pool.candidatesFor(preferred).length === 0) {
    json(res, 503, {
      error: {
        message: "Aucun modèle disponible dans le pool (découverte en cours ou tous en cooldown) — réessayez",
        type: "pool_exhausted",
        retry_after_s: 30,
      },
    });
    return;
  }

  // 1 à 2 balayages du pool ; le 2e, après POOL_WAIT_MS, laisse expirer les
  // cooldowns courts — c'est ce qui sauve les agents pendant les tempêtes
  // de 403 transitoires des upstreams gratuits.
  // NOTE : un 400 amont n'interrompt PLUS le 2e balayage. Un 400 d'UN
  // candidat (quota masqué, modèle capricieux, champ refusé par un seul
  // fournisseur) ne préjuge pas des autres — et tuer l'agent litellm avec
  // un BadRequestError (non retryable) est bien pire que 45 s d'attente.
  const rounds = POOL_WAIT_MS > 0 ? 2 : 1;
  let last: AttemptResult | null = null;
  let attemptsTotal = 0;
  for (let round = 0; round < rounds; round++) {
    if (round > 0) {
      console.warn(`[llm-bridge] pool à sec — nouvelle tentative après ${Math.round(POOL_WAIT_MS / 1000)}s de délai`);
      await new Promise((r) => setTimeout(r, POOL_WAIT_MS));
    }
    const candidates = pool.candidatesFor(preferred).slice(0, ATTEMPTS);
    for (const c of candidates) {
      attemptsTotal += 1;
      const r = await attemptUpstream(c, parsed, wantsStream, res, req);
      if (r.ok) {
        if (wantsStream) return; // flux déjà relayé tel quel
        console.log(
          `[llm-bridge] 200 model=${String(parsed.model ?? "auto")} → ${c.upstream.name}/${c.model} ${r.latencyMs}ms`,
        );
        json(res, 200, r.json, { "X-Af-Served-By": c.model });
        return;
      }
      last = r;
      if (r.streamBroken) return; // réponse partielle déjà envoyée
      if (!r.retriable) break;
    }
    if (last && !last.retriable) break;
  }

  console.error(
    `[llm-bridge] échec après ${attemptsTotal} tentative(s) — dernière erreur HTTP ${last?.status ?? "?"}`,
  );
  // Épuisement du pool → TOUJOURS 429 (retryable) avec Retry-After, y compris
  // quand la dernière erreur amont est un 400 : relayer ce 400 tuerait
  // l'agent litellm (BadRequestError non retryable) au lieu de le faire
  // patienter jusqu'à l'expiration des cooldowns. Le corps amont reste
  // disponible pour l'ops via `detail` et les logs « échec amont ».
  const retryAfterS = 60;
  json(res, 429, {
    error: {
      message: `Tous les modèles du pool ont échoué — pool en cooldown, réessayez dans ${retryAfterS}s`,
      type: "pool_exhausted",
      detail: last?.errText?.replace(/\s+/g, " ").slice(0, 600) ?? null,
      retry_after_s: retryAfterS,
    },
  }, { "Retry-After": String(retryAfterS) });
}

// ── Routes annexes ───────────────────────────────────────────────────────────

function handleModels(res: ServerResponse): void {
  const data: Array<Record<string, unknown>> = [
    {
      id: "auditforge-auto",
      object: "model",
      created: 0,
      owned_by: "auditforge-rotation",
    },
  ];
  const seen = new Set<string>(["auditforge-auto"]);
  for (const e of pool.snapshot().entries) {
    if (e.state === "dead" || seen.has(e.model)) continue;
    seen.add(e.model);
    data.push({
      id: e.model,
      object: "model",
      created: 0,
      owned_by: `auditforge-pool:${e.upstream}`,
    });
  }
  json(res, 200, { object: "list", data });
}

async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = (req.url ?? "/").split("?")[0];

  if (req.method === "GET" && (url === "/health" || url === "/")) {
    const snap = pool.snapshot();
    json(res, 200, {
      ok: true,
      service: "auditforge-llm-bridge",
      pool: { healthy: pool.healthyCount(), total: snap.entries.length },
      upstreams: snap.upstreams.map((u) => ({ name: u.name, role: u.role, healthy: u.healthy })),
    });
    return;
  }

  if (req.method === "GET" && (url === "/v1/models" || url === "/models")) {
    handleModels(res);
    return;
  }

  if (req.method === "GET" && (url === "/v1/pool" || url === "/pool")) {
    if (!authorized(req)) {
      json(res, 401, { error: { message: "Non autorisé", type: "auth_error" } });
      return;
    }
    json(res, 200, pool.snapshot());
    return;
  }

  if (req.method === "POST" && (url === "/v1/pool/refresh" || url === "/pool/refresh")) {
    if (!authorized(req)) {
      json(res, 401, { error: { message: "Non autorisé", type: "auth_error" } });
      return;
    }
    void pool.refresh().catch(() => undefined);
    json(res, 202, { started: true });
    return;
  }

  if (req.method === "POST" && (url === "/v1/chat/completions" || url === "/chat/completions")) {
    if (!authorized(req)) {
      json(res, 401, { error: { message: "Non autorisé", type: "auth_error" } });
      return;
    }
    await handleChatCompletions(req, res);
    return;
  }

  json(res, 404, { error: { message: "Route inconnue", type: "invalid_request_error" } });
}

// ── Serveur ──────────────────────────────────────────────────────────────────

const server = createServer((req, res) => {
  route(req, res).catch((err) => {
    console.error("[llm-bridge] erreur route:", err);
    if (!res.headersSent) json(res, 500, { error: { message: "Erreur interne", type: "internal_error" } });
  });
});
// Keep-alive des clients LiteLLM/agents : éviter les resets précoces.
server.keepAliveTimeout = 75_000;
server.headersTimeout = 240_000;
server.requestTimeout = 0; // les complétions d'agent peuvent durer des minutes

server.listen(PORT, BIND_HOST, () => {
  console.log(`[llm-bridge] v2 écoute sur ${BIND_HOST}:${PORT}`);
  console.log(`[llm-bridge] upstreams : ${UPSTREAMS.map((u) => `${u.name}(${u.role})`).join(", ") || "AUCUN"}`);
  if (!BRIDGE_KEY) {
    console.warn("[llm-bridge] LLM_BRIDGE_KEY absent — endpoint sans authentification (réseau interne uniquement)");
  }
  // Découverte initiale en arrière-plan ; AF_STATIC_MODELS couvre les
  // premières secondes (entrées « unverified » optimistes).
  void pool
    .discover()
    .catch((err) => console.error("[llm-bridge] découverte initiale échouée:", err));
  setInterval(() => {
    void pool.refresh().catch(() => undefined);
  }, REFRESH_MS).unref();
});

// ── Arrêt gracieux ───────────────────────────────────────────────────────────
let shuttingDown = false;
const shutdown = (signal: string): void => {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`[llm-bridge] arrêt gracieux (${signal})`);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref();
};
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
