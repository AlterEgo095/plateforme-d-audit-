/**
 * AuditForge — CLIENT du tunnel LLM (côté sandbox).
 * =====================================================================
 * Mission : offrir les ressources IA du sandbox (SDK Z.ai) au VPS
 * AuditForge via un tunnel WebSocket SORTANT (aucun port ouvert ici).
 *
 * Protocole (JSON sur WS) :
 *   serveur → client : {id, path: "/v1/chat/completions", body:{messages…}}
 *   client  → serveur : {id, status, body}  (réponse OpenAI-compatible)
 *   heartbeat : {type:"ping"} / {type:"pong"} toutes les 30 s
 *     (Cloudflare coupe les WS inactifs ~100 s — le ping maintient le flux)
 *
 * Le client n'ouvre AUCUN port : surface d'attaque nulle côté sandbox.
 * Il n'exécute que DEUX routes fixes — aucun code distant reçu par WS
 * n'est évalué. Les contenus de requête ne sont JAMAIS journalisés
 * (métriques uniquement).
 *
 * Configuration (.env) :
 *   TUNNEL_URL        wss://auditforge.aenews.online/llm-tunnel-ws
 *   TUNNEL_TOKEN      jeton partagé (comparé côté serveur)
 *   AF_TUNNEL_CLIENT_RATE   requêtes max / 60 s (défaut 30)
 *   AF_TUNNEL_MAX_MESSAGES  fenêtre de messages envoyée au SDK (défaut 60)
 */

import ZAI from "z-ai-web-dev-sdk";

const TUNNEL_URL = process.env.TUNNEL_URL ?? "wss://auditforge.aenews.online/llm-tunnel-ws";
const TUNNEL_TOKEN = process.env.TUNNEL_TOKEN ?? "";
const RATE_PER_MIN = Number(process.env.AF_TUNNEL_CLIENT_RATE ?? 30);
const MAX_MESSAGES = Number(process.env.AF_TUNNEL_MAX_MESSAGES ?? 60);
const MAX_BODY_BYTES = 4 * 1024 * 1024;
/**
 * Anti-burst : la plateforme Z.ai rate-limite le SDK (429 « Too many
 * requests ») dès que l'agent enchaîne les appels en rafale. Toute requête
 * passe donc par une file SÉQUENTIELLE avec espacement minimum, et les 429
 * sont rejoués en backoff (voir RETRY_DELAYS) — transparent pour l'agent.
 */
const MIN_INTERVAL_MS = Number(process.env.AF_TUNNEL_MIN_INTERVAL_MS ?? 10_000);
const RETRY_DELAYS = [20_000, 40_000, 80_000];

if (!TUNNEL_TOKEN) {
  console.error("[tunnel-client] TUNNEL_TOKEN manquant — refuse de démarrer (jeton public interdit)");
  process.exit(1);
}

type ChatMessage = { role: string; content: unknown };
type TunnelRequest = { id?: string; path?: string; body?: Record<string, unknown> };
type TunnelResponse = { status: number; body: unknown };

// ── SDK Z.ai (instance réutilisée — recommandation du skill) ────────────────
let zai: Awaited<ReturnType<typeof ZAI.create>> | null = null;
async function getZai() {
  if (!zai) zai = await ZAI.create();
  return zai;
}

// ── File séquentielle + espacement minimum entre appels SDK ─────────────────
let queueTail: Promise<void> = Promise.resolve();
let lastCallAt = 0;
function enqueue<T>(fn: () => Promise<T>): Promise<T> {
  const run = queueTail.then(async () => {
    const wait = Math.max(0, lastCallAt + MIN_INTERVAL_MS - Date.now());
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    lastCallAt = Date.now();
    return fn();
  });
  queueTail = run.then(
    () => undefined,
    () => undefined,
  );
  return run;
}

// ── Rate limit local (fenêtre glissante 60 s, compteur simple) ──────────────
const rateStamps: number[] = [];
function rateAllow(): boolean {
  const now = Date.now();
  while (rateStamps.length && now - rateStamps[0] > 60_000) rateStamps.shift();
  if (rateStamps.length >= RATE_PER_MIN) return false;
  rateStamps.push(now);
  return true;
}

// ── Conversion OpenAI → SDK Z.ai ─────────────────────────────────────────────
// Le SDK documente « assistant » comme rôle des prompts système.
function toSdkMessages(msgs: ChatMessage[]): Array<{ role: "user" | "assistant"; content: string }> {
  return msgs
    .slice(-MAX_MESSAGES)
    .map((m) => {
      const content = typeof m.content === "string" ? m.content : JSON.stringify(m.content ?? "");
      const role = m.role === "assistant" ? "assistant" : "user";
      return { role, content };
    });
}

const approxTokens = (s: string): number => Math.ceil(s.length / 4);

async function handleChat(body: Record<string, unknown>): Promise<TunnelResponse> {
  const msgs = Array.isArray(body.messages) ? (body.messages as ChatMessage[]) : null;
  if (!msgs || msgs.length === 0) {
    return { status: 400, body: { error: { message: "« messages » requis", type: "invalid_request_error" } } };
  }
  const thinkingType =
    (body.thinking as { type?: string } | undefined)?.type === "enabled" ? "enabled" : "disabled";
  const sdkMessages = toSdkMessages(msgs);
  const promptChars = sdkMessages.reduce((a, m) => a + m.content.length, 0);
  const t0 = Date.now();

  // Appel SDK via la file séquentielle + retry backoff sur 429 (rate limit
  // plateforme Z.ai) — l'agent ne voit jamais l'échec transitoire.
  const z = await getZai();
  let completion: Awaited<ReturnType<typeof z.chat.completions.create>> | null = null;
  for (let attempt = 0; ; attempt++) {
    try {
      completion = await enqueue(() =>
        z.chat.completions.create({
          messages: sdkMessages,
          thinking: { type: thinkingType } as { type: "enabled" | "disabled" },
        }),
      );
      break;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (attempt < RETRY_DELAYS.length && /429|too many requests/i.test(msg)) {
        console.warn(
          `[tunnel-client] 429 SDK — retry dans ${RETRY_DELAYS[attempt] / 1000} s (essai ${attempt + 1}/${RETRY_DELAYS.length + 1})`,
        );
        await new Promise((r) => setTimeout(r, RETRY_DELAYS[attempt]));
        continue;
      }
      throw err;
    }
  }

  const content = completion?.choices?.[0]?.message?.content ?? "";
  const out = {
    id: `chatcmpl-tunnel-${crypto.randomUUID()}`,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: String(body.model ?? "glm-4.6"),
    choices: [
      {
        index: 0,
        message: { role: "assistant", content },
        finish_reason: "stop",
      },
    ],
    usage: {
      prompt_tokens: approxTokens("x".repeat(promptChars)),
      completion_tokens: approxTokens(content),
      total_tokens: approxTokens("x".repeat(promptChars + content.length)),
    },
  };
  console.log(
    `[tunnel-client] chat OK — ${approxTokens(content)} tok sortis, ${Date.now() - t0} ms, thinking=${thinkingType}`,
  );
  return { status: 200, body: out };
}

async function handle(req: TunnelRequest): Promise<TunnelResponse> {
  if (req.path === "/v1/chat/completions") {
    if (!rateAllow()) {
      return {
        status: 429,
        body: { error: { message: `tunnel saturé (${RATE_PER_MIN} req/min)`, type: "rate_limit" } },
      };
    }
    const bytes = JSON.stringify(req.body ?? {}).length;
    if (bytes > MAX_BODY_BYTES) {
      return { status: 413, body: { error: { message: "corps trop large pour le tunnel" } } };
    }
    try {
      return await handleChat(req.body ?? {});
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`[tunnel-client] échec SDK: ${msg.slice(0, 200)}`);
      // Format erreur OpenAI-compatible — le bridge le classe (cooldown/failover)
      return { status: 502, body: { error: { message: `SDK sandbox: ${msg.slice(0, 300)}`, type: "upstream_error" } } };
    }
  }
  return { status: 404, body: { error: { message: `route tunnel non supportée : ${String(req.path)}` } } };
}

// ── Connexion WS sortante + reconnexion exponentielle ───────────────────────
// GARDE DE GÉNÉRATION : une seule connexion vivante à la fois. Les handlers
// d'une socket obsolète (fermée par remplacement/nettoyage) ne relancent PAS
// de reconnexion — sinon chaque close déclenche un connect concurrent et les
// sockets se remplacent mutuellement en boucle (oscillation observée).
let generation = 0;
let backoffMs = 2_000;
let ws: WebSocket | null = null;
let heartbeat: ReturnType<typeof setInterval> | null = null;
let lastPong = 0;

function scheduleReconnect(): void {
  const myGen = generation;
  setTimeout(() => {
    if (myGen === generation) connect();
  }, backoffMs);
}

function connect(): void {
  generation++;
  const myGen = generation;
  // Nettoyer toute socket résiduelle SANS déclencher ses handlers.
  if (ws) {
    ws.onclose = null;
    ws.onerror = null;
    ws.onmessage = null;
    try { ws.close(); } catch { /* */ }
  }
  if (heartbeat) {
    clearInterval(heartbeat);
    heartbeat = null;
  }
  const url = TUNNEL_URL + "?token=" + encodeURIComponent(TUNNEL_TOKEN);
  console.log(`[tunnel-client] connexion vers ${TUNNEL_URL}…`);
  const sock = new WebSocket(url);
  ws = sock;

  sock.onopen = () => {
    if (myGen !== generation) return;
    backoffMs = 2_000;
    lastPong = Date.now();
    console.log("[tunnel-client] TUNNEL ÉTABLI — ressources IA du sandbox offertes au VPS");
    heartbeat = setInterval(() => {
      if (Date.now() - lastPong > 120_000) {
        console.warn("[tunnel-client] pong absent > 120 s — reconnexion");
        try { sock.close(); } catch { /* */ }
        return;
      }
      try { sock.send(JSON.stringify({ type: "ping" })); } catch { /* */ }
    }, 30_000);
  };

  sock.onmessage = (ev: MessageEvent) => {
    if (myGen !== generation) return;
    let m: TunnelRequest & { type?: string };
    try {
      m = JSON.parse(typeof ev.data === "string" ? ev.data : String(ev.data));
    } catch {
      return;
    }
    if (m.type === "pong") {
      lastPong = Date.now();
      return;
    }
    if (m.type === "hello") {
      console.log(
        "[tunnel-client] serveur prêt — modèles annoncés:",
        JSON.stringify((m as { models?: string[] }).models ?? []),
      );
      return;
    }
    if (!m.id || !m.path) return;
    // Répondre de façon asynchrone — jamais bloqué par d'autres requêtes.
    handle(m)
      .then((resp) => {
        if (myGen !== generation) return;
        try { sock.send(JSON.stringify({ id: m.id, status: resp.status, body: resp.body })); } catch { /* */ }
      })
      .catch((err) => {
        const msg = err instanceof Error ? err.message : String(err);
        if (myGen !== generation) return;
        try {
          sock.send(JSON.stringify({ id: m.id, status: 500, body: { error: { message: msg.slice(0, 300) } } }));
        } catch { /* */ }
      });
  };

  sock.onclose = (ev: CloseEvent) => {
    if (myGen !== generation) return; // socket obsolète — la plus récente règne
    console.warn(
      `[tunnel-client] WS fermée (code=${ev.code}${ev.reason ? `, raison="${ev.reason}"` : ""}) — reconnexion dans ${Math.round(backoffMs / 1000)} s`,
    );
    if (heartbeat) {
      clearInterval(heartbeat);
      heartbeat = null;
    }
    scheduleReconnect();
    backoffMs = Math.min(backoffMs * 2, 60_000);
  };

  sock.onerror = () => {
    try { sock.close(); } catch { /* */ }
  };
}

connect();
console.log(`[tunnel-client] démarré — rate=${RATE_PER_MIN}/min, max_messages=${MAX_MESSAGES}, espacement=${MIN_INTERVAL_MS} ms`);
