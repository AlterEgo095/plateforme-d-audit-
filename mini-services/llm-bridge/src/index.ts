/**
 * AuditForge — Pont LLM OpenAI-compatible (Z.ai)
 * ================================================
 * Expose un endpoint /v1/chat/completions conforme à l'API OpenAI, adossé au
 * SDK z-ai-web-dev-sdk (backend uniquement). Destiné aux outils d'audit réels
 * (Phantom via LiteLLM, Basalt via son provider `openai_compat`) qui parlent
 * le protocole OpenAI.
 *
 * Endpoints :
 *   GET  /v1/models            → liste des modèles exposés
 *   POST /v1/chat/completions  → complétion (stream SSE émulé si stream:true)
 *   GET  /health               → {ok:true}
 *
 * Auth : si LLM_BRIDGE_KEY est défini, l'en-tête `Authorization: Bearer <key>`
 * est exigé. Sinon, endpoint ouvert (réseau interne uniquement).
 *
 * Port : 3031 (codé en dur, conventions du projet AuditForge).
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

const PORT = 3031;
const BRIDGE_KEY = process.env.LLM_BRIDGE_KEY ?? "";
const DEFAULT_MODEL = process.env.LLM_BRIDGE_MODEL ?? "glm-4.6";
const EXPOSED_MODELS = (process.env.LLM_BRIDGE_MODELS ?? "glm-4.6,glm-4.5-air,glm-4.5-flash")
  .split(",")
  .map((m) => m.trim())
  .filter(Boolean);

// ── SDK Z.ai (instance unique, réutilisée entre les requêtes) ────────────────
type ZAIClient = {
  chat: { completions: { create: (body: Record<string, unknown>) => Promise<any> } };
};
let zaiPromise: Promise<ZAIClient> | null = null;

async function getZai(): Promise<ZAIClient> {
  if (!zaiPromise) {
    zaiPromise = import("z-ai-web-dev-sdk").then((mod) => {
      const ZAI = (mod as any).default ?? mod;
      return ZAI.create() as Promise<ZAIClient>;
    });
  }
  return zaiPromise;
}

// ── Utilitaires HTTP ─────────────────────────────────────────────────────────
function json(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

function readBody(req: IncomingMessage, maxBytes = 8 * 1024 * 1024): Promise<string> {
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
  return header === `Bearer ${BRIDGE_KEY}`;
}

// ── Mapping OpenAI → SDK → OpenAI ────────────────────────────────────────────
interface OpenAIMessage {
  role: "system" | "user" | "assistant";
  content: unknown;
}

/** Convertit un contenu OpenAI (string ou tableau de parties) en string. */
function flattenContent(content: unknown): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .map((part) => {
        if (typeof part === "string") return part;
        if (part && typeof part === "object" && "text" in part) {
          return String((part as { text?: unknown }).text ?? "");
        }
        return "";
      })
      .join("\n");
  }
  if (content == null) return "";
  return String(content);
}

function toSdkMessages(messages: unknown): Array<{ role: string; content: string }> {
  if (!Array.isArray(messages)) return [];
  return (messages as OpenAIMessage[])
    .filter((m) => m && typeof m.role === "string")
    .slice(0, 256) // garde-fou
    .map((m) => ({ role: m.role, content: flattenContent(m.content) }));
}

function completionId(): string {
  return `chatcmpl-bridge-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

function buildNonStreamResponse(model: string, content: string, usage: unknown): Record<string, unknown> {
  return {
    id: completionId(),
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [
      {
        index: 0,
        message: { role: "assistant", content },
        finish_reason: "stop",
      },
    ],
    usage:
      usage && typeof usage === "object"
        ? usage
        : {
            prompt_tokens: 0,
            completion_tokens: 0,
            total_tokens: 0,
          },
  };
}

/** Écrit un flux SSE OpenAI valide en émulant les deltas à partir du contenu final. */
function writeEmulatedStream(res: ServerResponse, model: string, content: string): void {
  res.writeHead(200, {
    "Content-Type": "text/event-stream; charset=utf-8",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  });
  const id = completionId();
  const created = Math.floor(Date.now() / 1000);
  const send = (obj: unknown): void => {
    res.write(`data: ${JSON.stringify(obj)}\n\n`);
  };
  send({
    id,
    object: "chat.completion.chunk",
    created,
    model,
    choices: [{ index: 0, delta: { role: "assistant", content: "" }, finish_reason: null }],
  });
  // Découpage par tranches (~200 caractères) pour un rendu fluide côté client.
  const CHUNK = 200;
  for (let i = 0; i < content.length; i += CHUNK) {
    send({
      id,
      object: "chat.completion.chunk",
      created,
      model,
      choices: [
        { index: 0, delta: { content: content.slice(i, i + CHUNK) }, finish_reason: null },
      ],
    });
  }
  send({
    id,
    object: "chat.completion.chunk",
    created,
    model,
    choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
  });
  res.write("data: [DONE]\n\n");
  res.end();
}

// ── Routes ───────────────────────────────────────────────────────────────────
async function handleChatCompletions(req: IncomingMessage, res: ServerResponse): Promise<void> {
  let body: Record<string, unknown>;
  try {
    body = JSON.parse(await readBody(req));
  } catch {
    json(res, 400, {
      error: { message: "Corps de requête JSON invalide", type: "invalid_request_error" },
    });
    return;
  }

  const messages = toSdkMessages(body.messages);
  if (messages.length === 0) {
    json(res, 400, {
      error: { message: "`messages` est requis (tableau non vide)", type: "invalid_request_error" },
    });
    return;
  }

  const requestedModel = typeof body.model === "string" && body.model.trim() ? body.model.trim() : DEFAULT_MODEL;
  // Modèle SDK : on transmet la demande telle quelle ; le SDK/la plateforme
  // résout le modèle réel (glm-4.6 par défaut si inconnu).
  const sdkModel = /^(glm|zhipu)/i.test(requestedModel) ? requestedModel : undefined;
  const wantsStream = body.stream === true;

  const payload: Record<string, unknown> = {
    messages,
    thinking: { type: "disabled" },
  };
  if (sdkModel) payload.model = sdkModel;
  if (typeof body.temperature === "number") payload.temperature = body.temperature;
  if (typeof body.max_tokens === "number") payload.max_tokens = body.max_tokens;

  try {
    const zai = await getZai();
    const completion = (await zai.chat.completions.create(payload)) as any;
    const content: string =
      completion?.choices?.[0]?.message?.content ?? completion?.content ?? "";
    if (wantsStream) {
      writeEmulatedStream(res, requestedModel, content);
    } else {
      json(res, 200, buildNonStreamResponse(requestedModel, content, completion?.usage));
    }
  } catch (err) {
    console.error("[llm-bridge] erreur complétion:", err);
    json(res, 502, {
      error: {
        message: "Échec de la complétion en amont (Z.ai)",
        type: "upstream_error",
      },
    });
  }
}

async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = (req.url ?? "/").split("?")[0];

  if (req.method === "GET" && (url === "/health" || url === "/")) {
    json(res, 200, { ok: true, service: "auditforge-llm-bridge", models: EXPOSED_MODELS });
    return;
  }

  if (req.method === "GET" && (url === "/v1/models" || url === "/models")) {
    json(res, 200, {
      object: "list",
      data: EXPOSED_MODELS.map((m) => ({
        id: m,
        object: "model",
        created: 0,
        owned_by: "auditforge-bridge",
      })),
    });
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

// ── Serveur (bouclage uniquement, comme le moteur — jamais publié sur l'hôte) ─
const server = createServer((req, res) => {
  route(req, res).catch((err) => {
    console.error("[llm-bridge] erreur route:", err);
    if (!res.headersSent) json(res, 500, { error: { message: "Erreur interne", type: "internal_error" } });
  });
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`[llm-bridge] écoute sur 127.0.0.1:${PORT} (modèle par défaut: ${DEFAULT_MODEL})`);
  if (!BRIDGE_KEY) {
    console.warn("[llm-bridge] LLM_BRIDGE_KEY absent — endpoint sans authentification (réseau interne uniquement)");
  }
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
