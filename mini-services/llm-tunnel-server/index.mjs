/**
 * AuditForge — SERVEUR du tunnel LLM (côté VPS).
 * =====================================================================
 * Reçoit la connexion WebSocket SORTANTE du client sandbox (via Caddy :
 * wss://domaine/llm-tunnel-ws → llm-tunnel:3032) et expose une API
 * OpenAI-compatible interne pour le llm-bridge :
 *
 *   GET  /healthz               état du tunnel (sans auth)
 *   GET  /v1/models             liste AF_TUNNEL_MODELS (auth Bearer)
 *   POST /v1/chat/completions   requête relayée au SDK Z.ai du sandbox
 *
 * Auth : Bearer LLM_TUNNEL_KEY pour /v1/* ; jeton TUNNEL_TOKEN pour la WS.
 * stream:true est SIMULÉ en SSE (une completion complète émise en un
 * chunk + [DONE]) — compatible litellm/OpenAI clients.
 * Aucune route ne reçoit de code à exécuter — seul un JSON de requête
 * fixe est transféré. Les contenus ne sont pas journalisés.
 *
 * Dépendance unique : ws (Node ≥ 20). Aucun port publié sur l'hôte —
 * accès interne uniquement (Caddy + conteneurs du réseau compose).
 * NOTE : fichier .mjs — JavaScript PUR, aucune syntaxe TypeScript.
 */

import http from "node:http";
import crypto from "node:crypto";
import { WebSocketServer } from "ws";

const PORT = Number(process.env.PORT ?? 3032);
const TUNNEL_TOKEN = process.env.TUNNEL_TOKEN ?? "";
const HTTP_KEY = process.env.LLM_TUNNEL_KEY ?? "";
const MODELS = (process.env.AF_TUNNEL_MODELS ?? "glm-4.6,glm-4.5-flash")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const REQ_TIMEOUT_MS = clampInt(process.env.AF_TUNNEL_REQ_TIMEOUT_MS, 30000, 600000, 240000);
const MAX_BODY_BYTES = 4 * 1024 * 1024;

function clampInt(v, min, max, def) {
  const n = Number.parseInt(v ?? "", 10);
  if (!Number.isFinite(n)) return def;
  return Math.min(max, Math.max(min, n));
}

function safeEq(a, b) {
  if (typeof a !== "string" || !a) return false;
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

const log = (m) => console.log(`[llm-tunnel] ${m}`);

// ── État tunnel ──────────────────────────────────────────────────────────────
let tunnelSocket = null;
let tunnelId = null;
let lastTunnelMessage = Date.now();
const pending = new Map();

// Watchdog anti-socket-fantôme : le client heartbeat toutes les 30 s — au-delà
// de 150 s SANS aucun message, la socket est fermée (son « close » côté client
// peut ne jamais être détecté par le serveur, ex. après un reload du process).

// ── Serveur HTTP ─────────────────────────────────────────────────────────────
const server = http.createServer((req, res) => {
  const url = new URL(req.url ?? "/", "http://localhost");

  if (url.pathname === "/healthz") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        ok: true,
        tunnelConnected: Boolean(tunnelSocket),
        pending: pending.size,
        models: MODELS,
      }),
    );
    return;
  }

  if (!url.pathname.startsWith("/v1/")) {
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: { message: "not found" } }));
    return;
  }

  // Auth Bearer (comparaison à temps constant)
  const auth = req.headers.authorization ?? "";
  const key = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!HTTP_KEY || !safeEq(key, HTTP_KEY)) {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: { message: "unauthorized", type: "auth_error" } }));
    return;
  }

  if (url.pathname === "/v1/models" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        object: "list",
        data: MODELS.map((m) => ({ id: m, object: "model", owned_by: "auditforge-sandbox-tunnel" })),
      }),
    );
    return;
  }

  if (url.pathname === "/v1/chat/completions" && req.method === "POST") {
    handleChat(req, res);
    return;
  }

  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: { message: "route non supportée" } }));
});

function readBody(req, maxBytes) {
  return new Promise((resolve) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > maxBytes) {
        resolve(null);
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", () => resolve(null));
  });
}

async function handleChat(req, res) {
  if (!tunnelSocket || tunnelSocket.readyState !== 1) {
    res.writeHead(503, { "Content-Type": "application/json", "Retry-After": "15" });
    res.end(
      JSON.stringify({
        error: {
          message: "tunnel sandbox déconnecté — le client se reconnectera automatiquement",
          type: "tunnel_down",
        },
      }),
    );
    return;
  }

  const raw = await readBody(req, MAX_BODY_BYTES);
  if (raw === null) {
    res.writeHead(413, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: { message: "corps trop large pour le tunnel" } }));
    return;
  }
  let body;
  try {
    body = JSON.parse(raw || "{}");
  } catch {
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: { message: "corps JSON invalide" } }));
    return;
  }
  if (!Array.isArray(body.messages) || body.messages.length === 0) {
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: { message: "« messages » requis" } }));
    return;
  }

  const id = crypto.randomUUID();
  const wantStream = body.stream === true;
  const t0 = Date.now();

  const replyPromise = new Promise((resolve) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      resolve({
        status: 504,
        body: { error: { message: `tunnel silencieux après ${Math.round(REQ_TIMEOUT_MS / 1000)} s` } },
      });
    }, REQ_TIMEOUT_MS);
    pending.set(id, { resolve, timer });
  });

  tunnelSocket.send(JSON.stringify({ id, path: "/v1/chat/completions", body }));
  const reply = await replyPromise;
  const latency = Date.now() - t0;

  // Le client renvoie toujours du JSON ; on reflète son status (200/4xx/5xx).
  const status = typeof reply.status === "number" ? reply.status : 502;

  if (status !== 200) {
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(reply.body ?? { error: { message: "échec tunnel" } }));
    log(`chat ÉCHEC status=${status} (${latency} ms)`);
    return;
  }

  if (wantStream) {
    // SSE au format STREAM OpenAI réel : litellm/OpenAI clients attendent des
    // chunks avec choices[0].delta — l'ancienne simulation émettait un objet
    // non-stream (choices[0].message) dans le flux → litellm parsait delta,
    // trouvait vide → content='' → l'agent croyait à un refus du modèle.
    // On découpe donc la completion complète du sandbox en chunks conformes.
    const b = (reply.body && typeof reply.body === "object") ? reply.body : {};
    const chunkBase = {
      id: b.id || `chatcmpl-tunnel-${crypto.randomUUID()}`,
      object: "chat.completion.chunk",
      created: b.created || Math.floor(Date.now() / 1000),
      model: b.model || "glm-4.6",
    };
    const content =
      (b.choices && b.choices[0] && b.choices[0].message && typeof b.choices[0].message.content === "string")
        ? b.choices[0].message.content
        : "";
    res.writeHead(200, {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    });
    // Chunk 1 : delta role+content (la completion entière en un delta —
    // conforme au protocole : le client concatène les delta.content).
    res.write(
      `data: ${JSON.stringify({
        ...chunkBase,
        choices: [{ index: 0, delta: { role: "assistant", content }, finish_reason: null }],
      })}\n\n`,
    );
    // Chunk 2 : delta vide + finish_reason stop.
    res.write(
      `data: ${JSON.stringify({
        ...chunkBase,
        choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
        usage: b.usage || undefined,
      })}\n\n`,
    );
    res.write("data: [DONE]\n\n");
    res.end();
  } else {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(reply.body));
  }
  log(`chat OK (${latency} ms, stream=${wantStream ? "sse-simulé" : "json"})`);
}

// ── WebSocket (client sandbox) ───────────────────────────────────────────────
const wss = new WebSocketServer({ noServer: true });

server.on("upgrade", (req, socket, head) => {
  const url = new URL(req.url ?? "/", "http://localhost");
  if (url.pathname !== "/llm-tunnel-ws") {
    socket.write("HTTP/1.1 404 Not Found\r\n\r\n");
    socket.destroy();
    return;
  }
  const token = url.searchParams.get("token") ?? req.headers["x-tunnel-token"] ?? "";
  if (!TUNNEL_TOKEN || !safeEq(token, TUNNEL_TOKEN)) {
    log("upgrade WS REFUSÉ (token invalide)");
    socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
    socket.destroy();
    return;
  }
  if (tunnelSocket && tunnelSocket.readyState === 1) {
    // REMPLACEMENT AUTOMATIQUE : un nouveau client authentifié prend la main.
    // (L'ancien refus 409 créait une boucle de reconnexion quand le client
    // se rechargait — la socket fantôme ne libérait jamais la place.)
    log("tunnel existant REMPLACÉ par une nouvelle connexion authentifiée");
    try {
      tunnelSocket.close(4000, "replaced");
    } catch {
      /* */
    }
    tunnelSocket = null;
    // Échouer immédiatement les requêtes en attente sur l'ancien tunnel.
    for (const [id, p] of pending) {
      clearTimeout(p.timer);
      pending.delete(id);
      p.resolve({ status: 503, body: { error: { message: "tunnel remplacé — requête non servie", type: "tunnel_down" } } });
    }
  }
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit("connection", ws, req));
});

wss.on("connection", (ws) => {
  tunnelSocket = ws;
  tunnelId = crypto.randomUUID().slice(0, 8);
  lastTunnelMessage = Date.now();
  log(`tunnel client CONNECTÉ (${tunnelId}) — IA sandbox disponible`);
  ws.send(JSON.stringify({ type: "hello", models: MODELS }));

  ws.on("message", (raw) => {
    lastTunnelMessage = Date.now();
    let m;
    try {
      m = JSON.parse(raw.toString());
    } catch {
      return;
    }
    if (m.type === "ping") {
      try {
        ws.send(JSON.stringify({ type: "pong", t: Date.now() }));
      } catch {
        /* */
      }
      return;
    }
    if (m.id && pending.has(m.id)) {
      const p = pending.get(m.id);
      clearTimeout(p.timer);
      pending.delete(m.id);
      p.resolve({ status: m.status, body: m.body });
    }
  });

  ws.on("close", () => {
    if (tunnelSocket === ws) {
      tunnelSocket = null;
      log(`tunnel client DÉCONNECTÉ (${tunnelId}) — reconnexion attendue du sandbox`);
    }
  });
  ws.on("error", () => {
    try {
      ws.close();
    } catch {
      /* */
    }
  });
});

server.listen(PORT, "0.0.0.0", () => {
  log(`écoute 0.0.0.0:${PORT} — WS /llm-tunnel-ws + API /v1/* (Bearer LLM_TUNNEL_KEY)`);
  if (!TUNNEL_TOKEN || !HTTP_KEY) {
    log("⚠️ TUNNEL_TOKEN ou LLM_TUNNEL_KEY manquant — les accès correspondants seront refusés");
  }
  setInterval(() => {
    if (tunnelSocket && Date.now() - lastTunnelMessage > 150_000) {
      log("watchdog : tunnel silencieux > 150 s — fermeture forcée (socket fantôme ?)");
      try {
        tunnelSocket.close(4001, "watchdog");
      } catch {
        /* */
      }
      tunnelSocket = null;
    }
  }, 30_000).unref();
});
