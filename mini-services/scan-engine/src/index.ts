/**
 * AuditForge — scan-engine : mini-service d'exécution (port 3030).
 *
 * - HTTP interne (same-server) : POST /internal/run, POST /internal/cancel,
 *   GET /internal/health — consommé par l'API Next.js en localhost.
 *   Chaque route /internal/* exige l'en-tête `x-internal-token` (contrat K.1).
 * - socket.io (path par défaut /socket.io, derrière la gateway Caddy via
 *   XTransformPort=3030) : rooms scan:{id}, événements scan:update /
 *   scan:log / scan:finding / scan:done. Handshake authentifié (contrat K.2).
 * - SQLite partagée (WAL) via Prisma, pragmas appliqués au démarrage,
 *   récupération des scans RUNNING/QUEUED hérités d'un redémarrage (N.23).
 * - Écoute restreinte à 127.0.0.1 (contrat K.4) ; arrêt gracieux (N.24).
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { Server } from "socket.io";
import { db } from "./db";
import { ScanEngine, setIo } from "./engine";
import { verifySessionToken } from "./session";
import type {
  ClientToServerEvents,
  EngineRunRequest,
  Profile,
  ScanDoneEvent,
  ScanFindingEvent,
  ScanLogEvent,
  ScanUpdateEvent,
  TargetType,
  Tool,
} from "./types";

const PORT = 3030;
const MAX_BODY_BYTES = 1024 * 1024; // 1 MB
const BODY_TIMEOUT_MS = 5000; // N.27 : lecture du corps plafonnée à 5 s
const MAX_ROOMS_PER_SOCKET = 20; // K.4 : plafond de rooms par socket
const SHUTDOWN_GRACE_MS = 3000; // N.24 : budget de finalisation à l'arrêt

const TOOLS: Tool[] = ["PHANTOM", "DEEPAUDIT", "BASALT", "REDAMON"];
const PROFILES: Profile[] = ["QUICK", "STANDARD", "DEEP"];
const TARGET_TYPES: TargetType[] = ["URL", "GIT", "NETWORK"];
const SCAN_ID_RE = /^[A-Za-z0-9_-]{6,64}$/;

/** Événements serveur → client (miroir des DTO de types.ts, contrat §G). */
export interface ServerToClientEvents {
  "scan:update": (event: ScanUpdateEvent) => void;
  "scan:done": (event: ScanDoneEvent) => void;
  "scan:log": (event: ScanLogEvent) => void;
  "scan:finding": (event: ScanFindingEvent) => void;
}

function sendJson(res: ServerResponse, status: number, payload: unknown): void {
  if (res.headersSent) return;
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

/** Erreur typée de lecture de corps (permet de répondre 408/413/400 précisément). */
class BodyReadError extends Error {
  constructor(
    public readonly status: 400 | 408 | 413,
    message: string,
  ) {
    super(message);
  }
}

function readBody(req: IncomingMessage, limit = MAX_BODY_BYTES): Promise<string> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let size = 0;
    const chunks: Buffer[] = [];

    const finish = (fn: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      req.removeAllListeners("data");
      req.removeAllListeners("end");
      req.removeAllListeners("error");
      fn();
    };

    // N.27 : timeout de 5 s → 408 (la réponse est envoyée, puis le socket détruit).
    const timer = setTimeout(() => {
      finish(() => reject(new BodyReadError(408, "request timeout")));
    }, BODY_TIMEOUT_MS);
    timer.unref();

    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > limit) {
        finish(() => reject(new BodyReadError(413, "payload too large")));
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => finish(() => resolve(Buffer.concat(chunks).toString("utf8"))));
    req.on("error", () => finish(() => reject(new BodyReadError(400, "corps illisible"))));
  });
}

/** Lit + parse le corps JSON ; répond lui-même en cas d'erreur (et détruit le socket). */
async function readJsonBody(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<Record<string, unknown> | null> {
  let raw: string;
  try {
    raw = await readBody(req);
  } catch (err) {
    if (err instanceof BodyReadError) {
      sendJson(res, err.status, { ok: false, error: err.message });
    } else {
      sendJson(res, 400, { ok: false, error: "corps JSON invalide" });
    }
    // La réponse est partie : on referme le socket (débit interrompu / trop volumineux).
    try {
      req.destroy();
    } catch {
      // socket déjà fermé
    }
    return null;
  }
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      sendJson(res, 400, { ok: false, error: "corps JSON invalide" });
      return null;
    }
    return parsed as Record<string, unknown>;
  } catch {
    sendJson(res, 400, { ok: false, error: "corps JSON invalide" });
    return null;
  }
}

/** K.1 : vérification du token interne (comparaison à temps constant). */
function requireInternalToken(req: IncomingMessage): boolean {
  const expected = process.env.ENGINE_INTERNAL_TOKEN ?? "auditforge-internal-dev-token";
  const provided = req.headers["x-internal-token"];
  if (typeof provided !== "string" || provided.length === 0) return false;
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** N.22 : retire les caractères de contrôle (\u0000-\u001F + \u007F) et les espaces d'extrémité. */
function sanitizeTarget(raw: string): string {
  return raw.replace(/[\u0000-\u001F\u007F]/g, "").trim();
}

/** Parse un en-tête Cookie ('a=b; c=d') — valeurs URL-décodées si possible. */
function parseCookieHeader(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (!key) continue;
    try {
      out[key] = decodeURIComponent(value);
    } catch {
      out[key] = value;
    }
  }
  return out;
}

async function route(req: IncomingMessage, res: ServerResponse, engine: ScanEngine): Promise<void> {
  const url = new URL(req.url ?? "/", "http://localhost");
  const path = url.pathname;

  try {
    // ── POST /internal/run ──
    if (path === "/internal/run" && req.method === "POST") {
      if (!requireInternalToken(req)) {
        sendJson(res, 401, { ok: false, error: "unauthorized" });
        return;
      }
      const b = await readJsonBody(req, res);
      if (b === null) return;

      // ── Validations (N.22) ──
      const scanId = typeof b.scanId === "string" ? b.scanId : "";
      const targetRaw = typeof b.target === "string" ? b.target : "";
      const tool = typeof b.tool === "string" ? b.tool : "";
      const profile = typeof b.profile === "string" ? b.profile : "";
      const targetType = typeof b.targetType === "string" ? b.targetType : "";

      if (!TOOLS.includes(tool as Tool)) {
        sendJson(res, 400, { ok: false, error: `tool invalide (attendu : ${TOOLS.join(", ")})` });
        return;
      }
      if (!PROFILES.includes(profile as Profile)) {
        sendJson(res, 400, { ok: false, error: `profile invalide (attendu : ${PROFILES.join(", ")})` });
        return;
      }
      if (!TARGET_TYPES.includes(targetType as TargetType)) {
        sendJson(res, 400, {
          ok: false,
          error: `targetType invalide (attendu : ${TARGET_TYPES.join(", ")})`,
        });
        return;
      }
      if (!SCAN_ID_RE.test(scanId)) {
        sendJson(res, 400, {
          ok: false,
          error: "scanId invalide (6 à 64 caractères alphanumériques, - ou _)",
        });
        return;
      }
      const target = sanitizeTarget(targetRaw);
      if (!target || target.length > 300) {
        sendJson(res, 400, { ok: false, error: "target invalide (1 à 300 caractères)" });
        return;
      }

      // Le scan doit exister en base (404 AVANT le 202) ; campaignId lu en base.
      const scan = await db.scan.findUnique({ where: { id: scanId } });
      if (!scan) {
        sendJson(res, 404, { ok: false, error: "scan not found" });
        return;
      }

      const cfg: EngineRunRequest & { campaignId: string } = {
        scanId,
        tool: tool as Tool,
        target,
        targetType: targetType as TargetType,
        profile: profile as Profile,
        campaignId: scan.campaignId,
      };
      try {
        engine.run(cfg);
      } catch (err) {
        sendJson(res, 409, { ok: false, error: err instanceof Error ? err.message : String(err) });
        return;
      }
      sendJson(res, 202, { ok: true });
      return;
    }

    // ── POST /internal/cancel ──
    if (path === "/internal/cancel" && req.method === "POST") {
      if (!requireInternalToken(req)) {
        sendJson(res, 401, { ok: false, error: "unauthorized" });
        return;
      }
      const b = await readJsonBody(req, res);
      if (b === null) return;
      const scanId = typeof b.scanId === "string" ? b.scanId : "";
      if (!scanId) {
        sendJson(res, 400, { ok: false, error: "scanId requis" });
        return;
      }
      const ok = engine.cancel(scanId);
      sendJson(res, 200, { ok });
      return;
    }

    // ── GET /internal/health ──
    if (path === "/internal/health" && req.method === "GET") {
      if (!requireInternalToken(req)) {
        sendJson(res, 401, { ok: false, error: "unauthorized" });
        return;
      }
      sendJson(res, 200, { ok: true, running: engine.runningCount() });
      return;
    }

    sendJson(res, 404, { ok: false, error: "not found" });
  } catch (err) {
    console.error("[scan-engine] erreur interne:", err);
    if (!res.headersSent) {
      sendJson(res, 500, { ok: false, error: "erreur interne" });
    }
  }
}

async function main(): Promise<void> {
  // ── Pragmas SQLite (best effort) ──
  // NB : ces pragmas renvoient une ligne de résultat → $queryRawUnsafe
  // (executeRawUnsafe échoue avec "Execute returned results").
  try {
    await db.$queryRawUnsafe("PRAGMA journal_mode=WAL;");
    await db.$queryRawUnsafe("PRAGMA busy_timeout=5000;");
  } catch (err) {
    console.warn("[scan-engine] pragmas SQLite ignorés:", err);
  }

  // ── Récupération au démarrage (N.23) : scans hérités d'un redémarrage ──
  // RUNNING/QUEUED → FAILED + finishedAt + ScanLog (level ERROR, source 'systeme').
  try {
    const stale = await db.scan.findMany({
      where: { status: { in: ["RUNNING", "QUEUED"] } },
      select: { id: true },
    });
    for (const s of stale) {
      try {
        await db.scan.update({
          where: { id: s.id },
          data: { status: "FAILED", finishedAt: new Date() },
        });
        await db.scanLog.createMany({
          data: [
            {
              scanId: s.id,
              level: "ERROR",
              source: "systeme",
              message: "Scan interrompu par un redémarrage du moteur",
            },
          ],
        });
      } catch (err) {
        console.warn(`[scan-engine] récupération : scan ${s.id} non finalisable:`, err);
      }
    }
    if (stale.length > 0) {
      console.log(
        `[scan-engine] récupération : ${stale.length} scan(s) RUNNING/QUEUED marqué(s) FAILED après redémarrage`,
      );
    }
  } catch (err) {
    console.warn("[scan-engine] récupération au démarrage impossible:", err);
  }

  const engine = new ScanEngine();

  // socket.io intercepte /socket.io/* ; les autres requêtes (/internal/*)
  // arrivent au handler du serveur HTTP.
  const httpServer = createServer((req, res) => {
    void route(req, res, engine);
  });

  const io: Server<ClientToServerEvents, ServerToClientEvents> = new Server<
    ClientToServerEvents,
    ServerToClientEvents
  >(httpServer, {
    cors: { origin: "*", methods: ["GET", "POST"] },
    pingTimeout: 60000,
    pingInterval: 25000,
  });
  setIo(io);

  // ── Authentification du handshake (K.2) ──
  // Accepté si le cookie `af_session` du handshake est valide OU si
  // handshake.auth.token (v1.<payload>.<sig>) est valide — sinon rejet.
  io.use((socket, next) => {
    const cookies = parseCookieHeader(socket.handshake.headers.cookie);
    const cookieToken = cookies["af_session"];
    const authPayload: unknown = socket.handshake.auth?.token;
    const authToken = typeof authPayload === "string" ? authPayload : undefined;
    if (verifySessionToken(cookieToken) || verifySessionToken(authToken)) {
      next();
      return;
    }
    next(new Error("unauthorized"));
  });

  // ── Plafond de rooms par socket (K.4) ──
  const roomCounts = new Map<string, number>();

  io.on("connection", (socket) => {
    console.log(`[scan-engine] socket connecté : ${socket.id}`);
    socket.on("scan:subscribe", (data) => {
      const scanId = data?.scanId;
      if (typeof scanId !== "string" || !scanId) return;
      const room = `scan:${scanId}`;
      if (socket.rooms.has(room)) return; // déjà souscrit : pas de double comptage
      const count = roomCounts.get(socket.id) ?? 0;
      if (count >= MAX_ROOMS_PER_SOCKET) {
        console.warn(
          `[scan-engine] plafond de ${MAX_ROOMS_PER_SOCKET} rooms atteint pour ${socket.id} — subscription ignorée (${scanId})`,
        );
        return;
      }
      void socket.join(room);
      roomCounts.set(socket.id, count + 1);
    });
    socket.on("scan:unsubscribe", (data) => {
      const scanId = data?.scanId;
      if (typeof scanId !== "string" || !scanId) return;
      const room = `scan:${scanId}`;
      if (!socket.rooms.has(room)) return;
      void socket.leave(room);
      const count = roomCounts.get(socket.id) ?? 0;
      if (count <= 1) roomCounts.delete(socket.id);
      else roomCounts.set(socket.id, count - 1);
    });
    socket.on("disconnect", (reason) => {
      roomCounts.delete(socket.id); // libération du compteur de rooms
      console.log(`[scan-engine] socket déconnecté : ${socket.id} (${reason})`);
    });
  });

  // K.4 : écoute restreinte à l'interface de bouclage par défaut (le passage
  // navigateur se fait exclusivement via la gateway Caddy). En déploiement
  // Docker, BIND_HOST=0.0.0.0 est requis pour joindre le conteneur depuis le
  // réseau interne compose — le port n'est JAMAIS publié sur l'hôte.
  const BIND_HOST = process.env.BIND_HOST ?? "127.0.0.1";
  httpServer.listen(PORT, BIND_HOST, () => {
    console.log(`[scan-engine] listening on ${BIND_HOST}:${PORT}`);
  });

  // ── Arrêt gracieux (N.24) — SIGTERM/SIGINT idempotents ──
  let shuttingDown = false;
  const shutdown = (signal: string): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`[scan-engine] arrêt (${signal}) — finalisation des scans actifs…`);
    const active = engine.activeScanIds();
    void Promise.allSettled(active.map((id) => engine.cancelAndWait(id, SHUTDOWN_GRACE_MS)))
      .then(() => {
        console.log("[scan-engine] scans actifs finalisés (CANCELLED) — fermeture du serveur");
        try {
          io.close();
        } catch (err) {
          console.warn("[scan-engine] io.close() impossible:", err);
        }
        try {
          httpServer.close(() => process.exit(0));
        } catch {
          process.exit(0);
        }
        setTimeout(() => process.exit(0), 2000).unref();
      });
  };
  process.once("SIGTERM", () => shutdown("SIGTERM"));
  process.once("SIGINT", () => shutdown("SIGINT"));
}

main().catch((err) => {
  console.error("[scan-engine] erreur fatale au démarrage:", err);
  process.exit(1);
});
