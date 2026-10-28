/**
 * AuditForge — démarrage du scan-engine par l'app (confort de développement).
 *
 * Partagé entre src/instrumentation.ts (au boot, dev) et la route
 * /api/dev/engine (hot-reloadable — spawn à la demande). En production
 * (Docker/compose) l'engine est son PROPRE service : tout spawn est refusé
 * sauf si ENGINE_AUTO_SPAWN=1 est explicitement posé.
 *
 * Propriétés :
 *  - idempotent : sonde TCP :3030, aucun spawn si déjà en écoute ;
 *  - process détaché (unref) journalisant dans dev-engine.log ;
 *  - l'enfant appartient à l'arbre du serveur Next.js (supervisé), pas à un
 *    shell éphémère — il survit aux rechargements next dev.
 */
import { createConnection } from "node:net";
import { spawn } from "node:child_process";
import { openSync } from "node:fs";
import { join } from "node:path";

export interface EngineSpawnResult {
  spawned: boolean;
  reason: string;
  pid?: number;
}

function enginePortUp(): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = createConnection({ host: "127.0.0.1", port: 3030 }, () => {
      sock.destroy();
      resolve(true);
    });
    sock.on("error", () => resolve(false));
    const timer = setTimeout(() => {
      sock.destroy();
      resolve(false);
    }, 500);
    timer.unref();
  });
}

export async function ensureEngineRunning(): Promise<EngineSpawnResult> {
  const prod = process.env.NODE_ENV === "production";
  const valve = process.env.ENGINE_AUTO_SPAWN;
  if (prod && valve !== "1") {
    return { spawned: false, reason: "production — l'engine est son propre service (compose)" };
  }
  if (valve === "0") {
    return { spawned: false, reason: "ENGINE_AUTO_SPAWN=0 — spawn désactivé" };
  }
  if (await enginePortUp()) {
    return { spawned: false, reason: "déjà en écoute sur :3030" };
  }

  const cwd = join(process.cwd(), "mini-services", "scan-engine");
  const logPath = join(process.cwd(), "dev-engine.log");
  let out: number;
  try {
    out = openSync(logPath, "a");
  } catch {
    return { spawned: false, reason: `impossible d'ouvrir ${logPath}` };
  }
  const bin = process.env.BUN_BIN ?? "bun";
  const child = spawn(bin, ["src/index.ts"], {
    cwd,
    detached: true,
    stdio: ["ignore", out, out],
    env: { ...process.env, NODE_ENV: process.env.NODE_ENV ?? "development" },
  });
  child.unref();
  console.log(`[dev-engine] scan-engine spawné (pid ${child.pid ?? "?"}) → ${logPath}`);
  return { spawned: true, reason: "spawn effectué", pid: child.pid };
}
