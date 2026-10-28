/**
 * AuditForge — instrumentation Next.js (runtime nodejs).
 *
 * P5 (confort de développement sandbox) : au boot (dev), démarre le
 * scan-engine si absent via la logique partagée src/lib/dev-engine.ts
 * (idempotent, refusé en production sauf ENGINE_AUTO_SPAWN=1 explicite).
 *
 * NB : next dev n'appelle register() qu'au BOOT du serveur — si
 * l'instrumentation est ajoutée à chaud, la route /api/dev/engine
 * (hot-reloadable) permet le même spawn à la demande.
 */
export async function register(): Promise<void> {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  const { ensureEngineRunning } = await import("./lib/dev-engine");
  const result = await ensureEngineRunning();
  if (result.reason !== "déjà en écoute sur :3030") {
    console.log(`[instrumentation] scan-engine : ${result.reason}`);
  }
}
