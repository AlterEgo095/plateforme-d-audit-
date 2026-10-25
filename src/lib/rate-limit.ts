/**
 * AuditForge — Rate limiter mémoire pour la connexion (contrat worklog §K.5)
 *
 * Fenêtre glissante de 10 minutes, max 5 échecs d'authentification par clé
 * (`ip:username`). Stockage Map en mémoire (survit aux rechargements de module
 * en dev via globalThis), nettoyage périodique.
 *
 * API :
 * - registerLoginFailure(key) : enregistre un échec (user inconnu / mauvais mot
 *   de passe / mauvais TOTP)
 * - resetLoginFailures(key)   : succès → remise à zéro
 * - isLoginBlocked(key)       : {blocked, retryAfterSec}
 */

const WINDOW_MS = 10 * 60 * 1000 // 10 minutes
const MAX_FAILURES = 5

interface FailureRecord {
  /** Horodatages (ms) des échecs récents (triés croissant, fenêtre glissante). */
  timestamps: number[]
}

const g = globalThis as unknown as {
  __afRateLimitStore?: Map<string, FailureRecord>
  __afRateLimitTimer?: ReturnType<typeof setInterval>
}

const store: Map<string, FailureRecord> = (g.__afRateLimitStore ??= new Map())

/** Supprime les échecs hors fenêtre et les clés devenues vides. */
function pruneExpired(now: number): void {
  for (const [key, record] of store) {
    record.timestamps = record.timestamps.filter((t) => now - t < WINDOW_MS)
    if (record.timestamps.length === 0) store.delete(key)
  }
}

// Nettoyage périodique (1/min) — posé une seule fois même après rechargement du module.
if (!g.__afRateLimitTimer) {
  const timer = setInterval(() => pruneExpired(Date.now()), 60_000)
  // Ne pas empêcher l'arrêt du process pour ce simple timer.
  if (timer && typeof timer === 'object' && 'unref' in timer && typeof timer.unref === 'function') {
    timer.unref()
  }
  g.__afRateLimitTimer = timer
}

/** Enregistre un échec d'authentification pour la clé donnée. */
export function registerLoginFailure(key: string): void {
  const now = Date.now()
  const record = store.get(key) ?? { timestamps: [] }
  record.timestamps = record.timestamps.filter((t) => now - t < WINDOW_MS)
  record.timestamps.push(now)
  store.set(key, record)
}

/** Réinitialise les échecs d'une clé (appelé après une connexion réussie). */
export function resetLoginFailures(key: string): void {
  store.delete(key)
}

/** Indique si la clé est bloquée et, le cas échéant, dans combien de temps elle sera levée. */
export function isLoginBlocked(key: string): { blocked: boolean; retryAfterSec: number } {
  const now = Date.now()
  const record = store.get(key)
  if (!record) return { blocked: false, retryAfterSec: 0 }
  const active = record.timestamps.filter((t) => now - t < WINDOW_MS)
  if (active.length < MAX_FAILURES) return { blocked: false, retryAfterSec: 0 }
  // Il faut que le (active.length - MAX_FAILURES + 1)-ème échec le plus ancien sorte
  // de la fenêtre pour repasser sous la limite.
  const unlockAt = active[active.length - MAX_FAILURES] + WINDOW_MS
  return { blocked: true, retryAfterSec: Math.max(1, Math.ceil((unlockAt - now) / 1000)) }
}
