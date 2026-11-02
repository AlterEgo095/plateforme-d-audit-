/**
 * AuditForge — Rate limiters mémoire (contrat worklog §K.5 + durcissement RGPD/CSRF)
 *
 * 1) Limiteur de CONNEXION : fenêtre glissante de 10 minutes, max 5 échecs
 *    d'authentification par clé (`ip:username`).
 * 2) Limiteur GÉNÉRIQUE API : fenêtre glissante paramétrable (défaut 120
 *    requêtes/minute par IP) appliqué par `withApi` sur les méthodes mutantes
 *    (POST/PUT/PATCH/DELETE) — garde-fou anti-flood/DoS sur toutes les routes.
 *
 * Stockage Map en mémoire (survit aux rechargements de module en dev via
 * globalThis), nettoyage périodique. Limite intrinsèque : par instance de
 * process (une seule instance app en production).
 *
 * API :
 * - registerLoginFailure(key) : enregistre un échec (user inconnu / mauvais mot
 *   de passe / mauvais TOTP)
 * - resetLoginFailures(key)   : succès → remise à zéro
 * - isLoginBlocked(key)       : {blocked, retryAfterSec}
 * - hitRateLimit(key,max,win) : {limited, retryAfterSec} (limiteur générique)
 */

const WINDOW_MS = 10 * 60 * 1000 // 10 minutes
const MAX_FAILURES = 5
// i6 (audit 8-a) : plafond du nombre de clés suivies — un spray d'identifiants
// uniques avec X-Forwarded-For falsifiés ne peut pas faire croître la Map
// indéfiniment (fuite mémoire).
const MAX_KEYS = 5000

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

// Nettoyage périodique (1/min) des DEUX stores (login + API générique) — posé
// une seule fois même après rechargement du module. pruneApiStore est une
// déclaration de fonction hoistée (définie plus bas) : appel valide dans le callback.
if (!g.__afRateLimitTimer) {
  const timer = setInterval(() => {
    const now = Date.now()
    pruneExpired(now)
    pruneApiStore(now, 60_000)
  }, 60_000)
  // Ne pas empêcher l'arrêt du process pour ce simple timer.
  if (timer && typeof timer === 'object' && 'unref' in timer && typeof timer.unref === 'function') {
    timer.unref()
  }
  g.__afRateLimitTimer = timer
}

/** Enregistre un échec d'authentification pour la clé donnée. */
export function registerLoginFailure(key: string): void {
  const now = Date.now()
  // i6 : plafond de clés — purge des expirées puis éviction FIFO si nécessaire.
  if (store.size >= MAX_KEYS) {
    pruneExpired(now)
    while (store.size >= MAX_KEYS) {
      const oldest = store.keys().next().value
      if (oldest === undefined) break
      store.delete(oldest)
    }
  }
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

// ─────────────────────────────────────────────────────────────────────────────
// 2) Limiteur générique API (méthodes mutantes) — même famille de mécanique,
//    store séparé, fenêtre et plafond paramétrables par appel.
// ─────────────────────────────────────────────────────────────────────────────

interface HitRecord {
  /** Horodatages (ms) des requêtes récentes (triés croissant). */
  timestamps: number[]
}

const g2 = globalThis as unknown as {
  __afApiRateStore?: Map<string, HitRecord>
}

const apiStore: Map<string, HitRecord> = (g2.__afApiRateStore ??= new Map())

/** Plafond de clés du store générique (anti-fuite mémoire, même logique que i6). */
const API_MAX_KEYS = 5000

function pruneApiStore(now: number, windowMs: number): void {
  for (const [key, record] of apiStore) {
    record.timestamps = record.timestamps.filter((t) => now - t < windowMs)
    if (record.timestamps.length === 0) apiStore.delete(key)
  }
}

/**
 * Enregistre une requête pour la clé donnée et indique si le plafond est dépassé.
 * @param key      clé de suivi (ex. IP cliente)
 * @param max      nombre maximal de requêtes dans la fenêtre
 * @param windowMs taille de la fenêtre glissante en millisecondes
 */
export function hitRateLimit(
  key: string,
  max: number,
  windowMs: number
): { limited: boolean; retryAfterSec: number } {
  const now = Date.now()
  // Plafond de clés : purge des expirées puis éviction FIFO si nécessaire.
  if (apiStore.size >= API_MAX_KEYS) {
    pruneApiStore(now, windowMs)
    while (apiStore.size >= API_MAX_KEYS) {
      const oldest = apiStore.keys().next().value
      if (oldest === undefined) break
      apiStore.delete(oldest)
    }
  }
  const record = apiStore.get(key) ?? { timestamps: [] }
  record.timestamps = record.timestamps.filter((t) => now - t < windowMs)
  record.timestamps.push(now)
  apiStore.set(key, record)

  if (record.timestamps.length <= max) return { limited: false, retryAfterSec: 0 }
  // Le (len - max)-ème horodatage le plus ancien doit sortir de la fenêtre.
  const unlockAt = record.timestamps[record.timestamps.length - max - 1] + windowMs
  return { limited: true, retryAfterSec: Math.max(1, Math.ceil((unlockAt - now) / 1000)) }
}
