/**
 * AuditForge — Client HTTP vers le moteur d'exécution (:3030, localhost uniquement)
 *
 * Contrats worklog §H + §K.1 :
 * - POST /internal/run    → 202 {ok:true} | 409 {ok:false,error}
 * - POST /internal/cancel → {ok:true} (idempotent)
 * - GET  /internal/health → {ok:true, running:N}
 * - chaque requête porte l'en-tête `x-internal-token` (ENGINE_INTERNAL_TOKEN)
 */
import type { EngineRunRequest } from '@/lib/types'

export const ENGINE_URL = process.env.ENGINE_URL ?? 'http://127.0.0.1:3030'

/** Token interne moteur (contrat §K.1) — doit correspondre à ENGINE_INTERNAL_TOKEN du service :3030. */
const INTERNAL_TOKEN = process.env.ENGINE_INTERNAL_TOKEN ?? 'auditforge-internal-dev-token'

function internalHeaders(): Record<string, string> {
  return {
    'Content-Type': 'application/json',
    'x-internal-token': INTERNAL_TOKEN,
  }
}

/**
 * Lance un scan : POST /internal/run (timeout 4 s).
 * Lève une exception si le moteur est injoignable ou répond avec une erreur —
 * l'appelant (POST /api/campaigns, /launch) marque alors les scans en FAILED.
 */
export async function engineRun(cfg: EngineRunRequest): Promise<void> {
  let res: Response
  try {
    res = await fetch(`${ENGINE_URL}/internal/run`, {
      method: 'POST',
      headers: internalHeaders(),
      body: JSON.stringify(cfg),
      cache: 'no-store',
      signal: AbortSignal.timeout(4000),
    })
  } catch (error) {
    const reason = error instanceof Error ? error.message : 'erreur réseau'
    throw new Error(`Moteur d'exécution injoignable (${reason})`)
  }
  if (!res.ok) {
    let message = `Réponse moteur inattendue (HTTP ${res.status})`
    try {
      const body = (await res.json()) as { error?: string }
      if (body && typeof body.error === 'string') message = body.error
    } catch {
      // corps non JSON : on conserve le message par défaut
    }
    throw new Error(message)
  }
}

/**
 * Demande l'annulation d'un scan : POST /internal/cancel.
 * Retourne true si le moteur confirme {ok:true}, false sinon (idempotent, jamais lancé).
 */
export async function engineCancel(scanId: string): Promise<boolean> {
  try {
    const res = await fetch(`${ENGINE_URL}/internal/cancel`, {
      method: 'POST',
      headers: internalHeaders(),
      body: JSON.stringify({ scanId }),
      cache: 'no-store',
      signal: AbortSignal.timeout(4000),
    })
    if (!res.ok) return false
    const body = (await res.json()) as { ok?: boolean }
    return body?.ok === true
  } catch {
    // moteur injoignable : annulation locale uniquement
    return false
  }
}

/** Ping du moteur : GET /internal/health (timeout 2,5 s). false = moteur hors ligne. */
export async function engineHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${ENGINE_URL}/internal/health`, {
      headers: internalHeaders(),
      cache: 'no-store',
      signal: AbortSignal.timeout(2500),
    })
    if (!res.ok) return false
    const body = (await res.json()) as { ok?: boolean }
    return body?.ok === true
  } catch {
    return false
  }
}

/** Statut d'exécution réelle par outil : GET /internal/tools-status (timeout 15 s). */
export interface EngineToolStatus {
  tool: string
  mode: 'simulation' | 'auto' | 'real'
  realAvailable: boolean
  reason?: string
}

export async function engineToolsStatus(): Promise<EngineToolStatus[] | null> {
  try {
    const res = await fetch(`${ENGINE_URL}/internal/tools-status`, {
      headers: internalHeaders(),
      cache: 'no-store',
      signal: AbortSignal.timeout(15000),
    })
    if (!res.ok) return null
    const body = (await res.json()) as { ok?: boolean; mode?: string; tools?: EngineToolStatus[] }
    if (body?.ok !== true || !Array.isArray(body.tools)) return null
    return body.tools
  } catch {
    return null
  }
}
