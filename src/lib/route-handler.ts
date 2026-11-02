/**
 * AuditForge — Wrapper d'erreurs + garde-fous HTTP pour les route handlers
 * (contrat worklog §L.7, durcissement suite audit externe)
 *
 * `withApi` enveloppe le handler exporté d'une route :
 *
 * 1. GARDES-FOUS (méthodes mutantes POST/PUT/PATCH/DELETE uniquement) :
 *    - vérification d'Origine (anti-CSRF) : si l'en-tête `Origin` est présent
 *      (navigateurs), son hôte doit correspondre à l'hôte servi — un site tiers
 *      ne peut pas faire poster le navigateur d'un utilisateur connecté vers
 *      notre API. Les clients sans Origin (curl, scripts E2E, moteur) passent ;
 *    - plafond de taille du corps (`content-length`, défaut 2 Mo, override
 *      `AF_MAX_BODY_BYTES`) → 413 : aucune limite n'existait au niveau applicatif
 *      (seul nginx impose 50 Mo à l'edge) ;
 *    - rate limit générique par IP (défaut 120 req/min, overrides
 *      `AF_API_RATE_MAX` / `AF_API_RATE_WINDOW_MS`) → 429 + Retry-After.
 *
 * 2. Erreurs : toute exception non interceptée (SQLITE_BUSY, panne DB, bug
 *    imprévu…) est journalisée puis transformée en 500 {error:'Erreur interne
 *    du serveur'} (contrat §F). Les réponses d'erreur métier déjà codées dans
 *    les routes (401/403/404/409/428/400) sont renvoyées telles quelles.
 *
 * Usage :
 * - route dynamique : `export const GET = withApi<{ id: string }>(async (req, { params }) => {...})`
 * - route statique  : `export const GET = withApi(async (req) => {...})`
 */
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'
import { hitRateLimit } from '@/lib/rate-limit'
import { clientIp } from '@/lib/client-ip'

/** Contexte d'une route dynamique (params Promise, Next 16). */
export interface ApiRouteContext<P extends Record<string, string>> {
  params: Promise<P>
}

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

function envInt(name: string, fallback: number): number {
  const raw = process.env[name]
  if (!raw) return fallback
  const n = Number(raw)
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback
}

/** Plafond de taille du corps des requêtes mutantes (octets). Défaut : 2 Mo. */
const MAX_BODY_BYTES = envInt('AF_MAX_BODY_BYTES', 2 * 1024 * 1024)
/** Plafond de requêtes mutantes par IP et fenêtre. Défaut : 120 / minute. */
const API_RATE_MAX = envInt('AF_API_RATE_MAX', 120)
/** Fenêtre du rate limit générique (ms). Défaut : 60 000. */
const API_RATE_WINDOW_MS = envInt('AF_API_RATE_WINDOW_MS', 60_000)

/**
 * Anti-CSRF : valide l'en-tête `Origin` (s'il est présent) contre l'hôte servi.
 * - pas d'Origin → OK (curl, scripts E2E, moteur — clients non-navigateurs) ;
 * - Origin invalide/hôte différent → false (tentative CSRF).
 * L'hôte de référence : `x-forwarded-host` (posé par la chaîne de proxies) ou
 * `host` (préservé de bout en bout par nginx/Caddy).
 */
function sameOrigin(req: NextRequest): boolean {
  const origin = req.headers.get('origin')
  if (!origin) return true
  let parsed: URL
  try {
    parsed = new URL(origin)
  } catch {
    return false // Origin malformé (y compris la valeur littérale « null »)
  }
  const expected = (req.headers.get('x-forwarded-host') ?? req.headers.get('host') ?? '')
    .trim()
    .toLowerCase()
  if (!expected) return false
  return parsed.host.toLowerCase() === expected
}

export function withApi<P extends Record<string, string> = Record<string, string>>(
  handler: (req: NextRequest, ctx: ApiRouteContext<P>) => Promise<NextResponse>
): (req: NextRequest, ctx?: unknown) => Promise<NextResponse> {
  return async (req, ctx) => {
    try {
      if (MUTATING_METHODS.has(req.method.toUpperCase())) {
        // 1) Anti-CSRF : l'Origine, si fournie, doit être la nôtre.
        if (!sameOrigin(req)) {
          return NextResponse.json({ error: 'Origine non autorisée' }, { status: 403 })
        }
        // 2) Plafond de taille du corps (avant tout parsing applicatif).
        const len = Number(req.headers.get('content-length') ?? '0')
        if (Number.isFinite(len) && len > MAX_BODY_BYTES) {
          return NextResponse.json({ error: 'Corps de requête trop volumineux' }, { status: 413 })
        }
        // 3) Rate limit générique par IP (anti-flood).
        const rl = hitRateLimit(clientIp(req), API_RATE_MAX, API_RATE_WINDOW_MS)
        if (rl.limited) {
          return NextResponse.json(
            { error: 'Trop de requêtes' },
            { status: 429, headers: { 'Retry-After': String(rl.retryAfterSec) } }
          )
        }
      }
      return await handler(req, (ctx ?? {}) as ApiRouteContext<P>)
    } catch (error) {
      console.error('[api]', error)
      return NextResponse.json({ error: 'Erreur interne du serveur' }, { status: 500 })
    }
  }
}
