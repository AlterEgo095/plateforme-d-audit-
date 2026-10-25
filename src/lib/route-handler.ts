/**
 * AuditForge — Wrapper d'erreurs pour les route handlers (contrat worklog §L.7)
 *
 * `withApi` enveloppe le handler exporté d'une route : toute exception non
 * interceptée (SQLITE_BUSY, panne DB, bug imprévu…) est journalisée puis
 * transformée en 500 {error:'Erreur interne du serveur'} (contrat §F).
 *
 * Les réponses d'erreur métier déjà codées dans les routes (401/403/404/409/428/400)
 * sont renvoyées telles quelles — le wrapper ne sert qu'aux imprévus.
 *
 * Usage :
 * - route dynamique : `export const GET = withApi<{ id: string }>(async (req, { params }) => {...})`
 * - route statique  : `export const GET = withApi(async (req) => {...})`
 */
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

/** Contexte d'une route dynamique (params Promise, Next 16). */
export interface ApiRouteContext<P extends Record<string, string>> {
  params: Promise<P>
}

export function withApi<P extends Record<string, string> = Record<string, string>>(
  handler: (req: NextRequest, ctx: ApiRouteContext<P>) => Promise<NextResponse>
): (req: NextRequest, ctx?: unknown) => Promise<NextResponse> {
  return async (req, ctx) => {
    try {
      return await handler(req, (ctx ?? {}) as ApiRouteContext<P>)
    } catch (error) {
      console.error('[api]', error)
      return NextResponse.json({ error: 'Erreur interne du serveur' }, { status: 500 })
    }
  }
}
