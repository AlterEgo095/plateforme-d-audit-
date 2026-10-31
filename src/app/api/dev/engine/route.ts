/**
 * /api/dev/engine — P5 (confort de développement sandbox) : démarre le
 * scan-engine (:3030) comme enfant du serveur Next.js si absent.
 *
 * DÉVELOPPEMENT UNIQUEMENT : en production l'engine est son propre service
 * Docker (ensureEngineRunning refuse sauf ENGINE_AUTO_SPAWN=1 explicite).
 * Idempotent — un appel redondant répond simplement l'état courant.
 * F-08 : endpoint d'administration — réservé au rôle ADMIN.
 */
import { NextResponse } from 'next/server'
import { requireAuth } from '@/lib/auth'
import { withApi } from '@/lib/route-handler'
import { ensureEngineRunning } from '@/lib/dev-engine'

export const dynamic = 'force-dynamic'

export const GET = withApi(async () => {
  const session = await requireAuth(['ADMIN'])
  if (session instanceof NextResponse) return session
  const result = await ensureEngineRunning()
  return NextResponse.json(result)
})

export const POST = GET
