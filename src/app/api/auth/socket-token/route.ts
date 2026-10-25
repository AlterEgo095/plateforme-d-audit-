/**
 * GET /api/auth/socket-token — jeton de session pour le handshake socket.io
 * (contrat worklog §K.3). Toute session authentifiée (tous rôles).
 * → {token:'v1.<payload>.<sig>'} — consommé par le frontend (handshake auth)
 * et vérifié par le moteur (parseSession équivalent, §K.2).
 */
import { NextResponse } from 'next/server'
import { requireAuth, signSession } from '@/lib/auth'
import { withApi } from '@/lib/route-handler'

export const dynamic = 'force-dynamic'

export const GET = withApi(async () => {
  const session = await requireAuth()
  if (session instanceof NextResponse) return session
  return NextResponse.json({
    token: signSession({ id: session.sub, username: session.username, role: session.role }),
  })
})
