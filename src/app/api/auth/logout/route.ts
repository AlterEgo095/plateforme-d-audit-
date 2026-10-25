/**
 * POST /api/auth/logout — déconnexion (contrat worklog §F.2)
 * Supprime le cookie de session et trace LOGOUT si une session existait.
 */
import { NextResponse } from 'next/server'
import { clearSessionCookie, getSession } from '@/lib/auth'
import { writeAudit } from '@/lib/audit'
import { withApi } from '@/lib/route-handler'

export const dynamic = 'force-dynamic'

export const POST = withApi(async () => {
  const session = await getSession()
  if (session) {
    await writeAudit(session.username, 'LOGOUT', 'session')
  }
  await clearSessionCookie()
  return NextResponse.json({ ok: true })
})
