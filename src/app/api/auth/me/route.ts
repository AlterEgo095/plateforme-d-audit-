/**
 * GET /api/auth/me — session courante (contrat worklog §F.3)
 * → {user:UserDTO} | 401 {error:'Authentification requise'}
 */
import { NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { getSession } from '@/lib/auth'
import { toUserDTO } from '@/lib/dto'
import { withApi } from '@/lib/route-handler'

export const dynamic = 'force-dynamic'

export const GET = withApi(async () => {
  const session = await getSession()
  if (!session) {
    return NextResponse.json({ error: 'Authentification requise' }, { status: 401 })
  }
  // On recharge l'utilisateur pour refléter le rôle/MFA à jour.
  const user = await db.user.findUnique({ where: { id: session.sub } })
  if (!user) {
    return NextResponse.json({ error: 'Authentification requise' }, { status: 401 })
  }
  return NextResponse.json({ user: toUserDTO(user) })
})
