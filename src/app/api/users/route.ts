/**
 * GET /api/users — liste des comptes (ADMIN uniquement, contrat worklog §F.4)
 * → {users:UserDTO[]} triés par nom d'utilisateur
 */
import { NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { requireAuth } from '@/lib/auth'
import { toUserDTO } from '@/lib/dto'
import { withApi } from '@/lib/route-handler'

export const dynamic = 'force-dynamic'

export const GET = withApi(async () => {
  const session = await requireAuth(['ADMIN'])
  if (session instanceof NextResponse) return session

  const users = await db.user.findMany({ orderBy: { username: 'asc' } })
  return NextResponse.json({ users: users.map(toUserDTO) })
})
