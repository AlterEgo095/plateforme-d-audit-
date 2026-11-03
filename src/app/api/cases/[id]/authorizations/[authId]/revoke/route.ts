/**
 * /api/cases/[id]/authorizations/[authId]/revoke — Sprint 2 : révocation.
 *
 * POST : AUDITOR+ — { reason? } → attestation marquée révoquée (revokedAt =
 * maintenant). Effet immédiat : le garde de lancement (case-auth) refuse tout
 * nouveau scan tant qu'aucune autre autorisation active ne couvre la cible.
 * Le dossier non-clos repasse OPEN s'il n'a plus d'autorisation active.
 * Trace CASE_AUTHORIZATION_REVOKE.
 */
import { NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import { db } from '@/lib/db'
import { requireAuth } from '@/lib/auth'
import { writeAudit } from '@/lib/audit'
import { toAuthorizationDTO } from '@/lib/dto'
import { isAuthorizationActive } from '@/lib/dto'
import { withApi } from '@/lib/route-handler'

export const dynamic = 'force-dynamic'

const revokeSchema = z.object({
  reason: z.string().max(300).optional(),
})

export const POST = withApi<{ id: string; authId: string }>(async (req, { params }) => {
  const session = await requireAuth(['AUDITOR', 'ADMIN'])
  if (session instanceof NextResponse) return session

  const { id, authId } = await params
  const raw = await req.json().catch(() => ({}))
  const parsed = revokeSchema.safeParse(raw ?? {})
  if (!parsed.success) {
    return NextResponse.json({ error: 'Corps invalide — { reason? } attendu' }, { status: 400 })
  }

  const authorization = await db.caseAuthorization.findUnique({
    where: { id: authId },
  })
  if (!authorization || authorization.caseId !== id) {
    return NextResponse.json({ error: 'Autorisation introuvable' }, { status: 404 })
  }
  if (authorization.revokedAt) {
    return NextResponse.json(
      { error: 'Autorisation déjà révoquée' },
      { status: 409 }
    )
  }

  const now = new Date()
  const updated = await db.caseAuthorization.update({
    where: { id: authId },
    data: { revokedAt: now, revokedReason: parsed.data.reason?.trim() || null },
  })

  // Le dossier repasse OPEN si plus AUCUNE autorisation active ne subsiste
  // (sauf s'il est CLOSED — un dossier clos reste clos).
  const kase = await db.case.findUnique({
    where: { id },
    include: { authorizations: true },
  })
  if (kase && kase.status !== 'CLOSED') {
    const hasActive = kase.authorizations.some(
      (a) => a.id !== authId && isAuthorizationActive(a)
    )
    if (!hasActive && kase.status !== 'OPEN') {
      await db.case.update({ where: { id }, data: { status: 'OPEN' } })
    }
  }

  await writeAudit(
    session.username,
    'CASE_AUTHORIZATION_REVOKE',
    kase?.reference ?? id,
    `Autorisation ${authId.slice(0, 8)} révoquée` +
      (parsed.data.reason ? ` — motif : ${parsed.data.reason.trim().slice(0, 200)}` : '')
  )
  return NextResponse.json({ authorization: toAuthorizationDTO(updated) })
})
