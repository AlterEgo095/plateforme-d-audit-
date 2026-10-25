/**
 * PATCH /api/findings/[id] — changement de statut d'un constat (contrat worklog §F.16)
 * AUDITOR+ ; {status:FindingStatus} ; trace FINDING_STATUS_UPDATE « ancien → nouveau ».
 */
import { NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import { db } from '@/lib/db'
import { requireAuth } from '@/lib/auth'
import { writeAudit } from '@/lib/audit'
import { FINDING_STATUSES, toFindingDTO } from '@/lib/dto'
import { withApi } from '@/lib/route-handler'

export const dynamic = 'force-dynamic'

const patchSchema = z.object({
  status: z.enum(FINDING_STATUSES),
})

export const PATCH = withApi<{ id: string }>(async (req, { params }) => {
  const session = await requireAuth(['AUDITOR', 'ADMIN'])
  if (session instanceof NextResponse) return session

  const { id } = await params
  const raw = await req.json().catch(() => null)
  const parsed = patchSchema.safeParse(raw)
  if (!parsed.success) {
    return NextResponse.json(
      { error: 'Statut invalide — valeurs autorisées : OPEN, CONFIRMED, FALSE_POSITIVE, FIXED' },
      { status: 400 }
    )
  }

  const existing = await db.finding.findUnique({ where: { id } })
  if (!existing) {
    return NextResponse.json({ error: 'Constat introuvable' }, { status: 404 })
  }

  const updated = await db.finding.update({
    where: { id },
    data: { status: parsed.data.status },
  })
  await writeAudit(
    session.username,
    'FINDING_STATUS_UPDATE',
    id,
    `${existing.title} : ${existing.status} → ${parsed.data.status}`
  )
  return NextResponse.json({ finding: toFindingDTO(updated) })
})
