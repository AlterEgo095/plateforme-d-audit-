/**
 * POST /api/scans/[id]/cancel — annulation d'un scan en cours (contrat worklog §F.14 ; §L.11)
 * AUDITOR+ ; updateMany conditionnel (status in QUEUED/RUNNING) pour éliminer la
 * course check-then-update ; count 0 → 409. Moteur prévenu (idempotent),
 * log WARN + audit SCAN_CANCEL conservés.
 */
import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { requireAuth } from '@/lib/auth'
import { writeAudit } from '@/lib/audit'
import { engineCancel } from '@/lib/engine-client'
import { toScanDTO } from '@/lib/dto'
import { withApi } from '@/lib/route-handler'

export const dynamic = 'force-dynamic'

export const POST = withApi<{ id: string }>(async (_req, { params }) => {
  const session = await requireAuth(['AUDITOR', 'ADMIN'])
  if (session instanceof NextResponse) return session

  const { id } = await params
  const existing = await db.scan.findUnique({
    where: { id },
    include: { campaign: { select: { name: true } } },
  })
  if (!existing) {
    return NextResponse.json({ error: 'Scan introuvable' }, { status: 404 })
  }

  // On prévient le moteur (le résultat est ignoré : le moteur peut aussi écrire CANCELLED).
  await engineCancel(id)

  // Mise à jour conditionnelle : seul un scan QUEUED/RUNNING peut passer CANCELLED.
  const now = new Date()
  const result = await db.scan.updateMany({
    where: { id, status: { in: ['QUEUED', 'RUNNING'] } },
    data: {
      status: 'CANCELLED',
      finishedAt: now,
      ...(existing.startedAt ? { durationMs: now.getTime() - existing.startedAt.getTime() } : {}),
    },
  })
  if (result.count === 0) {
    return NextResponse.json({ error: 'Le scan est déjà terminé' }, { status: 409 })
  }

  await db.scanLog.create({
    data: {
      scanId: id,
      ts: now,
      level: 'WARN',
      source: 'system',
      message: 'Scan annulé par un opérateur',
    },
  })
  await writeAudit(
    session.username,
    'SCAN_CANCEL',
    id,
    `${existing.tool} sur ${existing.target} (campagne « ${existing.campaign.name} »)`
  )

  // Scan rechargé après mise à jour pour la réponse.
  const fresh = await db.scan.findUnique({
    where: { id },
    include: { campaign: { select: { name: true } } },
  })
  return NextResponse.json({
    scan: toScanDTO(fresh ?? { ...existing, status: 'CANCELLED', finishedAt: now }, existing.campaign.name),
  })
})
