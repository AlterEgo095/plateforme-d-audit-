/**
 * GET /api/reports/[scanId] — rapport d'audit d'un scan terminé (contrat worklog §F.17)
 * Scan COMPLETED requis (sinon 409). Construit le rapport + stats et trace REPORT_GENERATED.
 */
import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { requireAuth } from '@/lib/auth'
import { writeAudit } from '@/lib/audit'
import { FINDING_STATUSES, SEVERITIES, sortFindings, toFindingDTO, toScanDTO } from '@/lib/dto'
import { withApi } from '@/lib/route-handler'
import type { FindingStatus, Profile, Severity, TargetType } from '@/lib/types'

export const dynamic = 'force-dynamic'

export const GET = withApi<{ scanId: string }>(async (_req, { params }) => {
  const session = await requireAuth()
  if (session instanceof NextResponse) return session

  const { scanId } = await params
  const scan = await db.scan.findUnique({
    where: { id: scanId },
    include: { campaign: true, findings: true },
  })
  if (!scan) {
    return NextResponse.json({ error: 'Scan introuvable' }, { status: 404 })
  }
  if (scan.status !== 'COMPLETED') {
    return NextResponse.json(
      { error: "Le rapport n'est disponible que pour un scan terminé" },
      { status: 409 }
    )
  }

  const findings = sortFindings(scan.findings)

  // Compteurs exhaustifs : toutes les sévérités / tous les statuts, même à 0.
  const bySeverity = Object.fromEntries(
    SEVERITIES.map((severity) => [
      severity,
      findings.filter((f) => f.severity === severity).length,
    ])
  ) as Record<Severity, number>
  const byStatus = Object.fromEntries(
    FINDING_STATUSES.map((status) => [
      status,
      findings.filter((f) => f.status === status).length,
    ])
  ) as Record<FindingStatus, number>

  const report = {
    scan: toScanDTO(scan, scan.campaign.name),
    campaign: {
      id: scan.campaign.id,
      name: scan.campaign.name,
      target: scan.campaign.target,
      targetType: scan.campaign.targetType as TargetType,
      profile: scan.campaign.profile as Profile,
      createdAt: scan.campaign.createdAt.toISOString(),
    },
    findings: findings.map(toFindingDTO),
    stats: {
      bySeverity,
      byStatus,
      confirmedCount: findings.filter((f) => f.confidence === 'CONFIRMED').length,
      sentinelCount: findings.filter((f) => f.sentinelTriggered).length,
    },
    generatedAt: new Date().toISOString(),
    generatedBy: session.username,
  }

  await writeAudit(
    session.username,
    'REPORT_GENERATED',
    scanId,
    `Rapport du scan ${scan.tool} — ${findings.length} constat(s)`
  )
  return NextResponse.json({ report })
})
