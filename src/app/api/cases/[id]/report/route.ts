/**
 * /api/cases/[id]/report — Sprint 2 : rapport client agrégé du dossier.
 *
 * GET : toute session authentifiée — document { caseInfo, authorization,
 *       authorizationHistory, campaigns, findings, stats } : TOUTES les
 *       campagnes du dossier (scans inclus) et TOUTES leurs vulnérabilités
 *       (triées par sévérité desc, plafond 5000), stats agrégées
 *       (sévérité/statut/outil, confiance, sentinel). Premier générateur →
 *       statut dossier REPORTED (sauf CLOSED). Trace CASE_REPORT_GENERATED.
 */
import { NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { requireAuth } from '@/lib/auth'
import { writeAudit } from '@/lib/audit'
import {
  FINDING_STATUSES,
  SEVERITIES,
  isAuthorizationActive,
  sortFindings,
  toAuthorizationDTO,
  toCaseDTO,
  toFindingDTO,
  toScanDTO,
} from '@/lib/dto'
import { withApi } from '@/lib/route-handler'
import type { FindingStatus, Profile, Severity, TargetType } from '@/lib/types'

export const dynamic = 'force-dynamic'

export const GET = withApi<{ id: string }>(async (_req, { params }) => {
  const session = await requireAuth()
  if (session instanceof NextResponse) return session

  const { id } = await params
  const kase = await db.case.findUnique({
    where: { id },
    include: {
      createdBy: { select: { username: true } },
      authorizations: { orderBy: { signedAt: 'desc' } },
      campaigns: {
        orderBy: { createdAt: 'asc' },
        take: 100,
        include: { createdBy: { select: { username: true } }, scans: { orderBy: { createdAt: 'asc' } } },
      },
    },
  })
  if (!kase) {
    return NextResponse.json({ error: 'Dossier introuvable' }, { status: 404 })
  }

  const campaignIds = kase.campaigns.map((c) => c.id)
  const findingsRaw = campaignIds.length
    ? await db.finding.findMany({
        where: { scan: { campaignId: { in: campaignIds } } },
        take: 5000,
        orderBy: { createdAt: 'desc' },
      })
    : []
  const findings = sortFindings(findingsRaw)

  const bySeverity = Object.fromEntries(
    SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length])
  ) as Record<Severity, number>
  const byStatus = Object.fromEntries(
    FINDING_STATUSES.map((s) => [s, findings.filter((f) => f.status === s).length])
  ) as Record<FindingStatus, number>
  const byTool: Record<string, number> = {}
  for (const f of findings) {
    byTool[f.tool] = (byTool[f.tool] ?? 0) + 1
  }

  // Premier générateur du rapport → le dossier passe REPORTED (traçabilité
  // du cycle de vie), sauf s'il est déjà clôturé.
  let caseForDto = kase
  if (kase.status !== 'REPORTED' && kase.status !== 'CLOSED') {
    const updated = await db.case.update({
      where: { id },
      data: { status: 'REPORTED' },
      include: {
        createdBy: { select: { username: true } },
        authorizations: { orderBy: { signedAt: 'desc' } },
      },
    })
    // Le include `campaigns` reste celui du fetch initial (les campagnes
    // n'ont pas changé) — même forme pour toCaseDTO.
    caseForDto = { ...updated, campaigns: kase.campaigns }
  }

  const activeAuth = caseForDto.authorizations.find(isAuthorizationActive) ?? null

  await writeAudit(
    session.username,
    'CASE_REPORT_GENERATED',
    caseForDto.reference,
    `Rapport client — ${kase.campaigns.length} campagne(s), ${findings.length} constat(s)`
  )

  return NextResponse.json({
    report: {
      caseInfo: toCaseDTO(caseForDto),
      authorization: activeAuth ? toAuthorizationDTO(activeAuth) : null,
      authorizationHistory: caseForDto.authorizations.map(toAuthorizationDTO),
      campaigns: kase.campaigns.map((c) => ({
        id: c.id,
        name: c.name,
        target: c.target,
        targetType: c.targetType as TargetType,
        profile: c.profile as Profile,
        status: c.status,
        createdAt: c.createdAt.toISOString(),
        scans: c.scans.map((s) => toScanDTO(s)),
      })),
      findings: findings.map(toFindingDTO),
      stats: {
        total: findings.length,
        bySeverity,
        byStatus,
        byTool,
        confirmedCount: findings.filter((f) => f.confidence === 'CONFIRMED').length,
        sentinelCount: findings.filter((f) => f.sentinelTriggered).length,
      },
      generatedAt: new Date().toISOString(),
      generatedBy: session.username,
    },
  })
})
