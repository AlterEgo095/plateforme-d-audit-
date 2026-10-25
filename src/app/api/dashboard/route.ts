/**
 * GET /api/dashboard — synthèse globale (contrat worklog §F.5)
 * Recalcule paresseusement les statuts de campagnes puis agrège les compteurs.
 */
import { NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { requireAuth } from '@/lib/auth'
import { refreshCampaignStatuses } from '@/lib/campaign-status'
import { SEVERITIES, TOOLS, toCampaignDTO, toScanDTO } from '@/lib/dto'
import { withApi } from '@/lib/route-handler'

export const dynamic = 'force-dynamic'

export const GET = withApi(async () => {
  const session = await requireAuth()
  if (session instanceof NextResponse) return session

  await refreshCampaignStatuses()

  const [activeScans, totalCampaigns, openFindings, criticalConfirmed, completedScans] =
    await Promise.all([
      db.scan.count({ where: { status: { in: ['QUEUED', 'RUNNING'] } } }),
      db.campaign.count(),
      db.finding.count({ where: { status: 'OPEN' } }),
      db.finding.count({
        where: { severity: 'CRITICAL', confidence: 'CONFIRMED', status: { not: 'FALSE_POSITIVE' } },
      }),
      db.scan.count({ where: { status: 'COMPLETED' } }),
    ])

  // Distribution par sévérité (hors faux positifs), les 5 sévérités toujours présentes.
  const severityGroups = await db.finding.groupBy({
    by: ['severity'],
    where: { status: { not: 'FALSE_POSITIVE' } },
    _count: { _all: true },
  })
  const severityDistribution = SEVERITIES.map((severity) => ({
    severity,
    count: severityGroups.find((g) => g.severity === severity)?._count._all ?? 0,
  }))

  // Distribution par outil : constats (hors faux positifs) + scans lancés.
  const [toolFindingGroups, toolScanGroups] = await Promise.all([
    db.finding.groupBy({
      by: ['tool'],
      where: { status: { not: 'FALSE_POSITIVE' } },
      _count: { _all: true },
    }),
    db.scan.groupBy({ by: ['tool'], _count: { _all: true } }),
  ])
  const toolDistribution = TOOLS.map((tool) => ({
    tool,
    findings: toolFindingGroups.find((g) => g.tool === tool)?._count._all ?? 0,
    scans: toolScanGroups.find((g) => g.tool === tool)?._count._all ?? 0,
  }))

  const [recentScanRows, campaignRows] = await Promise.all([
    db.scan.findMany({
      orderBy: { createdAt: 'desc' },
      take: 10,
      include: { campaign: { select: { name: true } } },
    }),
    db.campaign.findMany({
      orderBy: { createdAt: 'desc' },
      take: 5,
      include: {
        createdBy: { select: { username: true } },
        scans: { orderBy: { createdAt: 'asc' } },
      },
    }),
  ])

  return NextResponse.json({
    stats: { activeScans, totalCampaigns, openFindings, criticalConfirmed, completedScans },
    severityDistribution,
    toolDistribution,
    recentScans: recentScanRows.map((s) => toScanDTO(s, s.campaign.name)),
    campaigns: campaignRows.map(toCampaignDTO),
  })
})
