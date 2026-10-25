/**
 * GET /api/scans/[id] — détail d'un scan (contrat worklog §F.12)
 * → {scan:ScanDTO, campaign:{id,name,profile,target,targetType}, findings:FindingDTO[]}
 * Constats triés : sévérité desc (CRITICAL d'abord) puis createdAt desc.
 */
import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { requireAuth } from '@/lib/auth'
import { sortFindings, toFindingDTO, toScanDTO } from '@/lib/dto'
import { withApi } from '@/lib/route-handler'
import type { Profile, TargetType } from '@/lib/types'

export const dynamic = 'force-dynamic'

export const GET = withApi<{ id: string }>(async (_req, { params }) => {
  const session = await requireAuth()
  if (session instanceof NextResponse) return session

  const { id } = await params
  const scan = await db.scan.findUnique({
    where: { id },
    include: {
      campaign: { select: { id: true, name: true, profile: true, target: true, targetType: true } },
    },
  })
  if (!scan) {
    return NextResponse.json({ error: 'Scan introuvable' }, { status: 404 })
  }

  // m10 (audit 8-a) : réponse bornée — un scan réel très bavard ne peut pas
  // saturer la mémoire/le réseau (2000 constats max, tri applicatif ensuite).
  const findings = await db.finding.findMany({
    where: { scanId: id },
    take: 2000,
    orderBy: { createdAt: 'desc' },
  })

  return NextResponse.json({
    scan: toScanDTO(scan, scan.campaign.name),
    campaign: {
      id: scan.campaign.id,
      name: scan.campaign.name,
      profile: scan.campaign.profile as Profile,
      target: scan.campaign.target,
      targetType: scan.campaign.targetType as TargetType,
    },
    findings: sortFindings(findings).map(toFindingDTO),
  })
})
