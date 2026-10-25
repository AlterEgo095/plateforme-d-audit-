/**
 * GET /api/scans — liste des scans (contrat worklog §F.11)
 * Filtres optionnels ?campaignId= & ?status= (CSV autorisé, ex: ?status=RUNNING,QUEUED)
 * Statuts de campagnes recalculés paresseusement (sauf filtrage par campagne).
 */
import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { requireAuth } from '@/lib/auth'
import { refreshCampaignStatuses } from '@/lib/campaign-status'
import { SCAN_STATUSES, parseCsvParam, toScanDTO } from '@/lib/dto'
import { withApi } from '@/lib/route-handler'

export const dynamic = 'force-dynamic'

export const GET = withApi(async (req: NextRequest) => {
  const session = await requireAuth()
  if (session instanceof NextResponse) return session

  const searchParams = req.nextUrl.searchParams
  const campaignId = searchParams.get('campaignId')?.trim() || null
  const statuses = parseCsvParam(searchParams.get('status'), SCAN_STATUSES)
  if (statuses === 'invalid') {
    return NextResponse.json(
      { error: 'Statut invalide — valeurs autorisées : QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED' },
      { status: 400 }
    )
  }

  // Recalcul paresseux uniquement quand on ne regarde pas une campagne précise.
  if (!campaignId) {
    await refreshCampaignStatuses()
  }

  const scans = await db.scan.findMany({
    where: {
      ...(campaignId ? { campaignId } : {}),
      ...(statuses ? { status: { in: statuses } } : {}),
    },
    orderBy: { createdAt: 'desc' },
    take: 200,
    include: { campaign: { select: { name: true } } },
  })
  return NextResponse.json({ scans: scans.map((s) => toScanDTO(s, s.campaign.name)) })
})
