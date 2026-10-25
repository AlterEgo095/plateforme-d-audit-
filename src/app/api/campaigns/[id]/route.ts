/**
 * /api/campaigns/[id] — détail et suppression (contrats worklog §F.8, §F.9 ; §L.11)
 * GET    : toute session authentifiée
 * DELETE : ADMIN uniquement (cascade) — 409 si des scans QUEUED/RUNNING existent.
 */
import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { requireAuth } from '@/lib/auth'
import { writeAudit } from '@/lib/audit'
import { toCampaignDTO } from '@/lib/dto'
import { withApi } from '@/lib/route-handler'

export const dynamic = 'force-dynamic'

const includeFull = {
  createdBy: { select: { username: true } },
  scans: { orderBy: { createdAt: 'asc' as const } },
}

// ─── GET /api/campaigns/[id] ─────────────────────────────────────────

export const GET = withApi<{ id: string }>(async (_req, { params }) => {
  const session = await requireAuth()
  if (session instanceof NextResponse) return session

  const { id } = await params
  const campaign = await db.campaign.findUnique({ where: { id }, include: includeFull })
  if (!campaign) {
    return NextResponse.json({ error: 'Campagne introuvable' }, { status: 404 })
  }
  return NextResponse.json({ campaign: toCampaignDTO(campaign) })
})

// ─── DELETE /api/campaigns/[id] ──────────────────────────────────────

export const DELETE = withApi<{ id: string }>(async (_req, { params }) => {
  const session = await requireAuth(['ADMIN'])
  if (session instanceof NextResponse) return session

  const { id } = await params
  const campaign = await db.campaign.findUnique({
    where: { id },
    include: { _count: { select: { scans: true } } },
  })
  if (!campaign) {
    return NextResponse.json({ error: 'Campagne introuvable' }, { status: 404 })
  }

  // Interdiction de supprimer une campagne avec des scans en cours ou en attente (§L.11).
  const activeScans = await db.scan.count({
    where: { campaignId: id, status: { in: ['QUEUED', 'RUNNING'] } },
  })
  if (activeScans > 0) {
    return NextResponse.json(
      { error: 'Impossible de supprimer : des scans sont en cours ou en attente' },
      { status: 409 }
    )
  }

  // Suppression en cascade : Scan → Finding/ScanLog (onDelete: Cascade)
  await db.campaign.delete({ where: { id } })
  await writeAudit(
    session.username,
    'CAMPAIGN_DELETE',
    campaign.name,
    `Campagne supprimée avec ${campaign._count.scans} scan(s) associé(s)`
  )
  return NextResponse.json({ ok: true })
})
