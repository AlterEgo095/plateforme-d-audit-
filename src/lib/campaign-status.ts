/**
 * AuditForge — Statut dérivé des campagnes (recalcul paresseux, worklog §F)
 *
 * Les campagnes ne portent pas leur statut « calculé » de façon fiable : on le
 * déduit des statuts de leurs scans, puis on met à jour la base quand le statut
 * stocké diverge. Appelé par GET /api/dashboard, /api/campaigns et /api/scans.
 */
import { db } from '@/lib/db'
import type { CampaignStatus } from '@/lib/types'

/**
 * Statut déterministe à partir des statuts des scans (contrat worklog §L.12) :
 * - ≥ 1 scan QUEUED/RUNNING  → RUNNING
 * - aucun scan               → DRAFT
 * - tous CANCELLED           → CANCELLED
 * - tous FAILED              → FAILED
 * - ≥ 1 COMPLETED, 0 FAILED  → COMPLETED
 * - sinon                    → statut courant inchangé
 */
export function deriveCampaignStatus(
  scanStatuses: string[],
  current: CampaignStatus
): CampaignStatus | 'DRAFT' {
  if (scanStatuses.some((s) => s === 'QUEUED' || s === 'RUNNING')) return 'RUNNING'
  if (scanStatuses.length === 0) return 'DRAFT'
  if (scanStatuses.every((s) => s === 'CANCELLED')) return 'CANCELLED'
  if (scanStatuses.every((s) => s === 'FAILED')) return 'FAILED'
  if (scanStatuses.some((s) => s === 'COMPLETED') && !scanStatuses.some((s) => s === 'FAILED')) {
    return 'COMPLETED'
  }
  return current
}

/** Recalcule le statut de toutes les campagnes et met à jour celles qui divergent. */
export async function refreshCampaignStatuses(): Promise<void> {
  try {
    const campaigns = await db.campaign.findMany({
      select: { id: true, status: true, scans: { select: { status: true } } },
    })
    for (const campaign of campaigns) {
      if (campaign.scans.length === 0) continue // pas de scan → on conserve le statut (DRAFT)
      const derived = deriveCampaignStatus(
        campaign.scans.map((s) => s.status),
        campaign.status as CampaignStatus
      )
      if (derived !== campaign.status) {
        await db.campaign.update({ where: { id: campaign.id }, data: { status: derived } })
      }
    }
  } catch (error) {
    // meilleur effort : le recalcul ne doit jamais bloquer une lecture
    console.error('[campaign-status] recalcul des statuts impossible', error)
  }
}
