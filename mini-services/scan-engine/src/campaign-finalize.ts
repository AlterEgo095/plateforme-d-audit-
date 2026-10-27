/**
 * AuditForge — finalisation des campagnes côté moteur (P0.5 audit v2).
 *
 * Problème corrigé : aucune transition campagne → statut terminal n'existait
 * côté moteur — une campagne restait RUNNING à jamais dès que tous ses scans
 * étaient terminés (campagnes « orphelines » observées en prod : cmvps3ssr0,
 * cmvqu8pwz0). La fonction est appelée :
 *   - après chaque mise à jour terminale d'un scan (COMPLETED/FAILED/CANCELLED) ;
 *   - au démarrage du moteur, pour réconcilier les campagnes RUNNING déjà
 *     orphelines (self-healing, y compris celles créées avant ce fix).
 *
 * Règles terminales (miroir app §L.12, avec décision pour les cas mixtes) :
 *   - tous CANCELLED              → CANCELLED
 *   - au moins un COMPLETED       → COMPLETED (mélange FAILED+COMPLETED inclus :
 *                                   des résultats exploitables existent)
 *   - au moins un FAILED          → FAILED
 * Seules les campagnes RUNNING sont modifiées (jamais de réactivation).
 */

import { db } from "./db";

export type CampaignTerminalStatus = "COMPLETED" | "FAILED" | "CANCELLED";

/** Statut terminal dérivé des statuts (tous terminaux) des scans d'une campagne. */
export function deriveCampaignTerminalStatus(
  statuses: string[],
): CampaignTerminalStatus | null {
  if (statuses.length === 0) return null;
  if (statuses.every((s) => s === "CANCELLED")) return "CANCELLED";
  if (statuses.includes("COMPLETED")) return "COMPLETED";
  if (statuses.includes("FAILED")) return "FAILED";
  return null;
}

/**
 * Finalise la campagne si aucun de ses scans n'est plus actif
 * (QUEUED/RUNNING). Retourne true si le statut a été mis à jour.
 */
export async function finalizeCampaignIfSettled(campaignId: string): Promise<boolean> {
  if (!campaignId) return false;
  try {
    const active = await db.scan.count({
      where: { campaignId, status: { in: ["QUEUED", "RUNNING"] } },
    });
    if (active > 0) return false;

    const scans = await db.scan.findMany({
      where: { campaignId },
      select: { status: true },
    });
    if (scans.length === 0) return false;

    const target = deriveCampaignTerminalStatus(scans.map((s) => s.status));
    if (!target) return false;

    const camp = await db.campaign.findUnique({
      where: { id: campaignId },
      select: { status: true },
    });
    // Seules les campagnes RUNNING sont modifiées (jamais de réactivation) ;
    // un statut déjà terminal n'est jamais réécrit (target ≠ RUNNING par
    // construction — voir deriveCampaignTerminalStatus).
    if (!camp || camp.status !== "RUNNING") return false;

    await db.campaign.update({ where: { id: campaignId }, data: { status: target } });
    console.log(`[scan-engine] campagne ${campaignId} finalisée → ${target}`);
    return true;
  } catch (err) {
    console.warn(`[scan-engine] finalisation campagne ${campaignId} impossible:`, err);
    return false;
  }
}

/**
 * Réconciliation au démarrage : finalise toutes les campagnes RUNNING
 * restées sans scan actif (orphelines d'un redémarrage ou d'un bug antérieur).
 */
export async function reconcileStaleCampaigns(): Promise<number> {
  try {
    const camps = await db.campaign.findMany({
      where: { status: "RUNNING" },
      select: { id: true },
    });
    let fixed = 0;
    for (const c of camps) {
      const updated = await finalizeCampaignIfSettled(c.id);
      if (updated) fixed += 1;
    }
    if (fixed > 0) {
      console.log(`[scan-engine] réconciliation : ${fixed} campagne(s) RUNNING orpheline(s) finalisée(s)`);
    }
    return fixed;
  } catch (err) {
    console.warn("[scan-engine] réconciliation des campagnes impossible:", err);
    return 0;
  }
}
