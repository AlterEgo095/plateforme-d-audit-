/**
 * AuditForge — Journal d'audit (AuditTrail)
 *
 * `writeAudit` avale les erreurs (journalisation console) afin de pouvoir être
 * attendu (`await`) dans les routes sans jamais faire échouer la requête métier.
 * Actions normalisées (worklog §E) : LOGIN, LOGOUT, CAMPAIGN_CREATE,
 * CAMPAIGN_LAUNCH, SCAN_CANCEL, FINDING_STATUS_UPDATE, REPORT_GENERATED, SEED.
 */
import { db } from '@/lib/db'

export async function writeAudit(
  actor: string,
  action: string,
  resource: string,
  detail?: string
): Promise<void> {
  try {
    await db.auditTrail.create({
      data: {
        actor,
        action,
        resource,
        detail: detail ?? null,
      },
    })
  } catch (error) {
    console.error("[audit] écriture dans AuditTrail impossible", error)
  }
}
