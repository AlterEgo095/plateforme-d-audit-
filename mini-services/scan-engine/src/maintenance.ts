/**
 * AuditForge — maintenance périodique (P3, audit plateforme v2) : rétention des journaux.
 * ============================================================================
 * Problème : ScanLog croît sans borne (le moteur est verbeux pendant les scans
 * — une campagne DEEP peut générer des dizaines de milliers de lignes). Sur un
 * VPS, la base gonfle, les requêtes par scan ralentissent et le volume Docker
 * finit par saturer le disque — aucun `deleteMany` n'existait dans le projet.
 *
 * Politique (volontairement conservatrice) :
 *   - ScanLog : purgé au-delà de LOG_RETENTION_DAYS jours (défaut 30, 0 = désactivé).
 *     Les journaux d'un scan COMPLETED ancien n'ont plus de valeur opérationnelle ;
 *     les constats (Findings) — données métier — sont INTACTS.
 *   - AuditTrail : JAMAIS purgé (journal d'audit immuable — exigence fonctionnelle).
 *   - Scans/constats : jamais supprimés (la purge ne touche que les lignes de log).
 *
 * Exécution : un balayage au démarrage (après la récupération N.23/P0.5, hors du
 * chemin critique — non bloquant) puis toutes les 24 h. Les erreurs sont
 * journalisées et non fatales : la rétention ne doit jamais empêcher le moteur
 * de scanner. Le timer est `unref()` pour ne pas retenir le process à l'arrêt.
 */

import { db } from "./db";

const RETENTION_INTERVAL_MS = 24 * 60 * 60 * 1000; // balayage quotidien

/** Jours de conservation des ScanLog (0 = rétention désactivée). */
function retentionDays(): number {
  const raw = Number(process.env.LOG_RETENTION_DAYS ?? 30);
  if (!Number.isFinite(raw) || raw < 0) return 30;
  return Math.floor(raw);
}

/**
 * Un balayage de rétention. Retourne le nombre de lignes purgées, ou null si
 * la rétention est désactivée (LOG_RETENTION_DAYS=0).
 * Lève uniquement si la base est injoignable — l'appelant journalise.
 */
export async function runLogRetention(): Promise<{ deleted: number; days: number } | null> {
  const days = retentionDays();
  if (days === 0) return null;

  const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  // deleteMany par lot unique : SQLite gère très bien quelques dizaines de
  // milliers de lignes ; exécuté hors scan actif (boot + 04:xx quotidiens
  // relatifs au boot) le verrou d'écriture reste bref.
  const res = await db.scanLog.deleteMany({ where: { ts: { lt: cutoff } } });
  return { deleted: res.count, days };
}

/** Journalise un balayage (jamais fatal). */
async function sweep(reason: string): Promise<void> {
  try {
    const res = await runLogRetention();
    if (res === null) return; // désactivé — un seul log au boot suffit
    if (res.deleted > 0) {
      console.log(
        `[scan-engine] rétention (${reason}) : ${res.deleted} ligne(s) de journal > ${res.days} j purgée(s)`,
      );
    } else {
      console.log(`[scan-engine] rétention (${reason}) : rien à purger (> ${res.days} j)`);
    }
  } catch (err) {
    console.warn(`[scan-engine] rétention (${reason}) impossible:`, err);
  }
}

/**
 * Démarre la rétention : balayage immédiat (non bloquant) puis quotidien.
 * Retourne le timer (unref) — utile aux tests ; le moteur l'ignore.
 */
export function startLogRetentionScheduler(): NodeJS.Timeout | null {
  if (retentionDays() === 0) {
    console.log("[scan-engine] rétention des journaux désactivée (LOG_RETENTION_DAYS=0)");
    return null;
  }
  void sweep("boot");
  const timer = setInterval(() => void sweep("périodique"), RETENTION_INTERVAL_MS);
  timer.unref();
  return timer;
}
