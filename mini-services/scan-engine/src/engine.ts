/**
 * AuditForge — ScanEngine : boucle d'exécution simulée.
 *
 * - Exécute les scripts de logs par outil (templates.ts) en temps réel.
 * - Persiste progress/phase/logs/findings dans la base SQLite partagée (Prisma).
 * - Émet les événements socket.io : 'scan:update' / 'scan:done' (globaux),
 *   'scan:log' / 'scan:finding' (room `scan:{id}`).
 *
 * Robustesse (contrats N.25) :
 * - pertes de persistance de logs → console.warn + compteur droppedLogs,
 *   constat ERROR local en fin de run si pertes ;
 * - mise à jour finale COMPLETED → 1 retry (500 ms) puis bascule FAILED
 *   côté événements (cohérence event/DB) ;
 * - re-vérification de l'annulation avant la branche COMPLETED (fenêtre
 *   cancel→final) ;
 * - Map running nettoyée sur les 3 chemins (COMPLETED / CANCELLED / FAILED).
 *
 * L'instance socket.io est injectée via setIo() par index.ts afin d'éviter
 * tout import circulaire.
 */

import type { Server } from "socket.io";
import { db } from "./db";
import {
  effectiveFindingCount,
  FINDING_POOLS,
  PROFILE_SECONDS,
  SCRIPT_BUILDERS,
  TOOL_FACTORS,
  phaseBounds,
  type FindingTemplate,
  type PhaseBound,
} from "./templates";
// Import de TYPE uniquement (aucun cycle à l'exécution) — interface définie dans index.ts.
import type { ServerToClientEvents } from "./index";
import type {
  ClientToServerEvents,
  Confidence,
  EngineRunRequest,
  FindingDTO,
  FindingStatus,
  LogEntry,
  LogLevel,
  ScanDoneEvent,
  ScanFindingEvent,
  ScanLogEvent,
  ScanStatus,
  ScanUpdateEvent,
  Severity,
} from "./types";

/** Paramètres d'exécution : la requête interne + le campaignId lu en base (N.22). */
export type EngineRunParams = EngineRunRequest & { campaignId: string };

// ─── Utilitaires RNG déterministes ────────────────────────────────────

/** FNV-1a 32 bits — graine déterministe dérivée du scanId. */
export function hashString(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

// ─── Types internes ───────────────────────────────────────────────────

interface RunningEntry {
  aborted: boolean;
  /** Promesse résolue quand la boucle du scan est totalement terminée. */
  done: Promise<void>;
  resolveDone: () => void;
}

interface PendingLog {
  ts: Date;
  level: string;
  source: string;
  message: string;
}

interface RunState {
  phaseIdx: number;
  progress: number;
  findingsCount: number;
  criticalCount: number;
  findingsDone: boolean;
  lastFlush: number;
  pending: PendingLog[];
  /** N.25 : nombre d'événements de journal dont la persistance a échoué. */
  droppedLogs: number;
}

// ─── Injection socket.io (évite les imports circulaires) ──────────────

let ioInstance: Server<ClientToServerEvents, ServerToClientEvents> | null = null;

export function setIo(io: Server<ClientToServerEvents, ServerToClientEvents>): void {
  ioInstance = io;
}

function io(): Server<ClientToServerEvents, ServerToClientEvents> {
  if (!ioInstance) throw new Error("socket.io n'est pas initialisé");
  return ioInstance;
}

// ─── Sélection des constats ───────────────────────────────────────────

/**
 * Moitié déterministe (graine = hash du scanId) + moitié aléatoire.
 *
 * BASALT (contrat §I + N.26) : dès que la quantité voulue est ≥ 2, le template
 * UNVERIFIED (b6 — PoC non déclenché, sandbox sans réseau) est GARANTI puis le
 * reste est complété par des sentinelles mélangées ; want === 1 → sentinelle
 * simple (CONFIRMED). La quantité voulue est capée au pool via
 * effectiveFindingCount().
 *
 * Retour trié par sévérité décroissante (CRITICAL d'abord).
 */
function selectFindings(cfg: EngineRunRequest): FindingTemplate[] {
  const pool = FINDING_POOLS[cfg.tool];
  const want = effectiveFindingCount(cfg.tool, cfg.profile);
  const deck = pool.slice();
  const picked: FindingTemplate[] = [];
  const unverified = pool.find((t) => t.confidence === "UNVERIFIED") ?? null;
  const rng = mulberry32(hashString(cfg.scanId));

  const drawDeterministic = (n: number): void => {
    for (let i = 0; i < n && deck.length > 0; i++) {
      const idx = Math.floor(rng() * deck.length);
      picked.push(deck.splice(idx, 1)[0]);
    }
  };
  const drawRandom = (target: number): void => {
    while (picked.length < target && deck.length > 0) {
      const idx = Math.floor(Math.random() * deck.length);
      picked.push(deck.splice(idx, 1)[0]);
    }
  };

  if (cfg.tool === "BASALT" && unverified) {
    if (want >= 2) {
      // Garantie UNVERIFIED puis sentinelles mélangées.
      picked.push(unverified);
      const uvIdx = deck.indexOf(unverified);
      if (uvIdx >= 0) deck.splice(uvIdx, 1);
      drawDeterministic(Math.ceil(want / 2));
      drawRandom(want);
    } else {
      // want === 1 → sentinelle simple (CONFIRMED) : écarte le template UNVERIFIED.
      const sentinels = deck.filter((t) => t.confidence !== "UNVERIFIED");
      const chosen = sentinels.length > 0 ? sentinels : deck;
      if (chosen.length > 0) picked.push(chosen[Math.floor(rng() * chosen.length)]);
    }
  } else {
    drawDeterministic(Math.ceil(want / 2));
    drawRandom(want);
    // Outil non-BASALT (historique 2-b) : si un template UNVERIFIED existe dans
    // le pool et que la quantité est grande, forcer sa présence en fin de liste.
    if (unverified && want >= 4 && picked.length > 0 && !picked.includes(unverified)) {
      picked[picked.length - 1] = unverified;
    }
  }

  picked.sort((a, b) => (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9));
  return picked;
}

// ─── Moteur ───────────────────────────────────────────────────────────

export class ScanEngine {
  private running = new Map<string, RunningEntry>();

  /** Lance un scan. Lève Error('scan already running') si déjà en cours. */
  run(cfg: EngineRunParams): void {
    if (this.running.has(cfg.scanId)) throw new Error("scan already running");
    let resolveDone: () => void = () => undefined;
    const done = new Promise<void>((resolve) => {
      resolveDone = resolve;
    });
    const ctrl: RunningEntry = { aborted: false, done, resolveDone };
    this.running.set(cfg.scanId, ctrl);
    void this.runScan(cfg, ctrl)
      .catch((err) => this.failScan(cfg, err))
      .finally(() => {
        // Filet de sécurité (les 3 chemins nettoient déjà la Map — delete idempotent).
        this.running.delete(cfg.scanId);
        ctrl.resolveDone();
      });
  }

  /** Demande l'annulation d'un scan en cours. true si le scan était actif. */
  cancel(scanId: string): boolean {
    const ctrl = this.running.get(scanId);
    if (!ctrl) return false;
    ctrl.aborted = true;
    return true;
  }

  /**
   * Annule le scan puis attend sa finalisation effective (persistance CANCELLED)
   * dans la limite du délai — usage : arrêt gracieux (N.24).
   */
  async cancelAndWait(scanId: string, timeoutMs = 3000): Promise<void> {
    const ctrl = this.running.get(scanId);
    if (!ctrl) return;
    ctrl.aborted = true;
    await Promise.race([ctrl.done, this.sleep(timeoutMs)]);
  }

  /** Identifiants des scans actuellement exécutés. */
  activeScanIds(): string[] {
    return Array.from(this.running.keys());
  }

  runningCount(): number {
    return this.running.size;
  }

  // ── Boucle principale ──

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, Math.max(0, ms)));
  }

  private progressOf(t0: number, totalMs: number): number {
    return Math.min(99, Math.round((100 * (Date.now() - t0)) / totalMs));
  }

  private updateEvent(
    cfg: EngineRunParams,
    campaignId: string,
    status: ScanStatus,
    progress: number,
    phase: string,
    findingsCount: number,
    criticalCount: number,
  ): ScanUpdateEvent {
    return {
      scanId: cfg.scanId,
      campaignId,
      tool: cfg.tool,
      status,
      progress: Math.max(0, Math.min(100, Math.round(progress))),
      phase: phase.slice(0, 64),
      findingsCount,
      criticalCount,
    };
  }

  private async runScan(cfg: EngineRunParams, ctrl: RunningEntry): Promise<void> {
    const t0 = Date.now();
    const seed = hashString(cfg.scanId);

    // Durée totale : base profil (s) × facteur outil ±10 % de jitter (déterministe par scan)
    const jitterRng = mulberry32(seed);
    const totalMs = Math.round(
      PROFILE_SECONDS[cfg.profile] * TOOL_FACTORS[cfg.tool] * (0.9 + jitterRng() * 0.2) * 1000,
    );
    const bounds: PhaseBound[] = phaseBounds(cfg.tool, totalMs);

    // État initial en base — campaignId transmis par index.ts (lu en base, N.22)
    try {
      await db.scan.update({
        where: { id: cfg.scanId },
        data: { status: "RUNNING", startedAt: new Date(), progress: 0, phase: bounds[0].name },
      });
    } catch (err) {
      console.warn(`[engine] passage RUNNING impossible pour ${cfg.scanId}`, err);
      throw err; // → failScan (FAILED + log ERROR + événements)
    }
    const campaignId = cfg.campaignId;

    const st: RunState = {
      phaseIdx: 0,
      progress: 0,
      findingsCount: 0,
      criticalCount: 0,
      findingsDone: false,
      lastFlush: Date.now(),
      pending: [],
      droppedLogs: 0,
    };

    const pushLog = (level: LogLevel, source: string, message: string): void => {
      const log: LogEntry = {
        id: 0, // id live = 0 en socket (contrat §G) ; l'id réel est en base
        scanId: cfg.scanId,
        ts: new Date().toISOString(),
        level,
        source,
        message,
      };
      io().to(`scan:${cfg.scanId}`).emit("scan:log", { scanId: cfg.scanId, log });
      st.pending.push({ ts: new Date(log.ts), level, source, message });
    };

    const flushPending = async (): Promise<void> => {
      if (st.pending.length === 0) return;
      const chunk = st.pending.splice(0, st.pending.length);
      try {
        await db.scanLog.createMany({
          data: chunk.map((l) => ({
            scanId: cfg.scanId,
            ts: l.ts,
            level: l.level,
            source: l.source,
            message: l.message,
          })),
        });
      } catch (err) {
        // la base peut être momentanément verrouillée — N.25 : warn + compteur
        st.droppedLogs += chunk.length;
        console.warn(`[engine] persistance de ${chunk.length} log(s) impossible pour ${cfg.scanId}`, err);
      }
    };

    this.emitUpdate(this.updateEvent(cfg, campaignId, "RUNNING", 0, bounds[0].name, 0, 0));

    // Script de simulation (lignes triées, atMs strictement croissant)
    const script = SCRIPT_BUILDERS[cfg.tool]({
      target: cfg.target,
      targetType: cfg.targetType,
      profile: cfg.profile,
      totalMs,
      rng: mulberry32(seed),
    });

    for (let i = 0; i < script.length; i++) {
      const line = script[i];
      const wait = line.atMs - (Date.now() - t0);
      if (wait > 0) await this.sleep(wait);
      if (ctrl.aborted) break;

      pushLog(line.level, line.source, line.message);

      // Changement de phase : mise à jour immédiate en base + événement
      while (
        st.phaseIdx + 1 < bounds.length &&
        Date.now() - t0 >= bounds[st.phaseIdx + 1].startMs
      ) {
        st.phaseIdx += 1;
        st.progress = this.progressOf(t0, totalMs);
        try {
          await db.scan.update({
            where: { id: cfg.scanId },
            data: { phase: bounds[st.phaseIdx].name },
          });
        } catch (err) {
          console.warn(`[engine] mise à jour de phase impossible pour ${cfg.scanId}`, err);
        }
        this.emitUpdate(
          this.updateEvent(
            cfg,
            campaignId,
            "RUNNING",
            st.progress,
            bounds[st.phaseIdx].name,
            st.findingsCount,
            st.criticalCount,
          ),
        );
      }

      // Création des constats vers ~85 % d'avancement
      if (!st.findingsDone && Date.now() - t0 >= totalMs * 0.85) {
        st.findingsDone = true;
        const created = await this.createFindings(cfg, pushLog);
        st.findingsCount = created.count;
        st.criticalCount = created.critical;
        st.progress = this.progressOf(t0, totalMs);
        this.emitUpdate(
          this.updateEvent(
            cfg,
            campaignId,
            "RUNNING",
            st.progress,
            bounds[st.phaseIdx].name,
            st.findingsCount,
            st.criticalCount,
          ),
        );
      }

      // Flush périodique (~2 s de temps mur) : logs en lot + progression
      if (Date.now() - st.lastFlush >= 2000) {
        st.lastFlush = Date.now();
        await flushPending();
        st.progress = this.progressOf(t0, totalMs);
        try {
          await db.scan.update({
            where: { id: cfg.scanId },
            data: { progress: st.progress, phase: bounds[st.phaseIdx].name },
          });
        } catch (err) {
          console.warn(`[engine] mise à jour de progression impossible pour ${cfg.scanId}`, err);
        }
        this.emitUpdate(
          this.updateEvent(
            cfg,
            campaignId,
            "RUNNING",
            st.progress,
            bounds[st.phaseIdx].name,
            st.findingsCount,
            st.criticalCount,
          ),
        );
      }
    }

    // N.25 (P2) : re-vérification de l'annulation à la sortie de la boucle.
    if (ctrl.aborted) {
      await flushPending();
      await this.finalizeCancelled(cfg, campaignId, t0, st, bounds[st.phaseIdx].name);
      return;
    }

    // Flush final + constats si le scan était trop court pour atteindre 85 %
    await flushPending();
    if (!st.findingsDone) {
      const created = await this.createFindings(cfg, pushLog);
      st.findingsCount = created.count;
      st.criticalCount = created.critical;
    }

    // N.25 (P2) : fenêtre cancel→final — l'annulation peut survenir pendant la
    // création des constats / le flush ; re-vérifie AVANT la branche COMPLETED.
    if (ctrl.aborted) {
      await flushPending();
      await this.finalizeCancelled(cfg, campaignId, t0, st, bounds[st.phaseIdx].name);
      return;
    }

    const durationMs = Date.now() - t0;
    pushLog(
      "SUCCESS",
      "system",
      `Scan terminé en ${Math.round(durationMs / 1000)}s — ${st.findingsCount} vulnérabilités dont ${st.criticalCount} critique(s)`,
    );
    await flushPending();
    await this.notifyDroppedLogs(cfg, st);

    // Mise à jour finale COMPLETED — 1 essai + 1 retry après 500 ms (N.25).
    const finalData = {
      status: "COMPLETED",
      progress: 100,
      phase: "TERMINÉ",
      finishedAt: new Date(),
      durationMs,
      findingsCount: st.findingsCount,
      criticalCount: st.criticalCount,
    } as const;
    let completed = false;
    try {
      await db.scan.update({ where: { id: cfg.scanId }, data: finalData });
      completed = true;
    } catch (err) {
      console.warn(`[engine] finalisation DB échouée pour ${cfg.scanId} — retry dans 500 ms`, err);
      await this.sleep(500);
      try {
        await db.scan.update({ where: { id: cfg.scanId }, data: finalData });
        completed = true;
      } catch (err2) {
        console.error(`[scan-engine] finalisation DB impossible pour ${cfg.scanId} (2 tentatives):`, err2);
      }
    }

    if (completed) {
      this.emitUpdate(
        this.updateEvent(cfg, campaignId, "COMPLETED", 100, "TERMINÉ", st.findingsCount, st.criticalCount),
      );
      const done: ScanDoneEvent = {
        scanId: cfg.scanId,
        campaignId,
        tool: cfg.tool,
        status: "COMPLETED",
        durationMs,
        findingsCount: st.findingsCount,
        criticalCount: st.criticalCount,
      };
      io().emit("scan:done", done);
      this.running.delete(cfg.scanId);
    } else {
      // Cohérence event/DB : signale FAILED côté temps réel + best-effort en base.
      try {
        await db.scan.updateMany({
          where: { id: cfg.scanId, status: { in: ["RUNNING", "QUEUED"] } },
          data: { status: "FAILED", finishedAt: new Date(), durationMs },
        });
      } catch (err) {
        console.warn(`[engine] marquage FAILED en base impossible pour ${cfg.scanId}`, err);
      }
      this.emitUpdate(
        this.updateEvent(
          cfg,
          campaignId,
          "FAILED",
          st.progress,
          bounds[st.phaseIdx].name,
          st.findingsCount,
          st.criticalCount,
        ),
      );
      const done: ScanDoneEvent = {
        scanId: cfg.scanId,
        campaignId,
        tool: cfg.tool,
        status: "FAILED",
        durationMs,
        findingsCount: st.findingsCount,
        criticalCount: st.criticalCount,
      };
      io().emit("scan:done", done);
      this.running.delete(cfg.scanId);
    }
  }

  /** Constat local (socket + base, best effort) si des logs ont été perdus (N.25). */
  private async notifyDroppedLogs(cfg: EngineRunParams, st: RunState): Promise<void> {
    if (st.droppedLogs <= 0) return;
    const message = `${st.droppedLogs} événements de journal n'ont pu être persistés`;
    const log: LogEntry = {
      id: 0,
      scanId: cfg.scanId,
      ts: new Date().toISOString(),
      level: "ERROR",
      source: "system",
      message,
    };
    io().to(`scan:${cfg.scanId}`).emit("scan:log", { scanId: cfg.scanId, log });
    try {
      await db.scanLog.create({
        data: { scanId: cfg.scanId, ts: new Date(log.ts), level: "ERROR", source: "system", message },
      });
    } catch (err) {
      console.warn(`[engine] consignation des pertes de logs impossible pour ${cfg.scanId}`, err);
    }
  }

  // ── Création des constats ──

  private async createFindings(
    cfg: EngineRunParams,
    pushLog: (level: LogLevel, source: string, message: string) => void,
  ): Promise<{ count: number; critical: number }> {
    const templates = selectFindings(cfg);
    let count = 0;
    let critical = 0;

    for (const t of templates) {
      try {
        const row = await db.finding.create({
          data: {
            scanId: cfg.scanId,
            tool: cfg.tool,
            title: t.title,
            severity: t.severity,
            confidence: t.confidence,
            category: t.category,
            cve: t.cve ?? null,
            cvss: t.cvss,
            location: t.location,
            description: t.description,
            evidence: t.evidence,
            poc: t.poc,
            sentinelTriggered: t.sentinel,
            status: "OPEN",
            remediation: t.remediation,
          },
        });

        const finding: FindingDTO = {
          id: row.id,
          scanId: row.scanId,
          tool: cfg.tool,
          title: row.title,
          severity: row.severity as Severity,
          confidence: row.confidence as Confidence,
          category: row.category,
          cve: row.cve,
          cvss: row.cvss,
          location: row.location,
          description: row.description,
          evidence: row.evidence,
          poc: row.poc,
          sentinelTriggered: row.sentinelTriggered,
          status: row.status as FindingStatus,
          remediation: row.remediation,
          createdAt: row.createdAt.toISOString(),
        };
        const event: ScanFindingEvent = { scanId: cfg.scanId, finding };
        io().to(`scan:${cfg.scanId}`).emit("scan:finding", event);

        // BASALT : ligne de sentinelle exacte pour chaque PoC déclenché
        if (cfg.tool === "BASALT" && t.sentinel) {
          pushLog(
            "SUCCESS",
            "basalt-sentinel",
            `BASALT-POC-TRIGGERED — sentinelle détectée pour « ${t.title} » (PoC exécuté en sandbox sans réseau)`,
          );
        }

        count += 1;
        if (t.severity === "CRITICAL") critical += 1;
      } catch (err) {
        console.error(`[scan-engine] création du finding impossible pour ${cfg.scanId}:`, err);
      }
    }

    try {
      await db.scan.update({
        where: { id: cfg.scanId },
        data: { findingsCount: count, criticalCount: critical },
      });
    } catch (err) {
      // best effort — les compteurs seront resynchronisés à la fin
      console.warn(`[engine] mise à jour des compteurs de constats impossible pour ${cfg.scanId}`, err);
    }
    return { count, critical };
  }

  // ── Fin de scan : annulation ──

  private async finalizeCancelled(
    cfg: EngineRunParams,
    campaignId: string,
    t0: number,
    st: RunState,
    phase: string,
  ): Promise<void> {
    const durationMs = Date.now() - t0;
    const message = "Scan annulé par l'opérateur";

    const log: LogEntry = {
      id: 0,
      scanId: cfg.scanId,
      ts: new Date().toISOString(),
      level: "WARN",
      source: "system",
      message,
    };
    io().to(`scan:${cfg.scanId}`).emit("scan:log", { scanId: cfg.scanId, log });

    try {
      await db.scanLog.create({
        data: { scanId: cfg.scanId, ts: new Date(), level: "WARN", source: "system", message },
      });
    } catch (err) {
      st.droppedLogs += 1;
      console.warn(`[engine] persistance du log d'annulation impossible pour ${cfg.scanId}`, err);
    }
    try {
      await db.scan.update({
        where: { id: cfg.scanId },
        data: { status: "CANCELLED", finishedAt: new Date(), durationMs },
      });
    } catch (err) {
      console.error(`[scan-engine] annulation DB impossible pour ${cfg.scanId}:`, err);
    }
    await this.notifyDroppedLogs(cfg, st);

    this.emitUpdate(
      this.updateEvent(
        cfg,
        campaignId,
        "CANCELLED",
        st.progress,
        phase,
        st.findingsCount,
        st.criticalCount,
      ),
    );
    const done: ScanDoneEvent = {
      scanId: cfg.scanId,
      campaignId,
      tool: cfg.tool,
      status: "CANCELLED",
      durationMs,
      findingsCount: st.findingsCount,
      criticalCount: st.criticalCount,
    };
    io().emit("scan:done", done);
    this.running.delete(cfg.scanId);
  }

  // ── Fin de scan : échec ──

  private async failScan(cfg: EngineRunParams, err: unknown): Promise<void> {
    this.running.delete(cfg.scanId);
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[scan-engine] scan ${cfg.scanId} échoué : ${message}`);

    let campaignId = "";
    let progress = 0;
    let phase = "";
    let findingsCount = 0;
    let criticalCount = 0;
    let durationMs = 0;

    try {
      const scan = await db.scan.findUnique({ where: { id: cfg.scanId } });
      if (scan) {
        campaignId = cfg.campaignId || scan.campaignId;
        progress = scan.progress;
        phase = scan.phase;
        findingsCount = scan.findingsCount;
        criticalCount = scan.criticalCount;
        durationMs = scan.startedAt ? Math.max(0, Date.now() - scan.startedAt.getTime()) : 0;
        await db.scan.update({
          where: { id: cfg.scanId },
          data: { status: "FAILED", finishedAt: new Date(), durationMs },
        });
        const logMessage = `Échec du moteur : ${message}`;
        await db.scanLog.create({
          data: { scanId: cfg.scanId, ts: new Date(), level: "ERROR", source: "system", message: logMessage },
        });
        const log: LogEntry = {
          id: 0,
          scanId: cfg.scanId,
          ts: new Date().toISOString(),
          level: "ERROR",
          source: "system",
          message: logMessage,
        };
        const event: ScanLogEvent = { scanId: cfg.scanId, log };
        io().to(`scan:${cfg.scanId}`).emit("scan:log", event);
      }
    } catch (dbErr) {
      console.error("[scan-engine] failScan : mise à jour DB impossible:", dbErr);
    }

    this.emitUpdate(
      this.updateEvent(cfg, campaignId, "FAILED", progress, phase, findingsCount, criticalCount),
    );
    const done: ScanDoneEvent = {
      scanId: cfg.scanId,
      campaignId,
      tool: cfg.tool,
      status: "FAILED",
      durationMs,
      findingsCount,
      criticalCount,
    };
    io().emit("scan:done", done);
  }

  private emitUpdate(ev: ScanUpdateEvent): void {
    io().emit("scan:update", ev);
  }
}
