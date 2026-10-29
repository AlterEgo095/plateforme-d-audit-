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
import { finalizeCampaignIfSettled } from "./campaign-finalize";
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
import { currentExecMode, getRealAdapter } from "./real-exec/index";
import { REAL_EXEC } from "./real-exec/env";
import { makeWorkdir, removeWorkdir } from "./real-exec/proc";
import { probeUrlTarget } from "./real-exec/arsenal";
import type { RealFinding, RealToolAdapter } from "./real-exec/types";
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

/** Paramètres d'exécution : la requête interne + le campaignId lu en base (N.22).
 * P5 : `sequential` (lu en base depuis Campaign.sequential) active la chaîne
 * d'outils — les scans d'une campagne séquentielle s'exécutent l'un après
 * l'autre (recon → DAST → exploitation), indépendamment des ressources libres. */
export type EngineRunParams = EngineRunRequest & { campaignId: string; sequential?: boolean };

// ─── Limites de ressources (P4 — audit v2) ────────────────────────────

/** Lit un entier d'environnement avec bornes (fallback défaut si absent/invalide). */
function envLimit(name: string, def: number, min: number): number {
  const n = Number(process.env[name]);
  return Number.isFinite(n) && n >= min ? Math.floor(n) : def;
}

/**
 * RF3 (audit v2) — seuil du watchdog de dispatch : un scan resté en file
 * (ou en tête de chaîne) côté moteur AU-DELÀ de ce délai ALORS que des
 * ressources sont libres signale un dispatch bloqué (pump coincé, erreur DB
 * répétée, set `advancing` jamais libéré). Le watchdog journalise l'état
 * (queuedSince, lastKick) puis force un re-dispatch direct.
 */
const QUEUE_WATCHDOG_MS = 5 * 60_000;

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

  /** P4 : file d'attente FIFO — les scans soumis au-delà du plafond y patientent. */
  private queue: Array<{ cfg: EngineRunParams; enqueuedAt: number }> = [];
  private pumping = false;
  /** RF3 : horodatage du dernier kick (journalisation watchdog). */
  private lastKickAt = 0;

  /**
   * P5 : chaînes séquentielles par campagne. `head` = prochain scan à démarrer
   * (pas encore en exécution) ; `pending` = la suite ordonnée. Le scan EN COURS
   * n'est pas dans la chaîne (il est dans running) — l'avancement est déclenché
   * par la fin de chaque scan (start().finally), le kick périodique, et submit.
   * Les entrées de chaîne gardent leur statut DB QUEUED (cohérence campaign-finalize).
   * RF3 : `headSince` horodate la mise en tête — détecte une chaîne bloquée.
   */
  private chains = new Map<
    string,
    { head: EngineRunParams | null; headSince: number; pending: EngineRunParams[] }
  >();
  /** Garde anti-entrée concurrente de advanceChain par campagne. */
  private advancing = new Set<string>();

  /** Plafond de scans exécutés en parallèle (protection VPS — MAX_CONCURRENT_SCANS). */
  readonly maxConcurrent: number;
  /** Capacité de la file d'attente (MAX_QUEUED_SCANS). */
  readonly maxQueued: number;
  private readonly bootAt = Date.now();

  constructor(
    maxConcurrent = envLimit("MAX_CONCURRENT_SCANS", 3, 1),
    maxQueued = envLimit("MAX_QUEUED_SCANS", 100, 1),
  ) {
    this.maxConcurrent = maxConcurrent;
    this.maxQueued = maxQueued;
  }

  /**
   * P4 : soumission d'un scan — démarrage immédiat si une ressource est libre,
   * sinon mise en file d'attente FIFO (dispatch à chaque libération). P5 : si
   * la campagne est séquentielle, le scan rejoint la chaîne d'outils (head ou
   * pending) et ne démarre que lorsque tous ses prédécesseurs sont terminaux.
   * Lève Error si le scan est déjà en cours/en file, ou si la file est saturée.
   * Retourne le statut d'exécution résultant ('RUNNING' | 'QUEUED').
   */
  submit(cfg: EngineRunParams): "RUNNING" | "QUEUED" {
    if (this.running.has(cfg.scanId) || this.queue.some((q) => q.cfg.scanId === cfg.scanId)) {
      throw new Error("scan already running or queued");
    }

    // ── P5 : campagne séquentielle (chaîne d'outils) ──
    if (cfg.sequential) {
      const chain = this.chains.get(cfg.campaignId);
      if (chain) {
        // Doublons dans la chaîne (head ou pending)
        if (chain.head?.scanId === cfg.scanId || chain.pending.some((p) => p.scanId === cfg.scanId)) {
          throw new Error("scan already running or queued");
        }
        // Saturation : la chaîne partage le budget de la file (protection mémoire)
        if (chain.pending.length + (chain.head ? 1 : 0) >= this.maxQueued) {
          throw new Error(
            `Chaîne séquentielle saturée (${this.maxQueued}) — augmentez MAX_QUEUED_SCANS`,
          );
        }
        chain.pending.push(cfg);
        return "QUEUED";
      }
      // Premier scan de la chaîne : démarre immédiatement si une ressource est
      // libre, sinon il devient la tête (lancée par advanceChain au prochain
      // déclencheur — kick 30 s, fin d'un autre scan, ou pump).
      this.chains.set(cfg.campaignId, { head: cfg, headSince: Date.now(), pending: [] });
      if (this.running.size < this.maxConcurrent) {
        this.advanceChain(cfg.campaignId);
        return "RUNNING"; // avance optimiste : le scan existait (vérifié en 404 par la route)
      }
      return "QUEUED";
    }

    if (this.running.size < this.maxConcurrent) {
      this.start(cfg);
      return "RUNNING";
    }
    if (this.queue.length >= this.maxQueued) {
      throw new Error(
        `File d'attente saturée (${this.maxQueued}) — augmentez MAX_QUEUED_SCANS ou attendez la fin des scans en cours`,
      );
    }
    this.queue.push({ cfg, enqueuedAt: Date.now() });
    return "QUEUED";
  }

  /**
   * P5 : démarre la tête de la chaîne séquentielle d'une campagne (après
   * re-vérification en base, comme pump : un scan annulé pendant son attente
   * est écarté). Un seul scan de la chaîne à la fois — l'appel suivant est
   * déclenché par la fin de ce scan. Récursion bornée (longueur de chaîne)
   * pour sauter les entrées écartées.
   */
  private advanceChain(campaignId: string): void {
    const chain = this.chains.get(campaignId);
    if (!chain || this.advancing.has(campaignId)) return;
    if (!chain.head) {
      if (chain.pending.length === 0) {
        this.chains.delete(campaignId);
        return;
      }
      // P5-fix (dispatch ordonné) : chaîne sans tête mais avec pending — le
      // /internal/run suivant est arrivé APRÈS le shift du démarrage précédent
      // (fenêtre entre les 2 vérifications DB et la prise de tête). Sans
      // promotion, ce retour anticipatif est atteint à CHAQUE déclencheur
      // (fin de scan, kick 30 s) : la chaîne reste bloquée pour toujours et
      // le watchdog ne surveille que les chaînes à tête non nulle.
      chain.head = chain.pending.shift() ?? null;
      chain.headSince = Date.now();
      if (!chain.head) return; // inatteignable (pending non vide ci-dessus)
    }
    if (this.running.size >= this.maxConcurrent) return; // réessayé au prochain déclencheur
    this.advancing.add(campaignId);
    void (async () => {
      try {
        const head = chain.head;
        if (!head) return;
        let status: string | null = null;
        try {
          const row = await db.scan.findUnique({
            where: { id: head.scanId },
            select: { status: true },
          });
          status = row?.status ?? null;
        } catch (err) {
          // DB brièvement occupée : tête conservée, retentée au prochain déclencheur
          console.warn(
            `[engine] chaîne : vérification de ${head.scanId} impossible — retentera plus tard`,
            err,
          );
          return;
        }
        if (this.running.size >= this.maxConcurrent) return; // occupé entre-temps
        // P5 (fix recouvrement) : un scan de CETTE campagne tourne-t-il encore ?
        // La global-concurrency seule ne suffit pas — le kick 30 s (ou tout
        // autre déclencheur) peut avancer la chaîne pendant qu'un scan de la
        // MÊME campagne est en cours. La base fait foi (aussi correct au boot).
        try {
          const active = await db.scan.count({
            where: { campaignId, status: "RUNNING" },
          });
          if (active > 0) return; // la chaîne attendra la fin du scan courant
        } catch {
          return; // DB occupée — réessai au prochain déclencheur
        }
        chain.head = chain.pending.shift() ?? null;
        chain.headSince = Date.now(); // RF3 : la nouvelle tête reprend son propre chrono
        if (status === "QUEUED") {
          this.start(head);
        } else {
          console.log(
            `[engine] chaîne : scan ${head.scanId} écarté (statut base : ${status ?? "inconnu"}) — avance au suivant`,
          );
          this.advanceChain(campaignId); // saute l'entrée écartée
        }
      } finally {
        this.advancing.delete(campaignId);
      }
    })();
  }

  /** P5 : avance toutes les chaînes (déclenché à chaque fin de scan et par kick). */
  private advanceAllChains(): void {
    for (const campaignId of this.chains.keys()) {
      this.advanceChain(campaignId);
    }
  }

  /** Démarre réellement un scan (ancien corps de run()).
   * RF3 : garde anti double-démarrage — le watchdog forçant un re-dispatch,
   * un pump/advanceChain "zombie" qui se réveillerait tardivement ne doit
   * JAMAIS relancer un scan déjà dans `running`. */
  private start(cfg: EngineRunParams): void {
    if (this.running.has(cfg.scanId)) {
      console.warn(`[engine] start : ${cfg.scanId} déjà en exécution — double démarrage évité`);
      return;
    }
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
        // P4 : une ressource vient de se libérer — dépile la file d'attente.
        // P5 : avance les chaînes séquentielles (le scan suivant d'une campagne
        // en chaîne démarre ici, et uniquement ici pour sa propre chaîne).
        this.pump();
        this.advanceAllChains();
      });
  }

  /**
   * P4 : dépile la file d'attente tant que des ressources sont libres.
   * Chaque entrée est re-vérifiée en base AVANT démarrage : un scan annulé
   * (CANCELLED), supprimé ou déjà terminal pendant son attente est écarté.
   * En cas d'erreur DB (SQLite brièvement occupé), la tête est CONSERVÉE et le
   * pump retentera au prochain déclencheur (fin de scan, submit, kick 30 s).
   */
  private pump(): void {
    if (this.pumping) return;
    this.pumping = true;
    void (async () => {
      try {
        while (this.running.size < this.maxConcurrent && this.queue.length > 0) {
          const head = this.queue[0];
          let status: string | null;
          try {
            const row = await db.scan.findUnique({
              where: { id: head.cfg.scanId },
              select: { status: true },
            });
            status = row?.status ?? null;
          } catch (err) {
            console.warn(
              `[engine] file : vérification de ${head.cfg.scanId} impossible — retentera plus tard`,
              err,
            );
            break; // tête conservée — nouvelle tentative au prochain déclencheur
          }
          this.queue.shift(); // vérification faite : l'entrée sort de la file (dans tous les cas)
          if (status === "QUEUED") {
            this.start(head.cfg);
          } else if (status !== null) {
            console.log(
              `[engine] file : scan ${head.cfg.scanId} écarté (statut base : ${status})`,
            );
          }
        }
      } finally {
        this.pumping = false;
      }
    })();
  }

  /** P4 : réveille le dispatch (timer de sécurité — file bloquée par une erreur DB).
   * P5 : réveille également les chaînes séquentielles en attente de ressources.
   * RF3 : journalisation systématique de l'état de dispatch (file, plus ancien
   * queuedSince, chaînes, occupation) — un blocage devient visible dans les
   * journaux AVANT que le watchdog n'intervienne. */
  kick(): void {
    this.lastKickAt = Date.now();
    const oldest = this.queue[0]?.enqueuedAt;
    if (this.queue.length > 0 || this.chains.size > 0) {
      const parts = [`running ${this.running.size}/${this.maxConcurrent}`];
      if (this.queue.length > 0) {
        parts.push(
          `file ${this.queue.length}/${this.maxQueued}`,
          `queuedSince ${Math.round((this.lastKickAt - (oldest ?? this.lastKickAt)) / 1000)}s`,
        );
      }
      if (this.chains.size > 0) parts.push(`chaînes ${this.chains.size}`);
      parts.push(`lastKick ${new Date(this.lastKickAt).toISOString()}`);
      console.log(`[engine] kick — ${parts.join(", ")}`);
    }
    if (this.queue.length > 0) this.pump();
    this.advanceAllChains();
  }

  /**
   * RF3 (audit v2) : watchdog de la file — détecte et débloque un dispatch
   * coincé. Signature du blocage : un scan en file OU en tête de chaîne depuis
   * plus de QUEUE_WATCHDOG_MS ALORS QUE des ressources sont libres (running <
   * maxConcurrent). Actions : journal ERROR avec queuedSince/lastKick, remise
   * à zéro des verrous internes (pumping/advancing) et re-dispatch forcé.
   * La garde anti double-démarrage de start() garantit l'innocuité si un
   * verrou "zombie" se réveillait plus tard.
   */
  watchdog(): void {
    const now = Date.now();
    // File FIFO — tête bloquée avec ressources libres ?
    const head = this.queue[0];
    if (head && this.running.size < this.maxConcurrent && now - head.enqueuedAt > QUEUE_WATCHDOG_MS) {
      const secs = Math.round((now - head.enqueuedAt) / 1000);
      console.error(
        `[engine] WATCHDOG — scan ${head.cfg.scanId} en file depuis ${secs}s avec ` +
          `${this.running.size}/${this.maxConcurrent} ressources occupées ` +
          `(dernier kick il y a ${Math.round((now - this.lastKickAt) / 1000)}s) : re-dispatch forcé`,
      );
      this.pumping = false; // déverrouille un pump coincé (async jamais retourné)
      this.pump();
    }
    // Chaînes séquentielles — tête bloquée avec ressources libres ?
    for (const [campaignId, chain] of this.chains) {
      if (
        chain.head &&
        this.running.size < this.maxConcurrent &&
        now - chain.headSince > QUEUE_WATCHDOG_MS
      ) {
        const secs = Math.round((now - chain.headSince) / 1000);
        console.error(
          `[engine] WATCHDOG — tête de chaîne ${chain.head.scanId} (campagne ${campaignId}) ` +
            `immobile depuis ${secs}s avec ${this.running.size}/${this.maxConcurrent} ` +
            `ressources occupées : avance forcée`,
        );
        this.advancing.delete(campaignId); // déverrouille un advanceChain coincé
        chain.headSince = now; // nouveau chrono (le re-dispatch est en cours)
        this.advanceChain(campaignId);
      }
    }
  }

  /**
   * Demande l'annulation : scan en cours → abort ; en file d'attente (P4) ou
   * dans une chaîne séquentielle (P5) → retiré. Retourne l'emplacement trouvé
   * (null si inconnu du moteur).
   */
  cancel(scanId: string): "running" | "queued" | null {
    const ctrl = this.running.get(scanId);
    if (ctrl) {
      ctrl.aborted = true;
      return "running";
    }
    const idx = this.queue.findIndex((q) => q.cfg.scanId === scanId);
    if (idx >= 0) {
      this.queue.splice(idx, 1);
      return "queued";
    }
    // P5 : retrait d'une chaîne séquentielle. Tête annulée → avance au suivant.
    for (const [campaignId, chain] of this.chains) {
      if (chain.head?.scanId === scanId) {
        chain.head = chain.pending.shift() ?? null;
        this.advanceChain(campaignId);
        return "queued";
      }
      const pi = chain.pending.findIndex((p) => p.scanId === scanId);
      if (pi >= 0) {
        chain.pending.splice(pi, 1);
        return "queued";
      }
    }
    return null;
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

  /** P4 : nombre de scans en attente de ressources. */
  queuedCount(): number {
    return this.queue.length;
  }

  /** P4 : durée de vie du process (s) — métriques /internal/health. */
  uptimeSeconds(): number {
    return Math.round((Date.now() - this.bootAt) / 1000);
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

    // ── Branchement exécution réelle vs simulation ──
    // mode "simulation" → chemin historique ; "auto" → réel si disponible,
    // sinon bascule explicite ; "real" → échec clair si indisponible.
    const mode = currentExecMode();
    if (mode !== "simulation") {
      const adapter = getRealAdapter(cfg.tool);
      if (adapter) {
        const avail = await adapter.checkAvailable();
        if (avail.available) {
          await this.runRealScan(cfg, ctrl, st, pushLog, flushPending, adapter, bounds[0].name);
          return;
        }
        if (mode === "real") {
          throw new Error(`Exécution réelle indisponible pour ${cfg.tool} : ${avail.reason ?? "environnement non préparé"}`);
        }
        pushLog(
          "WARN",
          "systeme",
          `Exécution réelle indisponible pour ${cfg.tool} (${avail.reason ?? "inconnue"}) — bascule en SIMULATION pour ce scan.`,
        );
      } else if (mode === "real") {
        throw new Error(
          `Aucun adaptateur réel enregistré pour ${cfg.tool} (vérifier la configuration du moteur).`,
        );
      } else {
        pushLog(
          "WARN",
          "systeme",
          `${cfg.tool} : adaptateur réel non implémenté (plateforme dédiée requise) — SIMULATION pour ce scan.`,
        );
      }
    }

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

    await this.finalizeCompleted(cfg, campaignId, t0, st, pushLog, flushPending, bounds[st.phaseIdx].name);
  }

  /**
   * Finalisation commune COMPLETED (simulation ET réel) : log de synthèse,
   * flush final, mise à jour DB avec 1 retry (N.25) puis événements —
   * bascule FAILED cohérente si la persistance échoue définitivement.
   */
  private async finalizeCompleted(
    cfg: EngineRunParams,
    campaignId: string,
    t0: number,
    st: RunState,
    pushLog: (level: LogLevel, source: string, message: string) => void,
    flushPending: () => Promise<void>,
    lastPhaseName: string,
  ): Promise<void> {
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
      // P0.5 : la campagne peut être terminale (plus aucun scan actif).
      await finalizeCampaignIfSettled(campaignId);
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
          lastPhaseName,
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
      // P0.5 : idem, même en cas d'échec de persistance du scan lui-même.
      await finalizeCampaignIfSettled(campaignId);
    }
  }

  // ── Exécution réelle (outils authentiques) ──

  /**
   * Exécute l'outil RÉEL via son adaptateur : diffusion des lignes de sortie,
   * progression temporelle heuristique, constats réels persistés puis
   * finalisation COMPLETED partagée. Annulation → kill du processus + CANCELLED.
   */
  private async runRealScan(
    cfg: EngineRunParams,
    ctrl: RunningEntry,
    st: RunState,
    pushLog: (level: LogLevel, source: string, message: string) => void,
    flushPending: () => Promise<void>,
    adapter: RealToolAdapter,
    initialPhase: string,
  ): Promise<void> {
    const t0 = Date.now();
    const campaignId = cfg.campaignId;
    const estMs = REAL_EXEC.estimatedMs(cfg.tool, cfg.profile);
    let lastPhase = initialPhase;

    const abortController = new AbortController();
    const cancelWatcher = setInterval(() => {
      if (ctrl.aborted && !abortController.signal.aborted) {
        pushLog("WARN", "systeme", "Annulation demandée — arrêt du processus réel…");
        adapter.cancel?.();
        abortController.abort();
      }
    }, 1000);

    let workdir: string | null = null;
    try {
      workdir = await makeWorkdir(cfg.scanId);
      pushLog(
        "INFO",
        "systeme",
        `MODE RÉEL — ${cfg.tool} sera exécuté authentiquement (adaptateur réel, profil ${cfg.profile}).`,
      );
      await flushPending();

      // Pré-vol (honnêteté des statuts) : une cible URL injoignable ne doit
      // ni produire un « COMPLETED — 0 constat » trompeur, ni laisser l'outil
      // griller son timeout global (ex. ffuf × wordlist sur un hôte mort).
      // Toute réponse HTTP — même 4xx/5xx — est considérée comme joignable.
      // Cibles GIT (dépôt local) et NETWORK (sonde outil-native) exemptées.
      if (cfg.targetType === "URL") {
        pushLog("INFO", "systeme", `Pré-vol : vérification de joignabilité de ${cfg.target}…`);
        await flushPending();
        const probe = await probeUrlTarget(cfg.target);
        if (!probe.ok) {
          pushLog("ERROR", "systeme", `Cible injoignable depuis le moteur — ${probe.detail.slice(0, 300)}`);
          await flushPending();
          throw new Error(
            `Cible injoignable depuis le moteur (${probe.detail.slice(0, 200)}) — ${cfg.tool} non exécuté.`,
          );
        }
        pushLog("INFO", "systeme", `Pré-vol OK — ${probe.detail}.`);
        await flushPending();
      }

      // Progression heuristique (temps écoulé / durée estimée) — plafonnée à 95 %.
      const ticker = setInterval(() => {
        const pct = Math.min(95, Math.round((100 * (Date.now() - t0)) / estMs));
        st.progress = pct;
        void (async () => {
          try {
            await db.scan.update({ where: { id: cfg.scanId }, data: { progress: pct, phase: lastPhase } });
          } catch {
            /* best effort — la persistance suivante resynchronisera */
          }
          this.emitUpdate(
            this.updateEvent(cfg, campaignId, "RUNNING", pct, lastPhase, st.findingsCount, st.criticalCount),
          );
        })();
      }, 3000);

      let findings: RealFinding[] = [];
      try {
        findings = await adapter.run({
          scanId: cfg.scanId,
          campaignId,
          tool: cfg.tool,
          target: cfg.target,
          targetType: cfg.targetType,
          profile: cfg.profile,
          workdir,
          signal: abortController.signal,
          onLog: async (message, level, source) => {
            pushLog(level ?? "TOOL", source ?? cfg.tool.toLowerCase(), message);
            if (st.pending.length >= 40) await flushPending();
          },
          onPhase: async (phase, pct) => {
            lastPhase = phase.slice(0, 64);
            if (typeof pct === "number") st.progress = Math.max(st.progress, Math.min(99, pct));
            try {
              await db.scan.update({
                where: { id: cfg.scanId },
                data: { phase: lastPhase, ...(typeof pct === "number" ? { progress: st.progress } : {}) },
              });
            } catch {
              /* best effort */
            }
            this.emitUpdate(
              this.updateEvent(cfg, campaignId, "RUNNING", st.progress, lastPhase, st.findingsCount, st.criticalCount),
            );
          },
        });
      } catch (err) {
        // Annulation opérateur pendant l'outil → CANCELLED (jamais FAILED).
        // Les adaptateurs lèvent en signalant l'abort à leurs processus /
        // plateformes distantes ; sans ce garde, une annulation légitime
        // serait comptabilisée comme un échec du moteur.
        if (ctrl.aborted || abortController.signal.aborted) {
          clearInterval(ticker);
          pushLog("INFO", "systeme", "Scan annulé pendant l'exécution réelle — finalisation CANCELLED.");
          await flushPending();
          await this.finalizeCancelled(cfg, campaignId, t0, st, lastPhase);
          return;
        }
        throw err;
      } finally {
        clearInterval(ticker);
      }

      // Fenêtre cancel→final (N.25) : l'annulation peut survenir pendant l'outil.
      if (ctrl.aborted) {
        await flushPending();
        await this.finalizeCancelled(cfg, campaignId, t0, st, lastPhase);
        return;
      }

      const created = await this.createRealFindings(cfg, findings, pushLog);
      st.findingsCount = created.count;
      st.criticalCount = created.critical;
      st.progress = 100;
      await flushPending();
      if (ctrl.aborted) {
        await flushPending();
        await this.finalizeCancelled(cfg, campaignId, t0, st, lastPhase);
        return;
      }
      await this.finalizeCompleted(cfg, campaignId, t0, st, pushLog, flushPending, lastPhase);
    } finally {
      clearInterval(cancelWatcher);
      await removeWorkdir(workdir);
    }
  }

  /** Persiste les constats réels (mêmes champs que la simulation) + événements. */
  private async createRealFindings(
    cfg: EngineRunParams,
    findings: RealFinding[],
    pushLog: (level: LogLevel, source: string, message: string) => void,
  ): Promise<{ count: number; critical: number }> {
    let count = 0;
    let critical = 0;

    for (const f of findings) {
      try {
        const row = await db.finding.create({
          data: {
            scanId: cfg.scanId,
            tool: cfg.tool,
            title: f.title.slice(0, 500),
            severity: f.severity,
            confidence: f.confidence,
            category: (f.category || "général").slice(0, 120),
            cve: f.cve ?? null,
            cvss: f.cvss ?? null,
            location: f.location?.slice(0, 500) ?? null,
            description: f.description,
            evidence: f.evidence,
            poc: f.poc ?? "",
            sentinelTriggered: f.sentinelTriggered,
            status: "OPEN",
            remediation: f.remediation ?? null,
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

        if (f.sentinelTriggered) {
          pushLog(
            "SUCCESS",
            "sentinelle",
            `PoC exécuté avec succès — « ${f.title} » confirmé par l'outil réel.`,
          );
        }
        count += 1;
        if (f.severity === "CRITICAL") critical += 1;
      } catch (err) {
        console.error(`[scan-engine] création du constat réel impossible pour ${cfg.scanId}:`, err);
      }
    }

    try {
      await db.scan.update({
        where: { id: cfg.scanId },
        data: { findingsCount: count, criticalCount: critical },
      });
    } catch (err) {
      console.warn(`[engine] mise à jour des compteurs de constats impossible pour ${cfg.scanId}`, err);
    }
    return { count, critical };
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
    // P0.5 : annulation = mise à jour terminale → campagne peut être finalisée.
    await finalizeCampaignIfSettled(campaignId);
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
    // P0.5 : échec = mise à jour terminale → campagne peut être finalisée.
    await finalizeCampaignIfSettled(campaignId);
  }

  private emitUpdate(ev: ScanUpdateEvent): void {
    io().emit("scan:update", ev);
  }
}
