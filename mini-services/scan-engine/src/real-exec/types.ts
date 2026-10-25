/**
 * AuditForge — Types du sous-système d'exécution réelle.
 *
 * Un adaptateur réel exécute l'OUTIL AUTHENTIQUE (binaire CLI installé sur
 * l'hôte du moteur) au lieu du pipeline de simulation. Chaque adaptateur :
 *  - vérifie sa disponibilité (binaire + Docker + configuration LLM) ;
 *  - exécute l'outil en subprocess et diffuse les lignes de sortie via
 *    les callbacks `onLog` / `onPhase` (socket + base via le moteur) ;
 *  - retourne des constats structurés (RealFinding) persistés par le moteur.
 *
 * L'annulation est notifiée via `signal` (abort) : l'adaptateur doit tuer
 * ses processus enfants et nettoyer ses ressources.
 */

import type { LogLevel, Profile, TargetType, Tool } from "../types";

/** Contexte d'exécution fourni par le moteur à l'adaptateur. */
export interface RealAdapterContext {
  scanId: string;
  campaignId: string;
  tool: Tool;
  /** Cible brute : URL, URL de dépôt Git ou plage réseau. */
  target: string;
  targetType: TargetType;
  profile: Profile;
  /** Répertoire de travail temporaire dédié à ce scan (nettoyé par le moteur). */
  workdir: string;
  /** Abandon demandé (annulation opérateur ou arrêt gracieux du moteur). */
  signal: AbortSignal;
  /** Diffuse une ligne de journal (socket + persistance gérée par le moteur). */
  onLog: (message: string, level?: LogLevel, source?: string) => void | Promise<void>;
  /** Signale une phase + progression (0-100) — optionnel. */
  onPhase: (phase: string, progressPct?: number) => void | Promise<void>;
}

/** Constat normalisé produit par un adaptateur réel. */
export interface RealFinding {
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  confidence: "CONFIRMED" | "PROBABLE" | "UNVERIFIED";
  category: string;
  cve?: string | null;
  cvss?: number | null;
  location?: string;
  description: string;
  /** Preuves brutes (sortie outil, requêtes HTTP, extraits de code…). */
  evidence: string;
  /** Preuve de concept exécutable le cas échéant. */
  poc?: string;
  /** true si un PoC a réellement été exécuté avec succès (sentinelle/sandbox). */
  sentinelTriggered: boolean;
  remediation?: string;
}

export interface RealAvailability {
  available: boolean;
  /** Raison de l'indisponibilité (affichée dans les logs de scan / UI). */
  reason?: string;
  /** Version du binaire détectée, le cas échéant. */
  version?: string;
}

export interface RealToolAdapter {
  tool: Tool;
  checkAvailable(): Promise<RealAvailability>;
  run(ctx: RealAdapterContext): Promise<RealFinding[]>;
  /** Annulation proactive (le signal abort couvre le cas général). */
  cancel?(): void;
}
