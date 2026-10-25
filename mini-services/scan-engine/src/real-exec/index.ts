/**
 * AuditForge — Registre des adaptateurs d'exécution réelle.
 *
 * Adaptateurs réels livrés : PHANTOM (CLI phantom-agent), BASALT (CLI
 * basalt-scan). DEEPAUDIT et REDAMON restent en simulation tant que leurs
 * plateformes Docker respectives ne sont pas déployées à côté du moteur
 * (procédure documentée dans le README — section « Exécution réelle »).
 */

import { BasaltAdapter } from "./basalt";
import { execMode, type ExecMode } from "./env";
import { PhantomAdapter } from "./phantom";
import type { RealToolAdapter } from "./types";
import type { Tool } from "../types";

const ADAPTERS: Partial<Record<Tool, () => RealToolAdapter>> = {
  PHANTOM: () => new PhantomAdapter(),
  BASALT: () => new BasaltAdapter(),
};

/** Retourne l'adaptateur réel de l'outil, ou null si non implémenté. */
export function getRealAdapter(tool: Tool): RealToolAdapter | null {
  const factory = ADAPTERS[tool];
  return factory ? factory() : null;
}

/** Outils disposant d'un adaptateur réel (même si l'environnement n'est pas prêt). */
export function realCapableTools(): Tool[] {
  return Object.keys(ADAPTERS) as Tool[];
}

export function currentExecMode(): ExecMode {
  return execMode();
}

export { execMode } from "./env";
export type { ExecMode } from "./env";
export type { RealAdapterContext, RealAvailability, RealFinding, RealToolAdapter } from "./types";
