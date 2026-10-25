/**
 * AuditForge — Registre des adaptateurs d'exécution réelle.
 *
 * Les 4 outils disposent d'un adaptateur réel :
 *   - PHANTOM (CLI phantom-agent + sandbox Docker Kali) ;
 *   - BASALT (CLI basalt-scan + sandbox Docker PoC) ;
 *   - DEEPAUDIT (plateforme distante pilotée par API REST) ;
 *   - REDAMON (plateforme distante pilotée par API REST).
 * Les plateformes doivent être déployées à côté du moteur et déclarées via
 * les variables DEEPAUDIT_API_URL / REDAMON_API_URL (voir README — section
 * « Exécution réelle »). Sans configuration, l'indisponibilité est signalée
 * honnêtement (tools-status + bascule simulation en mode auto).
 */

import { BasaltAdapter } from "./basalt";
import { DeepAuditAdapter } from "./deepaudit";
import { execMode, type ExecMode } from "./env";
import { PhantomAdapter } from "./phantom";
import { RedAmonAdapter } from "./redamon";
import type { RealToolAdapter } from "./types";
import type { Tool } from "../types";

const ADAPTERS: Partial<Record<Tool, () => RealToolAdapter>> = {
  PHANTOM: () => new PhantomAdapter(),
  BASALT: () => new BasaltAdapter(),
  DEEPAUDIT: () => new DeepAuditAdapter(),
  REDAMON: () => new RedAmonAdapter(),
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
