/**
 * AuditForge — Registre des adaptateurs d'exécution réelle.
 *
 * Plateformes / agents IA (adaptateurs dédiés) :
 *   - PHANTOM (CLI phantom-agent + sandbox Docker Kali) ;
 *   - BASALT (CLI basalt-scan + sandbox Docker PoC) ;
 *   - DEEPAUDIT (plateforme distante pilotée par API REST) ;
 *   - REDAMON (plateforme distante pilotée par API REST).
 *
 * P5 « Arsenal » — outils evergreen (adaptateurs génériques arsenal.ts) :
 *   - Recon : SUBFINDER, AMASS, HTTPX ;
 *   - DAST : NUCLEI, NIKTO, ZAP ;
 *   - SAST/SCA : SEMGREP, TRIVY, GITLEAKS ;
 *   - Exploitation : SQLMAP, FFUF.
 *
 * Sprint 1 « élargissement » :
 *   - DAST/CMS : WPSCAN (WordPress), DALFOX (XSS), TESTSSL (TLS) ;
 *   - Recon : WHATWEB (empreinte web), WAFW00F (détection WAF) ;
 *   - Exploitation : HYDRA (identifiants par défaut), JOHN (hashes faibles GIT).
 *
 * Les plateformes distantes doivent être déclarées via les variables
 * DEEPAUDIT_API_URL / REDAMON_API_URL (voir README — section « Exécution
 * réelle »). Les binaires arsenal sont détectés dans le PATH du moteur —
 * sans installation, l'indisponibilité est signalée honnêtement
 * (tools-status + bascule simulation en mode auto).
 */

import { ARSENAL_SPECS, makeArsenalAdapter, makeZapAdapter } from "./arsenal";
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
  // P5 — arsenal evergreen (framework générique + specs)
  SUBFINDER: () => makeArsenalAdapter(ARSENAL_SPECS.SUBFINDER),
  AMASS: () => makeArsenalAdapter(ARSENAL_SPECS.AMASS),
  HTTPX: () => makeArsenalAdapter(ARSENAL_SPECS.HTTPX),
  NUCLEI: () => makeArsenalAdapter(ARSENAL_SPECS.NUCLEI),
  NIKTO: () => makeArsenalAdapter(ARSENAL_SPECS.NIKTO),
  // RF2 (audit v2) : ZAP bascule automatiquement API REST (side-car compose,
  // ZAP_API_URL définie) ou binaire local (zap-baseline.py).
  ZAP: () => makeZapAdapter(),
  SEMGREP: () => makeArsenalAdapter(ARSENAL_SPECS.SEMGREP),
  TRIVY: () => makeArsenalAdapter(ARSENAL_SPECS.TRIVY),
  GITLEAKS: () => makeArsenalAdapter(ARSENAL_SPECS.GITLEAKS),
  SQLMAP: () => makeArsenalAdapter(ARSENAL_SPECS.SQLMAP),
  FFUF: () => makeArsenalAdapter(ARSENAL_SPECS.FFUF),
  // Sprint 1 — élargissement arsenal
  WPSCAN: () => makeArsenalAdapter(ARSENAL_SPECS.WPSCAN),
  DALFOX: () => makeArsenalAdapter(ARSENAL_SPECS.DALFOX),
  WHATWEB: () => makeArsenalAdapter(ARSENAL_SPECS.WHATWEB),
  TESTSSL: () => makeArsenalAdapter(ARSENAL_SPECS.TESTSSL),
  WAFW00F: () => makeArsenalAdapter(ARSENAL_SPECS.WAFW00F),
  HYDRA: () => makeArsenalAdapter(ARSENAL_SPECS.HYDRA),
  JOHN: () => makeArsenalAdapter(ARSENAL_SPECS.JOHN),
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
