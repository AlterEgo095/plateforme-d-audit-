/**
 * AuditForge — Configuration du sous-système d'exécution réelle (env).
 *
 * TOOL_EXECUTION_MODE :
 *   - "simulation" (défaut) : pipelines simulés uniquement (aucune cible touchée) ;
 *   - "auto" : exécution réelle SI l'outil est disponible (binaire + Docker ou
 *     plateforme distante joignable), sinon bascule explicite en simulation
 *     (ligne de journal dédiée) ;
 *   - "real" : exécution réelle stricte — scan marqué FAILED si l'outil
 *     réel est indisponible.
 *
 * Deux familles d'outils réels :
 *   - CLI locales (Phantom, Basalt) : binaire pip + Docker (sandboxes) ;
 *   - plateformes distantes (DeepAudit, RedAmon) : API REST — les variables
 *     *_API_URL / *_EMAIL / *_PASSWORD pointent vers leurs instances.
 */

import type { Profile, Tool } from "../types";

export type ExecMode = "simulation" | "auto" | "real";

function parseMode(raw: string | undefined): ExecMode {
  const v = (raw ?? "").trim().toLowerCase();
  if (v === "real") return "real";
  if (v === "auto") return "auto";
  return "simulation";
}

/**
 * m5 (audit 8-a) : validation stricte du timeout — une valeur corrompue
 * (NaN/négative) désactiverait le timeout de runStreaming → scan réel
 * potentiellement infini. Borné à 24 h.
 */
function parseTimeoutMinutes(raw: string | undefined): number {
  const n = Number(raw ?? "180");
  if (!Number.isFinite(n) || n <= 0) return 180;
  return Math.min(n, 24 * 60);
}

export const REAL_EXEC = {
  mode: parseMode(process.env.TOOL_EXECUTION_MODE),

  /** Binaire Phantom (phantom-agent, CLI `phantom`). */
  phantomBin: process.env.PHANTOM_BIN ?? "phantom",
  /** Binaire Basalt (basalt-scan, CLI `basalt`). */
  basaltBin: process.env.BASALT_BIN ?? "basalt",

  /** Plateforme DeepAudit — base API (ex. http://deepaudit-backend:8000). */
  deepauditUrl: (process.env.DEEPAUDIT_API_URL ?? "").trim(),
  deepauditEmail: (process.env.DEEPAUDIT_EMAIL ?? "").trim(),
  deepauditPassword: process.env.DEEPAUDIT_PASSWORD ?? "",

  /** Plateforme RedAmon — base webapp (ex. http://redamon-webapp:3000). */
  redamonUrl: (process.env.REDAMON_API_URL ?? "").trim(),
  redamonEmail: (process.env.REDAMON_EMAIL ?? "").trim(),
  redamonPassword: process.env.REDAMON_PASSWORD ?? "",

  /** Modèle LiteLLM transmis à Phantom (format provider/model). */
  phantomLlm: process.env.PHANTOM_LLM ?? "openai/glm-4.6",
  /** Clé API LLM transmise aux outils. */
  llmApiKey: process.env.LLM_API_KEY ?? "",
  /** Base URL OpenAI-compatible (pont llm-bridge ou Z.ai direct). */
  llmApiBase: process.env.LLM_API_BASE ?? "http://127.0.0.1:3031/v1",

  /** Timeout global d'un scan réel (minutes) — au-delà : échec (défaut 180, borné). */
  timeoutMinutes: parseTimeoutMinutes(process.env.REAL_SCAN_TIMEOUT_MIN),

  /** Durées estimées (ms) pour l'affichage de progression des scans réels. */
  estimatedMs: (tool: Tool, profile: Profile): number => {
    const baseMinutes =
      (
        {
          PHANTOM: { QUICK: 15, STANDARD: 45, DEEP: 120 } as Record<string, number>,
          BASALT: { QUICK: 8, STANDARD: 20, DEEP: 45 } as Record<string, number>,
          DEEPAUDIT: { QUICK: 20, STANDARD: 45, DEEP: 120 } as Record<string, number>,
          REDAMON: { QUICK: 25, STANDARD: 60, DEEP: 150 } as Record<string, number>,
        } as Record<string, Record<string, number>>
      )[tool] ?? { QUICK: 20, STANDARD: 45, DEEP: 90 };
    return (baseMinutes[profile] ?? 45) * 60_000;
  },
} as const;

export function execMode(): ExecMode {
  return REAL_EXEC.mode;
}
