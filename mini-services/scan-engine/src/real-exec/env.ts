/**
 * AuditForge — Configuration du sous-système d'exécution réelle (env).
 *
 * TOOL_EXECUTION_MODE :
 *   - "simulation" (défaut) : pipelines simulés uniquement (aucune cible touchée) ;
 *   - "auto" : exécution réelle SI l'outil est disponible (binaire + Docker),
 *     sinon bascule explicite en simulation (ligne de journal dédiée) ;
 *   - "real" : exécution réelle stricte — scan marqué FAILED si l'outil
 *     réel est indisponible.
 *
 * Les outils réels (Phantom, Basalt) ont besoin :
 *   - du binaire installé (pip install phantom-agent / pipx install basalt-scan) ;
 *   - de Docker (sandbox Kali Phantom, sandbox sans réseau Basalt) ;
 *   - d'un accès LLM (pont Z.ai llm-bridge ou endpoint OpenAI-compatible direct).
 */

export type ExecMode = "simulation" | "auto" | "real";

function parseMode(raw: string | undefined): ExecMode {
  const v = (raw ?? "").trim().toLowerCase();
  if (v === "real") return "real";
  if (v === "auto") return "auto";
  return "simulation";
}

export const REAL_EXEC = {
  mode: parseMode(process.env.TOOL_EXECUTION_MODE),

  /** Binaire Phantom (phantom-agent, CLI `phantom`). */
  phantomBin: process.env.PHANTOM_BIN ?? "phantom",
  /** Binaire Basalt (basalt-scan, CLI `basalt`). */
  basaltBin: process.env.BASALT_BIN ?? "basalt",

  /** Modèle LiteLLM transmis à Phantom (format provider/model). */
  phantomLlm: process.env.PHANTOM_LLM ?? "openai/glm-4.6",
  /** Clé API LLM transmise aux outils. */
  llmApiKey: process.env.LLM_API_KEY ?? "",
  /** Base URL OpenAI-compatible (pont llm-bridge ou Z.ai direct). */
  llmApiBase: process.env.LLM_API_BASE ?? "http://127.0.0.1:3031/v1",

  /** Timeout global d'un scan réel (minutes) — au-delà : échec. */
  timeoutMinutes: Number(process.env.REAL_SCAN_TIMEOUT_MIN ?? "180"),

  /** Durées estimées (ms) pour l'affichage de progression des scans réels. */
  estimatedMs: (tool: "PHANTOM" | "BASALT", profile: "QUICK" | "STANDARD" | "DEEP"): number => {
    const baseMinutes =
      (
        {
          PHANTOM: { QUICK: 15, STANDARD: 45, DEEP: 120 } as Record<string, number>,
          BASALT: { QUICK: 8, STANDARD: 20, DEEP: 45 } as Record<string, number>,
        } as Record<string, Record<string, number>>
      )[tool] ?? { QUICK: 20, STANDARD: 45, DEEP: 90 };
    return (baseMinutes[profile] ?? 45) * 60_000;
  },
} as const;

export function execMode(): ExecMode {
  return REAL_EXEC.mode;
}
