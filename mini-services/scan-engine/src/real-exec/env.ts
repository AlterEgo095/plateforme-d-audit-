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

  /**
   * Image Docker de la sandbox Kali de Phantom (défaut amont :
   * ghcr.io/usta0x001/phantom-sandbox:latest — variante enrichie :
   * auditforge/phantom-sandbox-plus). Vide = défaut amont.
   * ATTENTION : doit être transmis EXPLICITEMENT dans l'env du process
   * phantom (voir phantom.ts) — sanitizedEnv() (m7) ne forward que
   * l'allowlist + les variables déclarées par l'adaptateur.
   */
  phantomImage: (process.env.PHANTOM_IMAGE ?? "").trim(),
  /**
   * Modèle LiteLLM du compresseur mémoire de Phantom (résumé du contexte).
   * Défaut amont « DeepSeek-V3.2 » sans préfixe provider → litellm lève
   * « LLM Provider NOT provided » à CHAQUE compression (×2400 par scan,
   * fallback best-effort → 14.5M tokens d'input par scan). Doit être
   * transmis EXPLICITEMENT au process phantom (voir phantom.ts), même
   * mécanisme que PHANTOM_IMAGE. Vide = défaut amont.
   */
  phantomCompressorLlm: (process.env.PHANTOM_COMPRESSOR_LLM ?? "").trim(),
  /** Clé API LLM transmise aux outils. */
  llmApiKey: process.env.LLM_API_KEY ?? "",
  /** Base URL OpenAI-compatible (pont llm-bridge ou Z.ai direct). */
  llmApiBase: process.env.LLM_API_BASE ?? "http://127.0.0.1:3031/v1",

  /** Timeout global d'un scan réel (minutes) — au-delà : échec (défaut 180, borné). */
  timeoutMinutes: parseTimeoutMinutes(process.env.REAL_SCAN_TIMEOUT_MIN),

  // ── P5 « Arsenal » — binaires evergreen (surcharges par env) ─────────
  // Reconnaissance
  subfinderBin: (process.env.SUBFINDER_BIN ?? "subfinder").trim(),
  amassBin: (process.env.AMASS_BIN ?? "amass").trim(),
  httpxBin: (process.env.HTTPX_BIN ?? "httpx").trim(),
  // Scan dynamique (DAST)
  nucleiBin: (process.env.NUCLEI_BIN ?? "nuclei").trim(),
  niktoBin: (process.env.NIKTO_BIN ?? "nikto").trim(),
  /** Script d'automatisation OWASP ZAP (baseline CI) — mode binaire. */
  zapCommand: (process.env.ZAP_COMMAND ?? "zap-baseline.py").trim(),
  /**
   * RF2 (audit v2) : API REST du daemon ZAP (side-car compose
   * ghcr.io/zaproxy/zaproxy). Définie → l'adaptateur ZAP pilote l'API
   * (spider/passif/actif/alertes) au lieu du binaire local ; la
   * disponibilité est TRUE dès que l'API répond. Vide → mode binaire.
   */
  zapApiUrl: (process.env.ZAP_API_URL ?? "").trim().replace(/\/+$/, ""),
  /** Clé API du daemon ZAP (en-tête X-Zap-Api-Key). Vide si non protégé. */
  zapApiKey: (process.env.ZAP_API_KEY ?? "").trim(),
  // Analyse de code (SAST/SCA/secrets)
  semgrepBin: (process.env.SEMGREP_BIN ?? "semgrep").trim(),
  /** Règles Semgrep : « auto » (registre, réseau requis) ou chemin de règles local. */
  semgrepConfig: (process.env.SEMGREP_CONFIG ?? "auto").trim(),
  trivyBin: (process.env.TRIVY_BIN ?? "trivy").trim(),
  gitleaksBin: (process.env.GITLEAKS_BIN ?? "gitleaks").trim(),
  // Exploitation ciblée
  sqlmapBin: (process.env.SQLMAP_BIN ?? "sqlmap").trim(),
  ffufBin: (process.env.FFUF_BIN ?? "ffuf").trim(),
  /** Wordlist de ffuf — vérifiée à la disponibilité (manquante → outil honnêtement indisponible). */
  ffufWordlist: (process.env.FFUF_WORDLIST ?? "/usr/share/seclists/Discovery/Web-Content/common.txt").trim(),

  /** Durées estimées (ms) pour l'affichage de progression des scans réels. */
  estimatedMs: (tool: Tool, profile: Profile): number => {
    const baseMinutes =
      (
        {
          PHANTOM: { QUICK: 15, STANDARD: 45, DEEP: 120 } as Record<string, number>,
          BASALT: { QUICK: 8, STANDARD: 20, DEEP: 45 } as Record<string, number>,
          DEEPAUDIT: { QUICK: 20, STANDARD: 45, DEEP: 120 } as Record<string, number>,
          REDAMON: { QUICK: 25, STANDARD: 60, DEEP: 150 } as Record<string, number>,
          // P5 — arsenal evergreen (durées typiques d'un run CLI)
          SUBFINDER: { QUICK: 2, STANDARD: 4, DEEP: 8 } as Record<string, number>,
          AMASS: { QUICK: 8, STANDARD: 20, DEEP: 45 } as Record<string, number>,
          HTTPX: { QUICK: 1, STANDARD: 2, DEEP: 4 } as Record<string, number>,
          NUCLEI: { QUICK: 5, STANDARD: 12, DEEP: 30 } as Record<string, number>,
          NIKTO: { QUICK: 8, STANDARD: 18, DEEP: 40 } as Record<string, number>,
          ZAP: { QUICK: 10, STANDARD: 20, DEEP: 45 } as Record<string, number>,
          SEMGREP: { QUICK: 4, STANDARD: 10, DEEP: 25 } as Record<string, number>,
          TRIVY: { QUICK: 3, STANDARD: 7, DEEP: 18 } as Record<string, number>,
          GITLEAKS: { QUICK: 2, STANDARD: 4, DEEP: 10 } as Record<string, number>,
          SQLMAP: { QUICK: 8, STANDARD: 20, DEEP: 45 } as Record<string, number>,
          FFUF: { QUICK: 3, STANDARD: 7, DEEP: 18 } as Record<string, number>,
        } as Record<string, Record<string, number>>
      )[tool] ?? { QUICK: 20, STANDARD: 45, DEEP: 90 };
    return (baseMinutes[profile] ?? 45) * 60_000;
  },
} as const;

export function execMode(): ExecMode {
  return REAL_EXEC.mode;
}
