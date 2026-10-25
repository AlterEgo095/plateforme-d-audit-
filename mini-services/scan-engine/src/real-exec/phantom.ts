/**
 * AuditForge — Adaptateur réel PHANTOM (github.com/Usta0x001/Phantom).
 *
 * Phantom = agent de test d'intrusion autonome (boucle ReAct, 53 outils,
 * sandbox Docker Kali éphémère). Installation : `pip install phantom-agent`.
 *
 * Intégration :
 *   phantom scan -t <cible> -m quick|standard|deep --non-interactive --json
 *   - LLM via LiteLLM : PHANTOM_LLM=openai/glm-4.6 + LLM_API_KEY + LLM_API_BASE
 *     (pont Z.ai ou endpoint OpenAI-compatible direct) ;
 *   - sortie : JSON final sur stdout {run_name, status, vulnerabilities[],
 *     stats} ; les lignes précédentes sont diffusées comme journal ;
 *   - mapping : severity (critical|high|medium|low|info), status
 *     confirmed→CONFIRMED, suspected→PROBABLE ; metadata (cve…).
 *
 * Prérequis : Docker (sandbox Kali, ~13 Go au premier lancement).
 */

import { REAL_EXEC } from "./env";
import { prepareTarget } from "./git-target";
import { probeVersion, runStreaming } from "./proc";
import type {
  RealAdapterContext,
  RealAvailability,
  RealFinding,
  RealToolAdapter,
} from "./types";

const SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);

function mapSeverity(raw: unknown): RealFinding["severity"] {
  const v = String(raw ?? "").toLowerCase();
  if (SEVERITIES.has(v)) return v.toUpperCase() as RealFinding["severity"];
  return "MEDIUM";
}

function mapConfidence(raw: unknown): RealFinding["confidence"] {
  const v = String(raw ?? "").toLowerCase();
  if (v === "confirmed") return "CONFIRMED";
  if (v === "false_positive" || v === "mitigated") return "UNVERIFIED";
  return "PROBABLE";
}

interface PhantomVuln {
  id?: string;
  title?: string;
  severity?: string;
  status?: string;
  description?: string | null;
  evidence?: string[];
  remediation?: string | null;
  metadata?: Record<string, unknown>;
}

/** Extrait le dernier objet JSON complet imprimé sur stdout (mode --json). */
function extractJsonOutput(stdoutTail: string): Record<string, unknown> | null {
  const start = stdoutTail.indexOf("{");
  if (start < 0) return null;
  // Le JSON final est le DERNIER objet racine imprimé — on tente depuis la
  // dernière accolade ouvrante plausible puis on laisse JSON.parse trancher.
  for (let i = stdoutTail.length; i > start; i--) {
    const candidate = stdoutTail.slice(start, i);
    if (!candidate.trimEnd().endsWith("}")) continue;
    try {
      const parsed = JSON.parse(candidate) as Record<string, unknown>;
      if (parsed && typeof parsed === "object" && "vulnerabilities" in parsed) return parsed;
    } catch {
      // on continue d'essayer des suffixes plus courts
    }
  }
  return null;
}

export class PhantomAdapter implements RealToolAdapter {
  readonly tool = "PHANTOM" as const;

  async checkAvailable(): Promise<RealAvailability> {
    const version = await probeVersion(REAL_EXEC.phantomBin);
    if (!version) {
      return {
        available: false,
        reason: "binaire `phantom` introuvable (installer : pip install phantom-agent)",
      };
    }
    // Docker requis (sandbox Kali éphémère) — vérification best effort.
    const docker = await probeVersion("docker");
    if (!docker) {
      return {
        available: false,
        reason: "Docker requis pour la sandbox Kali de Phantom (docker indisponible)",
        version,
      };
    }
    return { available: true, version };
  }

  // m6 (audit 8-a) : pas de cancel() ici — l'annulation passe exclusivement
  // par le AbortSignal (kill arborescent du process group dans runStreaming).

  async run(ctx: RealAdapterContext): Promise<RealFinding[]> {
    const target = await prepareTarget(ctx);
    const mode = ctx.profile === "QUICK" ? "quick" : ctx.profile === "DEEP" ? "deep" : "standard";

    await ctx.onLog(`phantom scan -t ${target.value} -m ${mode} --non-interactive --json`, "CMD", "phantom");
    await ctx.onPhase("INITIALISATION", 2);

    let stdoutAll = "";
    let lastPhase = "";
    const phasePatterns: Array<[RegExp, string, number]> = [
      [/recon|reconnaissance|crawling|enumerat/i, "RECONNAISSANCE", 15],
      [/hypothes|exploit|inject|attack/i, "EXPLOITATION", 45],
      [/verif|poc|confirm|reproduc/i, "VÉRIFICATION", 75],
      [/report|enrich|mitre|cvss/i, "RAPPORT", 92],
    ];

    const result = await runStreaming({
      cmd: REAL_EXEC.phantomBin,
      args: ["scan", "-t", target.value, "-m", mode, "--non-interactive", "--json"],
      cwd: ctx.workdir,
      timeoutMs: REAL_EXEC.timeoutMinutes * 60_000,
      signal: ctx.signal,
      env: {
        // LLM via LiteLLM — pont Z.ai ou endpoint OpenAI-compatible direct
        PHANTOM_LLM: REAL_EXEC.phantomLlm,
        LLM_API_KEY: REAL_EXEC.llmApiKey,
        LLM_API_BASE: REAL_EXEC.llmApiBase,
        PHANTOM_SCAN_MODE: mode,
        PYTHONUNBUFFERED: "1",
        // les scans Phantom créent leur dossier de runs dans le cwd
        PHANTOM_TELEMETRY: "false",
      },
      onLine: async (line, isErr) => {
        if (!line.trim()) return;
        stdoutAll = (stdoutAll + line + "\n").slice(-400_000); // fenêtre glissante
        await ctx.onLog(line, isErr ? "WARN" : "TOOL", "phantom");
        for (const [re, phase, pct] of phasePatterns) {
          if (phase !== lastPhase && re.test(line)) {
            lastPhase = phase;
            await ctx.onPhase(phase, pct);
            break;
          }
        }
      },
    });

    if (result.timedOut) throw new Error("Scan Phantom : timeout global atteint");

    const parsed = extractJsonOutput(stdoutAll);
    const vulns = Array.isArray(parsed?.vulnerabilities)
      ? (parsed!.vulnerabilities as PhantomVuln[])
      : [];

    if (vulns.length === 0 && result.exitCode !== 0) {
      throw new Error(`Phantom a terminé avec le code ${result.exitCode} et aucun constat exploitable`);
    }

    await ctx.onPhase("RAPPORT", 96);
    const findings: RealFinding[] = vulns.map((v) => {
      const meta = (v.metadata ?? {}) as Record<string, unknown>;
      const evidence = Array.isArray(v.evidence) ? v.evidence.filter((e) => typeof e === "string") : [];
      const cvssRaw = meta.cvss ?? meta.cvss_score ?? meta.cvss3_score;
      const cvss = typeof cvssRaw === "number" ? cvssRaw : null;
      const cve = typeof meta.cve === "string" && meta.cve.trim() ? meta.cve.trim() : null;
      const location =
        typeof meta.location === "string"
          ? meta.location
          : typeof meta.url === "string"
            ? meta.url
            : undefined;
      return {
        title: String(v.title ?? v.id ?? "Constat Phantom"),
        severity: mapSeverity(v.severity),
        confidence: mapConfidence(v.status),
        category: String(meta.category ?? meta.cwe ?? "web"),
        cve,
        cvss,
        location,
        description: String(v.description ?? ""),
        evidence: evidence.join("\n") || "(aucune preuve détaillée fournie par l'outil)",
        poc: typeof meta.poc === "string" ? meta.poc : typeof meta.exploit_script === "string" ? meta.exploit_script : undefined,
        sentinelTriggered: mapConfidence(v.status) === "CONFIRMED",
        remediation: v.remediation ?? undefined,
      };
    });

    await ctx.onLog(
      `Phantom terminé (code ${result.exitCode}) — ${findings.length} constat(s) normalisé(s)`,
      "SUCCESS",
      "phantom",
    );
    return findings;
  }
}
