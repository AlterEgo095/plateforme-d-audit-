/**
 * AuditForge — Adaptateur réel BASALT (github.com/Arkessiah/Basalt).
 *
 * Basalt = équipe d'agents IA purple-team qui audite du CODE et PROUVE chaque
 * constat par exécution du PoC (sentinelle `BASALT-POC-TRIGGERED`) dans une
 * sandbox Docker sans réseau. Installation : `pipx install basalt-scan`.
 *
 * Intégration :
 *   basalt audit <répertoire-cible> --report <workdir>/report.json --format json
 *   - LLM : fichier config/basalt.yaml généré dans le workdir — provider
 *     `openai_compat` pointé vers le pont Z.ai (base_url) ;
 *   - cible : dépôt GIT cloné localement (les cibles URL sont refusées —
 *     Basalt audite du code, pas une URL) ;
 *   - sortie JSON : {target, funnel, summary, findings[{title, severity,
 *     category, location, description, poc, status, votes, meta}]}.
 *
 * Prérequis : Docker (exécution des PoC), clé/base LLM OpenAI-compatible.
 */

import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { readFile } from "node:fs/promises";
import { REAL_EXEC } from "./env";
import { prepareTarget } from "./git-target";
import { probeVersion, runStreaming } from "./proc";
import type {
  RealAdapterContext,
  RealAvailability,
  RealFinding,
  RealToolAdapter,
} from "./types";

const SENTINEL = "BASALT-POC-TRIGGERED";
const SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);

interface BasaltFinding {
  title?: string;
  severity?: string;
  category?: string;
  location?: string;
  description?: string;
  poc?: string;
  status?: string;
  votes?: number;
  meta?: Record<string, unknown>;
}

interface BasaltReport {
  target?: string;
  funnel?: { candidates?: number; rejected_judge?: number; rejected_exec?: number; confirmed?: number };
  summary?: { total?: number; by_severity?: Record<string, number> };
  findings?: BasaltFinding[];
}

function mapSeverity(raw: unknown): RealFinding["severity"] {
  const v = String(raw ?? "").toLowerCase();
  return SEVERITIES.has(v) ? (v.toUpperCase() as RealFinding["severity"]) : "MEDIUM";
}

/** Génère le fichier de configuration Basalt pointant vers le LLM configuré. */
async function writeBasaltConfig(ctx: RealAdapterContext): Promise<string> {
  const model = process.env.BASALT_MODEL ?? "glm-4.6";
  const path = join(ctx.workdir, "basalt.yaml");
  // YAML minimal généré à la main (dépendance yaml évitée)
  const yaml = [
    "lang: fr",
    "providers:",
    ...(["red", "purple", "blue", "grader"] as const).flatMap((role) => [
      `  ${role}:`,
      `    - provider: openai_compat`,
      `      model: ${model}`,
      `      api_key: "${REAL_EXEC.llmApiKey.replace(/"/g, '\\"')}"`,
      `      base_url: "${REAL_EXEC.llmApiBase.replace(/"/g, '\\"')}"`,
    ]),
  ].join("\n");
  await writeFile(path, yaml + "\n", "utf8");
  return path;
}

export class BasaltAdapter implements RealToolAdapter {
  readonly tool = "BASALT" as const;

  async checkAvailable(): Promise<RealAvailability> {
    // Basalt (Typer) n'expose pas --version — le sondage utilise --help.
    const version = await probeVersion(REAL_EXEC.basaltBin, 8000, ["--help"]);
    if (!version) {
      return {
        available: false,
        reason: "binaire `basalt` introuvable (installer : pipx install basalt-scan)",
      };
    }
    const docker = await probeVersion("docker");
    if (!docker) {
      return {
        available: false,
        reason: "Docker requis pour l'exécution des PoC en sandbox sans réseau",
        version,
      };
    }
    return { available: true, version };
  }

  async run(ctx: RealAdapterContext): Promise<RealFinding[]> {
    if (ctx.targetType === "NETWORK") {
      throw new Error("Basalt audite du code (cible GIT) — cible réseau non supportée");
    }

    const prepared = await prepareTarget(ctx);
    const configPath = await writeBasaltConfig(ctx);
    const reportPath = join(ctx.workdir, "report.json");

    await ctx.onLog(`basalt audit ${prepared.value} --report report.json --format json`, "CMD", "basalt");
    await ctx.onPhase("RECON", 5);

    let sawSentinel = false;
    let lastPhase = "";
    const phasePatterns: Array<[RegExp, string, number]> = [
      [/recon|attack surface/i, "RECON", 10],
      [/red|find|candidate/i, "RECHERCHE (agents rouges)", 30],
      [/purple|verif|judge/i, "VÉRIFICATION (juge sceptique)", 60],
      [/execut|sandbox|sentinel|poc/i, "EXÉCUTION PoC (sandbox sans réseau)", 80],
      [/blue|patch|grader|report/i, "RAPPORT", 92],
    ];

    const result = await runStreaming({
      cmd: REAL_EXEC.basaltBin,
      args: [
        "audit",
        prepared.value,
        "--report",
        reportPath,
        "--format",
        "json",
        "--fail-on",
        "never",
      ],
      cwd: ctx.workdir,
      timeoutMs: REAL_EXEC.timeoutMinutes * 60_000,
      signal: ctx.signal,
      env: {
        BASALT_CONFIG: configPath,
        PYTHONUNBUFFERED: "1",
      },
      onLine: async (line, isErr) => {
        if (!line.trim()) return;
        if (line.includes(SENTINEL)) sawSentinel = true;
        await ctx.onLog(line, isErr ? "WARN" : "TOOL", "basalt");
        for (const [re, phase, pct] of phasePatterns) {
          if (phase !== lastPhase && re.test(line)) {
            lastPhase = phase;
            await ctx.onPhase(phase, pct);
            break;
          }
        }
      },
    });

    if (result.timedOut) throw new Error("Scan Basalt : timeout global atteint");

    // Lecture du rapport JSON (fichier) — repli : store .basalt/findings.jsonl
    let report: BasaltReport | null = null;
    try {
      const raw = await readFile(reportPath, "utf8");
      report = JSON.parse(raw) as BasaltReport;
    } catch {
      try {
        const storeRaw = await readFile(join(prepared.value, ".basalt", "findings.jsonl"), "utf8");
        const lines = storeRaw.split("\n").filter((l) => l.trim());
        report = { findings: lines.map((l) => JSON.parse(l) as BasaltFinding) };
      } catch {
        // pas de rapport exploitable
      }
    }

    if (!report && result.exitCode !== 0) {
      throw new Error(`Basalt a terminé avec le code ${result.exitCode} sans rapport exploitable`);
    }

    await ctx.onPhase("RAPPORT", 96);
    const findings: RealFinding[] = (report?.findings ?? [])
      .filter((f) => f && f.status !== "rejected" && f.title)
      .map((f) => {
        const status = String(f.status ?? "candidate");
        const poc = typeof f.poc === "string" ? f.poc : "";
        const confirmed = status === "confirmed" || status === "patched";
        const meta = (f.meta ?? {}) as Record<string, unknown>;
        const cve = typeof meta.cve === "string" && meta.cve.trim() ? meta.cve.trim() : null;
        const cvssRaw = meta.cvss;
        return {
          title: String(f.title),
          severity: mapSeverity(f.severity),
          confidence: confirmed ? "CONFIRMED" : ("UNVERIFIED" as RealFinding["confidence"]),
          category: String(f.category ?? "code"),
          cve,
          cvss: typeof cvssRaw === "number" ? cvssRaw : null,
          location: f.location || undefined,
          description: String(f.description ?? ""),
          evidence:
            (sawSentinel ? `${SENTINEL} — sentinelle détectée pendant l'exécution.\n\n` : "") +
            (poc ? `PoC exécuté (statut: ${status}, votes: ${f.votes ?? 0}):\n${poc}` : `Statut: ${status}`),
          poc: poc || undefined,
          // Sentinelle réelle : un constat n'est CONFIRMÉ que si le PoC a été
          // exécuté avec succès (funnel confirmed / statut confirmed|patched).
          sentinelTriggered: confirmed,
          remediation: typeof meta.remediation === "string" ? meta.remediation : undefined,
        };
      });

    const funnel = report?.funnel;
    if (funnel) {
      await ctx.onLog(
        `Entonnoir Basalt : ${funnel.candidates ?? 0} candidat(s) → ${funnel.confirmed ?? 0} confirmé(s) par exécution`,
        "INFO",
        "basalt",
      );
    }
    await ctx.onLog(
      `Basalt terminé (code ${result.exitCode}) — ${findings.length} constat(s) normalisé(s)`,
      "SUCCESS",
      "basalt",
    );
    return findings;
  }
}
