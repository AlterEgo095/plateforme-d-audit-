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
import { MAX_LINE_LENGTH_HARD, probeVersion, runStreaming } from "./proc";
import { probeLlmEndpoint, stripLlmProvider } from "./llm-probe";
import type {
  RealAdapterContext,
  RealAvailability,
  RealFinding,
  RealToolAdapter,
} from "./types";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

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
  // Le JSON final est le DERNIER objet racine imprimé : on part de la FIN du
  // flux et on tente chaque paire accolade fermante/ouvrante en remontant.
  // (L'ancienne version partait de la PREMIÈRE accolade du tampon de 400 Ko :
  // avec des traces stderr dans la fenêtre, elle testait des candidates
  // géantes jamais valides et finissait par retourner null — les constats
  // étaient alors perdus, notamment avec « code 2 » quand des vulns existent.)
  for (let end = stdoutTail.length; end > 1; end--) {
    if (stdoutTail.charCodeAt(end - 1) !== 125) continue; // "}"
    for (let start = end - 1; start >= 0; start--) {
      if (stdoutTail.charCodeAt(start) !== 123) continue; // "{"
      try {
        const parsed = JSON.parse(stdoutTail.slice(start, end)) as Record<string, unknown>;
        if (parsed && typeof parsed === "object" && "vulnerabilities" in parsed) return parsed;
      } catch {
        // fragment invalide (accolade imbriquée, bruit stderr) — on remonte
      }
    }
  }
  return null;
}

/* ── Fallback de récupération : répertoire de run de Phantom ─────────────
 * Phantom écrit parallèlement au stdout : phantom_runs/<run>/vulnerabilities.csv
 * + vulnerabilities/vuln-XXXX.md (description, analyse, PoC). Si le JSON final
 * est illisible (sortie tronquée, crash en fin de CLI), les constats sont
 * reconstruits depuis ces fichiers — robustes par construction.
 * ───────────────────────────────────────────────────────────────────────*/

/** Éclate une ligne CSV en cellules (guillemets doublés gérés). */
function splitCsvLine(line: string): string[] {
  const out: string[] = [];
  let cur = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inQuotes) {
      if (c === '"') {
        if (line[i + 1] === '"') {
          cur += '"';
          i++;
        } else inQuotes = false;
      } else cur += c;
    } else if (c === '"') inQuotes = true;
    else if (c === ",") {
      out.push(cur);
      cur = "";
    } else cur += c;
  }
  out.push(cur);
  return out;
}

/** Section « ## <header> » d'un rapport markdown de vulnérabilité. */
function mdSection(md: string, header: string): string {
  const re = new RegExp(`^##\\s+${header}\\s*$`, "mi");
  const m = re.exec(md);
  if (!m) return "";
  const rest = md.slice(m.index + m[0].length);
  const next = rest.search(/^##\\s+/m);
  return (next >= 0 ? rest.slice(0, next) : rest).trim();
}

/** Valeur d'une ligne « **<Label>:** valeur » d'un rapport markdown. */
function mdMeta(md: string, label: string): string {
  const m = new RegExp(`\\*\\*${label}:\\*\\*\\s*([^\\n]+)`, "i").exec(md);
  return m ? m[1].trim() : "";
}

function mapRunDirConfidence(raw: string): RealFinding["confidence"] {
  const v = raw.toLowerCase();
  if (v === "confirmed") return "CONFIRMED";
  if (v === "false_positive" || v === "mitigated") return "UNVERIFIED";
  return "PROBABLE";
}

function findingsFromRunDir(workdir: string): RealFinding[] {
  try {
    const runsDir = join(workdir, "phantom_runs");
    if (!existsSync(runsDir)) return [];
    const findings: RealFinding[] = [];
    for (const run of readdirSync(runsDir)) {
      const runDir = join(runsDir, run);
      const csvPath = join(runDir, "vulnerabilities.csv");
      if (!existsSync(csvPath)) continue;
      const lines = readFileSync(csvPath, "utf8")
        .split(/\r?\n/)
        .filter((l) => l.trim());
      if (lines.length < 2) continue;
      const header = splitCsvLine(lines[0]).map((h) => h.trim());
      for (const line of lines.slice(1)) {
        const cells = splitCsvLine(line);
        const row: Record<string, string> = {};
        header.forEach((h, i) => {
          row[h] = (cells[i] ?? "").trim();
        });
        const mdPath = row.file ? join(runDir, row.file) : "";
        const md = mdPath && existsSync(mdPath) ? readFileSync(mdPath, "utf8") : "";
        const confidence = mapRunDirConfidence(row.confidence);
        const cvssTxt = row.cvss || mdMeta(md, "CVSS");
        const cvss = cvssTxt ? Number.parseFloat(cvssTxt) : NaN;
        const locBits = [row.method, `${row.target ?? ""}${row.endpoint ?? ""}`].filter(Boolean);
        const param = row.parameter ? ` (paramètre : ${row.parameter})` : "";
        const description =
          [mdSection(md, "Description"), mdSection(md, "Impact")].filter(Boolean).join("\n\n") ||
          "(description disponible dans le rapport markdown du run)";
        findings.push({
          title: row.title || row.id || "Constat Phantom",
          severity: mapSeverity(row.severity),
          confidence,
          category: mdMeta(md, "CWE") || "web",
          cve: null,
          cvss: Number.isFinite(cvss) ? cvss : null,
          location: locBits.length ? locBits.join(" ") + param : undefined,
          description,
          evidence: mdSection(md, "Technical Analysis") || "(aucune preuve détaillée fournie par l'outil)",
          poc: mdSection(md, "Proof of Concept") || undefined,
          sentinelTriggered: confidence === "CONFIRMED",
          remediation: mdSection(md, "Remediation") || mdSection(md, "Remédiation") || undefined,
        });
      }
    }
    return findings;
  } catch {
    return [];
  }
}

/**
 * Garde-fou anti-faux négatif : sonde la cible HTTP AVANT de lancer l'agent.
 * Toute réponse HTTP (même 4xx/5xx) = joignable ; erreur réseau/timeout = non.
 */
async function probeReachable(ctx: RealAdapterContext, url: string): Promise<boolean> {
  try {
    const res = await fetch(url, {
      redirect: "manual",
      signal: AbortSignal.timeout(15_000),
      headers: { "User-Agent": "Mozilla/5.0 (compatible; AuditForge/1.0)" },
    });
    await ctx.onLog(`Sonde de joignabilité : HTTP ${res.status} — cible atteignable`, "INFO", "phantom");
    void res.body?.cancel();
    return true;
  } catch (err) {
    await ctx.onLog(
      `Sonde de joignabilité en échec (${err instanceof Error ? err.message : "erreur réseau"})`,
      "WARN",
      "phantom",
    );
    return false;
  }
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
    // P5-fix : sonde LLM réelle (1 token) — l'agent ne peut rien faire sans
    // raisonnement ; un endpoint à sec (HTTP 402) doit être visible dans
    // tools-status, pas découvert au milieu d'un scan échoué.
    const llm = await probeLlmEndpoint({
      apiKey: REAL_EXEC.llmApiKey,
      apiBase: REAL_EXEC.llmApiBase,
      model: stripLlmProvider(REAL_EXEC.phantomLlm || "glm-4.6"),
    });
    if (!llm.ok) {
      return { available: false, reason: `LLM hors service : ${llm.reason}`, version };
    }
    return { available: true, version };
  }

  // m6 (audit 8-a) : pas de cancel() ici — l'annulation passe exclusivement
  // par le AbortSignal (kill arborescent du process group dans runStreaming).

  async run(ctx: RealAdapterContext): Promise<RealFinding[]> {
    const target = await prepareTarget(ctx);
    const mode = ctx.profile === "QUICK" ? "quick" : ctx.profile === "DEEP" ? "deep" : "standard";

    // P5-fix : re-sonde LLM juste avant l'exécution (l'état de checkAvailable
    // peut dater — cache tools-status 60 s, solde épuisé entre-temps). Échec
    // IMMÉDIAT avec cause claire plutôt que 20 s de sandbox morte puis
    // « JSON final illisible ».
    const llm = await probeLlmEndpoint({
      apiKey: REAL_EXEC.llmApiKey,
      apiBase: REAL_EXEC.llmApiBase,
      model: stripLlmProvider(REAL_EXEC.phantomLlm || "glm-4.6"),
    });
    if (!llm.ok) {
      throw new Error(`Phantom impossible : LLM hors service — ${llm.reason}`);
    }

    // Garde-fou anti-faux « 0 vulnérabilité » : une cible HTTP injoignable
    // (site hors ligne, pare-feu, geo-bloc, ban IP) ferait tourner l'agent
    // 30-60 min pour conclure « 0 vulnérabilité » — un faux négatif total.
    // On refuse explicitement AVANT de lancer la sandbox (cause claire).
    if (/^https?:\/\//i.test(target.value)) {
      const reachable = await probeReachable(ctx, target.value);
      if (!reachable) {
        throw new Error(
          `Cible injoignable depuis le moteur (timeout/refus TCP sur ${target.value}) — le serveur ne répond pas. ` +
          "Un audit rapporterait de faux « 0 vulnérabilité » : scan annulé avant exécution. " +
          "Vérifiez que la cible est en ligne et qu'elle ne bloque pas l'IP du scanner.",
        );
      }
    }

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
      // Ligne NON tronquée à 2000 : le JSON final contient des champs
      // (poc_script_code, evidence…) bien plus longs — la troncature
      // corrompait le JSON et perdait TOUS les constats. L'affichage reste
      // tronqué côté onLog (voir onLine ci-dessous).
      maxLineLength: MAX_LINE_LENGTH_HARD,
      env: {
        // LLM via LiteLLM — pont Z.ai ou endpoint OpenAI-compatible direct
        PHANTOM_LLM: REAL_EXEC.phantomLlm,
        LLM_API_KEY: REAL_EXEC.llmApiKey,
        LLM_API_BASE: REAL_EXEC.llmApiBase,
        PHANTOM_SCAN_MODE: mode,
        PYTHONUNBUFFERED: "1",
        // les scans Phantom créent leur dossier de runs dans le cwd
        PHANTOM_TELEMETRY: "false",
        // Sandbox Kali éventuellement enrichie (PHANTOM_IMAGE, voir env.ts).
        // Transmission EXPLICITE obligatoire : sanitizedEnv() (audit m7)
        // ne forward que l'allowlist système vers les CLI d'audit — sans
        // cette ligne, phantom ignore l'env du conteneur moteur et retombe
        // sur son image amont. Chaîne vide exclue : Config.get() retournerait
        // "" (falsy) → phantom lèverait « PHANTOM_IMAGE must be configured ».
        ...(REAL_EXEC.phantomImage ? { PHANTOM_IMAGE: REAL_EXEC.phantomImage } : {}),
        // Compresseur mémoire (voir env.ts) : sans cette ligne, phantom
        // retombe sur son défaut amont « DeepSeek-V3.2 » (sans préfixe
        // provider) → « LLM Provider NOT provided » à chaque compression.
        ...(REAL_EXEC.phantomCompressorLlm
          ? { PHANTOM_COMPRESSOR_LLM: REAL_EXEC.phantomCompressorLlm }
          : {}),
      },
      onLine: async (line, isErr) => {
        if (!line.trim()) return;
        // stdoutAll conserve la ligne ENTIÈRE (parsing du JSON final) ;
        // la journalisation affiche une version tronquée (hygiène m7).
        stdoutAll = (stdoutAll + line + "\n").slice(-400_000); // fenêtre glissante
        await ctx.onLog(
          line.length > 2000 ? line.slice(0, 2000) + "…" : line,
          isErr ? "WARN" : "TOOL",
          "phantom",
        );
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

    let findings: RealFinding[] = vulns.map((v) => {
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

    // Code de sortie 2 = convention amont de phantom (des vulnérabilités ont
    // été rapportées — voir interface/main.py sys.exit(2)). Si le JSON final
    // est illisible alors que le code est non nul (ou absent), on tente la
    // récupération depuis le répertoire de run AVANT de déclarer l'échec :
    // un scan de 50 min ne doit jamais perdre ses constats.
    if (findings.length === 0 && (result.exitCode !== 0 || !parsed)) {
      const recovered = findingsFromRunDir(ctx.workdir);
      if (recovered.length > 0) {
        findings = recovered;
        await ctx.onLog(
          `JSON final illisible (code ${result.exitCode}) — ${recovered.length} constat(s) récupéré(s) depuis le répertoire de run (vulnerabilities.csv + .md)`,
          "WARN",
          "phantom",
        );
      } else if (result.exitCode !== 0) {
        // Diagnostic embarqué dans l'erreur : la queue de sortie réelle + l'état
        // du répertoire de run. Les lignes TOOL peuvent avoir été perdues par le
        // flush batch (contention SQLite) — l'erreur survit, elle, en base.
        const tail = stdoutAll.trimEnd().slice(-600).replace(/\s+/g, " ");
        const runsDir = join(ctx.workdir, "phantom_runs");
        const runsList = existsSync(runsDir)
          ? readdirSync(runsDir).slice(0, 5).join(",") || "(vide)"
          : "(absent)";
        throw new Error(
          `Phantom a terminé avec le code ${result.exitCode} et aucun constat exploitable ` +
            `(JSON final ${parsed ? "absent" : "illisible"}, phantom_runs: ${runsList})` +
            `${tail ? ` — sortie : …${tail}` : " — sortie vide"}`,
        );
      }
    }

    await ctx.onPhase("RAPPORT", 96);

    await ctx.onLog(
      `Phantom terminé (code ${result.exitCode}) — ${findings.length} constat(s) normalisé(s)`,
      "SUCCESS",
      "phantom",
    );
    return findings;
  }
}
