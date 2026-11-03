/**
 * AuditForge — P5 « Arsenal » : adaptateurs réels génériques pour les outils
 * evergreen (Subfinder, Amass, httpx, Nuclei, Nikto, OWASP ZAP, Semgrep,
 * Trivy, Gitleaks, sqlmap, ffuf).
 *
 * Un ARSENAL_SPEC décrit l'outil (binaire, disponibilité, construction des
 * arguments par profil, parsing du rapport) et `makeArsenalAdapter` produit
 * l'adaptateur réel complet :
 *   - disponibilité = binaire résolu (sonde structurée + retry timeout) + exigences
 *     spécifiques (wordlist ffuf, registre Semgrep…) — honnêteté des statuts ;
 *   - exécution = runStreaming (env sanitisée m7, kill tree, abort, timeout
 *     global REAL_SCAN_TIMEOUT_MIN), lignes diffusées en TOOL + phases ;
 *   - parsing = fichier JSON/JSONL ou capture stdout (sqlmap) → RealFinding[]
 *     normalisées, dédupliquées et PLAFONDÉES (anti-flood de la base) ;
 *   - cibles = URL (telle quelle ou hôte dérivé), GIT (clonage superficiel
 *     via prepareTarget) ou NETWORK (hôte/plage).
 *
 * Les preuves restent brutes (sortie outil), les secrets gitleaks sont
 * masqués (--redact), aucune commande n'est construite via un shell.
 */

import { existsSync } from "node:fs";
import { readFile, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { REAL_EXEC } from "./env";
import { prepareTarget } from "./git-target";
import { describeProbeFailure, probeBinaryWithRetry, runStreaming } from "./proc";
import type {
  RealAdapterContext,
  RealAvailability,
  RealFinding,
  RealToolAdapter,
} from "./types";
import type { TargetType, Tool } from "../types";

// ─── Helpers communs ─────────────────────────────────────────────────

const SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);

/** Normalise une sévérité arbitraire (outil) vers l'énumération plateforme. */
function normSeverity(raw: unknown, fallback: RealFinding["severity"] = "MEDIUM"): RealFinding["severity"] {
  const v = String(raw ?? "").toLowerCase();
  return SEVERITIES.has(v) ? (v.toUpperCase() as RealFinding["severity"]) : fallback;
}

/** Hôte d'une cible URL (sans schéma/chemin) ; cible NETWORK rendue telle quelle. */
function hostOfTarget(target: string, targetType: TargetType): string {
  if (targetType === "URL") {
    try {
      return new URL(target).hostname || target;
    } catch {
      return target.replace(/^https?:\/\//i, "").split("/")[0] || target;
    }
  }
  return target;
}

/** URL de base d'une cible URL (sans slash final). */
function baseOfUrl(target: string): string {
  return target.replace(/\/+$/, "");
}

const IP_LIKE_RE = /^[0-9a-fA-F:.]+$/; // IPv4/IPv6/CIDR — aucun lettre

/** URL d'un hôte pour les sondes HTTP (préserve le schéma si la cible en a un). */
function httpProbeTarget(target: string, targetType: TargetType): string {
  if (targetType === "URL") return baseOfUrl(target);
  if (IP_LIKE_RE.test(target)) return target;
  return `https://${target}`;
}

/**
 * Pré-vol : sonde de joignabilité HTTP d'une cible URL (12 s max par schéma).
 * Toute réponse HTTP — même 4xx/5xx — est réputée joignable ; seul un échec
 * réseau (DNS, connexion, TLS) est rédhibitoire. Repli http si https échoue
 * (hébergement sans TLS). Objectif : ne jamais présenter un « COMPLETED —
 * 0 constat » trompeur quand la cible est morte.
 */
export async function probeUrlTarget(
  target: string,
  timeoutMs = 12_000,
): Promise<{ ok: boolean; detail: string }> {
  const url = baseOfUrl(target);
  const headers = { "user-agent": "AuditForge-Engine/1.0 (+pre-flight probe)" };
  try {
    const res = await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: AbortSignal.timeout(timeoutMs),
      cache: "no-store",
      headers,
    });
    return { ok: true, detail: `HTTP ${res.status}` };
  } catch (errHttps) {
    if (!/^https:/i.test(url)) return { ok: false, detail: String(errHttps) };
    try {
      const alt = url.replace(/^https:/i, "http:");
      const res = await fetch(alt, {
        method: "GET",
        redirect: "follow",
        signal: AbortSignal.timeout(timeoutMs),
        cache: "no-store",
        headers,
      });
      return { ok: true, detail: `HTTP ${res.status} (via http, https injoignable)` };
    } catch (errHttp) {
      const mHttps = errHttps instanceof Error ? errHttps.message : String(errHttps);
      const mHttp = errHttp instanceof Error ? errHttp.message : String(errHttp);
      return { ok: false, detail: `HTTPS : ${mHttps} ; HTTP : ${mHttp}` };
    }
  }
}

/** Hostnames « intéressants » — méritent un constat individuel en recon. */
const INTERESTING_HOST_RE =
  /(^|\.)(admin|portal|vpn|mail|smtp|api|dev|test|staging|uat|preprod|pre-prod|old|legacy|backup|git|gitlab|jenkins|jira|confluence|cpanel|direct|intranet|internal|sso|auth|db|sql|mysql|postgres|redis|kibana|grafana|elastic|monitor|nagios|zabbix|prod|internal-|kube|eks|aks|gke)[.-]/i;

interface DedupKey {
  title: string;
  location?: string;
}

/** Déduplique par (titre, localisation) et plafonne ; ajoute un constat de troncature. */
function capFindings(
  findings: RealFinding[],
  cap: number,
  truncaLabel: string,
): RealFinding[] {
  const seen = new Set<string>();
  const out: RealFinding[] = [];
  for (const f of findings) {
    const key: DedupKey = { title: f.title, location: f.location };
    const id = `${key.title}||${key.location ?? ""}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(f);
    if (out.length >= cap) break;
  }
  if (findings.length > cap) {
    out.push({
      title: `${truncaLabel} — ${findings.length - cap} résultat(s) supplémentaire(s) omis`,
      severity: "INFO",
      confidence: "CONFIRMED",
      category: "info-disclosure",
      cve: null,
      cvss: null,
      location: undefined,
      description:
        `La sortie de l'outil a produit ${findings.length} résultats ; seuls les ${cap} premiers ` +
        "sont persistés individuellement (plafond anti-flood de la plateforme). Consultez les " +
        "journaux du scan pour la liste complète.",
      evidence: `Plafond atteint : ${cap}/${findings.length} résultats persistés.`,
      sentinelTriggered: false,
    });
  }
  return out;
}

/** Parse un JSON classique OU des JSONL (une ligne = un objet), retourne des objets. */
function parseJsonOrJsonl(raw: string): Record<string, unknown>[] {
  const text = raw.trim();
  if (!text) return [];
  if (text.startsWith("[")) {
    try {
      const arr = JSON.parse(text) as unknown;
      return Array.isArray(arr) ? (arr as Record<string, unknown>[]) : [];
    } catch {
      /* tente JSONL */
    }
  }
  if (text.startsWith("{")) {
    try {
      const obj = JSON.parse(text) as unknown;
      return obj && typeof obj === "object" && !Array.isArray(obj)
        ? [obj as Record<string, unknown>]
        : [];
    } catch {
      /* tente JSONL */
    }
  }
  const out: Record<string, unknown>[] = [];
  for (const line of text.split("\n")) {
    const l = line.trim();
    if (!l) continue;
    try {
      const obj = JSON.parse(l) as unknown;
      if (obj && typeof obj === "object" && !Array.isArray(obj)) {
        out.push(obj as Record<string, unknown>);
      }
    } catch {
      /* ligne incomplète — ignorée */
    }
  }
  return out;
}

async function readReport(path: string | null): Promise<string> {
  if (!path || !existsSync(path)) return "";
  try {
    return await readFile(path, "utf8");
  } catch {
    return "";
  }
}

/** Assemble une preuve lisible (bloc borné en taille — hygiène des logs/base). */
function evidenceBlock(parts: Array<string | undefined>, max = 4000): string {
  return parts
    .filter((p): p is string => Boolean(p && p.trim()))
    .join("\n")
    .slice(0, max);
}

// ─── Contrat de spec ─────────────────────────────────────────────────

export interface ArsenalSpec {
  tool: Tool;
  /** Binaire (résolu depuis REAL_EXEC — surchargeable par env). */
  bin: () => string;
  /** Arguments de la sonde de version (défaut : --version). */
  versionArgs?: string[];
  /**
   * Timeout DÉDIÉ de la sonde de version (ms, défaut 10 s). SEMGREP impose
   * 30 s : démarrage à froid python lourd (imports) — un timeout à 10 s le
   * faisait passer pour « binaire introuvable » et basculer en simulation.
   */
  probeTimeoutMs?: number;
  /** Types de cibles réellement supportés par l'outil. */
  targets: TargetType[];
  /** Raison d'indisponibilité si l'environnement manque d'un prérequis. */
  checkExtra?: () => Promise<RealAvailability | null>;
  /**
   * Prépare et construit la commande : dérivation/clonage de la cible,
   * arguments (variantés par profil), chemin du rapport si applicable.
   */
  build(
    ctx: RealAdapterContext,
  ): Promise<{ args: string[]; reportPath: string | null; cmdLabel: string }>;
  /** Parse le rapport (fichier) ou la capture stdout en constats normalisés. */
  parse(input: { reportPath: string | null; stdout: string[]; ctx: RealAdapterContext }): Promise<RealFinding[]>;
  /** Plafond de constats persistés (anti-flood). */
  cap: number;
  /** Motifs de phase pour l'avancement heuristique. */
  phases?: Array<[RegExp, string, number]>;
}

// ─── Fabrique d'adaptateur ───────────────────────────────────────────

export function makeArsenalAdapter(spec: ArsenalSpec): RealToolAdapter {
  return {
    tool: spec.tool,

    async checkAvailable(): Promise<RealAvailability> {
      // HONNÊTETÉ : sonde STRUCTURÉE — ENOENT (binaire absent) ≠ timeout
      // (binaire présent mais lent à froid) ≠ code de sortie anormal ;
      // 1 retry après 2 s sur timeout (les lents à froid passent au 2e coup).
      const probed = await probeBinaryWithRetry(
        spec.bin(),
        spec.probeTimeoutMs ?? 10_000,
        spec.versionArgs ?? ["--version"],
      );
      if (probed.status !== "ok") {
        return { available: false, reason: describeProbeFailure(spec.bin(), probed) };
      }
      const version = probed.version;
      if (spec.checkExtra) {
        const extra = await spec.checkExtra();
        if (extra && !extra.available) return { ...extra, version };
      }
      return { available: true, version };
    },

    async run(ctx: RealAdapterContext): Promise<RealFinding[]> {
      if (!spec.targets.includes(ctx.targetType)) {
        throw new Error(
          `${spec.tool} ne supporte pas les cibles ${ctx.targetType} (supportées : ${spec.targets.join(", ")})`,
        );
      }

      const { args, reportPath, cmdLabel } = await spec.build(ctx);
      await ctx.onLog(cmdLabel, "CMD", spec.tool.toLowerCase());
      await ctx.onPhase("INIT", 4);

      const stdout: string[] = [];
      let lastPhase = "INIT";
      const result = await runStreaming({
        cmd: spec.bin(),
        args,
        cwd: ctx.workdir,
        timeoutMs: REAL_EXEC.timeoutMinutes * 60_000,
        signal: ctx.signal,
        // Les rapports JSON sont lus au FICHIER ; la limite de ligne protège
        // uniquement le journal — aucune reconstruction de JSON depuis stdout.
        maxLineLength: 4000,
        onLine: async (line, isErr) => {
          if (!line.trim()) return;
          stdout.push(line.length > 8000 ? line.slice(0, 8000) + "…" : line);
          if (stdout.length > 5000) stdout.splice(0, 1000); // borne mémoire
          await ctx.onLog(line, isErr ? "WARN" : "TOOL", spec.tool.toLowerCase());
          for (const [re, phase, pct] of spec.phases ?? []) {
            if (phase !== lastPhase && re.test(line)) {
              lastPhase = phase;
              await ctx.onPhase(phase, pct);
              break;
            }
          }
        },
      });

      if (result.aborted) throw new Error("Scan annulé pendant l'exécution de l'outil");
      if (result.timedOut) throw new Error(`Scan ${spec.tool} : timeout global atteint`);

      // Honnêteté : un CLI qui rejette une option (flag invalide) imprime son
      // aide et sort avec le code 0 — sans ce garde, le scan serait marqué
      // COMPLETED avec 0 constat alors que l'outil n'a jamais scanné
      // (ex. nikto et « Unknown option: nolsl »).
      const rejectedOption = stdout.find((l) => /unknown option/i.test(l));
      if (rejectedOption) {
        throw new Error(
          `${spec.tool} a rejeté ses options (« ${rejectedOption.trim().slice(0, 120)} ») — commande invalide, outil non exécuté.`,
        );
      }

      await ctx.onPhase("RAPPORT", 92);
      let findings: RealFinding[] = [];
      try {
        findings = await spec.parse({ reportPath, stdout, ctx });
      } catch (err) {
        throw new Error(
          `Parsing du rapport ${spec.tool} impossible : ${err instanceof Error ? err.message : String(err)}`,
        );
      }
      // Garde-fou anti « 0 constat silencieux » : un outil dont le rapport
      // attendu (-o) n'a PAS été écrit alors que le code de sortie est 0 a
      // crashé silencieusement après avoir affiché du succès (ex. semgrep
      // sans accès au registre de règles) — déclarer « 0 constat » serait
      // un faux négatif total. Les outils à reportPath écrivent toujours
      // leur fichier, même avec 0 résultat.
      if (
        findings.length === 0 &&
        result.exitCode === 0 &&
        reportPath &&
        !existsSync(reportPath)
      ) {
        throw new Error(
          `${spec.tool} a terminé (code 0) sans écrire son rapport attendu (${reportPath}) — ` +
            "exécution incomplète, résultat non exploitable. Vérifiez l'accès réseau du moteur " +
            "(registre de règles/config) et la commande, puis relancez.",
        );
      }
      findings = capFindings(findings, spec.cap, `${spec.tool} : sortie tronquée`);

      // Tolérance : plusieurs outils sortent non-zéro sur des résultats partiels.
      if (findings.length === 0 && result.exitCode !== 0) {
        // Diagnostic : embarquer la queue de sortie de l'outil dans l'erreur —
        // les lignes TOOL peuvent avoir été perdues (flush SQLite sous charge).
        const tail = stdout
          .slice(-4)
          .map((l) => l.slice(0, 120))
          .join(" ⏎ ")
          .slice(0, 400);
        throw new Error(
          `${spec.tool} a terminé avec le code ${result.exitCode} sans constat exploitable${tail ? ` — sortie : ${tail}` : ""}`,
        );
      }
      await ctx.onLog(
        `${spec.tool} terminé (code ${result.exitCode}) — ${findings.length} constat(s) normalisé(s)`,
        "SUCCESS",
        spec.tool.toLowerCase(),
      );
      return findings;
    },
  };
}

// ─── Reconnaissance : Subfinder / Amass / httpx ──────────────────────

/** Constats « intéressants » + résumé agrégé pour la recon passive (anti-bruit). */
function reconFindings(hosts: Array<{ host: string; source?: string; extra?: string }>, label: string): RealFinding[] {
  const out: RealFinding[] = [];
  for (const h of hosts) {
    if (!INTERESTING_HOST_RE.test(h.host)) continue;
    out.push({
      title: `Sous-domaine exposé : ${h.host}`,
      severity: "LOW",
      confidence: "CONFIRMED",
      category: "recon",
      cve: null,
      cvss: null,
      location: h.host,
      description:
        "Sous-domaine résolvable découvert par énumération passive. Les hôtes portant des indices " +
        "d'environnements (admin, dev, staging, vpn, api…) élargissent la surface d'attaque et " +
        "échappent souvent aux inventaires formels — candidats à la prise de contrôle (takeover) " +
        "et à l'exploitation d'environnements négligés.",
      evidence: evidenceBlock([h.source ? `source : ${h.source}` : undefined, h.extra]),
      sentinelTriggered: false,
      remediation:
        "Inventaire DNS continu ; suppression des enregistrements orphelins ; challenge de propriété " +
        "sur la zone ; expositions des environnements non-production à protéger (auth + IP allowlist).",
    });
  }
  out.push({
    title: `${label} : ${hosts.length} sous-domaine(s)/hôte(s) découvert(s)`,
    severity: hosts.length > 0 ? "INFO" : "LOW",
    confidence: "CONFIRMED",
    category: "recon",
    cve: null,
    cvss: null,
    location: undefined,
    description:
      `L'énumération passive a identifié ${hosts.length} entrée(s) DNS. Cette cartographie alimente ` +
      "les phases suivantes (sondes HTTP, scan de signatures, fuzzing). Les constats individuels " +
      "ci-dessus ne listent que les hôtes à indice sensible (admin/dev/staging/vpn/api…).",
    evidence: evidenceBlock(
      hosts.slice(0, 50).map((h) => h.extra ? `${h.host} — ${h.extra}` : h.host),
    ),
    sentinelTriggered: false,
  });
  return out;
}

const subfinderSpec: ArsenalSpec = {
  tool: "SUBFINDER",
  bin: () => REAL_EXEC.subfinderBin,
  versionArgs: ["-version"],
  targets: ["URL", "NETWORK"],
  cap: 250,
  phases: [
    [/sources?|resolv|probing/i, "SOURCES PASSIVES", 25],
    [/enumerat|host|domain/i, "ÉNUMÉRATION", 55],
    [/filter|dedup|output|writing/i, "FILTRAGE", 85],
  ],
  async build(ctx) {
    const host = hostOfTarget(ctx.target, ctx.targetType);
    if (IP_LIKE_RE.test(host)) {
      throw new Error(
        "Subfinder énumère des DOMAINES (DNS) — une IP/plage ne peut pas être énumérée passivement",
      );
    }
    const reportPath = join(ctx.workdir, "subfinder.jsonl");
    const args = ["-d", host, "-json", "-o", reportPath, "-silent"];
    if (ctx.profile === "DEEP") args.push("-recursive");
    return {
      args,
      reportPath,
      cmdLabel: `subfinder -d ${host} -json -o subfinder.jsonl -silent${ctx.profile === "DEEP" ? " -recursive" : ""}`,
    };
  },
  async parse({ reportPath }) {
    const raw = await readReport(reportPath);
    const rows = parseJsonOrJsonl(raw);
    const hosts = rows
      .map((r) => ({
        host: String(r.host ?? r.Host ?? "").trim(),
        source: typeof r.source === "string" ? r.source : undefined,
      }))
      .filter((h) => h.host.length > 0);
    return reconFindings(hosts, "Subfinder");
  },
};

const amassSpec: ArsenalSpec = {
  tool: "AMASS",
  bin: () => REAL_EXEC.amassBin,
  versionArgs: ["-version"],
  targets: ["URL", "NETWORK"],
  cap: 250,
  phases: [
    [/osint|passive|fetching/i, "OSINT PASSIF", 25],
    [/dns|resolv|brute/i, "RÉSOLUTION DNS", 55],
    [/enumerat|finish|writing/i, "CONSOLIDATION", 85],
  ],
  async build(ctx) {
    const host = hostOfTarget(ctx.target, ctx.targetType);
    if (IP_LIKE_RE.test(host)) {
      throw new Error("Amass enum -d attend un DOMAINE — une IP/plage n'est pas énumérable passivement");
    }
    const reportPath = join(ctx.workdir, "amass.json");
    // Mode passif strict (OSINT) : aucune requête active vers la cible.
    return {
      args: ["enum", "-passive", "-d", host, "-json", reportPath],
      reportPath,
      cmdLabel: `amass enum -passive -d ${host} -json amass.json`,
    };
  },
  async parse({ reportPath }) {
    const raw = await readReport(reportPath);
    const rows = parseJsonOrJsonl(raw);
    const hosts = rows.map((r) => {
      const name = String(r.name ?? "").trim();
      const sources = Array.isArray(r.sources) ? (r.sources as unknown[]).map(String) : [];
      return { host: name, source: sources.slice(0, 3).join(", ") || undefined };
    }).filter((h) => h.host.length > 0);
    return reconFindings(hosts, "Amass");
  },
};

const httpxSpec: ArsenalSpec = {
  tool: "HTTPX",
  bin: () => REAL_EXEC.httpxBin,
  versionArgs: ["-version"],
  targets: ["URL", "NETWORK"],
  cap: 200,
  phases: [
    [/init|loading|resolv/i, "INITIALISATION", 15],
    [/probing|scanning|request/i, "SONDES HTTP", 55],
    [/filter|output|done/i, "CONSOLIDATION", 88],
  ],
  async build(ctx) {
    const probe = httpProbeTarget(ctx.target, ctx.targetType);
    const reportPath = join(ctx.workdir, "httpx.jsonl");
    return {
      args: [
        "-u", probe,
        "-json", "-o", reportPath,
        "-status-code", "-title", "-tech-detect", "-web-server", "-cdn",
        "-follow-redirects", "-silent", "-no-color",
      ],
      reportPath,
      cmdLabel: `httpx -u ${probe} -json -o httpx.jsonl -status-code -title -tech-detect -web-server -silent`,
    };
  },
  async parse({ reportPath }) {
    const raw = await readReport(reportPath);
    const rows = parseJsonOrJsonl(raw);
    const out: RealFinding[] = [];
    const hosts: Array<{ host: string; source?: string; extra?: string }> = [];
    for (const r of rows) {
      const url = String(r.url ?? "").trim();
      if (!url) continue;
      const status = typeof r.status_code === "number" ? r.status_code : 0;
      const title = typeof r.title === "string" ? r.title.trim() : "";
      const webserver = typeof r.webserver === "string" ? r.webserver : "";
      const tech = Array.isArray(r.tech) ? (r.tech as unknown[]).map(String) : [];
      const extra = `[${status}] ${title ? `« ${title} » — ` : ""}${webserver}${tech.length ? ` (${tech.slice(0, 6).join(", ")})` : ""}`;
      hosts.push({ host: url, source: webserver || undefined, extra });
      // Signaux notables → constats individuels
      if (status >= 500) {
        out.push({
          title: `Erreur serveur exposée : ${url}`,
          severity: "LOW",
          confidence: "CONFIRMED",
          category: "info-disclosure",
          cve: null,
          cvss: null,
          location: url,
          description: `L'endpoint répond ${status} publiquement. Les traces d'erreur (500) révèlent souvent des stacks, chemins ou requêtes internes utiles à la préparation d'attaques.`,
          evidence: evidenceBlock([extra]),
          sentinelTriggered: false,
          remediation: "Pages d'erreur génériques ; correction des exceptions exposées ; logs côté serveur uniquement.",
        });
      }
      if (/index of|directory listing/i.test(title)) {
        out.push({
          title: `Listage de répertoires : ${url}`,
          severity: "MEDIUM",
          confidence: "CONFIRMED",
          category: "misconfig",
          cve: null,
          cvss: 5.3,
          location: url,
          description: "L'autoindex est activé : le contenu du répertoire est listé publiquement (fichiers, sauvegardes, artefacts).",
          evidence: evidenceBlock([extra]),
          sentinelTriggered: false,
          remediation: "autoindex off ; deny par défaut ; purge des artefacts du stockage web.",
        });
      }
      if (/login|sign[- ]?in|admin|dashboard|console|panel/i.test(title) || /\/admin|\/login|\/console/i.test(url)) {
        out.push({
          title: `Point d'entrée sensible découvert : ${url}`,
          severity: "LOW",
          confidence: "CONFIRMED",
          category: "recon",
          cve: null,
          cvss: null,
          location: url,
          description: "Un point d'entrée d'administration/authentification est exposé publiquement — surface de brute-force et d'énumération de comptes.",
          evidence: evidenceBlock([extra]),
          sentinelTriggered: false,
          remediation: "Restriction IP/VPN pour les consoles d'administration ; MFA ; verrouillage de compte.",
        });
      }
    }
    if (hosts.length > 0) {
      const first = hosts[0];
      out.push({
        title: `Hôte(s) HTTP vivant(s) : ${hosts.length} service(s) identifié(s)`,
        severity: "INFO",
        confidence: "CONFIRMED",
        category: "recon",
        cve: null,
        cvss: null,
        location: undefined,
        description: `Les sondes HTTP ont confirmé ${hosts.length} service(s) web vivant(s). Détail du premier : ${first.extra}`,
        evidence: evidenceBlock(hosts.slice(0, 50).map((h) => `${h.host} ${h.extra ?? ""}`)),
        sentinelTriggered: false,
      });
    }
    return out;
  },
};

// ─── DAST : Nuclei / Nikto / ZAP ─────────────────────────────────────

const NUCLEI_TAG_CATEGORY: Record<string, string> = {
  cve: "cve", xss: "xss", sqli: "injection", lfi: "traversal", rce: "rce",
  ssrf: "ssrf", misconfig: "misconfig", exposure: "info-disclosure",
  takeover: "takeover", auth: "auth", "default-login": "auth", token: "secrets",
};

const nucleiSpec: ArsenalSpec = {
  tool: "NUCLEI",
  bin: () => REAL_EXEC.nucleiBin,
  versionArgs: ["-version"],
  targets: ["URL", "NETWORK"],
  cap: 500,
  phases: [
    [/templates?|loading|compiled/i, "CHARGEMENT TEMPLATES", 20],
    [/crawl|request|matching|scanning/i, "SCAN SIGNATURES", 65],
    [/finish|writing|output/i, "RAPPORT", 90],
  ],
  async build(ctx) {
    const probe = httpProbeTarget(ctx.target, ctx.targetType);
    const reportPath = join(ctx.workdir, "nuclei.jsonl");
    const args = ["-u", probe, "-jsonl", "-o", reportPath, "-silent", "-nc", "-stats"];
    // Variantes par profil : QUICK épargne les templates info, DEEP les inclut.
    if (ctx.profile === "QUICK") args.push("-es", "info,unknown");
    else if (ctx.profile === "STANDARD") args.push("-es", "info");
    else args.push("-rl", "150"); // DEEP : rate limit contenu, toute sévérité
    return {
      args,
      reportPath,
      cmdLabel: `nuclei -u ${probe} -jsonl -o nuclei.jsonl -silent${ctx.profile === "DEEP" ? " -rl 150 (toute sévérité)" : ""}`,
    };
  },
  async parse({ reportPath }) {
    const raw = await readReport(reportPath);
    const rows = parseJsonOrJsonl(raw);
    const out: RealFinding[] = [];
    for (const r of rows) {
      if (r.matcher_status === false) continue;
      const info = (r.info ?? {}) as Record<string, unknown>;
      const classification = (info.classification ?? {}) as Record<string, unknown>;
      const name = String(info.name ?? r["template-id"] ?? "").trim();
      if (!name) continue;
      const severity = normSeverity(info.severity, "LOW");
      const cveRaw = classification["cve-id"];
      const cve = Array.isArray(cveRaw)
        ? ((cveRaw as unknown[])[0] ? String((cveRaw as unknown[])[0]) : null)
        : typeof cveRaw === "string" && cveRaw.trim()
          ? cveRaw.trim()
          : null;
      const cvss = typeof classification["cvss-score"] === "number"
        ? (classification["cvss-score"] as number)
        : null;
      const matchedAt = String(r["matched-at"] ?? r.host ?? "").trim();
      const tags = Array.isArray(info.tags) ? (info.tags as unknown[]).map(String) : [];
      const category = tags.map((t) => NUCLEI_TAG_CATEGORY[t]).find(Boolean) ?? "web";
      const curl = typeof r["curl-command"] === "string" ? r["curl-command"] : undefined;
      const extracted = Array.isArray(r["extracted-results"])
        ? (r["extracted-results"] as unknown[]).map(String).slice(0, 5)
        : [];
      out.push({
        title: `${name}${r["template-id"] ? ` [${String(r["template-id"])}]` : ""}`,
        severity,
        confidence: "PROBABLE",
        category,
        cve,
        cvss,
        location: matchedAt || undefined,
        description:
          String(info.description ?? "") ||
          `Détection Nuclei (template ${String(r["template-id"] ?? "?")}) — signature correspondante sur la cible.`,
        evidence: evidenceBlock([
          `template : ${String(r["template-id"] ?? "?")} — type ${String(r.type ?? "http")}`,
          `match : ${matchedAt}`,
          ...extracted.map((e) => `extrait : ${e}`),
          tags.length ? `tags : ${tags.slice(0, 8).join(", ")}` : undefined,
        ]),
        poc: curl,
        sentinelTriggered: false,
        remediation: typeof info.remediation === "string" && info.remediation.trim()
          ? info.remediation
          : undefined,
      });
    }
    return out;
  },
};

const niktoSpec: ArsenalSpec = {
  tool: "NIKTO",
  bin: () => REAL_EXEC.niktoBin,
  versionArgs: ["-Version"],
  targets: ["URL", "NETWORK"],
  cap: 250,
  phases: [
    [/target|start|scan/i, "COUP D'ŒIL SERVEUR", 30],
    [/items?|test|checking/i, "TESTS CONFIGURATION", 70],
    [/files?|report|save/i, "RAPPORT", 90],
  ],
  async build(ctx) {
    const probe = httpProbeTarget(ctx.target, ctx.targetType);
    const reportPath = join(ctx.workdir, "nikto.json");
    // nikto 2.6.1 (image moteur) : « -nolsl »/« -Timeout » n'existent pas (2.5 :
    // aide + exit 0) et « -nolookup » provoque un exit 1 SILENT — d'où le garde
    // « Unknown option » plus haut. Options valides 2.6.1 uniquement :
    // -nointeractive (pas de prompt), -nocheck (pas de check de MAJ réseau).
    return {
      args: ["-h", probe, "-Format", "json", "-o", reportPath, "-nointeractive", "-nocheck"],
      reportPath,
      cmdLabel: `nikto -h ${probe} -Format json -o nikto.json -nointeractive -nocheck`,
    };
  },
  async parse({ reportPath }) {
    const raw = await readReport(reportPath);
    const rows = parseJsonOrJsonl(raw);
    const out: RealFinding[] = [];
    for (const r of rows) {
      const vulns = Array.isArray(r.vulnerabilities) ? (r.vulnerabilities as Record<string, unknown>[]) : [];
      for (const v of vulns) {
        // nikto (perl) déréférence parfois un tableau dans son propre JSON —
        // artefact « ARRAY(0x…) » à nettoyer du titre/preuve.
        const clean = (s: unknown): string =>
          String(s ?? "").replace(/ARRAY\(0x[0-9a-fA-F]+\)/g, "").trim();
        const msg = clean(v.msg ?? v.namelink);
        if (!msg) continue;
        const url = String(v.url ?? "").trim();
        const low = msg.toLowerCase();
        const severity: RealFinding["severity"] =
          /sql inject|remote (code|command)|rce|shell|traversal|default account|backdoor/.test(low)
            ? "HIGH"
            : /expos|found|allowed|enabled|listing|missing|identif/.test(low)
              ? "MEDIUM"
              : "LOW";
        out.push({
          title: msg.length > 200 ? msg.slice(0, 197) + "…" : msg,
          severity,
          confidence: "PROBABLE",
          category: /misconfig|config|expos|listing/.test(low) ? "misconfig" : "web",
          cve: null,
          cvss: null,
          location: url || undefined,
          description: `Nikto (OSVDB ${String(v.id ?? "?")}) : ${msg}`,
          evidence: evidenceBlock([
            `${Array.isArray(v.method) ? v.method.join(",") : String(v.method ?? "GET")} ${url}`,
            typeof v.iplink === "string" && v.iplink !== url ? v.iplink : undefined,
          ]),
          sentinelTriggered: false,
        });
      }
    }
    return out;
  },
};

/** Risques ZAP (riskcode) → sévérité plateforme (report JSON ET vue /alerts). */
const ZAP_RISK: Record<string, RealFinding["severity"]> = {
  "0": "INFO", "1": "LOW", "2": "MEDIUM", "3": "HIGH",
};

/**
 * Alerte ZAP (report JSON « -J » OU vue /JSON/core/view/alerts) → constat.
 * Même structure d'objet dans les deux modes — mapping unique partagé.
 */
function zapAlertFinding(a: Record<string, unknown>): RealFinding | null {
  const name = String(a.name ?? "").trim();
  if (!name) return null;
  const instances = Array.isArray(a.instances) ? (a.instances as Record<string, unknown>[]) : [];
  const first = instances[0] ?? {};
  // Vue /JSON/core/view/alerts : champs à plat (url/param/evidence) ;
  // instances[] n'existe que dans le JSON du rapport (-J). Lire les deux.
  const uri = String(a.url ?? first.uri ?? "").trim();
  const param = String(a.param ?? first.param ?? "").trim();
  const evidence = String(a.evidence ?? first.evidence ?? "").trim();
  const riskcode = String(a.riskcode ?? "0");
  const zapConf = String(a.confidence ?? "0");
  return {
    title: name,
    severity: ZAP_RISK[riskcode] ?? "LOW",
    confidence: zapConf === "2" || zapConf === "3" ? "PROBABLE" : "UNVERIFIED",
    category: "web",
    cve: null,
    cvss: null,
    location: param ? `${uri} — paramètre ${param}` : uri || undefined,
    description: String(a.description ?? "").trim(),
    evidence: evidenceBlock([
      instances.length ? `${instances.length} occurrence(s)` : undefined,
      evidence ? `évidence : ${evidence}` : undefined,
      typeof a.otherinfo === "string" && a.otherinfo.trim() ? a.otherinfo.trim() : undefined,
      typeof a.cweid === "string" && a.cweid ? `CWE-${a.cweid}` : undefined,
      typeof a.reference === "string" && a.reference.trim() ? a.reference.trim().slice(0, 800) : undefined,
    ]),
    sentinelTriggered: false,
    remediation: String(a.solution ?? "").trim() || undefined,
  };
}

const zapSpec: ArsenalSpec = {
  tool: "ZAP",
  bin: () => REAL_EXEC.zapCommand,
  versionArgs: ["-h"],
  targets: ["URL"],
  cap: 300,
  phases: [
    [/starting|zap|daemon|init/i, "DÉMARRAGE ZAP", 15],
    [/spider|crawl|passive scan/i, "SPIDER + SCAN PASSIF", 45],
    [/active scan|attack|scan in progress/i, "SCAN ACTIF", 80],
    [/report|complete|exit/i, "RAPPORT", 92],
  ],
  async build(ctx) {
    if (ctx.targetType !== "URL") {
      throw new Error("OWASP ZAP (automation framework) audite une URL déployée — cible non supportée");
    }
    const reportPath = join(ctx.workdir, "zap-report.json");
    return {
      args: ["-t", baseOfUrl(ctx.target), "-J", reportPath, "-I", "-l", "INFO"],
      reportPath,
      cmdLabel: `${REAL_EXEC.zapCommand} -t ${baseOfUrl(ctx.target)} -J zap-report.json -I`,
    };
  },
  async parse({ reportPath }) {
    const raw = await readReport(reportPath);
    const rows = parseJsonOrJsonl(raw);
    const out: RealFinding[] = [];
    for (const site of rows) {
      const sites = Array.isArray(site.site) ? (site.site as Record<string, unknown>[]) : [];
      for (const s of sites) {
        const alerts = Array.isArray(s.alerts) ? (s.alerts as Record<string, unknown>[]) : [];
        for (const a of alerts) {
          const f = zapAlertFinding(a);
          if (f) out.push(f);
        }
      }
    }
    return out;
  },
};

// ─── ZAP — pilote API REST (side-car compose, RF2) ──────────────────

/**
 * Audit v2 (RF2) : ZAP est une application Java lourde — plutôt que de
 * l'installer dans l'image moteur, le déploiement compose le fournit en
 * side-car (ghcr.io/zaproxy/zaproxy, réseau interne). Quand ZAP_API_URL est
 * définie, cet adaptateur pilote le daemon via son API REST officielle :
 * spider → scan passif → scan actif → collecte des alertes. Aucun binaire
 * local n'est requis et la disponibilité (realAvailable) est TRUE dès que
 * l'API répond — exécution réelle authentique, pas une simulation.
 *
 * Sans ZAP_API_URL, on retombe sur le mode binaire (zapSpec ci-dessus).
 */
class ZapApiAdapter implements RealToolAdapter {
  readonly tool = "ZAP" as const;
  private readonly base = REAL_EXEC.zapApiUrl;
  private readonly key = REAL_EXEC.zapApiKey;

  private async api<T = Record<string, unknown>>(
    path: string,
    params: Record<string, string> = {},
    timeoutMs = 30_000,
  ): Promise<T> {
    const url = new URL(this.base + path);
    for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
    const res = await fetch(url, {
      headers: this.key ? { "X-Zap-Api-Key": this.key } : undefined,
      signal: AbortSignal.timeout(timeoutMs),
      cache: "no-store",
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`ZAP API ${path} → HTTP ${res.status}${body ? ` : ${body.slice(0, 200)}` : ""}`);
    }
    return (await res.json()) as T;
  }

  async checkAvailable(): Promise<RealAvailability> {
    if (!this.base) {
      return { available: false, reason: "ZAP_API_URL non définie — repli sur le mode binaire impossible ici" };
    }
    try {
      const v = await this.api<{ version?: string }>("/JSON/core/view/version/", {}, 10_000);
      return { available: true, version: v.version || "daemon" };
    } catch (err) {
      return {
        available: false,
        reason: `API ZAP (${this.base}) injoignable : ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }

  /** Boucle d'attente partagée : poll une vue jusqu'à la condition, abort-aware. */
  private async pollUntil(
    ctx: RealAdapterContext,
    label: string,
    view: string,
    params: Record<string, string>,
    readPct: (v: Record<string, unknown>) => number,
    opts: { intervalMs?: number; maxMinutes?: number } = {},
  ): Promise<void> {
    const interval = opts.intervalMs ?? 5_000;
    const deadline = Date.now() + (opts.maxMinutes ?? REAL_EXEC.timeoutMinutes) * 60_000;
    let lastPct = -1;
    for (;;) {
      if (ctx.signal.aborted) throw new Error("Scan annulé pendant l'exécution de l'outil");
      if (Date.now() > deadline) throw new Error(`Scan ZAP : timeout global atteint (${label})`);
      let pct = -1;
      try {
        pct = readPct(await this.api<Record<string, unknown>>(view, params));
      } catch (err) {
        await ctx.onLog(`${label} : interrogation impossible (${String(err)}) — nouvelle tentative`, "WARN", "zap");
      }
      if (pct >= 100) return;
      if (pct >= 0 && pct !== lastPct) {
        lastPct = pct;
        await ctx.onLog(`${label} : ${pct}%`, "TOOL", "zap");
        await ctx.onPhase(label, Math.max(5, Math.min(95, pct)));
      }
      await new Promise((r) => setTimeout(r, interval));
    }
  }

  async run(ctx: RealAdapterContext): Promise<RealFinding[]> {
    if (ctx.targetType !== "URL") {
      throw new Error("ZAP (API) audite une URL déployée — cible non supportée");
    }
    const target = baseOfUrl(ctx.target);
    await ctx.onPhase("INIT", 4);
    const version = await this.api<{ version?: string }>("/JSON/core/view/version/");
    await ctx.onLog(
      `ZAP daemon ${version.version ?? "?"} (API ${this.base}) — cible ${target}`,
      "CMD",
      "zap",
    );

    // Amorce l'arbre de sites (la cible doit être joignable depuis le daemon).
    try {
      await this.api("/JSON/core/action/accessUrl/", { url: target, followRedirects: "true" }, 60_000);
    } catch (err) {
      await ctx.onLog(`accessUrl : ${String(err)} — le spider tentera quand même`, "WARN", "zap");
    }

    // 1) Spider classique (découverte des URL) — 10 % → 45 %.
    let spiderOk = false;
    await ctx.onPhase("SPIDER", 10);
    try {
      await this.api("/JSON/spider/action/scan/", { url: target });
      await this.pollUntil(ctx, "SPIDER", "/JSON/spider/view/status/", {}, (v) => Number(v.status ?? 0));
      spiderOk = true;
    } catch (err) {
      if (ctx.signal.aborted) throw err;
      await ctx.onLog(`spider : ${String(err)} — poursuite sans spider`, "WARN", "zap");
    }

    // 2) Scan passif — attente de la vidange (recordsToScan = 0) — 50 %.
    await ctx.onPhase("SCAN PASSIF", 48);
    try {
      await this.pollUntil(
        ctx,
        "SCAN PASSIF",
        "/JSON/pscan/view/recordsToScan/",
        {},
        (v) => (Number(v.recordsToScan ?? 0) === 0 ? 100 : 50),
        { intervalMs: 3_000 },
      );
    } catch (err) {
      if (ctx.signal.aborted) throw err;
      await ctx.onLog(`scan passif : ${String(err)} — poursuite`, "WARN", "zap");
    }

    // 3) Scan actif (politique par défaut) — 55 % → 90 %.
    let ascanOk = false;
    await ctx.onPhase("SCAN ACTIF", 55);
    try {
      const started = await this.api<{ scan?: string }>("/JSON/ascan/action/scan/", {
        url: target,
        inScopeOnly: "false",
        recurse: "true",
      });
      if (!started.scan || started.scan === "-1" || started.scan === "") {
        throw new Error(`ascan non démarré (${JSON.stringify(started).slice(0, 200)})`);
      }
      await this.pollUntil(ctx, "SCAN ACTIF", "/JSON/ascan/view/status/", {}, (v) => Number(v.status ?? 0));
      ascanOk = true;
    } catch (err) {
      if (ctx.signal.aborted) throw err;
      await ctx.onLog(`scan actif : ${String(err)} — les alertes passives restent collectées`, "WARN", "zap");
    }

    if (ctx.signal.aborted) throw new Error("Scan annulé pendant l'exécution de l'outil");

    // 4) Collecte paginée des alertes (count max ZAP = 5000) — 95 %.
    await ctx.onPhase("RAPPORT", 92);
    const all: Record<string, unknown>[] = [];
    let start = 0;
    for (;;) {
      const page = await this.api<{ alerts?: Record<string, unknown>[] }>("/JSON/core/view/alerts/", {
        baseurl: target,
        start: String(start),
        count: "5000",
      });
      const alerts = Array.isArray(page.alerts) ? page.alerts : [];
      all.push(...alerts);
      if (alerts.length < 5000 || all.length >= 5000) break;
      start += alerts.length;
    }
    await ctx.onLog(`ZAP : ${all.length} alerte(s) collectée(s)`, "TOOL", "zap");
    // Honnêteté : si NI le spider NI le scan actif n'ont pu auditer la cible,
    // « 0 alerte » serait un faux COMPLETED — échec explicite à la place.
    if (!spiderOk && !ascanOk) {
      throw new Error(
        "ZAP n'a pu auditer la cible : spider et scan actif ont échoué (cible injoignable depuis le daemon ZAP ?)",
      );
    }
    const findings: RealFinding[] = [];
    for (const a of all) {
      const f = zapAlertFinding(a);
      if (f) findings.push(f);
    }
    await ctx.onPhase("RAPPORT", 96);
    return capFindings(findings, 300, "ZAP : sortie tronquée");
  }

  /** Annulation proactive : stoppe spider + ascan sur le daemon. */
  async cancel(): Promise<void> {
    try {
      await this.api("/JSON/ascan/action/stop/");
      await this.api("/JSON/spider/action/stop/");
    } catch {
      /* le daemon est peut-être déjà arrêté — rien de plus à faire */
    }
  }
}

/** P5+RF2 : adaptateur ZAP — API REST (side-car) si ZAP_API_URL, sinon binaire. */
export function makeZapAdapter(): RealToolAdapter {
  if (REAL_EXEC.zapApiUrl) return new ZapApiAdapter();
  return makeArsenalAdapter(zapSpec);
}

// ─── Analyse de code : Semgrep / Trivy / Gitleaks ────────────────────

const semgrepSpec: ArsenalSpec = {
  tool: "SEMGREP",
  bin: () => REAL_EXEC.semgrepBin,
  versionArgs: ["--version"],
  // Démarrage à froid python lourd (~3 s à chaud, > 10 s à froid) — sonde à 30 s.
  probeTimeoutMs: 30_000,
  targets: ["GIT"],
  cap: 300,
  phases: [
    [/rules?|loading|config/i, "CHARGEMENT RÈGLES", 20],
    [/scanning|analy|parsing/i, "ANALYSE SÉMANTIQUE", 70],
    [/report|complete|output/i, "RAPPORT", 90],
  ],
  async build(ctx) {
    const dir = await prepareTarget(ctx);
    const reportPath = join(ctx.workdir, "semgrep.json");
    // « --metrics=off » est REFUSÉ par semgrep quand « --config auto » est
    // utilisé (« Cannot create auto config when metrics are off » — le
    // registre de règles exige la télémétrie). Télémétrie désactivée
    // SEULEMENT pour une config explicite (règles locales/pack épinglé).
    const config = REAL_EXEC.semgrepConfig;
    const args = ["scan", "--config", config, "--json", "--quiet", "-o", reportPath, dir.value];
    if (config !== "auto") args.splice(3, 0, "--metrics=off");
    return {
      args,
      reportPath,
      cmdLabel: `semgrep scan --config ${config}${config !== "auto" ? " --metrics=off" : ""} --json -o semgrep.json ${dir.cloned ? "(dépôt cloné)" : dir.value}`,
    };
  },
  async parse({ reportPath, ctx }) {
    const raw = await readReport(reportPath);
    const rows = parseJsonOrJsonl(raw);
    const out: RealFinding[] = [];
    // Semgrep émet les chemins tels que passés sur la CLI (absolus ici) —
    // re-latériser sous la racine du dépôt cloné pour un emplacement lisible.
    const repoRoot = join(ctx.workdir, "target-repo") + "/";
    for (const r of rows) {
      const results = Array.isArray(r.results) ? (r.results as Record<string, unknown>[]) : [];
      for (const res of results) {
        const extra = (res.extra ?? {}) as Record<string, unknown>;
        const meta = (extra.metadata ?? {}) as Record<string, unknown>;
        const checkId = String(res.check_id ?? "").trim();
        if (!checkId) continue;
        const start = (res.start ?? {}) as Record<string, unknown>;
        const absPath = String(res.path ?? "").trim();
        const path = absPath.startsWith(repoRoot) ? absPath.slice(repoRoot.length) : absPath;
        const line = typeof start.line === "number" ? start.line : null;
        const sevMap: Record<string, RealFinding["severity"]> = {
          // Sévérités legacy (ERROR/WARNING/INFO) ET modernes (HIGH/CRITICAL/
          // MEDIUM/LOW — semgrep supply-chain/au-diapason) : les non couvertes
          // tombaient en LOW et sous-estimaient les constats critiques.
          ERROR: "HIGH", CRITICAL: "CRITICAL", HIGH: "HIGH",
          MEDIUM: "MEDIUM", WARNING: "MEDIUM", LOW: "LOW", INFO: "LOW",
        };
        const cwe = typeof meta.cwe === "string" ? meta.cwe : undefined;
        const cveRaw = meta.cve;
        const cve = Array.isArray(cveRaw)
          ? ((cveRaw as unknown[])[0] ? String((cveRaw as unknown[])[0]) : null)
          : typeof cveRaw === "string" && cveRaw.trim() ? cveRaw.trim() : null;
        out.push({
          title: checkId.length > 180 ? checkId.slice(0, 177) + "…" : checkId,
          severity: sevMap[String(extra.severity ?? "INFO")] ?? "LOW",
          confidence: "PROBABLE",
          category: "sast",
          cve,
          cvss: null,
          location: path ? `${path}${line ? `:${line}` : ""}` : undefined,
          description: String(extra.message ?? "").trim() || "Correspondance de règle Semgrep.",
          evidence: evidenceBlock([
            typeof extra.lines === "string" && extra.lines.trim()
              ? `code :\n${extra.lines.trim().slice(0, 1500)}`
              : undefined,
            cwe ? `CWE : ${cwe}` : undefined,
          ]),
          sentinelTriggered: false,
          remediation:
            (typeof meta.references === "string" && meta.references) ||
            (Array.isArray(meta.references) && (meta.references as unknown[])[0]
              ? String((meta.references as unknown[])[0])
              : undefined),
        });
      }
    }
    return out;
  },
};

const trivySpec: ArsenalSpec = {
  tool: "TRIVY",
  bin: () => REAL_EXEC.trivyBin,
  versionArgs: ["--version"],
  targets: ["GIT"],
  cap: 400,
  phases: [
    [/db|update|download/i, "MAJ BASE CVE", 20],
    [/scan|analy|detect/i, "SCAN DÉPENDANCES", 70],
    [/report|summary|output/i, "RAPPORT", 90],
  ],
  async build(ctx) {
    const dir = await prepareTarget(ctx);
    const reportPath = join(ctx.workdir, "trivy.json");
    return {
      args: [
        "fs", "--format", "json", "--output", reportPath,
        "--scanners", "vuln,secret", "--timeout", "20m", dir.value,
      ],
      reportPath,
      cmdLabel: `trivy fs --format json --scanners vuln,secret ${dir.cloned ? "(dépôt cloné)" : dir.value}`,
    };
  },
  async parse({ reportPath }) {
    const raw = await readReport(reportPath);
    const rows = parseJsonOrJsonl(raw);
    const out: RealFinding[] = [];
    for (const r of rows) {
      const results = Array.isArray(r.Results) ? (r.Results as Record<string, unknown>[]) : [];
      for (const res of results) {
        const target = String(res.Target ?? "");
        const vulns = Array.isArray(res.Vulnerabilities) ? (res.Vulnerabilities as Record<string, unknown>[]) : [];
        for (const v of vulns) {
          const id = String(v.VulnerabilityID ?? "").trim();
          const pkg = String(v.PkgName ?? "").trim();
          if (!id || !pkg) continue;
          const cvssObj = (v.CVSS ?? {}) as Record<string, Record<string, unknown>>;
          const cvss = cvssObj?.nvd?.V3Score ?? cvssObj?.redhat?.V3Score ?? null;
          const fixed = String(v.FixedVersion ?? "").trim();
          out.push({
            title: `${id} — ${pkg}@${String(v.InstalledVersion ?? "?")}`,
            severity: normSeverity(v.Severity, "MEDIUM"),
            confidence: "CONFIRMED",
            category: "sca",
            cve: /^CVE-/.test(id) ? id : null,
            cvss: typeof cvss === "number" ? cvss : null,
            location: `${target} : ${pkg}`,
            description:
              (typeof v.Title === "string" && v.Title ? `${v.Title} — ` : "") +
              (typeof v.Description === "string" ? v.Description.slice(0, 1200) : "") ||
              `Vulnérabilité connue sur la dépendance ${pkg}.`,
            evidence: evidenceBlock([
              typeof v.PrimaryURL === "string" ? v.PrimaryURL : undefined,
              fixed ? `correction disponible : ${fixed}` : undefined,
            ]),
            sentinelTriggered: false,
            remediation: fixed
              ? `Mettre à jour ${pkg} vers la version ${fixed} (ou au-delà), puis re-tester la chaîne de dépendances.`
              : undefined,
          });
        }
        const secrets = Array.isArray(res.Secrets) ? (res.Secrets as Record<string, unknown>[]) : [];
        for (const s of secrets) {
          const rule = String(s.RuleID ?? "").trim();
          const title = String(s.Title ?? rule).trim();
          if (!rule && !title) continue;
          const startLine = typeof s.StartLine === "number" ? s.StartLine : null;
          out.push({
            title: `Secret détecté : ${title || rule}`,
            severity: normSeverity(s.Severity, "HIGH"),
            confidence: "CONFIRMED",
            category: "secrets",
            cve: null,
            cvss: null,
            location: `${target}${startLine ? `:${startLine}` : ""}`,
            description: `Un secret (clé API, jeton, mot de passe) est présent dans le dépôt analysé (règle ${rule}). Toute valeur exposée doit être considérée comme compromise.`,
            evidence: evidenceBlock([
              typeof s.Match === "string" && s.Match
                ? `correspondance (masquée) : ${s.Match.slice(0, 120).replace(/[A-Za-z0-9+/_-]{12,}/g, "***")}`
                : undefined,
            ]),
            sentinelTriggered: false,
            remediation: "Révoquer le secret immédiatement, le retirer de l'historique git, adopter un gestionnaire de secrets et un scan pré-commit.",
          });
        }
        const misconfigs = Array.isArray(res.Misconfigurations) ? (res.Misconfigurations as Record<string, unknown>[]) : [];
        for (const m of misconfigs) {
          const mid = String(m.ID ?? "").trim();
          if (!mid) continue;
          out.push({
            title: `${mid} — ${String(m.Title ?? "").trim()}`,
            severity: normSeverity(m.Severity, "LOW"),
            confidence: "PROBABLE",
            category: "misconfig",
            cve: null,
            cvss: null,
            location: target,
            description: String(m.Message ?? m.Description ?? "").slice(0, 1200),
            evidence: evidenceBlock([
              typeof m.Resolution === "string" ? `résolution : ${m.Resolution}` : undefined,
            ]),
            sentinelTriggered: false,
            remediation: typeof m.Resolution === "string" ? m.Resolution : undefined,
          });
        }
      }
    }
    return out;
  },
};

const gitleaksSpec: ArsenalSpec = {
  tool: "GITLEAKS",
  bin: () => REAL_EXEC.gitleaksBin,
  versionArgs: ["version"],
  targets: ["GIT"],
  cap: 300,
  phases: [
    [/scan|init|detect/i, "DETECTION SECRETS", 40],
    [/history|commit|diff/i, "HISTORIQUE GIT", 75],
    [/report|complete/i, "RAPPORT", 90],
  ],
  async build(ctx) {
    const dir = await prepareTarget(ctx);
    const reportPath = join(ctx.workdir, "gitleaks.json");
    // --redact : les valeurs de secrets ne quittent JAMAIS le workdir du moteur.
    return {
      args: [
        "detect", "--source", dir.value,
        "--report-format", "json", "--report-path", reportPath,
        "--redact", "--no-banner",
      ],
      reportPath,
      cmdLabel: `gitleaks detect --source ${dir.cloned ? "(dépôt cloné)" : dir.value} --report-format json --redact`,
    };
  },
  async parse({ reportPath }) {
    const raw = await readReport(reportPath);
    let rows: Record<string, unknown>[] = [];
    try {
      rows = (JSON.parse(raw.trim() || "[]") as unknown) as Record<string, unknown>[];
      if (!Array.isArray(rows)) rows = [];
    } catch {
      rows = parseJsonOrJsonl(raw);
    }
    const out: RealFinding[] = rows.map((r) => {
      const rule = String(r.RuleID ?? "").trim();
      const desc = String(r.Description ?? "").trim();
      const file = String(r.File ?? "").trim();
      const line = typeof r.StartLine === "number" ? r.StartLine : null;
      const isPrivateKey = /private[-_]?key|pkcs|openssh|pem/i.test(`${rule} ${desc}`);
      return {
        title: `Secret exposé dans le dépôt : ${desc || rule}`,
        severity: isPrivateKey ? "CRITICAL" : "HIGH",
        confidence: "CONFIRMED",
        category: "secrets",
        cve: null,
        cvss: isPrivateKey ? 9.1 : 7.4,
        location: file ? `${file}${line ? `:${line}` : ""}` : undefined,
        description:
          "Gitleaks a détecté un secret (clé API, jeton, clé privée) dans le dépôt. La valeur est " +
          "masquée dans le rapport (--redact) mais doit être considérée comme compromise : elle est " +
          "dans l'historique git, donc récupérable par toute personne ayant accès au dépôt.",
        evidence: evidenceBlock([
          `règle : ${rule}`,
          typeof r.Match === "string" && r.Match ? `correspondance : ${r.Match.slice(0, 200)}` : undefined,
          typeof r.Secret === "string" && r.Secret ? `secret (masqué) : ${r.Secret}` : undefined,
          `fichier : ${file}${line ? ` ligne ${line}` : ""}`,
        ]),
        poc: `git -C <repo> log -p -- ${file || "<fichier>"} | grep -n "${rule}" | head`,
        sentinelTriggered: false,
        remediation:
          "Révoquer le secret, le retirer de l'historique (git filter-repo/BFG), utiliser un gestionnaire " +
          "de secrets (vault), activer un hook pre-commit gitleaks et la détection de push protégé.",
      };
    });
    return out;
  },
};

// ─── Exploitation ciblée : sqlmap / ffuf ─────────────────────────────

const sqlmapSpec: ArsenalSpec = {
  tool: "SQLMAP",
  bin: () => REAL_EXEC.sqlmapBin,
  versionArgs: ["--version"],
  targets: ["URL"],
  cap: 30,
  phases: [
    [/target|parsing|testing connection/i, "PRÉPARATION", 15],
    [/testing|parameter|injection/i, "TESTS D'INJECTION", 60],
    [/backend|dbms|exploit|dump/i, "EXPLOITATION", 85],
  ],
  async build(ctx) {
    if (ctx.targetType !== "URL") {
      throw new Error("sqlmap audite un endpoint HTTP — cible non supportée");
    }
    const lvl =
      ctx.profile === "QUICK" ? ["--level=1", "--risk=1"]
      : ctx.profile === "DEEP" ? ["--level=5", "--risk=3", "--forms"]
      : ["--level=2", "--risk=2"];
    return {
      // NB : pas de --no-banner — rejeté par le sqlmap installé
      // (« no such option: --no-banner » → exit 2 immédiat, cf. scan
      // cmvv49byb0039p401tbk2ltdv). -v 0 suffit à limiter la sortie.
      args: [
        "-u", ctx.target, "--batch", "--threads=4", "-v", "0",
        "--output-dir", join(ctx.workdir, "sqlmap-out"),
        ...lvl,
      ],
      reportPath: null, // parsing du stdout capturé
      cmdLabel: `sqlmap -u ${ctx.target} --batch --threads=4 ${lvl.join(" ")}`,
    };
  },
  async parse({ stdout, ctx }) {
    // sqlmap -v 0 : les points d'injection confirmés apparaissent sous la forme
    //   Parameter: email (POST)
    //       Type: boolean-based blind | Title: … | Payload: …
    // Audit v2 (RF2bis) : la regex d'origine était paresseuse SANS ancre — le
    // groupe optionnel « (\((\w+)\))? » n'étant jamais rétrogradé, la capture
    // s'arrêtait au 1er caractère (« email » → « e »). L'ancre lookahead
    // « (?=\n|$) » force le moteur à développer la capture jusqu'à la fin de
    // ligne : le nom complet du paramètre est extrait (User-Agent, #1*, id…).
    const text = stdout.join("\n");
    const out: RealFinding[] = [];
    const paramRe = /Parameter:\s*([^\n]+?)\s*(?:\((\w+)\))?\s*(?=\n|$)/g;
    let match: RegExpExecArray | null;
    while ((match = paramRe.exec(text)) !== null) {
      const param = match[1].trim();
      const place = (match[2] ?? "request").toUpperCase();
      const from = match.index;
      const nextParam = text.indexOf("Parameter:", from + 1);
      const block = text.slice(from, nextParam === -1 ? Math.min(text.length, from + 3000) : nextParam);
      const type = /Type:\s*(.+)/.exec(block)?.[1]?.trim() ?? "";
      const title = /Title:\s*(.+)/.exec(block)?.[1]?.trim() ?? "";
      const payload = /Payload:\s*(.+)/.exec(block)?.[1]?.trim() ?? "";
      const dbms = /back-end DBMS:\s*(.+)/.exec(text)?.[1]?.trim() ?? "";
      if (!param) continue;
      const isUnion = /union/i.test(type);
      out.push({
        title: `Injection SQL confirmée — paramètre ${param} (${place})${title ? ` — ${title.slice(0, 120)}` : ""}`,
        severity: isUnion || /time-based|boolean/.test(type) ? "CRITICAL" : "HIGH",
        confidence: "CONFIRMED",
        category: "injection",
        cve: null,
        cvss: isUnion ? 9.8 : 8.6,
        location: `${ctx.target} — ${place} ${param}`,
        description:
          `sqlmap a confirmé une injection SQL sur le paramètre ${param} (${place}) via ${type || "injection classique"}` +
          `${dbms ? ` contre un back-end ${dbms}` : ""}. L'extraction de données (dump) et, selon les droits, ` +
          "l'écriture de fichiers sont réalisables par un attaquant.",
        evidence: evidenceBlock([`Type : ${type}`, `Title : ${title}`, `Payload : ${payload}`, dbms ? `Back-end : ${dbms}` : undefined]),
        poc: `sqlmap -u "${ctx.target}" -p ${param} --batch --level=2 --risk=2`,
        sentinelTriggered: false,
        remediation:
          "Requêtes préparées/ORM paramétré ; validation stricte des entrées ; moindre privilège du compte DB ; " +
          "WAF en complément ; alerte sur les tentatives d'injection.",
      });
      if (out.length >= 10) break; // plafond interne (le cap global re-tronque si besoin)
    }
    return out;
  },
};

const ffufSpec: ArsenalSpec = {
  tool: "FFUF",
  bin: () => REAL_EXEC.ffufBin,
  versionArgs: ["-V"],
  targets: ["URL"],
  cap: 200,
  phases: [
    [/starting|init|wordlist/i, "PRÉPARATION FUZZING", 15],
    [/progress|status|running/i, "FUZZING MASSE", 70],
    [/completed|saving|done/i, "RAPPORT", 90],
  ],
  async checkExtra() {
    const wl = REAL_EXEC.ffufWordlist;
    if (!existsSync(wl)) {
      // Repli Kali courant
      const fallback = "/usr/share/wordlists/dirb/common.txt";
      if (existsSync(fallback)) return null;
      return {
        available: false,
        reason: `wordlist introuvable (${wl} ou ${fallback}) — installer seclists ou définir FFUF_WORDLIST`,
      };
    }
    return null;
  },
  async build(ctx) {
    if (ctx.targetType !== "URL") {
      throw new Error("ffuf fuzz une URL de base — cible non supportée");
    }
    const base = baseOfUrl(ctx.target);
    const wl = existsSync(REAL_EXEC.ffufWordlist)
      ? REAL_EXEC.ffufWordlist
      : "/usr/share/wordlists/dirb/common.txt";
    const reportPath = join(ctx.workdir, "ffuf.json");
    // Audit v2 (RF4) : -t 30 saturait la cible (30 threads = fuzzing agressif,
    // DoS potentiel sur un petit VPS cible). -t 4 + -rate 100 : fuzzing contenu,
    // sans dégradation du service audité. -ac (autofilter) est conservé.
    return {
      args: [
        "-u", `${base}/FUZZ`, "-w", wl,
        "-of", "json", "-o", reportPath,
        "-ac", "-t", "4", "-rate", "100", "-timeout", "8", "-s",
      ],
      reportPath,
      cmdLabel: `ffuf -u ${base}/FUZZ -w ${wl} -of json -o ffuf.json -ac -t 4 -rate 100`,
    };
  },
  async parse({ reportPath }) {
    const raw = await readReport(reportPath);
    const rows = parseJsonOrJsonl(raw);
    const out: RealFinding[] = [];
    for (const r of rows) {
      const results = Array.isArray(r.results) ? (r.results as Record<string, unknown>[]) : [];
      for (const res of results) {
        const url = String(res.url ?? "").trim();
        const status = typeof res.status === "number" ? res.status : 0;
        if (!url || status <= 0 || status >= 400) continue;
        const input = (res.input ?? {}) as Record<string, unknown>;
        const fuzz = String(input.FUZZ ?? "").trim();
        const path = fuzz.startsWith("/") ? fuzz : fuzz ? `/${fuzz}` : "/";
        const words = typeof res.words === "number" ? res.words : 0;
        const interesting = /admin|backup|\.git|config|env|api|console|jenkins|actuator|debug|test|wp-|phpmyadmin|\.sql|\.bak|\.env/i.test(path);
        out.push({
          title: `Chemin découvert : ${path} (${status})`,
          severity: interesting ? "LOW" : "INFO",
          confidence: "CONFIRMED",
          category: interesting ? "info-disclosure" : "recon",
          cve: null,
          cvss: null,
          location: url,
          description:
            `ffuf a découvert le chemin ${path} (HTTP ${status}${words ? `, ${words} mots` : ""}).` +
            (interesting
              ? " Ce chemin porte un indice sensible (administration, sauvegarde, configuration…) — à vérifier manuellement."
              : " Chemin actif identifié par fuzzing de répertoires."),
          evidence: evidenceBlock([`${url} → ${status}`]),
          poc: `curl -si ${url}`,
          sentinelTriggered: false,
        });
      }
    }
    return out;
  },
};

// ─── Sprint 1 « élargissement » : WPScan / Dalfox / WhatWeb / testssl.sh /
// ─── wafw00f / hydra / john ───────────────────────────────────────────

/**
 * Endpoint hôte[:port] pour les outils TLS/réseau :
 *  - URL : hôte + port explicite, sinon hôte nu (testssl.sh scanne 443 par défaut —
 *    un audit TLS porte sur le point de terminaison TLS, pas sur le port 80 clair) ;
 *  - NETWORK : suffixe CIDR retiré, forme hôte:port conservée telle quelle.
 */
function endpointOfTarget(target: string, targetType: TargetType): string {
  if (targetType === "URL") {
    try {
      const u = new URL(target);
      return u.port ? `${u.hostname}:${u.port}` : u.hostname;
    } catch {
      return hostOfTarget(target, targetType);
    }
  }
  return (target.split("/")[0] ?? target).trim();
}

/** Détection WAF — enregistrements wafw00f (JSON array, -o .json). */
const wafw00fSpec: ArsenalSpec = {
  tool: "WAFW00F",
  bin: () => REAL_EXEC.wafw00fBin,
  targets: ["URL"],
  cap: 50,
  phases: [
    [/request|checking|fingerprin/i, "SONDES WAF", 45],
    [/generic|result|number of requests/i, "DÉTECTION GÉNÉRIQUE", 85],
  ],
  async build(ctx) {
    const probe = baseOfUrl(ctx.target);
    const reportPath = join(ctx.workdir, "wafw00f.json");
    return {
      args: [probe, "-a", "-o", reportPath, "--no-colors"],
      reportPath,
      cmdLabel: `wafw00f ${probe} -a -o wafw00f.json`,
    };
  },
  async parse({ reportPath }) {
    const raw = await readReport(reportPath);
    if (!raw.trim()) return []; // rapport absent → échec honnête (garde-fou amont)
    const rows = parseJsonOrJsonl(raw);
    const out: RealFinding[] = [];
    const detected: string[] = [];
    for (const r of rows) {
      const url = String(r.url ?? "").trim();
      const firewall = String(r.firewall ?? "").trim();
      const manufacturer = String(r.manufacturer ?? "").trim();
      if (r.detected === true && firewall && firewall !== "None") {
        detected.push(`${firewall} (${manufacturer || "fabricant inconnu"})`);
        out.push({
          title: `WAF détecté : ${firewall}`, severity: "INFO",
          confidence: "CONFIRMED", category: "recon", cve: null, cvss: null,
          location: url || undefined,
          description:
            `Un pare-feu applicatif web (${firewall}${manufacturer ? `, éditeur ${manufacturer}` : ""}) intercepte ` +
            "les requêtes malveillantes en amont de l'application. Connaître le WAF en place permet de " +
            "calibrer les tests (bypass, rate-limit, règles bloquantes) et d'évaluer la couverture réelle " +
            "de cette couche de défense.",
          evidence: evidenceBlock([
            typeof r.trigger_url === "string" && r.trigger_url
              ? `requête de déclenchement : ${r.trigger_url}` : undefined,
          ]),
          sentinelTriggered: false,
        });
      }
    }
    const noneDetected = detected.length === 0;
    if (noneDetected) {
      out.push({
        title: "Aucun WAF détecté en amont de la cible", severity: "LOW",
        confidence: "CONFIRMED", category: "misconfig", cve: null, cvss: null,
        location: undefined,
        description:
          "wafw00f (tous détecteurs) n'a identifié aucun pare-feu applicatif web devant l'application. " +
          "Les requêtes offensives atteignent directement le serveur : les exploits publics et le fuzzing " +
          "ne sont ni filtrés ni ralentis. Ce n'est pas une vulnérabilité en soi, mais une couche de " +
          "défense en profondeur absente (ou furtive/CDN non signaturé).",
        evidence: `Cible sondée avec l'ensemble des détecteurs wafw00f (${rows.length} résultat(s)).`,
        sentinelTriggered: false,
        remediation:
          "Si un WAF est censé protéger l'application : vérifier son déploiement et sa visibilité DNS. " +
          "Sinon : évaluer l'ajout d'un WAF/CDN (Cloudflare, AWS WAF, ModSecurity) en complément du durcissement applicatif.",
      });
    }
    out.push({
      title: `wafw00f : ${detected.length} WAF identifié(s) sur ${rows.length} enregistrement(s)`,
      severity: "INFO", confidence: "CONFIRMED", category: "recon", cve: null, cvss: null,
      location: undefined,
      description: "Synthèse de la détection de WAF (empreintes d'éditeurs + détection générique par différences de réponses).",
      evidence: evidenceBlock(detected.length ? detected : ["aucun WAF identifié"]),
      sentinelTriggered: false,
    });
    return out;
  },
};

/** Empreinte web — whatweb (log JSON array). */
const whatwebSpec: ArsenalSpec = {
  tool: "WHATWEB",
  bin: () => REAL_EXEC.whatwebBin,
  targets: ["URL", "NETWORK"],
  cap: 120,
  phases: [
    [/loading|plugin|start/i, "CHARGEMENT PLUGINS", 20],
    [/target|scanning|request/i, "EMPREINTE CIBLE", 65],
    [/finished|summar/i, "CONSOLIDATION", 90],
  ],
  async build(ctx) {
    const probe = httpProbeTarget(ctx.target, ctx.targetType);
    const reportPath = join(ctx.workdir, "whatweb.json");
    // Aggressiveness : 1 (furtif) → 3 (agressif) → 4 (heavy, DEEP uniquement).
    const aggr = ctx.profile === "QUICK" ? "1" : ctx.profile === "STANDARD" ? "3" : "4";
    return {
      args: ["--color=never", "--no-errors", "-a", aggr, `--log-json=${reportPath}`, probe],
      reportPath,
      cmdLabel: `whatweb --color=never --no-errors -a ${aggr} --log-json=whatweb.json ${probe}`,
    };
  },
  async parse({ reportPath }) {
    const raw = await readReport(reportPath);
    if (!raw.trim()) return [];
    const rows = parseJsonOrJsonl(raw);
    const out: RealFinding[] = [];
    const versions: string[] = [];
    let httpStatus = 0;
    const pluginNames: string[] = [];
    for (const r of rows) {
      httpStatus = typeof r.http_status === "number" ? r.http_status : httpStatus;
      const plugins = (r.plugins ?? {}) as Record<string, Record<string, unknown>>;
      for (const [name, p] of Object.entries(plugins)) {
        pluginNames.push(name);
        const versionsList = Array.isArray(p.version) ? (p.version as unknown[]).map(String) : [];
        if (versionsList.length > 0) versions.push(`${name} ${versionsList.join(", ")}`);
        // Versions technologies exposées publiquement → renseigne l'attaquant
        // (CVE ciblées par version précise).
        const interesting = /php|apache|nginx|iis|asp\.net|wordpress|joomla|drupal|tomcat|express|struts|weblogic|shibboleth|jetty/i.test(name);
        if (interesting && versionsList.length > 0) {
          out.push({
            title: `Technologie versionnée exposée : ${name} ${versionsList.join(", ")}`,
            severity: "LOW", confidence: "CONFIRMED", category: "info-disclosure",
            cve: null, cvss: null,
            location: String(r.target ?? "") || undefined,
            description:
              `whatweb a identifié ${name} en version ${versionsList.join(", ")} via l'empreinte HTTP. ` +
              "Une version précise exposée permet de cibler les CVE connues de cette version exacte " +
              "sans phase de sondage.",
            evidence: evidenceBlock([
              `plugin : ${name}`, `version(s) : ${versionsList.join(", ")}`,
              typeof p.string === "string" && p.string ? `détail : ${p.string}` : undefined,
            ]),
            sentinelTriggered: false,
            remediation: "Masquer les en-têtes de version (ServerTokens Prod, server_tokens off, expose_php=Off) ; mettre à jour les composants.",
          });
        }
      }
    }
    if (httpStatus >= 500) {
      out.push({
        title: `Erreur serveur à l'empreinte : HTTP ${httpStatus}`, severity: "LOW",
        confidence: "CONFIRMED", category: "info-disclosure", cve: null, cvss: null,
        location: undefined,
        description: "La cible a répondu par une erreur serveur pendant l'empreinte — endpoint instable ou en panne.",
        evidence: `statut HTTP : ${httpStatus}`, sentinelTriggered: false,
      });
    }
    out.push({
      title: `whatweb : ${pluginNames.length} plugin(s) d'empreinte identifié(s) (HTTP ${httpStatus || "?"})`,
      severity: pluginNames.length > 0 ? "INFO" : "LOW",
      confidence: "CONFIRMED", category: "recon", cve: null, cvss: null, location: undefined,
      description:
        `Empreinte web de la cible : ${pluginNames.length} technologie(s)/caractéristique(s) identifiée(s)` +
        (versions.length ? ` — versions exposées : ${versions.slice(0, 10).join(" ; ")}` : " (aucune version divulguée)") +
        ". Cette cartographie oriente le choix des exploits et des templates Nuclei.",
      evidence: evidenceBlock(pluginNames.slice(0, 40)),
      sentinelTriggered: false,
    });
    return out;
  },
};

/** WordPress — WPScan (rapport JSON, API de vulnérabilités optionnelle). */
const wpscanSpec: ArsenalSpec = {
  tool: "WPSCAN",
  bin: () => REAL_EXEC.wpscanBin,
  targets: ["URL"],
  cap: 200,
  phases: [
    [/enumerat|checking|detection/i, "ÉNUMÉRATION WP", 35],
    [/plugins?|themes?|users?/i, "PLUGINS / THÈMES / USERS", 70],
    [/vulnerab|finished|report/i, "RAPPORT", 92],
  ],
  async build(ctx) {
    const probe = baseOfUrl(ctx.target);
    const reportPath = join(ctx.workdir, "wpscan.json");
    const enums =
      ctx.profile === "QUICK" ? "vp,vt"
      : ctx.profile === "STANDARD" ? "vp,vt,u"
      : "vp,vt,u,cb,dbe,bf"; // DEEP : + config-backups, db-exports, backup-folders
    return {
      args: [
        "--url", probe, "--format", "json", "--output", reportPath,
        "--no-banner", "--no-update", "--random-user-agent",
        "--request-timeout", "15", "--connect-timeout", "10",
        "--enumerate", enums,
      ],
      reportPath,
      cmdLabel: `wpscan --url ${probe} --format json --enumerate ${enums} --no-update --random-user-agent`,
    };
  },
  async parse({ reportPath }) {
    const raw = await readReport(reportPath);
    if (!raw.trim()) return [];
    const rows = parseJsonOrJsonl(raw);
    const out: RealFinding[] = [];
    const wpscanCvss = (score: unknown, rating: unknown): RealFinding["severity"] => {
      if (typeof score === "number" && score > 0) {
        if (score >= 9) return "CRITICAL";
        if (score >= 7) return "HIGH";
        if (score >= 4) return "MEDIUM";
        return "LOW";
      }
      const r = String(rating ?? "").toLowerCase();
      if (SEVERITIES.has(r)) return r.toUpperCase() as RealFinding["severity"];
      return "HIGH";
    };
    /** Parse un bloc "item" (plugin/thème) : obsolète + vulnérabilités CVE. */
    const wpItemFindings = (slug: string, item: Record<string, unknown>, kind: "plugin" | "thème") => {
      const version = (item.version ?? {}) as Record<string, unknown>;
      const vnum = String(version.number ?? "?").trim();
      if (version.outdated === true) {
        out.push({
          title: `${kind === "plugin" ? "Plugin" : "Thème"} WordPress obsolète : ${slug} (v${vnum})`,
          severity: "MEDIUM", confidence: "CONFIRMED", category: "sca", cve: null, cvss: null,
          location: String(item.location ?? "") || undefined,
          description:
            `Le ${kind} « ${slug} » (v${vnum}) n'est plus à jour (dernière version publiée : ` +
            `${String(version.latest_version ?? "inconnue")}). Les composants obsolètes cumulent des ` +
            "failles publiques non corrigées et élargissent la surface d'attaque du site.",
          evidence: evidenceBlock([
            `version installée : ${vnum}`, `dernière version : ${String(version.latest_version ?? "?")}`,
            version.last_updated ? `dernière mise à jour amont : ${String(version.last_updated)}` : undefined,
          ]),
          sentinelTriggered: false,
          remediation: `Mettre à jour ${slug} vers ${String(version.latest_version ?? "la dernière version")} puis re-tester.`,
        });
      }
      const vulns = Array.isArray(item.vulnerabilities) ? (item.vulnerabilities as Record<string, unknown>[]) : [];
      for (const v of vulns) {
        const title = String(v.title ?? "Vulnérabilité WordPress").trim();
        const cvss = (v.cvss ?? {}) as Record<string, unknown>;
        const refs = (v.references ?? {}) as Record<string, unknown>;
        const cves = Array.isArray(refs.cve) ? (refs.cve as unknown[]).map(String) : [];
        const fixed = String(v.fixed_in ?? "").trim();
        out.push({
          title: `${kind === "plugin" ? "Plugin" : "Thème"} vulnérable : ${slug} — ${title.slice(0, 140)}`,
          severity: wpscanCvss(cvss.score, cvss.rating),
          confidence: "CONFIRMED", category: kind === "plugin" ? "sca" : "web",
          cve: cves[0] ? `CVE-${cves[0].replace(/^CVE-?/i, "")}` : null,
          cvss: typeof cvss.score === "number" ? cvss.score : null,
          location: String(item.location ?? "") || undefined,
          description:
            `WPScan a identifié une vulnérabilité documentée affectant ${slug} v${vnum} : ${title}` +
            (fixed ? ` — corrigée en ${fixed}` : " (aucun correctif listé)"),
          evidence: evidenceBlock([
            cves.length ? `CVE : ${cves.slice(0, 5).join(", ")}` : undefined,
            typeof cvss.score === "number" ? `CVSS : ${cvss.score} (${String(cvss.rating ?? "?")})` : undefined,
            Array.isArray(refs.url) ? `références : ${(refs.url as unknown[]).slice(0, 3).map(String).join(" ; ")}` : undefined,
          ]),
          sentinelTriggered: false,
          remediation: fixed ? `Mettre à jour ${slug} en version ${fixed} (ou au-delà).` : "Rechercher un correctif ou remplacer le composant.",
        });
      }
    };
    let artifacts = 0;
    for (const r of rows) {
      const interesting = Array.isArray(r.interesting_findings) ? (r.interesting_findings as Record<string, unknown>[]) : [];
      for (const f of interesting) {
        const toS = String(f.to_s ?? "").trim();
        const url = String(f.url ?? "").trim();
        if (!toS && !url) continue;
        artifacts++;
        const sensitive = /xmlrpc|readme|debug\.log|backup|config|\.sql|wp-content\/debug|database/i.test(`${toS} ${url}`);
        out.push({
          title: `Artefact WordPress exposé : ${(toS || url).slice(0, 160)}`,
          severity: sensitive ? "MEDIUM" : "LOW", confidence: "CONFIRMED", category: "info-disclosure",
          cve: null, cvss: null, location: url || undefined,
          description:
            `WPScan a identifié un artefact accessible (${toS || url}) — découvert par ${String(f.found_by ?? "sonde standard")}. ` +
            (sensitive ? "Cet artefact peut révéler des informations techniques ou un point d'entrée d'exploitation."
              : "Cet artefact confirme l'installation WordPress et précise son empreinte."),
          evidence: evidenceBlock([url ? `URL : ${url}` : undefined, `découvert par : ${String(f.found_by ?? "?")}`]),
          sentinelTriggered: false,
          remediation: sensitive ? "Restreindre l'accès à l'artefact (XML-RPC, fichiers de debug, sauvegardes) via le serveur web ou un WAF." : undefined,
        });
      }
      const version = (r.version ?? null) as Record<string, unknown> | null;
      if (version && typeof version === "object") {
        artifacts++;
        const vnum = String(version.number ?? "?").trim();
        if (vnum !== "?") {
          out.push({
            title: `Version WordPress identifiée : ${vnum}`, severity: "INFO",
            confidence: "CONFIRMED", category: "recon", cve: null, cvss: null, location: undefined,
            description:
              `Le cœur WordPress est en version ${vnum} (découverte : ${String(version.found_by ?? "sonde standard")}). ` +
              "Une version précise permet de cibler les CVE du cœur ; les versions anciennes devraient être mises à jour.",
            evidence: evidenceBlock([`version : ${vnum}`, version.release_date ? `sortie : ${String(version.release_date)}` : undefined]),
            sentinelTriggered: false,
          });
        }
      }
      const plugins = (r.plugins ?? {}) as Record<string, Record<string, unknown>>;
      for (const [slug, item] of Object.entries(plugins)) { artifacts++; wpItemFindings(slug, item, "plugin"); }
      const themes = (r.themes ?? {}) as Record<string, Record<string, unknown>>;
      for (const [slug, item] of Object.entries(themes)) { artifacts++; wpItemFindings(slug, item, "thème"); }
      const users = (r.users ?? {}) as Record<string, Record<string, unknown>>;
      for (const name of Object.keys(users)) {
        artifacts++;
        out.push({
          title: `Utilisateur WordPress divulgué : ${name}`, severity: "MEDIUM",
          confidence: "CONFIRMED", category: "auth", cve: null, cvss: null, location: undefined,
          description:
            `Le nom d'utilisateur « ${name} » est divulgué publiquement (énumération d'auteurs, REST API ou flux). ` +
            "Un nom de compte valide réduit de moitié le coût d'une attaque par force brute sur wp-login.",
          evidence: evidenceBlock([`utilisateur : ${name}`, String(users[name]?.found_by ?? "")]),
          sentinelTriggered: false,
          remediation: "Masquer les mentions d'auteur (REST /users, ?author=N, flux) ; MFA et verrouillage sur wp-login."
        });
      }
    }
    if (artifacts === 0) {
      out.push({
        title: "WPScan : aucun artefact WordPress identifié", severity: "INFO",
        confidence: "CONFIRMED", category: "recon", cve: null, cvss: null, location: undefined,
        description:
          "Le scan s'est déroulé sans erreur mais n'a détecté aucun artefact WordPress (version, plugins, thèmes, " +
          "utilisateurs, points d'intérêt) : la cible n'est probablement pas un site WordPress, ou masque complètement son empreinte.",
        evidence: "Rapport WPScan lu et analysé — aucun artefact.", sentinelTriggered: false,
      });
    }
    return out;
  },
};

/** XSS — Dalfox v3 (rapport JSON objet {findings, meta}). */
const dalfoxSpec: ArsenalSpec = {
  tool: "DALFOX",
  bin: () => REAL_EXEC.dalfoxBin,
  targets: ["URL"],
  cap: 200,
  phases: [
    [/param|mining|discovery|analy/i, "DÉCOUVERTE PARAMÈTRES", 30],
    [/payload|inject|test|scanning/i, "INJECTION PAYLOADS", 65],
    [/finish|summary|report/i, "RAPPORT", 92],
  ],
  async build(ctx) {
    const probe = baseOfUrl(ctx.target);
    const reportPath = join(ctx.workdir, "dalfox.json");
    // v3 : sous-commande « scan » (v2 : « url »). --only-poc v,r,a = vulnérabilités,
    // réflexions exploitables, DOM AST. Sortie JSON objet (findings + meta).
    const args = [
      "scan", probe, "-f", "json", "-o", reportPath,
      "-S", "--no-color", "--timeout", "20", "--only-poc", "v,r,a",
    ];
    if (ctx.profile === "DEEP") args.push("--deep-scan");
    return {
      args,
      reportPath,
      cmdLabel: `dalfox scan ${probe} -f json -o dalfox.json -S --timeout 20 --only-poc v,r,a${ctx.profile === "DEEP" ? " --deep-scan" : ""}`,
    };
  },
  async parse({ reportPath, ctx }) {
    const raw = await readReport(reportPath);
    if (!raw.trim()) return [];
    const rows = parseJsonOrJsonl(raw);
    const out: RealFinding[] = [];
    let confirmed = 0;
    let candidates = 0;
    const skipped: string[] = [];
    for (const r of rows) {
      // meta.target_summary : statut par cible — skipped = cible non auditable.
      const summary = Array.isArray(r.target_summary) ? (r.target_summary as Record<string, unknown>[]) : [];
      for (const t of summary) {
        if (t.status === "skipped") {
          skipped.push(`${String(t.target ?? "?")} (${String(t.error_code ?? "erreur")})`);
        }
      }
      const findings = Array.isArray(r.findings) ? (r.findings as Record<string, unknown>[]) : [];
      for (const f of findings) {
        const type = String(f.type ?? "").toUpperCase();
        const param = String(f.param ?? "").trim();
        const payload = String(f.payload ?? "").trim();
        if (!param && !payload) continue;
        const vulnerable = type === "V" || type === "A";
        if (vulnerable) confirmed++;
        else candidates++;
        out.push({
          title: `XSS ${vulnerable ? "confirmé" : "candidat"} — paramètre ${param || "?"} (${String(f.inject_type ?? "?")})`,
          severity: normSeverity(f.severity, vulnerable ? "HIGH" : "LOW"),
          confidence: vulnerable ? (String(f.confidence ?? "") === "high" ? "CONFIRMED" : "PROBABLE") : "PROBABLE",
          category: "xss", cve: null, cvss: vulnerable ? 7.1 : null,
          location: param ? `${String(f.data ?? ctx.target).slice(0, 200)} — paramètre ${param}` : undefined,
          description:
            (vulnerable ? "Dalfox a DÉCLENCHÉ un payload XSS avec succès" : "Dalfox a observé une réflexion de payload exploitable") +
            ` sur le paramètre « ${param} » (${String(f.inject_type ?? "?")} — contexte ${String(f.location ?? "?")}).` +
            ` ${String(f.evidence ?? "")}`.trim(),
          evidence: evidenceBlock([
            `message : ${String(f.message_str ?? "")}`,
            `payload : ${payload}`,
            `méthode de détection : ${String(f.detection_method ?? "?")}`,
            typeof f.cwe === "string" ? `CWE : ${f.cwe}` : undefined,
          ]),
          poc: typeof f.data === "string" && f.data ? f.data : undefined,
          sentinelTriggered: false,
          remediation:
            "Échapper systématiquement les sorties HTML (contexte-aware), appliquer une CSP stricte, " +
            "valider les entrées côté serveur et éviter les réflexions brutes dans le DOM.",
        });
      }
    }
    // Honnêteté : toutes les cibles « skipped » → l'audit n'a pas eu lieu.
    if (candidates === 0 && confirmed === 0 && skipped.length > 0) {
      throw new Error(
        `dalfox n'a pu auditer la cible (toutes skippées : ${skipped.join(" ; ")}) — cible injoignable depuis le moteur ?`,
      );
    }
    out.push({
      title: `dalfox : ${confirmed} XSS confirmé(s), ${candidates} candidat(s) réfléchi(s)`,
      severity: confirmed > 0 ? "HIGH" : "INFO", confidence: "CONFIRMED", category: "xss",
      cve: null, cvss: null, location: undefined,
      description:
        `Synthèse Dalfox : ${confirmed} payload(s) déclenché(s) (exploitable) et ${candidates} réflexion(s) ` +
        "candidat(s) (à vérifier manuellement). Chaque constat individuel ci-dessus embarque le payload, " +
        "le contexte d'injection et une URL de preuve reproduisible.",
      evidence: evidenceBlock([
        skipped.length ? `cibles skippées : ${skipped.join(" ; ")}` : undefined,
      ]),
      sentinelTriggered: false,
    });
    return out;
  },
};

/** TLS/SSL — testssl.sh (rapport JSON structuré, array). */
const testsslSpec: ArsenalSpec = {
  tool: "TESTSSL",
  bin: () => REAL_EXEC.testsslBin,
  probeTimeoutMs: 15_000,
  targets: ["URL", "NETWORK"],
  cap: 150,
  phases: [
    [/start|Services|host/i, "PRÉ-TESTS", 15],
    [/protocol|cipher| TLS|pfs/i, "PROTOCOLS / CIPHERS", 45],
    [/vulnerab|certificate|client/i, "VULNÉRABILITÉS TLS", 80],
  ],
  async build(ctx) {
    const endpoint = endpointOfTarget(ctx.target, ctx.targetType);
    const reportPath = join(ctx.workdir, "testssl.json");
    return {
      args: [
        "--jsonfile-pretty", reportPath, "--quiet", "--color", "0",
        "--warnings", "off", "--connect-timeout", "12", endpoint,
      ],
      reportPath,
      cmdLabel: `testssl.sh --jsonfile-pretty testssl.json --quiet ${endpoint}`,
    };
  },
  async parse({ reportPath }) {
    const raw = await readReport(reportPath);
    if (!raw.trim()) return [];
    const rows = parseJsonOrJsonl(raw);
    const out: RealFinding[] = [];
    const infoLines: string[] = [];
    let counted = 0;
    for (const r of rows) {
      const id = String(r.id ?? "").trim();
      const finding = String(r.finding ?? "").trim();
      if (!id || !finding) continue;
      const severity = String(r.severity ?? "INFO").toUpperCase();
      const port = typeof r.port === "number" ? r.port : null;
      const loc = `${String(r.ip ?? r.target ?? "?")}${port ? `:${port}` : ""}`;
      if (severity === "INFO") {
        infoLines.push(`${id} : ${finding.slice(0, 150)}`);
        continue;
      }
      counted++;
      out.push({
        title: `TLS ${severity.toLowerCase()} — ${id} : ${finding.slice(0, 130)}`,
        severity: normSeverity(severity, "LOW"),
        confidence: "CONFIRMED", category: "tls",
        cve: typeof r.cve === "string" && r.cve.trim() ? r.cve.trim() : null,
        cvss: null, location: loc,
        description:
          `testssl.sh a relevé un problème TLS de sévérité ${severity.toLowerCase()} (test ${id}) : ${finding}. ` +
          "Les faiblesses TLS (protocoles obsolètes, suites faibles, certificats invalides, vulnérabilités " +
          "historiques) exposent les échanges à l'interception et à la dégradation.",
        evidence: evidenceBlock([
          `test : ${id}`, `constat : ${finding}`,
          typeof r.cwe === "string" && r.cwe ? `CWE : ${r.cwe}` : undefined,
        ]),
        sentinelTriggered: false,
      });
    }
    if (counted === 0 && infoLines.length > 0) {
      out.push({
        title: "testssl.sh : configuration TLS sans anomalie notable", severity: "INFO",
        confidence: "CONFIRMED", category: "tls", cve: null, cvss: null, location: undefined,
        description:
          "Le scan TLS complet n'a révélé aucune vulnérabilité de sévérité LOW à CRITICAL — la configuration " +
          "TLS de l'endpoint est robuste au regard des tests standards (protocoles, suites, certificat, vulnérabilités historiques).",
        evidence: evidenceBlock(infoLines.slice(0, 40)), sentinelTriggered: false,
      });
    }
    return out;
  },
};

/**
 * Identifiants par défaut — hydra (SSH uniquement, liste FIXE de 14 paires
 * par défaut, débit plafonné : t4/w10, -f stop au premier succès). Ce test
 * ciblé remplace le brute-force générique (hors périmètre de la plateforme).
 */
const HYDRA_DEFAULT_CREDS = [
  "root:root", "root:toor", "root:password", "root:123456",
  "admin:admin", "admin:password", "admin:123456", "admin:changeme",
  "test:test", "ubuntu:ubuntu", "debian:debian", "pi:raspberry",
  "user:user", "guest:guest",
] as const;

const hydraSpec: ArsenalSpec = {
  tool: "HYDRA",
  bin: () => REAL_EXEC.hydraBin,
  // hydra -h affiche l'aide puis sort en -1 (255) — la sonde du moteur ne
  // regarde que la présence de sortie : probe honnête (binaire présent).
  versionArgs: ["-h"],
  targets: ["NETWORK"],
  cap: 50,
  phases: [
    [/data|task|attempt/i, "ATTAQUE DICTIONNAIRE", 50],
    [/valid password|login:|found/i, "VÉRIFICATION", 85],
  ],
  async build(ctx) {
    if (ctx.targetType !== "NETWORK") {
      throw new Error("hydra audite un hôte réseau (module SSH) — cible non supportée");
    }
    const hostPort = (ctx.target.split("/")[0] ?? ctx.target).trim();
    if (!hostPort || hostPort.startsWith("-")) {
      throw new Error(`cible hydra invalide : ${ctx.target}`);
    }
    // Liste fixe d'identifiants PAR DÉFAUT (pas de brute-force générique) —
    // écrite dans le workdir du scan, jamais partagée entre scans.
    const credsPath = join(ctx.workdir, "hydra-default-creds.txt");
    await writeFile(credsPath, HYDRA_DEFAULT_CREDS.join("\n") + "\n", "utf8");
    const reportPath = join(ctx.workdir, "hydra-report.txt");
    return {
      args: [
        "-C", credsPath, "-t", "4", "-w", "10", "-f",
        "-o", reportPath, `ssh://${hostPort}`,
      ],
      reportPath,
      cmdLabel: `hydra -C (14 identifiants par défaut) -t 4 -w 10 -f -o hydra-report.txt ssh://${hostPort}`,
    };
  },
  async parse({ reportPath }) {
    const raw = await readReport(reportPath);
    if (!raw.trim()) return [];
    const out: RealFinding[] = [];
    const foundRe = /^\[(\d+)\]\[(\w+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(.+?)\s*$/;
    let found = 0;
    for (const line of raw.split("\n")) {
      const m = foundRe.exec(line.trim());
      if (!m) continue;
      found++;
      const [, port, service, host, login, password] = m;
      out.push({
        title: `Identifiants par défaut valides : ${service}://host (port ${port}) — ${login}`,
        severity: "CRITICAL", confidence: "CONFIRMED", category: "auth",
        cve: null, cvss: 9.8, location: `${host}:${port}`,
        description:
          `hydra a authentifié avec succès le compte « ${login} » via un mot de passe par défaut bien connu ` +
          `(${service} port ${port}). Un accès distant authentifié = compromission totale potentielle de l'hôte.`,
        evidence: evidenceBlock([
          `service : ${service} — hôte : ${host} — port : ${port}`,
          `identifiant : ${login}`,
          `mot de passe : ${password.slice(0, 60)}`,
        ]),
        poc: `ssh ${login}@${host} -p ${port}`,
        sentinelTriggered: false,
        remediation:
          "Changer immédiatement le mot de passe, interdire l'authentification par mot de passe (clés SSH " +
          "uniquement), restreindre l'accès par pare-feu/VPN et activer fail2ban.",
      });
    }
    out.push({
      title: `hydra : test d'identifiants par défaut terminé — ${found} identifiant(s) valide(s)`,
      severity: found > 0 ? "CRITICAL" : "INFO", confidence: "CONFIRMED", category: "auth",
      cve: null, cvss: null, location: undefined,
      description:
        `Vérification d'identifiants par défaut (liste FIXE de ${HYDRA_DEFAULT_CREDS.length} paires courantes, ` +
        "débit plafonné à 4 tentatives parallèles, arrêt au premier succès) sur le service SSH de la cible. " +
        (found > 0 ? "DES IDENTIFIANTS PAR DÉFAUT SONT ACTIFS — action immédiate requise." : "Aucun identifiant par défaut n'est actif."),
      evidence: evidenceBlock(HYDRA_DEFAULT_CREDS.slice(0, 14)),
      sentinelTriggered: false,
      remediation: found > 0 ? "Rotation immédiate des credentials ; authentification par clés uniquement." : undefined,
    });
    return out;
  },
};

/**
 * Craquage de hashes faibles — john (cibles GIT : htpasswd, shadow, SSHA…
 * détectés par motifs dans le dépôt cloné, wordlist john-data par défaut).
 * Le scan craque AVEC LA WORDLIST SEULE : un hash non craqué n'est PAS une
 * vulnérabilité — seul un mot de passe trouvé est un constat.
 */
const JOHN_HASH_PATTERNS: RegExp[] = [
  /\$apr1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22,}/, // Apache MD5 (apr1)
  /\$1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{31}/, // md5crypt
  /\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}/, // bcrypt
  /\$5\$(?:rounds=\d+\$)?[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{43}/, // sha256crypt
  /\$6\$(?:rounds=\d+\$)?[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{86}/, // sha512crypt
  /\{SSHA\}[A-Za-z0-9+/=]{24,}/, // LDAP SSHA
  /\{SHA\}[A-Za-z0-9+/=]{28}/, // LDAP SHA1
];
const JOHN_SKIP_DIRS = new Set([
  ".git", "node_modules", "vendor", "__pycache__", ".next", "dist", "build", ".venv",
]);
const JOHN_TRIVIAL_PASSWORDS = new Set([
  "password", "123456", "12345678", "admin", "root", "toor", "qwerty",
  "letmein", "abc123", "changeme", "welcome", "monkey", "dragon", "iloveyou",
]);

const johnSpec: ArsenalSpec = {
  tool: "JOHN",
  bin: () => REAL_EXEC.johnBin,
  versionArgs: ["--list=build-info"],
  targets: ["GIT"],
  cap: 100,
  phases: [
    [/loaded|formats|hashes/i, "CHARGEMENT HASHES", 30],
    [/guess|crack|wordlist|rules/i, "CRAQUAGE WORDLIST", 70],
    [/session|completed|done/i, "RAPPORT", 92],
  ],
  async checkExtra() {
    if (!existsSync(REAL_EXEC.johnWordlist)) {
      return {
        available: false,
        reason: `wordlist john introuvable (${REAL_EXEC.johnWordlist}) — installer john-data ou définir JOHN_WORDLIST`,
      };
    }
    return null;
  },
  async build(ctx) {
    const dir = await prepareTarget(ctx);
    // 1) Balayage du dépôt cloné → collecte des lignes contenant des hashes.
    const hashLines = new Set<string>();
    let filesSeen = 0;
    const walk = async (root: string, depth: number): Promise<void> => {
      if (depth > 6 || filesSeen > 3000) return;
      let entries;
      try {
        entries = await readdir(root, { withFileTypes: true });
      } catch {
        return; // répertoire illisible — ignoré
      }
      for (const e of entries) {
        if (filesSeen > 3000) return;
        const full = join(root, e.name);
        if (e.isDirectory()) {
          if (!JOHN_SKIP_DIRS.has(e.name)) await walk(full, depth + 1);
          continue;
        }
        if (!e.isFile()) continue;
        filesSeen++;
        try {
          const st = await stat(full);
          if (st.size > 2 * 1024 * 1024) continue; // fichier volumineux — hors périmètre
          const content = await readFile(full, "utf8");
          if (content.slice(0, 1000).includes("\u0000")) continue; // binaire
          for (const line of content.split("\n")) {
            const trimmed = line.trim().slice(0, 400);
            if (!trimmed) continue;
            for (const re of JOHN_HASH_PATTERNS) {
              if (re.test(trimmed)) {
                hashLines.add(trimmed);
                break;
              }
            }
          }
        } catch {
          /* fichier illisible (binaire/permissions) — ignoré */
        }
      }
    };
    await walk(dir.value, 0);
    const modePath = join(ctx.workdir, "john-mode.json");
    const hashFile = join(ctx.workdir, "hashes.txt");
    if (hashLines.size === 0) {
      // Aucun hash dans le dépôt : john tourne en mode inventaire (sans crack)
      // et le parse rend un constat INFO honnête (mode "none" consigné).
      await writeFile(modePath, JSON.stringify({ mode: "none", hashes: 0 }), "utf8");
      return {
        args: ["--list=formats"],
        reportPath: null,
        cmdLabel: `john --list=formats (aucun hash détecté dans ${dir.cloned ? "le dépôt cloné" : dir.value})`,
      };
    }
    await writeFile(hashFile, [...hashLines].join("\n") + "\n", "utf8");
    await writeFile(modePath, JSON.stringify({ mode: "crack", hashes: hashLines.size }), "utf8");
    // NB : pas d'option « --no-log » — absente du john Debian (erreur
    // « Unknown option ») ; la verbosité par défaut est journalisée par le
    // moteur et le parse lit les guesses live sur stdout.
    const args = [`--wordlist=${REAL_EXEC.johnWordlist}`];
    if (ctx.profile === "DEEP") args.push("--rules"); // mangles wordlist (DEEP uniquement)
    args.push(hashFile);
    return {
      args,
      reportPath: null, // parsing du stdout capturé (guesses live de john)
      cmdLabel: `john --wordlist=password.lst${ctx.profile === "DEEP" ? " --rules" : ""} hashes.txt (${hashLines.size} hash(s) détecté(s) dans le dépôt)`,
    };
  },
  async parse({ stdout, ctx }) {
    let mode: { mode?: string; hashes?: number } = {};
    try {
      const raw = await readFile(join(ctx.workdir, "john-mode.json"), "utf8");
      mode = JSON.parse(raw) as { mode?: string; hashes?: number };
    } catch {
      mode = {};
    }
    const out: RealFinding[] = [];
    if (mode.mode !== "crack") {
      out.push({
        title: "John : aucun hash de mot de passe détecté dans le dépôt", severity: "INFO",
        confidence: "CONFIRMED", category: "secrets", cve: null, cvss: null, location: undefined,
        description:
          "Le balayage du dépôt (htpasswd, shadow, LDAP, bcrypt/md5crypt/sha256crypt/sha512crypt) n'a trouvé " +
          "aucun hash de mot de passe à évaluer. Aucun credential faible exposable via le dépôt.",
        evidence: `Motifs testés : apr1, md5crypt ($1$), bcrypt ($2a/b/y$), sha256crypt ($5$), sha512crypt ($6$), {SSHA}, {SHA}.`,
        sentinelTriggered: false,
      });
      return out;
    }
    const text = stdout.join("\n");
    const loaded = /Loaded (\d+) password hash/i.exec(text);
    const loadedCount = loaded ? Number(loaded[1]) : (mode.hashes ?? 0);
    const guessRe = /^(.+?)\s{2,}\(([^)]+)\)$/;
    let cracked = 0;
    for (const line of stdout) {
      const l = line.trim();
      if (!l || /^(loaded|remaining|will run|using|note|press|warning|session|rule|thread)/i.test(l)) continue;
      const m = guessRe.exec(l);
      if (!m) continue;
      const password = m[1].trim();
      const where = m[2].trim();
      if (!password || /^(loaded|remaining|will run|using|note|press|warning|session)/i.test(password)) continue;
      cracked++;
      const trivial = JOHN_TRIVIAL_PASSWORDS.has(password.toLowerCase());
      out.push({
        title: `Mot de passe faible craqué : ${where.split(":").pop() ?? where} → « ${password.slice(0, 40)} »`,
        severity: trivial ? "CRITICAL" : "HIGH",
        confidence: "CONFIRMED", category: "secrets", cve: null,
        cvss: trivial ? 9.1 : 7.4,
        location: where || undefined,
        description:
          `John the Ripper a craqué le hash (${where}) avec la wordlist par défaut : le mot de passe « ${password} » ` +
          (trivial ? "est un mot de passe TRIVIAL présent dans toutes les dictionnaires. " : "a été retrouvé en quelques secondes. ") +
          "Toute dépendance d'authentification sur ce hash (htpasswd, LDAP, système) est compromise.",
        evidence: evidenceBlock([
          `hash : ${where}`,
          `mot de passe craqué : ${password}`,
          `trivial : ${trivial ? "oui (dictionnaire de base)" : "non"}`,
        ]),
        poc: `john --wordlist=/usr/share/john/password.lst <hashfile>`,
        sentinelTriggered: false,
        remediation:
          "Changer immédiatement le mot de passe concerné ; appliquer une politique de complexité et un hachage " +
          "lent (bcrypt/argon2id) ; retirer les fichiers de credentials du dépôt.",
      });
      if (cracked >= 30) break; // plafond interne (le cap global re-tronque)
    }
    out.push({
      title: `john : ${loadedCount} hash(s) détecté(s) dans le dépôt — ${cracked} craqué(s) (wordlist par défaut)`,
      severity: cracked > 0 ? "HIGH" : "INFO", confidence: "CONFIRMED", category: "secrets",
      cve: null, cvss: null, location: undefined,
      description:
        `Synthèse John the Ripper : ${loadedCount} hash(s) de mot de passe détecté(s) dans le dépôt analysé, ` +
        `${cracked} craqué(s) avec la wordlist standard${mode.mode === "crack" ? "" : ""}. ` +
        "Les hashes non craqués ne constituent PAS une vulnérabilité — seul un mot de passe retrouvé est un constat individuel.",
      evidence: evidenceBlock([`hashes détectés : ${loadedCount}`, `craqués : ${cracked}`]),
      sentinelTriggered: false,
      remediation: cracked > 0 ? "Rotation des credentials craqués + hachage lent (bcrypt/argon2id) + purge du dépôt." : undefined,
    });
    return out;
  },
};

// ─── Registre exporté ────────────────────────────────────────────────

/** P5 + Sprint 1 : specs des 18 outils evergreen (clé = id Tool). */
export const ARSENAL_SPECS = {
  SUBFINDER: subfinderSpec,
  AMASS: amassSpec,
  HTTPX: httpxSpec,
  NUCLEI: nucleiSpec,
  NIKTO: niktoSpec,
  ZAP: zapSpec,
  SEMGREP: semgrepSpec,
  TRIVY: trivySpec,
  GITLEAKS: gitleaksSpec,
  SQLMAP: sqlmapSpec,
  FFUF: ffufSpec,
  WPSCAN: wpscanSpec,
  DALFOX: dalfoxSpec,
  WHATWEB: whatwebSpec,
  TESTSSL: testsslSpec,
  WAFW00F: wafw00fSpec,
  HYDRA: hydraSpec,
  JOHN: johnSpec,
} as const satisfies Record<string, ArsenalSpec>;
