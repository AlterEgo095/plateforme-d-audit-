/**
 * AuditForge — Adaptateur réel DEEPAUDIT : Agent d'audit profond piloté par IA.
 *
 * Réécriture 2026-10 : DEEPAUDIT n'est plus un simple client de plateforme
 * distante (GIT) mais un AGENT D'AUDIT AUTONOME multi-phases qui manipule
 * lui-même une trentaine d'outils offensifs dans une sandbox Docker Kali
 * (image auditforge/phantom-sandbox-plus), avec un LLM au centre des
 * décisions — exactement comme un auditeur humain expérimenté :
 *
 *   1. RECONNAISSANCE  — empreinte HTTP/TLS/WAF, ports, crawl, JS, formulaires,
 *                        paramètres cachés (arjun), fuzzing de répertoires (ffuf).
 *   2. PLANIFICATION   — le LLM analyse la surface d'attaque reconstruite et
 *                        produit un plan d'attaque priorisé (JSON).
 *   3. EXPLOITATION    — exécution ciblée : nuclei, sqlmap, dalfox, commix,
 *                        nikto + sondes maison (traversée, redirection ouverte,
 *                        SSRF, CORS, fichiers sensibles, headers, cookies,
 *                        méthodes HTTP, GraphQL…).
 *   4. VÉRIFICATION    — le LLM re-juge chaque candidat (preuves brutes) :
 *                        CONFIRMED / PROBABLE / FALSE_POSITIVE + réécriture du
 *                        constat (titre, sévérité, remédiation).
 *   5. RAPPORT         — synthèse LLM + constats normalisés RealFinding[].
 *
 * Contrairement à un agent ReAct libre (PHANTOM) qui peut s'arrêter trop tôt,
 * ce pipeline est DÉTERMINISTE : toutes les phases sont toujours exécutées,
 * avec des budgets de temps par profil (QUICK 25 min, STANDARD 60, DEEP 120).
 *
 * Architecture d'exécution (même modèle que phantom CLI) :
 *   - le conteneur moteur (qui monte /var/run/docker.sock) orchestre ;
 *   - la sandbox est un conteneur Docker de longue durée lancé en détaché
 *     (`tail -f /dev/null`, entrypoint contourné — ni Caido ni tool server) ;
 *   - chaque outil est exécuté via `docker exec <sandbox> <argv…>` et son
 *     flux est diffusé dans le journal du scan ;
 *   - les appels LLM sont faits DEPUIS LE MOTEUR (endpoint OpenAI-compatible
 *     LLM_API_BASE / LLM_API_KEY / PHANTOM_LLM — préfixe provider retiré).
 *
 * Cibles : URL (application web déployée) et NETWORK (hôte — webports auto).
 * La matrice applicative TOOL_TARGET_COMPAT est alignée côté app.
 */

import { spawn, type ChildProcess } from "node:child_process";
import { REAL_EXEC } from "./env";
import { MAX_LINE_LENGTH_HARD, probeVersion, runStreaming } from "./proc";
import type {
  RealAdapterContext,
  RealAvailability,
  RealFinding,
  RealToolAdapter,
} from "./types";
import type { Profile } from "../types";

/* ────────────────────────────────────────────────────────────────────────── */
/* Types module-scope                                                         */
/* ────────────────────────────────────────────────────────────────────────── */

/** Horloge de phase : part de budget + temps restant (millisecondes). */
interface PhaseClock {
  /** min(part demandée, temps restant) — passé en timeoutMs aux outils. */
  left(shareMs: number): number;
  /** Temps restant avant le deadline global (ms). */
  remainingMs(): number;
}

interface ReconResult {
  endpoints: string[];
  params: Map<string, string>;
  forms: Array<{ action: string; method: string; fields: string[] }>;
  ports: Array<{ port: string; service: string; version: string }>;
  waf: string;
  tech: string;
  headers: Record<string, string>;
  cookies: Array<{ name: string; flags: string }>;
  subdomains: string[];
  tlsFindings: Array<{ id: string; finding: string; severity: string }>;
}

interface AttackPlan {
  notes: string[];
  sqli: Array<{ url: string; param?: string; data?: string }>;
  xss: Array<{ url: string; param?: string }>;
  vectors: Array<{ vector: string; url: string; param?: string; rationale?: string }>;
}

interface Candidate {
  id: string;
  tool: string;
  title: string;
  category: string;
  severity: RealFinding["severity"];
  /** CONFIRMED si l'outil a vérifié lui-même (nuclei matcher, sqlmap, dalfox [V]). */
  toolVerified: boolean;
  location?: string;
  description: string;
  evidence: string;
  poc?: string;
}

interface ToolResult {
  code: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

interface HttpProbeResult {
  status: number;
  headers: Record<string, string>;
  body: string;
}

/* ────────────────────────────────────────────────────────────────────────── */
/* Constantes                                                                 */
/* ────────────────────────────────────────────────────────────────────────── */

/** Image sandbox Kali enrichie (même que Phantom). */
const SANDBOX_IMAGE =
  REAL_EXEC.phantomImage || "auditforge/phantom-sandbox-plus:latest";

/** Sévérités valides d'un constat. */
const SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);

/** Budgets de temps (millisecondes) par profil — marge laissée sur le timeout moteur. */
const BUDGETS: Record<Profile, { total: number; recon: number; tools: number; verify: number }> = {
  QUICK: { total: 25 * 60_000, recon: 8 * 60_000, tools: 10 * 60_000, verify: 4 * 60_000 },
  STANDARD: { total: 60 * 60_000, recon: 18 * 60_000, tools: 26 * 60_000, verify: 8 * 60_000 },
  DEEP: { total: 120 * 60_000, recon: 28 * 60_000, tools: 62 * 60_000, verify: 16 * 60_000 },
};

/** Fichiers sensibles à sonder (motifs attendus dans le corps, | = alternative). */
const SENSITIVE_FILES: Array<[string, string, RealFinding["severity"]]> = [
  [".env", "APP_KEY|DB_PASSWORD|SECRET|AWS_|API_KEY", "HIGH"],
  [".git/config", "repositoryformatversion|[remote", "HIGH"],
  [".git/HEAD", "ref: refs/", "HIGH"],
  ["composer.json", '"require"', "MEDIUM"],
  ["backup.zip", "PK", "MEDIUM"],
  ["db.sqlite", "SQLite format", "HIGH"],
  ["database.sql", "INSERT INTO|CREATE TABLE", "HIGH"],
  ["phpinfo.php", "phpinfo()|PHP Version", "MEDIUM"],
  ["info.php", "phpinfo()|PHP Version", "MEDIUM"],
  ["server-status", "Apache Server Status", "MEDIUM"],
  ["wp-config.php.bak", "DB_PASSWORD|DB_NAME", "CRITICAL"],
  ["debug.log", "ERROR|Stack trace|WARN", "MEDIUM"],
  ["dump.sql", "INSERT INTO|CREATE TABLE", "HIGH"],
  [".htaccess", "RewriteRule|Deny from", "LOW"],
];

/** Mini-wordlist de repli si seclists absente (fuzzing). */
const FALLBACK_WORDLIST = [
  "admin", "administrator", "api", "app", "backup", "blog", "config", "console",
  "dashboard", "db", "debug", "dev", "docs", "download", "editor", "files",
  "forum", "home", "images", "img", "index", "install", "js", "json", "login",
  "log", "mail", "manager", "media", "members", "old", "panel", "phpinfo",
  "phpmyadmin", "private", "register", "rest", "robots.txt", "shop", "site",
  "sql", "src", "static", "status", "store", "support", "system", "temp",
  "test", "tmp", "tools", "uploads", "user", "v1", "v2", "web", "webmail",
  "wp-admin", "wp-content", "wp-login.php", ".env", ".git/config", ".htaccess",
  "config.php", "database", "graphql", "swagger", "swagger.json",
  "openapi.json", "api/v1", "api/v2", "assets", "cgi-bin", "data", "include",
  "phpMyAdmin", "server-info", "server-status", "xmlrpc.php",
];

/** Remédiations par catégorie. */
const REMEDIATIONS: Record<string, string> = {
  sqli: "Utiliser des requêtes préparées (paramétrées), valider les entrées côté serveur, appliquer le principe du moindre privilège sur les comptes SQL.",
  xss: "Encoder les sorties selon le contexte HTML, appliquer une CSP stricte, valider et normaliser les entrées utilisateur.",
  "command-injection": "Éviter les appels shell avec des entrées utilisateur ; utiliser des API dédiées et une liste blanche de valeurs autorisées.",
  traversal: "Normaliser les chemins (realpath), refuser les séquences ../, restreindre l'accès fichier à un répertoire racine dédié.",
  "open-redirect": "Valider les URL de redirection contre une liste blanche de domaines, refuser les protocoles relatifs de réseau (//).",
  ssrf: "Filtrer les URL récupérées (liste blanche), bloquer les plages internes/métadonnées (169.254.169.254), désactiver les redirections.",
  cors: "Ne jamais refléter l'origine arbitraire ; définir explicitement les origines autorisées et credentials:false par défaut.",
  headers: "Ajouter les en-têtes de sécurité : CSP, X-Content-Type-Options, X-Frame-Options/frame-ancestors, Referrer-Policy, HSTS (HTTPS).",
  cookies: "Ajouter HttpOnly, Secure et SameSite=Lax/Strict aux cookies de session.",
  exposure: "Supprimer les fichiers sensibles exposés, restreindre par règles serveur (nginx/Apache) et retirer les dépôts/services de debug.",
  ssl: "Corriger la configuration TLS : TLS 1.2+ uniquement, chiffrements forts, certificat valide et chaîne complète.",
  methods: "Désactiver les méthodes HTTP inutiles (TRACE/PUT/DELETE) et l'affichage de répertoires.",
  graphql: "Désactiver l'introspection en production, mettre en place des limites de profondeur et d'authentification.",
  listing: "Désactiver l'autoindex (Options -Indexes) sur les répertoires sans index.",
  misc: "Appliquer les recommandations de l'outil source et corriger la configuration concernée.",
};

/* ────────────────────────────────────────────────────────────────────────── */
/* Helpers                                                                    */
/* ────────────────────────────────────────────────────────────────────────── */

function mapSeverity(raw: unknown): RealFinding["severity"] {
  const v = String(raw ?? "").toLowerCase();
  return SEVERITIES.has(v) ? (v.toUpperCase() as RealFinding["severity"]) : "MEDIUM";
}

/** Tronque une preuve à une taille raisonnable. */
function clip(text: string, max = 6000): string {
  const t = String(text ?? "");
  return t.length <= max ? t : t.slice(0, max) + `\n… (tronqué, ${t.length - max} caractères restants)`;
}

/** Normalise la cible : URL complète avec schéma + défense SSRF. */
function normalizeTarget(raw: string): URL {
  const trimmed = raw.trim();
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;
  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    throw new Error(`Cible invalide (URL illisible) : ${raw}`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("Cible refusée : seuls les schémas http/https sont acceptés");
  }
  if (url.username || url.password) {
    throw new Error("Cible refusée : identifiants dans l'URL non autorisés");
  }
  const host = url.hostname.toLowerCase();
  const privateRe =
    /^(localhost|127\.|10\.|192\.168\.|169\.254\.|0\.0\.0\.0|\[::1\]|\[fc|\[fd|172\.(1[6-9]|2\d|3[01])\.)/;
  if (privateRe.test(host)) {
    throw new Error("Cible refusée : adresses privées/locales interdites (défense SSRF)");
  }
  return url;
}

/** Retire le préfixe provider LiteLLM (« openai/… ») pour un appel API direct. */
function stripProvider(model: string): string {
  return model.replace(/^[a-z0-9_-]+\//i, "");
}

/** Extrait le premier objet JSON complet d'un texte (fences tolérés). */
function extractJson(text: string): Record<string, unknown> | null {
  const cleaned = text.replace(/```(?:json)?/gi, "").trim();
  for (let end = cleaned.length; end > 1; end--) {
    if (cleaned.charCodeAt(end - 1) !== 125) continue;
    for (let start = end - 1; start >= 0; start--) {
      if (cleaned.charCodeAt(start) !== 123) continue;
      try {
        const parsed = JSON.parse(cleaned.slice(start, end));
        if (parsed && typeof parsed === "object") return parsed as Record<string, unknown>;
      } catch {
        /* fragment invalide */
      }
    }
  }
  return null;
}

/* ────────────────────────────────────────────────────────────────────────── */
/* Adaptateur                                                                 */
/* ────────────────────────────────────────────────────────────────────────── */

export class DeepAuditAdapter implements RealToolAdapter {
  readonly tool = "DEEPAUDIT" as const;

  /** Nom du conteneur sandbox pour le scan en cours. */
  private container = "";
  private llmCalls = 0;
  private toolExecutions = 0;

  async checkAvailable(): Promise<RealAvailability> {
    const docker = await probeVersion("docker");
    if (!docker) {
      return { available: false, reason: "Docker requis pour la sandbox DeepAudit (docker indisponible)" };
    }
    const image = await this.dockerCapture(["image", "inspect", SANDBOX_IMAGE], 15_000);
    if (image.code !== 0) {
      return {
        available: false,
        reason: `image sandbox ${SANDBOX_IMAGE} absente (docker pull ${SANDBOX_IMAGE})`,
      };
    }
    if (!REAL_EXEC.llmApiKey) {
      return { available: false, reason: "LLM_API_KEY non configurée (l'agent IA ne peut pas raisonner)" };
    }
    return { available: true, version: `agent IA multi-phases · ${SANDBOX_IMAGE}` };
  }

  /* ── Orchestration ─────────────────────────────────────────────────────── */

  async run(ctx: RealAdapterContext): Promise<RealFinding[]> {
    if (ctx.targetType === "GIT") {
      throw new Error("DeepAudit audite les applications déployées : une cible URL ou NETWORK est requise");
    }
    const target = normalizeTarget(ctx.target);
    const profile = ctx.profile;
    const budget = BUDGETS[profile];
    const deadline =
      Date.now() + Math.max(5, Math.min(budget.total, REAL_EXEC.timeoutMinutes * 60_000 - 120_000));
    const t0 = Date.now();
    this.container = `deepaudit-${ctx.scanId.replace(/[^a-zA-Z0-9]/g, "").slice(-14)}`;
    this.llmCalls = 0;
    this.toolExecutions = 0;

    const clock: PhaseClock = {
      left: (shareMs) => Math.min(shareMs, Math.max(0, deadline - Date.now())),
      remainingMs: () => Math.max(0, deadline - Date.now()),
    };

    await ctx.onLog(
      `DeepAudit Agent — cible ${target.origin} · profil ${profile} · budget ${Math.round(budget.total / 60_000)} min · ` +
      "LLM au centre des décisions (plan d'attaque + vérification des preuves + synthèse)",
      "INFO",
      "deepaudit",
    );
    await ctx.onPhase("INITIALISATION", 3);

    try {
      // ── Sandbox ──
      await ctx.onLog(
        `docker run -d --rm --name ${this.container} (entrypoint contourné) ${SANDBOX_IMAGE}`,
        "CMD",
        "docker",
      );
      const started = await this.dockerCapture(
        [
          "run", "-d", "--rm", "--name", this.container,
          "--network", "bridge", "--memory", "4g",
          // NET_RAW : requis par nmap (scan SYN) — sinon « Operation not permitted ».
          "--cap-add", "NET_RAW",
          "--entrypoint", "/bin/bash",
          SANDBOX_IMAGE, "-c", "tail -f /dev/null",
        ],
        60_000,
      );
      if (started.code !== 0) {
        throw new Error(`Impossible de démarrer la sandbox DeepAudit : ${clip(started.err || started.out, 400)}`);
      }
      const ready = await this.waitReady(ctx, 30_000);
      if (!ready) throw new Error("Sandbox DeepAudit non opérationnelle après 30 s (docker exec en échec)");
      await ctx.onLog(`Sandbox prête (${this.container}) — 25+ outils offensifs disponibles`, "SUCCESS", "deepaudit");

      // Préparation des outils : le binaire nmap de l'image porte des file
      // capabilities (cap_net_admin/raw=eip) que l'environnement conteneur
      // refuse → execve EPERM. Une COPIE du binaire perd les caps mais
      // s'exécute correctement (nmap retombe sur un scan connect).
      const nmapFix = await this.dockerCapture(
        ["exec", this.container, "sh", "-c", "cp /usr/lib/nmap/nmap /tmp/nmap-real 2>/dev/null && chmod +x /tmp/nmap-real"],
        10_000,
      );

      // ── Garde-fou anti-faux « 0 vulnérabilité » : la cible doit répondre. ──
      // Un scan sur une cible injoignable rapporterait 0 constat SANS que ce
      // soit un verdict de sécurité — le pire des faux négatifs. On refuse
      // explicitement (scan FAILED avec cause claire) plutôt que de tromper
      // l'opérateur avec un rapport vide.
      const reach = await this.httpProbe(ctx, target.origin + "/", 15_000, clock);
      let activeOrigin = target.origin;
      if (reach.status === 0) {
        // Réessai avec l'autre schéma (http⇄https) avant de déclarer l'échec.
        const alt = new URL(target.toString());
        alt.protocol = target.protocol === "https:" ? "http:" : "https:";
        const altProbe = await this.httpProbe(ctx, alt.origin + "/", 15_000, clock);
        if (altProbe.status === 0) {
          throw new Error(
            `Cible injoignable depuis la sandbox (timeout/refus TCP sur ${target.origin} et ${alt.origin}) — ` +
            "le serveur ne répond pas aux requêtes du scanner. Un audit rapporterait de faux « 0 vulnérabilité » : scan annulé. " +
            "Vérifiez que la cible est en ligne et qu'elle ne bloque pas l'IP du scanner (pare-feu, geo-bloc, ban).",
          );
        }
        activeOrigin = alt.origin;
        await ctx.onLog(
          `Le schéma initial ne répond pas — bascule sur ${activeOrigin} (HTTP ${altProbe.status})`,
          "WARN",
          "deepaudit",
        );
      }

      // ── Phase 1 : RECONNAISSANCE ──
      await ctx.onPhase("RECONNAISSANCE", 8);
      const scanTarget = new URL(activeOrigin);
      const recon = await this.phaseRecon(ctx, scanTarget, profile, clock, nmapFix.code === 0 ? "/tmp/nmap-real" : "nmap");
      await ctx.onLog(
        `Recon terminée : ${recon.endpoints.length} endpoint(s), ${recon.params.size} paramètre(s), ` +
        `${recon.forms.length} formulaire(s), ${recon.ports.length} port(s) ouvert(s)` +
        `${recon.waf ? `, WAF : ${recon.waf}` : ""}${recon.tech ? `, tech : ${recon.tech.slice(0, 120)}` : ""}`,
        "SUCCESS",
        "deepaudit",
      );

      // ── Phase 2 : PLANIFICATION (LLM) ──
      await ctx.onPhase("PLANIFICATION", 36);
      const plan = await this.phasePlan(ctx, scanTarget, profile, recon, clock);

      // ── Phase 3 : EXPLOITATION ──
      await ctx.onPhase("EXPLOITATION", 42);
      const candidates = await this.phaseExploit(ctx, scanTarget, profile, recon, plan, clock);
      await ctx.onLog(
        `Exploitation terminée : ${candidates.length} constat(s) candidat(s) avant vérification`,
        "SUCCESS",
        "deepaudit",
      );

      // ── Phase 4 : VÉRIFICATION (LLM) ──
      await ctx.onPhase("VÉRIFICATION", 78);
      const verified = await this.phaseVerify(ctx, candidates, clock);

      // ── Phase 5 : RAPPORT ──
      await ctx.onPhase("RAPPORT", 93);
      await this.phaseReport(ctx, scanTarget, findingsSummary(verified), Math.round((Date.now() - t0) / 1000));

      await ctx.onPhase("RAPPORT", 98);
      return verified;
    } finally {
      await this.dockerCapture(["rm", "-f", this.container], 15_000);
      await ctx.onLog(`Sandbox ${this.container} détruite — outillage nettoyé`, "INFO", "deepaudit");
    }
  }

  /* ── Phase 1 : reconnaissance ──────────────────────────────────────────── */

  private async phaseRecon(
    ctx: RealAdapterContext,
    target: URL,
    profile: Profile,
    clock: PhaseClock,
    nmapBin: string,
  ): Promise<ReconResult> {
    const recon: ReconResult = {
      endpoints: [target.origin + (target.pathname === "/" ? "/" : target.pathname)],
      params: new Map(),
      forms: [],
      ports: [],
      waf: "",
      tech: "",
      headers: {},
      cookies: [],
      subdomains: [],
      tlsFindings: [],
    };
    const deep = profile === "DEEP";
    const std = profile !== "QUICK";

    // 1. En-têtes + statut
    const page = await this.httpProbe(ctx, target.origin + "/", 15_000, clock);
    recon.headers = page.headers;
    const server = page.headers["server"] ?? "";
    const powered = page.headers["x-powered-by"] ?? "";
    recon.tech = [server, powered].filter(Boolean).join(" · ");
    if (page.status > 0) {
      await ctx.onLog(`HTTP ${page.status} — serveur : ${server || "n/a"}${powered ? ` (${powered})` : ""}`, "INFO", "http");
    }
    for (const set of this.setCookies(page.headers["set-cookie"] ?? "")) {
      recon.cookies.push(set);
    }

    // 2. whatweb
    const ww = await this.execTool(ctx, ["whatweb", "-a", "1", "-q", "--no-errors", target.origin], {
      timeoutMs: clock.left(60_000), label: "whatweb (empreinte technique)",
    });
    if (ww.stdout.trim()) recon.tech = [recon.tech, ww.stdout.trim().slice(0, 300)].filter(Boolean).join(" · ");

    // 3. wafw00f
    const waf = await this.execTool(ctx, ["wafw00f", "-a", target.origin], {
      timeoutMs: clock.left(90_000), label: "wafw00f (détection WAF)", maxLines: 60,
    });
    const wafMatch = /is behind (.+?)(?:\s*$|\s\()/im.exec(waf.stdout);
    if (wafMatch) recon.waf = wafMatch[1].trim();

    // 4. Crawling (katana — -fs dn : scope domaine racine)
    const crawlDepth = deep ? "4" : std ? "3" : "1";
    const crawl = await this.execTool(
      ctx,
      ["katana", "-u", target.origin, "-d", crawlDepth, "-jc", "-silent", "-kf", "all",
       "-timeout", "10", "-c", "10", "-fs", "dn"],
      { timeoutMs: clock.left(deep ? 240_000 : 150_000), label: `katana -d ${crawlDepth} (crawl + JS)`, maxLines: 400 },
    );
    for (const line of crawl.stdout.split("\n")) {
      let url = line.trim();
      try {
        const j = JSON.parse(url) as { endpoint?: string };
        if (j.endpoint) url = String(j.endpoint);
      } catch { /* sortie non-JSON */ }
      if (!/^https?:\/\//i.test(url)) continue;
      try {
        const u = new URL(url);
        if (u.origin === target.origin) {
          recon.endpoints.push(url);
          u.searchParams.forEach((_, k) => {
            if (!recon.params.has(k)) recon.params.set(k, url);
          });
        }
      } catch { /* URL invalide */ }
    }

    // 5. JS — extraction d'endpoints API
    const jsUrls = [...new Set(recon.endpoints.filter((e) => /\.js(\?|$)/i.test(e)))].slice(0, deep ? 20 : 10);
    for (const js of jsUrls) {
      const body = await this.httpProbe(ctx, js, 12_000, clock);
      if (body.status !== 200) continue;
      const apiRe = /["'`](\/[a-zA-Z0-9_\-/.]{2,60}(?:api|v[12]|admin|user|upload|search|query|action)[a-zA-Z0-9_\-/.]*)["'`]/gi;
      let m: RegExpExecArray | null;
      while ((m = apiRe.exec(body.body)) !== null) {
        recon.endpoints.push(target.origin + m[1]);
      }
    }
    recon.endpoints = [...new Set(recon.endpoints)];

    // 6. Formulaires (pages principales)
    const formTargets = [...new Set([target.origin + "/", ...recon.endpoints.filter((e) => /login|signin|auth|contact|search|register|upload/i.test(e))])].slice(0, 8);
    for (const u of formTargets) {
      const body = await this.httpProbe(ctx, u, 12_000, clock);
      if (body.status < 200 || body.status >= 400) continue;
      for (const form of this.parseForms(body.body, u)) {
        recon.forms.push(form);
        recon.endpoints.push(form.action);
      }
    }
    recon.endpoints = [...new Set(recon.endpoints)];

    // 7. Fuzzing de répertoires (ffuf)
    const wordlist = await this.pickWordlist(ctx, std);
    const ff = await this.execTool(
      ctx,
      ["ffuf", "-u", `${target.origin}/FUZZ`, "-w", wordlist, "-mc",
       "200,201,204,301,302,307,401,403,405", "-t", "30", "-timeout", "8",
       "-s", "-of", "csv", "-o", "/tmp/ffuf.csv"],
      { timeoutMs: clock.left(std ? 600_000 : 180_000), label: `ffuf (fuzzing répertoires, ${wordlist})`, maxLines: 120 },
    );
    if (ff.code === 0 || ff.code === 1) {
      const csv = await this.execTool(ctx, ["cat", "/tmp/ffuf.csv"], { timeoutMs: 15_000, label: "ffuf résultats", maxLines: 200 });
      const rows = csv.stdout.split("\n").filter((r) => r.trim());
      // Entête ffuf : FUZZ,url,redirectlocation,position,status_code,… — la
      // colonne « url » est repérée dynamiquement (elle varie selon versions).
      const header = (rows[0] ?? "").split(",").map((c) => c.replace(/^"|"$/g, "").trim().toLowerCase());
      const urlCol = header.indexOf("url");
      for (const row of rows.slice(1)) {
        const cells = row.split(",").map((c) => c.replace(/^"|"$/g, "").trim());
        const url = (urlCol >= 0 ? cells[urlCol] : cells[1]) ?? "";
        if (/^https?:\/\//i.test(url)) recon.endpoints.push(url);
      }
      recon.endpoints = [...new Set(recon.endpoints)];
    }

    // 8. Paramètres cachés (arjun)
    if (std) {
      const ar = await this.execTool(ctx, ["arjun", "-u", target.origin, "-t", "15", "-m", "GET"], {
        timeoutMs: clock.left(240_000), label: "arjun (paramètres cachés)", maxLines: 80,
      });
      for (const m of ar.stdout.matchAll(/Discovered (?:a )?parameter(?: set)?:\s*([a-zA-Z0-9_\-\[\]]+)/gi)) {
        const p = m[1];
        if (!recon.params.has(p)) recon.params.set(p, target.origin + "/");
      }
    }

    // 9. Ports (nmap — binaire recopié si les file caps bloquaient l'exec)
    if (std) {
      const nm = await this.execTool(
        ctx,
        [nmapBin, "-Pn", "-T4", "--top-ports", deep ? "1000" : "500", "-sT", "-sV", "--version-light",
         "--open", "-oN", "/tmp/nmap.txt", target.hostname],
        { timeoutMs: clock.left(deep ? 720_000 : 420_000), label: `nmap (--top-ports ${deep ? 1000 : 500} -sV)`, maxLines: 200 },
      );
      for (const m of nm.stdout.matchAll(/^\s*(\d+\/(?:tcp|udp))\s+open\s+(\S+)(?:\s+(.*))?$/gm)) {
        recon.ports.push({ port: m[1], service: m[2], version: (m[3] ?? "").trim() });
      }
    }

    // 10. TLS (testssl.sh)
    if (target.protocol === "https:" && std) {
      const ts = await this.execTool(
        ctx,
        ["testssl.sh", "--quiet", "--warnings", "off", "--color", "0",
         "--csvfile", "/tmp/testssl.csv", target.hostname],
        { timeoutMs: clock.left(600_000), label: "testssl.sh (audit TLS)", maxLines: 60 },
      );
      if (ts.code === 0) {
        const csv = await this.execTool(ctx, ["cat", "/tmp/testssl.csv"], { timeoutMs: 15_000, label: "testssl résultats", maxLines: 400 });
        for (const line of csv.stdout.split("\n").slice(1)) {
          const cols = line.split(",").map((c) => c.replace(/^"|"$/g, "").trim());
          if (cols.length < 7) continue;
          const severity = cols[6] ?? "";
          if (/^(HIGH|CRITICAL|MEDIUM)$/i.test(severity)) {
            recon.tlsFindings.push({ id: cols[0] ?? "", finding: cols[2] ?? "", severity });
          }
        }
      }
    }

    // 11. Sous-domaines (DEEP uniquement)
    if (deep && !/^\d+\.\d+\.\d+\.\d+$/.test(target.hostname)) {
      const sf = await this.execTool(ctx, ["subfinder", "-d", target.hostname, "-silent"], {
        timeoutMs: clock.left(180_000), label: "subfinder (sous-domaines)", maxLines: 150,
      });
      recon.subdomains = sf.stdout.split("\n").map((l) => l.trim()).filter((l) => l && l !== target.hostname).slice(0, 60);
    }

    return recon;
  }

  /* ── Phase 2 : planification LLM ───────────────────────────────────────── */

  private async phasePlan(
    ctx: RealAdapterContext,
    target: URL,
    profile: Profile,
    recon: ReconResult,
    clock: PhaseClock,
  ): Promise<AttackPlan> {
    void clock;
    const digest = {
      cible: target.origin,
      tech: recon.tech,
      waf: recon.waf || "aucun détecté",
      ports: recon.ports.map((p) => `${p.port} ${p.service} ${p.version}`).slice(0, 15),
      endpoints: recon.endpoints.slice(0, 60),
      parametres: [...recon.params.keys()].slice(0, 40),
      formulaires: recon.forms.slice(0, 10),
      cookies: recon.cookies.slice(0, 10),
      tls: recon.tlsFindings.slice(0, 10),
      sous_domaines: recon.subdomains.slice(0, 20),
    };
    const system =
      "Tu es un auditeur d'application web senior (OWASP Top 10, WSTG). On te fournit le résultat de la " +
      "reconnaissance d'une cible AUTORISÉE. Produis un plan d'attaque PRIORISÉ en JSON strict, sans commentaire. " +
      'Schéma attendu : {"notes":[string], "sqli":[{"url":string,"param"?:string,"data"?:string}], ' +
      '"xss":[{"url":string,"param"?:string}], ' +
      '"vectors":[{"vector":string,"url":string,"param"?:string,"rationale"?:string}]}. ' +
      "vector ∈ {traversal,open-redirect,ssrf,cors,graphql,command-injection,auth,upload}. " +
      "Sélectionne les endpoints/params les PLUS PROMETTEURS (reflétés, SQL, upload, redirect). Reste concis (max 40 entrées).";
    const user = `Profil d'audit : ${profile}\nReconnaissance :\n${JSON.stringify(digest, null, 1).slice(0, 12_000)}`;

    // Repli programmatique — toujours construit d'abord (LLM optionnel).
    const fallback: AttackPlan = {
      notes: ["plan de repli généré localement (LLM indisponible)"],
      sqli: [...recon.params.keys()].slice(0, 8).map((p) => ({ url: recon.params.get(p) as string, param: p })),
      xss: [...recon.params.keys()].slice(0, 6).map((p) => ({ url: recon.params.get(p) as string, param: p })),
      vectors: [],
    };

    const plan = await this.llmJson(ctx, system, user, 2500, 90_000);
    if (!plan) {
      await ctx.onLog("LLM indisponible pour la planification — plan de repli programmatique appliqué", "WARN", "agent");
      return fallback;
    }
    const arr = <T,>(v: unknown): T[] => (Array.isArray(v) ? (v as T[]) : []);
    const result: AttackPlan = {
      notes: arr<string>(plan.notes).map(String).slice(0, 10),
      sqli: arr<{ url: string; param?: string; data?: string }>(plan.sqli)
        .filter((x) => x && typeof x.url === "string" && /^https?:\/\//i.test(x.url)).slice(0, 12),
      xss: arr<{ url: string; param?: string }>(plan.xss)
        .filter((x) => x && typeof x.url === "string" && /^https?:\/\//i.test(x.url)).slice(0, 10),
      vectors: arr<{ vector: string; url: string; param?: string; rationale?: string }>(plan.vectors)
        .filter((x) => x && typeof x.url === "string" && /^https?:\/\//i.test(x.url)).slice(0, 20),
    };
    const total = result.sqli.length + result.xss.length + result.vectors.length;
    if (total === 0) return fallback;
    await ctx.onLog(
      `Plan d'attaque IA : ${result.sqli.length} cible(s) SQLi, ${result.xss.length} cible(s) XSS, ` +
      `${result.vectors.length} vecteur(s) ciblé(s)${result.notes.length ? ` — ${result.notes[0]}` : ""}`,
      "AGENT",
      "agent",
    );
    return result;
  }

  /* ── Phase 3 : exploitation ────────────────────────────────────────────── */

  private async phaseExploit(
    ctx: RealAdapterContext,
    target: URL,
    profile: Profile,
    recon: ReconResult,
    plan: AttackPlan,
    clock: PhaseClock,
  ): Promise<Candidate[]> {
    const out: Candidate[] = [];
    const deep = profile === "DEEP";
    const std = profile !== "QUICK";
    const push = (c: Candidate) => {
      if (out.length < 250) out.push(c);
    };

    // 3.1 nuclei (templates officiels)
    const sevArg = profile === "QUICK" ? ["-severity", "high,critical"]
      : profile === "STANDARD" ? ["-severity", "medium,high,critical"] : [];
    const nu = await this.execTool(
      ctx,
      ["nuclei", "-u", target.origin, "-silent", "-nc", "-rl", "40", "-c", "15",
       "-timeout", "12", "-retries", "1", ...sevArg, "-jle", "/tmp/nuclei.jsonl"],
      { timeoutMs: clock.left(deep ? 900_000 : std ? 600_000 : 300_000), label: "nuclei (templates officiels)", maxLines: 150 },
    );
    if (nu.code === 0 || nu.code === 1) {
      const jsonl = await this.execTool(ctx, ["cat", "/tmp/nuclei.jsonl"], { timeoutMs: 15_000, label: "nuclei résultats", maxLines: 400 });
      for (const line of jsonl.stdout.split("\n")) {
        if (!line.trim().startsWith("{")) continue;
        try {
          const j = JSON.parse(line) as {
            "template-id"?: string; info?: { name?: string; severity?: string; description?: string };
            "matcher-status"?: boolean; "matched-at"?: string; "curl-command"?: string; host?: string;
          };
          if (j["matcher-status"] === false) continue;
          push({
            id: `nuclei-${j["template-id"] ?? out.length}`,
            tool: "nuclei",
            title: j.info?.name ?? j["template-id"] ?? "Détection nuclei",
            category: /cve/i.test(j["template-id"] ?? "") ? "misc" : "misc",
            severity: mapSeverity(j.info?.severity),
            toolVerified: true,
            location: j["matched-at"] ?? j.host ?? undefined,
            description: j.info?.description ?? `Template nuclei ${j["template-id"]} déclenché sur la cible.`,
            evidence: [j["matched-at"] ? `URL déclenchante : ${j["matched-at"]}` : "",
              j["curl-command"] ? `Commande de reproduction :\n${j["curl-command"]}` : ""]
              .filter(Boolean).join("\n") || "Template nuclei déclenché.",
            poc: j["curl-command"],
          });
        } catch { /* ligne partielle */ }
      }
    }
    await ctx.onPhase("EXPLOITATION", 55);

    // 3.2 sqlmap (candidates du plan + formulaires)
    const sqlTargets = this.dedupTargets(
      plan.sqli.map((s) => ({ url: s.url, param: s.param, data: s.data }))
        .concat(recon.forms.slice(0, 3).map((f) => ({ url: f.action, param: f.fields[0], data: undefined as string | undefined }))),
    ).slice(0, deep ? 8 : std ? 5 : 3);
    let sqlIdx = 0;
    for (const t of sqlTargets) {
      if (clock.remainingMs() < 60_000) break;
      sqlIdx += 1;
      const args = ["sqlmap", "-u", t.url, "--batch", "--threads", "4", "--time-sec", "3",
        "--timeout", "25", "--retries", "1", "--flush-session",
        "--level", profile === "DEEP" ? "3" : std ? "2" : "1",
        "--risk", std ? "2" : "1"];
      if (t.param) args.push("-p", t.param);
      if (t.data) args.push("--data", t.data);
      const sm = await this.execTool(ctx, args, {
        timeoutMs: clock.left(deep ? 900_000 : 600_000),
        label: `sqlmap #${sqlIdx} (${t.url.slice(0, 80)}${t.param ? ` · ${t.param}` : ""})`,
        maxLines: 250,
      });
      const vulnBlock = /sqlmap identified the following injection point[\s\S]{0,2500}?Payload: .+|Type: [^\n]+\nTitle: [^\n]+\nPayload: [^\n]+/g;
      let m: RegExpExecArray | null;
      while ((m = vulnBlock.exec(sm.stdout)) !== null) {
        const param = /Parameter:\s*(\S+)/.exec(m[0])?.[1] ?? t.param ?? "?";
        push({
          id: `sqlmap-${sqlIdx}-${out.length}`,
          tool: "sqlmap",
          title: `Injection SQL confirmée — paramètre ${param}`,
          category: "sqli",
          severity: "CRITICAL",
          toolVerified: true,
          location: `${t.url} (paramètre ${param})`,
          description: `sqlmap a confirmé une injection SQL sur ${t.url}, paramètre ${param}. Détails techniques extraits du flux :`,
          evidence: clip(m[0], 4000),
        });
      }
    }
    await ctx.onPhase("EXPLOITATION", 62);

    // 3.3 dalfox (XSS)
    const xssTargets = this.dedupTargets(plan.xss.map((x) => ({ url: x.url, param: x.param })))
      .slice(0, deep ? 6 : std ? 4 : 2);
    let xssIdx = 0;
    for (const t of xssTargets) {
      if (clock.remainingMs() < 45_000) break;
      xssIdx += 1;
      const dl = await this.execTool(ctx, ["dalfox", "url", t.url, "--silence", "--no-color", "--no-spinner", "--timeout", "15"], {
        timeoutMs: clock.left(300_000), label: `dalfox #${xssIdx} (${t.url.slice(0, 70)})`, maxLines: 120,
      });
      for (const line of dl.stdout.split("\n")) {
        if (!line.includes("[V] ")) continue;
        const poc = line.replace(/^\[[\d:]+\]\s*/, "").trim();
        push({
          id: `dalfox-${xssIdx}-${out.length}`,
          tool: "dalfox",
          title: "XSS réfléchi confirmé",
          category: "xss",
          severity: "HIGH",
          toolVerified: true,
          location: t.url,
          description: `dalfox a vérifié l'exécution d'un payload sur ${t.url}. PoC reproduit par l'outil :`,
          evidence: clip(poc, 2500),
          poc,
        });
      }
    }

    // 3.4 commix (DEEP)
    if (deep) {
      const cmdTargets = plan.vectors.filter((v) => v.vector === "command-injection").slice(0, 2);
      let ci = 0;
      for (const t of cmdTargets) {
        if (clock.remainingMs() < 45_000) break;
        ci += 1;
        const cx = await this.execTool(ctx, ["commix", "--batch", "--url", t.url, "--no-color"], {
          timeoutMs: clock.left(480_000), label: `commix #${ci} (${t.url.slice(0, 70)})`, maxLines: 120,
        });
        if (/Command(?:s)? that can be injected|'[\w\-]+' is vulnerable/i.test(cx.stdout)) {
          push({
            id: `commix-${ci}`,
            tool: "commix",
            title: "Injection de commande système confirmée",
            category: "command-injection",
            severity: "CRITICAL",
            toolVerified: true,
            location: t.url,
            description: "commix a confirmé l'exécution de commandes système via un paramètre de la requête.",
            evidence: clip(cx.stdout.split("\n").filter((l) => /vulnerable|injected|output/i.test(l)).join("\n") || cx.stdout, 4000),
          });
        }
      }
    }

    // 3.5 nikto (STANDARD/DEEP) — parsing du STDOUT (« + [id] chemin : desc »),
    //     le format CSV variant trop selon les versions.
    if (std && clock.remainingMs() > 120_000) {
      const nk = await this.execTool(ctx, ["nikto", "-h", target.origin, "-timeout", "20"], {
        timeoutMs: clock.left(780_000), label: "nikto (scan serveur web)", maxLines: 120,
      });
      for (const line of nk.stdout.split("\n")) {
        const m = /^\+\s+\[(\d+)\]\s+(\S+?):\s+(.+)$/.exec(line.trim());
        if (!m) continue;
        const [, ref, path, desc] = m;
        if (/Nikto test completed|statistics|tokens? retrieved/i.test(desc)) continue;
        push({
          id: `nikto-${ref}-${out.length}`,
          tool: "nikto",
          title: `Nikto : ${desc.slice(0, 180)}`,
          category: "misc",
          severity: /admin|config|backup|password|shell|phpinfo|RFC-1918|internal IP/i.test(desc) ? "MEDIUM" : "LOW",
          toolVerified: false,
          location: target.origin + path,
          description: `${desc} (référence nikto ${ref})`,
          evidence: line.trim().slice(0, 2000),
        });
      }
    }
    await ctx.onPhase("EXPLOITATION", 70);

    // 3.6 Sondes maison (curl) — headers, cookies, CORS, fichiers sensibles,
    //     listing, méthodes, GraphQL, traversée, redirection, SSRF
    out.push(...(await this.customProbes(ctx, target, recon, clock)));
    return out;
  }

  /** Sondes HTTP déterministes (preuves capturées brutes). */
  private async customProbes(
    ctx: RealAdapterContext,
    target: URL,
    recon: ReconResult,
    clock: PhaseClock,
  ): Promise<Candidate[]> {
    const out: Candidate[] = [];
    const origin = target.origin;

    // a) En-têtes de sécurité manquants
    const page = await this.httpProbe(ctx, origin + "/", 15_000, clock);
    const h = page.headers;
    const missing: string[] = [];
    if (!h["content-security-policy"]) missing.push("Content-Security-Policy");
    if (!h["strict-transport-security"] && target.protocol === "https:") missing.push("Strict-Transport-Security");
    if (!h["x-content-type-options"]) missing.push("X-Content-Type-Options");
    if (!h["x-frame-options"] && !h["content-security-policy"]) missing.push("X-Frame-Options");
    if (!h["referrer-policy"]) missing.push("Referrer-Policy");
    if (!h["permissions-policy"]) missing.push("Permissions-Policy");
    if (missing.length >= 3 && page.status > 0) {
      out.push({
        id: "probe-headers",
        tool: "sondes DeepAudit",
        title: `En-têtes de sécurité HTTP absents (${missing.length})`,
        category: "headers",
        severity: missing.length >= 4 ? "MEDIUM" : "LOW",
        toolVerified: true,
        location: origin,
        description: `Les en-têtes de sécurité suivants ne sont pas renvoyés par le serveur : ${missing.join(", ")}. ` +
          "Cela expose les utilisateurs à du clickjacking, du sniffing de contenu et des injections.",
        evidence: `Réponse HTTP ${page.status} — en-têtes reçus :\n${
          Object.entries(h).slice(0, 20).map(([k, v]) => `${k}: ${v}`).join("\n")}`,
      });
    }

    // b) Cookies sans HttpOnly/Secure/SameSite
    for (const c of recon.cookies) {
      const flaws: string[] = [];
      if (!/httponly/i.test(c.flags)) flaws.push("HttpOnly");
      if (!/secure/i.test(c.flags)) flaws.push("Secure");
      if (!/samesite/i.test(c.flags)) flaws.push("SameSite");
      if (flaws.length) {
        out.push({
          id: `probe-cookie-${c.name}`,
          tool: "sondes DeepAudit",
          title: `Cookie ${c.name} sans ${flaws.join(" / ")}`,
          category: "cookies",
          severity: flaws.includes("HttpOnly") ? "MEDIUM" : "LOW",
          toolVerified: true,
          location: origin,
          description: `Le cookie ${c.name} est délivré sans ${flaws.join(", ")} — ` +
            (flaws.includes("HttpOnly") ? "lecture possible par du JavaScript volé (XSS), " : "") +
            "transmission possible en clair.",
          evidence: `Set-Cookie : ${c.name}=… ; attributs : ${c.flags || "(aucun attribut)"}`,
        });
      }
    }

    // c) CORS permissif
    const cors = await this.httpProbe(ctx, origin + "/", 15_000, clock, { Origin: "https://cors-probe.auditforge-test.example" });
    const acao = cors.headers["access-control-allow-origin"] ?? "";
    if (acao && (acao === "https://cors-probe.auditforge-test.example" || acao === "*")) {
      out.push({
        id: "probe-cors",
        tool: "sondes DeepAudit",
        title: `CORS permissif (Access-Control-Allow-Origin : ${acao})`,
        category: "cors",
        severity: acao === "*" ? "MEDIUM" : "HIGH",
        toolVerified: true,
        location: origin,
        description: "Le serveur reflète l'origine arbitraire (ou *) dans Access-Control-Allow-Origin : n'importe quel site peut lire les réponses authentifiées des visiteurs.",
        evidence: `Requête avec Origin: https://cors-probe.auditforge-test.example\n` +
          `Réponse : Access-Control-Allow-Origin: ${acao}\nACAC : ${cors.headers["access-control-allow-credentials"] ?? "(absent)"}`,
      });
    }

    // d) Fichiers sensibles exposés
    for (const [path, sig, sev] of SENSITIVE_FILES) {
      if (clock.remainingMs() < 30_000) break;
      const p = await this.httpProbe(ctx, `${origin}/${path}`, 12_000, clock);
      if (p.status !== 200) continue;
      const matched = sig.split("|").some((s) => p.body.includes(s));
      if (!matched) continue;
      if (path === "robots.txt") continue;
      out.push({
        id: `probe-file-${path.replace(/[^\w.]/g, "_")}`,
        tool: "sondes DeepAudit",
        title: `Fichier sensible exposé : /${path}`,
        category: "exposure",
        severity: sev,
        toolVerified: true,
        location: `${origin}/${path}`,
        description: `Le fichier /${path} est accessible publiquement (HTTP ${p.status}) et son contenu correspond à un motif attendu.`,
        evidence: clip(p.body, 2500),
      });
    }

    // e) Listing de répertoires
    if (/Index of \//i.test(page.body) && /Parent Directory/i.test(page.body)) {
      out.push({
        id: "probe-listing",
        tool: "sondes DeepAudit",
        title: "Listage de répertoires activé (autoindex)",
        category: "listing",
        severity: "MEDIUM",
        toolVerified: true,
        location: origin,
        description: "Le serveur expose la liste des fichiers du répertoire — découverte de la structure et de fichiers non liés.",
        evidence: clip(page.body, 2000),
      });
    }

    // f) Méthodes HTTP dangereuses
    const opt = await this.httpProbe(ctx, origin + "/", 12_000, clock, undefined, "OPTIONS");
    const allow = `${opt.headers["allow"] ?? ""} ${opt.headers["public"] ?? ""}`;
    if (/\b(PUT|DELETE|TRACE)\b/i.test(allow)) {
      const methods = allow.match(/\b(PUT|DELETE|TRACE)\b/gi)?.join(", ") ?? "";
      out.push({
        id: "probe-methods",
        tool: "sondes DeepAudit",
        title: `Méthodes HTTP dangereuses autorisées : ${methods}`,
        category: "methods",
        severity: /TRACE/i.test(methods) ? "MEDIUM" : "LOW",
        toolVerified: true,
        location: origin,
        description: "Le serveur annonce des méthodes HTTP sensibles — XST (TRACE) ou défigurement de contenu (PUT/DELETE) si réellement actives.",
        evidence: `OPTIONS → Allow: ${allow.trim()}`,
      });
    }

    // g) GraphQL introspection
    const gql = await this.httpProbe(ctx, `${origin}/graphql`, 12_000, clock,
      { "Content-Type": "application/json" }, "POST", JSON.stringify({ query: "{ __schema { types { name } } }" }));
    if (gql.status === 200 && gql.body.includes("__schema")) {
      out.push({
        id: "probe-graphql",
        tool: "sondes DeepAudit",
        title: "GraphQL : introspection activée",
        category: "graphql",
        severity: "MEDIUM",
        toolVerified: true,
        location: `${origin}/graphql`,
        description: "L'API GraphQL expose son schéma complet via __schema — cartographie facilitée de toute l'API.",
        evidence: clip(gql.body, 2500),
        poc: `curl -X POST ${origin}/graphql -H 'Content-Type: application/json' -d '{"query":"{ __schema { types { name } } }"}'`,
      });
    }

    // h) Traversée / redirection ouverte / SSRF sur les paramètres découverts
    const paramTargets: Array<{ url: string; param: string }> = [];
    for (const [param, url] of recon.params) {
      if (/^(file|page|path|include|template|doc|document|download|read|show|view|lang|dir)$/i.test(param)
        || /^(next|url|redirect|return|goto|r|target|continue|dest|destination|returnTo)$/i.test(param)
        || /^(url|feed|fetch|proxy|source|load|img|image|file|resource|site)$/i.test(param)) {
        paramTargets.push({ url, param });
      }
    }
    for (const t of paramTargets.slice(0, 12)) {
      if (clock.remainingMs() < 30_000) break;
      let u: URL;
      try {
        u = new URL(t.url);
      } catch {
        continue;
      }
      if (u.origin !== origin) continue;
      // traversée de chemin
      if (/^(file|page|path|include|template|doc|document|download|read|show|view|lang|dir)$/i.test(t.param)) {
        for (const payload of ["../../../../etc/passwd", "..%2F..%2F..%2F..%2Fetc%2Fpasswd", "....//....//....//etc/passwd"]) {
          u.searchParams.set(t.param, payload);
          const r = await this.httpProbe(ctx, u.toString(), 12_000, clock);
          if (/root:[x*!]?:0:0:/i.test(r.body)) {
            out.push({
              id: `probe-traversal-${t.param}`,
              tool: "sondes DeepAudit",
              title: `Traversée de chemin confirmée — paramètre ${t.param}`,
              category: "traversal",
              severity: "CRITICAL",
              toolVerified: true,
              location: u.toString(),
              description: `Le paramètre ${t.param} n'est pas normalisé : /etc/passwd a été lu via une séquence de traversée.`,
              evidence: `Requête : ${u.toString()}\nExtrait de la réponse :\n${clip(r.body, 1800)}`,
              poc: `curl '${u.toString()}'`,
            });
            break;
          }
        }
      }
      // redirection ouverte
      if (/^(next|url|redirect|return|goto|r|target|continue|dest|destination|returnTo)$/i.test(t.param)) {
        u.searchParams.set(t.param, "https://auditforge-open-redirect-probe.example/");
        const r = await this.httpProbe(ctx, u.toString(), 12_000, clock);
        const loc = r.headers["location"] ?? "";
        if (r.status >= 300 && r.status < 400 && /auditforge-open-redirect-probe\.example/.test(loc)) {
          out.push({
            id: `probe-redirect-${t.param}`,
            tool: "sondes DeepAudit",
            title: `Redirection ouverte — paramètre ${t.param}`,
            category: "open-redirect",
            severity: "MEDIUM",
            toolVerified: true,
            location: u.toString(),
            description: `Le paramètre ${t.param} redirige vers un domaine arbitraire — hameçonnage facilité.`,
            evidence: `Requête : ${u.toString()}\nRéponse : HTTP ${r.status} Location: ${loc}`,
          });
        }
      }
      // SSRF
      if (/^(url|feed|fetch|proxy|source|load|img|image|file|resource|site)$/i.test(t.param)) {
        u.searchParams.set(t.param, "http://169.254.169.254/latest/meta-data/");
        const r = await this.httpProbe(ctx, u.toString(), 12_000, clock);
        if (/ami-id|iam\/security-credentials|latest\/meta-data/i.test(r.body)) {
          out.push({
            id: `probe-ssrf-${t.param}`,
            tool: "sondes DeepAudit",
            title: `SSRF vers les métadonnées cloud — paramètre ${t.param}`,
            category: "ssrf",
            severity: "CRITICAL",
            toolVerified: true,
            location: u.toString(),
            description: `Le paramètre ${t.param} est récupéré côté serveur sans filtrage : l'endpoint de métadonnées cloud (169.254.169.254) a répondu.`,
            evidence: `Requête : ${u.toString()}\nExtrait de la réponse :\n${clip(r.body, 1800)}`,
          });
        }
      }
    }

    return out;
  }

  /* ── Phase 4 : vérification LLM ────────────────────────────────────────── */

  private async phaseVerify(
    ctx: RealAdapterContext,
    candidates: Candidate[],
    clock: PhaseClock,
  ): Promise<RealFinding[]> {
    // Dédoublonnage (catégorie + localisation + titre)
    const seen = new Set<string>();
    const unique: Candidate[] = [];
    for (const c of candidates) {
      const key = `${c.category}|${(c.location ?? "").slice(0, 120)}|${c.title.toLowerCase().slice(0, 60)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      unique.push(c);
    }
    await ctx.onLog(
      `Vérification : ${unique.length} candidat(s) unique(s) (déduction de ${candidates.length - unique.length} doublon(s))`,
      "INFO",
      "agent",
    );

    // Candidats déterministes : verdict direct, pas de LLM.
    const deterministic = new Set(["headers", "cookies", "exposure", "listing", "methods", "graphql", "cors"]);
    const findings: RealFinding[] = [];
    const toJudge: Candidate[] = [];
    for (const c of unique) {
      if (deterministic.has(c.category)) {
        findings.push(this.toFinding(c, "CONFIRMED"));
      } else {
        toJudge.push(c);
      }
    }

    // Re-jugement LLM par lots de 6.
    const CHUNK = 6;
    const judged = new Map<string, { verdict: string; severity?: string; title?: string; description?: string; remediation?: string }>();
    for (let i = 0; i < toJudge.length; i += CHUNK) {
      if (clock.remainingMs() < 30_000) {
        await ctx.onLog("Budget temps épuisé — candidats restants conservés avec leur verdict outil d'origine", "WARN", "agent");
        break;
      }
      const chunk = toJudge.slice(i, i + CHUNK);
      const system =
        "Tu es un auditeur sécurité qui valide des découvertes brutes d'outils. Pour chaque candidat, juge la preuve " +
        'fournie et réponds en JSON strict : {"verdicts":[{"id":string,"verdict":"confirmed"|"probable"|' +
        '"false_positive","severity":"critical"|"high"|"medium"|"low"|"info","title":string,' +
        '"description":string,"remediation":string}]}. false_positive = preuve insuffisante ou comportement normal. ' +
        "Soyez STRICT : sans preuve concrète dans l'extrait, réponds probable ou false_positive (jamais confirmed).";
      const user = JSON.stringify(chunk.map((c) => ({
        id: c.id, outil: c.tool, titre: c.title, categorie: c.category,
        localisation: c.location, preuve: clip(c.evidence, 1800),
      })), null, 1);
      const res = await this.llmJson(ctx, system, user, 3000, 90_000);
      const arr = Array.isArray(res?.verdicts) ? (res.verdicts as Array<Record<string, unknown>>) : [];
      for (const v of arr) {
        if (v && typeof v.id === "string") {
          judged.set(v.id, {
            verdict: String(v.verdict ?? "probable").toLowerCase(),
            severity: typeof v.severity === "string" ? v.severity : undefined,
            title: typeof v.title === "string" ? v.title : undefined,
            description: typeof v.description === "string" ? v.description : undefined,
            remediation: typeof v.remediation === "string" ? v.remediation : undefined,
          });
        }
      }
    }

    let falsePositives = 0;
    for (const c of toJudge) {
      const j = judged.get(c.id);
      const verdict = j?.verdict ?? (c.toolVerified ? "confirmed" : "probable");
      if (verdict === "false_positive") {
        falsePositives += 1;
        continue;
      }
      const confidence: RealFinding["confidence"] =
        verdict === "confirmed" ? "CONFIRMED" : c.toolVerified ? "CONFIRMED" : "PROBABLE";
      findings.push(this.toFinding(
        {
          ...c,
          severity: mapSeverity(j?.severity ?? c.severity),
          title: j?.title ?? c.title,
          description: j?.description ?? c.description,
        },
        confidence,
      ));
    }
    if (falsePositives) {
      await ctx.onLog(`Agent IA : ${falsePositives} faux positif(s) écarté(s) après re-lecture des preuves`, "AGENT", "agent");
    }

    // Tri : sévérité puis confiance.
    const order: Record<RealFinding["severity"], number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    findings.sort((a, b) => (order[a.severity] - order[b.severity]) || (a.confidence === "CONFIRMED" ? -1 : 1));
    return findings;
  }

  /* ── Phase 5 : rapport ─────────────────────────────────────────────────── */

  private async phaseReport(
    ctx: RealAdapterContext,
    target: URL,
    summary: string,
    elapsedSec: number,
  ): Promise<void> {
    await ctx.onLog(`DeepAudit terminé en ${Math.round(elapsedSec / 60)} min — ${summary}`, "SUCCESS", "deepaudit");

    if (REAL_EXEC.llmApiKey) {
      const system =
        "Tu es un auditeur sécurité. Rédige une synthèse exécutive en 3-5 phrases (FR) sur la cible " +
        target.origin + " : état général, risque principal, 2-3 axes de remédiation prioritaires. " +
        "Pas de liste à puces, pas de titre.";
      const res = await this.llmChat(ctx, system, summary.slice(0, 3000), 500, 60_000);
      if (res?.trim()) {
        await ctx.onLog(`Synthèse exécutive de l'agent : ${res.trim()}`, "AGENT", "agent");
      }
    }
  }

  /* ── Conversion en RealFinding ─────────────────────────────────────────── */

  private toFinding(c: Candidate, confidence: RealFinding["confidence"]): RealFinding {
    return {
      title: c.title.slice(0, 300),
      severity: c.severity,
      confidence,
      category: c.category,
      cve: /CVE-\d{4}-\d{4,7}/i.exec(c.evidence)?.[0] ?? null,
      cvss: null,
      location: c.location,
      description: c.description || c.title,
      evidence: c.evidence || "(aucune preuve détaillée)",
      poc: c.poc,
      sentinelTriggered: confidence === "CONFIRMED",
      remediation: REMEDIATIONS[c.category] ?? REMEDIATIONS.misc,
    };
  }

  /* ── Exécution d'outils dans la sandbox ────────────────────────────────── */

  /** Exécute un outil via docker exec — flux diffusé dans le journal du scan. */
  private async execTool(
    ctx: RealAdapterContext,
    argv: string[],
    opts: { timeoutMs: number; label: string; maxLines?: number },
  ): Promise<ToolResult> {
    this.toolExecutions += 1;
    const maxLines = opts.maxLines ?? 0; // 0 = silencieux (sondes curl rapides)
    await ctx.onLog(`$ ${argv.join(" ")}`, "CMD", "deepaudit");
    let stdout = "";
    let stderr = "";
    let lines = 0;
    const result = await runStreaming({
      cmd: "docker",
      args: ["exec", this.container, ...argv],
      timeoutMs: opts.timeoutMs,
      signal: ctx.signal,
      maxLineLength: MAX_LINE_LENGTH_HARD,
      env: { NO_COLOR: "1" },
      onLine: async (line, isErr) => {
        if (isErr) stderr = (stderr + line + "\n").slice(-60_000);
        else stdout = (stdout + line + "\n").slice(-140_000);
        lines += 1;
        if (maxLines > 0 && lines <= maxLines) {
          await ctx.onLog(line.length > 1600 ? line.slice(0, 1600) + "…" : line, isErr ? "WARN" : "TOOL", "deepaudit");
        } else if (maxLines > 0 && lines === maxLines + 1) {
          await ctx.onLog(`… (sortie tronquée pour ce tool — ${opts.label})`, "INFO", "deepaudit");
        }
      },
    });
    return { code: result.exitCode ?? -1, stdout, stderr, timedOut: result.timedOut };
  }

  /** docker / capture non-streamée (gestion du cycle de vie du conteneur). */
  private dockerCapture(args: string[], timeoutMs: number): Promise<{ code: number; out: string; err: string }> {
    return new Promise((resolve) => {
      let child: ChildProcess;
      try {
        child = spawn("docker", args, { stdio: ["ignore", "pipe", "pipe"] });
      } catch {
        resolve({ code: -1, out: "", err: "spawn docker impossible" });
        return;
      }
      let out = "";
      let err = "";
      const t = setTimeout(() => {
        child.kill("SIGKILL");
        resolve({ code: -1, out, err: err || "timeout" });
      }, timeoutMs);
      child.stdout?.on("data", (d: Buffer) => { out += d.toString("utf8"); });
      child.stderr?.on("data", (d: Buffer) => { err += d.toString("utf8"); });
      child.on("error", (e) => {
        clearTimeout(t);
        resolve({ code: -1, out, err: String(e) });
      });
      child.on("close", (code) => {
        clearTimeout(t);
        resolve({ code: code ?? -1, out, err });
      });
    });
  }

  private async waitReady(ctx: RealAdapterContext, timeoutMs: number): Promise<boolean> {
    const end = Date.now() + timeoutMs;
    while (Date.now() < end) {
      if (ctx.signal.aborted) return false;
      const r = await this.dockerCapture(["exec", this.container, "echo", "READY"], 5_000);
      if (r.code === 0 && r.out.includes("READY")) return true;
      await new Promise((res) => setTimeout(res, 1500));
    }
    return false;
  }

  /* ── HTTP via curl dans la sandbox ─────────────────────────────────────── */

  /** Requête HTTP via curl dans la sandbox — en-têtes + corps capturés. */
  private async httpProbe(
    ctx: RealAdapterContext,
    url: string,
    timeoutMs: number,
    clock: PhaseClock,
    extraHeaders?: Record<string, string>,
    method = "GET",
    body?: string,
  ): Promise<HttpProbeResult> {
    const args = [
      "curl", "-sk", "-i", "-m", String(Math.max(5, Math.round(timeoutMs / 1000))),
      "--compressed", "-A", "Mozilla/5.0 (compatible; AuditForgeDeepAudit/1.0)",
    ];
    if (method !== "GET") args.push("-X", method);
    if (body) args.push("--data-binary", body);
    for (const [k, v] of Object.entries(extraHeaders ?? {})) args.push("-H", `${k}: ${v}`);
    args.push(url);
    const r = await this.execTool(ctx, args, { timeoutMs: clock.left(timeoutMs + 8_000), label: `curl ${method} ${url.slice(0, 60)}` });
    const raw = r.stdout;
    const sep = raw.indexOf("\r\n\r\n");
    const head = sep >= 0 ? raw.slice(0, sep) : raw;
    const bodyText = sep >= 0 ? raw.slice(sep + 4) : "";
    const statusMatch = /HTTP\/[\d.]+\s+(\d{3})/.exec(head);
    const headers: Record<string, string> = {};
    for (const line of head.split(/\r?\n/).slice(1)) {
      const idx = line.indexOf(":");
      if (idx > 0) headers[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
    }
    return { status: statusMatch ? Number(statusMatch[1]) : 0, headers, body: bodyText.slice(0, 40_000) };
  }

  /** Parse les Set-Cookie d'une réponse (nom + attributs). */
  private setCookies(header: string): Array<{ name: string; flags: string }> {
    const out: Array<{ name: string; flags: string }> = [];
    for (const part of header.split(/(?=Set-Cookie:)/i)) {
      const m = /Set-Cookie:\s*([^=;]+)=([^;]*)(.*)/i.exec(part);
      if (m) out.push({ name: m[1].trim(), flags: m[3].trim() });
    }
    return out;
  }

  /** Extraction naïve des formulaires HTML (action, method, champs). */
  private parseForms(html: string, baseUrl: string): Array<{ action: string; method: string; fields: string[] }> {
    const out: Array<{ action: string; method: string; fields: string[] }> = [];
    for (const m of html.matchAll(/<form\b[^>]*>([\s\S]*?)<\/form>/gi)) {
      const tag = m[0];
      const actionRaw = /\baction\s*=\s*["']([^"']*)["']/i.exec(tag)?.[1] ?? "";
      const method = (/\bmethod\s*=\s*["']([^"']*)["']/i.exec(tag)?.[1] ?? "GET").toUpperCase();
      let action = actionRaw;
      try {
        action = new URL(actionRaw || baseUrl, baseUrl).toString();
      } catch { /* garde l'action brute */ }
      const fields = [...tag.matchAll(/<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["']([^"']+)["']/gi)].map((x) => x[1]);
      out.push({ action, method, fields: [...new Set(fields)].slice(0, 25) });
    }
    return out;
  }

  /** Choisit la wordlist ffuf (seclists si présente, repli embarqué). */
  private async pickWordlist(ctx: RealAdapterContext, std: boolean): Promise<string> {
    void ctx;
    const candidates = std
      ? ["/usr/share/seclists/Discovery/Web-Content/common.txt", "/usr/share/wordlists/dirb/common.txt"]
      : ["/usr/share/wordlists/dirb/common.txt"];
    for (const p of candidates) {
      const r = await this.dockerCapture(["exec", this.container, "test", "-f", p], 5_000);
      if (r.code === 0) return p;
    }
    // Repli : wordlist embarquée écrite dans la sandbox.
    const words = FALLBACK_WORDLIST.map((w) => w.replace(/[^a-zA-Z0-9._\-\/]/g, "")).filter(Boolean).join(" ");
    await this.dockerCapture(["exec", this.container, "sh", "-c", `printf '%s\n' ${words} > /tmp/wl.txt`], 10_000);
    return "/tmp/wl.txt";
  }

  /** Déduplique les cibles outil (URL + param). */
  private dedupTargets<T extends { url: string; param?: string }>(list: T[]): T[] {
    const seen = new Set<string>();
    const out: T[] = [];
    for (const t of list) {
      if (!t?.url || !/^https?:\/\//i.test(t.url)) continue;
      const key = `${t.url}|${t.param ?? ""}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(t);
    }
    return out;
  }

  /* ── LLM (endpoint OpenAI-compatible) ──────────────────────────────────── */

  /** Appel chat simple (texte). */
  private async llmChat(
    ctx: RealAdapterContext,
    system: string,
    user: string,
    maxTokens: number,
    timeoutMs: number,
  ): Promise<string | null> {
    if (!REAL_EXEC.llmApiKey) return null;
    const base = (REAL_EXEC.llmApiBase || "").replace(/\/+$/, "");
    if (!base) return null;
    const model = stripProvider(REAL_EXEC.phantomLlm || "glm-4.6");
    for (let attempt = 0; attempt < 2; attempt++) {
      if (ctx.signal.aborted) return null;
      try {
        this.llmCalls += 1;
        const res = await fetch(`${base}/chat/completions`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${REAL_EXEC.llmApiKey}` },
          body: JSON.stringify({
            model,
            messages: [
              { role: "system", content: system },
              { role: "user", content: user },
            ],
            temperature: 0.2,
            max_tokens: maxTokens,
          }),
          signal: AbortSignal.timeout(timeoutMs),
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = (await res.json()) as { choices?: Array<{ message?: { content?: string } }> };
        return data.choices?.[0]?.message?.content ?? null;
      } catch (err) {
        if (attempt === 1) {
          await ctx.onLog(`LLM injoignable (${err instanceof Error ? err.message : "erreur"}) — continuation sans raisonnement IA`, "WARN", "agent");
          return null;
        }
        await new Promise((r) => setTimeout(r, 2000));
      }
    }
    return null;
  }

  /** Appel chat avec attente d'un objet JSON (repli null). */
  private async llmJson(
    ctx: RealAdapterContext,
    system: string,
    user: string,
    maxTokens: number,
    timeoutMs: number,
  ): Promise<Record<string, unknown> | null> {
    const text = await this.llmChat(ctx, system, user, maxTokens, timeoutMs);
    if (!text) return null;
    const parsed = extractJson(text);
    if (!parsed) await ctx.onLog("Réponse LLM sans JSON exploitable — repli programmatique", "WARN", "agent");
    return parsed;
  }
}

/** Résumé textuel des constats (phase rapport). */
function findingsSummary(findings: RealFinding[]): string {
  const bySev = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 } as Record<RealFinding["severity"], number>;
  for (const f of findings) bySev[f.severity] += 1;
  const list = findings.slice(0, 25).map((f) => `- [${f.severity}] ${f.title} (${f.category})`).join("\n");
  return `${findings.length} constat(s) : ${bySev.CRITICAL} critique(s), ${bySev.HIGH} élevé(s), ` +
    `${bySev.MEDIUM} moyen(s), ${bySev.LOW} faible(s), ${bySev.INFO} info.\n${list}`;
}
