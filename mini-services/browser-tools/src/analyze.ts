/**
 * AuditForge — Sprint 3 : analyseurs navigateur headless.
 *
 * Quatre outils evergreen basés Chromium (playwright-core) :
 *   - BROWSER_RECON  : empreinte technologique en conditions réelles de rendu ;
 *   - DOM_SINK_SCAN  : analyse statique des sources/sinks DOM (XSS potentiel) ;
 *   - JS_LIB_AUDIT   : versions des bibliothèques front + CVE connues (SCA) ;
 *   - FORM_AUDIT     : sécurité des formulaires et iframes (credentials, CSRF).
 *
 * Chaque analyseur retourne des constats normalisés (BrowserFinding) que le
 * moteur traduit 1:1 en RealFinding. Le JSON est écrit par cli.ts — TOUJOURS,
 * même partiel (contrat moteur : un rapport attendu doit exister).
 */

import type { Page } from "playwright-core";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type Confidence = "CONFIRMED" | "PROBABLE" | "UNVERIFIED";

export interface BrowserFinding {
  key: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  category: string;
  cve?: string;
  cvss?: number;
  location: string;
  description: string;
  evidence: string;
  poc?: string;
  remediation?: string;
}

export interface BrowserToolReport {
  tool: string;
  ok: boolean;
  target: string;
  finalUrl: string;
  httpStatus: number | null;
  loadMs: number;
  requestCount: number;
  error?: string;
  stats: Record<string, unknown>;
  findings: BrowserFinding[];
}

export interface AnalyzeCtx {
  page: Page;
  target: string;
  finalUrl: string;
  httpStatus: number | null;
  loadMs: number;
  requestUrls: string[];
  responseHeaders: Record<string, string>;
}

export interface AnalyzeResult {
  findings: BrowserFinding[];
  stats: Record<string, unknown>;
}

const FINDINGS_CAP = 120;

/** Dédup (title, location) + plafond anti-flood (contrat arsenal.capFindings). */
export function capFindings(findings: BrowserFinding[]): BrowserFinding[] {
  const seen = new Set<string>();
  const out: BrowserFinding[] = [];
  for (const f of findings) {
    const k = `${f.title}::${f.location}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(f);
  }
  return out.length > FINDINGS_CAP ? out.slice(0, FINDINGS_CAP) : out;
}

function evidenceBlock(parts: unknown[], max = 4000): string {
  const joined = parts
    .filter((p) => p !== null && p !== undefined && p !== "")
    .map((p) => (typeof p === "string" ? p : JSON.stringify(p)))
    .join("\n");
  return joined.length > max ? `${joined.slice(0, max)}\n… (tronqué)` : joined;
}

/** Comparaison de versions sémantiques simples (« 3.6.0 » vs « 3.5.0 »). */
export function cmpVersions(a: string, b: string): number {
  const pa = a.split(/[.\-+]/).map((x) => parseInt(x, 10) || 0);
  const pb = b.split(/[.\-+]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < 4; i++) {
    const da = pa[i] ?? 0;
    const db = pb[i] ?? 0;
    if (da !== db) return da - db;
  }
  return 0;
}

// ─────────────────────────── BROWSER_RECON ───────────────────────────

interface TechHit {
  name: string;
  version: string | null;
  source: string;
}

/** Détection par variables globales (versions exactes, fiable). */
function globalTechScript(): TechHit[] {
  const w = window as unknown as Record<string, unknown>;
  const out: TechHit[] = [];
  const push = (name: string, version: unknown, source: string) => {
    out.push({ name, version: version ? String(version) : null, source });
  };
  try {
    const jq = (w.jQuery ?? w.$) as { fn?: { jquery?: string } } | undefined;
    if (jq?.fn?.jquery) push("jQuery", jq.fn.jquery, "window.jQuery/$.fn.jquery");
  } catch { /* page hostile */ }
  try {
    const ui = (w.jQuery as { ui?: { version?: string } } | undefined)?.ui;
    if (ui?.version) push("jQuery UI", ui.version, "window.jQuery.ui.version");
  } catch { /* ignore */ }
  try {
    const mig = (w.jQuery as { migrateVersion?: string } | undefined)?.migrateVersion;
    if (mig) push("jQuery Migrate", mig, "window.jQuery.migrateVersion");
  } catch { /* ignore */ }
  try {
    const mom = w.moment as { version?: string } | undefined;
    if (mom?.version) push("Moment.js", mom.version, "window.moment.version");
  } catch { /* ignore */ }
  try {
    const ld = w._ as { VERSION?: string } | undefined;
    if (ld?.VERSION) push("Lodash/Underscore", ld.VERSION, "window._.VERSION");
  } catch { /* ignore */ }
  try {
    const ang = w.angular as { version?: { full?: string } } | undefined;
    if (ang?.version?.full) push("AngularJS", ang.version.full, "window.angular.version");
  } catch { /* ignore */ }
  try {
    const vue = w.Vue as { version?: string } | undefined;
    if (vue?.version) push("Vue.js", vue.version, "window.Vue.version");
  } catch { /* ignore */ }
  try {
    const react = w.React as { version?: string } | undefined;
    if (react?.version) push("React", react.version, "window.React.version");
  } catch { /* ignore */ }
  try {
    const chart = w.Chart as { version?: string } | undefined;
    if (chart?.version) push("Chart.js", chart.version, "window.Chart.version");
  } catch { /* ignore */ }
  try {
    const three = w.THREE as { REVISION?: string } | undefined;
    if (three?.REVISION) push("Three.js", `r${three.REVISION}`, "window.THREE.REVISION");
  } catch { /* ignore */ }
  try {
    const gsap = w.gsap as { version?: string } | undefined;
    if (gsap?.version) push("GSAP", gsap.version, "window.gsap.version");
  } catch { /* ignore */ }
  try {
    const popper = w.Popper as { VERSION?: string } | undefined;
    if (popper?.VERSION) push("Popper.js", popper.VERSION, "window.Popper.VERSION");
  } catch { /* ignore */ }
  try {
    const boot = w.bootstrap as { Version?: string } | undefined;
    if (boot?.Version) push("Bootstrap", boot.Version, "window.bootstrap.Version");
  } catch { /* ignore */ }
  try {
    if (w.__NEXT_DATA__) push("Next.js", (w.__NEXT_DATA__ as { buildId?: string }).buildId ? "runtime détecté" : null, "window.__NEXT_DATA__");
  } catch { /* ignore */ }
  try {
    if (w.__NUXT__) push("Nuxt", null, "window.__NUXT__");
  } catch { /* ignore */ }
  try {
    if (document.querySelector("[data-reactroot], [data-reactid]")) push("React (marqueurs DOM)", null, "data-reactroot/id");
  } catch { /* ignore */ }
  try {
    if (document.querySelector("[data-v-app], [data-v-]")) push("Vue (marqueurs DOM)", null, "data-v-app");
  } catch { /* ignore */ }
  return out;
}

/** Détection par URL des scripts réseau (couvre les libs sans global). */
function techFromUrls(urls: string[]): TechHit[] {
  const out: TechHit[] = [];
  const seen = new Set<string>();
  const patterns: Array<{ name: string; re: RegExp }> = [
    { name: "jQuery", re: /\/jquery[\w.-]*?([\d.]+)?\.min?\.js/i },
    { name: "jQuery Migrate", re: /\/jquery-migrate[\w.-]*?([\d.]+)?\.min?\.js/i },
    { name: "jQuery UI", re: /\/jquery-ui[\w.-]*?([\d.]+)?\.min?\.js/i },
    { name: "Bootstrap", re: /\/bootstrap[\w.-]*?([\d.]+)?(?:\.bundle)?\.min?\.js/i },
    { name: "Moment.js", re: /\/moment[\w.-]*?([\d.]+)?\.min?\.js/i },
    { name: "Lodash", re: /\/lodash[\w.-]*?([\d.]+)?\.min?\.js/i },
    { name: "AngularJS", re: /\/angular[\w.-]*?([\d.]+)?\.min?\.js/i },
    { name: "Vue.js", re: /\/vue(?:\.runtime)?[\w.-]*?([\d.]+)?\.min?\.js/i },
    { name: "React", re: /\/react[\w.-]*?([\d.]+)?\.min?\.js/i },
    { name: "Chart.js", re: /\/chart[\w.-]*?([\d.]+)?\.min?\.js/i },
    { name: "GSAP", re: /\/gsap[\w.-]*?([\d.]+)?\.min?\.js/i },
    { name: "Three.js", re: /\/three[\w.-]*?([\d.]+)?\.min?\.js/i },
    { name: "Slick Carousel", re: /\/slick[\w.-]*?([\d.]+)?\.min?\.js/i },
    { name: "Owl Carousel", re: /\/owl\.carousel[\w.-]*?([\d.]+)?\.min?\.js/i },
    { name: "Swiper", re: /\/swiper[\w.-]*?([\d.]+)?\.min?\.js/i },
    { name: "Font Awesome", re: /\/font-?awesome[\w.-]*?([\d.]+)?\.min?\.js/i },
  ];
  for (const url of urls) {
    for (const p of patterns) {
      const m = url.match(p.re);
      if (!m) continue;
      const key = p.name;
      if (seen.has(key)) break;
      // Version : paramètre ?ver= prioritaire (WordPress/Drupal), sinon basename.
      const qver = url.match(/[?&]ver=([\d.]+)/);
      const bver = m[1] && /[\d]/.test(m[1]) ? m[1] : null;
      const version = qver ? qver[1] : bver;
      seen.add(key);
      out.push({ name: key, version, source: "URL script" });
      break;
    }
  }
  return out;
}

export async function analyzeRecon(ctx: AnalyzeCtx): Promise<AnalyzeResult> {
  const findings: BrowserFinding[] = [];
  const pageOrigin = new URL(ctx.finalUrl);

  const [globalTechs, generator, mixedContent, domStats] = await Promise.all([
    ctx.page.evaluate(globalTechScript).catch(() => [] as TechHit[]),
    ctx.page
      .evaluate(() => document.querySelector('meta[name="generator" i]')?.getAttribute("content") ?? null)
      .catch(() => null as string | null),
    ctx.page
      .evaluate(() => {
        if (location.protocol !== "https:") return [];
        const urls: string[] = [];
        for (const el of document.querySelectorAll("[src],[href],[action]")) {
          const u = el.getAttribute("src") ?? el.getAttribute("href") ?? el.getAttribute("action");
          if (u && u.startsWith("http://")) urls.push(u);
        }
        return [...new Set(urls)];
      })
      .catch(() => [] as string[]),
    ctx.page
      .evaluate(() => ({
        scripts: document.querySelectorAll("script").length,
        externals: document.querySelectorAll("script[src]").length,
        forms: document.querySelectorAll("form").length,
        iframes: document.querySelectorAll("iframe").length,
        nodes: document.getElementsByTagName("*").length,
        title: document.title,
        lang: document.documentElement.lang ?? null,
      }))
      .catch(() => ({ scripts: 0, externals: 0, forms: 0, iframes: 0, nodes: 0, title: "", lang: null })),
  ]);

  const urlTechs = techFromUrls(ctx.requestUrls);
  const merged = new Map<string, TechHit>();
  for (const t of [...urlTechs, ...globalTechs]) {
    const prev = merged.get(t.name);
    if (!prev || (!prev.version && t.version)) merged.set(t.name, t);
  }
  const techs = [...merged.values()];

  // 1. TLS absent
  if (pageOrigin.protocol === "http:") {
    findings.push({
      key: "recon-no-tls",
      title: "Contenu servi sans chiffrement TLS (HTTP en clair)",
      severity: "MEDIUM",
      confidence: "CONFIRMED",
      category: "misconfig",
      location: ctx.finalUrl,
      description:
        "La page a été rendue depuis une URL http:// sans redirection visible vers https:// : l'intégralité du contenu (et de tout futur formulaire) circule en clair, interceptable par un attaquant en position réseau (wifi public, FAI, hop compromis).",
      evidence: evidenceBlock([`URL finale : ${ctx.finalUrl}`, `Statut HTTP : ${ctx.httpStatus ?? "?"}`]),
      remediation:
        "Forcer HTTPS partout : redirection 301 permanente, HSTS (max-age ≥ 15552000), certificat valide (Let's Encrypt) et cookies Secure.",
    });
  }

  // 2. Mixed content
  if (mixedContent.length > 0) {
    findings.push({
      key: "recon-mixed-content",
      title: `Contenu mixte HTTP/HTTPS (${mixedContent.length} ressource(s))`,
      severity: "MEDIUM",
      confidence: "CONFIRMED",
      category: "web",
      location: ctx.finalUrl,
      description:
        "Une page HTTPS charge des ressources en http:// (scripts, images, iframes, actions). Un attaquant en position réseau peut substituer ces ressources (script malveillant injecté sans alerte navigateur pour le passif, MITM actif pour le script).",
      evidence: evidenceBlock(mixedContent.slice(0, 20)),
      remediation:
        "Migrer toutes les ressources en https:// (ou URL relatives), ajouter une CSP upgrade-insecure-requests, corriger les liens codés en dur.",
    });
  }

  // 3. Technologies versionnées exposées
  const versioned = techs.filter((t) => t.version);
  if (versioned.length > 0) {
    findings.push({
      key: "recon-versioned-tech",
      title: `${versioned.length} technologie(s) front exposée(s) avec version précise`,
      severity: "LOW",
      confidence: "CONFIRMED",
      category: "info-disclosure",
      location: ctx.finalUrl,
      description:
        "Les versions exactes des bibliothèques front sont publiquement dérivables (variables globales, noms de fichiers ?ver=). Cette cartographie oriente directement la sélection d'exploits connus sans phase de reconnaissance pour l'attaquant.",
      evidence: evidenceBlock(versioned.map((t) => `${t.name} ${t.version} (${t.source})`)),
      remediation:
        "Minifier/empaqueter les dépendances sans version dans le nom, retirer les en-têtes X-Powered-By, évaluer une CSP ; maintenir les libs à jour de toute façon.",
    });
  }

  // 4. Meta generator
  if (generator) {
    findings.push({
      key: "recon-generator-meta",
      title: "Métadonnée generator divulguée",
      severity: "LOW",
      confidence: "CONFIRMED",
      category: "info-disclosure",
      location: ctx.finalUrl,
      description:
        "La balise <meta name=\"generator\"> expose la pile technique (CMS, version). Couplée aux CVE publiques du produit cité, elle permet un ciblage immédiat.",
      evidence: evidenceBlock([generator]),
      remediation: "Retirer la balise generator (remove_action WordPress « wp_generator », filtre Drupal, etc.).",
    });
  }

  // 5. En-têtes serveur divulgués
  const headerLeaks: string[] = [];
  for (const h of ["server", "x-powered-by", "x-aspnet-version", "x-generator", "via"]) {
    const v = ctx.responseHeaders[h];
    if (v) headerLeaks.push(`${h}: ${v}`);
  }
  if (headerLeaks.length > 0) {
    findings.push({
      key: "recon-header-leak",
      title: "En-têtes de réponse divulguant la pile serveur",
      severity: "LOW",
      confidence: "CONFIRMED",
      category: "info-disclosure",
      location: ctx.finalUrl,
      description:
        "Les en-têtes Server/X-Powered-By exposent produits et versions exactes du backend — une entrée d'enumération gratuite pour l'attaquant (exploits ciblés, fingerprinting automatisé).",
      evidence: evidenceBlock(headerLeaks),
      remediation: "ServerTokens Prod (Apache), server_tokens off (nginx), supprimer X-Powered-By (expose_php=Off, expose header off).",
    });
  }

  // 6. Constat de synthèse (empreinte complète — toujours)
  findings.push({
    key: "recon-summary",
    title: `Empreinte navigateur : ${techs.length} technologie(s), ${domStats.nodes} nœud(s) DOM`,
    severity: "INFO",
    confidence: "CONFIRMED",
    category: "recon",
    location: ctx.finalUrl,
    description:
      "Rendu Chromium headless complet : technologies identifiées en conditions réelles d'exécution JavaScript (ce que WhatWeb/HTTPX voient via headers uniquement), statistiques de chargement et composition du DOM.",
    evidence: evidenceBlock([
      `Titre : ${domStats.title}`,
      `Langue : ${domStats.lang ?? "non définie"}`,
      ...techs.map((t) => `${t.name}${t.version ? ` ${t.version}` : ""} (${t.source})`),
      `DOM : ${domStats.nodes} nœuds, ${domStats.scripts} scripts (${domStats.externals} externes), ${domStats.forms} formulaires, ${domStats.iframes} iframes`,
      `Requêtes réseau : ${ctx.requestUrls.length}`,
      `Chargement : ${ctx.loadMs} ms`,
      ...Object.entries(ctx.responseHeaders).slice(0, 15).map(([k, v]) => `${k}: ${v}`),
    ]),
    remediation:
      "Réduire l'empreinte (versions visibles, en-têtes, chemins génériques) — défense en profondeur, pas une faille en soi.",
  });

  return {
    findings: capFindings(findings),
    stats: {
      techs: techs.map((t) => ({ name: t.name, version: t.version })),
      title: domStats.title,
      domNodes: domStats.nodes,
      scripts: domStats.scripts,
      externals: domStats.externals,
      forms: domStats.forms,
      iframes: domStats.iframes,
      mixedContent: mixedContent.length,
    },
  };
}

// ─────────────────────────── DOM_SINK_SCAN ───────────────────────────

const SOURCE_RE =
  /location\.hash|location\.search|location\.href|document\.URL|document\.documentURI|document\.referrer|window\.name|event\.data|URLSearchParams/;

const SINKS: Array<{ re: RegExp; label: string }> = [
  { re: /\.innerHTML\s*=/, label: "innerHTML" },
  { re: /\.outerHTML\s*=/, label: "outerHTML" },
  { re: /insertAdjacentHTML\s*\(/, label: "insertAdjacentHTML()" },
  { re: /document\.write(ln)?\s*\(/, label: "document.write()" },
  { re: /(?:^|[^.\w])eval\s*\(/, label: "eval()" },
  { re: /new\s+Function\s*\(/, label: "new Function()" },
  { re: /setTimeout\s*\(\s*["'`]/, label: "setTimeout(string)" },
  { re: /(?:location(?:\.href)?|window\.location)\s*=/, label: "redirection location dynamique" },
];

interface ScriptUnit {
  name: string;
  code: string;
  inline: boolean;
  bytes: number;
}

export async function analyzeDomXss(ctx: AnalyzeCtx): Promise<AnalyzeResult> {
  const findings: BrowserFinding[] = [];

  const pageData = await ctx.page
    .evaluate(() => {
      const inline: string[] = [];
      for (const s of document.querySelectorAll("script:not([src])")) {
        const t = s.textContent ?? "";
        if (t.trim().length > 0 && t.length < 400_000) inline.push(t);
      }
      const externals: string[] = [];
      for (const s of document.querySelectorAll("script[src]")) {
        const src = (s as HTMLScriptElement).src;
        if (src) externals.push(src);
      }
      const srcdocCount = document.querySelectorAll("iframe[srcdoc]").length;
      return { inline, externals, srcdocCount, origin: location.origin };
    })
    .catch(() => ({ inline: [] as string[], externals: [] as string[], srcdocCount: 0, origin: "" }));

  // Scripts externes same-origin (lecture directe ; cross-origin protégé par CORS).
  const units: ScriptUnit[] = pageData.inline.map((code, i) => ({
    name: `inline#${i + 1}`,
    code,
    inline: true,
    bytes: code.length,
  }));
  const sameOrigin = pageData.externals.filter((u) => {
    try {
      return new URL(u).origin === pageData.origin;
    } catch {
      return false;
    }
  });
  const fetchTargets = sameOrigin.slice(0, 25);
  const fetched = await Promise.all(
    fetchTargets.map(async (u) => {
      try {
        const res = await fetch(u, { signal: AbortSignal.timeout(5000), redirect: "follow" });
        if (!res.ok) return null;
        const text = await res.text();
        if (text.length > 1_000_000) return { u, text: text.slice(0, 1_000_000) };
        return { u, text };
      } catch {
        return null;
      }
    })
  );
  for (const f of fetched) {
    if (f) units.push({ name: f.u, code: f.text, inline: false, bytes: f.text.length });
  }

  const flows: Array<{ unit: string; sink: string }> = [];
  const lonelySinks: Array<{ unit: string; sink: string; inline: boolean; lib: boolean }> = [];
  const evalUnits: string[] = [];
  const postMessageUnits: Array<{ unit: string; hasOriginCheck: boolean }> = [];

  for (const unit of units) {
    const hasSource = SOURCE_RE.test(unit.code);
    const hitSinks: string[] = [];
    for (const sink of SINKS) {
      if (sink.re.test(unit.code)) hitSinks.push(sink.label);
    }
    const isLib = !unit.inline && unit.bytes > 100_000;
    if (hasSource && hitSinks.length > 0) {
      for (const sink of hitSinks) flows.push({ unit: unit.name, sink });
    } else {
      for (const sink of hitSinks) {
        lonelySinks.push({ unit: unit.name, sink, inline: unit.inline, lib: isLib });
      }
    }
    if (/(?:^|[^.\w])eval\s*\(|new\s+Function\s*\(/.test(unit.code)) evalUnits.push(unit.name);
    if (/addEventListener\s*\(\s*["'`]message["'`]/.test(unit.code)) {
      const hasOriginCheck = /\.origin\b/.test(unit.code);
      postMessageUnits.push({ unit: unit.name, hasOriginCheck });
    }
  }

  // 1. Flux source → sink (DOM XSS potentiel)
  const flowKeys = [...new Set(flows.map((f) => `${f.unit}|${f.sink}`))];
  if (flowKeys.length > 0) {
    // Les occurrences situées au sein d'une bibliothèque tierce volumineuse
    // (>100 Ko, code minifié non contrôlé) sont majoritairement des faux
    // positifs (helpers génériques) — dégradées en LOW.
    const unitIsLib = new Map<string, boolean>(units.map((u) => [u.name, !u.inline && u.bytes > 50_000]));
    for (const key of flowKeys.slice(0, 15)) {
      const [unit, sink] = key.split("|");
      const isLib = unitIsLib.get(unit) ?? false;
      findings.push({
        key: "domxss-flow",
        title: `Flux de données contrôlé vers sink DOM « ${sink} »`,
        severity: isLib ? "LOW" : "HIGH",
        confidence: "UNVERIFIED",
        category: "xss",
        location: unit.startsWith("http") ? unit : ctx.finalUrl,
        description:
          isLib
            ? `Une valeur contrôlable par l'attaquant (fragment d'URL, paramètre, window.name, message postMessage) atteint un sink dangereux (${sink}) au sein de la bibliothèque ${unit}. Dans du code de bibliothèque minifié, ces motifs sont le plus souvent des helpers génériques (faux positif probable) — à confirmer manuellement.`
            : "Une valeur contrôlable par l'attaquant (fragment d'URL, paramètre, window.name, message postMessage) atteint un sink dangereux (injection HTML/évaluation de code) sans échappement visible. L'analyse est statique : un contre-flux (encodage, DOMPurify, validation) peut exister — à vérifier manuellement avec un payload.",
        evidence: evidenceBlock([`Script : ${unit}${isLib ? " (bibliothèque tierce)" : ""}`, `Source identifiée par motif : location.* / window.name / event.data`, `Sink : ${sink}`]),
        poc: `Ouvrir la page, exécuter dans la console : history.replaceState(null,'','#<img src=x onerror=alert(1)>') puis recharger / interagir — observer si le payload atteint ${sink}.`,
        remediation:
          "Ne jamais affecter une donnée non validée à innerHTML/outerHTML/document.write : utiliser textContent, encoder au contexte, DOMPurify pour le HTML riche, et auditer les handlers postMessage (validation event.origin stricte).",
      });
    }
  }

  // 2. Sinks isolés (surface) — inline ou scripts applicatifs uniquement (pas les libs)
  const appLonely = lonelySinks.filter((s) => s.inline || (!s.lib && s.unit.startsWith("http")));
  if (appLonely.length > 0) {
    const bySink = new Map<string, number>();
    for (const s of appLonely) bySink.set(s.sink, (bySink.get(s.sink) ?? 0) + 1);
    findings.push({
      key: "domxss-sinks",
      title: `Sinks DOM sensibles présents (${appLonely.length} occurrence(s), ${bySink.size} type(s))`,
      severity: "LOW",
      confidence: "PROBABLE",
      category: "xss",
      location: ctx.finalUrl,
      description:
        "Des constructions JavaScript dangereuses sont présentes dans le code applicatif sans flux attaquant identifiable par analyse statique. Elles constituent une dette XSS : toute future modification (paramètre, API, refacturation) peut créer un flux exploitable.",
      evidence: evidenceBlock([...bySink.entries()].map(([k, v]) => `${k} : ${v} occurrence(s)`), 2000),
      remediation: "Privilégier textContent/createElement, bannir eval/document.write via lint et CSP sans unsafe-eval.",
    });
  }

  // 3. postMessage sans validation d'origine
  const noOrigin = postMessageUnits.filter((p) => !p.hasOriginCheck);
  if (postMessageUnits.length > 0 && noOrigin.length > 0) {
    findings.push({
      key: "domxss-postmessage",
      title: `Écouteur postMessage sans validation d'origine (${noOrigin.length})`,
      severity: "MEDIUM",
      confidence: "PROBABLE",
      category: "auth",
      location: ctx.finalUrl,
      description:
        "Un addEventListener('message') ne vérifie pas event.origin (aucune référence .origin dans le script) : n'importe quel site tiers peut lui envoyer des messages, potentiellement traités comme des données de confiance (injection DOM, actions sensibles, exfiltration).",
      evidence: evidenceBlock(noOrigin.map((p) => `Script : ${p.unit}`), 2000),
      poc: `Depuis n'importe quelle origine : <script>window.open('CIBLE').postMessage(JSON.stringify({"__proto__":{}}),'*')</script> — observer le traitement du message.`,
      remediation: "Toujours vérifier event.origin contre une allowlist stricte, valider le schéma du message, ne jamais innerHTMLer un message.",
    });
  }

  // 4. iframes srcdoc
  if (pageData.srcdocCount > 0) {
    findings.push({
      key: "domxss-srcdoc",
      title: `Iframe(s) srcdoc présentes (${pageData.srcdocCount})`,
      severity: "LOW",
      confidence: "PROBABLE",
      category: "xss",
      location: ctx.finalUrl,
      description:
        "Les iframes srcdoc exécutent du HTML inline dans le contexte de l'origine parente : toute interpolation dynamique dans l'attribut srcdoc est une XSS directe. Sans sandbox, le contenu accède au DOM parent.",
      evidence: evidenceBlock([`${pageData.srcdocCount} iframe(s) avec attribut srcdoc`]),
      remediation: "Ajouter sandbox=\"allow-scripts\" (origine opaque), ou migrer vers une iframe URL + CSP frame-src.",
    });
  }

  // 5. Synthèse eval
  if (evalUnits.length > 0) {
    findings.push({
      key: "domxss-eval",
      title: `Évaluation dynamique de code présente (${evalUnits.length} script(s))`,
      severity: "INFO",
      confidence: "CONFIRMED",
      category: "xss",
      location: ctx.finalUrl,
      description:
        "eval()/new Function() sont présents dans les scripts de la page (code applicatif ou bibliothèque). Leur présence interdit l'usage d'une CSP sans unsafe-eval et élargit la surface d'injection si une donnée contrôlée y transitait.",
      evidence: evidenceBlock(evalUnits.slice(0, 10), 2000),
      remediation: "Remplacer eval par JSON.parse/indexation, activer une CSP sans unsafe-eval, isoler les libs legacy le cas échéant.",
    });
  }

  return {
    findings: capFindings(findings),
    stats: {
      unitsAnalyzed: units.length,
      inlineScripts: pageData.inline.length,
      externalSameOrigin: fetchTargets.length,
      externalTotal: pageData.externals.length,
      flows: flowKeys.length,
      srcdocIframes: pageData.srcdocCount,
    },
  };
}

// ─────────────────────────── JS_LIB_AUDIT ───────────────────────────

interface CveEntry {
  cve: string;
  cvss: number;
  fixedIn: string;
  severity: Severity;
  summary: string;
}

/** Base CVE front embarquée (versions fixes connues — mise à jour à chaque sprint). */
const KNOWN_CVES: Record<string, CveEntry[]> = {
  jQuery: [
    { cve: "CVE-2020-11023", cvss: 6.9, fixedIn: "3.5.0", severity: "MEDIUM", summary: "XSS via manipulation de <option>/fichiers SVG non filtrés" },
    { cve: "CVE-2020-11022", cvss: 6.9, fixedIn: "3.5.0", severity: "MEDIUM", summary: "XSS lors du passage de HTML non fiable à .html()/append()" },
    { cve: "CVE-2019-11358", cvss: 6.1, fixedIn: "3.4.0", severity: "MEDIUM", summary: "Prototype pollution via jQuery.extend(true,…)" },
    { cve: "CVE-2015-9251", cvss: 6.1, fixedIn: "3.0.0", severity: "MEDIUM", summary: "XSS via cross-domain ajax responses (dataType auto)" },
  ],
  "jQuery Migrate": [{ cve: "CVE-2020-11022", cvss: 6.9, fixedIn: "3.4.0", severity: "MEDIUM", summary: "Hérite du XSS .html() de jQuery < 3.5 (dépendance liée)" }],
  "jQuery UI": [
    { cve: "CVE-2022-31160", cvss: 6.1, fixedIn: "1.13.2", severity: "MEDIUM", summary: "XSS via reset/refresh des checkboxradio et button" },
    { cve: "CVE-2021-41184", cvss: 6.1, fixedIn: "1.13.0", severity: "MEDIUM", summary: "XSS via manipulation de <option>" },
    { cve: "CVE-2016-7103", cvss: 5.4, fixedIn: "1.12.0", severity: "MEDIUM", summary: "XSS via dialog/closeText et autres options non échappées" },
  ],
  Bootstrap: [
    { cve: "CVE-2024-6484", cvss: 6.4, fixedIn: "4.7.3", severity: "MEDIUM", summary: "XSS via carousel cross-fading (sanitize non appliqué)" },
    { cve: "CVE-2019-8331", cvss: 6.1, fixedIn: "4.3.1", severity: "MEDIUM", summary: "XSS via template tooltip/popover avec sanitize:false" },
    { cve: "CVE-2018-20677", cvss: 6.1, fixedIn: "3.4.0", severity: "MEDIUM", summary: "XSS via sanitizer bypass dans tooltip" },
  ],
  Lodash: [
    { cve: "CVE-2021-23337", cvss: 7.2, fixedIn: "4.17.21", severity: "HIGH", summary: "Command injection via _.template (option variable)" },
    { cve: "CVE-2020-8203", cvss: 7.4, fixedIn: "4.17.19", severity: "HIGH", summary: "Prototype pollution via _.zipObjectDeep/_.set" },
  ],
  "Moment.js": [
    { cve: "CVE-2022-31129", cvss: 7.5, fixedIn: "2.29.4", severity: "HIGH", summary: "ReDoS via parsing de chemins très longs (toLocaleString)" },
    { cve: "CVE-2022-24785", cvss: 7.5, fixedIn: "2.29.2", severity: "HIGH", summary: "Path traversal via le choix de locale (moment.locale)" },
  ],
  AngularJS: [
    { cve: "CVE-2022-25844", cvss: 7.5, fixedIn: "1.8.3", severity: "HIGH", summary: "ReDoS dans le filtre $locale/currency (input long)" },
    { cve: "CVE-2020-7676", cvss: 7.5, fixedIn: "1.8.0", severity: "HIGH", summary: "XSS bypass du sanitizer via module massivement chargé" },
  ],
};

/** Libs avec fin de vie annoncée (pas de correctif). */
const EOL_LIBS: Record<string, { note: string }> = {
  AngularJS: { note: "AngularJS 1.x est en fin de vie (LTS terminée le 31/12/2021) : plus aucun correctif de sécurité." },
  "jQuery Migrate": { note: "jQuery Migrate est un polyfill de transition : il ne devrait jamais rester en production." },
};

export async function analyzeJsLibs(ctx: AnalyzeCtx): Promise<AnalyzeResult> {
  const findings: BrowserFinding[] = [];

  const globalTechs = await ctx.page.evaluate(globalTechScript).catch(() => [] as TechHit[]);
  const urlTechs = techFromUrls(ctx.requestUrls);
  const merged = new Map<string, TechHit>();
  for (const t of [...urlTechs, ...globalTechs]) {
    const prev = merged.get(t.name);
    if (!prev || (!prev.version && t.version)) merged.set(t.name, t);
  }

  // SRI des scripts tiers (cross-origin sans integrity)
  const sri = await ctx.page
    .evaluate(() => {
      const missing: string[] = [];
      const total: string[] = [];
      for (const s of document.querySelectorAll("script[src]")) {
        const el = s as HTMLScriptElement;
        let crossOrigin = false;
        try {
          crossOrigin = new URL(el.src).origin !== location.origin;
        } catch {
          continue;
        }
        if (!crossOrigin) continue;
        total.push(el.src);
        if (!el.hasAttribute("integrity")) missing.push(el.src);
      }
      return { missing, total };
    })
    .catch(() => ({ missing: [] as string[], total: [] as string[] }));

  // CVE matching par lib versionnée
  const libFindings: BrowserFinding[] = [];
  for (const [lib, tech] of merged) {
    if (!tech.version) continue;
    const entries = KNOWN_CVES[lib] ?? [];
    const vulnerable = entries.filter((e) => cmpVersions(tech.version as string, e.fixedIn) < 0);
    const worst = vulnerable.sort((a, b) => b.cvss - a.cvss)[0];
    if (worst) {
      libFindings.push({
        key: "jslibs-cve",
        title: `${lib} ${tech.version} — ${worst.cve} (${worst.summary})`,
        severity: worst.severity,
        confidence: "CONFIRMED",
        category: "cve",
        cve: worst.cve,
        cvss: worst.cvss,
        location: tech.source === "URL script" ? String(ctx.requestUrls.find((u) => u.toLowerCase().includes(lib.toLowerCase().replace(/\s/g, ""))) ?? ctx.finalUrl) : ctx.finalUrl,
        description:
          `${lib} en version ${tech.version} est exposée publiquement et affectée par au moins ${worst.cve} (CVSS ${worst.cvss}) : ${worst.summary}. ` +
          (vulnerable.length > 1 ? `${vulnerable.length} CVE connues s'appliquent à cette version (fixées à partir de ${vulnerable.sort((a, b) => cmpVersions(b.fixedIn, a.fixedIn))[0].fixedIn}).` : `Le correctif est disponible à partir de ${worst.fixedIn}.`) +
          " La version exacte étant publiquement identifiable, l'exploitation est reproductible par tout attaquant sans compétence particulière.",
        evidence: evidenceBlock([
          `${lib} ${tech.version} détectée via ${tech.source}`,
          ...vulnerable.map((v) => `${v.cve} (CVSS ${v.cvss}) — fix ${v.fixedIn} : ${v.summary}`),
        ]),
        remediation: `Mettre à jour ${lib} vers ≥ ${worst.fixedIn} (dernière stable recommandée), vérifier la compatibilité, et retirer les versions dupliquées chargées par plugins/thèmes.`,
      });
    }
    const eol = EOL_LIBS[lib];
    if (eol && !vulnerable.some((v) => v.severity === "HIGH" || v.severity === "CRITICAL")) {
      libFindings.push({
        key: "jslibs-eol",
        title: `${lib} ${tech.version} — bibliothèque en fin de vie`,
        severity: "MEDIUM",
        confidence: "CONFIRMED",
        category: "sca",
        location: ctx.finalUrl,
        description: `${lib} est présente en production alors que ${eol.note} Aucun correctif futur ne sera publié : chaque faille découverte reste exploitables à vie.`,
        evidence: evidenceBlock([`${lib} ${tech.version} via ${tech.source}`, eol.note]),
        remediation: "Planifier la migration vers la successeur supporté (Angular → Angular moderne/React, jQuery Migrate → code natif).",
      });
    }
  }

  if (sri.missing.length > 0) {
    findings.push({
      key: "jslibs-sri",
      title: `${sri.missing.length} script(s) tiers sans attribut d'intégrité (SRI)`,
      severity: "LOW",
      confidence: "CONFIRMED",
      category: "sca",
      location: ctx.finalUrl,
      description:
        "Des scripts chargés depuis des origines tierces (CDN) n'ont pas d'attribut integrity : si le CDN est compromis (ou un MITM avant HSTS), le code substitué s'exécute avec l'origine de la page. La sous-ressource n'est pas bornée par hash.",
      evidence: evidenceBlock(sri.missing.slice(0, 15)),
      remediation: "Ajouter integrity=\"sha384-…\" + crossorigin=\"anonymous\" à chaque script/lien tiers, ou auto-héberger les dépendances critiques.",
    });
  }

  // Constat de synthèse
  if (merged.size > 0) {
    findings.push({
      key: "jslibs-summary",
      title: `${merged.size} bibliothèque(s) front identifiée(s)`,
      severity: "INFO",
      confidence: "CONFIRMED",
      category: "sca",
      location: ctx.finalUrl,
      description:
        "Inventaire des bibliothèques client chargées par la page (variables globales + URLs de scripts réseau, rendu Chromium réel). Cet inventaire alimente la veille CVE sur la stack front.",
      evidence: evidenceBlock([...merged.values()].map((t) => `${t.name}${t.version ? ` ${t.version}` : " (version indéterminée)"} — ${t.source}`)),
      remediation: "Maintenir un inventaire SCA à jour (bundle analyser) et suivre les advisories des libs front.",
    });
  }

  // Les CVE d'abord (tri sévérité), puis le reste
  const sevRank: Record<Severity, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
  const all = [...libFindings, ...findings].sort((a, b) => sevRank[b.severity] - sevRank[a.severity]);

  return {
    findings: capFindings(all),
    stats: {
      libs: [...merged.values()].map((t) => ({ name: t.name, version: t.version })),
      cveMatched: libFindings.filter((f) => f.cve).length,
      sriMissing: sri.missing.length,
      sriTotal: sri.total.length,
    },
  };
}

// ─────────────────────────── FORM_AUDIT ───────────────────────────

const CSRF_TOKEN_RE = /csrf|xsrf|anticsrf|_token|token|nonce|wpnonce|authenticity/;

interface PageForm {
  action: string;
  method: string;
  hasPassword: boolean;
  passwordAutocomplete: (string | null)[];
  hiddenNames: string[];
  fieldCount: number;
}

export async function analyzeForms(ctx: AnalyzeCtx): Promise<AnalyzeResult> {
  const findings: BrowserFinding[] = [];

  const pageData = await ctx.page
    .evaluate(() => {
      const origin = location.origin;
      const protocol = location.protocol;
      const forms: PageForm[] = [];
      for (const f of document.querySelectorAll("form")) {
        const el = f as HTMLFormElement;
        forms.push({
          action: el.getAttribute("action") || el.action || location.href,
          method: (el.getAttribute("method") || "get").toUpperCase(),
          hasPassword: !!el.querySelector("input[type=password]"),
          passwordAutocomplete: [...el.querySelectorAll("input[type=password]")].map((i) =>
            i.getAttribute("autocomplete")
          ),
          hiddenNames: [...el.querySelectorAll("input[type=hidden]")].map((i) =>
            (i.name || i.id || "").toLowerCase()
          ),
          fieldCount: el.querySelectorAll("input,select,textarea").length,
        });
      }
      const iframes = [...document.querySelectorAll("iframe")].map((f) => {
        const el = f as HTMLIFrameElement;
        let crossOrigin = false;
        try {
          crossOrigin = el.src ? new URL(el.src).origin !== origin : false;
        } catch {
          crossOrigin = false;
        }
        return { src: el.src || null, sandbox: el.getAttribute("sandbox"), srcdoc: !!el.getAttribute("srcdoc"), crossOrigin };
      });
      const passwordInputs = document.querySelectorAll("input[type=password]").length;
      return { forms, iframes, passwordInputs, origin, protocol };
    })
    .catch(() => ({ forms: [] as PageForm[], iframes: [] as Array<{ src: string | null; sandbox: string | null; srcdoc: boolean; crossOrigin: boolean }>, passwordInputs: 0, origin: "", protocol: "https:" }));

  const loginForms = pageData.forms.filter((f) => f.hasPassword);

  for (const [i, form] of pageData.forms.entries()) {
    let abs: URL | null = null;
    try {
      abs = new URL(form.action, ctx.finalUrl);
    } catch {
      continue;
    }

    // 1. Mot de passe sans TLS
    if (form.hasPassword && abs.protocol === "http:") {
      findings.push({
        key: "forms-plaintext-password",
        title: `Mot de passe transmis en clair (formulaire #${i + 1} en HTTP)`,
        severity: "HIGH",
        confidence: "CONFIRMED",
        category: "auth",
        location: abs.toString(),
        description:
          "Un formulaire contenant un champ mot de passe poste vers une URL http:// : les credentials circulent en clair et sont capturables par quiconque écoute le réseau (wifi partagé, proxy d'entreprise, fournisseur d'accès).",
        evidence: evidenceBlock([`Page : ${ctx.finalUrl}`, `Action : ${abs.toString()}`, `Méthode : ${form.method}`, `Champs : ${form.fieldCount}`]),
        poc: "tcpdump/ Wireshark sur le réseau : POST http://… avec le corps du formulaire lisible.",
        remediation: "Basculer l'action du formulaire en https://, rediriger tout http vers https, activer HSTS.",
      });
    }

    // 2. Credentials vers un domaine tiers
    if (form.hasPassword && abs.origin !== pageData.origin && abs.protocol === "https:") {
      findings.push({
        key: "forms-cross-origin-credentials",
        title: `Envoi de credentials vers un domaine tiers (${abs.host})`,
        severity: "HIGH",
        confidence: "PROBABLE",
        category: "auth",
        location: abs.toString(),
        description:
          "Un formulaire avec mot de passe est posté vers un domaine différent de la page courante. Si ce domaine n'est pas un fournisseur d'identité documenté (SSO), c'est le schéma type du credential harvesting (phishing intégré, tracker malveillant, compromission du site).",
        evidence: evidenceBlock([`Origine page : ${pageData.origin}`, `Action : ${abs.toString()}`, `Méthode : ${form.method}`]),
        remediation: "Vérifier la légitimité du domaine cible (SSO documenté ?) ; sinon restreindre l'action au même origin et auditer le code injecté (plugins, tiers).",
      });
    }

    // 3. Mot de passe en GET
    if (form.hasPassword && form.method === "GET") {
      findings.push({
        key: "forms-password-get",
        title: `Mot de passe via méthode GET (formulaire #${i + 1})`,
        severity: "MEDIUM",
        confidence: "CONFIRMED",
        category: "auth",
        location: abs.toString(),
        description:
          "Le mot de passe transiterait dans l'URL (méthode GET) : il finit dans les logs serveur, les historiques navigateur, les proxies et les en-têtes Referer des pages suivantes.",
        evidence: evidenceBlock([`Action : ${abs.toString()}`, `Méthode : GET`]),
        remediation: "Passer le formulaire en POST (method=\"post\") et vérifier qu'aucun paramètre password ne transite dans les URLs.",
      });
    }

    // 4. autocomplete non restreint
    if (form.hasPassword) {
      const ac = form.passwordAutocomplete;
      const unrestricted = ac.some((a) => a === null || a === "on");
      if (unrestricted) {
        findings.push({
          key: "forms-password-autocomplete",
          title: `Autocomplete du mot de passe non restreint (formulaire #${i + 1})`,
          severity: "LOW",
          confidence: "CONFIRMED",
          category: "auth",
          location: abs.toString(),
          description:
            "Le champ mot de passe n'impose pas autocomplete=\"new-password\"/\"off\" (ou current-password) : le navigateur peut stocker le secret sur des postes partagés et le rejouer sur des pages trompeuses.",
          evidence: evidenceBlock([`autocomplete: ${JSON.stringify(ac)}`]),
          remediation: "Définir explicitement autocomplete (new-password pour l'inscription/reset, current-password pour le login) et un identifiant id/name stable.",
        });
      }
    }

    // 5. Aucun jeton anti-CSRF visible (heuristique)
    if (form.method === "POST" && !form.hiddenNames.some((n) => CSRF_TOKEN_RE.test(n))) {
      findings.push({
        key: "forms-no-csrf",
        title: `Aucun jeton anti-CSRF visible (formulaire POST #${i + 1})`,
        severity: "LOW",
        confidence: "PROBABLE",
        category: "auth",
        location: abs.toString(),
        description:
          "Heuristique : aucun champ caché de type CSRF/token/nonce n'est présent dans ce formulaire POST. Le jeton peut être porté par un en-tête (framework JS) — mais si le formulaire est un formulaire classique, une protection CSRF manque (action forcée par un site tiers avec les cookies de la victime).",
        evidence: evidenceBlock([`Champs cachés : ${JSON.stringify(form.hiddenNames)}`, `Action : ${abs.toString()}`]),
        remediation: "Injecter un jeton anti-CSRF synchronisé (ou SameSite=Lax/Strict + vérification Origin) sur toutes les actions modifiantes.",
      });
    }
  }

  // 6. Iframes tierces sans sandbox
  const unsafeIframes = pageData.iframes.filter((f) => f.crossOrigin && !f.sandbox && !f.srcdoc);
  if (unsafeIframes.length > 0) {
    findings.push({
      key: "forms-iframe-unsandboxed",
      title: `${unsafeIframes.length} iframe(s) tierce(s) sans attribut sandbox`,
      severity: "LOW",
      confidence: "CONFIRMED",
      category: "misconfig",
      location: ctx.finalUrl,
      description:
        "Des iframes cross-origin sont embarquées sans sandbox : le contenu tiers dispose de toutes les capacités normales du navigateur (scripts, popups, formulaires). Un contenu tiers compromis peut piéger des clics (clickjacking) ou exécuter du code non borné.",
      evidence: evidenceBlock(unsafeIframes.map((f) => f.src ?? "(sans src)").slice(0, 15)),
      remediation: "Ajouter sandbox=\"allow-scripts allow-same-origin\" au minimum nécessaire, charger en lazy, et documenter chaque intégration tierce.",
    });
  }

  // 7. Surface d'authentification (synthèse)
  if (pageData.passwordInputs > 0) {
    findings.push({
      key: "forms-login-surface",
      title: `Surface d'authentification exposée (${pageData.passwordInputs} champ(s) mot de passe)`,
      severity: "INFO",
      confidence: "CONFIRMED",
      category: "auth",
      location: ctx.finalUrl,
      description:
        "La page expose des champs mot de passe : cible naturelle du brute-force, du credential stuffing et du phishing. Vérifier la présence d'un rate-limiting, d'une MFA et de messages d'erreur non discriminants.",
      evidence: evidenceBlock(pageData.forms.map((f, i) => `form#${i + 1} ${f.method} ${f.action} password=${f.hasPassword} champs=${f.fieldCount}`)),
      remediation: "Rate limiting par compte ET par IP, MFA, CAPTCHA progressif, verrouillage temporaire et journalisation des tentatives.",
    });
  }

  return {
    findings: capFindings(findings),
    stats: {
      forms: pageData.forms.length,
      loginForms: loginForms.length,
      iframes: pageData.iframes.length,
      crossOriginIframes: pageData.iframes.filter((f) => f.crossOrigin).length,
    },
  };
}
