/**
 * AuditForge — Sprint 3 : CLI des outils navigateur headless.
 *
 * Usage :
 *   af-browser-tools <recon|domxss|jslibs|forms> <url> --report <chemin.json> [--timeout <secondes>]
 *
 * Contrat moteur (framework arsenal) :
 *   - la sortie stdout est diffusée en logs TOOL du scan (lignes phases) ;
 *   - le rapport JSON est TOUJOURS écrit (même en cas d'erreur partielle) ;
 *   - exit 0 = analyse terminée (0..N constats), exit ≠ 0 = échec fatale
 *     (cible injoignable, Chromium absent, timeout global).
 *
 * Le moteur appelle ce binaire via les 4 ArsenalSpec (BROWSER_RECON,
 * DOM_SINK_SCAN, JS_LIB_AUDIT, FORM_AUDIT) — voir scan-engine/real-exec/arsenal.ts.
 */

import { chromium } from "playwright-core";
import { writeFileSync } from "node:fs";
import { CHROMIUM_LAUNCH_ARGS, resolveChromiumPath } from "./resolve";
import {
  analyzeDomXss,
  analyzeForms,
  analyzeJsLibs,
  analyzeRecon,
  type AnalyzeCtx,
  type BrowserFinding,
  type BrowserToolReport,
} from "./analyze";

const TOOL_BY_COMMAND: Record<string, string> = {
  recon: "BROWSER_RECON",
  domxss: "DOM_SINK_SCAN",
  jslibs: "JS_LIB_AUDIT",
  forms: "FORM_AUDIT",
};

/** Version du CLI — sonde de disponibilité du moteur (probeBinary --version). */
const CLI_VERSION = "1.0.0";

function log(msg: string): void {
  console.log(`[af-browser-tools] ${msg}`);
}

function fail(msg: string, code: number): never {
  console.error(`[af-browser-tools] ERREUR — ${msg}`);
  process.exit(code);
}

function parseArgs(argv: string[]): { command: string; target: string; report: string; timeoutS: number } {
  const positional: string[] = [];
  let report = "";
  let timeoutS = 60;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--report") {
      report = argv[++i] ?? "";
    } else if (a === "--timeout") {
      timeoutS = Math.max(10, Math.min(600, parseInt(argv[++i] ?? "60", 10) || 60));
    } else {
      positional.push(a);
    }
  }
  const [command, target] = positional;
  if (!command || !TOOL_BY_COMMAND[command]) {
    fail(`sous-commande inconnue « ${command ?? "(vide)"} » — attendu : ${Object.keys(TOOL_BY_COMMAND).join(" | ")}`, 2);
  }
  if (!target || !/^https?:\/\//i.test(target)) {
    fail(`cible invalide « ${target ?? "(vide)"} » — URL http(s) attendue`, 2);
  }
  if (!report) fail("option --report <chemin.json> requise", 2);
  return { command, target, report, timeoutS };
}

/** Garde-fou global : tue le processus si l'analyse dépasse le budget. */
function armKillTimer(seconds: number): void {
  setTimeout(() => {
    console.error(`[af-browser-tools] ERREUR — timeout global ${seconds}s dépassé`);
    process.exit(2);
  }, seconds * 1000).unref();
}

async function main(): Promise<void> {
  // Sonde de version (contrat moteur : `bin --version` doit sortir 0).
  if (process.argv.includes("--version") || process.argv.includes("-V")) {
    const exe = resolveChromiumPath();
    console.log(`af-browser-tools ${CLI_VERSION} (chromium: ${exe ?? "ABSENT"})`);
    process.exit(exe ? 0 : 3);
  }
  const { command, target, report, timeoutS } = parseArgs(process.argv.slice(2));
  const tool = TOOL_BY_COMMAND[command];
  armKillTimer(timeoutS + 30);

  const exe = resolveChromiumPath();
  if (!exe) {
    fail("Chromium headless introuvable — installer le Chromium Playwright (~/.cache/ms-playwright) ou définir AF_CHROMIUM_BIN", 3);
  }
  log(`Chromium : ${exe}`);

  const startedAt = Date.now();
  const requestUrls: string[] = [];
  let httpStatus: number | null = null;
  let finalUrl = target;
  let responseHeaders: Record<string, string> = {};

  const browser = await chromium.launch({ executablePath: exe, args: [...CHROMIUM_LAUNCH_ARGS] });
  try {
    const context = await browser.newContext({
      viewport: { width: 1366, height: 900 },
      userAgent:
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
      ignoreHTTPSErrors: true,
    });
    const page = await context.newPage();
    page.on("request", (req) => {
      if (requestUrls.length < 400) requestUrls.push(req.url());
    });
    page.on("dialog", (d) => {
      void d.dismiss().catch(() => undefined);
    });

    log(`Navigation vers ${target} (budget ${timeoutS}s)`);
    const navStarted = Date.now();
    const response = await page.goto(target, { waitUntil: "domcontentloaded", timeout: Math.min(timeoutS * 1000, 30_000) });
    try {
      await page.waitForLoadState("networkidle", { timeout: 8_000 });
    } catch {
      // networkidle non atteignable (flux longs, beacons) — on poursuit
    }
    const loadMs = Date.now() - navStarted;
    httpStatus = response?.status() ?? null;
    finalUrl = page.url();
    responseHeaders = response?.headers() ?? {};
    log(`Rendu effectué — HTTP ${httpStatus ?? "?"} en ${loadMs} ms, URL finale ${finalUrl}`);

    const ctx: AnalyzeCtx = { page, target, finalUrl, httpStatus, loadMs, requestUrls, responseHeaders };
    log(`Analyse ${tool} en cours…`);

    let findings: BrowserFinding[] = [];
    let stats: Record<string, unknown> = {};
    let error: string | undefined;
    try {
      const result =
        command === "recon"
          ? await analyzeRecon(ctx)
          : command === "domxss"
            ? await analyzeDomXss(ctx)
            : command === "jslibs"
              ? await analyzeJsLibs(ctx)
              : await analyzeForms(ctx);
      findings = result.findings;
      stats = result.stats;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
      log(`⚠️ analyse partielle : ${error}`);
    }

    const rep: BrowserToolReport = {
      tool,
      ok: !error,
      target,
      finalUrl,
      httpStatus,
      loadMs,
      requestCount: requestUrls.length,
      error,
      stats,
      findings,
    };
    writeFileSync(report, JSON.stringify(rep, null, 2));
    log(`Rapport écrit (${findings.length} constat(s)) → ${report}`);
    log(`Terminé en ${((Date.now() - startedAt) / 1000).toFixed(1)}s`);
    await browser.close();
    process.exit(0);
  } catch (e) {
    // Erreur fatale (navigation refusée, TLS/ DNS, crash) — le rapport est
    // quand même écrit pour le débogage, puis échec explicite (exit ≠ 0).
    const msg = e instanceof Error ? e.message : String(e);
    const rep: BrowserToolReport = {
      tool,
      ok: false,
      target,
      finalUrl,
      httpStatus,
      loadMs: Date.now() - startedAt,
      requestCount: requestUrls.length,
      error: msg,
      stats: {},
      findings: [],
    };
    try {
      writeFileSync(report, JSON.stringify(rep, null, 2));
    } catch {
      // rapport non écrivable — on laisse l'exit code parler
    }
    await browser.close().catch(() => undefined);
    fail(`échec de navigation/analyse : ${msg}`, 1);
  }
}

void main();
