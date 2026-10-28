export {};

/**
 * AuditForge — smoke test E2E (garde-fou anti-récidive RF1, audit v2).
 *
 * Chemin vérifié de bout en bout : login → création d'une campagne
 * séquentielle (2 outils par défaut) → attente terminale → assertions :
 *   - création/lancement sans erreur (une dérive de schéma Prisma entre
 *     l'app et le moteur produisait un 500 sur /internal/run — RF1) ;
 *   - campagne finale COMPLETED, chaque scan COMPLETED ;
 *   - JAMAIS 2 scans RUNNING simultanés (chaîne séquentielle respectée) ;
 *   - export DefectDojo joignable (option, SMOKE_DOJO=1 — défaut).
 *
 * Usage : ./scripts/smoke-test.sh   (ou : bun scripts/smoke-test.ts)
 * Environnement :
 *   SMOKE_BASE_URL  (défaut http://127.0.0.1:3000)
 *   SMOKE_USER      (défaut auditeur)  SMOKE_PASS (défaut Audit123!)
 *   SMOKE_TOOLS     (défaut SUBFINDER,HTTPX — 2 outils, chaîne séquentielle)
 *   SMOKE_PROFILE   (défaut QUICK)     SMOKE_TARGET (défaut https://smoke.invalid)
 *   SMOKE_TIMEOUT_S (défaut 300)       SMOKE_DOJO (défaut 1)
 */

const BASE_URL = (process.env.SMOKE_BASE_URL ?? "http://127.0.0.1:3000").replace(/\/+$/, "");
const USER = process.env.SMOKE_USER ?? "auditeur";
const PASS = process.env.SMOKE_PASS ?? "Audit123!";
const TOOLS = (process.env.SMOKE_TOOLS ?? "SUBFINDER,HTTPX")
  .split(",")
  .map((t) => t.trim().toUpperCase())
  .filter(Boolean);
const PROFILE = process.env.SMOKE_PROFILE ?? "QUICK";
const TARGET = process.env.SMOKE_TARGET ?? "https://smoke.invalid";
const TIMEOUT_S = Number(process.env.SMOKE_TIMEOUT_S ?? "300") || 300;
const CHECK_DOJO = (process.env.SMOKE_DOJO ?? "1") !== "0";

let cookie = "";

async function api(method: string, path: string, body?: unknown) {
  const res = await fetch(BASE_URL + path, {
    method,
    headers: { "content-type": "application/json", ...(cookie ? { cookie } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(30_000),
  });
  const setCookie = res.headers.get("set-cookie");
  if (setCookie && setCookie.includes("af_session=")) cookie = setCookie.split(";")[0]!;
  const text = await res.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = { _raw: text.slice(0, 300) };
  }
  return { status: res.status, json } as { status: number; json: any };
}

function fail(message: string): never {
  console.error(`❌ SMOKE TEST ÉCHOUÉ : ${message}`);
  process.exit(1);
}

// ── 1. Login ─────────────────────────────────────────────────────────
const login = await api("POST", "/api/auth/login", { username: USER, password: PASS });
if (login.status !== 200) fail(`login HTTP ${login.status} (${JSON.stringify(login.json).slice(0, 200)})`);
console.log(`✅ login ${USER} (cookie de session reçu)`);

// ── 2. Campagne séquentielle — lancement immédiat ────────────────────
const create = await api("POST", "/api/campaigns", {
  name: `smoke-test-${new Date().toISOString().slice(0, 19)}`,
  description: "Garde-fou E2E automatique (scripts/smoke-test) — supprimable",
  target: TARGET,
  targetType: "URL",
  profile: PROFILE,
  tools: TOOLS,
  sequential: true,
  launchNow: true,
});
if (create.status !== 201) {
  fail(`création de campagne HTTP ${create.status} — un 500/409 ici signale un moteur indisponible ou une dérive de schéma (RF1) : ${JSON.stringify(create.json).slice(0, 300)}`);
}
const campaign = create.json.campaign;
console.log(`✅ campagne ${campaign.id} créée (séquentielle=${campaign.sequential}, outils ${TOOLS.join(" → ")})`);

// ── 3. Polling — jamais 2 RUNNING simultanés ─────────────────────────
const deadline = Date.now() + TIMEOUT_S * 1000;
let overlaps = 0;
let sawRunning = false;
let last: any = null;
while (Date.now() < deadline) {
  await new Promise((r) => setTimeout(r, 2000));
  const poll = await api("GET", `/api/campaigns/${campaign.id}`);
  if (poll.status !== 200) fail(`polling HTTP ${poll.status}`);
  last = poll.json;
  const c = last.campaign;
  const running = c.scans.filter((s: any) => s.status === "RUNNING").length;
  const terminal = c.scans.filter((s: any) => ["COMPLETED", "FAILED", "CANCELLED"].includes(s.status)).length;
  if (running > 0) sawRunning = true;
  if (running > 1) overlaps++;
  console.log(
    `   ${c.status} — running=${running} terminal=${terminal}/${c.scans.length} | ` +
      c.scans.map((s: any) => `${s.tool}:${s.status}`).join(" "),
  );
  if (terminal === c.scans.length && running === 0) break;
}
if (!last) fail("aucun polling réussi");
if (Date.now() >= deadline && last.campaign.status !== "COMPLETED") {
  fail(`campagne non terminée après ${TIMEOUT_S}s (statut ${last.campaign.status})`);
}
if (overlaps > 0) fail(`chaîne séquentielle rompue : ${overlaps} poll(s) avec >1 scan RUNNING simultané`);
if (last.campaign.status !== "COMPLETED") fail(`campagne finale ${last.campaign.status} (attendu COMPLETED)`);
for (const s of last.campaign.scans as any[]) {
  if (s.status !== "COMPLETED") fail(`scan ${s.tool} final ${s.status} (attendu COMPLETED)`);
}
console.log(`✅ campagne COMPLETED — ${last.campaign.scans.length} scan(s) en chaîne, 0 chevauchement${sawRunning ? ", exécution observée" : ""}`);

// ── 4. Export DefectDojo ─────────────────────────────────────────────
if (CHECK_DOJO) {
  const dojo = await api("GET", `/api/reports/dojo?campaignId=${campaign.id}`);
  if (dojo.status !== 200) fail(`export Dojo HTTP ${dojo.status} : ${JSON.stringify(dojo.json).slice(0, 200)}`);
  const expected = (last.campaign.scans as any[]).reduce((a, s) => a + (s.findingsCount ?? 0), 0);
  if (dojo.json.findings?.length !== expected) {
    fail(`export Dojo : ${dojo.json.findings?.length} constat(s) ≠ ${expected} en base`);
  }
  console.log(`✅ export DefectDojo — ${dojo.json.findings.length} constat(s) cohérent(s) avec la base`);
}

console.log("\n🎉 SMOKE TEST : PASS");
