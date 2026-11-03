/**
 * AuditForge — Sprint 3 : résolution du binaire Chromium headless.
 *
 * Stratégie (sans variable d'environnement imposée — l'env du moteur est
 * allowlistée) :
 *   1. AF_CHROMIUM_BIN (surcharge explicite du wrapper) ;
 *   2. cache Playwright ~/.cache/ms-playwright/chromium-XXXX/chrome-linuxXXXX/chrome
 *      (version la plus haute) ;
 *   3. binaires système (chromium, chromium-browser, google-chrome…) via PATH.
 */

import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

export const CHROMIUM_LAUNCH_ARGS = [
  "--no-sandbox",
  "--disable-dev-shm-usage",
  "--disable-gpu",
  "--no-first-run",
  "--no-zygote",
  "--disable-blink-features=AutomationControlled",
] as const;

/** Candidats système (noms usuels sur Debian/Ubuntu/Alpine). */
const SYSTEM_CANDIDATES = [
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/usr/local/bin/chromium",
  "/snap/bin/chromium",
];

function playwrightCacheCandidates(): string[] {
  const root = join(homedir(), ".cache", "ms-playwright");
  if (!existsSync(root)) return [];
  let dirs: string[] = [];
  try {
    dirs = readdirSync(root).filter((d) => d.startsWith("chromium-"));
  } catch {
    return [];
  }
  // Tri par version décroissante (chromium-1200 > chromium-1187).
  dirs.sort((a, b) => Number(b.split("-")[1] ?? 0) - Number(a.split("-")[1] ?? 0));
  const out: string[] = [];
  for (const dir of dirs) {
    for (const sub of ["chrome-linux64", "chrome-linux"]) {
      out.push(join(root, dir, sub, "chrome"));
    }
  }
  return out;
}

/** Retourne le chemin Chromium (existant) ou null. */
export function resolveChromiumPath(): string | null {
  const explicit = (process.env.AF_CHROMIUM_BIN ?? "").trim();
  if (explicit) return existsSync(explicit) ? explicit : null;
  for (const candidate of [...playwrightCacheCandidates(), ...SYSTEM_CANDIDATES]) {
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

/**
 * Sonde de disponibilité réutilisable côté moteur (checkExtra des specs
 * arsenal) : décrit ce que l'opérateur doit installer si absent.
 */
export function describeChromiumAvailability(): { available: boolean; path?: string; reason?: string } {
  const p = resolveChromiumPath();
  if (p) return { available: true, path: p };
  return {
    available: false,
    reason:
      "Chromium headless introuvable — installer Playwright Chromium (~/.cache/ms-playwright) ou le paquet système (chromium), ou définir AF_CHROMIUM_BIN",
  };
}
