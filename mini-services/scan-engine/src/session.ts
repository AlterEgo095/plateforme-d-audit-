/**
 * AuditForge — Vérification de session côté moteur (réimplémentation sans Next).
 *
 * Contrats worklog §K.2 / §K.6 : même algorithme que src/lib/auth.ts
 * (parseSession) — token `v1.<payload base64url>.<hmac-sha256 base64url>`,
 * payload { sub, username, role, exp }, secret = AUTH_SECRET (fallback dev),
 * comparaison de signature en temps constant (timingSafeEqual).
 *
 * AUCUNE dépendance au projet racine ni à Next : copie locale volontaire.
 */

import { createHmac, timingSafeEqual } from "node:crypto";

const SECRET = process.env.AUTH_SECRET ?? "auditforge-dev-secret-change-me";

const VALID_ROLES = ["ADMIN", "AUDITOR", "VIEWER"] as const;
type ValidRole = (typeof VALID_ROLES)[number];

/** Session décodée (= payload du token). Même forme que src/lib/auth.ts. */
export interface EngineSession {
  sub: string;
  username: string;
  role: ValidRole;
  /** Expiration en secondes (epoch). */
  exp: number;
}

// K.6 : warning au boot si le secret de développement (fallback) est utilisé.
if (!process.env.AUTH_SECRET) {
  console.warn(
    "[scan-engine] AUTH_SECRET manquant — secret de développement appliqué " +
      "('auditforge-dev-secret-change-me'). À configurer impérativement en production.",
  );
}

/** Vérifie la signature ET l'expiration ; retourne la session ou null. */
export function parseSession(token: string | null | undefined): EngineSession | null {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== "v1") return null;
  const [, body, sig] = parts;
  if (!body || !sig) return null;
  const expected = createHmac("sha256", SECRET).update(body).digest("base64url");
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as Partial<EngineSession>;
    if (!payload || typeof payload.sub !== "string" || typeof payload.username !== "string") return null;
    if (!payload.role || !VALID_ROLES.includes(payload.role as ValidRole)) return null;
    if (typeof payload.exp !== "number" || payload.exp * 1000 <= Date.now()) return null;
    return { sub: payload.sub, username: payload.username, role: payload.role as ValidRole, exp: payload.exp };
  } catch {
    // payload corrompu ou non décodable → session invalide
    return null;
  }
}

/** Prédicat de session valide (usage : middleware socket.io). */
export function verifySessionToken(token: string | null | undefined): boolean {
  return parseSession(token) !== null;
}
