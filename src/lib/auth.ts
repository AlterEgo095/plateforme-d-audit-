/**
 * AuditForge — Authentification (mots de passe scrypt + sessions HMAC signées)
 *
 * Contrats worklog §D :
 * - cookie httpOnly `af_session`, token `v1.<payload base64url>.<hmac-sha256>`
 * - payload { sub, username, role, exp }, secret = AUTH_SECRET (fallback dev)
 * - durée de session : 8 h, sameSite=lax, path=/
 * - RBAC : VIEWER (lecture) < AUDITOR < ADMIN
 */
import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto'
import { cookies, headers } from 'next/headers'
import { NextResponse } from 'next/server'
import type { Role } from '@/lib/types'

export const SESSION_COOKIE = 'af_session'
const SESSION_TTL_SECONDS = 8 * 60 * 60 // 8 heures
const SECRET = process.env.AUTH_SECRET ?? 'auditforge-dev-secret-change-me'

// Sécurité (contrat worklog §K.6) : refuser de démarrer en production sans secret
// de signature dédié — le fallback est toléré uniquement en développement.
if (process.env.NODE_ENV === 'production' && !process.env.AUTH_SECRET) {
  throw new Error('AUTH_SECRET requis en production')
}

const VALID_ROLES: Role[] = ['ADMIN', 'AUDITOR', 'VIEWER']

/** Session décodée (= payload du token). */
export interface Session {
  sub: string
  username: string
  role: Role
  /** Expiration en secondes (epoch). */
  exp: number
}

// ─── Mots de passe (scrypt, stockage `salt:hash` en hex) ─────────────

/** Hache un mot de passe : sel aléatoire 16 octets + scrypt 64 octets → `salt:hash` hex. */
export function hashPassword(pw: string): string {
  const salt = randomBytes(16).toString('hex')
  const hash = scryptSync(pw, salt, 64).toString('hex')
  return `${salt}:${hash}`
}

/** Vérifie un mot de passe contre un stockage `salt:hash` (comparaison à temps constant). */
export function verifyPassword(pw: string, stored: string): boolean {
  const [salt, hash] = stored.split(':')
  if (!salt || !hash) return false
  const candidate = scryptSync(pw, salt, 64)
  const expected = Buffer.from(hash, 'hex')
  if (candidate.length !== expected.length) return false
  return timingSafeEqual(candidate, expected)
}

// ─── Sessions (token `v1.<payload>.<signature>`) ─────────────────────

function signPayload(payload: Session): string {
  const body = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url')
  const sig = createHmac('sha256', SECRET).update(body).digest('base64url')
  return `v1.${body}.${sig}`
}

/** Construit une session fraîche (exp = maintenant + 8 h). */
export function newSession(user: { id: string; username: string; role: string }): Session {
  return {
    sub: user.id,
    username: user.username,
    role: (VALID_ROLES.includes(user.role as Role) ? user.role : 'VIEWER') as Role,
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
  }
}

/** Signe une session fraîche pour l'utilisateur et retourne le token complet. */
export function signSession(user: { id: string; username: string; role: string }): string {
  return signPayload(newSession(user))
}

/** Vérifie la signature ET l'expiration ; retourne la session ou null. */
export function parseSession(token: string | undefined | null): Session | null {
  if (!token) return null
  const parts = token.split('.')
  if (parts.length !== 3 || parts[0] !== 'v1') return null
  const [, body, sig] = parts
  const expected = createHmac('sha256', SECRET).update(body).digest('base64url')
  const a = Buffer.from(sig)
  const b = Buffer.from(expected)
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as Partial<Session>
    if (!payload || typeof payload.sub !== 'string' || typeof payload.username !== 'string') return null
    if (!payload.role || !VALID_ROLES.includes(payload.role)) return null
    if (typeof payload.exp !== 'number' || payload.exp * 1000 <= Date.now()) return null
    return { sub: payload.sub, username: payload.username, role: payload.role, exp: payload.exp }
  } catch {
    // payload corrompu ou non décodable → session invalide
    return null
  }
}

// ─── Accès au cookie de session (Next 16 : cookies() est asynchrone) ─

/** Lit la session depuis le cookie de la requête courante. */
export async function getSession(): Promise<Session | null> {
  const store = await cookies()
  return parseSession(store.get(SESSION_COOKIE)?.value)
}

/**
 * M1 (audit 8-a) : décide si le cookie doit être `Secure` en se fiant au
 * protocole réellement vu par le client (X-Forwarded-Proto, posé par Caddy ou
 * tout reverse proxy) plutôt qu'à NODE_ENV — sinon un déploiement HTTP
 * (SITE_DOMAIN absent, chemin documenté du README) casse le login : les
 * navigateurs rejettent un cookie Secure sur du HTTP non-localhost.
 * Override explicite possible via COOKIE_SECURE=1|0.
 */
async function sessionCookieSecure(): Promise<boolean> {
  const override = process.env.COOKIE_SECURE
  if (override === '1') return true
  if (override === '0') return false
  const h = await headers()
  const proto = h.get('x-forwarded-proto')?.split(',')[0]?.trim()
  return proto === 'https'
}

/** Pose le cookie de session (httpOnly, lax, path=/, 8 h, Secure si HTTPS détecté). Valide uniquement dans un route handler. */
export async function setSessionCookie(session: Session): Promise<void> {
  const store = await cookies()
  store.set({
    name: SESSION_COOKIE,
    value: signPayload(session),
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    maxAge: SESSION_TTL_SECONDS,
    secure: await sessionCookieSecure(),
  })
}

/** Supprime le cookie de session. */
export async function clearSessionCookie(): Promise<void> {
  const store = await cookies()
  store.delete(SESSION_COOKIE)
}

/**
 * Garde d'authentification : retourne la session, ou une NextResponse 401/403 prête à être renvoyée.
 * Usage :
 *   const s = await requireAuth(['ADMIN']);
 *   if (s instanceof NextResponse) return s;
 */
export async function requireAuth(roles?: Role[]): Promise<Session | NextResponse> {
  const session = await getSession()
  if (!session) {
    return NextResponse.json({ error: 'Authentification requise' }, { status: 401 })
  }
  if (roles && roles.length > 0 && !roles.includes(session.role)) {
    return NextResponse.json({ error: 'Permissions insuffisantes' }, { status: 403 })
  }
  return session
}
