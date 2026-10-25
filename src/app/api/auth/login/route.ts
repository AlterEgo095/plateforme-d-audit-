/**
 * POST /api/auth/login — connexion (contrat worklog §F.1, §D ; remédiations §K.5, §L.14)
 * {username, password, totp?} → {user:UserDTO} | 428 {mfaRequired:true} | 401 | 429
 *
 * Remédiations :
 * - rate limiting mémoire : 5 échecs / 10 min par `ip:username` (§K.5) ;
 * - timing attack : si l'utilisateur est inconnu, le mot de passe est tout de même
 *   confronté à un hash scrypt factice avant le 401 (coût équivalent) ;
 * - TOTP comparé en timingSafeEqual (buffers utf8, code démo 123456 conservé).
 */
import { NextRequest, NextResponse } from 'next/server'
import { timingSafeEqual } from 'node:crypto'
import { z } from 'zod'
import { db } from '@/lib/db'
import { newSession, setSessionCookie, verifyPassword } from '@/lib/auth'
import { writeAudit } from '@/lib/audit'
import { ensureSeed } from '@/lib/seed'
import { toUserDTO } from '@/lib/dto'
import { isLoginBlocked, registerLoginFailure, resetLoginFailures } from '@/lib/rate-limit'
import { withApi } from '@/lib/route-handler'

export const dynamic = 'force-dynamic'

const bodySchema = z.object({
  username: z.string().min(1).max(100),
  password: z.string().min(1).max(200),
  totp: z.string().min(1).max(10).optional(),
})

/** Code TOTP de démonstration (compte admin, worklog §C). */
const DEMO_TOTP = '123456'

/**
 * Hash scrypt factice (`salt:hash` hex) d'un mot de passe aléatoire détruit :
 * consommé quand l'utilisateur est inconnu pour égaliser le temps de réponse.
 * Généré une seule fois (scrypt 64 octets) — personne ne peut le deviner.
 */
const DUMMY_HASH =
  'ecdfb49d990c01b237cf9b839a7f0c28:11dc5cc2dbd7055ab9b0ed20a6e988a2bad08e9a430522046597bf95da10eeeb370c42b80609fef267ca204ab7024f23a881e74421c750bed7edef4234af528c'

/** Consume le coût scrypt du hash factice (résultat ignoré, ne lève jamais). */
function burnDummyVerify(password: string): void {
  try {
    verifyPassword(password, DUMMY_HASH)
  } catch {
    // ignoré : seul le coût de calcul compte
  }
}

/** Comparaison de chaînes à temps constant (buffers utf8). */
function timingSafeStringEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8')
  const bufB = Buffer.from(b, 'utf8')
  if (bufA.length !== bufB.length) {
    // Longueurs différentes : comparaison à vide pour homogénéiser le temps, résultat faux.
    timingSafeEqual(bufB, bufB)
    return false
  }
  return timingSafeEqual(bufA, bufB)
}

export const POST = withApi(async (req: NextRequest) => {
  // Le seed s'assure que les comptes de démo existent au premier démarrage.
  await ensureSeed()

  const raw = await req.json().catch(() => null)
  const parsed = bodySchema.safeParse(raw)
  if (!parsed.success) {
    return NextResponse.json({ error: 'Requête invalide — identifiant et mot de passe requis' }, { status: 400 })
  }

  const username = parsed.data.username.trim().toLowerCase()
  const ip = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ?? 'local'
  const rateKey = `${ip}:${username}`

  // Rate limiting (§K.5) : 5 échecs / 10 min par ip+username.
  const { blocked, retryAfterSec } = isLoginBlocked(rateKey)
  if (blocked) {
    return NextResponse.json(
      { error: `Trop de tentatives. Réessayez dans ${Math.ceil(retryAfterSec / 60)} minute(s).` },
      { status: 429 }
    )
  }

  const user = await db.user.findUnique({ where: { username } })
  if (!user) {
    // Utilisateur inconnu : même coût de calcul qu'un utilisateur existant (anti timing attack),
    // puis échec enregistré pour le rate limiting.
    burnDummyVerify(parsed.data.password)
    registerLoginFailure(rateKey)
    return NextResponse.json({ error: 'Identifiants invalides' }, { status: 401 })
  }
  if (!verifyPassword(parsed.data.password, user.passwordHash)) {
    registerLoginFailure(rateKey)
    return NextResponse.json({ error: 'Identifiants invalides' }, { status: 401 })
  }

  // MFA de démonstration : code TOTP attendu si activé sur le compte.
  if (user.mfaEnabled && !parsed.data.totp) {
    return NextResponse.json({ mfaRequired: true }, { status: 428 })
  }
  if (user.mfaEnabled && parsed.data.totp && !timingSafeStringEqual(parsed.data.totp, DEMO_TOTP)) {
    registerLoginFailure(rateKey)
    return NextResponse.json({ error: 'Code TOTP invalide' }, { status: 401 })
  }

  resetLoginFailures(rateKey)
  await setSessionCookie(newSession(user))
  await writeAudit(user.username, 'LOGIN', 'session')
  return NextResponse.json({ user: toUserDTO(user) })
})
