/**
 * POST /api/auth/login — connexion (contrat worklog §F.1, §D ; remédiations §K.5, §L.14)
 * {username, password, totp?} → {user:UserDTO} | 401 | 403 | 429
 *
 * Remédiations :
 * - rate limiting mémoire : 5 échecs / 10 min par `ip:username` (§K.5) ;
 * - timing attack : si l'utilisateur est inconnu, le mot de passe est tout de même
 *   confronté à un hash scrypt factice avant le 401 (coût équivalent) ;
 * - F-06 : IP cliente réelle — cf-connecting-ip (Cloudflare) sinon DERNIER élément
 *   de x-forwarded-for (posé par notre proxy) sinon 'local' (src/lib/client-ip.ts) ;
 * - F-05 : plus de code TOTP de démonstration. Le champ `totp` fourni est accepté
 *   puis ignoré ; un compte mfaEnabled sans secret enrôlé est refusé (403).
 */
import { NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import { db } from '@/lib/db'
import { newSession, setSessionCookie, verifyPassword } from '@/lib/auth'
import { writeAudit } from '@/lib/audit'
import { ensureSeed } from '@/lib/seed'
import { toUserDTO } from '@/lib/dto'
import { isLoginBlocked, registerLoginFailure, resetLoginFailures } from '@/lib/rate-limit'
import { withApi } from '@/lib/route-handler'
import { clientIp } from '@/lib/client-ip'

export const dynamic = 'force-dynamic'

const bodySchema = z.object({
  username: z.string().min(1).max(100),
  password: z.string().min(1).max(200),
  // F-05 : accepté pour compatibilité des clients, ignoré tant qu'aucun secret
  // TOTP n'est enrôlé (schéma Prisma sans champ totpSecret).
  totp: z.string().min(1).max(10).optional(),
})

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

export const POST = withApi(async (req: NextRequest) => {
  // Le seed s'assure que les comptes de démo existent au premier démarrage.
  await ensureSeed()

  const raw = await req.json().catch(() => null)
  const parsed = bodySchema.safeParse(raw)
  if (!parsed.success) {
    return NextResponse.json({ error: 'Requête invalide — identifiant et mot de passe requis' }, { status: 400 })
  }

  const username = parsed.data.username.trim().toLowerCase()
  const rateKey = `${clientIp(req)}:${username}`

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

  // F-05 : plus de backdoor TOTP. Le schéma Prisma n'a pas de champ totpSecret
  // (aucun enrôlement MFA) : un compte mfaEnabled ne peut PAS être vérifié —
  // refus explicite plutôt que code universel. Quand un champ totpSecret
  // existera, brancher verifyTotp(secret, totp) de src/lib/totp.ts ici
  // (échec → 401 « Code TOTP invalide »). Le champ `totp` fourni est ignoré
  // pour les comptes sans MFA.
  if (user.mfaEnabled) {
    return NextResponse.json(
      { error: 'MFA activé mais non configuré — contacter l’administrateur' },
      { status: 403 }
    )
  }

  resetLoginFailures(rateKey)
  await setSessionCookie(newSession(user))
  await writeAudit(user.username, 'LOGIN', 'session')
  return NextResponse.json({ user: toUserDTO(user) })
})
