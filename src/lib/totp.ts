/**
 * AuditForge — TOTP RFC 6238 (F-05) — sans dépendance.
 *
 * - verifyTotp(secretBase32, code, t?) : vérification d'un code à 6 chiffres,
 *   pas de 30 s, fenêtre ±1 pas (dérive d'horloge), HMAC-SHA1 (RFC 4226),
 *   comparaison à temps constant.
 * - generateTotpSecret() : secret de 20 octets aléatoires encodé en base32
 *   RFC 4648, prêt pour un futur enrôlement MFA (aucun usage automatique ici).
 *
 * NOTE (audit F-05) : le code de démonstration « 123456 » a été supprimé de la
 * route de login. Le schéma Prisma n'a pas de champ totpSecret : ce module est
 * le socle à brancher le jour où l'enrôlement MFA existera (hors scope).
 */
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

/** Alphabet base32 RFC 4648. */
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

const STEP_SECONDS = 30
const WINDOW_STEPS = 1
const CODE_DIGITS = 6

/** Décode du base32 RFC 4648 (padding et espaces tolérés) → Buffer. */
function base32Decode(input: string): Buffer {
  const clean = input.toUpperCase().replace(/=+$/, '').replace(/\s+/g, '')
  let bits = 0
  let value = 0
  const out: number[] = []
  for (const char of clean) {
    const idx = BASE32_ALPHABET.indexOf(char)
    if (idx === -1) throw new Error('Secret base32 invalide')
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }
  return Buffer.from(out)
}

/** Encode des octets en base32 RFC 4648 (avec padding « = »). */
function base32Encode(bytes: Buffer): string {
  let bits = 0
  let value = 0
  let out = ''
  for (const byte of bytes) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31]
  return out + '='.repeat((8 - (out.length % 8)) % 8)
}

/** Code TOTP (6 chiffres) d'un secret pour un compteur temporel donné (RFC 4226). */
function totpAt(secret: Buffer, counter: number): string {
  const msg = Buffer.alloc(8)
  msg.writeBigUInt64BE(BigInt(counter))
  const mac = createHmac('sha1', secret).update(msg).digest()
  const offset = mac[mac.length - 1] & 0x0f
  const bin =
    ((mac[offset] & 0x7f) << 24) |
    ((mac[offset + 1] & 0xff) << 16) |
    ((mac[offset + 2] & 0xff) << 8) |
    (mac[offset + 3] & 0xff)
  return String(bin % 10 ** CODE_DIGITS).padStart(CODE_DIGITS, '0')
}

/**
 * Vérifie un code TOTP (RFC 6238) : fenêtre ±1 pas autour de l'instant `t`
 * (ms), comparaison à temps constant. Vrai si un code de la fenêtre correspond.
 */
export function verifyTotp(secretBase32: string, code: string, t: number = Date.now()): boolean {
  if (!/^\d{6}$/.test(code)) return false
  let secret: Buffer
  try {
    secret = base32Decode(secretBase32)
  } catch {
    return false // secret mal formé → refus, jamais d'exception vers l'appelant
  }
  if (secret.length === 0) return false
  const counter = Math.floor(t / 1000 / STEP_SECONDS)
  const provided = Buffer.from(code, 'utf8')
  for (let drift = -WINDOW_STEPS; drift <= WINDOW_STEPS; drift++) {
    const candidate = Buffer.from(totpAt(secret, counter + drift), 'utf8')
    if (provided.length === candidate.length && timingSafeEqual(provided, candidate)) {
      return true
    }
  }
  return false
}

/** Génère un nouveau secret TOTP : 20 octets aléatoires en base32 (RFC 4648). */
export function generateTotpSecret(): string {
  return base32Encode(randomBytes(20))
}
