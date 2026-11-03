/**
 * AuditForge — Sprint 2 : autorisation de test par dossier (Case)
 *
 * Ce module centralise :
 * 1. La construction canonique d'une attestation d'autorisation et son
 *    empreinte SHA-256 (preuve d'intégrité affichée dans les rapports) ;
 * 2. L'extraction d'hôte d'une cible et la vérification de périmètre
 *    (hôte exact ou joker *.domaine — anti-évasion : jamais de simple
 *    `endsWith` sur l'entrée brute) ;
 * 3. Le garde de lancement : une campagne rattachée à un dossier exige une
 *    autorisation ACTIVE (signée, non révoquée, fenêtre valide) couvrant la
 *    cible — sinon le lancement est refusé (403 côté routes).
 *
 * Sémantique d'activité partagée avec src/lib/dto.ts (isAuthorizationActive).
 */
import { createHash } from 'crypto'
import { db } from '@/lib/db'

// ─── 1. Attestation canonique + empreinte ────────────────────────────

/** Champs canoniques d'une attestation (l'ordre est FIGÉ — contractuel). */
export interface AuthorizationPayload {
  caseReference: string
  caseTitle: string
  client: string
  signatory: string
  signatoryRole: string
  scope: string
  targets: string[]
  validFrom: string // ISO
  validUntil: string // ISO
}

/**
 * Chaîne canonique signée : JSON trié par clé, séparateurs stables. Le sel
 * « auditforge-authorization-v1 » lie l'empreinte au format de la plateforme
 * (une ré-émission avec des champs modifiés produit une empreinte différente).
 */
export function canonicalAuthorizationString(p: AuthorizationPayload): string {
  const sorted: Record<string, unknown> = {}
  for (const key of Object.keys(p).sort()) {
    sorted[key] = p[key as keyof AuthorizationPayload]
  }
  return `auditforge-authorization-v1\n${JSON.stringify(sorted)}`
}

/** Empreinte SHA-256 hexadécimale de l'attestation canonique. */
export function authorizationSignature(p: AuthorizationPayload): string {
  return createHash('sha256').update(canonicalAuthorizationString(p)).digest('hex')
}

// ─── 2. Périmètre (hôte exact / joker *.domaine) ─────────────────────

/** Hôte d'une cible URL (validée en amont par validateTarget). */
function hostOfUrl(target: string): string {
  try {
    return new URL(target).hostname.toLowerCase()
  } catch {
    return ''
  }
}

/**
 * Hôte d'une cible NETWORK (formats tolérés : hôte, hôte:port, CIDR,
 * [IPv6], [IPv6]:port) — même découpe que src/lib/dto.ts.
 */
function hostOfNetwork(target: string): string {
  const addr = (target.split('/')[0] ?? target).trim()
  if (addr.startsWith('[')) {
    const end = addr.indexOf(']')
    return (end === -1 ? addr.slice(1) : addr.slice(1, end)).toLowerCase()
  }
  const colon = addr.indexOf(':')
  if (colon === -1) return addr.toLowerCase()
  const rest = addr.slice(colon + 1)
  return (/^\d+$/.test(rest) ? addr.slice(0, colon) : addr).toLowerCase()
}

/** Hôte discriminant d'une cible quelconque (minuscules, sans port). */
export function hostOfTarget(target: string, targetType: string): string {
  const t = target.trim().toLowerCase()
  if (targetType === 'URL') return hostOfUrl(t)
  if (targetType === 'NETWORK') return hostOfNetwork(t)
  // GIT : git@host:path / ssh://host/path / https://host/path
  const gitMatch = /^(?:https?:\/\/|ssh:\/\/|git@)([^/:]+)/i.exec(t)
  return gitMatch ? (gitMatch[1] ?? '').toLowerCase() : ''
}

/**
 * Vrai si l'hôte est couvert par la liste d'hôtes autorisés :
 * - correspondance EXACTE (« example.com ») ;
 * - joker « *.example.com » → tout sous-domaine direct d'example.com
 *   (mais PAS example.com lui-même ni a.b.example.com) ;
 * - l'entrée est comparée en minuscules, sans point final.
 * Aucune autre méta-caractère n'est interprété (pas de regex arbitraire).
 */
export function isHostInScope(host: string, authorizedTargets: string[]): boolean {
  const h = host.trim().toLowerCase().replace(/\.$/, '')
  if (!h) return false
  for (const raw of authorizedTargets) {
    const entry = raw.trim().toLowerCase().replace(/\.$/, '')
    if (!entry) continue
    if (entry === h) return true
    if (entry.startsWith('*.')) {
      const suffix = entry.slice(1) // « .example.com »
      // h se termine par « .example.com » et il reste un libellé avant :
      // h = « sub.example.com » → ok ; « example.com » → non ; « a.b.example.com » → non.
      if (h.endsWith(suffix)) {
        const label = h.slice(0, h.length - suffix.length)
        if (label && !label.includes('.')) return true
      }
    }
  }
  return false
}

// ─── 3. Garde de lancement (DB) ──────────────────────────────────────

/** Résultat du garde de lancement. */
export interface LaunchAuthorizationCheck {
  ok: boolean
  /** Message d'erreur FR si refus (→ 403 côté route). */
  error?: string
  /** Référence du dossier (pour les messages/audit). */
  caseReference?: string
}

/**
 * Vérifie qu'une campagne (rattachée au dossier caseId) peut être lancée :
 * dossier existant, non CLOSED, autorisation ACTIVE couvrant l'hôte cible.
 * Une campagne sans dossier n'est pas concernée (retour ok immédiat).
 */
export async function checkLaunchAuthorization(input: {
  caseId: string | null
  target: string
  targetType: string
  campaignName?: string
}): Promise<LaunchAuthorizationCheck> {
  if (!input.caseId) return { ok: true }

  const kase = await db.case.findUnique({
    where: { id: input.caseId },
    include: { authorizations: { orderBy: { signedAt: 'desc' } } },
  })
  if (!kase) {
    return { ok: false, error: 'Dossier client introuvable (rattachement invalide)' }
  }
  if (kase.status === 'CLOSED') {
    return {
      ok: false,
      caseReference: kase.reference,
      error: `Dossier ${kase.reference} clôturé — lancement refusé`,
    }
  }

  const active = kase.authorizations.find(
    (a) => a.revokedAt === null && a.validFrom.getTime() <= Date.now() && a.validUntil.getTime() >= Date.now()
  )
  if (!active) {
    return {
      ok: false,
      caseReference: kase.reference,
      error:
        `Aucune autorisation signée active pour le dossier ${kase.reference} — ` +
        'une attestation valide (non révoquée, dans sa période) est requise avant tout lancement',
    }
  }

  const host = hostOfTarget(input.target, input.targetType)
  let targets: string[] = []
  try {
    const parsed: unknown = JSON.parse(active.targets)
    if (Array.isArray(parsed)) targets = parsed.filter((t): t is string => typeof t === 'string')
  } catch {
    targets = []
  }
  if (!isHostInScope(host, targets)) {
    return {
      ok: false,
      caseReference: kase.reference,
      error:
        `Cible « ${host || input.target} » hors périmètre de l'autorisation du dossier ` +
        `${kase.reference} (hôtes autorisés : ${targets.slice(0, 5).join(', ')})`,
    }
  }

  return { ok: true, caseReference: kase.reference }
}

// ─── 4. Génération de référence client (AF-<année>-<NNN>) ────────────

/**
 * Prochaine référence du dossier : AF-<année>-<NNN> (séquence annuelle,
 * 3 chiffres zéro-complétés). Démarre à 001 ; en cas de collision unique
 * (créations concurrentes), l'appelant réessaie avec la référence suivante
 * (boucle max 50 dans la route).
 */
export function caseReferenceForYear(year: number, sequence: number): string {
  return `AF-${year}-${String(sequence).padStart(3, '0')}`
}

/** Nombre de dossiers créés l'année donnée (pour amorcer la séquence). */
export async function countCasesForYear(year: number): Promise<number> {
  const from = new Date(Date.UTC(year, 0, 1))
  const to = new Date(Date.UTC(year + 1, 0, 1))
  return db.case.count({ where: { createdAt: { gte: from, lt: to } } })
}
