/**
 * AuditForge — Helpers API partagés (tâche 3-a)
 *
 * Contient :
 * - les listes d'énumérations autorisées (validation des filtres CSV),
 * - le tri par sévérité, la compatibilité outils ⇄ cibles (worklog §B),
 * - les mappers Prisma → DTO (contrats EXACTS de src/lib/types.ts).
 *
 * NOTE (déviation mineure documentée dans worklog.md) : fichier utilitaire créé
 * par la tâche 3-a pour éviter de dupliquer les mappers dans les 17 routes.
 * Aucun contrat existant n'est modifié (types.ts intact).
 */
import type {
  AuditEntry,
  CampaignDTO,
  CampaignStatus,
  CaseAuthorizationDTO,
  CaseDTO,
  CaseStatus,
  Confidence,
  FindingDTO,
  FindingStatus,
  LogEntry,
  LogLevel,
  Profile,
  ScanDTO,
  ScanExecMode,
  ScanStatus,
  Severity,
  TargetType,
  Tool,
  UserDTO,
} from '@/lib/types'
import type {
  AuditTrail,
  Campaign,
  Case,
  CaseAuthorization,
  Finding,
  Scan,
  ScanLog,
  User,
} from '@prisma/client'

// ─── Énumérations autorisées (validation des filtres) ────────────────

export const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
export const FINDING_STATUSES: FindingStatus[] = ['OPEN', 'CONFIRMED', 'FALSE_POSITIVE', 'FIXED']
/**
 * P5 « Arsenal » — catalogue complet des outils :
 *  - plateformes/agents IA : PHANTOM, DEEPAUDIT, BASALT, REDAMON ;
 *  - evergreen : SUBFINDER, AMASS, HTTPX (recon) · NUCLEI, NIKTO, ZAP (DAST) ·
 *    SEMGREP, TRIVY, GITLEAKS (SAST/SCA) · SQLMAP, FFUF (exploitation) ;
 *  - Sprint 1 : WPSCAN, DALFOX, TESTSSL (DAST/CMS/TLS) · WHATWEB, WAFW00F (recon) ·
 *    HYDRA, JOHN (exploitation).
 * Synchronisé avec TOOLS du moteur (mini-services/scan-engine/src/index.ts).
 */
export const TOOLS: Tool[] = [
  'PHANTOM', 'DEEPAUDIT', 'BASALT', 'REDAMON',
  'SUBFINDER', 'AMASS', 'HTTPX',
  'NUCLEI', 'NIKTO', 'ZAP',
  'SEMGREP', 'TRIVY', 'GITLEAKS',
  'SQLMAP', 'FFUF',
  'WPSCAN', 'DALFOX', 'WHATWEB', 'TESTSSL', 'WAFW00F', 'HYDRA', 'JOHN',
  // Sprint 3 — navigateur headless (wrapper af-browser-tools, Chromium)
  'BROWSER_RECON', 'DOM_SINK_SCAN', 'JS_LIB_AUDIT', 'FORM_AUDIT',
]
export const SCAN_STATUSES: ScanStatus[] = ['QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED']
export const TARGET_TYPES: TargetType[] = ['URL', 'GIT', 'NETWORK']
export const PROFILES: Profile[] = ['QUICK', 'STANDARD', 'DEEP']
/** Sprint 2 : statuts d'un dossier client (voir type CaseStatus). */
export const CASE_STATUSES: CaseStatus[] = ['OPEN', 'AUTHORIZED', 'RUNNING', 'REPORTED', 'CLOSED']

/** P5 : familles d'outils (regroupement du catalogue et de l'assistant campagne). */
export type ToolFamily = 'AGENT' | 'RECON' | 'DAST' | 'CODE' | 'EXPLOIT' | 'BROWSER'

export const TOOL_FAMILY: Record<Tool, ToolFamily> = {
  PHANTOM: 'AGENT',
  DEEPAUDIT: 'AGENT',
  BASALT: 'AGENT',
  REDAMON: 'AGENT',
  SUBFINDER: 'RECON',
  AMASS: 'RECON',
  HTTPX: 'RECON',
  NUCLEI: 'DAST',
  NIKTO: 'DAST',
  ZAP: 'DAST',
  SEMGREP: 'CODE',
  TRIVY: 'CODE',
  GITLEAKS: 'CODE',
  SQLMAP: 'EXPLOIT',
  FFUF: 'EXPLOIT',
  // Sprint 1 — élargissement arsenal
  WPSCAN: 'DAST',
  DALFOX: 'DAST',
  WHATWEB: 'RECON',
  TESTSSL: 'DAST',
  WAFW00F: 'RECON',
  HYDRA: 'EXPLOIT',
  JOHN: 'EXPLOIT',
  // Sprint 3 — navigateur headless
  BROWSER_RECON: 'BROWSER',
  DOM_SINK_SCAN: 'BROWSER',
  JS_LIB_AUDIT: 'BROWSER',
  FORM_AUDIT: 'BROWSER',
}

export const TOOL_FAMILY_LABEL: Record<ToolFamily, string> = {
  AGENT: 'Agents IA & plateformes',
  RECON: 'Reconnaissance',
  DAST: 'Scan dynamique (DAST)',
  CODE: 'Analyse de code (SAST / SCA / secrets)',
  EXPLOIT: 'Exploitation ciblée',
  BROWSER: 'Navigateur headless',
}

/** Poids de tri des sévérités (du plus grave au moins grave). */
export const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0,
}

/**
 * Compatibilité outils ⇄ types de cible (worklog §B + P5 « Arsenal »).
 * M4 (audit 8-a) : BASALT en mode RÉEL n'accepte qu'un chemin/dépôt GIT.
 * P5 : les 11 outils evergreen couvrent l'ensemble du spectre —
 *   GIT : BASALT + SEMGREP + TRIVY + GITLEAKS (audit de code complet) ;
 *   URL : recon, DAST, exploitation (Subfinder→Amass→httpx→Nuclei→ZAP→sqlmap/ffuf) ;
 *   NETWORK : recon + Nuclei/Nikto sur hôtes.
 */
export const TOOL_TARGET_COMPAT: Record<Tool, TargetType[]> = {
  PHANTOM: ['URL', 'NETWORK'],
  REDAMON: ['URL', 'NETWORK'],
  // DeepAudit = agent d'audit profond multi-phases (sandbox Docker Kali) :
  // audite les applications web déployées (URL) et les hôtes (NETWORK).
  DEEPAUDIT: ['URL', 'NETWORK'],
  BASALT: ['GIT'],
  // P5 — arsenal evergreen
  SUBFINDER: ['URL', 'NETWORK'], // domaine dérivé (IP/plage refusée par l'adaptateur, message clair)
  AMASS: ['URL', 'NETWORK'], // idem — énumération passive de domaine
  HTTPX: ['URL', 'NETWORK'], // sondes HTTP (hôtes, IP, plages)
  NUCLEI: ['URL', 'NETWORK'], // templates sur URL/hôte
  NIKTO: ['URL', 'NETWORK'], // configuration serveur
  ZAP: ['URL'], // automation framework (baseline) — URL déployée uniquement
  SEMGREP: ['GIT'], // SAST sur dépôt cloné
  TRIVY: ['GIT'], // SCA + secrets sur dépôt cloné
  GITLEAKS: ['GIT'], // secrets sur dépôt cloné
  SQLMAP: ['URL'], // endpoint HTTP
  FFUF: ['URL'], // URL de base de fuzzing
  // Sprint 1 — élargissement arsenal
  WPSCAN: ['URL'], // site WordPress déployé
  DALFOX: ['URL'], // endpoint/URL de base pour le scan XSS
  WHATWEB: ['URL', 'NETWORK'], // empreinte web (URL ou hôte)
  TESTSSL: ['URL', 'NETWORK'], // endpoint TLS (hôte[:port] dérivé)
  WAFW00F: ['URL'], // URL de base de détection WAF
  HYDRA: ['NETWORK'], // hôte unique (module SSH, identifiants par défaut)
  JOHN: ['GIT'], // hashes faibles dans le dépôt cloné
  // Sprint 3 — navigateur headless (rendu d'une URL réelle en Chromium)
  BROWSER_RECON: ['URL'],
  DOM_SINK_SCAN: ['URL'],
  JS_LIB_AUDIT: ['URL'],
  FORM_AUDIT: ['URL'],
}

export function isToolCompatible(tool: Tool, targetType: TargetType): boolean {
  return TOOL_TARGET_COMPAT[tool]?.includes(targetType) ?? false
}

// ─── Validation des cibles (C1 — audit 8-a) ──────────────────────────
//
// Les cibles sont transmises comme arguments uniques à des CLI exécutées SANS
// shell (git clone, phantom scan, basalt audit…). Sans schéma strict, un
// AUDITOR peut injecter des options CLI (cible débutant par « - ») ou un
// transport git arbitraire (« ext::sh -c … » → exécution de commande sur le
// conteneur moteur). Chaque type impose son format : tout le reste est refusé.

const URL_TARGET_RE = /^https?:\/\/[^\s]+$/i
const GIT_TARGET_RE = /^(https?:\/\/|ssh:\/\/|git@)[^\s]+$/i
const NETWORK_TARGET_RE = /^[a-zA-Z0-9._:[\]/-]+$/

// ─── Protection SSRF (F-04 — audit sécurité) ─────────────────────────
//
// Les cibles URL/NETWORK sont transmises aux outils du moteur, qui joignent
// l'hôte depuis la sandbox. Sans garde sur l'hôte, un AUDITOR peut demander
// le scan d'une cible interne (boucle, réseau privé, liaison, métadonnées
// cloud) et obtenir un SSRF. Le contrôle porte sur l'hôte LITTÉRAL de la
// cible ; la résolution DNS (nom public → IP privée) reste du ressort du
// moteur, hors périmètre APP. Les cibles GIT ne sont pas concernées
// (github.com etc. conservent leur comportement).

/** Noms d'hôtes internes interdits (métadonnées cloud couvertes par .internal). */
const FORBIDDEN_HOSTNAMES = new Set(['localhost', 'metadata.google.internal'])
/** Suffixes internes : *.localhost, *.internal. */
const FORBIDDEN_HOST_SUFFIXES = ['.localhost', '.internal']

/** Parse une IPv4 pointée → 4 octets, ou null si ce n'est pas une IPv4 littérale. */
function parseIPv4(host: string): [number, number, number, number] | null {
  const parts = host.split('.')
  if (parts.length !== 4) return null
  const octets = parts.map((p) => (/^\d{1,3}$/.test(p) ? Number(p) : NaN))
  if (octets.some((n) => Number.isNaN(n) || n > 255)) return null
  return [octets[0] as number, octets[1] as number, octets[2] as number, octets[3] as number]
}

/** Vrai si l'IPv4 est privée/boucle/liaison/réservée (0.0.0.0/8 inclus). */
function isPrivateIPv4([a, b]: [number, number, number, number]): boolean {
  if (a === 0) return true // 0.0.0.0/8 — « ce réseau »
  if (a === 10) return true // 10.0.0.0/8 — privé
  if (a === 127) return true // 127.0.0.0/8 — boucle
  if (a === 169 && b === 254) return true // 169.254.0.0/16 — liaison (link-local)
  if (a === 172 && b >= 16 && b <= 31) return true // 172.16.0.0/12 — privé
  if (a === 192 && b === 168) return true // 192.168.0.0/16 — privé
  return false
}

/** Développe une IPv6 littérale en 8 groupes numériques, ou null si invalide. */
function ipv6Groups(host: string): number[] | null {
  const halves = host.split('::')
  if (halves.length > 2) return null
  const head = halves[0] ? halves[0].split(':') : []
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : []
  const missing = 8 - head.length - tail.length
  if (halves.length === 2 && missing < 1) return null
  const all = halves.length === 2 ? [...head, ...Array<string>(missing).fill('0'), ...tail] : head
  if (all.length !== 8) return null
  const groups = all.map((g) => (/^[0-9a-f]{1,4}$/.test(g) ? parseInt(g, 16) : NaN))
  return groups.some((n) => Number.isNaN(n)) ? null : groups
}

/** Vrai si l'IPv6 est boucle/non spécifiée/privée/liaison (::1, fc00::/7, fe80::/10, ::). */
function isPrivateIPv6(rawHost: string): boolean {
  const host = rawHost.replace(/^\[|\]$/g, '').split('%')[0] as string // crochets + zone id
  if (host === '::' || host === '::1') return true
  if (host.startsWith('::ffff:')) {
    // IPv4 mappée (::ffff:10.0.0.1) → réévaluée comme IPv4
    const v4 = parseIPv4(host.slice(7))
    return v4 ? isPrivateIPv4(v4) : true
  }
  const groups = ipv6Groups(host)
  if (!groups) return false // pas une IPv6 littérale → traitée comme nom d'hôte
  if (groups.every((g) => g === 0)) return true // :: (non spécifiée)
  if (groups.slice(0, 7).every((g) => g === 0) && groups[7] === 1) return true // ::1 forme complète
  const g0 = groups[0] as number
  if ((g0 & 0xfe00) === 0xfc00) return true // fc00::/7 — unique local
  if ((g0 & 0xffc0) === 0xfe80) return true // fe80::/10 — liaison
  return false
}

/**
 * F-04 (SSRF) : vrai si l'hôte est privé/interne — boucle, réseau privé,
 * liaison, métadonnées cloud, localhost. Exporté pour réutilisation.
 */
export function isForbiddenTargetHost(rawHost: string): boolean {
  const host = rawHost.trim().toLowerCase().replace(/\.$/, '') // FQDN sans point final
  if (host.length === 0) return true
  if (FORBIDDEN_HOSTNAMES.has(host) || FORBIDDEN_HOST_SUFFIXES.some((s) => host.endsWith(s))) {
    return true
  }
  const v4 = parseIPv4(host)
  if (v4) return isPrivateIPv4(v4)
  if (host.includes(':')) return isPrivateIPv6(host)
  return false
}

/** Hôte + port d'une cible URL (déjà validée par URL_TARGET_RE). */
function extractUrlHostPort(target: string): { host: string; port: string | null } {
  try {
    const u = new URL(target)
    return { host: u.hostname, port: u.port || null }
  } catch {
    // Injoignable ici (format déjà refusé) — hôte vide non significatif.
    return { host: '', port: null }
  }
}

/**
 * Hôte + port d'une cible NETWORK (formats tolérés : hôte, hôte:port,
 * hôte/chemin, CIDR, [IPv6], [IPv6]:port).
 */
function extractNetworkHostPort(target: string): { host: string; port: string | null } {
  const addr = (target.split('/')[0] ?? target).trim() // CIDR → adresse de base
  if (addr.startsWith('[')) {
    const end = addr.indexOf(']')
    const host = end === -1 ? addr.slice(1) : addr.slice(1, end)
    const after = end === -1 ? '' : addr.slice(end + 1)
    return { host, port: after.startsWith(':') ? after.slice(1) : null }
  }
  const colon = addr.indexOf(':')
  if (colon === -1) return { host: addr, port: null }
  const rest = addr.slice(colon + 1)
  if (/^\d+$/.test(rest)) return { host: addr.slice(0, colon), port: rest } // hôte:port
  return { host: addr, port: null } // IPv6 nue (plusieurs ':')
}

/**
 * F-04bis : allowlist opérateur — hosts EXACTS (minuscules, séparés par des
 * virgules, via TARGET_HOST_ALLOWLIST) que l'opérateur autorise explicitement
 * malgré la liste noire privée/interne (ex. fixtures de test hébergées sur le
 * VPS lui-même : 172.17.0.1:809x). Correspondance exacte sur le hostname
 * uniquement — jamais de suffixe/wildcard. Vide (défaut) : le garde SSRF
 * reste strict, aucun contournement implicite.
 */
const TARGET_HOST_ALLOWLIST = (process.env.TARGET_HOST_ALLOWLIST ?? '')
  .split(',')
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean)

/**
 * Valide une cible selon son type. Retourne un message d'erreur FR, ou null si
 * la cible est acceptée.
 */
export function validateTarget(targetType: TargetType, target: string): string | null {
  const t = target.trim()
  if (t.length === 0 || t.length > 300) {
    return 'La cible doit contenir entre 1 et 300 caractères'
  }
  if (/[\s\u0000-\u001f\u007f]/.test(t)) {
    return 'La cible ne doit contenir ni espace ni caractère de contrôle'
  }
  if (t.startsWith('-')) {
    return 'La cible ne peut pas commencer par « - »'
  }
  if (targetType === 'URL' && !URL_TARGET_RE.test(t)) {
    return 'Cible URL invalide — format attendu : http(s)://hôte/chemin'
  }
  if (targetType === 'GIT' && !GIT_TARGET_RE.test(t)) {
    return 'Cible GIT invalide — formats acceptés : https://…, ssh://…, git@hôte:chemin'
  }
  if (targetType === 'NETWORK' && !NETWORK_TARGET_RE.test(t)) {
    return 'Cible réseau invalide — caractères autorisés : alphanumériques, . : / [ ] -'
  }
  // F-04 : après le format, l'hôte des cibles URL/NETWORK est confronté à la
  // liste noire privée/interne (les cibles GIT gardent leur comportement).
  if (targetType === 'URL' || targetType === 'NETWORK') {
    const { host, port } =
      targetType === 'URL' ? extractUrlHostPort(t) : extractNetworkHostPort(t)
    if (host && isForbiddenTargetHost(host) && !TARGET_HOST_ALLOWLIST.includes(host)) {
      return 'Cible interdite : hôtes privés/internes non autorisés (protection SSRF)'
    }
    if (port === '0') {
      return 'Cible interdite : port 0 non autorisé'
    }
  }
  return null
}

/**
 * Parse un paramètre CSV (`?severity=CRITICAL,HIGH`) contre une liste d'autorisations.
 * - null       → paramètre absent / vide
 * - 'invalid'  → au moins une valeur hors liste (la route répondra 400)
 * - T[]        → valeurs valides
 */
export function parseCsvParam<T extends string>(
  raw: string | null,
  allowed: readonly T[]
): T[] | null | 'invalid' {
  if (raw === null) return null
  const parts = raw
    .split(',')
    .map((p) => p.trim())
    .filter((p) => p.length > 0)
  if (parts.length === 0) return null
  if (parts.some((p) => !allowed.includes(p as T))) return 'invalid'
  return parts as T[]
}

/** Trie des constats : sévérité desc (CRITICAL d'abord) puis createdAt desc. */
export function sortFindings<T extends { severity: string; createdAt: Date | string }>(
  findings: T[]
): T[] {
  return [...findings].sort((a, b) => {
    const rankDelta =
      (SEVERITY_RANK[a.severity as Severity] ?? -1) - (SEVERITY_RANK[b.severity as Severity] ?? -1)
    if (rankDelta !== 0) return -rankDelta // rang décroissant
    return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
  })
}

// ─── Mappers Prisma → DTO (les Date deviennent des ISO strings) ──────

export function toUserDTO(u: User): UserDTO {
  return {
    id: u.id,
    username: u.username,
    role: u.role as UserDTO['role'],
    mfaEnabled: u.mfaEnabled,
  }
}

export function toScanDTO(s: Scan, campaignName?: string | null): ScanDTO {
  return {
    id: s.id,
    campaignId: s.campaignId,
    campaignName: campaignName ?? null,
    tool: s.tool as Tool,
    target: s.target,
    status: s.status as ScanStatus,
    // REAL | SIMULATION — renseigné par le moteur (null : scans anciens)
    mode: (s.mode as ScanExecMode | null) ?? null,
    progress: s.progress,
    phase: s.phase,
    startedAt: s.startedAt ? s.startedAt.toISOString() : null,
    finishedAt: s.finishedAt ? s.finishedAt.toISOString() : null,
    durationMs: s.durationMs,
    findingsCount: s.findingsCount,
    criticalCount: s.criticalCount,
    createdAt: s.createdAt.toISOString(),
  }
}

export function toFindingDTO(f: Finding): FindingDTO {
  return {
    id: f.id,
    scanId: f.scanId,
    tool: f.tool as Tool,
    title: f.title,
    severity: f.severity as Severity,
    confidence: f.confidence as Confidence,
    category: f.category,
    cve: f.cve ?? null,
    cvss: f.cvss ?? null,
    location: f.location ?? null,
    description: f.description,
    evidence: f.evidence,
    poc: f.poc,
    sentinelTriggered: f.sentinelTriggered,
    status: f.status as FindingStatus,
    remediation: f.remediation ?? null,
    createdAt: f.createdAt.toISOString(),
  }
}

export function toLogDTO(l: ScanLog): LogEntry {
  return {
    id: l.id,
    scanId: l.scanId,
    ts: l.ts.toISOString(),
    level: l.level as LogLevel,
    source: l.source,
    message: l.message,
  }
}

export function toAuditDTO(a: AuditTrail): AuditEntry {
  return {
    id: a.id,
    actor: a.actor,
    action: a.action,
    resource: a.resource,
    detail: a.detail ?? null,
    createdAt: a.createdAt.toISOString(),
  }
}

/** Campagne telle que renvoyée par Prisma avec/without includes optionnels. */
interface CampaignLike extends Campaign {
  createdBy?: { username: string } | null
  scans?: Scan[]
  case?: { reference: string } | null
}

/**
 * Compteurs globaux optionnels (m9 — audit 8-a) : quand la liste `scans` est
 * tronquée (take 50) les sommes JS sous-estiment les totaux réels. La route
 * fournit alors scansCount (via _count) et les sommes exactes (via groupBy).
 */
interface CampaignTotals {
  scansCount?: number
  findingsCount?: number
  criticalCount?: number
}

/** Mappe une campagne (scans triés asc, comptages agrégés, createdByName). */
export function toCampaignDTO(c: CampaignLike, totals?: CampaignTotals): CampaignDTO {
  const scans = [...(c.scans ?? [])].sort(
    (a, b) => a.createdAt.getTime() - b.createdAt.getTime()
  )
  return {
    id: c.id,
    name: c.name,
    description: c.description ?? null,
    target: c.target,
    targetType: c.targetType as TargetType,
    profile: c.profile as Profile,
    status: c.status as CampaignStatus,
    sequential: c.sequential ?? false,
    // Sprint 2 : dossier client rattaché (null si campagne isolée).
    caseId: c.caseId ?? null,
    caseReference: c.case?.reference ?? null,
    createdAt: c.createdAt.toISOString(),
    createdById: c.createdById,
    createdByName: c.createdBy?.username ?? 'inconnu',
    scans: scans.map((s) => toScanDTO(s)),
    scansCount: totals?.scansCount ?? scans.length,
    findingsCount: totals?.findingsCount ?? scans.reduce((acc, s) => acc + s.findingsCount, 0),
    criticalCount: totals?.criticalCount ?? scans.reduce((acc, s) => acc + s.criticalCount, 0),
  }
}

// ─── Sprint 2 : mappers Case / CaseAuthorization ─────────────────────

export function toAuthorizationDTO(a: CaseAuthorization): CaseAuthorizationDTO {
  return {
    id: a.id,
    caseId: a.caseId,
    signatory: a.signatory,
    signatoryRole: a.signatoryRole,
    scope: a.scope,
    targets: parseTargetsJson(a.targets),
    validFrom: a.validFrom.toISOString(),
    validUntil: a.validUntil.toISOString(),
    signature: a.signature,
    signedAt: a.signedAt.toISOString(),
    revokedAt: a.revokedAt ? a.revokedAt.toISOString() : null,
    revokedReason: a.revokedReason ?? null,
  }
}

/** Parse sûr du JSON d'hôtes autorisés (tolérant aux valeurs corrompues). */
function parseTargetsJson(raw: string): string[] {
  try {
    const parsed: unknown = JSON.parse(raw)
    if (!Array.isArray(parsed)) return []
    return parsed.filter((t): t is string => typeof t === 'string' && t.length > 0)
  } catch {
    return []
  }
}

/** Case telle que renvoyée par Prisma avec includes optionnels. */
export interface CaseLike extends Case {
  createdBy?: { username: string } | null
  authorizations?: CaseAuthorization[]
  /** Compteurs portés par les SCANS des campagnes (pas par Campaign). */
  campaigns?: { scans?: { findingsCount: number; criticalCount: number }[] }[]
  _count?: { campaigns: number }
}

/**
 * Mappe un dossier → CaseDTO. Les compteurs campagnes acceptent soit les
 * campagnes incluses (somme JS), soit _count.campaigns pour le nombre brut.
 * activeAuthorization = l'autorisation active la plus récente (tri signAt desc).
 */
export function toCaseDTO(c: CaseLike): CaseDTO {
  const authorizations = [...(c.authorizations ?? [])].sort(
    (a, b) => b.signedAt.getTime() - a.signedAt.getTime()
  )
  const active = authorizations.find((a) => isAuthorizationActive(a)) ?? null
  const campaigns = c.campaigns ?? []
  return {
    id: c.id,
    reference: c.reference,
    title: c.title,
    client: c.client,
    contact: c.contact ?? null,
    description: c.description ?? null,
    status: c.status as CaseStatus,
    createdAt: c.createdAt.toISOString(),
    createdByName: c.createdBy?.username ?? 'inconnu',
    campaignsCount: c._count?.campaigns ?? campaigns.length,
    findingsCount: campaigns.reduce(
      (acc, s) => acc + (s.scans ?? []).reduce((a, f) => a + f.findingsCount, 0),
      0
    ),
    criticalCount: campaigns.reduce(
      (acc, s) => acc + (s.scans ?? []).reduce((a, f) => a + f.criticalCount, 0),
      0
    ),
    activeAuthorization: active ? toAuthorizationDTO(active) : null,
  }
}

/**
 * Autorisation ACTIVE = signée, non révoquée, dans la fenêtre de validité.
 * Sémantique partagée entre le DTO et le garde de lancement (case-auth.ts).
 */
export function isAuthorizationActive(a: {
  validFrom: Date
  validUntil: Date
  revokedAt: Date | null
}): boolean {
  const now = Date.now()
  return a.revokedAt === null && a.validFrom.getTime() <= now && a.validUntil.getTime() >= now
}
