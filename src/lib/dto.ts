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
  Confidence,
  FindingDTO,
  FindingStatus,
  LogEntry,
  LogLevel,
  Profile,
  ScanDTO,
  ScanStatus,
  Severity,
  TargetType,
  Tool,
  UserDTO,
} from '@/lib/types'
import type { AuditTrail, Campaign, Finding, Scan, ScanLog, User } from '@prisma/client'

// ─── Énumérations autorisées (validation des filtres) ────────────────

export const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
export const FINDING_STATUSES: FindingStatus[] = ['OPEN', 'CONFIRMED', 'FALSE_POSITIVE', 'FIXED']
export const TOOLS: Tool[] = ['PHANTOM', 'DEEPAUDIT', 'BASALT', 'REDAMON']
export const SCAN_STATUSES: ScanStatus[] = ['QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED']
export const TARGET_TYPES: TargetType[] = ['URL', 'GIT', 'NETWORK']
export const PROFILES: Profile[] = ['QUICK', 'STANDARD', 'DEEP']

/** Poids de tri des sévérités (du plus grave au moins grave). */
export const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0,
}

/**
 * Compatibilité outils ⇄ types de cible (worklog §B).
 * M4 (audit 8-a) : BASALT en mode RÉEL n'accepte qu'un chemin/dépôt GIT
 * (`basalt audit <chemin>`) — une cible URL produisait un échec systématique
 * sans repli. La compatibilité est alignée sur l'adaptateur réel.
 */
export const TOOL_TARGET_COMPAT: Record<Tool, TargetType[]> = {
  PHANTOM: ['URL', 'NETWORK'],
  REDAMON: ['URL', 'NETWORK'],
  DEEPAUDIT: ['URL', 'GIT'],
  BASALT: ['GIT'],
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
    createdAt: c.createdAt.toISOString(),
    createdById: c.createdById,
    createdByName: c.createdBy?.username ?? 'inconnu',
    scans: scans.map((s) => toScanDTO(s)),
    scansCount: totals?.scansCount ?? scans.length,
    findingsCount: totals?.findingsCount ?? scans.reduce((acc, s) => acc + s.findingsCount, 0),
    criticalCount: totals?.criticalCount ?? scans.reduce((acc, s) => acc + s.criticalCount, 0),
  }
}
