/**
 * AuditForge — Contrats partagés (Frontend ⇄ API ⇄ Moteur d'exécution)
 *
 * CE FICHIER EST LA SOURCE DE VÉRITÉ DES TYPES.
 * Ne pas modifier sans mettre à jour /home/z/my-project/worklog.md.
 */

// ─── Énumérations métier ─────────────────────────────────────────────

export type Role = "ADMIN" | "AUDITOR" | "VIEWER";

export type Tool = "PHANTOM" | "DEEPAUDIT" | "BASALT" | "REDAMON";

export type TargetType = "URL" | "GIT" | "NETWORK";

export type Profile = "QUICK" | "STANDARD" | "DEEP";

export type CampaignStatus =
  | "DRAFT"
  | "RUNNING"
  | "COMPLETED"
  | "FAILED"
  | "CANCELLED";

export type ScanStatus =
  | "QUEUED"
  | "RUNNING"
  | "COMPLETED"
  | "FAILED"
  | "CANCELLED";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type Confidence = "CONFIRMED" | "PROBABLE" | "UNVERIFIED";

export type FindingStatus = "OPEN" | "CONFIRMED" | "FALSE_POSITIVE" | "FIXED";

export type LogLevel =
  | "INFO"
  | "CMD"
  | "WARN"
  | "ERROR"
  | "SUCCESS"
  | "TOOL"
  | "AGENT";

// ─── DTO (dates sérialisées en ISO string) ───────────────────────────

export interface UserDTO {
  id: string;
  username: string;
  role: Role;
  mfaEnabled: boolean;
}

export interface ScanDTO {
  id: string;
  campaignId: string;
  /** Nom de la campagne (renseigné par l'API de listage). */
  campaignName?: string | null;
  tool: Tool;
  target: string;
  status: ScanStatus;
  progress: number;
  phase: string;
  startedAt: string | null;
  finishedAt: string | null;
  durationMs: number | null;
  findingsCount: number;
  criticalCount: number;
  createdAt: string;
}

export interface CampaignDTO {
  id: string;
  name: string;
  description: string | null;
  target: string;
  targetType: TargetType;
  profile: Profile;
  status: CampaignStatus;
  createdAt: string;
  createdById: string;
  createdByName: string;
  scans: ScanDTO[];
  findingsCount: number;
  criticalCount: number;
}

export interface FindingDTO {
  id: string;
  scanId: string;
  tool: Tool;
  title: string;
  severity: Severity;
  confidence: Confidence;
  category: string;
  cve: string | null;
  cvss: number | null;
  location: string | null;
  description: string;
  evidence: string;
  poc: string;
  sentinelTriggered: boolean;
  status: FindingStatus;
  remediation: string | null;
  createdAt: string;
}

export interface LogEntry {
  id: number;
  scanId: string;
  ts: string;
  level: LogLevel;
  source: string;
  message: string;
}

export interface AuditEntry {
  id: number;
  actor: string;
  action: string;
  resource: string;
  detail: string | null;
  createdAt: string;
}

export interface ToolInfo {
  id: Tool;
  name: string;
  description: string;
  nature: string;
  integration: string;
  sandbox: string;
  capabilities: string[];
  supportedTargets: TargetType[];
  status: "CONNECTE" | "HORS_LIGNE";
}

// ─── Événements socket.io (moteur :3030 → navigateur) ────────────────

/** Diffusé globalement (tous les clients) à chaque changement d'état d'un scan. */
export interface ScanUpdateEvent {
  scanId: string;
  campaignId: string;
  tool: Tool;
  status: ScanStatus;
  progress: number;
  phase: string;
  findingsCount: number;
  criticalCount: number;
}

/** Émis uniquement dans la room `scan:{id}`. */
export interface ScanLogEvent {
  scanId: string;
  log: LogEntry;
}

/** Émis uniquement dans la room `scan:{id}`. */
export interface ScanFindingEvent {
  scanId: string;
  finding: FindingDTO;
}

/** Diffusé globalement à la fin d'un scan. */
export interface ScanDoneEvent {
  scanId: string;
  campaignId: string;
  tool: Tool;
  status: ScanStatus;
  durationMs: number;
  findingsCount: number;
  criticalCount: number;
}

/** Contrats client → serveur socket.io */
export interface ClientToServerEvents {
  "scan:subscribe": (data: { scanId: string }) => void;
  "scan:unsubscribe": (data: { scanId: string }) => void;
}

// ─── API interne moteur (Next.js → moteur, localhost:3030) ───────────

export interface EngineRunRequest {
  scanId: string;
  tool: Tool;
  target: string;
  targetType: TargetType;
  profile: Profile;
}

export interface EngineRunResponse {
  ok: boolean;
  error?: string;
}

export interface EngineHealth {
  ok: boolean;
  running: number;
}
