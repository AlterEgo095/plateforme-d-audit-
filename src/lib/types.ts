/**
 * AuditForge — Contrats partagés (Frontend ⇄ API ⇄ Moteur d'exécution)
 *
 * CE FICHIER EST LA SOURCE DE VÉRITÉ DES TYPES.
 * Ne pas modifier sans mettre à jour /home/z/my-project/worklog.md.
 */

// ─── Énumérations métier ─────────────────────────────────────────────

export type Role = "ADMIN" | "AUDITOR" | "VIEWER";

/**
 * Outils d'audit — P5 « Arsenal » : 4 plateformes/agents IA + 11 outils
 * evergreen (recon, DAST, SAST/SCA, exploitation). Ajout additif — la base
 * stocke la colonne `tool` en String.
 */
export type Tool =
  | "PHANTOM"
  | "DEEPAUDIT"
  | "BASALT"
  | "REDAMON"
  | "SUBFINDER"
  | "AMASS"
  | "HTTPX"
  | "NUCLEI"
  | "NIKTO"
  | "ZAP"
  | "SEMGREP"
  | "TRIVY"
  | "GITLEAKS"
  | "SQLMAP"
  | "FFUF"
  | "WPSCAN"
  | "DALFOX"
  | "WHATWEB"
  | "TESTSSL"
  | "WAFW00F"
  | "HYDRA"
  | "JOHN";

/** P5 : famille d'un outil (regroupement catalogue / assistant de campagne). */
export type ToolFamily = "AGENT" | "RECON" | "DAST" | "CODE" | "EXPLOIT";

export type TargetType = "URL" | "GIT" | "NETWORK";

export type Profile = "QUICK" | "STANDARD" | "DEEP";

export type CampaignStatus =
  | "DRAFT"
  | "RUNNING"
  | "COMPLETED"
  | "FAILED"
  | "CANCELLED";

/**
 * Sprint 2 — statut d'un dossier client (Case) :
 * OPEN (créé) → AUTHORIZED (autorisation signée active) → RUNNING (au moins
 * une campagne en cours) → REPORTED (rapport client généré) → CLOSED.
 */
export type CaseStatus =
  | "OPEN"
  | "AUTHORIZED"
  | "RUNNING"
  | "REPORTED"
  | "CLOSED";

export type ScanStatus =
  | "QUEUED"
  | "RUNNING"
  | "COMPLETED"
  | "FAILED"
  | "CANCELLED";

/**
 * Mode d'exécution réellement suivi par un scan — renseigné par le moteur
 * (Scan.mode). REAL = outil authentique exécuté ; SIMULATION = résultats
 * synthétiques (fallback auto ou mode simulé explicite). null = scans anciens.
 */
export type ScanExecMode = "REAL" | "SIMULATION";

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
  /** REAL | SIMULATION — honnêteté : badge UI distinct si simulé. */
  mode: ScanExecMode | null;
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
  /** P5 : chaîne d'outils — les scans s'exécutent l'un après l'autre. */
  sequential: boolean;
  /**
   * Sprint 2 : dossier client rattaché (optionnel) — lancement soumis à
   * autorisation signée active couvrant la cible.
   */
  caseId: string | null;
  caseReference: string | null;
  createdAt: string;
  createdById: string;
  createdByName: string;
  scans: ScanDTO[];
  /** Nombre TOTAL de scans de la campagne (peut dépasser scans.length, liste tronquée). */
  scansCount: number;
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

// ─── Sprint 2 : dossiers client (Case) + autorisations ───────────────

/** Autorisation de test signée — voir model CaseAuthorization (schéma Prisma). */
export interface CaseAuthorizationDTO {
  id: string;
  caseId: string;
  signatory: string;
  signatoryRole: string;
  scope: string;
  /** Hôtes autorisés (hôte exact ou joker *.domaine, minuscules). */
  targets: string[];
  validFrom: string;
  validUntil: string;
  /** Empreinte SHA-256 de l'attestation canonique (preuve d'intégrité). */
  signature: string;
  signedAt: string;
  revokedAt: string | null;
  revokedReason: string | null;
}

export interface CaseDTO {
  id: string;
  /** Référence client unique — AF-<année>-<NNN>. */
  reference: string;
  title: string;
  client: string;
  contact: string | null;
  description: string | null;
  status: CaseStatus;
  createdAt: string;
  createdByName: string;
  campaignsCount: number;
  findingsCount: number;
  criticalCount: number;
  /** Autorisation active la plus récente (signée, non révoquée, période valide), sinon null. */
  activeAuthorization: CaseAuthorizationDTO | null;
}

/** Campagne résumée dans le rapport client (scans inclus). */
export interface CaseReportCampaign {
  id: string;
  name: string;
  target: string;
  targetType: TargetType;
  profile: Profile;
  status: CampaignStatus;
  createdAt: string;
  scans: ScanDTO[];
}

/** Rapport client agrégé — toutes les campagnes/constats du dossier. */
export interface CaseReportDTO {
  caseInfo: CaseDTO;
  authorization: CaseAuthorizationDTO | null;
  /** Historique des autorisations (actives et révoquées) — traçabilité. */
  authorizationHistory: CaseAuthorizationDTO[];
  campaigns: CaseReportCampaign[];
  findings: FindingDTO[];
  stats: {
    total: number;
    bySeverity: Record<Severity, number>;
    byStatus: Record<FindingStatus, number>;
    byTool: Record<string, number>;
    confirmedCount: number;
    sentinelCount: number;
  };
  generatedAt: string;
  generatedBy: string;
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
  /** Mode d'exécution du moteur : simulation | auto | real. */
  execMode?: "simulation" | "auto" | "real";
  /** true si l'outil authentique est exécutable par le moteur (binaire + Docker). */
  realAvailable?: boolean;
  /** Raison d'indisponibilité de l'exécution réelle, le cas échéant. */
  realReason?: string;
  /** P5 : famille de l'outil (regroupement catalogue / assistant de campagne). */
  family?: ToolFamily;
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
  /** P4 (file d'attente) : statut d'exécution résultant de la soumission. */
  scanStatus?: "RUNNING" | "QUEUED";
}

export interface EngineHealth {
  ok: boolean;
  running: number;
  /** P4 (file d'attente) : métriques additives du moteur. */
  queued?: number;
  maxConcurrent?: number;
  maxQueued?: number;
  uptime_s?: number;
  mem_mb?: number;
  exec_mode?: "simulation" | "auto" | "real";
}
