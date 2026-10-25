"use client";

/**
 * AuditForge — Aides de présentation partagées : badges de sévérité/statut,
 * badges outils, cartes statistiques, états vides, formatage FR.
 */

import type { LucideIcon } from "lucide-react";
import { ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";
import type {
  CampaignStatus,
  Confidence,
  FindingStatus,
  ScanStatus,
  Severity,
  TargetType,
  Tool,
} from "@/lib/types";

// ─── Couleurs de sévérité (contrat J) ────────────────────────────────

export const SEVERITY_COLORS = {
  CRITICAL: "#f43f5e",
  HIGH: "#fb923c",
  MEDIUM: "#fbbf24",
  LOW: "#a3e635",
  INFO: "#94a3b8",
} as const;

export const SEVERITY_ORDER: Severity[] = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFO",
];

export function severityColor(sev: Severity | string): string {
  return SEVERITY_COLORS[sev as Severity] ?? SEVERITY_COLORS.INFO;
}

// ─── Badges métier ───────────────────────────────────────────────────

export const SEVERITY_LABELS: Record<Severity, string> = {
  CRITICAL: "Critique",
  HIGH: "Majeur",
  MEDIUM: "Modéré",
  LOW: "Mineur",
  INFO: "Info",
};

/** Sévérité déduite d'un score CVSS (seuils 9 / 7 / 4). */
export function cvssSeverity(
  cvss: number | null | undefined
): { label: string; color: string } {
  if (cvss === null || cvss === undefined) {
    return { label: "—", color: SEVERITY_COLORS.INFO };
  }
  if (cvss >= 9) {
    return { label: SEVERITY_LABELS.CRITICAL, color: SEVERITY_COLORS.CRITICAL };
  }
  if (cvss >= 7) {
    return { label: SEVERITY_LABELS.HIGH, color: SEVERITY_COLORS.HIGH };
  }
  if (cvss >= 4) {
    return { label: SEVERITY_LABELS.MEDIUM, color: SEVERITY_COLORS.MEDIUM };
  }
  return { label: SEVERITY_LABELS.LOW, color: SEVERITY_COLORS.LOW };
}

export function SeverityBadge({
  severity,
  className,
}: {
  severity: Severity;
  className?: string;
}) {
  const color = severityColor(severity);
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap",
        className
      )}
      style={{
        backgroundColor: `${color}1a`,
        color,
        borderColor: `${color}55`,
      }}
    >
      <span
        className="size-1.5 rounded-full"
        style={{ backgroundColor: color }}
        aria-hidden
      />
      {SEVERITY_LABELS[severity] ?? severity}
    </span>
  );
}

export const SCAN_STATUS_LABELS: Record<ScanStatus, string> = {
  QUEUED: "En file",
  RUNNING: "En cours",
  COMPLETED: "Terminé",
  FAILED: "Échec",
  CANCELLED: "Annulé",
};

/** Libellés de statut de campagne (la campagne a en plus l'état DRAFT). */
export const CAMPAIGN_STATUS_LABELS: Record<CampaignStatus, string> = {
  DRAFT: "Brouillon",
  RUNNING: "En cours",
  COMPLETED: "Terminé",
  FAILED: "Échec",
  CANCELLED: "Annulé",
};

export function scanStatusColor(status: ScanStatus): string {
  switch (status) {
    case "RUNNING":
      return "#34d399";
    case "COMPLETED":
      return "#10b981";
    case "FAILED":
      return "#f43f5e";
    case "CANCELLED":
      return "#94a3b8";
    default:
      return "#fbbf24";
  }
}

export function ScanStatusBadge({
  status,
  className,
}: {
  status: ScanStatus | CampaignStatus;
  className?: string;
}) {
  const color = scanStatusColor(status as ScanStatus);
  const isRunning = status === "RUNNING";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap",
        className
      )}
      style={{
        backgroundColor: `${color}1a`,
        color,
        borderColor: `${color}55`,
      }}
    >
      {isRunning && (
        <span
          className="af-live-dot size-1.5 rounded-full"
          style={{ backgroundColor: color }}
          aria-hidden
        />
      )}
      {status === "DRAFT"
        ? CAMPAIGN_STATUS_LABELS.DRAFT
        : (SCAN_STATUS_LABELS[status as ScanStatus] ?? status)}
    </span>
  );
}

const FINDING_STATUS_LABELS: Record<FindingStatus, string> = {
  OPEN: "Ouvert",
  CONFIRMED: "Confirmé",
  FALSE_POSITIVE: "Faux positif",
  FIXED: "Corrigé",
};

export function findingStatusColor(status: FindingStatus): string {
  switch (status) {
    case "OPEN":
      return "#fb923c";
    case "CONFIRMED":
      return "#f43f5e";
    case "FALSE_POSITIVE":
      return "#94a3b8";
    case "FIXED":
      return "#34d399";
  }
}

export function FindingStatusBadge({
  status,
  className,
}: {
  status: FindingStatus;
  className?: string;
}) {
  const color = findingStatusColor(status);
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap",
        className
      )}
      style={{
        backgroundColor: `${color}1a`,
        color,
        borderColor: `${color}55`,
      }}
    >
      {FINDING_STATUS_LABELS[status] ?? status}
    </span>
  );
}

export const FINDING_STATUS_LABELS_MAP = FINDING_STATUS_LABELS;

const TOOL_COLORS: Record<Tool, string> = {
  PHANTOM: "#a78bfa",
  DEEPAUDIT: "#2dd4bf",
  BASALT: "#34d399",
  REDAMON: "#fbbf24",
};

// M4 (audit 8-a) : les cibles supportées dérivent de TOOL_TARGET_COMPAT
// (src/lib/dto.ts) — SOURCE UNIQUE, aucun drift possible entre le formulaire
// de campagne, les fiches outils et la validation serveur.
import { TOOL_TARGET_COMPAT } from "@/lib/dto";

/** Métadonnées centralisées des outils (contrat §B pour les cibles). */
export const TOOL_META: Record<
  Tool,
  {
    label: string;
    color: string;
    description: string;
    supportedTargets: TargetType[];
  }
> = {
  PHANTOM: {
    label: "Phantom (IA)",
    color: TOOL_COLORS.PHANTOM,
    description: "Agent IA de pentest (boucle ReAct)",
    supportedTargets: TOOL_TARGET_COMPAT.PHANTOM,
  },
  DEEPAUDIT: {
    label: "DeepAudit",
    color: TOOL_COLORS.DEEPAUDIT,
    description: "Audit de code multi-agents",
    supportedTargets: TOOL_TARGET_COMPAT.DEEPAUDIT,
  },
  BASALT: {
    label: "Basalt",
    color: TOOL_COLORS.BASALT,
    description: "Vérification de PoC en sandbox",
    supportedTargets: TOOL_TARGET_COMPAT.BASALT,
  },
  REDAMON: {
    label: "Redamon",
    color: TOOL_COLORS.REDAMON,
    description: "Reconnaissance & exploitation",
    supportedTargets: TOOL_TARGET_COMPAT.REDAMON,
  },
};

export function toolColor(tool: Tool | string): string {
  return TOOL_META[tool as Tool]?.color ?? "#94a3b8";
}

export function ToolBadge({
  tool,
  small,
  className,
}: {
  tool: Tool;
  small?: boolean;
  className?: string;
}) {
  const color = toolColor(tool);
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border font-mono font-semibold tracking-wide whitespace-nowrap",
        small ? "px-1.5 py-0 text-[10px]" : "px-2 py-0.5 text-xs",
        className
      )}
      style={{
        backgroundColor: `${color}1a`,
        color,
        borderColor: `${color}55`,
      }}
    >
      {tool}
    </span>
  );
}

const CONFIDENCE_LABELS: Record<Confidence, string> = {
  CONFIRMED: "Confirmé",
  PROBABLE: "Probable",
  UNVERIFIED: "Non vérifié",
};

export function ConfidenceBadge({
  confidence,
  className,
}: {
  confidence: Confidence;
  className?: string;
}) {
  const color =
    confidence === "CONFIRMED"
      ? "#34d399"
      : confidence === "PROBABLE"
        ? "#fbbf24"
        : "#94a3b8";
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap",
        className
      )}
      style={{
        backgroundColor: `${color}1a`,
        color,
        borderColor: `${color}55`,
      }}
    >
      {CONFIDENCE_LABELS[confidence] ?? confidence}
    </span>
  );
}

export function SentinelBadge({ className }: { className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap",
        className
      )}
      style={{
        backgroundColor: "#10b9811a",
        color: "#34d399",
        borderColor: "#10b98155",
      }}
      title="Vulnérabilité confirmée par exécution du PoC en sandbox isolée"
    >
      <ShieldCheck className="size-3" aria-hidden />
      PoC vérifié (sandbox)
    </span>
  );
}

// ─── Carte statistique ───────────────────────────────────────────────

export function StatCard({
  label,
  value,
  icon: Icon,
  hint,
  accent = "#10b981",
}: {
  label: string;
  value: number | string;
  icon: LucideIcon;
  hint?: string;
  accent?: string;
}) {
  return (
    <div className="bg-card flex items-center gap-4 rounded-xl border p-4 shadow-sm transition-colors hover:border-accent">
      <div
        className="flex size-11 shrink-0 items-center justify-center rounded-full"
        style={{ backgroundColor: `${accent}1a`, color: accent }}
        aria-hidden
      >
        <Icon className="size-5" />
      </div>
      <div className="min-w-0">
        <div className="text-2xl leading-tight font-bold tabular-nums">
          {value}
        </div>
        <div className="text-muted-foreground truncate text-xs font-medium sm:text-sm">
          {label}
        </div>
        {hint && (
          <div className="text-muted-foreground/80 truncate text-[11px]">
            {hint}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── État vide ───────────────────────────────────────────────────────

export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
}: {
  icon: LucideIcon;
  title: string;
  description?: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-12 text-center">
      <div
        className="text-muted-foreground flex size-12 items-center justify-center rounded-full border border-dashed"
        aria-hidden
      >
        <Icon className="size-6" />
      </div>
      <p className="text-sm font-semibold">{title}</p>
      {description && (
        <p className="text-muted-foreground max-w-md text-sm">{description}</p>
      )}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}

// ─── Formatage ───────────────────────────────────────────────────────

export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return "—";
  const totalSec = Math.round(ms / 1000);
  const min = Math.floor(totalSec / 60);
  const sec = totalSec % 60;
  if (min === 0) return `${sec} s`;
  return `${min} min ${String(sec).padStart(2, "0")} s`;
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return new Intl.DateTimeFormat("fr-FR", {
    dateStyle: "short",
    timeStyle: "medium",
  }).format(d);
}

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return new Intl.DateTimeFormat("fr-FR", { dateStyle: "long" }).format(d);
}

export const PROFILE_LABELS: Record<string, string> = {
  QUICK: "Rapide (~25 s)",
  STANDARD: "Standard (~45 s)",
  DEEP: "Approfondi (~80 s)",
};

export const TARGET_TYPE_LABELS: Record<string, string> = {
  URL: "Application web (URL)",
  GIT: "Dépôt de code (Git)",
  NETWORK: "Plage réseau / hôte",
};

export const ROLE_LABELS: Record<string, string> = {
  ADMIN: "Administrateur",
  AUDITOR: "Auditeur",
  VIEWER: "Observateur",
};
