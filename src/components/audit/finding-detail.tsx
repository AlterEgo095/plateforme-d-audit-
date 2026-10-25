"use client";

/**
 * AuditForge — Panneau de détail d'une vulnérabilité (Sheet).
 * Utilisé par la vue Vulnérabilités et par le détail de scan.
 */

import { useEffect, useState } from "react";
import { Loader2, Wrench } from "lucide-react";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import {
  ConfidenceBadge,
  cvssSeverity,
  FindingStatusBadge,
  SeverityBadge,
  SentinelBadge,
  ToolBadge,
  FINDING_STATUS_LABELS_MAP,
  formatDateTime,
} from "@/components/audit/status-badges";
import { apiPatch, getErrorMessage } from "@/lib/api-client";
import { useToast } from "@/hooks/use-toast";
import type { FindingDTO, FindingStatus, UserDTO } from "@/lib/types";

export function FindingDetail({
  finding,
  open,
  onOpenChange,
  user,
  onStatusUpdated,
}: {
  finding: FindingDTO | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  user: UserDTO | null;
  onStatusUpdated?: (updated: FindingDTO) => void;
}) {
  const { toast } = useToast();
  const [saving, setSaving] = useState(false);
  const [localStatus, setLocalStatus] = useState<FindingStatus | null>(null);

  const status = finding ? (localStatus ?? finding.status) : null;
  const canEdit = user !== null && user.role !== "VIEWER";

  // Nouvelle vulnérabilité sélectionnée : réinitialise le statut local
  // (sinon l'optimiste du précédent finding fuyait sur le suivant).
  useEffect(() => {
    setLocalStatus(null);
  }, [finding?.id]);

  const updateStatus = async (newStatus: FindingStatus) => {
    if (!finding) return;
    const previous = status;
    setLocalStatus(newStatus);
    setSaving(true);
    try {
      const res = await apiPatch<{ finding: FindingDTO }>(
        `/api/findings/${finding.id}`,
        { status: newStatus }
      );
      toast({
        title: "Statut mis à jour",
        description: `Vulnérabilité marquée « ${FINDING_STATUS_LABELS_MAP[newStatus]} ».`,
      });
      onStatusUpdated?.(res.finding ?? { ...finding, status: newStatus });
    } catch (e) {
      setLocalStatus(previous ?? null);
      toast({
        title: "Erreur",
        description: getErrorMessage(e),
        variant: "destructive",
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="flex w-full flex-col gap-0 overflow-hidden p-0 sm:max-w-2xl">
        {finding ? (
          <>
            <SheetHeader className="shrink-0 space-y-2 border-b">
              <div className="flex flex-wrap items-center gap-2 pr-8">
                <SeverityBadge severity={finding.severity} />
                <ToolBadge tool={finding.tool} />
                {status && <FindingStatusBadge status={status} />}
              </div>
              <SheetTitle className="text-base leading-snug sm:text-lg">
                {finding.title}
              </SheetTitle>
              <SheetDescription className="sr-only">
                Détails de la vulnérabilité, preuves et remédiation
              </SheetDescription>
            </SheetHeader>

            <div className="flex-1 space-y-5 overflow-y-auto p-4 scrollbar-slim">
              {/* Métadonnées */}
              <dl className="grid grid-cols-2 gap-3 rounded-lg border p-3 text-xs sm:grid-cols-3">
                <div>
                  <dt className="text-muted-foreground">Score CVSS</dt>
                  <dd
                    className="mt-0.5 font-mono text-sm font-bold"
                    style={{
                      color:
                        finding.cvss !== null
                          ? cvssSeverity(finding.cvss).color
                          : undefined,
                    }}
                  >
                    {finding.cvss !== null ? finding.cvss.toFixed(1) : "—"}
                  </dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">CVE</dt>
                  <dd className="mt-0.5">
                    {finding.cve ? (
                      <Badge variant="outline" className="font-mono">
                        {finding.cve}
                      </Badge>
                    ) : (
                      <span>—</span>
                    )}
                  </dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Confiance</dt>
                  <dd className="mt-0.5">
                    <ConfidenceBadge confidence={finding.confidence} />
                  </dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Catégorie</dt>
                  <dd className="mt-0.5 font-mono">{finding.category}</dd>
                </div>
                <div className="col-span-2">
                  <dt className="text-muted-foreground">Localisation</dt>
                  <dd className="mt-0.5 truncate font-mono" title={finding.location ?? undefined}>
                    {finding.location ?? "—"}
                  </dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Détecté le</dt>
                  <dd className="mt-0.5">{formatDateTime(finding.createdAt)}</dd>
                </div>
                <div className="col-span-2 sm:col-span-3">
                  <dt className="text-muted-foreground">Scan</dt>
                  <dd className="mt-0.5 font-mono text-[11px] break-all">
                    {finding.scanId.length > 24
                      ? `${finding.scanId.slice(0, 8)}…${finding.scanId.slice(-8)}`
                      : finding.scanId}
                  </dd>
                </div>
              </dl>

              {/* Statut */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between gap-2">
                  <Label className="text-sm font-semibold">Statut de la vulnérabilité</Label>
                  {canEdit ? (
                    <Select
                      value={status ?? undefined}
                      onValueChange={(v) => updateStatus(v as FindingStatus)}
                      disabled={saving}
                    >
                      <SelectTrigger
                        className="h-9 w-44"
                        aria-label="Modifier le statut de la vulnérabilité"
                      >
                        {saving ? (
                          <span className="flex items-center gap-2">
                            <Loader2 className="size-3.5 animate-spin" aria-hidden />
                            Enregistrement…
                          </span>
                        ) : (
                          <SelectValue />
                        )}
                      </SelectTrigger>
                      <SelectContent>
                        {Object.entries(FINDING_STATUS_LABELS_MAP).map(([value, label]) => (
                          <SelectItem key={value} value={value}>
                            {label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  ) : (
                    <span className="text-muted-foreground text-xs italic">
                      Lecture seule
                    </span>
                  )}
                </div>
              </div>

              {/* Description */}
              <section className="space-y-2" aria-labelledby="finding-desc-title">
                <h3 id="finding-desc-title" className="text-sm font-semibold">
                  Description
                </h3>
                <p className="text-muted-foreground text-sm leading-relaxed">
                  {finding.description}
                </p>
              </section>

              {/* Preuves */}
              <section className="space-y-2" aria-labelledby="finding-evidence-title">
                <div className="flex flex-wrap items-center gap-2">
                  <h3 id="finding-evidence-title" className="text-sm font-semibold">
                    Preuves
                  </h3>
                  {finding.sentinelTriggered && <SentinelBadge />}
                </div>
                {finding.sentinelTriggered && (
                  <p className="text-xs" style={{ color: "#34d399" }}>
                    Vulnérabilité confirmée par exécution du PoC en sandbox sans
                    réseau — sentinelle BASALT-POC-TRIGGERED
                  </p>
                )}
                <pre className="terminal-grid bg-black/40 overflow-x-auto rounded-lg border p-3 font-mono text-xs whitespace-pre-wrap scrollbar-slim">
                  {finding.evidence || "—"}
                </pre>
              </section>

              {/* PoC */}
              <section className="space-y-2" aria-labelledby="finding-poc-title">
                <h3 id="finding-poc-title" className="text-sm font-semibold">
                  Preuve de concept
                </h3>
                <pre className="terminal-grid bg-black/40 overflow-x-auto rounded-lg border p-3 font-mono text-xs whitespace-pre-wrap scrollbar-slim">
                  {finding.poc || "—"}
                </pre>
              </section>

              {/* Remédiation */}
              {finding.remediation && (
                <section
                  className="space-y-2"
                  aria-labelledby="finding-remediation-title"
                >
                  <h3 id="finding-remediation-title" className="text-sm font-semibold">
                    Remédiation
                  </h3>
                  <Card
                    className="border-emerald-500/40 bg-emerald-500/5"
                    role="note"
                  >
                    <CardContent className="flex items-start gap-3 p-4">
                      <Wrench className="mt-0.5 size-4 shrink-0 text-emerald-400" aria-hidden />
                      <p className="text-sm leading-relaxed">
                        {finding.remediation}
                      </p>
                    </CardContent>
                  </Card>
                </section>
              )}
            </div>
          </>
        ) : (
          <div className="flex flex-1 items-center justify-center">
            <p className="text-muted-foreground text-sm">Aucune vulnérabilité sélectionnée.</p>
          </div>
        )}
      </SheetContent>
    </Sheet>
  );
}
