"use client";

/**
 * AuditForge — Vue Rapports : génération et prévisualisation imprimable
 * du rapport d'audit formel d'un scan terminé.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { FileText, Loader2, Printer, Shield } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import { apiGet, getErrorMessage } from "@/lib/api-client";
import { useToast } from "@/hooks/use-toast";
import {
  EmptyState,
  PROFILE_LABELS,
  SEVERITY_LABELS,
  SEVERITY_ORDER,
  SeverityBadge,
  TARGET_TYPE_LABELS,
  ToolBadge,
  formatDateTime,
  formatDate,
  formatDuration,
  severityColor,
} from "@/components/audit/status-badges";
import type { FindingDTO, ScanDTO, Severity, UserDTO } from "@/lib/types";

interface ReportData {
  scan: ScanDTO;
  campaign: {
    id: string;
    name: string;
    target: string;
    targetType: string;
    profile: string;
    createdAt?: string;
  };
  findings: FindingDTO[];
  stats: {
    bySeverity: Record<string, number>;
    byStatus: Record<string, number>;
    confirmedCount: number;
    sentinelCount: number;
  };
  generatedAt: string;
  generatedBy: string;
}


export function ReportsView({
  user,
  scanReportId,
  onConsumeReportId,
}: {
  user: UserDTO;
  scanReportId?: string | null;
  onConsumeReportId?: () => void;
}) {
  const { toast } = useToast();
  const [completedScans, setCompletedScans] = useState<ScanDTO[]>([]);
  const [loadingList, setLoadingList] = useState(true);
  const [report, setReport] = useState<ReportData | null>(null);
  const [generating, setGenerating] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  /** Jeton de séquence : ignore les réponses de fetch obsolètes. */
  const seqRef = useRef(0);
  /** Jeton de séquence dédié à generate() (indépendant de loadList). */
  const genSeqRef = useRef(0);

  const loadList = useCallback(async () => {
    const seq = ++seqRef.current;
    try {
      const res = await apiGet<{ scans: ScanDTO[] }>(
        "/api/scans?status=COMPLETED"
      );
      if (seq !== seqRef.current) return; // réponse obsolète
      setCompletedScans(res.scans);
    } catch (e) {
      if (seq !== seqRef.current) return;
      setError(getErrorMessage(e));
    } finally {
      if (seq === seqRef.current) setLoadingList(false);
    }
  }, []);

  useEffect(() => {
    void loadList();
  }, [loadList]);

  const generate = useCallback(
    async (scanId: string) => {
      const seq = ++genSeqRef.current;
      setGenerating(scanId);
      setError(null);
      try {
        const res = await apiGet<{ report: ReportData }>(
          `/api/reports/${scanId}`
        );
        if (seq !== genSeqRef.current) return; // réponse obsolète
        setReport(res.report);
      } catch (e) {
        if (seq !== genSeqRef.current) return; // erreur obsolète
        setReport(null);
        toast({
          title: "Erreur",
          description: getErrorMessage(e),
          variant: "destructive",
        });
      } finally {
        if (seq === genSeqRef.current) setGenerating(null);
      }
    },
    [toast]
  );

  // Ouverture dirigée depuis un scan terminé (détail de scan / vue scans).
  useEffect(() => {
    if (scanReportId) {
      void generate(scanReportId);
      onConsumeReportId?.();
    }
  }, [scanReportId, generate, onConsumeReportId]);

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-[340px_1fr]">
      {/* Colonne gauche : scans terminés */}
      <Card className="no-print h-fit lg:sticky lg:top-20">
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Scans terminés</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {loadingList ? (
            <div className="space-y-2 px-4 pb-4">
              {Array.from({ length: 4 }).map((_, i) => (
                <Skeleton key={i} className="h-14 w-full" />
              ))}
            </div>
          ) : completedScans.length === 0 ? (
            <p className="text-muted-foreground px-4 pb-4 text-sm">
              Aucun scan terminé pour le moment. Lancez une campagne puis
              attendez la fin d&apos;un scan pour générer son rapport.
            </p>
          ) : (
            <div className="max-h-[60vh] overflow-y-auto px-2 pb-2 scrollbar-slim">
              {completedScans.map((scan) => (
                <div
                  key={scan.id}
                  className="hover:bg-accent/60 flex items-center gap-3 rounded-lg p-2 transition-colors"
                >
                  <ToolBadge tool={scan.tool} small />
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-mono text-xs" title={scan.target}>
                      {scan.target}
                    </div>
                    <div className="text-muted-foreground text-[11px]">
                      {formatDateTime(scan.finishedAt ?? scan.createdAt)}
                    </div>
                  </div>
                  <Button
                    size="sm"
                    variant={report?.scan.id === scan.id ? "secondary" : "outline"}
                    className="h-9 shrink-0"
                    disabled={generating === scan.id}
                    onClick={() => void generate(scan.id)}
                  >
                    {generating === scan.id ? (
                      <Loader2 className="size-4 animate-spin" aria-hidden />
                    ) : (
                      <FileText className="size-4" aria-hidden />
                    )}
                    {report?.scan.id === scan.id ? "Régénérer" : "Générer"}
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Colonne droite : aperçu du rapport */}
      <div>
        {report ? (
          <>
            <div className="no-print mb-4 flex flex-wrap items-center justify-between gap-3">
              <p className="text-muted-foreground text-sm">
                Aperçu du rapport — utilisez « Imprimer / Exporter PDF » pour
                l&apos;archiver.
              </p>
              <Button onClick={() => window.print()} className="min-h-11">
                <Printer className="size-4" aria-hidden />
                Imprimer / Exporter PDF
              </Button>
            </div>
            <ReportDocument report={report} viewer={user.username} />
          </>
        ) : (
          <Card>
            <EmptyState
              icon={FileText}
              title="Aucun rapport généré"
              description="Sélectionnez un scan terminé pour générer un rapport"
            />
            {error && (
              <p className="text-destructive px-6 pb-6 text-center text-sm" role="alert">
                {error}
              </p>
            )}
          </Card>
        )}
      </div>
    </div>
  );
}

// ─── Document de rapport (impression formelle) ───────────────────────

function ReportDocument({
  report,
  viewer,
}: {
  report: ReportData;
  viewer: string;
}) {
  const { scan, campaign, findings, stats } = report;
  const total = findings.length;

  const sevCounts = SEVERITY_ORDER.map((sev) => ({
    severity: sev,
    count: stats.bySeverity?.[sev] ?? 0,
  }));
  const dominant = [...sevCounts]
    .sort((a, b) => b.count - a.count)
    .find((s) => s.count > 0);

  const critical = sevCounts.find((s) => s.severity === "CRITICAL")?.count ?? 0;
  const confirmed = stats.confirmedCount ?? 0;
  const sentinel = stats.sentinelCount ?? 0;

  const synthesis = buildSynthesis({
    tool: scan.tool,
    target: campaign.target,
    total,
    critical,
    confirmed,
    sentinel,
    dominantSeverity: dominant?.severity,
    dominantCount: dominant?.count,
  });

  const grouped = SEVERITY_ORDER.map((sev) => ({
    severity: sev,
    items: findings.filter((f) => f.severity === sev),
  })).filter((g) => g.items.length > 0);

  return (
    <article
      id="report-area"
      className="print-plain rounded-xl border bg-white p-6 text-zinc-900 shadow-sm sm:p-10"
      lang="fr"
    >
      {/* En-tête */}
      <header className="flex items-start justify-between gap-4 border-b-2 border-zinc-900 pb-5">
        <div className="flex items-center gap-3">
          <div
            className="flex size-12 items-center justify-center rounded-lg"
            style={{ backgroundColor: "#10b9811a", color: "#059669" }}
            aria-hidden
          >
            <Shield className="size-7" />
          </div>
          <div>
            <h2 className="text-xl font-bold tracking-tight sm:text-2xl">
              RAPPORT D&apos;AUDIT DE SÉCURITÉ
            </h2>
            <p className="text-sm text-zinc-600">{campaign.name}</p>
          </div>
        </div>
        <div className="text-right text-xs text-zinc-500">
          <div className="font-mono font-semibold text-zinc-800">AuditForge</div>
          <div>Réf. scan : {scan.id.slice(0, 8)}</div>
        </div>
      </header>

      {/* Tableau de méta-informations */}
      <table className="mt-5 w-full border-collapse text-sm">
        <tbody>
          <MetaRow label="Cible" value={campaign.target} mono />
          <MetaRow
            label="Type de cible"
            value={TARGET_TYPE_LABELS[campaign.targetType] ?? campaign.targetType}
          />
          <MetaRow label="Profil" value={PROFILE_LABELS[campaign.profile] ?? campaign.profile} />
          <MetaRow label="Outil" value={scan.tool} mono />
          <MetaRow
            label="Période"
            value={`${formatDate(scan.startedAt ?? scan.createdAt)} — ${formatDate(
              scan.finishedAt
            )} · durée ${formatDuration(scan.durationMs)}`}
          />
          <MetaRow
            label="Généré par"
            value={`${report.generatedBy || viewer} (automatique)`}
          />
          <MetaRow label="Généré le" value={formatDateTime(report.generatedAt)} />
        </tbody>
      </table>

      {/* Synthèse exécutive */}
      <section className="mt-8" aria-labelledby="report-synthesis">
        <h3 id="report-synthesis" className="text-base font-bold uppercase tracking-wide">
          Synthèse exécutive
        </h3>
        <p className="mt-2 text-sm leading-relaxed text-zinc-700">{synthesis}</p>

        <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-5">
          {sevCounts.map(({ severity, count }) => (
            <div
              key={severity}
              className="print-plain rounded-lg border p-3 text-center"
              style={{ borderColor: `${severityColor(severity)}66` }}
            >
              <div
                className="text-2xl font-bold tabular-nums print:text-zinc-900!"
                style={{ color: severityColor(severity) }}
              >
                {count}
              </div>
              <div className="print:text-zinc-700 mt-0.5 text-[11px] font-medium text-zinc-600">
                {SEVERITY_LABELS[severity]}
              </div>
            </div>
          ))}
        </div>
      </section>

      <Separator className="my-8 bg-zinc-200" />

      {/* Vulnérabilités */}
      <section aria-labelledby="report-findings">
        <h3 id="report-findings" className="text-base font-bold uppercase tracking-wide">
          Vulnérabilités ({total})
        </h3>
        {total === 0 ? (
          <p className="mt-3 text-sm text-zinc-600">
            Aucune vulnérabilité n&apos;a été relevée lors de ce scan.
          </p>
        ) : (
          grouped.map((group) => (
            <div key={group.severity} className="mt-5">
              <div className="flex items-center gap-2">
                <SeverityBadge severity={group.severity} />
                <span className="print:text-zinc-700 text-xs font-semibold text-zinc-500">
                  {group.items.length} constat(s)
                </span>
              </div>
              <div className="mt-2 space-y-3">
                {group.items.map((f, idx) => (
                  <div key={f.id} className="rounded-lg border border-zinc-300 p-4">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-bold text-zinc-900">
                        {idx + 1}. {f.title}
                      </span>
                      {f.cve && (
                        <Badge
                          variant="outline"
                          className="border-zinc-400 font-mono text-zinc-800"
                        >
                          {f.cve}
                        </Badge>
                      )}
                      <span className="ml-auto font-mono text-xs text-zinc-600">
                        CVSS {f.cvss !== null ? f.cvss.toFixed(1) : "—"}
                        {f.location ? ` · ${f.location}` : ""}
                      </span>
                    </div>
                    <p className="mt-2 text-sm leading-relaxed text-zinc-700">
                      {f.description}
                    </p>
                    {f.remediation && (
                      <p className="mt-2 rounded-md border border-emerald-300 bg-emerald-50 p-2.5 text-sm leading-relaxed text-emerald-900">
                        <span className="font-semibold">Remédiation : </span>
                        {f.remediation}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ))
        )}
      </section>

      {/* Pied du rapport */}
      <footer className="mt-10 border-t border-zinc-300 pt-4 text-center text-xs text-zinc-500">
        Rapport généré automatiquement par AuditForge — usage interne.
      </footer>
    </article>
  );
}

function MetaRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <tr className="border-b border-zinc-200">
      <th scope="row" className="w-36 py-1.5 pr-3 text-left align-top text-xs font-semibold text-zinc-500 uppercase">
        {label}
      </th>
      <td className={`py-1.5 text-sm ${mono ? "font-mono text-xs" : ""}`}>{value}</td>
    </tr>
  );
}

function buildSynthesis({
  tool,
  target,
  total,
  critical,
  confirmed,
  sentinel,
  dominantSeverity,
  dominantCount,
}: {
  tool: string;
  target: string;
  total: number;
  critical: number;
  confirmed: number;
  sentinel: number;
  dominantSeverity?: Severity;
  dominantCount?: number;
}): string {
  const parts: string[] = [];
  parts.push(
    `L'outil ${tool} a audité la cible ${target} dans le cadre de cette campagne. ` +
      (total > 0
        ? `L'exécution a permis d'identifier ${total} vulnérabilité(s).`
        : "Aucune vulnérabilité n'a été identifiée.")
  );
  if (total > 0) {
    parts.push(
      `${confirmed} constat(s) présentent une confiance confirmée` +
        (sentinel > 0
          ? `, dont ${sentinel} vérifié(s) par exécution du proof-of-concept en sandbox isolée`
          : "") +
        "."
    );
    if (dominantSeverity) {
      parts.push(
        `La sévérité dominante est « ${SEVERITY_LABELS[dominantSeverity]} » (${dominantCount} occurrence(s)).`
      );
    }
    parts.push(
      critical > 0
        ? `${critical} vulnérabilité(s) de criticité critique exigent un traitement prioritaire immédiat.`
        : "Aucune vulnérabilité critique n'a été relevée."
    );
  }
  parts.push(
    "Les recommandations de remédiation détaillées ci-dessous doivent être traitées selon la priorité des sévérités."
  );
  return parts.join(" ");
}
