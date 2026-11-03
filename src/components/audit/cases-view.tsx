"use client";

/**
 * AuditForge — Vue Dossiers (Sprint 2) : gestion des dossiers clients
 * (référence AF-…), autorisations de test signées (empreinte SHA-256),
 * campagnes rattachées et rapport client agrégé imprimable (attestation
 * d'autorisation incluse).
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Ban,
  Briefcase,
  FileSignature,
  FileText,
  Loader2,
  Lock,
  Plus,
  Printer,
  RotateCcw,
  Shield,
  ShieldCheck,
  ShieldOff,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import { Textarea } from "@/components/ui/textarea";
import { apiGet, apiPatch, apiPost, getErrorMessage } from "@/lib/api-client";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import {
  CAMPAIGN_STATUS_LABELS,
  CaseStatusBadge,
  EmptyState,
  PROFILE_LABELS,
  SEVERITY_LABELS,
  SEVERITY_ORDER,
  SeverityBadge,
  ScanStatusBadge,
  formatDateTime,
  formatDate,
  severityColor,
} from "@/components/audit/status-badges";
import type {
  CaseAuthorizationDTO,
  CaseDTO,
  CaseReportCampaign,
  CaseReportDTO,
  Severity,
  UserDTO,
} from "@/lib/types";

/** Réponse GET /api/cases/[id] — détail complet d'un dossier. */
interface CaseDetail {
  case: CaseDTO;
  authorizationHistory: CaseAuthorizationDTO[];
  campaigns: CaseReportCampaign[];
}

/** Une autorisation est expirée si sa période de validité est passée. */
function isAuthorizationExpired(a: CaseAuthorizationDTO): boolean {
  return new Date(a.validUntil).getTime() <= Date.now();
}

/** Somme des vulnérabilités des scans d'une campagne résumée. */
function campaignFindingsCount(c: CaseReportCampaign): number {
  return c.scans.reduce((n, s) => n + s.findingsCount, 0);
}

export function CasesView({
  user,
  onOpenScans,
}: {
  user: UserDTO;
  onOpenScans?: (campaignId: string) => void;
}) {
  const { toast } = useToast();
  const [cases, setCases] = useState<CaseDTO[]>([]);
  const [loadingList, setLoadingList] = useState(true);
  const [listError, setListError] = useState<string | null>(null);
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);
  const [detail, setDetail] = useState<CaseDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [report, setReport] = useState<CaseReportDTO | null>(null);
  const [generatingReport, setGeneratingReport] = useState(false);
  const [statusBusy, setStatusBusy] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [signOpen, setSignOpen] = useState(false);
  const [revokeTarget, setRevokeTarget] = useState<CaseAuthorizationDTO | null>(
    null
  );
  const [closeConfirmOpen, setCloseConfirmOpen] = useState(false);

  /** Jetons de séquence : ignorent les réponses de fetch obsolètes. */
  const listSeqRef = useRef(0);
  const detailSeqRef = useRef(0);
  const reportSeqRef = useRef(0);

  const canWrite = user.role !== "VIEWER";

  const loadList = useCallback(async () => {
    const seq = ++listSeqRef.current;
    try {
      const res = await apiGet<{ cases: CaseDTO[] }>("/api/cases");
      if (seq !== listSeqRef.current) return; // réponse obsolète
      setCases(res.cases);
    } catch (e) {
      if (seq !== listSeqRef.current) return;
      setListError(getErrorMessage(e));
    } finally {
      if (seq === listSeqRef.current) setLoadingList(false);
    }
  }, []);

  // Chargement différé d'un tick — annulé au démontage (react-hooks v6).
  useEffect(() => {
    const t = setTimeout(() => void loadList(), 0);
    return () => clearTimeout(t);
  }, [loadList]);

  const loadDetail = useCallback(async (id: string) => {
    const seq = ++detailSeqRef.current;
    setLoadingDetail(true);
    setDetailError(null);
    try {
      const res = await apiGet<CaseDetail>(`/api/cases/${id}`);
      if (seq !== detailSeqRef.current) return; // réponse obsolète
      setDetail(res);
    } catch (e) {
      if (seq !== detailSeqRef.current) return;
      setDetail(null);
      setDetailError(getErrorMessage(e));
    } finally {
      if (seq === detailSeqRef.current) setLoadingDetail(false);
    }
  }, []);

  // Détail de la sélection — différé d'un tick, annulé au démontage ou si la
  // sélection change (react-hooks v6 : aucun setState synchrone ici).
  useEffect(() => {
    if (!selectedCaseId) return;
    const t = setTimeout(() => void loadDetail(selectedCaseId), 0);
    return () => clearTimeout(t);
  }, [selectedCaseId, loadDetail]);

  /** Sélection d'un dossier : purge rapport + détail, puis chargement différé. */
  const selectCase = (id: string) => {
    if (id === selectedCaseId) return;
    setReport(null);
    setDetail(null);
    setLoadingDetail(true);
    setSelectedCaseId(id);
  };

  const onCaseCreated = useCallback(
    (created: CaseDTO) => {
      setCreateOpen(false);
      setReport(null);
      setDetail(null);
      setLoadingDetail(true);
      setSelectedCaseId(created.id);
      void loadList();
    },
    [loadList]
  );

  const generateReport = useCallback(
    async (id: string) => {
      const seq = ++reportSeqRef.current;
      setGeneratingReport(true);
      try {
        const res = await apiGet<{ report: CaseReportDTO }>(
          `/api/cases/${id}/report`
        );
        if (seq !== reportSeqRef.current) return; // réponse obsolète
        setReport(res.report);
        // Le statut du dossier peut passer REPORTED (première génération).
        void loadDetail(id);
        void loadList();
      } catch (e) {
        if (seq !== reportSeqRef.current) return; // erreur obsolète
        toast({
          title: "Erreur",
          description: getErrorMessage(e),
          variant: "destructive",
        });
      } finally {
        if (seq === reportSeqRef.current) setGeneratingReport(false);
      }
    },
    [loadDetail, loadList, toast]
  );

  const updateStatus = useCallback(
    async (id: string, status: "OPEN" | "CLOSED") => {
      setStatusBusy(true);
      try {
        await apiPatch<{ case: CaseDTO }>(`/api/cases/${id}`, { status });
        toast({
          title: status === "CLOSED" ? "Dossier clôturé" : "Dossier réouvert",
          description:
            status === "CLOSED"
              ? "Aucun lancement de campagne ne sera plus possible sur ce dossier."
              : "Le dossier accepte à nouveau les campagnes rattachées.",
        });
        void loadDetail(id);
        void loadList();
      } catch (e) {
        toast({
          title: "Erreur",
          description: getErrorMessage(e),
          variant: "destructive",
        });
      } finally {
        setStatusBusy(false);
      }
    },
    [loadDetail, loadList, toast]
  );

  const onSigned = useCallback(() => {
    setSignOpen(false);
    if (selectedCaseId) void loadDetail(selectedCaseId);
    void loadList();
  }, [loadDetail, loadList, selectedCaseId]);

  const onRevoked = useCallback(() => {
    setRevokeTarget(null);
    if (selectedCaseId) void loadDetail(selectedCaseId);
    void loadList();
  }, [loadDetail, loadList, selectedCaseId]);

  const auth = detail?.case.activeAuthorization ?? null;

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-[340px_1fr]">
      {/* ─── Colonne gauche : liste des dossiers ─────────────────────── */}
      <Card className="no-print h-fit lg:sticky lg:top-20">
        <CardHeader className="pb-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <CardTitle className="text-base">Dossiers</CardTitle>
            {canWrite && (
              <Button
                size="sm"
                className="h-11 sm:h-9"
                onClick={() => setCreateOpen(true)}
              >
                <Plus className="size-4" aria-hidden />
                Nouveau dossier
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {loadingList ? (
            <div className="space-y-2 px-4 pb-4">
              {Array.from({ length: 4 }).map((_, i) => (
                <Skeleton key={i} className="h-16 w-full" />
              ))}
            </div>
          ) : cases.length === 0 ? (
            <p className="text-muted-foreground px-4 pb-4 text-sm">
              Aucun dossier pour le moment. Créez le premier dossier client
              pour rattacher des campagnes et générer un rapport client.
            </p>
          ) : (
            <div className="max-h-[60vh] overflow-y-auto px-2 pb-2 scrollbar-slim">
              {cases.map((c) => (
                <button
                  key={c.id}
                  type="button"
                  onClick={() => selectCase(c.id)}
                  aria-current={selectedCaseId === c.id ? "true" : undefined}
                  className={cn(
                    "flex w-full flex-col gap-1 rounded-lg p-2.5 text-left transition-colors",
                    selectedCaseId === c.id
                      ? "bg-accent"
                      : "hover:bg-accent/60"
                  )}
                >
                  <span className="flex items-center gap-2">
                    <span className="text-muted-foreground font-mono text-xs">
                      {c.reference}
                    </span>
                    <CaseStatusBadge status={c.status} className="ml-auto" />
                  </span>
                  <span className="truncate text-sm font-medium">{c.title}</span>
                  <span className="text-muted-foreground truncate text-xs">
                    {c.client}
                  </span>
                  <span className="text-muted-foreground flex items-center gap-1.5 text-[11px] tabular-nums">
                    {c.campaignsCount} camp. · {c.findingsCount} vuln.
                    {c.criticalCount > 0 && (
                      <span
                        className="inline-block size-1.5 shrink-0 rounded-full"
                        style={{ backgroundColor: "#f43f5e" }}
                        title={`${c.criticalCount} vulnérabilité(s) critique(s)`}
                        aria-label={`${c.criticalCount} vulnérabilité(s) critique(s)`}
                      />
                    )}
                    {c.activeAuthorization && (
                      <span
                        className="inline-block size-1.5 shrink-0 rounded-full"
                        style={{ backgroundColor: "#10b981" }}
                        title="Autorisation active"
                        aria-label="Autorisation active"
                      />
                    )}
                  </span>
                </button>
              ))}
            </div>
          )}
          {listError && (
            <p className="text-destructive px-4 pb-4 text-sm" role="alert">
              {listError}
            </p>
          )}
        </CardContent>
      </Card>

      {/* ─── Colonne droite : détail du dossier ──────────────────────── */}
      <div className="space-y-4">
        {!selectedCaseId ? (
          <Card className="no-print">
            <EmptyState
              icon={Briefcase}
              title="Aucun dossier sélectionné"
              description="Sélectionnez un dossier dans la liste pour consulter son autorisation de test, ses campagnes rattachées et générer son rapport client."
            />
          </Card>
        ) : loadingDetail && !detail ? (
          <Card className="no-print">
            <CardContent className="space-y-3 p-6">
              <Skeleton className="h-7 w-2/3" />
              <Skeleton className="h-4 w-1/3" />
              <Skeleton className="h-20 w-full" />
              <Skeleton className="h-32 w-full" />
            </CardContent>
          </Card>
        ) : detailError ? (
          <Card className="no-print">
            <EmptyState
              icon={Briefcase}
              title="Impossible de charger le dossier"
              description={detailError}
            />
          </Card>
        ) : detail ? (
          <>
            {/* 1. En-tête du dossier */}
            <Card className="no-print">
              <CardHeader className="space-y-2 pb-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0 space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-muted-foreground font-mono text-xs">
                        {detail.case.reference}
                      </span>
                      <CaseStatusBadge status={detail.case.status} />
                    </div>
                    <CardTitle className="text-lg leading-snug">
                      {detail.case.title}
                    </CardTitle>
                  </div>
                  {canWrite && (
                    <div className="flex flex-wrap items-center gap-2">
                      <Button
                        className="h-11 sm:h-9"
                        disabled={generatingReport}
                        onClick={() => void generateReport(detail.case.id)}
                      >
                        {generatingReport ? (
                          <Loader2 className="size-4 animate-spin" aria-hidden />
                        ) : (
                          <FileText className="size-4" aria-hidden />
                        )}
                        Générer le rapport client
                      </Button>
                      {detail.case.status === "CLOSED" ? (
                        <Button
                          variant="outline"
                          className="h-11 sm:h-9"
                          disabled={statusBusy}
                          onClick={() =>
                            void updateStatus(detail.case.id, "OPEN")
                          }
                        >
                          {statusBusy ? (
                            <Loader2 className="size-4 animate-spin" aria-hidden />
                          ) : (
                            <RotateCcw className="size-4" aria-hidden />
                          )}
                          Réouvrir
                        </Button>
                      ) : (
                        <Button
                          variant="outline"
                          className="h-11 sm:h-9"
                          disabled={statusBusy}
                          onClick={() => setCloseConfirmOpen(true)}
                        >
                          <Lock className="size-4" aria-hidden />
                          Clôturer le dossier
                        </Button>
                      )}
                    </div>
                  )}
                </div>
                <CardDescription className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
                  <span>
                    Client :{" "}
                    <span className="text-foreground font-medium">
                      {detail.case.client}
                    </span>
                  </span>
                  {detail.case.contact && (
                    <span>Contact : {detail.case.contact}</span>
                  )}
                </CardDescription>
                <CardDescription className="text-xs">
                  Créé le {formatDateTime(detail.case.createdAt)} par{" "}
                  {detail.case.createdByName || "—"}
                </CardDescription>
                {detail.case.description && (
                  <CardDescription className="text-xs leading-relaxed whitespace-pre-wrap">
                    {detail.case.description}
                  </CardDescription>
                )}
              </CardHeader>
            </Card>

            {/* 2. Autorisation de test */}
            <Card
              className={cn(
                "no-print",
                auth ? "border-emerald-500/30" : "border-amber-500/30"
              )}
            >
              <CardHeader className="pb-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <CardTitle className="text-base">
                    Autorisation de test
                  </CardTitle>
                  {auth ? (
                    <Badge
                      variant="outline"
                      className="border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
                    >
                      Active
                    </Badge>
                  ) : (
                    <Badge
                      variant="outline"
                      className="border-amber-500/40 bg-amber-500/10 text-amber-400"
                    >
                      Aucune
                    </Badge>
                  )}
                </div>
              </CardHeader>
              <CardContent className="space-y-4 pt-0">
                {auth ? (
                  <div className="border-emerald-500/30 bg-emerald-500/5 space-y-3 rounded-lg border p-4">
                    <div className="flex items-center gap-2 text-sm font-medium text-emerald-300">
                      <ShieldCheck className="size-4 shrink-0" aria-hidden />
                      Attestation signée couvrant le périmètre ci-dessous
                    </div>
                    <div className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-2">
                      <div>
                        <p className="text-muted-foreground text-xs">
                          Signataire
                        </p>
                        <p className="font-medium">
                          {auth.signatory}{" "}
                          <span className="text-muted-foreground font-normal">
                            ({auth.signatoryRole})
                          </span>
                        </p>
                      </div>
                      <div>
                        <p className="text-muted-foreground text-xs">Validité</p>
                        <p className="font-medium">
                          {formatDate(auth.validFrom)} →{" "}
                          {formatDate(auth.validUntil)}
                        </p>
                      </div>
                      <div className="sm:col-span-2">
                        <p className="text-muted-foreground text-xs">
                          Périmètre autorisé (scope)
                        </p>
                        <p className="leading-relaxed whitespace-pre-wrap">
                          {auth.scope}
                        </p>
                      </div>
                      <div className="sm:col-span-2">
                        <p className="text-muted-foreground text-xs">
                          Hôtes autorisés
                        </p>
                        <div className="mt-1 flex flex-wrap gap-1.5">
                          {auth.targets.map((t) => (
                            <Badge
                              key={t}
                              variant="outline"
                              className="font-mono text-[11px] font-normal"
                            >
                              {t}
                            </Badge>
                          ))}
                        </div>
                      </div>
                      <div className="sm:col-span-2">
                        <p className="text-muted-foreground text-xs">
                          Empreinte de signature (SHA-256)
                        </p>
                        <p
                          className="truncate font-mono text-xs"
                          title={auth.signature}
                        >
                          {auth.signature}
                        </p>
                      </div>
                    </div>
                    {canWrite && (
                      <div className="flex justify-end">
                        <Button
                          variant="outline"
                          className="h-11 border-rose-500/40 text-rose-400 hover:bg-rose-500/10 hover:text-rose-300 sm:h-9"
                          onClick={() => setRevokeTarget(auth)}
                        >
                          <Ban className="size-4" aria-hidden />
                          Révoquer
                        </Button>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="border-amber-500/40 bg-amber-500/5 flex flex-col gap-3 rounded-lg border p-4 sm:flex-row sm:items-center sm:justify-between">
                    <div className="flex items-start gap-2.5">
                      <ShieldOff
                        className="mt-0.5 size-4 shrink-0 text-amber-400"
                        aria-hidden
                      />
                      <div>
                        <p className="text-sm font-medium text-amber-300">
                          Aucune autorisation active — le lancement de
                          campagnes rattachées est bloqué
                        </p>
                        <p className="text-muted-foreground mt-1 text-xs">
                          Signez une attestation (horodatée, empreinte
                          SHA-256) couvrant les hôtes du périmètre pour
                          débloquer les lancements.
                        </p>
                      </div>
                    </div>
                    {canWrite && (
                      <Button
                        className="h-11 shrink-0 sm:h-9"
                        onClick={() => setSignOpen(true)}
                      >
                        <FileSignature className="size-4" aria-hidden />
                        Signer une autorisation
                      </Button>
                    )}
                  </div>
                )}

                {/* Historique des autorisations (traçabilité) */}
                {detail.authorizationHistory.length > 0 && (
                  <>
                    <Separator />
                    <div>
                      <p className="text-muted-foreground text-xs font-semibold tracking-wide uppercase">
                        Historique ({detail.authorizationHistory.length})
                      </p>
                      <div className="mt-2 max-h-40 space-y-1.5 overflow-y-auto pr-1 scrollbar-slim">
                        {detail.authorizationHistory.map((a) => (
                          <div
                            key={a.id}
                            className="flex flex-wrap items-center gap-2 rounded-md border px-2.5 py-1.5 text-xs"
                          >
                            <span className="text-muted-foreground tabular-nums">
                              {formatDateTime(a.signedAt)}
                            </span>
                            <span className="min-w-0 max-w-40 truncate font-medium">
                              {a.signatory}
                            </span>
                            <span className="text-muted-foreground truncate">
                              ({a.signatoryRole})
                            </span>
                            {a.revokedAt ? (
                              <Badge
                                variant="outline"
                                className="ml-auto border-rose-500/40 bg-rose-500/10 text-rose-400"
                              >
                                Révoquée
                              </Badge>
                            ) : isAuthorizationExpired(a) ? (
                              <Badge
                                variant="outline"
                                className="ml-auto border-amber-500/40 bg-amber-500/10 text-amber-400"
                              >
                                Expirée
                              </Badge>
                            ) : (
                              <Badge
                                variant="outline"
                                className="ml-auto border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
                              >
                                Active
                              </Badge>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  </>
                )}
              </CardContent>
            </Card>

            {/* 3. Campagnes rattachées */}
            <Card className="no-print">
              <CardHeader className="pb-3">
                <CardTitle className="text-base">
                  Campagnes rattachées
                </CardTitle>
                <CardDescription className="text-xs">
                  {detail.campaigns.length} campagne(s) — le lancement exige
                  une autorisation active couvrant la cible.
                </CardDescription>
              </CardHeader>
              <CardContent className="pt-0">
                {detail.campaigns.length === 0 ? (
                  <p className="text-muted-foreground text-sm">
                    Aucune campagne rattachée — créez-en une depuis l&apos;onglet
                    Campagnes (sélecteur « Dossier client »).
                  </p>
                ) : (
                  <div className="space-y-2">
                    {detail.campaigns.map((c) => (
                      <div
                        key={c.id}
                        className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-lg border p-3"
                      >
                        <div className="min-w-0 basis-48 flex-1">
                          <div className="truncate text-sm font-medium">
                            {c.name}
                          </div>
                          <div className="text-muted-foreground truncate font-mono text-xs">
                            {c.target}
                          </div>
                        </div>
                        <div className="flex flex-wrap items-center gap-1.5">
                          <Badge
                            variant="outline"
                            className="text-[11px] font-normal"
                          >
                            {PROFILE_LABELS[c.profile] ?? c.profile}
                          </Badge>
                          <ScanStatusBadge status={c.status} />
                        </div>
                        <span className="text-muted-foreground text-xs tabular-nums">
                          {c.scans.length} scans · {campaignFindingsCount(c)}{" "}
                          vuln.
                        </span>
                        <Button
                          variant="outline"
                          size="sm"
                          className="ml-auto h-11 sm:h-9"
                          onClick={() => onOpenScans?.(c.id)}
                          aria-label={`Voir les scans de la campagne ${c.name}`}
                        >
                          Voir les scans
                        </Button>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* 4. Rapport client imprimable */}
            {report && (
              <>
                <div className="no-print flex flex-wrap items-center justify-between gap-3">
                  <p className="text-muted-foreground text-sm">
                    Aperçu du rapport client — « Imprimer / Exporter PDF »
                    pour l&apos;archiver ou le transmettre.
                  </p>
                  <Button onClick={() => window.print()} className="min-h-11">
                    <Printer className="size-4" aria-hidden />
                    Imprimer / Exporter PDF
                  </Button>
                </div>
                <CaseReportDocument report={report} />
              </>
            )}
          </>
        ) : null}
      </div>

      {/* ─── Dialogue de création de dossier ─────────────────────────── */}
      <CreateCaseDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onCreated={onCaseCreated}
      />

      {/* ─── Dialogue de signature d'autorisation ────────────────────── */}
      {detail && (
        <SignAuthorizationDialog
          caseId={detail.case.id}
          open={signOpen}
          onOpenChange={setSignOpen}
          onSigned={onSigned}
        />
      )}

      {/* ─── Dialogue de révocation (motif optionnel) ────────────────── */}
      {detail && (
        <RevokeAuthorizationDialog
          caseId={detail.case.id}
          authorization={revokeTarget}
          onOpenChange={(o) => !o && setRevokeTarget(null)}
          onRevoked={onRevoked}
        />
      )}

      {/* ─── Confirmation de clôture ─────────────────────────────────── */}
      <AlertDialog open={closeConfirmOpen} onOpenChange={setCloseConfirmOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              Clôturer le dossier {detail?.case.reference ?? ""} ?
            </AlertDialogTitle>
            <AlertDialogDescription>
              Un dossier clôturé n&apos;accepte plus aucun lancement de
              campagne ni nouvelle signature d&apos;autorisation. Le rapport
              client reste consultable. Vous pourrez le réouvrir à tout
              moment.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="min-h-10">Annuler</AlertDialogCancel>
            <AlertDialogAction
              className="min-h-10"
              disabled={statusBusy}
              onClick={() => {
                setCloseConfirmOpen(false);
                if (detail) void updateStatus(detail.case.id, "CLOSED");
              }}
            >
              Clôturer le dossier
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

// ─── Dialogue : création d'un dossier ─────────────────────────────────

function CreateCaseDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: (created: CaseDTO) => void;
}) {
  const { toast } = useToast();
  const [title, setTitle] = useState("");
  const [client, setClient] = useState("");
  const [contact, setContact] = useState("");
  const [description, setDescription] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const reset = () => {
    setTitle("");
    setClient("");
    setContact("");
    setDescription("");
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim() || !client.trim()) return;
    setSubmitting(true);
    try {
      const res = await apiPost<{ case: CaseDTO }>("/api/cases", {
        title: title.trim(),
        client: client.trim(),
        contact: contact.trim() || undefined,
        description: description.trim() || undefined,
      });
      toast({
        title: "Dossier créé",
        description: `Référence ${res.case.reference} — ${res.case.client}.`,
      });
      reset();
      onCreated(res.case);
    } catch (err) {
      toast({
        title: "Erreur",
        description: getErrorMessage(err),
        variant: "destructive",
      });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[92vh] overflow-y-auto scrollbar-slim sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Nouveau dossier client</DialogTitle>
          <DialogDescription>
            La référence client (AF-…) est générée automatiquement. Le dossier
            démarre au statut « Ouvert ».
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="case-title">Intitulé du dossier *</Label>
            <Input
              id="case-title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="ex. Audit de sécurité annuel — portail intranet"
              required
              maxLength={120}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="case-client">Client *</Label>
            <Input
              id="case-client"
              value={client}
              onChange={(e) => setClient(e.target.value)}
              placeholder="ex. Société Exemple SAS"
              required
              maxLength={120}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="case-contact">Contact côté client</Label>
            <Input
              id="case-contact"
              value={contact}
              onChange={(e) => setContact(e.target.value)}
              placeholder="ex. Mme Durand — RSSI"
              maxLength={160}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="case-description">Description</Label>
            <Textarea
              id="case-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Contexte, objectifs, contraintes…"
              rows={3}
              maxLength={1000}
            />
          </div>
          <DialogFooter>
            <Button
              type="button"
              variant="ghost"
              className="min-h-10"
              onClick={() => onOpenChange(false)}
            >
              Annuler
            </Button>
            <Button
              type="submit"
              className="min-h-10"
              disabled={submitting || !title.trim() || !client.trim()}
            >
              {submitting && <Loader2 className="size-4 animate-spin" aria-hidden />}
              {submitting ? "Création…" : "Créer le dossier"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

// ─── Dialogue : signature d'une autorisation de test ──────────────────

function SignAuthorizationDialog({
  caseId,
  open,
  onOpenChange,
  onSigned,
}: {
  caseId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSigned: () => void;
}) {
  const { toast } = useToast();
  const [signatory, setSignatory] = useState("");
  const [signatoryRole, setSignatoryRole] = useState("");
  const [scope, setScope] = useState("");
  const [targetsText, setTargetsText] = useState("");
  const [validFrom, setValidFrom] = useState("");
  const [validUntil, setValidUntil] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const reset = () => {
    setSignatory("");
    setSignatoryRole("");
    setScope("");
    setTargetsText("");
    setValidFrom("");
    setValidUntil("");
  };

  const targets = targetsText
    .split(/[\n,]+/)
    .map((t) => t.trim())
    .filter(Boolean);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (
      !signatory.trim() ||
      !signatoryRole.trim() ||
      !scope.trim() ||
      targets.length === 0 ||
      !validUntil
    ) {
      return;
    }
    setSubmitting(true);
    try {
      await apiPost<{ authorization: CaseAuthorizationDTO }>(
        `/api/cases/${caseId}/authorizations`,
        {
          signatory: signatory.trim(),
          signatoryRole: signatoryRole.trim(),
          scope: scope.trim(),
          targets,
          ...(validFrom
            ? { validFrom: new Date(`${validFrom}T00:00:00`).toISOString() }
            : {}),
          validUntil: new Date(`${validUntil}T23:59:59`).toISOString(),
        }
      );
      toast({
        title: "Autorisation signée",
        description:
          "L'attestation (empreinte SHA-256) est enregistrée — les campagnes rattachées peuvent être lancées sur le périmètre.",
      });
      reset();
      onSigned();
    } catch (err) {
      toast({
        title: "Erreur",
        description: getErrorMessage(err),
        variant: "destructive",
      });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[92vh] overflow-y-auto scrollbar-slim sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Signer une autorisation de test</DialogTitle>
          <DialogDescription>
            L&apos;attestation est horodatée et scellée par une empreinte
            SHA-256. Elle engage le signataire sur le périmètre et la période
            déclarés.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} className="space-y-4">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="auth-signatory">Signataire *</Label>
              <Input
                id="auth-signatory"
                value={signatory}
                onChange={(e) => setSignatory(e.target.value)}
                placeholder="ex. Claire Durand"
                required
                minLength={2}
                maxLength={120}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="auth-signatory-role">Fonction du signataire *</Label>
              <Input
                id="auth-signatory-role"
                value={signatoryRole}
                onChange={(e) => setSignatoryRole(e.target.value)}
                placeholder="ex. RSSI — Société Exemple SAS"
                required
                minLength={2}
                maxLength={120}
              />
            </div>
          </div>
          <div className="space-y-2">
            <Label htmlFor="auth-scope">Périmètre autorisé (scope) *</Label>
            <Textarea
              id="auth-scope"
              value={scope}
              onChange={(e) => setScope(e.target.value)}
              placeholder="ex. Audit de sécurité offensive du portail client — tests d'intrusion applicatifs et infrastructure exposée"
              rows={3}
              required
              minLength={5}
              maxLength={1000}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="auth-targets">Hôtes autorisés *</Label>
            <Textarea
              id="auth-targets"
              value={targetsText}
              onChange={(e) => setTargetsText(e.target.value)}
              placeholder={"exemple.com\n*.exemple.com\n(un hôte par ligne ou séparés par des virgules)"}
              rows={3}
              required
            />
            <p className="text-muted-foreground text-xs">
              Nom d&apos;hôte exact ou joker « *.domaine » — ni IP, ni URL, ni
              chemin. Maximum 20 hôtes.
            </p>
          </div>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="auth-valid-from">Valide à partir du</Label>
              <Input
                id="auth-valid-from"
                type="date"
                value={validFrom}
                onChange={(e) => setValidFrom(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="auth-valid-until">Valide jusqu&apos;au *</Label>
              <Input
                id="auth-valid-until"
                type="date"
                value={validUntil}
                onChange={(e) => setValidUntil(e.target.value)}
                required
              />
            </div>
          </div>
          <DialogFooter>
            <Button
              type="button"
              variant="ghost"
              className="min-h-10"
              onClick={() => onOpenChange(false)}
            >
              Annuler
            </Button>
            <Button
              type="submit"
              className="min-h-10"
              disabled={
                submitting ||
                !signatory.trim() ||
                !signatoryRole.trim() ||
                !scope.trim() ||
                targets.length === 0 ||
                !validUntil
              }
            >
              {submitting && <Loader2 className="size-4 animate-spin" aria-hidden />}
              {submitting ? "Signature…" : "Signer l'autorisation"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

// ─── Dialogue : révocation d'une autorisation ─────────────────────────

function RevokeAuthorizationDialog({
  caseId,
  authorization,
  onOpenChange,
  onRevoked,
}: {
  caseId: string;
  authorization: CaseAuthorizationDTO | null;
  onOpenChange: (open: boolean) => void;
  onRevoked: () => void;
}) {
  const { toast } = useToast();
  const [reason, setReason] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const submit = async () => {
    if (!authorization) return;
    setSubmitting(true);
    try {
      await apiPost<{ authorization: CaseAuthorizationDTO }>(
        `/api/cases/${caseId}/authorizations/${authorization.id}/revoke`,
        { reason: reason.trim() || undefined }
      );
      toast({
        title: "Autorisation révoquée",
        description: `L'attestation signée par ${authorization.signatory} n'est plus valide — les lancements sont bloqués.`,
      });
      setReason("");
      onRevoked();
    } catch (err) {
      toast({
        title: "Erreur",
        description: getErrorMessage(err),
        variant: "destructive",
      });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog open={authorization !== null} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Révoquer cette autorisation ?</DialogTitle>
          <DialogDescription>
            L&apos;attestation signée par {authorization?.signatory ?? "—"}{" "}
            cessera d&apos;être valide immédiatement : tout nouveau lancement
            de campagne rattachée sera refusé jusqu&apos;à la signature
            d&apos;une nouvelle autorisation.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-2">
          <Label htmlFor="revoke-reason">Motif de révocation (optionnel)</Label>
          <Input
            id="revoke-reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="ex. Périmètre renégocié, mission terminée"
            maxLength={300}
          />
        </div>
        <DialogFooter>
          <Button
            type="button"
            variant="ghost"
            className="min-h-10"
            onClick={() => onOpenChange(false)}
          >
            Annuler
          </Button>
          <Button
            type="button"
            variant="destructive"
            className="min-h-10"
            disabled={submitting}
            onClick={() => void submit()}
          >
            {submitting ? (
              <Loader2 className="size-4 animate-spin" aria-hidden />
            ) : (
              <Ban className="size-4" aria-hidden />
            )}
            {submitting ? "Révocation…" : "Révoquer l'autorisation"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Document : rapport client imprimable ─────────────────────────────

function CaseReportDocument({ report }: { report: CaseReportDTO }) {
  const { caseInfo, authorization: auth, campaigns, findings, stats } = report;
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
  const targetsCount = new Set(campaigns.map((c) => c.target)).size;

  const synthesis = buildCaseSynthesis({
    reference: caseInfo.reference,
    campaignsCount: campaigns.length,
    targetsCount,
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
      id="case-report-area"
      className="print-plain rounded-xl border bg-white p-6 text-zinc-900 shadow-sm sm:p-10"
      lang="fr"
    >
      {/* En-tête */}
      <header className="flex items-start justify-between gap-4 border-b-2 border-zinc-900 pb-5">
        <div className="flex items-center gap-3">
          <div
            className="flex size-12 shrink-0 items-center justify-center rounded-lg"
            style={{ backgroundColor: "#10b9811a", color: "#059669" }}
            aria-hidden
          >
            <Shield className="size-7" />
          </div>
          <div className="min-w-0">
            <h2 className="text-xl font-bold tracking-tight sm:text-2xl">
              RAPPORT D&apos;AUDIT DE SÉCURITÉ — DOSSIER {caseInfo.reference}
            </h2>
            <p className="mt-0.5 text-sm text-zinc-600">{caseInfo.title}</p>
          </div>
        </div>
        <div className="shrink-0 text-right text-xs text-zinc-500">
          <div className="font-mono font-semibold text-zinc-800">AuditForge</div>
          <div>Réf. dossier : {caseInfo.reference}</div>
        </div>
      </header>

      {/* Tableau de méta-informations */}
      <table className="mt-5 w-full border-collapse text-sm">
        <tbody>
          <MetaRow label="Client" value={caseInfo.client} />
          <MetaRow label="Contact" value={caseInfo.contact ?? "—"} />
          <MetaRow
            label="Périmètre autorisé"
            value={auth?.scope ?? "Aucune autorisation active"}
          />
          <MetaRow
            label="Signataire"
            value={auth ? `${auth.signatory} (${auth.signatoryRole})` : "—"}
          />
          <MetaRow
            label="Hôtes autorisés"
            value={auth ? auth.targets.join(", ") : "—"}
          />
          <MetaRow
            label="Validité"
            value={
              auth
                ? `${formatDate(auth.validFrom)} → ${formatDate(auth.validUntil)}`
                : "—"
            }
          />
          <MetaRow label="Empreinte autorisation" value={auth?.signature ?? "—"} mono />
          <MetaRow label="Généré par" value={`${report.generatedBy} (automatique)`} />
          <MetaRow label="Généré le" value={formatDateTime(report.generatedAt)} />
        </tbody>
      </table>

      {/* Synthèse exécutive */}
      <section className="mt-8" aria-labelledby="case-report-synthesis">
        <h3
          id="case-report-synthesis"
          className="text-base font-bold tracking-wide uppercase"
        >
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

      {/* Campagnes */}
      <section aria-labelledby="case-report-campaigns">
        <h3
          id="case-report-campaigns"
          className="text-base font-bold tracking-wide uppercase"
        >
          Campagnes ({campaigns.length})
        </h3>
        {campaigns.length === 0 ? (
          <p className="mt-3 text-sm text-zinc-600">
            Aucune campagne rattachée à ce dossier.
          </p>
        ) : (
          <table className="mt-3 w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-zinc-300 text-left text-[11px] font-semibold tracking-wide text-zinc-500 uppercase">
                <th scope="col" className="py-1.5 pr-3">Campagne</th>
                <th scope="col" className="py-1.5 pr-3">Cible</th>
                <th scope="col" className="py-1.5 pr-3">Profil</th>
                <th scope="col" className="py-1.5 pr-3">Statut</th>
                <th scope="col" className="py-1.5 pr-3 text-right">Scans</th>
                <th scope="col" className="py-1.5 text-right">Vulnérabilités</th>
              </tr>
            </thead>
            <tbody>
              {campaigns.map((c) => (
                <tr key={c.id} className="border-b border-zinc-200">
                  <td className="py-1.5 pr-3 font-medium">{c.name}</td>
                  <td className="py-1.5 pr-3 font-mono text-xs">{c.target}</td>
                  <td className="py-1.5 pr-3 text-xs">
                    {PROFILE_LABELS[c.profile] ?? c.profile}
                  </td>
                  <td className="py-1.5 pr-3 text-xs">
                    {CAMPAIGN_STATUS_LABELS[c.status] ?? c.status}
                  </td>
                  <td className="py-1.5 pr-3 text-right tabular-nums">
                    {c.scans.length}
                  </td>
                  <td className="py-1.5 text-right tabular-nums">
                    {campaignFindingsCount(c)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <Separator className="my-8 bg-zinc-200" />

      {/* Vulnérabilités */}
      <section aria-labelledby="case-report-findings">
        <h3
          id="case-report-findings"
          className="text-base font-bold tracking-wide uppercase"
        >
          Vulnérabilités ({total})
        </h3>
        {total === 0 ? (
          <p className="mt-3 text-sm text-zinc-600">
            Aucune vulnérabilité n&apos;a été relevée sur le périmètre de ce
            dossier.
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

      {/* Attestation */}
      <section className="mt-8" aria-labelledby="case-report-attestation">
        <h3
          id="case-report-attestation"
          className="text-base font-bold tracking-wide uppercase"
        >
          Attestation
        </h3>
        {auth ? (
          <div className="print-plain mt-3 rounded-lg border border-zinc-400 bg-zinc-50 p-4">
            <p className="text-sm leading-relaxed text-zinc-800">
              <span className="font-semibold">
                Test intrusif réalisé dans le périmètre autorisé ci-dessus
              </span>
              , sur délégation de {auth.signatory} ({auth.signatoryRole}) —
              autorisation signée le {formatDate(auth.signedAt)}.
            </p>
            <p
              className="mt-2 font-mono text-[10px] break-all text-zinc-600"
              title="Empreinte SHA-256 de l'attestation canonique"
            >
              Empreinte SHA-256 : {auth.signature}
            </p>
          </div>
        ) : (
          <div className="print-plain mt-3 rounded-lg border border-zinc-400 bg-zinc-50 p-4">
            <p className="text-sm leading-relaxed text-zinc-700">
              Aucune autorisation active au moment de la génération de ce
              rapport — aucun test intrusif n&apos;aurait dû être réalisé sans
              attestation signée au préalable.
            </p>
          </div>
        )}
      </section>

      {/* Pied du rapport */}
      <footer className="mt-10 border-t border-zinc-300 pt-4 text-center text-xs text-zinc-500">
        Rapport généré automatiquement par AuditForge — communication client
        autorisée après relecture.
      </footer>
    </article>
  );
}

function MetaRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <tr className="border-b border-zinc-200">
      <th
        scope="row"
        className="w-36 py-1.5 pr-3 text-left align-top text-xs font-semibold text-zinc-500 uppercase"
      >
        {label}
      </th>
      <td className={`py-1.5 text-sm ${mono ? "font-mono text-xs" : ""}`}>
        {value}
      </td>
    </tr>
  );
}

/** Synthèse exécutive du dossier — mêmes phrases que le rapport de scan. */
function buildCaseSynthesis({
  reference,
  campaignsCount,
  targetsCount,
  total,
  critical,
  confirmed,
  sentinel,
  dominantSeverity,
  dominantCount,
}: {
  reference: string;
  campaignsCount: number;
  targetsCount: number;
  total: number;
  critical: number;
  confirmed: number;
  sentinel: number;
  dominantSeverity?: Severity;
  dominantCount?: number;
}): string {
  const parts: string[] = [];
  parts.push(
    `Le dossier ${reference} regroupe ${campaignsCount} campagne(s) d'audit couvrant ${targetsCount} cible(s). ` +
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
