"use client";

/**
 * AuditForge — Vue Scans : liste filtrable avec mise à jour temps réel
 * (fusion locale des événements scan:update / scan:done, sans rechargement).
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Eye,
  FileText,
  Loader2,
  Radar,
  Square,
  X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { apiGet, apiPost, getErrorMessage } from "@/lib/api-client";
import { useScanEvents } from "@/hooks/use-socket";
import { useToast } from "@/hooks/use-toast";
import {
  EmptyState,
  ScanStatusBadge,
  SeverityBadge,
  ToolBadge,
  formatDuration,
} from "@/components/audit/status-badges";
import type {
  ScanDTO,
  UserDTO,
} from "@/lib/types";

const STATUS_FILTERS: { value: string; label: string }[] = [
  { value: "all", label: "Tous les statuts" },
  { value: "QUEUED", label: "En file" },
  { value: "RUNNING", label: "En cours" },
  { value: "COMPLETED", label: "Terminé" },
  { value: "FAILED", label: "Échec" },
  { value: "CANCELLED", label: "Annulé" },
];

export function ScansView({
  user,
  onOpenScan,
  initialCampaignId,
  onClearCampaign,
  onOpenReport,
}: {
  user: UserDTO;
  onOpenScan: (scanId: string) => void;
  initialCampaignId?: string | null;
  onClearCampaign?: () => void;
  onOpenReport?: (scanId: string) => void;
}) {
  const { toast } = useToast();
  const [scans, setScans] = useState<ScanDTO[]>([]);
  const [campaignNames, setCampaignNames] = useState<
    { id: string; name: string }[]
  >([]);
  const [loading, setLoading] = useState(true);
  const [campaignFilter, setCampaignFilter] = useState<string>(
    initialCampaignId ?? "all"
  );
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [cancellingId, setCancellingId] = useState<string | null>(null);
  const refetchTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  /** Jeton de séquence : annule les réponses de fetch obsolètes. */
  const seqRef = useRef(0);
  /** Ids des scans affichés (lecture HORS updater pour rester pur). */
  const knownIdsRef = useRef<Set<string>>(new Set());

  // Synchronise le filtre de campagne quand il change depuis l'extérieur.
  useEffect(() => {
    if (initialCampaignId) setCampaignFilter(initialCampaignId);
  }, [initialCampaignId]);

  const load = useCallback(async () => {
    const seq = ++seqRef.current;
    try {
      const params = new URLSearchParams();
      if (campaignFilter !== "all") {
        params.set("campaignId", campaignFilter);
      }
      if (statusFilter !== "all") {
        params.set("status", statusFilter);
      }
      const qs = params.toString();
      const res = await apiGet<{ scans: ScanDTO[] }>(
        `/api/scans${qs ? `?${qs}` : ""}`
      );
      if (seq !== seqRef.current) return; // réponse obsolète
      setScans(res.scans);
      knownIdsRef.current = new Set(res.scans.map((s) => s.id));
    } catch (e) {
      toast({
        title: "Erreur",
        description: getErrorMessage(e),
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  }, [campaignFilter, statusFilter, toast]);

  useEffect(() => {
    void load();
  }, [load]);

  // Liste des campagnes (pour le filtre).
  useEffect(() => {
    void (async () => {
      try {
        const res = await apiGet<{
          campaigns: { id: string; name: string }[];
        }>("/api/campaigns");
        setCampaignNames(
          res.campaigns.map((c) => ({ id: c.id, name: c.name }))
        );
      } catch {
        // Silencieux : le filtre de campagne reste utilisable sans noms.
      }
    })();
  }, []);

  // Temps réel : fusion locale des mises à jour (scan:update / scan:done).
  useScanEvents((ev) => {
    // Les événements de log/finding ne concernent pas cette liste.
    if ("log" in ev || "finding" in ev) return;

    const isUpdate = "progress" in ev;

    // Détection du scan inconnu HORS de l'updater (lecture du ref) :
    // refetch différé pour respecter les filtres en vigueur.
    if (!knownIdsRef.current.has(ev.scanId)) {
      if (refetchTimer.current) clearTimeout(refetchTimer.current);
      refetchTimer.current = setTimeout(() => void load(), 1200);
      return;
    }

    setScans((prev) =>
      prev.map((s) => {
        if (s.id !== ev.scanId) return s;
        // FAILED/CANCELLED : on conserve la progression réellement reçue
        // (le payload scan:done ne porte pas de progression).
        const keepProgress = !isUpdate && ev.status !== "COMPLETED";
        return {
          ...s,
          status: ev.status,
          progress: keepProgress ? s.progress : isUpdate ? ev.progress : 100,
          phase: (isUpdate ? ev.phase : "") || s.phase,
          findingsCount: ev.findingsCount,
          criticalCount: ev.criticalCount,
          ...(ev.status === "RUNNING" && !s.startedAt
            ? { startedAt: new Date().toISOString() }
            : {}),
          ...(!isUpdate
            ? { finishedAt: s.finishedAt ?? new Date().toISOString() }
            : {}),
        };
      })
    );
  });

  useEffect(
    () => () => {
      if (refetchTimer.current) clearTimeout(refetchTimer.current);
    },
    []
  );

  const cancel = async (scan: ScanDTO) => {
    setCancellingId(scan.id);
    try {
      await apiPost<{ scan: ScanDTO }>(`/api/scans/${scan.id}/cancel`);
      toast({
        title: "Scan annulé",
        description: `Le scan ${scan.tool} a été annulé.`,
      });
      void load();
    } catch (e) {
      toast({
        title: "Erreur",
        description: getErrorMessage(e),
        variant: "destructive",
      });
    } finally {
      setCancellingId(null);
    }
  };

  const canWrite = user.role !== "VIEWER";
  const campaignName = (id: string) =>
    campaignNames.find((c) => c.id === id)?.name ?? "—";

  const emptyResult = !loading && scans.length === 0;

  return (
    <TooltipProvider delayDuration={200}>
    <div className="space-y-4">
      {/* Filtres */}
      <Card className="p-4">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex min-w-52 flex-1 items-center gap-2 sm:max-w-72">
            <Select
              value={campaignFilter}
              onValueChange={(v) => setCampaignFilter(v)}
            >
              <SelectTrigger
                className="w-full"
                aria-label="Filtrer par campagne"
              >
                <SelectValue placeholder="Toutes les campagnes" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Toutes les campagnes</SelectItem>
                {campaignNames.map((c) => (
                  <SelectItem key={c.id} value={c.id}>
                    {c.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {campaignFilter !== "all" && (
              <Button
                variant="ghost"
                size="icon"
                className="size-11 shrink-0"
                aria-label="Retirer le filtre de campagne"
                onClick={() => {
                  setCampaignFilter("all");
                  onClearCampaign?.();
                }}
              >
                <X className="size-4" />
              </Button>
            )}
          </div>

          <Select value={statusFilter} onValueChange={(v) => setStatusFilter(v)}>
            <SelectTrigger
              className="w-full sm:w-44"
              aria-label="Filtrer par statut"
            >
              <SelectValue placeholder="Tous les statuts" />
            </SelectTrigger>
            <SelectContent>
              {STATUS_FILTERS.map((s) => (
                <SelectItem key={s.value} value={s.value}>
                  {s.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <span className="text-muted-foreground ml-auto text-xs tabular-nums">
            {loading ? "Chargement…" : `${scans.length} scan(s)`}
          </span>
        </div>
      </Card>

      {/* Table */}
      <Card>
        <CardContent className="p-0">
          {loading ? (
            <div className="space-y-2 p-4">
              {Array.from({ length: 5 }).map((_, i) => (
                <Skeleton key={i} className="h-12 w-full" />
              ))}
            </div>
          ) : emptyResult ? (
            <EmptyState
              icon={Radar}
              title="Aucun scan trouvé"
              description="Aucun scan ne correspond aux filtres sélectionnés. Lancez une campagne pour générer des scans."
            />
          ) : (
            <div className="max-h-[70vh] overflow-auto scrollbar-slim">
              <Table>
                <TableHeader className="sticky top-0 z-10 bg-card">
                  <TableRow>
                    <TableHead>Outil</TableHead>
                    <TableHead>Cible</TableHead>
                    <TableHead className="hidden lg:table-cell">Campagne</TableHead>
                    <TableHead>Statut</TableHead>
                    <TableHead className="hidden min-w-32 sm:table-cell">Progression</TableHead>
                    <TableHead className="hidden xl:table-cell">Phase</TableHead>
                    <TableHead>Vulns</TableHead>
                    <TableHead className="hidden lg:table-cell">Durée</TableHead>
                    <TableHead className="text-right">
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {scans.map((scan) => {
                    const active =
                      scan.status === "RUNNING" || scan.status === "QUEUED";
                    return (
                      <TableRow key={scan.id}>
                        <TableCell>
                          <ToolBadge tool={scan.tool} />
                        </TableCell>
                        <TableCell className="max-w-40 font-mono text-xs sm:max-w-56">
                          <span className="block truncate" title={scan.target}>
                            {scan.target}
                          </span>
                        </TableCell>
                        <TableCell className="hidden max-w-40 lg:table-cell">
                          <span
                            className="block truncate text-xs"
                            title={
                              scan.campaignName ?? campaignName(scan.campaignId)
                            }
                          >
                            {scan.campaignName ?? campaignName(scan.campaignId)}
                          </span>
                        </TableCell>
                        <TableCell>
                          <ScanStatusBadge status={scan.status} />
                        </TableCell>
                        <TableCell className="hidden sm:table-cell">
                          <div className="flex items-center gap-2">
                            <Progress
                              value={scan.progress}
                              className="h-1.5 w-20"
                              aria-hidden
                            />
                            <span className="text-muted-foreground w-9 text-right text-xs tabular-nums">
                              {scan.progress}%
                            </span>
                          </div>
                        </TableCell>
                        <TableCell className="hidden max-w-32 font-mono text-[11px] xl:table-cell">
                          <span className="block truncate" title={scan.phase}>
                            {scan.phase || "—"}
                          </span>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-1.5">
                            <span className="text-sm tabular-nums">
                              {scan.findingsCount}
                            </span>
                            {scan.criticalCount > 0 && (
                              <SeverityBadge
                                severity="CRITICAL"
                                className="px-1.5 py-0 text-[10px]"
                              />
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="hidden text-xs lg:table-cell">
                          {scan.durationMs !== null
                            ? formatDuration(scan.durationMs)
                            : active
                              ? "en cours…"
                              : "—"}
                        </TableCell>
                        <TableCell className="text-right">
                            <div className="flex items-center justify-end gap-1">
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <Button
                                    variant="ghost"
                                    size="icon"
                                    className="size-11"
                                    aria-label={`Voir les détails du scan ${scan.tool}`}
                                    onClick={() => onOpenScan(scan.id)}
                                  >
                                    <Eye className="size-4" />
                                  </Button>
                                </TooltipTrigger>
                                <TooltipContent>Détails du scan</TooltipContent>
                              </Tooltip>

                              {canWrite && active && (
                                <Tooltip>
                                  <TooltipTrigger asChild>
                                    <Button
                                      variant="ghost"
                                      size="icon"
                                      className="size-11 text-muted-foreground hover:text-rose-400"
                                      disabled={cancellingId === scan.id}
                                      aria-label={`Annuler le scan ${scan.tool}`}
                                      onClick={() => cancel(scan)}
                                    >
                                      {cancellingId === scan.id ? (
                                        <Loader2 className="size-4 animate-spin" />
                                      ) : (
                                        <Square className="size-4" />
                                      )}
                                    </Button>
                                  </TooltipTrigger>
                                  <TooltipContent>Annuler le scan</TooltipContent>
                                </Tooltip>
                              )}

                              {scan.status === "COMPLETED" && (
                                <Tooltip>
                                  <TooltipTrigger asChild>
                                    <Button
                                      variant="ghost"
                                      size="icon"
                                      className="size-11 text-muted-foreground hover:text-emerald-400"
                                      aria-label={`Voir le rapport du scan ${scan.tool}`}
                                      onClick={() =>
                                        onOpenReport
                                          ? onOpenReport(scan.id)
                                          : onOpenScan(scan.id)
                                      }
                                    >
                                      <FileText className="size-4" />
                                    </Button>
                                  </TooltipTrigger>
                                  <TooltipContent>Générer le rapport</TooltipContent>
                                </Tooltip>
                              )}
                            </div>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
    </TooltipProvider>
  );
}
