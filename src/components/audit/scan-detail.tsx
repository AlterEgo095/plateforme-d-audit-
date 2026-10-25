"use client";

/**
 * AuditForge — Panneau de détail d'un scan : terminal live, vulnérabilités
 * et informations techniques. S'abonne à la room socket.io du scan.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { Loader2, Radar, Square } from "lucide-react";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  ConfidenceBadge,
  PROFILE_LABELS,
  ScanStatusBadge,
  SeverityBadge,
  SentinelBadge,
  TARGET_TYPE_LABELS,
  ToolBadge,
  formatDateTime,
  formatDuration,
} from "@/components/audit/status-badges";
import { FindingDetail } from "@/components/audit/finding-detail";
import {
  apiGet,
  apiPost,
  getErrorMessage,
} from "@/lib/api-client";
import {
  ensureSocket,
  subscribeScan,
  unsubscribeScan,
  useScanEvents,
} from "@/hooks/use-socket";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import type {
  FindingDTO,
  LogEntry,
  LogLevel,
  ScanDTO,
  UserDTO,
} from "@/lib/types";

interface ScanDetailData {
  scan: ScanDTO;
  campaign: {
    id: string;
    name: string;
    profile: string;
    target: string;
    targetType: string;
  };
  findings: FindingDTO[];
}

const LEVEL_COLORS: Record<LogLevel, string> = {
  CMD: "#6ee7b7",
  SUCCESS: "#34d399",
  WARN: "#fcd34d",
  ERROR: "#fb7185",
  TOOL: "#5eead4",
  AGENT: "#c4b5fd",
  INFO: "#d4d4d8",
};

function logTime(ts: string): string {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return "--:--:--";
  return d.toLocaleTimeString("fr-FR", { hour12: false });
}

function TerminalLine({ log }: { log: LogEntry }) {
  return (
    <div className="leading-relaxed break-words">
      <span className="text-zinc-500">[{logTime(log.ts)}]</span>{" "}
      <span style={{ color: LEVEL_COLORS[log.level] ?? "#d4d4d8" }}>
        [{log.level}]
      </span>{" "}
      <span className="text-zinc-400">[{log.source}]</span>{" "}
      <span className="text-zinc-300">{log.message}</span>
    </div>
  );
}

export function ScanDetail({
  scanId,
  open,
  onClose,
  user,
  onOpenReport,
}: {
  scanId: string | null;
  open: boolean;
  onClose: () => void;
  user: UserDTO;
  onOpenReport?: (scanId: string) => void;
}) {
  const { toast } = useToast();
  const [data, setData] = useState<ScanDetailData | null>(null);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<FindingDTO | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const terminalRef = useRef<HTMLDivElement>(null);
  const nearBottomRef = useRef(true);
  /** Compteur monotone pour les ids négatifs des logs live (clés React stables). */
  const liveSeqRef = useRef(0);

  const refreshScan = useCallback(async (id: string) => {
    try {
      const d = await apiGet<ScanDetailData>(`/api/scans/${id}`);
      setData(d);
    } catch {
      // Silencieux : le panneau conserve les données déjà chargées.
    }
  }, []);

  // Chargement à l'ouverture + abonnement à la room du scan.
  useEffect(() => {
    if (!open || !scanId) return;
    let cancelled = false;
    setLoading(true);
    nearBottomRef.current = true;
    setLogs([]);
    void (async () => {
      try {
        const [detail, logRes] = await Promise.all([
          apiGet<ScanDetailData>(`/api/scans/${scanId}`),
          apiGet<{ logs: LogEntry[] }>(`/api/scans/${scanId}/logs?limit=500`),
        ]);
        if (cancelled) return;
        setData(detail);
        // Fusion (pas remplacement) : on conserve les logs live (id < 0)
        // reçus pendant le chargement qui sont PLUS RÉCENTS que le dernier
        // log persisté, pour éviter les doublons au moment de la fusion.
        const fetched = logRes.logs;
        const maxFetchedTs = fetched.reduce((max, l) => {
          const t = new Date(l.ts).getTime();
          return Number.isNaN(t) ? max : Math.max(max, t);
        }, 0);
        setLogs((prev) => {
          const live = prev.filter((l) => {
            if (l.id >= 0) return false;
            const t = new Date(l.ts).getTime();
            return !Number.isNaN(t) && t > maxFetchedTs;
          });
          return [...fetched, ...live].sort(
            (a, b) =>
              new Date(a.ts).getTime() - new Date(b.ts).getTime()
          );
        });
      } catch (e) {
        if (!cancelled) {
          toast({
            title: "Erreur",
            description: getErrorMessage(e),
            variant: "destructive",
          });
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    // L'abonnement attend le socket asynchrone (auth token + handshake).
    void ensureSocket().then(() => {
      if (!cancelled) subscribeScan(scanId);
    });
    return () => {
      cancelled = true;
      unsubscribeScan(scanId);
    };
  }, [open, scanId, toast]);

  // Événements temps réel (filtrés par scanId).
  useScanEvents((ev) => {
    if (!scanId || ev.scanId !== scanId) return;

    if ("log" in ev) {
      const live: LogEntry =
        ev.log.id === 0
          ? { ...ev.log, id: -(++liveSeqRef.current) }
          : ev.log;
      setLogs((prev) => {
        const next = [...prev, live];
        // Buffer plafonné : au-delà de 1500 lignes on garde les plus récentes.
        return next.length > 1500 ? next.slice(-1500) : next;
      });
      return;
    }

    if ("finding" in ev) {
      setData((prev) =>
        prev
          ? { ...prev, findings: [ev.finding, ...prev.findings] }
          : prev
      );
      toast({
        title: "Nouvelle vulnérabilité détectée",
        description: `${ev.finding.title} (${ev.finding.tool})`,
      });
      return;
    }

    if ("progress" in ev) {
      setData((prev) =>
        prev
          ? {
              ...prev,
              scan: {
                ...prev.scan,
                status: ev.status,
                progress: ev.progress,
                phase: ev.phase || prev.scan.phase,
                findingsCount: ev.findingsCount,
                criticalCount: ev.criticalCount,
              },
            }
          : prev
      );
      return;
    }

    // scan:done → rafraîchit le scan (durée exacte) puis quitte la room.
    void refreshScan(scanId).then(() => unsubscribeScan(scanId));
  });

  // Auto-scroll du terminal si l'utilisateur est proche du bas (< 60 px).
  useEffect(() => {
    const el = terminalRef.current;
    if (!el || !nearBottomRef.current) return;
    el.scrollTop = el.scrollHeight;
  }, [logs]);

  const onTerminalScroll = () => {
    const el = terminalRef.current;
    if (!el) return;
    nearBottomRef.current =
      el.scrollHeight - el.scrollTop - el.clientHeight < 60;
  };

  const cancelScan = async () => {
    if (!data) return;
    setCancelling(true);
    try {
      await apiPost<{ scan: ScanDTO }>(`/api/scans/${data.scan.id}/cancel`);
      toast({
        title: "Scan annulé",
        description: `Le scan ${data.scan.tool} a été annulé.`,
      });
      await refreshScan(data.scan.id);
    } catch (e) {
      toast({
        title: "Erreur",
        description: getErrorMessage(e),
        variant: "destructive",
      });
    } finally {
      setCancelling(false);
    }
  };

  const scan = data?.scan ?? null;
  const isActive = scan
    ? scan.status === "RUNNING" || scan.status === "QUEUED"
    : false;

  return (
    <>
      <Sheet open={open} onOpenChange={(o) => !o && onClose()}>
        <SheetContent className="flex w-full flex-col gap-0 overflow-hidden p-0 sm:max-w-3xl">
          <SheetHeader className="shrink-0 space-y-2 border-b">
            <div className="flex flex-wrap items-center gap-2 pr-8">
              {scan ? (
                <>
                  <ToolBadge tool={scan.tool} />
                  <span className="font-mono text-xs" title={scan.target}>
                    {scan.target}
                  </span>
                  <ScanStatusBadge status={scan.status} />
                </>
              ) : (
                <Skeleton className="h-5 w-48" />
              )}
            </div>
            <SheetTitle className="text-base font-semibold">
              {data?.campaign.name ?? "Détail du scan"}
            </SheetTitle>
            <SheetDescription className="sr-only">
              Suivi du scan en temps réel : terminal, vulnérabilités et
              informations
            </SheetDescription>

            {/* Bloc progression */}
            {scan ? (
              <div className="space-y-1.5 pt-1">
                <div className="flex items-center gap-3">
                  <Progress value={scan.progress} className="h-2 flex-1" aria-hidden />
                  <span className="text-xs font-semibold tabular-nums">
                    {scan.progress}%
                  </span>
                </div>
                <div className="text-muted-foreground flex flex-wrap gap-x-4 gap-y-0.5 text-xs">
                  <span className="font-mono">
                    {scan.phase || (isActive ? "initialisation…" : "—")}
                  </span>
                  {scan.startedAt && (
                    <span>Démarré : {formatDateTime(scan.startedAt)}</span>
                  )}
                  <span>
                    Durée :{" "}
                    {scan.durationMs !== null
                      ? formatDuration(scan.durationMs)
                      : isActive
                        ? "en cours…"
                        : "—"}
                  </span>
                </div>
              </div>
            ) : (
              <Skeleton className="h-10 w-full" />
            )}
          </SheetHeader>

          {loading && !data ? (
            <div className="flex-1 space-y-3 p-4">
              <Skeleton className="h-full w-full" />
            </div>
          ) : scan && data ? (
            <Tabs defaultValue="terminal" className="flex min-h-0 flex-1 flex-col gap-0">
              <div className="shrink-0 border-b px-4 pt-2">
                <TabsList className="grid h-10 w-full grid-cols-3 sm:w-96">
                  <TabsTrigger value="terminal">Terminal</TabsTrigger>
                  <TabsTrigger value="findings">
                    Vulnérabilités ({scan.findingsCount})
                  </TabsTrigger>
                  <TabsTrigger value="info">Informations</TabsTrigger>
                </TabsList>
              </div>

              {/* Onglet Terminal */}
              <TabsContent
                value="terminal"
                className="min-h-0 flex-1 data-[state=inactive]:hidden"
              >
                <div
                  ref={terminalRef}
                  onScroll={onTerminalScroll}
                  className="terminal-grid bg-black/40 m-4 h-[60vh] overflow-y-auto rounded-lg border p-4 font-mono text-xs scrollbar-slim"
                  role="log"
                  aria-live="polite"
                  aria-label="Journal d'exécution du scan en direct"
                >
                  {logs.length === 0 ? (
                    <p className="text-zinc-500 italic">
                      En attente des premiers logs…
                      {isActive && (
                        <>
                          <br />
                          Le journal apparaît dès que le moteur démarre l&apos;exécution.
                        </>
                      )}
                    </p>
                  ) : (
                    logs.map((log) => <TerminalLine key={log.id} log={log} />)
                  )}
                  {!isActive && logs.length > 0 && (
                    <p className="text-zinc-600 mt-2 italic">
                      — Fin du journal (scan {scan.status === "COMPLETED" ? "terminé" : scan.status === "FAILED" ? "en échec" : "annulé"}) —
                    </p>
                  )}
                </div>
              </TabsContent>

              {/* Onglet Vulnérabilités */}
              <TabsContent
                value="findings"
                className="min-h-0 flex-1 overflow-y-auto data-[state=inactive]:hidden scrollbar-slim"
              >
                <div className="space-y-2 p-4">
                  {data.findings.length === 0 ? (
                    <p className="text-muted-foreground py-10 text-center text-sm italic">
                      Aucune vulnérabilité détectée
                      {isActive ? " pour le moment — le scan est encore en cours." : "."}
                    </p>
                  ) : (
                    data.findings.map((f) => (
                      <button
                        key={f.id}
                        type="button"
                        className="hover:bg-accent/60 w-full rounded-lg border p-3 text-left transition-colors"
                        onClick={() => setSelectedFinding(f)}
                        aria-label={`Ouvrir le détail de la vulnérabilité ${f.title}`}
                      >
                        <div className="flex flex-wrap items-center gap-2">
                          <SeverityBadge severity={f.severity} />
                          <span className="min-w-0 flex-1 truncate text-sm font-medium">
                            {f.title}
                          </span>
                        </div>
                        <div className="mt-2 flex flex-wrap items-center gap-1.5">
                          <ToolBadge tool={f.tool} small />
                          <ConfidenceBadge confidence={f.confidence} />
                          {f.sentinelTriggered && <SentinelBadge />}
                        </div>
                      </button>
                    ))
                  )}
                </div>
              </TabsContent>

              {/* Onglet Informations */}
              <TabsContent
                value="info"
                className="min-h-0 flex-1 overflow-y-auto data-[state=inactive]:hidden scrollbar-slim"
              >
                <dl className="grid grid-cols-1 gap-x-6 gap-y-3 p-4 text-sm sm:grid-cols-2">
                  <InfoRow label="Campagne" value={data.campaign.name} />
                  <InfoRow
                    label="Profil"
                    value={PROFILE_LABELS[data.campaign.profile] ?? data.campaign.profile}
                  />
                  <InfoRow
                    label="Cible"
                    value={scan.target}
                    mono
                  />
                  <InfoRow
                    label="Type de cible"
                    value={
                      TARGET_TYPE_LABELS[data.campaign.targetType] ??
                      data.campaign.targetType
                    }
                  />
                  <InfoRow label="Démarré" value={formatDateTime(scan.startedAt)} />
                  <InfoRow label="Terminé" value={formatDateTime(scan.finishedAt)} />
                  <InfoRow
                    label="Durée"
                    value={
                      scan.durationMs !== null ? formatDuration(scan.durationMs) : "—"
                    }
                  />
                  <InfoRow label="Statut" value={<ScanStatusBadge status={scan.status} />} />
                  <InfoRow
                    label="Vulnérabilités"
                    value={`${scan.findingsCount} au total`}
                  />
                  <InfoRow
                    label="Critiques"
                    value={
                      <span className="font-semibold" style={{ color: "#f43f5e" }}>
                        {scan.criticalCount}
                      </span>
                    }
                  />
                </dl>
              </TabsContent>
            </Tabs>
          ) : (
            <div className="flex flex-1 flex-col items-center justify-center gap-2">
              <Radar className="text-muted-foreground size-8" aria-hidden />
              <p className="text-muted-foreground text-sm">
                Impossible de charger ce scan.
              </p>
            </div>
          )}

          {/* Actions de pied */}
          {scan && (
            <div className="flex shrink-0 flex-wrap items-center gap-2 border-t p-4">
              {isActive && user.role !== "VIEWER" && (
                <Button
                  variant="destructive"
                  size="sm"
                  className="min-h-10"
                  disabled={cancelling}
                  onClick={() => void cancelScan()}
                >
                  {cancelling ? (
                    <Loader2 className="size-4 animate-spin" aria-hidden />
                  ) : (
                    <Square className="size-4" aria-hidden />
                  )}
                  Annuler le scan
                </Button>
              )}
              {scan.status === "COMPLETED" && onOpenReport && (
                <Button
                  size="sm"
                  className="min-h-10"
                  onClick={() => onOpenReport(scan.id)}
                >
                  Voir le rapport
                </Button>
              )}
              <Button
                variant="ghost"
                size="sm"
                className="ml-auto min-h-10"
                onClick={onClose}
              >
                Fermer
              </Button>
            </div>
          )}
        </SheetContent>
      </Sheet>

      {/* Détail d'une vulnérabilité (au-dessus du détail de scan) */}
      <FindingDetail
        finding={selectedFinding}
        open={selectedFinding !== null}
        onOpenChange={(o) => !o && setSelectedFinding(null)}
        user={user}
      />
    </>
  );
}

function InfoRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="min-w-0">
      <dt className="text-muted-foreground text-xs">{label}</dt>
      <dd className={cn("mt-0.5 truncate font-medium", mono && "font-mono text-xs")} title={typeof value === "string" ? value : undefined}>
        {value}
      </dd>
    </div>
  );
}
