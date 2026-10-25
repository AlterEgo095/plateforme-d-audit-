"use client";

/**
 * AuditForge — Tableau de bord : statistiques globales, graphiques de
 * répartition, scans récents et actions rapides.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Activity,
  Bug,
  Crosshair,
  Plus,
  ShieldAlert,
} from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { apiGet, getErrorMessage } from "@/lib/api-client";
import { useScanEvents } from "@/hooks/use-socket";
import {
  EmptyState,
  ScanStatusBadge,
  SEVERITY_LABELS,
  SeverityBadge,
  StatCard,
  TOOL_META,
  ToolBadge,
  formatDuration,
  formatDateTime,
  severityColor,
} from "@/components/audit/status-badges";
import type { ScanDTO, Severity, Tool, UserDTO } from "@/lib/types";

interface DashboardData {
  stats: {
    activeScans: number;
    totalCampaigns: number;
    openFindings: number;
    criticalConfirmed: number;
    completedScans: number;
  };
  severityDistribution: { severity: Severity; count: number }[];
  toolDistribution: { tool: Tool; findings: number; scans: number }[];
  recentScans: ScanDTO[];
  campaigns: { id: string; name: string }[];
}

function ChartSkeleton() {
  return (
    <div className="flex h-64 items-center justify-center">
      <Skeleton className="size-40 rounded-full" />
    </div>
  );
}

export function DashboardView({
  user,
  onOpenScan,
  onNavigate,
}: {
  user: UserDTO;
  onOpenScan: (scanId: string) => void;
  onNavigate: (view: "campaigns" | "findings") => void;
}) {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const refreshTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const load = useCallback(async () => {
    try {
      const d = await apiGet<DashboardData>("/api/dashboard");
      setData(d);
      setError(null);
    } catch (e) {
      setError(getErrorMessage(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // Rafraîchissement différée (800 ms) dès qu'un événement de scan arrive.
  useScanEvents(() => {
    if (refreshTimer.current) clearTimeout(refreshTimer.current);
    refreshTimer.current = setTimeout(() => void load(), 800);
  });

  useEffect(
    () => () => {
      if (refreshTimer.current) clearTimeout(refreshTimer.current);
    },
    []
  );

  const stats = data?.stats;
  const severityData = data?.severityDistribution ?? [];
  const totalSeverity = severityData.reduce((acc, s) => acc + s.count, 0);
  const toolData =
    data?.toolDistribution.map((t) => ({
      ...t,
      label: TOOL_META[t.tool]?.label ?? t.tool,
    })) ?? [];

  const empty =
    !loading &&
    data &&
    data.stats.totalCampaigns === 0 &&
    data.recentScans.length === 0;

  return (
    <div className="space-y-6">
      {error && (
        <p className="text-destructive text-sm" role="alert">
          Impossible de charger le tableau de bord : {error}
        </p>
      )}

      {/* Statistiques clés */}
      <section aria-label="Statistiques clés" className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Scans actifs"
          value={loading ? "—" : (stats?.activeScans ?? 0)}
          icon={Activity}
          accent="#10b981"
          hint={loading ? undefined : "En file ou en cours d'exécution"}
        />
        <StatCard
          label="Campagnes"
          value={loading ? "—" : (stats?.totalCampaigns ?? 0)}
          icon={Crosshair}
          accent="#a78bfa"
          hint={loading ? undefined : `${stats?.completedScans ?? 0} scan(s) terminé(s)`}
        />
        <StatCard
          label="Vulnérabilités ouvertes"
          value={loading ? "—" : (stats?.openFindings ?? 0)}
          icon={Bug}
          accent="#fbbf24"
          hint={loading ? undefined : "Statut « ouvert »"}
        />
        <StatCard
          label="Critiques confirmées"
          value={loading ? "—" : (stats?.criticalConfirmed ?? 0)}
          icon={ShieldAlert}
          accent="#f43f5e"
          hint={loading ? undefined : "Sévérité critique · confiance confirmée"}
        />
      </section>

      {/* Graphiques */}
      <section
        aria-label="Répartitions"
        className="grid grid-cols-1 gap-4 lg:grid-cols-2"
      >
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Répartition par sévérité</CardTitle>
            <CardDescription>Vulnérabilités détectées (hors faux positifs)</CardDescription>
          </CardHeader>
          <CardContent>
            {loading ? (
              <ChartSkeleton />
            ) : totalSeverity === 0 ? (
              <div className="flex h-64 items-center justify-center">
                <p className="text-muted-foreground text-sm">Aucune vulnérabilité à afficher.</p>
              </div>
            ) : (
              <div className="relative h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={severityData}
                      dataKey="count"
                      nameKey="severity"
                      cx="50%"
                      cy="50%"
                      innerRadius={62}
                      outerRadius={92}
                      paddingAngle={3}
                      strokeWidth={0}
                    >
                      {severityData.map((entry) => (
                        <Cell
                          key={entry.severity}
                          fill={severityColor(entry.severity)}
                        />
                      ))}
                    </Pie>
                    <Tooltip
                      formatter={(value: number | string, name: string) => [
                        `${value} vulnérabilité(s)`,
                        SEVERITY_LABELS[name as Severity] ?? name,
                      ]}
                      contentStyle={{
                        backgroundColor: "oklch(0.17 0.007 160)",
                        border: "1px solid oklch(1 0 0 / 10%)",
                        borderRadius: 8,
                        color: "oklch(0.97 0.004 160)",
                        fontSize: 12,
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
                {/* Légende personnalisée + total au centre */}
                <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
                  <span className="text-3xl font-bold tabular-nums">{totalSeverity}</span>
                  <span className="text-muted-foreground text-xs">au total</span>
                </div>
                <div className="mt-1 flex flex-wrap justify-center gap-3 pb-2">
                  {severityData.map((entry) => (
                    <span key={entry.severity} className="flex items-center gap-1.5 text-xs">
                      <span
                        className="size-2.5 rounded-sm"
                        style={{ backgroundColor: severityColor(entry.severity) }}
                        aria-hidden
                      />
                      {SEVERITY_LABELS[entry.severity] ?? entry.severity}
                      <span className="text-muted-foreground tabular-nums">({entry.count})</span>
                    </span>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Vulnérabilités par outil</CardTitle>
            <CardDescription>Nombre de vulnérabilités relevées par outil</CardDescription>
          </CardHeader>
          <CardContent>
            {loading ? (
              <ChartSkeleton />
            ) : toolData.length === 0 ? (
              <div className="flex h-64 items-center justify-center">
                <p className="text-muted-foreground text-sm">Aucun scan exécuté pour le moment.</p>
              </div>
            ) : (
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={toolData} margin={{ top: 12, right: 8, left: -18, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="oklch(1 0 0 / 8%)" vertical={false} />
                    <XAxis
                      dataKey="label"
                      tick={{ fill: "oklch(0.66 0.012 160)", fontSize: 11 }}
                      axisLine={{ stroke: "oklch(1 0 0 / 10%)" }}
                      tickLine={false}
                      interval={0}
                    />
                    <YAxis
                      allowDecimals={false}
                      tick={{ fill: "oklch(0.66 0.012 160)", fontSize: 11 }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <Tooltip
                      cursor={{ fill: "oklch(1 0 0 / 5%)" }}
                      formatter={(value: number | string, name: string) => [
                        String(value),
                        name === "findings" ? "Vulnérabilités" : "Scans",
                      ]}
                      contentStyle={{
                        backgroundColor: "oklch(0.17 0.007 160)",
                        border: "1px solid oklch(1 0 0 / 10%)",
                        borderRadius: 8,
                        color: "oklch(0.97 0.004 160)",
                        fontSize: 12,
                      }}
                    />
                    <Bar dataKey="findings" fill="#10b981" radius={4} maxBarSize={48} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </CardContent>
        </Card>
      </section>

      {/* Scans récents */}
      <Card>
        <CardHeader className="flex-row items-center justify-between space-y-0">
          <div className="space-y-1.5">
            <CardTitle className="text-base">Scans récents</CardTitle>
            <CardDescription>Les 10 derniers scans toutes campagnes confondues</CardDescription>
          </div>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="space-y-2">
              {Array.from({ length: 4 }).map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : empty ? (
            <EmptyState
              icon={Crosshair}
              title="Aucun scan pour le moment"
              description="Créez une campagne d'audit puis lancez vos premiers scans pour voir les résultats s'afficher ici."
              action={
                user.role !== "VIEWER" ? (
                  <Button onClick={() => onNavigate("campaigns")}>
                    <Plus className="size-4" aria-hidden />
                    Nouvelle campagne
                  </Button>
                ) : undefined
              }
            />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Outil</TableHead>
                    <TableHead>Cible</TableHead>
                    <TableHead className="hidden sm:table-cell">Statut</TableHead>
                    <TableHead className="hidden md:table-cell">Progression</TableHead>
                    <TableHead>Vulns</TableHead>
                    <TableHead className="hidden lg:table-cell">Durée</TableHead>
                    <TableHead className="w-10 text-right">
                      <span className="sr-only">Détails</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(data?.recentScans ?? []).map((scan) => (
                    <TableRow key={scan.id}>
                      <TableCell>
                        <ToolBadge tool={scan.tool} />
                      </TableCell>
                      <TableCell className="max-w-44 font-mono text-xs">
                        <span className="block truncate" title={scan.target}>
                          {scan.target}
                        </span>
                      </TableCell>
                      <TableCell className="hidden sm:table-cell">
                        <ScanStatusBadge status={scan.status} />
                      </TableCell>
                      <TableCell className="hidden min-w-28 md:table-cell">
                        <div className="flex items-center gap-2">
                          <Progress value={scan.progress} className="h-1.5" aria-hidden />
                          <span className="text-muted-foreground w-9 text-right text-xs tabular-nums">
                            {scan.progress}%
                          </span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1.5">
                          <span className="text-sm tabular-nums">{scan.findingsCount}</span>
                          {scan.criticalCount > 0 && (
                            <SeverityBadge severity="CRITICAL" className="px-1.5 py-0 text-[10px]" />
                          )}
                        </div>
                        <span className="sr-only">
                          {scan.criticalCount} critique(s) sur {scan.findingsCount} vulnérabilité(s)
                        </span>
                      </TableCell>
                      <TableCell className="hidden text-xs lg:table-cell">
                        {scan.durationMs !== null
                          ? formatDuration(scan.durationMs)
                          : scan.status === "RUNNING"
                            ? "en cours…"
                            : "—"}
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-9 px-3"
                          onClick={() => onOpenScan(scan.id)}
                        >
                          Détails
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Actions rapides */}
      {user.role !== "VIEWER" && (
        <section aria-label="Actions rapides" className="flex flex-wrap gap-3">
          <Button onClick={() => onNavigate("campaigns")} className="min-h-11">
            <Plus className="size-4" aria-hidden />
            Nouvelle campagne
          </Button>
          <Button variant="outline" onClick={() => onNavigate("findings")} className="min-h-11">
            <Bug className="size-4" aria-hidden />
            Voir les vulnérabilités
          </Button>
        </section>
      )}
    </div>
  );
}
