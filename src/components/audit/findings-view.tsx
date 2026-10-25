"use client";

/**
 * AuditForge — Vue Vulnérabilités : recherche filtrée, tableau et détail.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { Bug, Search } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
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
import { apiGet, getErrorMessage } from "@/lib/api-client";
import { useScanEvents } from "@/hooks/use-socket";
import { useToast } from "@/hooks/use-toast";
import {
  ConfidenceBadge,
  cvssSeverity,
  EmptyState,
  FINDING_STATUS_LABELS_MAP,
  FindingStatusBadge,
  SEVERITY_LABELS,
  SeverityBadge,
  SentinelBadge,
  TOOL_META,
  ToolBadge,
} from "@/components/audit/status-badges";
import { FindingDetail } from "@/components/audit/finding-detail";
import type {
  FindingDTO,
  FindingStatus,
  Tool,
  UserDTO,
} from "@/lib/types";

const SEVERITY_OPTIONS: { value: string; label: string }[] = [
  { value: "all", label: "Toutes sévérités" },
  ...Object.entries(SEVERITY_LABELS).map(([value, label]) => ({
    value,
    label,
  })),
];

const TOOL_OPTIONS: { value: string; label: string }[] = [
  { value: "all", label: "Tous les outils" },
  ...(Object.keys(TOOL_META) as Tool[]).map((id) => ({
    value: id,
    label: TOOL_META[id].label,
  })),
];

const STATUS_OPTIONS: { value: string; label: string }[] = [
  { value: "all", label: "Tous les statuts" },
  ...Object.entries(FINDING_STATUS_LABELS_MAP).map(([value, label]) => ({
    value,
    label,
  })),
];

export function FindingsView({ user }: { user: UserDTO }) {
  const { toast } = useToast();
  const [findings, setFindings] = useState<FindingDTO[]>([]);
  const [loading, setLoading] = useState(true);
  const [q, setQ] = useState("");
  const [debouncedQ, setDebouncedQ] = useState("");
  const [severity, setSeverity] = useState("all");
  const [tool, setTool] = useState("all");
  const [status, setStatus] = useState("all");
  const [selected, setSelected] = useState<FindingDTO | null>(null);
  const loadTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  /** Jeton de séquence : ignore les réponses de fetch obsolètes. */
  const seqRef = useRef(0);

  // Debounce de la recherche (400 ms).
  useEffect(() => {
    const t = setTimeout(() => setDebouncedQ(q), 400);
    return () => clearTimeout(t);
  }, [q]);

  const load = useCallback(async () => {
    const seq = ++seqRef.current;
    try {
      const params = new URLSearchParams();
      if (debouncedQ.trim()) params.set("q", debouncedQ.trim());
      if (severity !== "all") params.set("severity", severity);
      if (tool !== "all") params.set("tool", tool);
      if (status !== "all") params.set("status", status);
      const qs = params.toString();
      const res = await apiGet<{ findings: FindingDTO[] }>(
        `/api/findings${qs ? `?${qs}` : ""}`
      );
      if (seq !== seqRef.current) return; // réponse obsolète
      setFindings(res.findings);
    } catch (e) {
      if (seq === seqRef.current) {
        toast({
          title: "Erreur",
          description: getErrorMessage(e),
          variant: "destructive",
        });
      }
    } finally {
      setLoading(false);
    }
  }, [debouncedQ, severity, tool, status, toast]);

  useEffect(() => {
    void load();
  }, [load]);

  // Une nouvelle vulnérabilité arrive en temps réel → rafraîchit la liste.
  useScanEvents((ev) => {
    if (!("finding" in ev)) return;
    if (loadTimer.current) clearTimeout(loadTimer.current);
    loadTimer.current = setTimeout(() => void load(), 800);
  });

  useEffect(
    () => () => {
      if (loadTimer.current) clearTimeout(loadTimer.current);
    },
    []
  );

  const onStatusUpdated = (updated: FindingDTO) => {
    setFindings((prev) =>
      prev.map((f) => (f.id === updated.id ? { ...f, status: updated.status } : f))
    );
    setSelected((prev) =>
      prev && prev.id === updated.id ? { ...prev, status: updated.status } : prev
    );
  };

  return (
    <div className="space-y-4">
      {/* Barre de filtres */}
      <Card className="p-4">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative min-w-52 flex-1 sm:max-w-72">
            <Search
              className="text-muted-foreground pointer-events-none absolute top-2.5 left-3 size-4"
              aria-hidden
            />
            <Input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Rechercher un titre, une CVE, une catégorie…"
              className="pl-9"
              aria-label="Rechercher une vulnérabilité"
            />
          </div>

          <Select value={severity} onValueChange={setSeverity}>
            <SelectTrigger
              className="w-full sm:w-44"
              aria-label="Filtrer par sévérité"
            >
              <SelectValue placeholder="Sévérité" />
            </SelectTrigger>
            <SelectContent>
              {SEVERITY_OPTIONS.map((o) => (
                <SelectItem key={o.value} value={o.value}>
                  {o.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Select value={tool} onValueChange={setTool}>
            <SelectTrigger
              className="w-full sm:w-40"
              aria-label="Filtrer par outil"
            >
              <SelectValue placeholder="Outil" />
            </SelectTrigger>
            <SelectContent>
              {TOOL_OPTIONS.map((o) => (
                <SelectItem key={o.value} value={o.value}>
                  {o.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Select value={status} onValueChange={setStatus}>
            <SelectTrigger
              className="w-full sm:w-44"
              aria-label="Filtrer par statut"
            >
              <SelectValue placeholder="Statut" />
            </SelectTrigger>
            <SelectContent>
              {STATUS_OPTIONS.map((o) => (
                <SelectItem key={o.value} value={o.value}>
                  {o.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <span className="text-muted-foreground ml-auto text-xs tabular-nums">
            {loading
              ? "Chargement…"
              : `${findings.length} vulnérabilité(s)`}
          </span>
        </div>
      </Card>

      {/* Tableau */}
      <Card>
        <CardContent className="p-0">
          {loading ? (
            <div className="space-y-2 p-4">
              {Array.from({ length: 6 }).map((_, i) => (
                <Skeleton key={i} className="h-12 w-full" />
              ))}
            </div>
          ) : findings.length === 0 ? (
            <EmptyState
              icon={Bug}
              title="Aucune vulnérabilité trouvée"
              description="Aucun résultat pour ces filtres. Lancez de nouveaux scans ou élargissez votre recherche."
            />
          ) : (
            <div className="max-h-[70vh] overflow-auto scrollbar-slim">
              <Table>
                <TableHeader className="sticky top-0 z-10 bg-card">
                  <TableRow>
                    <TableHead>Sévérité</TableHead>
                    <TableHead>Titre</TableHead>
                    <TableHead className="hidden md:table-cell">Outil</TableHead>
                    <TableHead className="hidden xl:table-cell">Catégorie</TableHead>
                    <TableHead>CVSS</TableHead>
                    <TableHead className="hidden sm:table-cell">Confiance</TableHead>
                    <TableHead className="hidden lg:table-cell">PoC</TableHead>
                    <TableHead className="hidden sm:table-cell">Statut</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {findings.map((f) => (
                    <TableRow
                      key={f.id}
                      className="hover:bg-accent/60 cursor-pointer"
                      tabIndex={0}
                      role="button"
                      aria-label={`Voir le détail : ${f.title}`}
                      onClick={() => setSelected(f)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          setSelected(f);
                        }
                      }}
                    >
                      <TableCell>
                        <SeverityBadge severity={f.severity} />
                      </TableCell>
                      <TableCell className="max-w-48 sm:max-w-72">
                        <span className="block truncate font-medium" title={f.title}>
                          {f.title}
                        </span>
                        <span className="text-muted-foreground block truncate text-[11px] md:hidden">
                          {f.tool} · {f.category}
                        </span>
                      </TableCell>
                      <TableCell className="hidden md:table-cell">
                        <ToolBadge tool={f.tool} small />
                      </TableCell>
                      <TableCell className="hidden max-w-36 font-mono text-[11px] xl:table-cell">
                        <span className="block truncate" title={f.category}>
                          {f.category}
                        </span>
                      </TableCell>
                      <TableCell
                        className="font-mono text-sm font-semibold tabular-nums"
                        style={{
                          color:
                            f.cvss !== null
                              ? cvssSeverity(f.cvss).color
                              : undefined,
                        }}
                      >
                        {f.cvss !== null ? f.cvss.toFixed(1) : "—"}
                      </TableCell>
                      <TableCell className="hidden sm:table-cell">
                        <ConfidenceBadge confidence={f.confidence} />
                      </TableCell>
                      <TableCell className="hidden lg:table-cell">
                        {f.sentinelTriggered ? <SentinelBadge /> : <span>—</span>}
                      </TableCell>
                      <TableCell className="hidden sm:table-cell">
                        <FindingStatusBadge status={f.status as FindingStatus} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Détail */}
      <FindingDetail
        finding={selected}
        open={selected !== null}
        onOpenChange={(o) => !o && setSelected(null)}
        user={user}
        onStatusUpdated={onStatusUpdated}
      />
    </div>
  );
}
