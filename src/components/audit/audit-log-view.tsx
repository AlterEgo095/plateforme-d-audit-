"use client";

/**
 * AuditForge — Journal d'audit : traces horodatées des actions opérateur.
 */

import { useCallback, useEffect, useState } from "react";
import { RefreshCw, ScrollText } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
import { useToast } from "@/hooks/use-toast";
import {
  EmptyState,
  formatDateTime,
} from "@/components/audit/status-badges";
import type { AuditEntry } from "@/lib/types";

export function AuditLogView() {
  const { toast } = useToast();
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async () => {
    setRefreshing(true);
    try {
      const res = await apiGet<{ entries: AuditEntry[] }>(
        "/api/audit-log?limit=200"
      );
      setEntries(res.entries);
    } catch (e) {
      toast({
        title: "Erreur",
        description: getErrorMessage(e),
        variant: "destructive",
      });
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [toast]);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between space-y-0 pb-3">
        <div className="space-y-1">
          <CardTitle className="text-base">Journal d&apos;audit</CardTitle>
          <p className="text-muted-foreground text-sm">
            Traçabilité des actions réalisées sur la plateforme (200 dernières
            entrées).
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          className="min-h-10"
          disabled={refreshing}
          onClick={() => void load()}
          aria-label="Rafraîchir le journal d'audit"
        >
          <RefreshCw className={`size-4 ${refreshing ? "animate-spin" : ""}`} aria-hidden />
          Rafraîchir
        </Button>
      </CardHeader>
      <CardContent className="p-0">
        {loading ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 8 }).map((_, i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        ) : entries.length === 0 ? (
          <EmptyState
            icon={ScrollText}
            title="Journal vide"
            description="Aucune action enregistrée pour le moment. Les connexions, campagnes, lancements et modifications apparaîtront ici."
          />
        ) : (
          <div className="max-h-[70vh] overflow-auto scrollbar-slim">
            <Table>
              <TableHeader className="sticky top-0 z-10 bg-card">
                <TableRow>
                  <TableHead className="w-44">Horodatage</TableHead>
                  <TableHead className="w-32">Acteur</TableHead>
                  <TableHead className="w-44">Action</TableHead>
                  <TableHead className="w-56">Ressource</TableHead>
                  <TableHead>Détail</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {entries.map((entry) => (
                  <TableRow key={entry.id}>
                    <TableCell className="text-xs whitespace-nowrap">
                      {formatDateTime(entry.createdAt)}
                    </TableCell>
                    <TableCell className="text-sm font-medium">
                      {entry.actor}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="font-mono text-[10px]">
                        {entry.action}
                      </Badge>
                    </TableCell>
                    <TableCell className="max-w-52 font-mono text-xs">
                      <span className="block truncate" title={entry.resource}>
                        {entry.resource}
                      </span>
                    </TableCell>
                    <TableCell className="text-muted-foreground max-w-72 text-xs">
                      <span className="block truncate" title={entry.detail ?? undefined}>
                        {entry.detail ?? "—"}
                      </span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
