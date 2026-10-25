"use client";

/**
 * AuditForge — Vue Outils : bannière de démonstration, schéma d'architecture
 * (CSS pur) et fiches des 4 outils d'audit.
 */

import { useEffect, useState } from "react";
import {
  Boxes,
  CheckCircle2,
  GitBranch,
  Globe,
  Info,
  MonitorSmartphone,
  Network,
  Server,
  TerminalSquare,
  XCircle,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { apiGet } from "@/lib/api-client";
import { useSocketConnection } from "@/hooks/use-socket";
import { cn } from "@/lib/utils";
import { ToolBadge, toolColor } from "@/components/audit/status-badges";
import type { TargetType, Tool, ToolInfo } from "@/lib/types";

const TARGET_META: Record<TargetType, { icon: typeof Globe; label: string }> = {
  URL: { icon: Globe, label: "URL web" },
  GIT: { icon: GitBranch, label: "Dépôt Git" },
  NETWORK: { icon: Network, label: "Réseau" },
};

// ─── Boîte du schéma d'architecture ──────────────────────────────────

function ArchBox({
  title,
  subtitle,
  icon: Icon,
  accent = "#10b981",
  className,
}: {
  title: string;
  subtitle?: string;
  icon?: typeof Globe;
  accent?: string;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "bg-card flex min-w-40 flex-col items-center gap-1 rounded-lg border px-4 py-3 text-center shadow-sm",
        className
      )}
      style={{ borderColor: `${accent}55` }}
    >
      {Icon && (
        <Icon className="size-5 shrink-0" style={{ color: accent }} aria-hidden />
      )}
      <span className="font-mono text-xs font-semibold" style={{ color: accent }}>
        {title}
      </span>
      {subtitle && (
        <span className="text-muted-foreground text-[11px] leading-tight">
          {subtitle}
        </span>
      )}
    </div>
  );
}

function ArrowV() {
  return (
    <div className="flex h-6 items-center justify-center text-muted-foreground" aria-hidden>
      <svg width="16" height="24" viewBox="0 0 16 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <path d="M8 2v16m0 0 4-4m-4 4-4-4" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </div>
  );
}

function ArrowH() {
  return (
    <div className="hidden items-center px-1 text-muted-foreground md:flex" aria-hidden>
      <svg width="24" height="16" viewBox="0 0 24 16" fill="none" stroke="currentColor" strokeWidth="1.5">
        <path d="M2 8h16m0 0-4-4m4 4-4 4" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </div>
  );
}

function ArchitectureDiagram() {
  return (
    <div className="terminal-grid bg-black/20 overflow-x-auto rounded-lg border p-4 sm:p-6">
      <div className="flex min-w-fit flex-col items-center">
        {/* Navigateur */}
        <ArchBox
          title="Navigateur"
          subtitle="Interface opérateur (SPA React)"
          icon={MonitorSmartphone}
          accent="#94a3b8"
        />
        <ArrowV />
        <div className="flex flex-col items-center gap-2 md:flex-row md:items-stretch">
          {/* Frontend + API */}
          <ArchBox
            title="Frontend + API — Next.js :3000"
            subtitle="Routes /api/* · REST JSON + cookies"
            icon={Server}
          />
          <ArrowH />
          {/* Prisma / SQLite */}
          <ArchBox
            title="Prisma / SQLite"
            subtitle="Persistance (WAL) — campagnes, scans, findings, logs"
            icon={Boxes}
            accent="#fbbf24"
          />
        </div>
        <ArrowV />
        {/* Passerelle temps réel */}
        <ArchBox
          title="Passerelle temps réel — socket.io :3030"
          subtitle="Événements scan:update · scan:log · scan:finding · scan:done"
          icon={TerminalSquare}
          accent="#a78bfa"
        />
        <ArrowV />
        {/* Outils */}
        <div className="flex flex-wrap items-stretch justify-center gap-2">
          {(["PHANTOM", "DEEPAUDIT", "BASALT", "REDAMON"] as Tool[]).map((t) => (
            <ArchBox
              key={t}
              title={t}
              accent={toolColor(t)}
              className="min-w-36"
            />
          ))}
        </div>
        <ArrowV />
        {/* Sandboxes */}
        <ArchBox
          title="Sandboxes éphémères"
          subtitle="Réseau restreint / sans réseau (vérification de PoC)"
          icon={Network}
          accent="#2dd4bf"
        />
      </div>
    </div>
  );
}

// ─── Vue principale ──────────────────────────────────────────────────

export function ToolsView() {
  const { connected } = useSocketConnection();
  const [tools, setTools] = useState<ToolInfo[] | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    void (async () => {
      try {
        const res = await apiGet<{ tools: ToolInfo[] }>("/api/tools");
        setTools(res.tools);
      } catch {
        setTools(null);
      } finally {
        setLoading(false);
      }
    })();
  }, [connected]);

  return (
    <div className="space-y-6">
      {/* Bannière démo */}
      <Card className="border-amber-500/30 bg-amber-500/5">
        <CardContent className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center">
          <div className="flex items-start gap-3">
            <Info className="mt-0.5 size-5 shrink-0 text-amber-400" aria-hidden />
            <div className="text-sm leading-relaxed">
              <p className="font-semibold">Environnement de démonstration</p>
              <p className="text-muted-foreground">
                AuditForge fonctionne avec un moteur de simulation embarqué :
                les outils exécutent des pipelines simulés (logs réalistes,
                vulnérabilités générées, PoC vérifiés en sandbox) sans aucune
                dépendance externe ni trafic réseau réel.
              </p>
            </div>
          </div>
          <span
            className={cn(
              "inline-flex shrink-0 items-center gap-2 self-start rounded-full border px-3 py-1 text-xs font-medium sm:ml-auto",
              connected
                ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
                : "border-rose-500/40 bg-rose-500/10 text-rose-400"
            )}
            role="status"
          >
            <span
              className={cn("size-2 rounded-full", connected && "af-live-dot")}
              style={{ backgroundColor: connected ? "#34d399" : "#f43f5e" }}
              aria-hidden
            />
            {connected ? "Moteur connecté" : "Moteur hors ligne"}
          </span>
        </CardContent>
      </Card>

      {/* Architecture */}
      <section aria-labelledby="arch-title" className="space-y-3">
        <div>
          <h2 id="arch-title" className="text-lg font-semibold tracking-tight">
            Architecture de la plateforme
          </h2>
          <p className="text-muted-foreground text-sm">
            Flux de données entre le navigateur, l&apos;API, la passerelle temps
            réel et les outils d&apos;audit.
          </p>
        </div>
        <ArchitectureDiagram />
      </section>

      {/* Fiches outils */}
      <section aria-labelledby="tools-title" className="space-y-3">
        <div>
          <h2 id="tools-title" className="text-lg font-semibold tracking-tight">
            Outils intégrés
          </h2>
          <p className="text-muted-foreground text-sm">
            Chaque outil s&apos;exécute dans une sandbox éphémère avec des
            capacités et cibles dédiées.
          </p>
        </div>

        {loading ? (
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-56 w-full rounded-xl" />
            ))}
          </div>
        ) : !tools ? (
          <Card>
            <CardContent className="text-muted-foreground p-6 text-center text-sm">
              Impossible de charger la liste des outils.
            </CardContent>
          </Card>
        ) : (
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            {tools.map((tool) => (
              <ToolCard key={tool.id} tool={tool} />
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

function ToolCard({ tool }: { tool: ToolInfo }) {
  const online = tool.status === "CONNECTE";
  return (
    <Card className="flex flex-col gap-3">
      <CardHeader className="pb-0">
        <div className="flex flex-wrap items-center gap-2">
          <ToolBadge tool={tool.id} />
          <span
            className={cn(
              "inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] font-medium",
              online
                ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
                : "border-zinc-500/40 bg-zinc-500/10 text-zinc-400"
            )}
            role="status"
          >
            {online ? (
              <CheckCircle2 className="size-3" aria-hidden />
            ) : (
              <XCircle className="size-3" aria-hidden />
            )}
            {online ? "Connecté" : "Hors ligne"}
          </span>
        </div>
        <CardTitle className="text-sm font-medium text-muted-foreground">
          {tool.nature}
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-1 flex-col gap-3 pt-0">
        <p className="text-sm leading-relaxed">{tool.description}</p>

        <div className="text-muted-foreground space-y-1 text-xs">
          <p>
            <span className="text-foreground font-semibold">Intégration : </span>
            {tool.integration}
          </p>
          <p>
            <span className="text-foreground font-semibold">Sandbox : </span>
            {tool.sandbox}
          </p>
        </div>

        <div className="flex flex-wrap gap-1.5">
          {tool.capabilities.map((cap) => (
            <Badge key={cap} variant="outline" className="font-mono text-[10px]">
              {cap}
            </Badge>
          ))}
        </div>

        <div className="text-muted-foreground mt-auto flex flex-wrap items-center gap-3 border-t pt-3 text-xs">
          <span className="font-medium">Cibles supportées :</span>
          {tool.supportedTargets.map((tt) => {
            const meta = TARGET_META[tt];
            const Icon = meta.icon;
            return (
              <span key={tt} className="inline-flex items-center gap-1">
                <Icon className="size-3.5" aria-hidden />
                {meta.label}
              </span>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}
