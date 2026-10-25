"use client";

/**
 * AuditForge — Coquille applicative : navigation latérale, en-tête collant
 * (statut moteur), contenu et pied de page collant (min-h-screen flex-col).
 */

import { useState } from "react";
import {
  Bug,
  Crosshair,
  FileText,
  LayoutDashboard,
  LogOut,
  Menu,
  Radar,
  ScrollText,
  Shield,
  Wrench,
  type LucideIcon,
} from "lucide-react";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetTitle, SheetDescription } from "@/components/ui/sheet";
import { cn } from "@/lib/utils";
import { useSocketConnection } from "@/hooks/use-socket";
import { ROLE_LABELS } from "@/components/audit/status-badges";
import type { UserDTO } from "@/lib/types";

export type View =
  | "dashboard"
  | "campaigns"
  | "scans"
  | "findings"
  | "reports"
  | "tools"
  | "audit";

export const VIEW_TITLES: Record<View, string> = {
  dashboard: "Tableau de bord",
  campaigns: "Campagnes",
  scans: "Scans",
  findings: "Vulnérabilités",
  reports: "Rapports",
  tools: "Outils",
  audit: "Journal d'audit",
};

const NAV_ITEMS: { view: View; label: string; icon: LucideIcon }[] = [
  { view: "dashboard", label: "Tableau de bord", icon: LayoutDashboard },
  { view: "campaigns", label: "Campagnes", icon: Crosshair },
  { view: "scans", label: "Scans", icon: Radar },
  { view: "findings", label: "Vulnérabilités", icon: Bug },
  { view: "reports", label: "Rapports", icon: FileText },
  { view: "tools", label: "Outils", icon: Wrench },
  { view: "audit", label: "Journal d'audit", icon: ScrollText },
];

function EngineStatusPill({
  compact,
  className,
}: {
  compact?: boolean;
  className?: string;
}) {
  const { connected } = useSocketConnection();
  const label = connected ? "Moteur connecté" : "Moteur hors ligne";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium",
        connected
          ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
          : "border-rose-500/40 bg-rose-500/10 text-rose-400",
        compact ? "size-8 justify-center px-0" : "",
        className
      )}
      role="status"
      aria-live="polite"
      title={compact ? label : undefined}
    >
      <span
        className={cn("size-2 rounded-full", connected && "af-live-dot")}
        style={{ backgroundColor: connected ? "#34d399" : "#f43f5e" }}
        aria-hidden
      />
      {!compact && label}
    </span>
  );
}

function Logo() {
  return (
    <div className="flex items-center gap-2.5 px-2">
      <div
        className="border-primary/50 bg-primary/10 text-primary flex size-9 shrink-0 items-center justify-center rounded-lg border"
        aria-hidden
      >
        <Shield className="size-5" />
      </div>
      <div className="min-w-0 leading-tight">
        <div className="flex items-center gap-1.5">
          <span className="truncate text-sm font-bold tracking-tight">AuditForge</span>
          <span className="bg-primary/15 text-primary rounded px-1 py-px font-mono text-[9px] font-bold tracking-widest">
            SOC
          </span>
        </div>
        <div className="text-muted-foreground text-[10px]">
          Plateforme d&apos;audit unifiée
        </div>
      </div>
    </div>
  );
}

function UserCard({
  user,
  onLogout,
}: {
  user: UserDTO;
  onLogout: () => void;
}) {
  const initials = user.username
    .split(/[\s._-]+/)
    .map((p) => p[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2.5 rounded-lg border p-2">
        <Avatar className="size-8">
          <AvatarFallback className="bg-primary/15 text-primary text-xs font-bold">
            {initials}
          </AvatarFallback>
        </Avatar>
        <div className="min-w-0 leading-tight">
          <div className="truncate text-sm font-medium">{user.username}</div>
          <div className="text-muted-foreground text-[11px]">
            {ROLE_LABELS[user.role] ?? user.role}
          </div>
        </div>
      </div>
      <Button
        variant="ghost"
        className="h-10 w-full justify-start gap-2 text-muted-foreground hover:text-foreground"
        onClick={onLogout}
      >
        <LogOut className="size-4" aria-hidden />
        Déconnexion
      </Button>
    </div>
  );
}

function NavList({
  view,
  onView,
  onNavigate,
}: {
  view: View;
  onView: (v: View) => void;
  onNavigate?: () => void;
}) {
  return (
    <nav className="space-y-1" aria-label="Navigation principale">
      {NAV_ITEMS.map(({ view: v, label, icon: Icon }) => (
        <button
          key={v}
          type="button"
          onClick={() => {
            onView(v);
            onNavigate?.();
          }}
          aria-current={view === v ? "page" : undefined}
          className={cn(
            "flex min-h-11 w-full items-center gap-3 rounded-md border-l-2 px-3 py-2 text-sm font-medium transition-colors",
            view === v
              ? "bg-accent border-primary text-foreground"
              : "text-muted-foreground hover:bg-accent/60 hover:text-foreground border-transparent"
          )}
        >
          <Icon className="size-4 shrink-0" aria-hidden />
          {label}
        </button>
      ))}
    </nav>
  );
}

export function AppShell({
  user,
  view,
  onView,
  onLogout,
  children,
}: {
  user: UserDTO;
  view: View;
  onView: (v: View) => void;
  onLogout: () => void;
  children: React.ReactNode;
}) {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className="flex min-h-screen flex-col">
      {/* Barre latérale fixe (desktop) */}
      <aside
        className="bg-sidebar print:hidden hidden flex-col fixed inset-y-0 left-0 z-30 w-60 border-r md:flex"
        aria-label="Barre latérale"
      >
        <div className="flex h-16 items-center border-b px-4">
          <Logo />
        </div>
        <div className="flex-1 overflow-y-auto p-3 scrollbar-slim">
          <NavList view={view} onView={onView} />
        </div>
        <div className="border-t p-3">
          <UserCard user={user} onLogout={onLogout} />
        </div>
      </aside>

      {/* En-tête collant */}
      <header className="bg-background/95 supports-[backdrop-filter]:bg-background/75 print:hidden sticky top-0 z-20 flex h-16 shrink-0 items-center gap-3 border-b px-4 backdrop-blur md:pl-60">
        <Button
          variant="ghost"
          size="icon"
          className="size-11 md:hidden"
          aria-label="Ouvrir le menu de navigation"
          onClick={() => setMobileOpen(true)}
        >
          <Menu className="size-5" />
        </Button>

        <h1 className="min-w-0 truncate text-base font-semibold tracking-tight sm:text-lg">
          {VIEW_TITLES[view]}
        </h1>

        <div className="ml-auto flex items-center gap-2">
          <EngineStatusPill className="hidden sm:inline-flex" />
          <EngineStatusPill compact className="sm:hidden" />
          <Button
            variant="ghost"
            size="icon"
            className="size-11 md:hidden"
            aria-label="Déconnexion"
            onClick={onLogout}
          >
            <LogOut className="size-5" />
          </Button>
        </div>
      </header>

      {/* Menu mobile */}
      <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
        <SheetContent side="left" className="bg-sidebar flex w-72 flex-col gap-0 p-0 sm:max-w-72">
          <SheetTitle className="sr-only">Menu de navigation</SheetTitle>
          <SheetDescription className="sr-only">
            Navigation entre les vues de la plateforme
          </SheetDescription>
          <div className="flex h-16 shrink-0 items-center border-b px-4">
            <Logo />
          </div>
          <div className="flex-1 overflow-y-auto p-3 scrollbar-slim">
            <NavList view={view} onView={onView} onNavigate={() => setMobileOpen(false)} />
          </div>
          <div className="border-t p-3">
            <UserCard user={user} onLogout={onLogout} />
          </div>
        </SheetContent>
      </Sheet>

      {/* Contenu principal */}
      <main className="flex-1 md:pl-60 print:pl-0">
        <div className="mx-auto w-full max-w-7xl space-y-6 p-4 sm:p-6">{children}</div>
      </main>

      {/* Pied de page collant */}
      <footer className="mt-auto border-t md:pl-60 print:hidden">
        <div className="text-muted-foreground mx-auto flex w-full max-w-7xl flex-col gap-1 px-4 py-4 text-xs sm:flex-row sm:items-center sm:justify-between">
          <p>AuditForge v1.0 — Plateforme d&apos;audit unifiée auto-hébergée</p>
          <p className="sm:text-right">
            Exécution réelle ou simulation selon la configuration du moteur
            (TOOL_EXECUTION_MODE).
          </p>
        </div>
      </footer>
    </div>
  );
}
