"use client";

/**
 * AuditForge — Page unique (SPA) : démarrage, authentification, coquille
 * applicative et routage par vue (état local, aucune route supplémentaire).
 */

import { useCallback, useEffect, useState } from "react";
import { Loader2, Shield } from "lucide-react";
import { apiGet, apiPost } from "@/lib/api-client";
import { resetSocketState } from "@/hooks/use-socket";
import { LoginScreen } from "@/components/audit/login-screen";
import { AppShell, type View } from "@/components/audit/app-shell";
import { DashboardView } from "@/components/audit/dashboard-view";
import { CampaignsView } from "@/components/audit/campaigns-view";
import { ScansView } from "@/components/audit/scans-view";
import { FindingsView } from "@/components/audit/findings-view";
import { ReportsView } from "@/components/audit/reports-view";
import { ToolsView } from "@/components/audit/tools-view";
import { AuditLogView } from "@/components/audit/audit-log-view";
import { ScanDetail } from "@/components/audit/scan-detail";
import type { UserDTO } from "@/lib/types";

export default function Page() {
  const [booting, setBooting] = useState(true);
  const [user, setUser] = useState<UserDTO | null>(null);
  const [view, setView] = useState<View>("dashboard");
  const [scanDetailId, setScanDetailId] = useState<string | null>(null);
  const [scanReportId, setScanReportId] = useState<string | null>(null);
  const [campaignFilter, setCampaignFilter] = useState<string | null>(null);

  // Session existante ?
  useEffect(() => {
    void (async () => {
      try {
        const res = await apiGet<{ user: UserDTO }>("/api/auth/me");
        setUser(res.user);
      } catch {
        setUser(null);
      } finally {
        setBooting(false);
      }
    })();
  }, []);

  // 401 hors routes d'authentification → session expirée : retour au login
  // et nettoyage des états locaux de vue.
  useEffect(() => {
    const onSessionExpired = () => {
      setUser(null);
      setView("dashboard");
      setScanDetailId(null);
      setScanReportId(null);
      setCampaignFilter(null);
      // Purge du socket (token caché + singleton) : la reconnexion après
      // re-login repartira d'un token frais.
      resetSocketState();
    };
    window.addEventListener("af:session-expired", onSessionExpired);
    return () =>
      window.removeEventListener("af:session-expired", onSessionExpired);
  }, []);

  const logout = useCallback(async () => {
    try {
      await apiPost("/api/auth/logout");
    } catch {
      // La déconnexion locale a priorité même si l'API échoue.
    }
    setUser(null);
    setView("dashboard");
    setScanDetailId(null);
    setScanReportId(null);
    setCampaignFilter(null);
    // Purge du socket (token caché + singleton) pour la prochaine session.
    resetSocketState();
  }, []);

  const openScan = useCallback((scanId: string) => {
    setScanDetailId(scanId);
  }, []);

  const openReportFor = useCallback((scanId: string) => {
    setScanDetailId(null);
    setScanReportId(scanId);
    setView("reports");
  }, []);

  const viewScansFor = useCallback((campaignId: string) => {
    setCampaignFilter(campaignId);
    setView("scans");
  }, []);

  if (booting) {
    return (
      <div
        className="flex min-h-screen flex-col items-center justify-center gap-4"
        aria-busy="true"
        aria-live="polite"
      >
        <div
          className="border-primary/50 bg-primary/10 text-primary flex size-14 items-center justify-center rounded-full border"
          aria-hidden
        >
          <Shield className="size-7 af-live-dot" />
        </div>
        <p className="text-sm font-semibold tracking-tight">AuditForge</p>
        <Loader2 className="text-muted-foreground size-5 animate-spin" aria-hidden />
        <p className="text-muted-foreground text-xs">
          Chargement de la plateforme…
        </p>
      </div>
    );
  }

  if (!user) {
    return (
      <LoginScreen
        onLogin={(u) => {
          // Repart d'un socket sain (token frais) après une authentification.
          resetSocketState();
          setUser(u);
          setView("dashboard");
        }}
      />
    );
  }

  return (
    <>
      <AppShell user={user} view={view} onView={setView} onLogout={() => void logout()}>
        {view === "dashboard" && (
          <DashboardView
            user={user}
            onOpenScan={openScan}
            onNavigate={(v) => setView(v)}
          />
        )}
        {view === "campaigns" && (
          <CampaignsView
            user={user}
            onOpenScan={openScan}
            onViewScansFor={viewScansFor}
          />
        )}
        {view === "scans" && (
          <ScansView
            key={campaignFilter ?? "all"}
            user={user}
            onOpenScan={openScan}
            initialCampaignId={campaignFilter}
            onClearCampaign={() => setCampaignFilter(null)}
            onOpenReport={openReportFor}
          />
        )}
        {view === "findings" && <FindingsView user={user} />}
        {view === "reports" && (
          <ReportsView
            user={user}
            scanReportId={scanReportId}
            onConsumeReportId={() => setScanReportId(null)}
          />
        )}
        {view === "tools" && <ToolsView />}
        {view === "audit" && <AuditLogView />}
      </AppShell>

      {/* Panneau de détail de scan (au-dessus de tout) */}
      <ScanDetail
        scanId={scanDetailId}
        open={scanDetailId !== null}
        onClose={() => setScanDetailId(null)}
        user={user}
        onOpenReport={openReportFor}
      />
    </>
  );
}
