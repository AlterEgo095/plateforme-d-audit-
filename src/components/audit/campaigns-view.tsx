"use client";

/**
 * AuditForge — Vue Campagnes : création (assistant), liste des campagnes,
 * relance et suppression (ADMIN), suivi par scan.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Crosshair,
  GitBranch,
  Globe,
  Info,
  Loader2,
  Network,
  Plus,
  RotateCcw,
  Table2,
  Trash2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { Switch } from "@/components/ui/switch";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
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
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { apiGet, apiPost, apiDelete, getErrorMessage } from "@/lib/api-client";
import { useScanEvents } from "@/hooks/use-socket";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import {
  EmptyState,
  PROFILE_LABELS,
  ScanStatusBadge,
  TOOL_META,
  ToolBadge,
  formatDateTime,
} from "@/components/audit/status-badges";
import type {
  CampaignDTO,
  Profile,
  TargetType,
  Tool,
  UserDTO,
} from "@/lib/types";

const TOOL_IDS = Object.keys(TOOL_META) as Tool[];

const TARGET_PLACEHOLDERS: Record<TargetType, string> = {
  URL: "https://cible.exemple.com",
  GIT: "https://github.com/org/repo.git",
  NETWORK: "10.0.0.0/24",
};

const TARGET_ICONS: Record<TargetType, typeof Globe> = {
  URL: Globe,
  GIT: GitBranch,
  NETWORK: Network,
};

export function CampaignsView({
  user,
  onOpenScan,
  onViewScansFor,
}: {
  user: UserDTO;
  onOpenScan: (scanId: string) => void;
  onViewScansFor: (campaignId: string) => void;
}) {
  const { toast } = useToast();
  const [campaigns, setCampaigns] = useState<CampaignDTO[]>([]);
  const [loading, setLoading] = useState(true);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<CampaignDTO | null>(null);
  const [relaunchTarget, setRelaunchTarget] = useState<CampaignDTO | null>(null);
  const [relaunchingId, setRelaunchingId] = useState<string | null>(null);
  const refreshTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await apiGet<{ campaigns: CampaignDTO[] }>("/api/campaigns");
      setCampaigns(res.campaigns);
    } catch (e) {
      toast({
        title: "Erreur",
        description: getErrorMessage(e),
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

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

  const relaunch = async (campaign: CampaignDTO) => {
    const tools = Array.from(new Set(campaign.scans.map((s) => s.tool)));
    setRelaunchingId(campaign.id);
    try {
      const res = await apiPost<{ campaign: CampaignDTO; warning?: string }>(
        `/api/campaigns/${campaign.id}/launch`,
        { tools }
      );
      if (res.warning) {
        toast({
          title: "Campagne relancée avec un avertissement",
          description: res.warning,
          variant: "destructive",
        });
      } else {
        toast({
          title: "Campagne relancée",
          description: `${tools.length} nouveau(x) scan(s) remis en file d'attente.`,
        });
      }
      void load();
    } catch (e) {
      toast({
        title: "Erreur",
        description: getErrorMessage(e),
        variant: "destructive",
      });
    } finally {
      setRelaunchingId(null);
    }
  };

  const remove = async (campaign: CampaignDTO) => {
    try {
      await apiDelete(`/api/campaigns/${campaign.id}`);
      toast({
        title: "Campagne supprimée",
        description: `« ${campaign.name} » et ses scans ont été supprimés.`,
      });
      void load();
    } catch (e) {
      toast({
        title: "Erreur",
        description: getErrorMessage(e),
        variant: "destructive",
      });
    }
  };

  const canWrite = user.role !== "VIEWER";

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold tracking-tight">Campagnes d&apos;audit</h2>
          <p className="text-muted-foreground text-sm">
            {loading
              ? "Chargement…"
              : `${campaigns.length} campagne(s) enregistrée(s)`}
          </p>
        </div>
        {canWrite && (
          <CreateCampaignDialog
            open={dialogOpen}
            onOpenChange={setDialogOpen}
            onCreated={() => {
              setDialogOpen(false);
              void load();
            }}
          />
        )}
      </div>

      {loading ? (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-48 w-full rounded-xl" />
          ))}
        </div>
      ) : campaigns.length === 0 ? (
        <Card>
          <EmptyState
            icon={Crosshair}
            title="Aucune campagne"
            description="Une campagne regroupe des scans exécutés par un ou plusieurs outils sur une cible commune. Créez la première campagne pour démarrer."
            action={
              canWrite ? (
                <Button onClick={() => setDialogOpen(true)}>
                  <Plus className="size-4" aria-hidden />
                  Nouvelle campagne
                </Button>
              ) : undefined
            }
          />
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {campaigns.map((campaign) => (
            <CampaignCard
              key={campaign.id}
              campaign={campaign}
              user={user}
              onOpenScan={onOpenScan}
              onViewScansFor={onViewScansFor}
              onRelaunch={(c) => setRelaunchTarget(c)}
              onDelete={() => setDeleteTarget(campaign)}
              relaunching={relaunchingId === campaign.id}
            />
          ))}
        </div>
      )}

      {/* Confirmation de relance (ré-exécution des outils) */}
      <AlertDialog
        open={relaunchTarget !== null}
        onOpenChange={(o) => !o && setRelaunchTarget(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Relancer cette campagne ?</AlertDialogTitle>
            <AlertDialogDescription>
              Un nouveau scan sera créé pour chaque outil :{" "}
              <span className="text-foreground font-mono font-semibold">
                {relaunchTarget
                  ? Array.from(
                      new Set(relaunchTarget.scans.map((s) => s.tool))
                    ).join(", ")
                  : ""}
              </span>
              . Les résultats des exécutions précédentes sont conservés.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="min-h-10">Annuler</AlertDialogCancel>
            <AlertDialogAction
              className="min-h-10"
              disabled={relaunchingId !== null}
              onClick={() => {
                if (relaunchTarget) void relaunch(relaunchTarget);
                setRelaunchTarget(null);
              }}
            >
              Relancer
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Confirmation de suppression (ADMIN) */}
      <AlertDialog
        open={deleteTarget !== null}
        onOpenChange={(o) => !o && setDeleteTarget(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Supprimer cette campagne ?</AlertDialogTitle>
            <AlertDialogDescription>
              La campagne « {deleteTarget?.name} » ainsi que tous ses scans,
              vulnérabilités et journaux associés seront définitivement
              supprimés. Cette action est irréversible.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="min-h-10">Annuler</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-white hover:bg-destructive/90"
              onClick={() => {
                if (deleteTarget) void remove(deleteTarget);
                setDeleteTarget(null);
              }}
            >
              Supprimer définitivement
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

function CampaignCard({
  campaign,
  user,
  onOpenScan,
  onViewScansFor,
  onRelaunch,
  onDelete,
  relaunching,
}: {
  campaign: CampaignDTO;
  user: UserDTO;
  onOpenScan: (scanId: string) => void;
  onViewScansFor: (campaignId: string) => void;
  onRelaunch: (campaign: CampaignDTO) => void;
  onDelete: () => void;
  relaunching: boolean;
}) {
  const TargetIcon = TARGET_ICONS[campaign.targetType];
  const tools = useMemo(
    () => Array.from(new Set(campaign.scans.map((s) => s.tool))),
    [campaign.scans]
  );
  const hasRunning = campaign.scans.some(
    (s) => s.status === "RUNNING" || s.status === "QUEUED"
  );
  const canRelaunch =
    user.role !== "VIEWER" && !hasRunning && campaign.scansCount > 0;

  return (
    <Card className="flex flex-col gap-0 overflow-hidden">
      <CardHeader className="space-y-2 pb-3">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <CardTitle className="text-base leading-snug">{campaign.name}</CardTitle>
          <ScanStatusBadge status={campaign.status} />
        </div>
        <CardDescription className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
          <span className="inline-flex items-center gap-1.5 font-mono">
            <TargetIcon className="size-3.5" aria-hidden />
            {campaign.target}
          </span>
          <span className="text-muted-foreground">
            {PROFILE_LABELS[campaign.profile] ?? campaign.profile}
          </span>
        </CardDescription>
        <CardDescription className="text-xs">
          Créée par {campaign.createdByName || "—"} · {formatDateTime(campaign.createdAt)}
        </CardDescription>
        {campaign.description && (
          <CardDescription className="line-clamp-2 text-xs">
            {campaign.description}
          </CardDescription>
        )}
      </CardHeader>

      <CardContent className="flex flex-1 flex-col gap-3 pt-0">
        {/* Outils */}
        <div className="flex flex-wrap gap-1.5">
          {tools.length === 0 ? (
            <span className="text-muted-foreground text-xs italic">
              Aucun scan associé
            </span>
          ) : (
            tools.map((t) => <ToolBadge key={t} tool={t} small />)
          )}
        </div>

        {/* Progression par scan (liste tronquée à 50 — le total réel est scansCount) */}
        {campaign.scans.length > 0 && (
          <div className="space-y-1.5">
            {campaign.scans.map((scan) => (
              <div key={scan.id} className="flex items-center gap-2">
                <ToolBadge tool={scan.tool} small />
                <Progress value={scan.progress} className="h-1.5 flex-1" aria-hidden />
                <ScanStatusBadge status={scan.status} className="hidden sm:inline-flex" />
                <button
                  type="button"
                  className="text-muted-foreground hover:text-foreground inline-flex min-h-9 items-center gap-1 text-xs tabular-nums"
                  onClick={() => onOpenScan(scan.id)}
                  aria-label={`Voir le détail du scan ${scan.tool} : ${scan.findingsCount} vulnérabilité(s)`}
                >
                  {scan.findingsCount} vuln.
                  {scan.criticalCount > 0 && (
                    <span className="font-semibold" style={{ color: "#f43f5e" }}>
                      ({scan.criticalCount} crit.)
                    </span>
                  )}
                </button>
              </div>
            ))}
          </div>
        )}

        <Separator className="mt-auto" />

        {/* Actions */}
        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            className="h-11 sm:h-9 flex-1 sm:flex-none"
            onClick={() => onViewScansFor(campaign.id)}
          >
            <Table2 className="size-4" aria-hidden />
            Voir les scans
          </Button>
          {canRelaunch && (
            <Button
              variant="secondary"
              size="sm"
              className="h-11 sm:h-9 flex-1 sm:flex-none"
              disabled={relaunching}
              onClick={() => onRelaunch(campaign)}
            >
              {relaunching ? (
                <Loader2 className="size-4 animate-spin" aria-hidden />
              ) : (
                <RotateCcw className="size-4" aria-hidden />
              )}
              Relancer
            </Button>
          )}
          {user.role === "ADMIN" && (
            <TooltipProvider delayDuration={200}>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="ml-auto size-11 text-muted-foreground hover:text-rose-400"
                    aria-label={`Supprimer la campagne ${campaign.name}`}
                    onClick={onDelete}
                  >
                    <Trash2 className="size-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Supprimer (administrateur)</TooltipContent>
              </Tooltip>
            </TooltipProvider>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function CreateCampaignDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: () => void;
}) {
  const { toast } = useToast();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [targetType, setTargetType] = useState<TargetType>("URL");
  const [target, setTarget] = useState("");
  const [profile, setProfile] = useState<Profile>("STANDARD");
  const [tools, setTools] = useState<Tool[]>(["PHANTOM"]);
  const [launchNow, setLaunchNow] = useState(true);
  const [submitting, setSubmitting] = useState(false);

  const compatibleTools = useMemo(
    () =>
      TOOL_IDS.map((id) => ({
        id,
        ...TOOL_META[id],
        compatible: TOOL_META[id].supportedTargets.includes(targetType),
      })),
    [targetType]
  );

  // Retire les outils devenus incompatibles quand le type de cible change.
  useEffect(() => {
    setTools((prev) =>
      prev.filter((t) =>
        compatibleTools.find((meta) => meta.id === t)?.compatible
      )
    );
  }, [compatibleTools]);

  const reset = () => {
    setName("");
    setDescription("");
    setTargetType("URL");
    setTarget("");
    setProfile("STANDARD");
    setTools(["PHANTOM"]);
    setLaunchNow(true);
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !target.trim() || tools.length === 0) return;
    setSubmitting(true);
    try {
      const res = await apiPost<{
        campaign: CampaignDTO;
        warning?: string;
      }>("/api/campaigns", {
        name: name.trim(),
        description: description.trim() || undefined,
        target: target.trim(),
        targetType,
        profile,
        tools,
        launchNow,
      });
      toast({
        title: "Campagne créée",
        description: res.warning
          ? res.warning
          : launchNow
            ? "Les scans ont été lancés sur la cible."
            : "Vous pouvez lancer les scans depuis la liste des campagnes.",
      });
      reset();
      onCreated();
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
      <DialogTrigger asChild>
        <Button className="min-h-11">
          <Plus className="size-4" aria-hidden />
          Nouvelle campagne
        </Button>
      </DialogTrigger>
      <DialogContent className="max-h-[92vh] overflow-y-auto sm:max-w-xl scrollbar-slim">
        <DialogHeader>
          <DialogTitle>Nouvelle campagne d&apos;audit</DialogTitle>
          <DialogDescription>
            Définissez la cible, le profil d&apos;exécution et les outils à
            orchestrer.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={submit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="campaign-name">Nom de la campagne *</Label>
            <Input
              id="campaign-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="ex. Audit trimestriel du portail client"
              required
              maxLength={120}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="campaign-desc">Description</Label>
            <Textarea
              id="campaign-desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Objectif, périmètre, contexte…"
              rows={2}
              maxLength={500}
            />
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label>Type de cible</Label>
              <Select
                value={targetType}
                onValueChange={(v) => setTargetType(v as TargetType)}
              >
                <SelectTrigger className="w-full" aria-label="Type de cible">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="URL">Application web (URL)</SelectItem>
                  <SelectItem value="GIT">Dépôt de code (Git)</SelectItem>
                  <SelectItem value="NETWORK">Plage réseau / hôte</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="campaign-target">Cible *</Label>
              <Input
                id="campaign-target"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder={TARGET_PLACEHOLDERS[targetType]}
                className="font-mono"
                required
              />
            </div>
          </div>

          <div className="space-y-2">
            <Label>Profil d&apos;exécution</Label>
            <Select
              value={profile}
              onValueChange={(v) => setProfile(v as Profile)}
            >
              <SelectTrigger className="w-full" aria-label="Profil d'exécution">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="QUICK">Rapide (~25 s)</SelectItem>
                <SelectItem value="STANDARD">Standard (~45 s)</SelectItem>
                <SelectItem value="DEEP">Approfondi (~80 s)</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label>Outils à orchestrer *</Label>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              {compatibleTools.map((t) => {
                const checked = tools.includes(t.id);
                return (
                  <TooltipProvider key={t.id} delayDuration={200}>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <label
                          className={cn(
                            "flex cursor-pointer items-start gap-2.5 rounded-lg border p-3 transition-colors",
                            checked
                              ? "border-primary bg-primary/10"
                              : "hover:bg-accent/50",
                            !t.compatible && "cursor-not-allowed opacity-45"
                          )}
                        >
                          <Checkbox
                            className="mt-0.5"
                            checked={checked && t.compatible}
                            disabled={!t.compatible}
                            onCheckedChange={(v) =>
                              setTools((prev) =>
                                v
                                  ? [...prev, t.id]
                                  : prev.filter((x) => x !== t.id)
                              )
                            }
                            aria-label={`Sélectionner l'outil ${t.id}`}
                          />
                          <span className="min-w-0 space-y-0.5">
                            <ToolBadge tool={t.id} small />
                            <span className="block text-xs leading-snug">
                              {t.description}
                            </span>
                            <span className="text-muted-foreground block text-[11px]">
                              {t.supportedTargets
                                .map((tt) =>
                                  tt === "URL"
                                    ? "URL"
                                    : tt === "GIT"
                                      ? "Git"
                                      : "Réseau"
                                )
                                .join(" · ")}
                            </span>
                          </span>
                        </label>
                      </TooltipTrigger>
                      {!t.compatible && (
                        <TooltipContent>
                          Outil incompatible avec ce type de cible
                        </TooltipContent>
                      )}
                    </Tooltip>
                  </TooltipProvider>
                );
              })}
            </div>
            {tools.length === 0 && (
              <p className="text-destructive text-xs" role="alert">
                Sélectionnez au moins un outil compatible.
              </p>
            )}
          </div>

          <div className="flex items-center justify-between gap-3 rounded-lg border p-3">
            <div className="space-y-0.5">
              <Label htmlFor="launch-now" className="cursor-pointer">
                Lancer les scans immédiatement
              </Label>
              <p className="text-muted-foreground text-xs">
                Les scans passent en file d&apos;attente dès la création.
              </p>
            </div>
            <Switch
              id="launch-now"
              checked={launchNow}
              onCheckedChange={setLaunchNow}
            />
          </div>

          <div className="bg-muted/40 flex items-start gap-2 rounded-lg p-3 text-xs text-muted-foreground">
            <Info className="mt-0.5 size-3.5 shrink-0" aria-hidden />
            Compatibilité outils ⇄ cibles : PHANTOM et REDAMON ciblent les URL
            et plages réseau ; DEEPAUDIT et BASALT ciblent les URL et dépôts
            Git.
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
                submitting || !name.trim() || !target.trim() || tools.length === 0
              }
            >
              {submitting && <Loader2 className="size-4 animate-spin" aria-hidden />}
              {submitting ? "Création…" : "Créer la campagne"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
