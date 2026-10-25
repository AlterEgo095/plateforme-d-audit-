/**
 * AuditForge — Adaptateur réel DEEPAUDIT (github.com/lintsinghua/DeepAudit).
 *
 * DeepAudit = plateforme d'audit de code multi-agents LLM (FastAPI + Postgres
 * + sandbox Docker). Contrairement à Phantom/Basalt (CLI locales), c'est une
 * plateforme distante que le moteur pilote par API REST.
 *
 * Flux d'intégration (API /api/v1, auth JWT Bearer) :
 *   1. POST /auth/login (form OAuth2 : username=email, password) → access_token
 *   2. POST /projects {source_type:"repository", repository_url} → projet
 *      (le dépôt est cloné PAR DeepAudit côté serveur — aucune copie locale) ;
 *   3. POST /agent-tasks {project_id, verification_level, …} → tâche d'audit ;
 *   4. polling GET /agent-tasks/{id} (status, current_phase,
 *      progress_percentage, findings_count…) → onPhase/onLog ;
 *   5. GET /agent-tasks/{id}/findings → constats normalisés ;
 *      GET /agent-tasks/{id}/summary → score de sécurité (journal final).
 *   Annulation : POST /agent-tasks/{id}/cancel.
 *
 * Niveaux de vérification selon le profil :
 *   QUICK → analysis_only, STANDARD → sandbox, DEEP → generate_poc.
 *
 * Cible : GIT uniquement (DeepAudit audite du code, pas une application
 * déployée) — la matrice TOOL_TARGET_COMPAT est alignée côté application.
 *
 * Prérequis : plateforme DeepAudit déployée à côté du moteur (docker-compose
 * du dépôt DeepAudit) + DEEPAUDIT_API_URL / DEEPAUDIT_EMAIL / DEEPAUDIT_PASSWORD.
 */

import { REAL_EXEC } from "./env";
import { assertSafeGitTarget } from "./git-target";
import { HttpError, httpJson, sleepInterruptible } from "./remote";
import type {
  RealAdapterContext,
  RealAvailability,
  RealFinding,
  RealToolAdapter,
} from "./types";

const SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);
const MAX_FINDINGS = 500;

/** Phases DeepAudit → libellés FR affichés dans la vue de scan. */
const PHASE_LABELS: Record<string, string> = {
  planning: "PLANIFICATION",
  indexing: "INDEXATION",
  reconnaissance: "RECONNAISSANCE",
  analysis: "ANALYSE",
  analyzing: "ANALYSE",
  verification: "VÉRIFICATION",
  verifying: "VÉRIFICATION",
  reporting: "RAPPORT",
  initializing: "INITIALISATION",
};

interface DeepAuditFinding {
  id?: string;
  vulnerability_type?: string | null;
  severity?: string;
  title?: string;
  description?: string | null;
  file_path?: string | null;
  line_start?: number | null;
  line_end?: number | null;
  code_snippet?: string | null;
  is_verified?: boolean;
  confidence?: number | null;
  status?: string;
  suggestion?: string | null;
  poc?: Record<string, unknown> | null;
}

interface DeepAuditTask {
  id?: string;
  status?: string;
  current_phase?: string | null;
  current_step?: string | null;
  progress_percentage?: number | null;
  findings_count?: number | null;
  verified_count?: number | null;
  error_message?: string | null;
  security_score?: number | null;
}

interface DeepAuditSummary {
  security_score?: number | null;
  total_findings?: number | null;
  verified_findings?: number | null;
  severity_distribution?: Record<string, number>;
}

function mapSeverity(raw: unknown): RealFinding["severity"] {
  const v = String(raw ?? "").toLowerCase();
  return SEVERITIES.has(v) ? (v.toUpperCase() as RealFinding["severity"]) : "MEDIUM";
}

function mapVerificationLevel(profile: "QUICK" | "STANDARD" | "DEEP"): string {
  if (profile === "QUICK") return "analysis_only";
  if (profile === "DEEP") return "generate_poc";
  return "sandbox";
}

function repositoryType(url: string): string {
  const lower = url.toLowerCase();
  if (lower.includes("github.com")) return "github";
  if (lower.includes("gitlab")) return "gitlab";
  return "other";
}

export class DeepAuditAdapter implements RealToolAdapter {
  readonly tool = "DEEPAUDIT" as const;

  /** Jeton JWT mis en cache entre checkAvailable() et run() (même instance). */
  private token: string | null = null;

  private get baseUrl(): string {
    return (REAL_EXEC.deepauditUrl ?? "").replace(/\/+$/, "");
  }

  private get configured(): boolean {
    return Boolean(this.baseUrl && REAL_EXEC.deepauditEmail && REAL_EXEC.deepauditPassword);
  }

  private configError(): string {
    if (!this.baseUrl) {
      return "DEEPAUDIT_API_URL non configurée (plateforme à déployer séparément — voir README)";
    }
    return "DEEPAUDIT_EMAIL / DEEPAUDIT_PASSWORD non configurés (compte DeepAudit requis)";
  }

  /** Connexion (form OAuth2) — jeton mis en cache pour le reste du scan. */
  private async login(signal?: AbortSignal): Promise<string> {
    if (this.token) return this.token;
    const body = new URLSearchParams({
      username: REAL_EXEC.deepauditEmail,
      password: REAL_EXEC.deepauditPassword,
    });
    const res = await httpJson<{ access_token?: string }>(`${this.baseUrl}/api/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
      timeoutMs: 12_000,
      signal,
    });
    if (!res.access_token) throw new Error("DeepAudit : login sans access_token (réponse inattendue)");
    this.token = res.access_token;
    return this.token;
  }

  /** Rejoue la requête avec le Bearer ; re-login unique sur 401. */
  private async authed<T>(fn: (token: string) => Promise<T>, signal?: AbortSignal): Promise<T> {
    const token = await this.login(signal);
    try {
      return await fn(token);
    } catch (err) {
      if (err instanceof HttpError && err.status === 401) {
        this.token = null;
        const fresh = await this.login(signal);
        return await fn(fresh);
      }
      throw err;
    }
  }

  async checkAvailable(): Promise<RealAvailability> {
    if (!this.configured) return { available: false, reason: this.configError() };
    try {
      // 1) la plateforme répond-elle ? (/health est publique)
      await httpJson<unknown>(`${this.baseUrl}/health`, { timeoutMs: 5_000 });
      // 2) les identifiants sont-ils valides ?
      await this.login();
      return { available: true };
    } catch (err) {
      const reason =
        err instanceof HttpError
          ? err.status === 401 || err.status === 400
            ? "authentification DeepAudit refusée (vérifier DEEPAUDIT_EMAIL / DEEPAUDIT_PASSWORD)"
            : `DeepAudit inaccessible : ${err.message}`
          : `DeepAudit inaccessible sur ${this.baseUrl} (${err instanceof Error ? err.message : "erreur réseau"})`;
      return { available: false, reason };
    }
  }

  async run(ctx: RealAdapterContext): Promise<RealFinding[]> {
    if (ctx.targetType !== "GIT") {
      // Défense en profondeur : la matrice applicative doit déjà l'exclure.
      throw new Error(
        "DeepAudit audite du CODE : une cible GIT (URL de dépôt) est requise pour l'exécution réelle",
      );
    }
    assertSafeGitTarget(ctx.target);
    const deadline = Date.now() + REAL_EXEC.timeoutMinutes * 60_000;

    await ctx.onLog(`Plateforme DeepAudit : ${this.baseUrl}`, "INFO", "deepaudit");
    await ctx.onPhase("INITIALISATION", 2);

    // ── 1. Projet (DeepAudit clone le dépôt lui-même) ──
    const shortName = ctx.target.replace(/\.git$/i, "").split(/[/:]/).filter(Boolean).pop() ?? "cible";
    const project = await this.authed(
      (token) =>
        httpJson<{ id?: string }>(`${this.baseUrl}/api/v1/projects`, {
          method: "POST",
          headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
          body: JSON.stringify({
            name: `AuditForge ${shortName} ${new Date().toISOString().slice(0, 16)}`,
            description: `Audit lancé par AuditForge (scan ${ctx.scanId}, profil ${ctx.profile})`,
            source_type: "repository",
            repository_url: ctx.target,
            repository_type: repositoryType(ctx.target),
            default_branch: "main",
            programming_languages: [],
          }),
          timeoutMs: 20_000,
          signal: ctx.signal,
        }),
      ctx.signal,
    );
    if (!project.id) throw new Error("DeepAudit : création de projet sans identifiant");
    await ctx.onLog(`Projet DeepAudit créé (${project.id}) — dépôt : ${ctx.target}`, "INFO", "deepaudit");

    // ── 2. Tâche d'audit agent ──
    const task = await this.authed(
      (token) =>
        httpJson<DeepAuditTask>(`${this.baseUrl}/api/v1/agent-tasks`, {
          method: "POST",
          headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
          body: JSON.stringify({
            project_id: project.id,
            name: `AuditForge ${ctx.scanId}`,
            description: `Audit ${ctx.tool} profil ${ctx.profile} — cible ${ctx.target}`,
            verification_level: mapVerificationLevel(ctx.profile),
            max_iterations: ctx.profile === "DEEP" ? 100 : ctx.profile === "QUICK" ? 25 : 50,
            timeout_seconds: Math.min(REAL_EXEC.timeoutMinutes * 60, 7200),
          }),
          timeoutMs: 20_000,
          signal: ctx.signal,
        }),
      ctx.signal,
    );
    if (!task.id) throw new Error("DeepAudit : création de tâche sans identifiant");
    await ctx.onLog(
      `Tâche d'audit ${task.id} lancée (vérification : ${mapVerificationLevel(ctx.profile)})`,
      "CMD",
      "deepaudit",
    );

    // ── 3. Polling de progression ──
    let lastPhase = "";
    let lastFindingsCount = -1;
    let finalTask: DeepAuditTask | null = null;
    let polls = 0;
    for (;;) {
      const taskId = task.id as string;
      if (ctx.signal.aborted) {
        await this.cancelTask(taskId).catch(() => undefined);
        throw ctx.signal.reason instanceof Error ? ctx.signal.reason : new Error("scan annulé");
      }
      if (Date.now() > deadline) {
        await this.cancelTask(taskId).catch(() => undefined);
        throw new Error("Scan DeepAudit : timeout global atteint (annulation demandée côté plateforme)");
      }
      await sleepInterruptible(3_000, ctx.signal).catch(async (err) => {
        await this.cancelTask(taskId).catch(() => undefined);
        throw err;
      });

      const current = await this.authed(
        (token) =>
          httpJson<DeepAuditTask>(`${this.baseUrl}/api/v1/agent-tasks/${task.id}`, {
            headers: { Authorization: `Bearer ${token}` },
            timeoutMs: 15_000,
            signal: ctx.signal,
          }),
        ctx.signal,
      ).catch((err) => {
        // erreur réseau ponctuelle : on tolère 5 échecs consécutifs avant abandon
        polls += 1;
        if (polls >= 5) throw err;
        return null as unknown as DeepAuditTask;
      });
      if (!current) continue;
      polls = 0;

      const status = String(current.status ?? "").toLowerCase();
      if (status === "failed") {
        throw new Error(`DeepAudit : tâche en échec${current.error_message ? ` — ${current.error_message}` : ""}`);
      }
      if (status === "cancelled") {
        throw new Error("DeepAudit : tâche annulée côté plateforme");
      }
      if (status === "completed") {
        finalTask = current;
        break;
      }

      const phaseKey = String(current.current_phase ?? "").toLowerCase();
      const phaseLabel = PHASE_LABELS[phaseKey] ?? (current.current_phase ? String(current.current_phase) : "EXÉCUTION");
      const pct =
        typeof current.progress_percentage === "number"
          ? Math.max(0, Math.min(99, Math.round(current.progress_percentage)))
          : undefined;
      if (phaseLabel !== lastPhase || pct !== undefined) {
        lastPhase = phaseLabel;
        await ctx.onPhase(phaseLabel, pct);
      }
      const count = typeof current.findings_count === "number" ? current.findings_count : null;
      if (count !== null && count !== lastFindingsCount) {
        lastFindingsCount = count;
        await ctx.onLog(
          `Phase ${phaseLabel.toLowerCase()} — ${count} constat(s) intermédiaire(s), étape : ${current.current_step ?? "en cours"}`,
          "AGENT",
          "deepaudit",
        );
      }
    }

    // ── 4. Récupération des constats (paginé) ──
    const findings: RealFinding[] = [];
    let skippedFalsePositives = 0;
    for (let skip = 0; findings.length < MAX_FINDINGS; skip += 200) {
      const batch = await this.authed(
        (token) =>
          httpJson<DeepAuditFinding[]>(
            `${this.baseUrl}/api/v1/agent-tasks/${task.id}/findings?skip=${skip}&limit=200`,
            { headers: { Authorization: `Bearer ${token}` }, timeoutMs: 30_000, signal: ctx.signal },
          ),
        ctx.signal,
      ).catch(() => [] as DeepAuditFinding[]);
      for (const f of batch) {
        if (String(f.status ?? "").toLowerCase() === "false_positive") {
          skippedFalsePositives += 1;
          continue;
        }
        findings.push(this.mapFinding(f));
        if (findings.length >= MAX_FINDINGS) break;
      }
      if (batch.length < 200) break;
    }

    // ── 5. Résumé final ──
    let summary: DeepAuditSummary | null = null;
    try {
      summary = await this.authed(
        (token) =>
          httpJson<DeepAuditSummary>(`${this.baseUrl}/api/v1/agent-tasks/${task.id}/summary`, {
            headers: { Authorization: `Bearer ${token}` },
            timeoutMs: 15_000,
            signal: ctx.signal,
          }),
        ctx.signal,
      );
    } catch {
      /* best effort */
    }

    await ctx.onPhase("RAPPORT", 98);
    const score =
      typeof summary?.security_score === "number"
        ? ` — score de sécurité : ${summary.security_score}/100`
        : "";
    await ctx.onLog(
      `DeepAudit terminé (statut ${finalTask?.status ?? "completed"}) — ${findings.length} constat(s) retenu(s)` +
        `${skippedFalsePositives ? `, ${skippedFalsePositives} faux positif(s) écarté(s)` : ""}${score}`,
      "SUCCESS",
      "deepaudit",
    );
    return findings;
  }

  private mapFinding(f: DeepAuditFinding): RealFinding {
    const verified = f.is_verified === true;
    const lines =
      typeof f.line_start === "number" && f.line_start > 0
        ? typeof f.line_end === "number" && f.line_end > f.line_start
          ? `:${f.line_start}-${f.line_end}`
          : `:${f.line_start}`
        : "";
    const location = f.file_path ? `${f.file_path}${lines}` : undefined;
    const evidenceParts: string[] = [];
    if (f.code_snippet) evidenceParts.push(`Extrait de code :\n${f.code_snippet}`);
    if (f.vulnerability_type) evidenceParts.push(`Type de vulnérabilité : ${f.vulnerability_type}`);
    if (verified) evidenceParts.push("Constat vérifié par les agents DeepAudit (analyse/sandbox)");
    const confidence: RealFinding["confidence"] = verified
      ? "CONFIRMED"
      : (f.confidence ?? 0) >= 0.75
        ? "PROBABLE"
        : "UNVERIFIED";
    return {
      title: String(f.title ?? "Constat DeepAudit").slice(0, 300),
      severity: mapSeverity(f.severity),
      confidence,
      category: String(f.vulnerability_type ?? "audit-code"),
      cve: null,
      cvss: null,
      location,
      description: String(f.description ?? f.title ?? "Constat renvoyé par DeepAudit"),
      evidence: evidenceParts.join("\n\n") || "(aucun extrait fourni par DeepAudit)",
      poc: f.poc ? JSON.stringify(f.poc, null, 2) : undefined,
      sentinelTriggered: verified,
      remediation: f.suggestion ?? undefined,
    };
  }

  /** Annulation best effort côté plateforme (opérateur ou timeout). */
  private async cancelTask(taskId: string): Promise<void> {
    if (!this.token) return;
    await httpJson(`${this.baseUrl}/api/v1/agent-tasks/${taskId}/cancel`, {
      method: "POST",
      headers: { Authorization: `Bearer ${this.token}` },
      timeoutMs: 8_000,
    });
  }
}
