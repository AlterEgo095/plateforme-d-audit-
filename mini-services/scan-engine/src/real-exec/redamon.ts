/**
 * AuditForge — Adaptateur réel REDAMON (github.com/samugit83/redamon).
 *
 * RedAmon = plateforme d'orchestration de reconnaissance offensive en
 * conteneurs Docker (nmap, naabu, httpx, nuclei, zap, gvm… réseaux isolés).
 * Plateforme distante pilotée par l'API REST de sa webapp Next.js.
 *
 * Auth : connexion utilisateur (POST /api/auth/login {email, password}) →
 * cookie de session `redamon-auth` (JWT 7 j). La clé interne X-Internal-Key
 * de RedAmon ne couvre pas les routes projets/recon/graph — la session est
 * donc le canal d'intégration légitime et complet.
 *
 * Flux d'intégration :
 *   1. POST /api/auth/login → session (re-login automatique sur 401) ;
 *   2. POST /api/projects — cible dérivée de la campagne AuditForge :
 *        URL     → hostname (targetDomain ; IP littérale → ipMode) ;
 *        NETWORK → targetIps (CIDR IPv4 ≤ /24, IPv6 ≥ /104 — limites RedAmon) ;
 *      scanModules selon le profil (QUICK/STANDARD/DEEP) ;
 *   3. POST /api/recon/{projectId}/start {mode:"new"} (RedAmon orchestre
 *      ses conteneurs via son recon-orchestrator interne) ;
 *   4. suivi : polling GET /api/recon/{projectId}/status (phases 1→6) +
 *      flux SSE GET /api/recon/{projectId}/logs (journal temps réel) ;
 *   5. résultats : GET /api/graph?projectId&fresh=1 → nœuds Vulnerability
 *      (nuclei, gvm, security_check, takeover, cache_poisoning, netlas…)
 *      normalisés en RealFinding + compteurs de surface (hôtes, ports…).
 *   Annulation : POST /api/recon/{projectId}/stop.
 *
 * Prérequis : plateforme RedAmon déployée à côté du moteur (son propre
 * docker-compose — PostgreSQL, Neo4j, orchestrator, webapp…) + variables
 * REDAMON_API_URL / REDAMON_EMAIL / REDAMON_PASSWORD. ≥ 8 Go RAM recommandés.
 */

import { REAL_EXEC } from "./env";
import { httpFetch, httpJson, readSse, sleepInterruptible } from "./remote";
import type {
  RealAdapterContext,
  RealAvailability,
  RealFinding,
  RealToolAdapter,
} from "./types";

const MAX_FINDINGS = 500;
const SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);
/** Sources « actives » (requêtes réelles émises contre la cible) → CONFIRMED. */
const ACTIVE_SOURCES = new Set([
  "nuclei",
  "gvm",
  "security_check",
  "graphql_scan",
  "takeover_scan",
  "cache_poisoning",
  "vhost_sni_enum",
]);

const PROFILE_MODULES: Record<"QUICK" | "STANDARD" | "DEEP", string[]> = {
  QUICK: ["port_scan", "http_probe", "vuln_scan"],
  STANDARD: ["domain_discovery", "port_scan", "http_probe", "vuln_scan"],
  DEEP: ["domain_discovery", "port_scan", "http_probe", "resource_enum", "vuln_scan"],
};

interface GraphNode {
  id: string;
  name: string;
  type: string;
  properties: Record<string, unknown>;
}
interface GraphLink {
  source: string;
  target: string;
  type: string;
}
interface GraphPayload {
  nodes?: GraphNode[];
  links?: GraphLink[];
  truncated?: { truncated?: boolean; totalNodes?: number; returnedNodes?: number };
}

interface ReconState {
  status?: string;
  current_phase?: string | null;
  phase_number?: number | null;
  total_phases?: number | null;
  error?: string | null;
}

function mapSeverity(raw: unknown): RealFinding["severity"] {
  const v = String(raw ?? "").toLowerCase();
  if (SEVERITIES.has(v)) return v.toUpperCase() as RealFinding["severity"];
  return "INFO";
}

/** Valide la cible réseau contre les limites RedAmon (CIDR v4 ≤ /24, v6 ≥ /104). */
function assertNetworkAllowed(target: string): void {
  const m = target.match(/^(.+?)\/(\d{1,3})$/);
  if (!m) {
    // IP simple (v4/v6) — toujours acceptée
    if (/^[0-9a-fA-F:.]+$/.test(target)) return;
    throw new Error(`Cible réseau invalide pour RedAmon : ${target}`);
  }
  const [, addr, prefixRaw] = m;
  const prefix = Number(prefixRaw);
  const isV6 = addr.includes(":");
  if (isV6 && prefix < 104) {
    throw new Error(`RedAmon limite les plages IPv6 à /104 minimum (reçu /${prefix})`);
  }
  if (!isV6 && prefix < 24) {
    throw new Error(`RedAmon limite les plages IPv4 à /24 maximum (reçu /${prefix})`);
  }
}

/** Dérive la cible RedAmon depuis la campagne (URL → hôte, NETWORK → IP/CIDR). */
function deriveTarget(ctx: RealAdapterContext): { targetDomain?: string; targetIps?: string[] } {
  if (ctx.targetType === "NETWORK") {
    assertNetworkAllowed(ctx.target);
    return { targetIps: [ctx.target] };
  }
  // URL → hostname ; le scan RedAmon couvre le domaine (DNS, ports, HTTP, vulns)
  let host: string;
  try {
    host = new URL(ctx.target).hostname;
  } catch {
    host = ctx.target.trim();
  }
  if (!host) throw new Error(`Impossible d'extraire un hôte de la cible : ${ctx.target}`);
  if (/^[0-9a-fA-F:.]+$/.test(host) && host.includes(".")) {
    // IP littérale : RedAmon refuse les IP en mode domaine → ipMode
    return { targetIps: [host] };
  }
  return { targetDomain: host };
}

export class RedAmonAdapter implements RealToolAdapter {
  readonly tool = "REDAMON" as const;

  /** Cookie de session RedAmon (cache d'instance — même scan). */
  private sessionCookie: string | null = null;

  private get baseUrl(): string {
    return (REAL_EXEC.redamonUrl ?? "").replace(/\/+$/, "");
  }

  private get configured(): boolean {
    return Boolean(this.baseUrl && REAL_EXEC.redamonEmail && REAL_EXEC.redamonPassword);
  }

  private configError(): string {
    if (!this.baseUrl) {
      return "REDAMON_API_URL non configurée (plateforme à déployer séparément — voir README)";
    }
    return "REDAMON_EMAIL / REDAMON_PASSWORD non configurés (compte utilisateur RedAmon requis)";
  }

  private async login(signal?: AbortSignal): Promise<string> {
    if (this.sessionCookie) return this.sessionCookie;
    const res = await httpFetch(`${this.baseUrl}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: REAL_EXEC.redamonEmail, password: REAL_EXEC.redamonPassword }),
      timeoutMs: 12_000,
      signal,
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(
        `RedAmon : connexion refusée (HTTP ${res.status})${text ? ` — ${text.slice(0, 200)}` : ""}`,
      );
    }
    const cookie =
      typeof res.headers.getSetCookie === "function"
        ? res.headers
            .getSetCookie()
            .find((c) => c.startsWith("redamon-auth="))
            ?.split(";")[0]
            ?.split("=")
            .slice(1)
            .join("=") ?? null
        : null;
    if (!cookie) throw new Error("RedAmon : login sans cookie de session (réponse inattendue)");
    this.sessionCookie = cookie;
    return cookie;
  }

  /** Requête authentifiée avec re-login unique sur 401. */
  private async authedJson<T>(url: string, init: Parameters<typeof httpJson>[1], signal?: AbortSignal): Promise<T> {
    const cookie = await this.login(signal);
    try {
      return await httpJson<T>(url, { ...init, headers: { ...init?.headers, Cookie: `redamon-auth=${cookie}` } });
    } catch (err) {
      const status = (err as { status?: number }).status;
      if (status === 401) {
        this.sessionCookie = null;
        const fresh = await this.login(signal);
        return await httpJson<T>(url, {
          ...init,
          headers: { ...init?.headers, Cookie: `redamon-auth=${fresh}` },
        });
      }
      throw err;
    }
  }

  async checkAvailable(): Promise<RealAvailability> {
    if (!this.configured) return { available: false, reason: this.configError() };
    try {
      await this.login();
      return { available: true };
    } catch (err) {
      return {
        available: false,
        reason: `RedAmon inaccessible sur ${this.baseUrl} (${err instanceof Error ? err.message : "erreur réseau"})`,
      };
    }
  }

  async run(ctx: RealAdapterContext): Promise<RealFinding[]> {
    const deadline = Date.now() + REAL_EXEC.timeoutMinutes * 60_000;
    const remaining = () => Math.max(1_000, deadline - Date.now());
    const target = deriveTarget(ctx);
    const modules = PROFILE_MODULES[ctx.profile];

    await ctx.onLog(`Plateforme RedAmon : ${this.baseUrl}`, "INFO", "redamon");
    await ctx.onLog(`Modules activés (${ctx.profile}) : ${modules.join(", ")}`, "INFO", "redamon");
    await ctx.onPhase("INITIALISATION", 2);

    // ── 1. Projet RedAmon ──
    const project = await this.authedJson<{ id?: string; name?: string }>(
      `${this.baseUrl}/api/projects`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          userId: "auditforge",
          name: `AuditForge ${ctx.scanId.slice(0, 8)} — ${ctx.profile}`,
          description: `Scan lancé par AuditForge (cible ${ctx.target})`,
          ...target,
          scanModules: modules,
          targetGuardrailEnabled: true,
        }),
        timeoutMs: 20_000,
      },
      ctx.signal,
    );
    if (!project.id) throw new Error("RedAmon : création de projet sans identifiant");
    const projectId = project.id;
    await ctx.onLog(
      `Projet RedAmon créé (${projectId}) — cible : ${target.targetDomain ?? target.targetIps?.join(", ")}`,
      "INFO",
      "redamon",
    );

    // État partagé des deux boucles (SSE + polling).
    const state = { done: false, error: "" };
    const stop = () =>
      this.authedJson(
        `${this.baseUrl}/api/recon/${projectId}/stop`,
        { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({}), timeoutMs: 8_000 },
      ).catch(() => undefined);

    // ── 2. Démarrage du recon complet ──
    await this.authedJson<ReconState>(
      `${this.baseUrl}/api/recon/${projectId}/start`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: "new" }),
        timeoutMs: 30_000,
      },
      ctx.signal,
    );
    await ctx.onLog("Scan RedAmon lancé (orchestrateur RedAmon)", "CMD", "redamon");

    // ── 3. Journal temps réel (SSE RedAmon) — boucle avec reprise ──
    const sseLoop = (async () => {
      while (!state.done) {
        if (ctx.signal.aborted) return;
        try {
          const cookie = await this.login(ctx.signal);
          const res = await httpFetch(`${this.baseUrl}/api/recon/${projectId}/logs`, {
            headers: { Accept: "text/event-stream", Cookie: `redamon-auth=${cookie}` },
            timeoutMs: Math.min(remaining(), 300_000),
            signal: ctx.signal,
          });
          if (!res.ok) {
            await sleepInterruptible(4_000, ctx.signal).catch(() => undefined);
            continue;
          }
          await readSse(
            res,
            (event, data) => {
              try {
                const payload = JSON.parse(data) as Record<string, unknown>;
                if (event === "log") {
                  const message = String(payload.log ?? "").trim();
                  if (message) {
                    const level = String(payload.level ?? "INFO").toUpperCase();
                    void ctx.onLog(
                      message,
                      level === "ERROR" ? "ERROR" : level === "WARN" ? "WARN" : "TOOL",
                      "redamon",
                    );
                  }
                } else if (event === "error") {
                  state.error = String(payload.error ?? "erreur RedAmon");
                } else if (event === "complete") {
                  state.done = true;
                }
              } catch {
                /* fragment non JSON — ignoré */
              }
            },
            ctx.signal,
          );
        } catch {
          /* flux interrompu — reprise après délai si le scan tourne encore */
        }
        if (!state.done) await sleepInterruptible(2_000, ctx.signal).catch(() => undefined);
      }
    })();

    // ── 4. Polling de statut (phases + progression) ──
    try {
      let lastPhase = "";
      for (;;) {
        if (ctx.signal.aborted) {
          await stop();
          throw ctx.signal.reason instanceof Error ? ctx.signal.reason : new Error("scan annulé");
        }
        if (Date.now() > deadline) {
          await stop();
          throw new Error("Scan RedAmon : timeout global atteint (arrêt demandé côté plateforme)");
        }
        await sleepInterruptible(4_000, ctx.signal).catch(async (err) => {
          await stop();
          throw err;
        });
        const st = await this.authedJson<ReconState>(
          `${this.baseUrl}/api/recon/${projectId}/status`,
          { timeoutMs: 15_000 },
          ctx.signal,
        ).catch(() => null);
        if (!st) continue; // erreur réseau ponctuelle
        const status = String(st.status ?? "").toLowerCase();
        if (status === "error") {
          throw new Error(`RedAmon : scan en échec${st.error ? ` — ${st.error}` : ""}`);
        }
        if (status === "completed" || status === "idle") {
          state.done = true;
          break;
        }
        const phase = st.current_phase ? String(st.current_phase) : "EXÉCUTION";
        const total = typeof st.total_phases === "number" && st.total_phases > 0 ? st.total_phases : 7;
        const num = typeof st.phase_number === "number" && st.phase_number > 0 ? st.phase_number : null;
        const pct = num ? Math.min(95, Math.round((100 * num) / total)) : undefined;
        if (phase !== lastPhase || pct !== undefined) {
          lastPhase = phase;
          await ctx.onPhase(`${num ? `${num}/${total} — ` : ""}${phase}`.slice(0, 64), pct);
        }
      }
    } finally {
      state.done = true;
      await sseLoop.catch(() => undefined);
    }

    if (state.error) throw new Error(`RedAmon : ${state.error}`);

    // ── 5. Résultats : graphe Neo4j (Vulnerability + surface) ──
    await ctx.onPhase("COLLECTE DES RÉSULTATS", 97);
    const graph = await this.authedJson<GraphPayload>(
      `${this.baseUrl}/api/graph?projectId=${projectId}&fresh=1`,
      { timeoutMs: 45_000 },
      ctx.signal,
    ).catch(() => ({}) as GraphPayload);

    const nodes = Array.isArray(graph.nodes) ? graph.nodes : [];
    const links = Array.isArray(graph.links) ? graph.links : [];
    if (graph.truncated?.truncated) {
      await ctx.onLog(
        `Graphe RedAmon tronqué côté plateforme (${graph.truncated.returnedNodes ?? "?"}/${graph.truncated.totalNodes ?? "?"} nœuds) — résultats partiels`,
        "WARN",
        "redamon",
      );
    }

    // Compteurs de surface (journal + transparence)
    const countType = (type: string) => nodes.filter((n) => n.type === type).length;
    await ctx.onLog(
      `Surface cartographiée : ${countType("Subdomain")} sous-domaine(s), ${countType("IP")} IP, ${countType("Port")} port(s), ${countType("Service")} service(s), ${countType("BaseURL")} URL — ${countType("Vulnerability")} vulnérabilité(s)`,
      "INFO",
      "redamon",
    );

    // Localisation d'une vulnérabilité : matched_at/url propres, sinon via les liens
    const byId = new Map(nodes.map((n) => [n.id, n] as const));
    const linkTarget = new Map<string, string>();
    for (const l of links) {
      if (["FOUND_AT", "HAS_VULNERABILITY", "AFFECTS", "FOUND_ON"].includes(l.type)) {
        linkTarget.set(l.source, l.target);
      }
    }
    const locate = (n: GraphNode): string | undefined => {
      const p = n.properties ?? {};
      for (const key of ["matched_at", "url", "probe_url", "matched-url"]) {
        const v = p[key];
        if (typeof v === "string" && v) return v;
      }
      const linked = linkTarget.get(n.id) ? byId.get(linkTarget.get(n.id)!) : undefined;
      if (linked) {
        const lp = linked.properties ?? {};
        for (const key of ["url", "host", "address", "name"]) {
          const v = lp[key];
          if (typeof v === "string" && v) return `${linked.type.toLowerCase()} ${v}`;
        }
        return linked.name || undefined;
      }
      return undefined;
    };

    const findings: RealFinding[] = [];
    for (const n of nodes) {
      if (n.type !== "Vulnerability" || findings.length >= MAX_FINDINGS) continue;
      const p = n.properties ?? {};
      const source = String(p.source ?? "redamon");
      const title = String(p.name ?? p.template_id ?? n.name ?? "Vulnérabilité RedAmon");
      const active = ACTIVE_SOURCES.has(source);
      const cveRaw = Array.isArray(p.cves) ? (p.cves as unknown[])[0] : undefined;
      const cve =
        typeof cveRaw === "string" && cveRaw
          ? cveRaw
          : /^CVE-\d{4}-\d{4,}/i.test(String(p.id ?? ""))
            ? String(p.id)
            : null;
      const cvss = typeof p.cvss_score === "number" ? p.cvss_score : null;
      const evidenceParts = [
        `Source : ${source}`,
        p.template_id ? `Template : ${p.template_id}` : null,
        p.recommendation ? `Recommandation : ${String(p.recommendation)}` : null,
      ].filter(Boolean) as string[];
      findings.push({
        title: title.slice(0, 300),
        severity: mapSeverity(p.severity),
        confidence: active ? "CONFIRMED" : String(p.needs_agent_confirmation) === "true" ? "UNVERIFIED" : "PROBABLE",
        category: source,
        cve,
        cvss,
        location: locate(n),
        description: String(p.description ?? title),
        evidence: evidenceParts.join("\n") || "(métadonnées du graphe RedAmon)",
        sentinelTriggered: active,
        remediation: typeof p.recommendation === "string" ? p.recommendation : undefined,
      });
    }

    await ctx.onLog(
      `RedAmon terminé — ${findings.length} vulnérabilité(s) normalisée(s) depuis le graphe`,
      "SUCCESS",
      "redamon",
    );
    return findings;
  }
}
