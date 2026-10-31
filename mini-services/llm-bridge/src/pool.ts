/**
 * AuditForge — ModelPool : pool multi-modèles avec rotation round-robin.
 * ========================================================================
 * Le pont agrège N upstreams OpenAI-compatibles (ex. Alibaba MaaS + routeur
 * de secours) et répartit les requêtes « à tours de rôle » sur tous les
 * modèles réellement provisionnés, afin qu'aucun quota de modèle ne
 * s'épuise :
 *
 *   - Découverte dynamique : GET /models de chaque upstream, filtrage
 *     (audio/image/embedding/realtime exclus), sonde réelle (1 token) de
 *     chaque candidat → seuls les modèles fonctionnels entrent dans le pool.
 *   - Rotation stricte : un compteur global fait tourner le point de départ
 *     dans la liste des modèles sains → chaque requête part sur un modèle
 *     différent (round-robin).
 *   - Épinglage : si le client demande un modèle précis du pool, il est
 *     servi en priorité (le reste du pool sert de filet de secours).
 *   - Failover : en cas d'erreur par modèle (402/403/429/5xx/timeout), le
 *     modèle passe en « cooldown » exponentiel et la requête est rejouée
 *     immédiatement sur le modèle suivant — l'échec n'atteint jamais le
 *     client tant qu'il reste un modèle sain.
 *   - Épuisement structurel (2-c) : un 402 (solde) ou un 4xx dont le corps
 *     mentionne quota/balance/billing (ex. DashScope « free quota exhausted »)
 *     n'est PAS transitoire : tout l'upstream passe en « exhausted » et sort
 *     de la rotation pour une fenêtre longue (6 h par défaut) — plus aucun
 *     retry ni attente contre lui (le reset manuel passe par
 *     POST /v1/pool/refresh).
 *   - Re-découverte périodique : si de nouveaux modèles sont provisionnés
 *     (quota accordé a posteriori), ils rejoignent le pool tout seuls ;
 *     les modèles retirés de /models sont marqués « dead ».
 *
 * Aucune dépendance : Bun fetch natif.
 */

// ── Types publics ────────────────────────────────────────────────────────────

export type UpstreamRole = "primary" | "fallback";

export interface Upstream {
  /** Nom court utilisé dans les journaux et /v1/pool. */
  name: string;
  /** Base URL OpenAI-compatible, ex. https://…/compatible-mode/v1 */
  base: string;
  /** Clé API transmise en Authorization: Bearer à cet upstream. */
  key: string;
  /** primary = pool de rotation ; fallback = uniquement si plus aucun primary sain. */
  role: UpstreamRole;
}

/**
 * États d'un modèle :
 *  - healthy    : sonde/appel réel OK ;
 *  - unverified : découvert mais pas encore éprouvé (optimiste) ;
 *  - cooldown   : échec transitoire (429/5xx/timeout) — réessai après délai court ;
 *  - exhausted  : quota/solde épuisés côté fournisseur — retiré LONGTEMPS (fenêtre 6 h) ;
 *  - dead       : disparu de la liste /models de l'upstream.
 */
export type ModelState = "healthy" | "unverified" | "cooldown" | "dead" | "exhausted";

export interface PoolEntry {
  upstream: string;
  model: string;
  state: ModelState;
  /** Fin du cooldown (epoch ms) — 0 si non applicable. */
  cooldownUntil: number;
  consecutiveFails: number;
  requests: number;
  errors: number;
  totalLatencyMs: number;
  lastLatencyMs: number;
  lastError: string | null;
  /** Dernière sonde/résultat (epoch ms). */
  lastCheck: number;
}

export interface PickResult {
  upstream: Upstream;
  model: string;
  entry: PoolEntry;
}

export interface PoolOptions {
  cooldownBaseMs?: number;
  cooldownMaxMs?: number;
  probeTimeoutMs?: number;
  probeConcurrency?: number;
  /**
   * Fenêtre d'exclusion d'un upstream « exhausted » (quota/solde épuisés).
   * Défaut 6 h — la sortie anticipée se fait par sonde réussie (découverte)
   * ou par reset manuel (POST /v1/pool/refresh).
   */
  exhaustedWindowMs?: number;
  /** IDs exclus de la découverte (OCR/VL/traduction spécialisés, etc.). */
  excludeRe?: RegExp;
  logger?: (msg: string) => void;
}

export interface PoolCounts {
  healthy: number;
  unverified: number;
  cooldown: number;
  exhausted: number;
  dead: number;
  total: number;
}

export interface UpstreamExhaustion {
  name: string;
  /** Fin de la fenêtre d'exclusion (epoch ms). */
  until: number;
  /** Raison (erreur amont tronquée). */
  reason: string;
}

export interface PoolSnapshot {
  generatedAt: number;
  /** Compteurs par état — consommés par les diagnostics PHANTOM (/v1/pool). */
  counts: PoolCounts;
  upstreams: Array<{
    name: string;
    role: UpstreamRole;
    base: string;
    keyPreview: string;
    healthy: number;
    /** true = quota/solde épuisé — upstream retiré de la rotation. */
    exhausted: boolean;
    /** Fin de la fenêtre d'exclusion (epoch ms) si épuisé, sinon null. */
    exhaustedUntil: number | null;
    /** Raison de l'exclusion (erreur amont) si épuisé, sinon null. */
    exhaustedReason: string | null;
  }>;
  entries: PoolEntry[];
  rotationCursor: number;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Alias « rotation pure » : toute valeur demandée correspondant à ces noms déclenche le round-robin. */
const ROTATION_ALIASES = new Set([
  "auto",
  "auditforge-auto",
  "default",
  "rotation",
  "round-robin",
  "round_robin",
  "*",
]);

/**
 * Normalise le modèle demandé par le client.
 * - retire un éventuel préfixe provider LiteLLM « openai/… » ;
 * - renvoie null pour un alias de rotation (round-robin pur) ;
 * - renvoie sinon l'ID à épingler en priorité.
 */
export function normalizePreferred(model: unknown): string | null {
  if (typeof model !== "string") return null;
  let m = model.trim();
  if (!m) return null;
  m = m.replace(/^[a-z0-9_-]+\/(?=[a-z0-9])/i, (full) =>
    /^openai\//i.test(full) ? "" : full,
  );
  if (ROTATION_ALIASES.has(m.toLowerCase())) return null;
  return m;
}

/**
 * Corps/messages d'échec qui signent un épuisement STRUCTUREL (non récupérable
 * en patientant 45 s) : quota gratuit épuisé, solde/facturation, impayés.
 * Cas réels constatés en production :
 *   - DashScope maas : HTTP 403 « …free quota exhausted… » (~50 modèles) ;
 *   - routeur api.anyrouter.dev : HTTP 402 (balance $0.00).
 */
export const EXHAUSTED_BODY_RE = /quota|balance|billing|arrearage|insufficient|exhausted/i;

export interface FailureClass {
  cooldown: boolean;
  retry: boolean;
  /** true → upstream ENTIER à retirer de la rotation pour une longue fenêtre. */
  exhausted: boolean;
}

/**
 * Classification d'un échec HTTP upstream :
 *   - exhausted : quota/solde épuisés (402, ou 4xx + corps évocateur) — non transitoire ;
 *   - cooldown : le modèle doit être écarté (rate-limit/serveur/timeout) ;
 *   - retry    : la requête peut être rejouée sur un autre modèle.
 * 400 reste volontairement SANS cooldown (souvent lié à la requête elle-même —
 * ex. outils non supportés par ce modèle — inutile d'empoisonner le pool),
 * mais AVEC retry (un autre modèle l'acceptera peut-être) — SAUF si son corps
 * signe un épuisement de compte.
 */
export function classifyFailure(status: number, errText = ""): FailureClass {
  if (status === 0) return { cooldown: true, retry: true, exhausted: false }; // réseau / timeout / abort
  // 402 = paiement requis (solde épuisé) — toujours structurel. Les autres 4xx
  // ne sont structurels que si le corps le confirme (le 429 « rate limit »
  // sans mention de quota reste transitoire).
  const exhausted =
    status === 402 ||
    (status >= 400 && status < 500 && EXHAUSTED_BODY_RE.test(errText));
  if (status === 400) return { cooldown: false, retry: true, exhausted };
  if (status === 404 || status === 408 || status === 429) return { cooldown: true, retry: true, exhausted };
  if (status >= 500) return { cooldown: true, retry: true, exhausted: false };
  // 401 (clé invalide), 402 (crédits), 403 (entitlement/quota), 405… → cooldown + failover.
  return { cooldown: true, retry: true, exhausted };
}

/** Parse AF_UPSTREAMS : « nom|base|clé|role;nom2|base2|clé2|role2 ». */
export function parseUpstreams(spec: string): Upstream[] {
  const out: Upstream[] = [];
  const seen = new Set<string>();
  for (const chunk of spec.split(";")) {
    const parts = chunk.split("|").map((p) => p.trim());
    if (parts.length < 3 || !parts[0] || !parts[1] || !parts[2]) {
      if (chunk.trim()) console.warn(`[llm-bridge] upstream ignoré (format attendu nom|base|clé[|role]) : « ${chunk.slice(0, 40)}… »`);
      continue;
    }
    const [name, base, key, role] = parts;
    if (!/^https?:\/\//i.test(base)) {
      console.warn(`[llm-bridge] upstream « ${name} » ignoré : base non http(s)`);
      continue;
    }
    if (seen.has(name)) {
      console.warn(`[llm-bridge] upstream « ${name} » dupliqué — ignoré`);
      continue;
    }
    seen.add(name);
    out.push({ name, base: base.replace(/\/+$/, ""), key, role: role === "fallback" ? "fallback" : "primary" });
  }
  return out;
}

// ── Pool ─────────────────────────────────────────────────────────────────────

export class ModelPool {
  readonly upstreams: Upstream[];
  private readonly entries = new Map<string, PoolEntry>();
  private readonly cooldownBaseMs: number;
  private readonly cooldownMaxMs: number;
  private readonly probeTimeoutMs: number;
  private readonly probeConcurrency: number;
  private readonly exhaustedWindowMs: number;
  private readonly excludeRe: RegExp;
  private readonly log: (msg: string) => void;
  /** Upstreams épuisés (quota/solde) : nom → fin de fenêtre + raison. */
  private readonly exhausted = new Map<string, UpstreamExhaustion>();
  /** Compteur global de rotation (round-robin strict). */
  private rr = 0;

  constructor(upstreams: Upstream[], opts: PoolOptions = {}) {
    this.upstreams = upstreams;
    this.cooldownBaseMs = opts.cooldownBaseMs ?? 90_000;
    this.cooldownMaxMs = opts.cooldownMaxMs ?? 30 * 60_000;
    this.probeTimeoutMs = opts.probeTimeoutMs ?? 30_000;
    this.probeConcurrency = Math.max(1, opts.probeConcurrency ?? 8);
    this.exhaustedWindowMs = opts.exhaustedWindowMs ?? 6 * 3_600_000;
    this.excludeRe = opts.excludeRe ?? /(^$)/; // n'exclut rien par défaut
    this.log = opts.logger ?? ((m) => console.log(`[llm-bridge] ${m}`));
  }

  private key(upstream: string, model: string): string {
    return `${upstream}::${model}`;
  }

  ensureEntry(upstream: string, model: string): PoolEntry {
    const k = this.key(upstream, model);
    let e = this.entries.get(k);
    if (!e) {
      // Un upstream épuisé ne propose que des entrées épuisées (jamais
      // « optimistes ») — sinon les STATIC_MODELS ré-injecteraient un upstream
      // hors quota dans la rotation.
      const ex = this.exhausted.get(upstream);
      e = {
        upstream,
        model,
        state: ex ? "exhausted" : "unverified",
        cooldownUntil: ex ? ex.until : 0,
        consecutiveFails: 0,
        requests: 0,
        errors: 0,
        totalLatencyMs: 0,
        lastLatencyMs: 0,
        lastError: null,
        lastCheck: 0,
      };
      this.entries.set(k, e);
    }
    return e;
  }

  // ── Épuisement structurel (2-c) ───────────────────────────────────────────

  /** Purge les exclusions expirées ; leurs entrées redeviennent à vérifier. */
  private sweepExhausted(): void {
    if (this.exhausted.size === 0) return;
    const now = Date.now();
    for (const [name, info] of this.exhausted) {
      if (info.until > now) continue;
      this.exhausted.delete(name);
      this.log(`upstream « ${name} » : fin de la fenêtre d'épuisement — retour en rotation (à confirmer par sonde)`);
      for (const e of this.entries.values()) {
        if (e.upstream === name && e.state === "exhausted") {
          e.state = "unverified";
          e.cooldownUntil = 0;
        }
      }
    }
  }

  /** true si l'upstream est actuellement exclu pour épuisement (quota/solde). */
  isExhausted(name: string): boolean {
    this.sweepExhausted();
    return this.exhausted.has(name);
  }

  /** Nombre d'entrées actuellement épuisées (après purge des fenêtres expirées). */
  exhaustedCount(): number {
    this.sweepExhausted();
    let n = 0;
    for (const e of this.entries.values()) if (e.state === "exhausted") n += 1;
    return n;
  }

  /** Détail des exclusions courantes (diagnostics /v1/pool). */
  exhaustedUpstreams(): UpstreamExhaustion[] {
    this.sweepExhausted();
    return [...this.exhausted.values()];
  }

  /**
   * Retire TOUT l'upstream de la rotation pour la fenêtre longue : les modèles
   * d'un même compte partagent le quota/solde — réessayer un autre modèle du
   * même upstream ne peut que reproduire l'échec (et griller des tentatives).
   */
  exhaustUpstream(name: string, reason: string, status: number): void {
    const until = Date.now() + this.exhaustedWindowMs;
    const existing = this.exhausted.get(name);
    const trimmed = reason.replace(/\s+/g, " ").slice(0, 300);
    if (existing) {
      // Déjà exclu : prolonger silencieusement la fenêtre (pas de spam de logs).
      existing.until = until;
      existing.reason = trimmed;
    } else {
      this.exhausted.set(name, { name, until, reason: trimmed });
      const hours = Math.round((this.exhaustedWindowMs / 3_600_000) * 10) / 10;
      this.log(`upstream « ${name} » : EXHAUSTED (HTTP ${status} — ${trimmed}) — retiré de la rotation pendant ${hours} h`);
    }
    for (const e of this.entries.values()) {
      if (e.upstream !== name || e.state === "dead") continue;
      e.state = "exhausted";
      e.cooldownUntil = until;
      e.lastError = `HTTP ${status}: ${trimmed.slice(0, 160)}`;
      e.lastCheck = Date.now();
    }
  }

  /**
   * Reset manuel (POST /v1/pool/refresh) : lève toutes les exclusions
   * d'épuisement — l'opérateur vient de réapprovisionner clés/soldes.
   */
  clearExhausted(): void {
    if (this.exhausted.size === 0) return;
    this.log(`reset manuel : levée de ${this.exhausted.size} exclusion(s) d'épuisement (${[...this.exhausted.keys()].join(", ")})`);
    this.exhausted.clear();
    for (const e of this.entries.values()) {
      if (e.state === "exhausted") {
        e.state = "unverified";
        e.cooldownUntil = 0;
      }
    }
  }

  /** Entrées utilisables d'un upstream : healthy + unverified (optimiste) + cooldown expiré.
   *  Un upstream épuisé (quota/solde) ne fournit RIEN — pas même un cooldown expiré. */
  private upstreamUsable(u: Upstream): PoolEntry[] {
    this.sweepExhausted();
    if (this.exhausted.has(u.name)) return [];
    const now = Date.now();
    const out: PoolEntry[] = [];
    for (const e of this.entries.values()) {
      if (e.upstream !== u.name) continue;
      if (e.state === "dead" || e.state === "exhausted") continue;
      if (e.state === "cooldown" && e.cooldownUntil > now) continue;
      out.push(e);
    }
    // Ordre stable : latence mesurée croissante puis nom (les rapides d'abord à chaque cycle).
    out.sort((a, b) => {
      const la = a.lastLatencyMs || Number.MAX_SAFE_INTEGER;
      const lb = b.lastLatencyMs || Number.MAX_SAFE_INTEGER;
      if (la !== lb) return la - lb;
      return a.model.localeCompare(b.model);
    });
    return out;
  }

  /**
   * Ordre de rotation complet : tous les modèles utilisables des upstreams
   * primaires (point de départ tournant), puis les fallbacks.
   */
  rotationOrder(): PickResult[] {
    const primaries = this.upstreams.filter((u) => u.role === "primary");
    const fallbacks = this.upstreams.filter((u) => u.role !== "primary");
    const collect = (list: Upstream[]): PickResult[] =>
      list.flatMap((u) =>
        this.upstreamUsable(u).map((entry) => ({ upstream: u, model: entry.model, entry })),
      );
    const primary = collect(primaries);
    const fallback = collect(fallbacks);
    if (primary.length === 0) return fallback;
    const off = this.rr % primary.length;
    this.rr = (this.rr + 1) % Number.MAX_SAFE_INTEGER;
    return [...primary.slice(off), ...primary.slice(0, off), ...fallback];
  }

  /**
   * Candidats pour une requête : épinglage éventuel du modèle demandé, sinon
   * rotation pure. L'appelant borne le nombre de tentatives.
   */
  candidatesFor(preferred: string | null): PickResult[] {
    const order = this.rotationOrder();
    if (!preferred) return order;
    const pin = order.find((c) => c.model === preferred);
    if (pin) return [pin, ...order.filter((c) => c !== pin)];
    this.log(`modèle demandé « ${preferred} » absent/indisponible → rotation pure`);
    return order;
  }

  private cooldownFor(consecutiveFails: number): number {
    const exp = Math.min(consecutiveFails - 1, 12);
    return Math.min(this.cooldownBaseMs * 2 ** exp, this.cooldownMaxMs);
  }

  markSuccess(p: PickResult, latencyMs: number): void {
    const e = p.entry;
    e.state = "healthy";
    e.consecutiveFails = 0;
    e.cooldownUntil = 0;
    e.lastError = null;
    e.lastLatencyMs = latencyMs;
    e.totalLatencyMs += latencyMs;
    e.requests += 1;
    e.lastCheck = Date.now();
  }

  markSoftFail(p: PickResult, err: string): void {
    // Échec imputable à la requête (400) — pas de cooldown, mais compté.
    p.entry.requests += 1;
    p.entry.errors += 1;
    p.entry.lastError = err.slice(0, 200);
    p.entry.lastCheck = Date.now();
  }

  markFailure(p: PickResult, status: number, err: string): void {
    const e = p.entry;
    e.requests += 1;
    e.errors += 1;
    e.consecutiveFails += 1;
    e.lastError = `HTTP ${status}: ${err.slice(0, 160)}`;
    e.lastCheck = Date.now();
    e.state = "cooldown";
    e.cooldownUntil = Date.now() + this.cooldownFor(e.consecutiveFails);
    // 401 = clé refusée → tout l'upstream est en cause : cooldown long global.
    if (status === 401) {
      const now = Date.now();
      for (const other of this.entries.values()) {
        if (other.upstream === e.upstream) {
          other.state = "cooldown";
          other.cooldownUntil = now + this.cooldownMaxMs;
          other.lastError = "clé refusée (401) — upstream entier en cooldown";
        }
      }
      this.log(`upstream « ${e.upstream} » : clé refusée (401) → cooldown global`);
    }
    this.log(`modèle ${e.upstream}/${e.model} → cooldown ${Math.round(this.cooldownFor(e.consecutiveFails) / 1000)}s (échec HTTP ${status})`);
  }

  // ── Découverte / sondes ────────────────────────────────────────────────────

  private upstreamHeaders(u: Upstream): Record<string, string> {
    return { Authorization: `Bearer ${u.key}`, "Content-Type": "application/json" };
  }

  async listUpstreamModels(u: Upstream): Promise<string[]> {
    const res = await fetch(`${u.base}/models`, {
      headers: this.upstreamHeaders(u),
      signal: AbortSignal.timeout(this.probeTimeoutMs),
    });
    if (!res.ok) {
      // Le corps est précieux (quota/balance) — il pilote la classification
      // « exhausted » dans discover().
      const body = (await res.text().catch(() => "")).slice(0, 400);
      const err = new Error(`HTTP ${res.status} — ${body}`) as Error & { status?: number; body?: string };
      err.status = res.status;
      err.body = body;
      throw err;
    }
    const data = (await res.json()) as { data?: Array<{ id?: unknown }> };
    if (!Array.isArray(data?.data)) throw new Error("réponse /models inattendue");
    return data.data.map((m) => (typeof m?.id === "string" ? m.id : "")).filter(Boolean);
  }

  /** Sonde 1 token — détermine si un modèle est réellement utilisable. */
  async probeUpstreamModel(
    u: Upstream,
    model: string,
  ): Promise<{ ok: true; latencyMs: number } | { ok: false; status: number; err: string }> {
    const t0 = Date.now();
    try {
      const res = await fetch(`${u.base}/chat/completions`, {
        method: "POST",
        headers: this.upstreamHeaders(u),
        body: JSON.stringify({
          model,
          messages: [{ role: "user", content: "ping" }],
          max_tokens: 1,
        }),
        signal: AbortSignal.timeout(this.probeTimeoutMs),
      });
      if (res.ok) return { ok: true, latencyMs: Date.now() - t0 };
      const body = await res.text().catch(() => "");
      return { ok: false, status: res.status, err: body.slice(0, 400) };
    } catch (err) {
      return { ok: false, status: 0, err: err instanceof Error ? err.message : "erreur sonde" };
    }
  }

  private isCandidate(id: string): boolean {
    return !this.excludeRe.test(id);
  }

  private async probeAndRegister(u: Upstream, id: string): Promise<void> {
    const e = this.ensureEntry(u.name, id);
    const r = await this.probeUpstreamModel(u, id);
    e.lastCheck = Date.now();
    if (r.ok) {
      e.state = "healthy";
      e.consecutiveFails = 0;
      e.cooldownUntil = 0;
      e.lastError = null;
      e.lastLatencyMs = r.latencyMs;
      e.totalLatencyMs += r.latencyMs;
      // Une sonde réussie lève l'épuisement de l'upstream entier (quota rétabli).
      if (this.exhausted.delete(u.name)) {
        this.log(`upstream « ${u.name} » : de nouveau fonctionnel (sonde OK) — fin de l'exclusion d'épuisement`);
        for (const other of this.entries.values()) {
          if (other.upstream === u.name && other.state === "exhausted") {
            other.state = "unverified";
            other.cooldownUntil = 0;
          }
        }
      }
    } else if (classifyFailure(r.status, r.err).exhausted) {
      // Sonde qui signe un épuisement → upstream ENTIER hors rotation.
      this.exhaustUpstream(u.name, r.err.slice(0, 200), r.status);
      const until = this.exhausted.get(u.name)?.until ?? Date.now() + this.exhaustedWindowMs;
      e.state = "exhausted";
      e.consecutiveFails += 1;
      e.cooldownUntil = until;
      e.lastError = `sonde HTTP ${r.status}: ${r.err.slice(0, 120)}`;
    } else {
      e.state = "cooldown";
      e.consecutiveFails += 1;
      e.cooldownUntil = Date.now() + this.cooldownFor(e.consecutiveFails);
      e.lastError = `sonde HTTP ${r.status}: ${r.err.slice(0, 120)}`;
    }
  }

  private async probeBatch(u: Upstream, ids: string[]): Promise<void> {
    for (let i = 0; i < ids.length; i += this.probeConcurrency) {
      await Promise.all(ids.slice(i, i + this.probeConcurrency).map((id) => this.probeAndRegister(u, id)));
    }
  }

  /**
   * Découverte complète : liste /models + sonde de tous les candidats de
   * chaque upstream. Les modèles disparus de la liste passent en « dead ».
   */
  async discover(): Promise<void> {
    for (const u of this.upstreams) {
      // Upstream épuisé : ne rien sonder (les appels ne peuvent qu'échouer —
      // et l'upstream resterait de toute façon hors rotation). La sortie se
      // fait par fin de fenêtre OU par reset manuel (POST /v1/pool/refresh,
      // qui lève l'exclusion AVANT de relancer la découverte).
      if (this.isExhausted(u.name)) {
        this.log(`upstream « ${u.name} » : épuisé (quota/solde) — découverte ignorée`);
        continue;
      }
      let ids: string[];
      try {
        ids = await this.listUpstreamModels(u);
      } catch (err) {
        const status = (err as { status?: number }).status ?? 0;
        const body = (err as { body?: string }).body ?? (err instanceof Error ? err.message : "");
        if (classifyFailure(status, body).exhausted) {
          this.exhaustUpstream(u.name, body.replace(/\s+/g, " ").slice(0, 200), status);
        } else {
          this.log(`upstream « ${u.name} » : /models injoignable (${err instanceof Error ? err.message : "erreur"})`);
        }
        continue;
      }
      const candidates = ids.filter((id) => this.isCandidate(id));
      await this.probeBatch(u, candidates);
      for (const e of this.entries.values()) {
        if (e.upstream === u.name && e.state !== "dead" && !ids.includes(e.model)) {
          e.state = "dead";
          e.lastError = "disparu de la liste /models";
        }
      }
      this.log(`upstream « ${u.name} » : ${candidates.length} candidats sondés → ${this.healthyOf(u.name)} sains`);
    }
    this.log(`pool : ${this.summary()}`);
  }

  /** Rafraîchissement périodique (même logique que discover — coûte quelques 403 bon marché). */
  async refresh(): Promise<void> {
    await this.discover();
  }

  // ── Introspection ──────────────────────────────────────────────────────────

  healthyOf(upstream: string): number {
    let n = 0;
    for (const e of this.entries.values()) if (e.upstream === upstream && e.state === "healthy") n += 1;
    return n;
  }

  /** Compteurs par état (consommés par /v1/pool, /health et les logs). */
  counts(): PoolCounts {
    this.sweepExhausted();
    let healthy = 0;
    let cooldown = 0;
    let dead = 0;
    let unverified = 0;
    let exhausted = 0;
    for (const e of this.entries.values()) {
      if (e.state === "healthy") healthy += 1;
      else if (e.state === "cooldown") cooldown += 1;
      else if (e.state === "exhausted") exhausted += 1;
      else if (e.state === "dead") dead += 1;
      else unverified += 1;
    }
    return { healthy, cooldown, dead, exhausted, unverified, total: this.entries.size };
  }

  /** Résumé textuel (logs internes). */
  summary(): string {
    const c = this.counts();
    return (
      `${c.healthy} sains, ${c.cooldown} cooldown, ${c.unverified} non vérifiés, ` +
      `${c.exhausted} épuisés, ${c.dead} morts (${this.upstreams.length} upstreams)`
    );
  }

  healthyCount(): number {
    let n = 0;
    for (const e of this.entries.values()) if (e.state === "healthy") n += 1;
    return n;
  }

  snapshot(): PoolSnapshot {
    this.sweepExhausted();
    return {
      generatedAt: Date.now(),
      counts: this.counts(),
      upstreams: this.upstreams.map((u) => {
        const ex = this.exhausted.get(u.name);
        return {
          name: u.name,
          role: u.role,
          base: u.base,
          keyPreview: `${u.key.slice(0, 10)}…`,
          healthy: this.healthyOf(u.name),
          exhausted: ex !== undefined,
          exhaustedUntil: ex ? ex.until : null,
          exhaustedReason: ex ? ex.reason : null,
        };
      }),
      entries: [...this.entries.values()].sort(
        (a, b) => a.upstream.localeCompare(b.upstream) || a.model.localeCompare(b.model),
      ),
      rotationCursor: this.rr,
    };
  }
}
