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

export type ModelState = "healthy" | "unverified" | "cooldown" | "dead";

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
  /** IDs exclus de la découverte (OCR/VL/traduction spécialisés, etc.). */
  excludeRe?: RegExp;
  logger?: (msg: string) => void;
}

export interface PoolSnapshot {
  generatedAt: number;
  upstreams: Array<{ name: string; role: UpstreamRole; base: string; keyPreview: string; healthy: number }>;
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
 * Classification d'un échec HTTP upstream :
 *   - cooldown : le modèle doit être écarté (quota/entitlement/serveur/timeout) ;
 *   - retry    : la requête peut être rejouée sur un autre modèle.
 * 400 est volontairement SANS cooldown (souvent lié à la requête elle-même —
 * ex. outils non supportés par ce modèle — inutile d'empoisonner le pool),
 * mais AVEC retry (un autre modèle l'acceptera peut-être).
 */
export function classifyFailure(status: number): { cooldown: boolean; retry: boolean } {
  if (status === 0) return { cooldown: true, retry: true }; // réseau / timeout / abort
  if (status === 400) return { cooldown: false, retry: true };
  if (status === 404 || status === 408 || status === 429) return { cooldown: true, retry: true };
  if (status >= 500) return { cooldown: true, retry: true };
  // 401 (clé invalide), 402 (crédits), 403 (entitlement/quota), 405… → cooldown + failover.
  return { cooldown: true, retry: true };
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
  private readonly excludeRe: RegExp;
  private readonly log: (msg: string) => void;
  /** Compteur global de rotation (round-robin strict). */
  private rr = 0;

  constructor(upstreams: Upstream[], opts: PoolOptions = {}) {
    this.upstreams = upstreams;
    this.cooldownBaseMs = opts.cooldownBaseMs ?? 90_000;
    this.cooldownMaxMs = opts.cooldownMaxMs ?? 30 * 60_000;
    this.probeTimeoutMs = opts.probeTimeoutMs ?? 30_000;
    this.probeConcurrency = Math.max(1, opts.probeConcurrency ?? 8);
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
      e = {
        upstream,
        model,
        state: "unverified",
        cooldownUntil: 0,
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

  private upstreamOf(name: string): Upstream | undefined {
    return this.upstreams.find((u) => u.name === name);
  }

  /** Entrées utilisables d'un upstream : healthy + unverified (optimiste) + cooldown expiré. */
  private upstreamUsable(u: Upstream): PoolEntry[] {
    const now = Date.now();
    const out: PoolEntry[] = [];
    for (const e of this.entries.values()) {
      if (e.upstream !== u.name) continue;
      if (e.state === "dead") continue;
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
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const body = (await res.json()) as { data?: Array<{ id?: unknown }> };
    if (!Array.isArray(body?.data)) throw new Error("réponse /models inattendue");
    return body.data.map((m) => (typeof m?.id === "string" ? m.id : "")).filter(Boolean);
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
      return { ok: false, status: res.status, err: body.slice(0, 160) };
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
      let ids: string[];
      try {
        ids = await this.listUpstreamModels(u);
      } catch (err) {
        this.log(`upstream « ${u.name} » : /models injoignable (${err instanceof Error ? err.message : "erreur"})`);
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
    this.log(`pool : ${this.counts()}`);
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

  counts(): string {
    let healthy = 0;
    let cooldown = 0;
    let dead = 0;
    let unverified = 0;
    for (const e of this.entries.values()) {
      if (e.state === "healthy") healthy += 1;
      else if (e.state === "cooldown") cooldown += 1;
      else if (e.state === "dead") dead += 1;
      else unverified += 1;
    }
    return `${healthy} sains, ${cooldown} cooldown, ${unverified} non vérifiés, ${dead} morts (${this.upstreams.length} upstreams)`;
  }

  healthyCount(): number {
    let n = 0;
    for (const e of this.entries.values()) if (e.state === "healthy") n += 1;
    return n;
  }

  snapshot(): PoolSnapshot {
    return {
      generatedAt: Date.now(),
      upstreams: this.upstreams.map((u) => ({
        name: u.name,
        role: u.role,
        base: u.base,
        keyPreview: `${u.key.slice(0, 10)}…`,
        healthy: this.healthyOf(u.name),
      })),
      entries: [...this.entries.values()].sort(
        (a, b) => a.upstream.localeCompare(b.upstream) || a.model.localeCompare(b.model),
      ),
      rotationCursor: this.rr,
    };
  }
}
