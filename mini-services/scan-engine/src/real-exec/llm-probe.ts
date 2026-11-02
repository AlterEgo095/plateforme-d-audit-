/**
 * AuditForge — Sonde LLM partagée (P5-fix 2026-10-29).
 *
 * Les agents IA-natives (PHANTOM, BASALT) sont inutilisables sans LLM
 * opérationnel : jusqu'ici un endpoint à sec (HTTP 402 — solde $0.00
 * constaté sur le routeur en production) faisait échouer le scan ~20 s
 * après le lancement de la sandbox avec un message illisible pour
 * l'opérateur (« code 1 / JSON final illisible »).
 *
 * Cette sonde interroge l'endpoint OpenAI-compatible AVANT tout lancement
 * (requête 1 token) et retourne une cause actionnable :
 *   - HTTP 402 → crédits épuisés ;
 *   - HTTP 401/403 → clé invalide ;  HTTP 429 → quota ;
 *   - erreur réseau/timeout → endpoint injoignable.
 *
 * Le modèle passé en argument doit être le nom DIRECT (sans préfixe
 * provider LiteLLM « openai/… ») tel que l'endpoint le reçoit réellement.
 */

export type LlmProbeResult = { ok: true } | { ok: false; reason: string };

export async function probeLlmEndpoint(opts: {
  apiKey?: string;
  apiBase?: string;
  /** Nom de modèle DIRECT (préfixe provider retiré par l'appelant). */
  model: string;
  timeoutMs?: number;
}): Promise<LlmProbeResult> {
  const { apiKey, apiBase, model, timeoutMs = 30_000 } = opts;
  if (!apiKey) {
    return { ok: false, reason: "LLM_API_KEY non configurée (agent IA — impossible de raisonner)" };
  }
  const base = (apiBase || "").replace(/\/+$/, "");
  if (!base) return { ok: false, reason: "LLM_API_BASE non configurée (agent IA — impossible de raisonner)" };
  try {
    const res = await fetch(`${base}/chat/completions`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({
        model,
        messages: [{ role: "user", content: "ping" }],
        max_tokens: 1,
      }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (res.ok) return { ok: true };
    if (res.status === 402) {
      return { ok: false, reason: `crédits LLM épuisés sur ${base} (HTTP 402) — rechargez le compte ou fournissez une clé LLM valide` };
    }
    if (res.status === 401 || res.status === 403) {
      return { ok: false, reason: `clé LLM refusée par ${base} (HTTP ${res.status}) — vérifiez LLM_API_KEY` };
    }
    if (res.status === 429) {
      return { ok: false, reason: `quota LLM atteint sur ${base} (HTTP 429) — réessayez plus tard ou changez de fournisseur` };
    }
    return { ok: false, reason: `endpoint LLM ${base} en erreur (HTTP ${res.status})` };
  } catch (err) {
    const msg = err instanceof Error ? err.message : "erreur réseau";
    // Distinguer TIMEOUT (signal AbortSignal.timeout — l'amont répond trop
    // lentement : cascade d'upstreams défaillants du pont avant son 503) d'un
    // VRAI échec réseau (DNS/refus). L'ancien message unique « injoignable »
    // était trompeur : le pont répond, c'est son amont qui ne répond pas.
    const isTimeout =
      (err instanceof Error && (err.name === "TimeoutError" || err.name === "AbortError")) ||
      /timed?\s*out/i.test(msg);
    return {
      ok: false,
      reason: isTimeout
        ? `endpoint LLM ${base} silencieux (aucune réponse après ${Math.round(timeoutMs / 1000)} s) — amont lent ou pool en cascade d'erreurs (cf. GET /v1/pool et POST /v1/pool/refresh)`
        : `endpoint LLM ${base} injoignable (${msg})`,
    };
  }
}

/** Retire le préfixe provider LiteLLM (« openai/… ») pour un appel API direct. */
export function stripLlmProvider(model: string): string {
  return model.replace(/^[a-z0-9_-]+\//i, "");
}

// ── Sonde de CAPACITÉ + diagnostics pool (2-c) ───────────────────────────────

/**
 * Prompt de capacité : représentatif du travail réel de PHANTOM (plan de test
 * web + payloads). Suffisamment court pour rester bon marché, suffisamment
 * « offensif » pour déclencher un filtre fournisseur s'il existe.
 */
const CAPACITY_PROMPT =
  "Plan a brief web penetration test for https://example.com: list two SQL injection and two XSS test payloads.";

/**
 * Refus sémantique du modèle : 200 OK mais contenu qui refuse la tâche.
 * Exemples RÉELS constatés en production (sondes 2-c) :
 *   - « I can't provide concrete attack payloads… » (maas qwen, 100-125 s de latence) ;
 *   - corps d'erreur JSON relayé par le pont : {"status":"refused",…}.
 * Testé sur le contenu extrait ET le corps brut (certains fournisseurs
 * renvoient 200 avec un corps d'erreur non standard).
 */
export const REFUSAL_RE =
  /(i (?:can'?t|cannot|won'?t|am unable)|i'?m sorry|cannot assist|cannot provide|status["']?\s*:\s*["']?refused)/i;

export type LlmCapacityResult =
  | { kind: "ok"; latencyMs: number; modelServed: string | null; preview: string }
  /** 503 pool_exhausted/pool_busy du pont — pool indisponible (quota/balance). */
  | { kind: "pool_exhausted"; detail: string }
  /** 200 mais refus de la tâche (filtre fournisseur). */
  | { kind: "refused"; detail: string }
  /** Autre erreur HTTP amont. */
  | { kind: "http_error"; status: number; detail: string }
  /** Timeout / erreur réseau / configuration manquante. */
  | { kind: "unreachable"; detail: string };

/** Message d'erreur lisible d'un corps d'erreur JSON (OpenAI-like ou maison). */
function extractErrorDetail(body: string): string | null {
  try {
    const j = JSON.parse(body) as {
      error?: { message?: unknown; type?: unknown };
      message?: unknown;
      status?: unknown;
    };
    const m = j?.error?.message ?? j?.message;
    if (typeof m === "string" && m.trim()) return `${m.trim()} (type: ${String(j?.error?.type ?? j?.status ?? "?")})`.slice(0, 300);
  } catch {
    // corps non JSON — tant pis, l'appelant affichera l'extrait brut
  }
  return null;
}

/**
 * Sonde de capacité PHANTOM (pré-vol en 2e étape, après la sonde de
 * joignabilité probeLlmEndpoint) : un vrai appel chat/completions court avec
 * un prompt représentatif. Détecte AVANT de payer 20 s de sandbox + 30-60 min
 * d'agent mort :
 *   - le pool épuisé (503 pool_exhausted/pool_busy du pont — quota/balance) ;
 *   - le refus sémantique (200 + « I can't provide… » / {"status":"refused"}) ;
 *   - une endpoint injoignable (timeout/réseau).
 */
export async function probeLlmCapacity(opts: {
  apiKey?: string;
  apiBase?: string;
  model: string;
  timeoutMs?: number;
}): Promise<LlmCapacityResult> {
  const { apiKey, apiBase, model, timeoutMs = 90_000 } = opts;
  if (!apiKey) return { kind: "unreachable", detail: "LLM_API_KEY non configurée" };
  const base = (apiBase || "").replace(/\/+$/, "");
  if (!base) return { kind: "unreachable", detail: "LLM_API_BASE non configurée" };
  const t0 = Date.now();
  try {
    const res = await fetch(`${base}/chat/completions`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({
        model,
        messages: [{ role: "user", content: CAPACITY_PROMPT }],
        max_tokens: 200,
      }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const bodyText = (await res.text().catch(() => "")).slice(0, 20_000);
    if (res.status === 503) {
      return {
        kind: "pool_exhausted",
        detail: extractErrorDetail(bodyText) ?? `HTTP 503 — ${bodyText.replace(/\s+/g, " ").slice(0, 200)}`,
      };
    }
    if (!res.ok) {
      return { kind: "http_error", status: res.status, detail: extractErrorDetail(bodyText) ?? bodyText.replace(/\s+/g, " ").slice(0, 300) };
    }
    // 200 : analyser le contenu ET le corps brut (refus « 200 avec corps
    // d'erreur » — ex. {"status":"refused"} observé via le pont).
    let content = "";
    let modelServed: string | null = null;
    try {
      const j = JSON.parse(bodyText) as {
        model?: unknown;
        choices?: Array<{ message?: { content?: unknown } }>;
      };
      const c = j?.choices?.[0]?.message?.content;
      if (typeof c === "string") content = c;
      if (typeof j?.model === "string") modelServed = j.model;
    } catch {
      // corps non JSON : le test de refus sur bodyText suffit
    }
    if (REFUSAL_RE.test(`${content}\n${bodyText}`)) {
      return { kind: "refused", detail: (content || bodyText).replace(/\s+/g, " ").slice(0, 300) };
    }
    return {
      kind: "ok",
      latencyMs: Date.now() - t0,
      modelServed,
      preview: content.replace(/\s+/g, " ").trim().slice(0, 160),
    };
  } catch (err) {
    return {
      kind: "unreachable",
      detail: err instanceof Error ? `${err.name}: ${err.message}` : "erreur réseau",
    };
  }
}

/**
 * Résumé compact de l'état du pool du pont (GET <LLM_API_BASE>/pool, 5 s max,
 * échec silencieux → chaîne d'indisponibilité). Alimente les diagnostics
 * PHANTOM (échec de run / gel détecté). Auth : LLM_BRIDGE_KEY, à défaut
 * LLM_API_KEY (le pont compare le Bearer à sa propre clé).
 */
export async function fetchPoolSummary(timeoutMs = 5_000): Promise<string> {
  const base = (process.env.LLM_API_BASE || "").replace(/\/+$/, "");
  if (!base) return "État pool: indisponible (LLM_API_BASE absente)";
  const headers: Record<string, string> = {};
  const key = process.env.LLM_BRIDGE_KEY || process.env.LLM_API_KEY;
  if (key) headers.Authorization = `Bearer ${key}`;
  try {
    const res = await fetch(`${base}/pool`, { headers, signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) return `État pool: indisponible (HTTP ${res.status})`;
    const body = (await res.json()) as {
      counts?: { healthy?: number; cooldown?: number; dead?: number; exhausted?: number };
      upstreams?: Array<{ name?: string; exhausted?: boolean; exhaustedReason?: string }>;
      entries?: Array<{ state?: string; lastError?: string | null }>;
    };
    const c: Record<string, number | undefined> = { ...(body.counts ?? {}) };
    // Compatibilité pont v2 sans champ `counts` : recalcul depuis entries.
    if (c.healthy === undefined && Array.isArray(body.entries)) {
      for (const e of body.entries) {
        const s = e.state ?? "";
        if (s === "healthy") c.healthy = (c.healthy ?? 0) + 1;
        else if (s === "cooldown") c.cooldown = (c.cooldown ?? 0) + 1;
        else if (s === "dead") c.dead = (c.dead ?? 0) + 1;
        else if (s === "exhausted") c.exhausted = (c.exhausted ?? 0) + 1;
      }
    }
    const parts = [
      `${c.healthy ?? 0} healthy`,
      `${c.cooldown ?? 0} cooldown`,
      `${c.dead ?? 0} dead`,
      `${c.exhausted ?? 0} exhausted`,
    ].join(" / ");
    const exclusions = Array.isArray(body.upstreams)
      ? body.upstreams.filter((u) => u.exhausted).slice(0, 3).map((u) => `${u.name}: ${(u.exhaustedReason ?? "?").slice(0, 120)}`)
      : [];
    const lastErr = Array.isArray(body.entries)
      ? body.entries.map((e) => e.lastError).find((s): s is string => typeof s === "string" && s.length > 0)
      : undefined;
    return (
      `État pool: ${parts}` +
      (exclusions.length ? ` ; exclus: ${exclusions.join(" | ")}` : "") +
      (lastErr ? ` ; dernière erreur: ${lastErr.slice(0, 200)}` : "")
    );
  } catch (err) {
    return `État pool: indisponible (${err instanceof Error ? err.message : "erreur réseau"})`;
  }
}
