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
  const { apiKey, apiBase, model, timeoutMs = 12_000 } = opts;
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
    return {
      ok: false,
      reason: `endpoint LLM ${base} injoignable (${err instanceof Error ? err.message : "erreur réseau"})`,
    };
  }
}

/** Retire le préfixe provider LiteLLM (« openai/… ») pour un appel API direct. */
export function stripLlmProvider(model: string): string {
  return model.replace(/^[a-z0-9_-]+\//i, "");
}
