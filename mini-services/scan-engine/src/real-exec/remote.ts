/**
 * AuditForge — Helpers HTTP pour les adaptateurs de plateformes distantes.
 *
 * DeepAudit (FastAPI) et RedAmon (webapp Next.js) sont des plateformes
 * complètes pilotées par API REST — contrairement à Phantom/Basalt (CLI
 * locales). Ce module fournit les primitives communes :
 *  - fetch avec timeout ET chaînage du signal d'annulation du scan ;
 *  - sommeil interrompible (boucles de polling réactives à l'annulation) ;
 *  - extraction d'un cookie `Set-Cookie` (session RedAmon) ;
 *  - troncature sûre des payloads injectés dans les logs / preuves.
 *
 * Aucune dépendance externe : fetch natif (Bun ≥ 1.0).
 */

export class HttpError extends Error {
  constructor(
    public readonly status: number,
    public readonly url: string,
    bodyPreview: string,
  ) {
    super(`HTTP ${status} sur ${url}${bodyPreview ? ` — ${bodyPreview}` : ""}`);
    this.name = "HttpError";
  }
}

export interface FetchOpts {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  headers?: Record<string, string>;
  /** Corps déjà sérialisé (JSON.stringify, URLSearchParams…) ou undefined. */
  body?: string;
  /** Timeout par requête (ms) — défaut 15 000. */
  timeoutMs?: number;
  /** Signal d'annulation du scan (chaîné au timeout interne). */
  signal?: AbortSignal;
}

export async function httpFetch(url: string, opts: FetchOpts = {}): Promise<Response> {
  const { timeoutMs = 15_000, signal, method = "GET", headers = {}, body } = opts;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error(`timeout ${timeoutMs} ms`)), timeoutMs);
  const onAbort = () => controller.abort(signal?.reason);
  if (signal) {
    if (signal.aborted) controller.abort(signal.reason);
    else signal.addEventListener("abort", onAbort, { once: true });
  }
  try {
    return await fetch(url, {
      method,
      headers,
      body,
      signal: controller.signal,
      redirect: "manual",
    });
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", onAbort);
  }
}

/** Requête JSON : parse la réponse, lève HttpError si statut ≥ 400. */
export async function httpJson<T>(url: string, opts: FetchOpts = {}): Promise<T> {
  const res = await httpFetch(url, opts);
  const text = await res.text();
  if (!res.ok) {
    let preview = "";
    try {
      const parsed = JSON.parse(text) as Record<string, unknown>;
      preview = String(parsed.detail ?? parsed.error ?? parsed.message ?? "");
    } catch {
      preview = text.slice(0, 200);
    }
    throw new HttpError(res.status, url, preview.slice(0, 300));
  }
  if (!text.trim()) return {} as T;
  return JSON.parse(text) as T;
}

/** Sommeil interrompible : résolu à temps, rejeté sur abort. */
export function sleepInterruptible(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason instanceof Error ? signal.reason : new Error("annulé"));
      return;
    }
    const timer = setTimeout(finish, ms);
    function finish() {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }
    function onAbort() {
      clearTimeout(timer);
      reject(signal?.reason instanceof Error ? signal.reason : new Error("annulé"));
    }
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

/** Extrait la valeur du cookie nommé depuis les en-têtes Set-Cookie d'une réponse. */
export function extractCookie(res: Response, name: string): string | null {
  // getSetCookie() (Bun moderne / undici) sinon fallback sur l'en-tête brut.
  const raws: string[] =
    typeof res.headers.getSetCookie === "function"
      ? res.headers.getSetCookie()
      : (res.headers.get("set-cookie") ?? "").split(/,(?=[^;]+?=)/);
  for (const raw of raws) {
    const pair = raw.split(";", 1)[0]?.trim() ?? "";
    const eq = pair.indexOf("=");
    if (eq > 0 && pair.slice(0, eq).trim() === name) return pair.slice(eq + 1).trim();
  }
  return null;
}

/** Troncature sûre pour logs / preuves. */
export function trunc(value: unknown, max = 4000): string {
  const s = typeof value === "string" ? value : JSON.stringify(value) ?? "";
  return s.length > max ? `${s.slice(0, max)}…(${s.length} caractères)` : s;
}

/** Lit un flux SSE ligne par ligne et délivre les événements complets. */
export async function readSse(
  res: Response,
  onEvent: (event: string | null, data: string) => void,
  signal?: AbortSignal,
): Promise<void> {
  const reader = res.body?.getReader();
  if (!reader) return;
  const decoder = new TextDecoder();
  let buffer = "";
  let event: string | null = null;
  const abort = () => void reader.cancel().catch(() => undefined);
  signal?.addEventListener("abort", abort, { once: true });
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let nl: number;
      while ((nl = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, nl).replace(/\r$/, "");
        buffer = buffer.slice(nl + 1);
        if (line.startsWith("event:")) {
          event = line.slice(6).trim();
        } else if (line.startsWith("data:")) {
          const data = line.slice(5).trim();
          if (data) {
            onEvent(event, data);
            event = null;
          }
        }
        // les lignes vides séparent les événements — géré par la remise ci-dessus
      }
      if (buffer.length > 1_000_000) buffer = buffer.slice(-100_000); // garde-fou
    }
  } finally {
    signal?.removeEventListener("abort", abort);
  }
}
