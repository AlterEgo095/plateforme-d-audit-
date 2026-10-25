/**
 * AuditForge — Client HTTP typé pour l'API REST (/api/...).
 * Toutes les requêtes sont relatives (même origine), JSON, avec cookies.
 */

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function request<T>(url: string, init: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(url, {
      credentials: "same-origin",
      ...init,
      headers: {
        "Content-Type": "application/json",
        ...(init.headers ?? {}),
      },
    });
  } catch {
    throw new ApiError("Impossible de joindre le serveur", 0);
  }

  let body: unknown = null;
  const text = await res.text();
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = null;
    }
  }

  if (!res.ok) {
    // Session expirée : notification globale (la page retourne au login),
    // sauf pour les routes d'authentification elles-mêmes.
    if (res.status === 401 && !url.includes("/api/auth/") && typeof window !== "undefined") {
      window.dispatchEvent(new CustomEvent("af:session-expired"));
    }
    const message =
      (body !== null &&
        typeof body === "object" &&
        "error" in body &&
        typeof (body as { error?: unknown }).error === "string" &&
        (body as { error: string }).error) ||
      res.statusText ||
      "Erreur inattendue";
    throw new ApiError(message, res.status);
  }

  return body as T;
}

export function apiGet<T>(url: string): Promise<T> {
  return request<T>(url, { method: "GET" });
}

export function apiPost<T>(url: string, body?: unknown): Promise<T> {
  return request<T>(url, {
    method: "POST",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

export function apiPatch<T>(url: string, body?: unknown): Promise<T> {
  return request<T>(url, {
    method: "PATCH",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

export function apiDelete<T>(url: string): Promise<T> {
  return request<T>(url, { method: "DELETE" });
}

/** Extrait un message lisible (FR) d'une erreur quelconque. */
export function getErrorMessage(e: unknown): string {
  if (e instanceof ApiError) return e.message;
  if (e instanceof Error && e.message) return e.message;
  return "Une erreur inattendue est survenue";
}
