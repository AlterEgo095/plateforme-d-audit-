"use client";

/**
 * AuditForge — Connexion temps réel au moteur d'exécution (socket.io :3030
 * via la passerelle Caddy). Singleton asynchrone créé uniquement côté
 * navigateur, authentifié par un token signé (GET /api/auth/socket-token).
 */

import { useEffect, useRef, useState } from "react";
import { io, type Socket } from "socket.io-client";
import type {
  ScanDoneEvent,
  ScanFindingEvent,
  ScanLogEvent,
  ScanUpdateEvent,
} from "@/lib/types";

export type ScanEventHandler =
  | ScanUpdateEvent
  | ScanDoneEvent
  | ScanLogEvent
  | ScanFindingEvent;

// ── Token d'authentification du handshake (cache module ~30 min) ─────

let cachedToken: string | null = null;
let tokenFetchedAt = 0;
const TOKEN_TTL_MS = 30 * 60 * 1000;

/**
 * Récupère un token de session signé pour le handshake socket.io.
 * Utilise fetch natif same-origin (pas api-client) pour éviter toute
 * dépendance circulaire (api-client émet des événements d'expiration).
 * Retourne null en cas d'échec : le socket sera alors créé sans auth
 * et le handshake sera rejeté par le moteur.
 */
async function fetchSocketToken(): Promise<string | null> {
  if (typeof window === "undefined") return null;
  if (cachedToken && Date.now() - tokenFetchedAt < TOKEN_TTL_MS) {
    return cachedToken;
  }
  try {
    const res = await fetch("/api/auth/socket-token", {
      credentials: "same-origin",
      cache: "no-store",
    });
    if (!res.ok) return null;
    const body = (await res.json()) as { token?: unknown };
    if (typeof body.token === "string" && body.token.length > 0) {
      cachedToken = body.token;
      tokenFetchedAt = Date.now();
      return cachedToken;
    }
    return null;
  } catch {
    return null;
  }
}

function invalidateToken(): void {
  cachedToken = null;
  tokenFetchedAt = 0;
}

// ── Singleton asynchrone ─────────────────────────────────────────────

let socketInstance: Socket | null = null;
let socketPromise: Promise<Socket | null> | null = null;
let authRecoveryDone = false;

/** Rooms `scan:{id}` actuellement souscrites (ré-émises après reconnexion). */
const subscribedScans = new Set<string>();

/**
 * Crée (ou retourne) le socket partagé. La promesse est mémorisée pour
 * éviter les doubles créations. Résout toujours (même sans token) : le
 * moteur rejettera le handshake si l'authentification est invalide.
 */
export function ensureSocket(): Promise<Socket | null> {
  if (typeof window === "undefined") return Promise.resolve(null);
  if (socketInstance) return Promise.resolve(socketInstance);
  if (socketPromise) return socketPromise;

  socketPromise = (async () => {
    const token = await fetchSocketToken();
    const socket = io("/?XTransformPort=3030", {
      transports: ["websocket", "polling"],
      reconnection: true,
      reconnectionAttempts: Infinity,
      reconnectionDelay: 1000,
      auth: token ? { token } : {},
    });

    // Reconnexion : ré-émettre scan:subscribe pour toutes les rooms.
    socket.on("connect", () => {
      for (const scanId of subscribedScans) {
        socket.emit("scan:subscribe", { scanId });
      }
    });

    // Rejet d'authentification : UNE seule récupération par session —
    // invalider le cache, re-fetch du token, réassignation puis reconnect.
    socket.on("connect_error", (err: Error) => {
      if (authRecoveryDone) return;
      if (!err?.message || !err.message.includes("unauthorized")) return;
      authRecoveryDone = true;
      invalidateToken();
      void fetchSocketToken().then((fresh) => {
        if (fresh) {
          socket.auth = { token: fresh };
          socket.connect();
        }
      });
    });

    socketInstance = socket;
    return socket;
  })();

  return socketPromise;
}

/** État de connexion au moteur (true dès l'événement "connect"). */
export function useSocketConnection(): { connected: boolean } {
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    let mounted = true;
    let socket: Socket | null = null;

    const onConnect = () => setConnected(true);
    const onDisconnect = () => setConnected(false);

    void ensureSocket().then((s) => {
      if (!s || !mounted) return;
      socket = s;
      setConnected(s.connected);
      s.on("connect", onConnect);
      s.on("disconnect", onDisconnect);
    });

    return () => {
      mounted = false;
      socket?.off("connect", onConnect);
      socket?.off("disconnect", onDisconnect);
    };
  }, []);

  return { connected };
}

/**
 * S'abonne aux événements de scan du moteur. Le handler est conservé dans un
 * ref (toujours la dernière version) et les listeners sont retirés au
 * démontage. Le singleton n'est jamais déconnecté ici.
 */
export function useScanEvents(
  handler: (ev: ScanEventHandler) => void
): void {
  const handlerRef = useRef(handler);

  // Mise à jour du handler après chaque rendu (jamais pendant le rendu).
  useEffect(() => {
    handlerRef.current = handler;
  }, [handler]);

  useEffect(() => {
    let mounted = true;
    let socket: Socket | null = null;
    const dispatch = (ev: ScanEventHandler) => handlerRef.current(ev);

    void ensureSocket().then((s) => {
      if (!s || !mounted) return;
      socket = s;
      s.on("scan:update", dispatch);
      s.on("scan:done", dispatch);
      s.on("scan:log", dispatch);
      s.on("scan:finding", dispatch);
    });

    return () => {
      mounted = false;
      socket?.off("scan:update", dispatch);
      socket?.off("scan:done", dispatch);
      socket?.off("scan:log", dispatch);
      socket?.off("scan:finding", dispatch);
    };
  }, []);
}

/** Rejoint la room `scan:{scanId}` du moteur (et la mémorise). */
export function subscribeScan(scanId: string): void {
  subscribedScans.add(scanId);
  void ensureSocket().then((s) => {
    // Émis seulement si la souscription est toujours active.
    if (s && subscribedScans.has(scanId)) {
      s.emit("scan:subscribe", { scanId });
    }
  });
}

/** Quitte la room `scan:{scanId}` du moteur (et oublie l'id). */
export function unsubscribeScan(scanId: string): void {
  subscribedScans.delete(scanId);
  void ensureSocket().then((s) => {
    s?.emit("scan:unsubscribe", { scanId });
  });
}
