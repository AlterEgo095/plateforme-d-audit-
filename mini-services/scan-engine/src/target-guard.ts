/**
 * AuditForge — Garde SSRF des cibles de scan (F-04/F-11, remédiation 2-c).
 * =========================================================================
 * Défense en profondeur CÔTÉ MOTEUR : l'API applique déjà un blocage en amont
 * (commit d4b4a95), mais le moteur ne doit jamais dépendre de son appelant.
 *
 * Pour une cible URL/NETWORK, on refuse :
 *   - les schémas non http/https ;
 *   - les hosts littéraux privés/réservés : 127/8, 10/8, 172.16/12, 192.168/16,
 *     169.254/16 (lien local — inclut 169.254.169.254 métadonnées cloud),
 *     0.0.0.0/8, ::1, :: (non spécifiée), fc00::/7 (unique local), fe80::/10
 *     (lien local), IPv4-mappées ::ffff:a.b.c.d, port 0 ;
 *   - les noms d'hôte internes : localhost, *.localhost, *.internal
 *     (couvre metadata.google.internal) ;
 *   - puis RÉSOLUTION DNS (node:dns, {all:true}) : UNE SEULE adresse résolue
 *     privée/boucle/lien-local est rédhibitoire — bloque aussi le rebinding
 *     basique (le nom « légitime » qui résout vers 127.0.0.1).
 *
 * La résolution DNS échoue → refus fail-closed (une cible que le moteur ne
 * sait pas résoudre produirait de toute façon un scan inutile).
 *
 * Limites assumées (documentées) : pas de suivi des redirections vers des
 * cibles privées (les sondes HTTP utilisent redirect:manual/follow — une
 * redirection est une décision de la cible distante, hors périmètre SSRF
 * d'entrée), pas de détection 6to4/Teredo (obsolètes), pas de TOCTOU complet
 * (l'IP peut changer entre la validation et l'outil — la fenêtre est réduite
 * par la validation immédiatement pré-execution dans runRealScan).
 *
 * Les cibles GIT restent HORS périmètre (l'appelant décide — clonage de
 * dépôts, pas d'accès IP direct).
 */

import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

export type TargetGuardResult = { ok: true } | { ok: false; reason: string };

/**
 * F-04bis (symétrique de l'app — src/lib/dto.ts) : allowlist opérateur de
 * hosts EXACTS (TARGET_HOST_ALLOWLIST, virgules, minuscules). Contexte : les
 * fixtures de test de la plateforme (WordPress d'exercice, réflecteur XSS,
 * dépôt git de fixtures) sont hébergées sur le VPS lui-même et joignables via
 * sa passerelle Docker (192.168.0.1) — des adresses privées que le garde
 * refuse par défaut. Correspondance EXACTE sur l'hôte littéral de la cible
 * (jamais sur les adresses RÉSOLUES — un nom public qui résout privé reste
 * refusé, l'anti-rebinding est préservé). Vide (défaut) : garde stricte.
 */
const OPERATOR_ALLOWLIST = (process.env.TARGET_HOST_ALLOWLIST ?? "")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

export interface TargetGuardOptions {
  /**
   * Résolveur injectable (tests sans réseau) — défaut : dns lookup {all:true}.
   */
  resolve?: (host: string) => Promise<Array<{ address: string; family: number }>>;
}

function refused(reason: string): TargetGuardResult {
  return { ok: false, reason };
}

/** Plages IPv4 privées/réservées : [début, fin] en entier 32 bits + libellé. */
const V4_RANGES: Array<[number, number, string]> = [
  [0x00000000, 0x00ffffff, "0.0.0.0/8 — réseau « this »"],
  [0x0a000000, 0x0affffff, "10.0.0.0/8 — privé"],
  [0x7f000000, 0x7fffffff, "127.0.0.0/8 — boucle locale"],
  [0xa9fe0000, 0xa9feffff, "169.254.0.0/16 — lien local (métadonnées cloud)"],
  [0xac100000, 0xac1fffff, "172.16.0.0/12 — privé"],
  [0xc0a80000, 0xc0a8ffff, "192.168.0.0/16 — privé"],
];

function ipv4Risk(v: number): string | null {
  for (const [lo, hi, label] of V4_RANGES) {
    if (v >= lo && v <= hi) return label;
  }
  return null;
}

/** Parse strict d'une IPv4 en points-décimaux → entier 32 bits, sinon null. */
function parseIpv4(host: string): number | null {
  const parts = host.split(".");
  if (parts.length !== 4) return null;
  let out = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const n = Number.parseInt(p, 10);
    if (n > 255) return null;
    out = (out << 8) | n;
  }
  return out >>> 0;
}

/** Décompose une IPv6 (sans crochets, zone % supprimée) en 8 hextets, sinon null. */
function expandIpv6(raw: string): number[] | null {
  const h = raw.split("%")[0].toLowerCase();
  if (h.includes("::")) {
    const [head, tail = ""] = h.split("::");
    const hp = head ? head.split(":") : [];
    const tp = tail ? tail.split(":") : [];
    const fill = 8 - hp.length - tp.length;
    if (fill < 0) return null;
    const groups = [...hp, ...Array<string>(fill).fill("0"), ...tp];
    const out: number[] = [];
    for (const g of groups) {
      if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
      out.push(Number.parseInt(g, 16));
    }
    return out;
  }
  const groups = h.split(":");
  if (groups.length !== 8) return null;
  const out: number[] = [];
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    out.push(Number.parseInt(g, 16));
  }
  return out;
}

/** Risque d'une adresse IPv6 (privée/boucle/lien-local) ou null si autorisée. */
function ipv6Risk(raw: string): string | null {
  const groups = expandIpv6(raw);
  if (!groups) return "adresse IPv6 malformée";
  // Boucle locale (::1) et non spécifiée (::)
  if (groups.every((g) => g === 0)) return ":: — adresse non spécifiée";
  if (groups.slice(0, 7).every((g) => g === 0) && groups[7] === 1) {
    return "::1 — boucle locale";
  }
  // fc00::/7 — unique local (fc00-fdff sur le premier hextet)
  if ((groups[0] & 0xfe00) === 0xfc00) return "fc00::/7 — IPv6 unique local";
  // fe80::/10 — lien local (fe80-febf)
  if (groups[0] >= 0xfe80 && groups[0] <= 0xfebf) return "fe80::/10 — IPv6 lien local";
  // IPv4-mappée ::ffff:a.b.c.d (et forme héxa ::ffff:7f00:1) → risque de l'IPv4
  const first5Zero = groups.slice(0, 5).every((g) => g === 0);
  if (first5Zero && (groups[5] === 0xffff || groups[5] === 0)) {
    const v = (((groups[6] << 16) | groups[7]) >>> 0) as number;
    const r = ipv4Risk(v);
    if (r) return `IPv4-mappée — ${r}`;
  }
  return null;
}

function defaultResolve(host: string): Promise<Array<{ address: string; family: number }>> {
  return lookup(host, { all: true });
}

/** Risque d'une adresse résolue (v4 ou v6) ou null si autorisée. */
function resolvedAddressRisk(address: string): string | null {
  if (address.includes(":")) return ipv6Risk(address);
  const v = parseIpv4(address);
  if (v === null) return "adresse IPv4 malformée";
  return ipv4Risk(v);
}

/**
 * Vérifie qu'une cible de scan est bien une cible DISTANTE autorisée.
 * Accepte une URL (http/https) ou une cible NETWORK (hôte, IP, CIDR — un
 * schéma http:// implicite est appliqué pour normaliser le parsing).
 */
export async function assertRemoteTargetAllowed(
  rawTarget: string,
  opts: TargetGuardOptions = {},
): Promise<TargetGuardResult> {
  const raw = String(rawTarget ?? "").trim();
  if (!raw) return refused("cible vide");
  if (raw.startsWith("-")) return refused("cible invalide (commence par « - » — risque d'injection d'option CLI)");

  // Normalisation : les cibles NETWORK (« example.com », « 10.0.0.0/24 »,
  // « [::1]:8080 ») sont parsées avec un schéma implicite.
  const candidate = /^https?:\/\//i.test(raw) ? raw : `http://${raw}`;
  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    return refused("cible illisible (URL invalide)");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return refused(`schéma « ${url.protocol.replace(/:$/, "")} » non autorisé (http/https uniquement)`);
  }
  if (url.port === "0") return refused("port 0 invalide");
  const hostname = url.hostname;
  if (!hostname) return refused("hôte absent");

  // Hostnames internes (case-insensitive — URL a déjà normalisé la casse ASCII).
  const lower = hostname.toLowerCase();
  if (lower === "localhost" || lower.endsWith(".localhost")) {
    return refused("« localhost » (boucle locale) — les scans ciblent des hôtes distants uniquement");
  }
  if (lower === "metadata.google.internal" || lower.endsWith(".internal")) {
    return refused("hôte interne (*.internal, inclut metadata.google.internal) — résolution interne interdite");
  }

  // Allowlist opérateur (F-04bis) — match EXACT sur l'hôte littéral, après
  // normalisation crochets IPv6. Court-circuite IP littérale ET résolution DNS.
  const bareHost = lower.replace(/^\[/, "").replace(/\]$/, "");
  if (OPERATOR_ALLOWLIST.includes(bareHost)) {
    return { ok: true };
  }

  // IP littérale (v4/v6, crochets IPv6 retirés) → contrôle direct, sans DNS.
  const bare = bareHost;
  const family = isIP(bare);
  if (family === 4) {
    const v = parseIpv4(bare);
    if (v === null) return refused(`adresse IPv4 malformée (${bare})`);
    const risk = ipv4Risk(v);
    if (risk) return refused(`adresse IP privée/réservée (${bare} — ${risk})`);
    return { ok: true };
  }
  if (family === 6) {
    const risk = ipv6Risk(bare);
    if (risk) return refused(`adresse IPv6 privée/réservée (${bare} — ${risk})`);
    return { ok: true };
  }

  // Nom d'hôte → résolution DNS : UNE SEULE adresse privée/boucle/lien-local
  // rédhibitoire (anti-rebinding basique — on valide TOUTES les réponses).
  const resolve = opts.resolve ?? defaultResolve;
  let addrs: Array<{ address: string; family: number }>;
  try {
    addrs = await resolve(bare);
  } catch (err) {
    return refused(
      `résolution DNS impossible (${err instanceof Error ? err.message : "erreur"}) — cible introuvable ou DNS du moteur défaillant`,
    );
  }
  if (!Array.isArray(addrs) || addrs.length === 0) {
    return refused("résolution DNS sans résultat — cible introuvable");
  }
  for (const a of addrs) {
    const risk = resolvedAddressRisk(a.address);
    if (risk) {
      return refused(
        `l'hôte ${bare} résout vers une adresse privée/réservée (${a.address} — ${risk}) — cible interdite (SSRF)`,
      );
    }
  }
  return { ok: true };
}
