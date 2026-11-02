import type { NextConfig } from "next";

// M3 (audit 8-a) : en-têtes de sécurité HTTP pour l'exposition publique VPS.
// - CSP tolérante aux contraintes Next.js (scripts inline d'hydratation) et à
//   socket.io (ws/wss same-origin via la gateway).
// - 'unsafe-eval' est REQUISE par Turbopack en DÉVELOPPEMENT uniquement ; elle
//   est retirée en production (durcissement suite audit externe — un XSS ne
//   doit pas pouvoir escalader vers eval/Function).
// - HSTS : ignorée sur HTTP simple, appliquée automatiquement dès que le site
//   est servi en HTTPS (Caddy + SITE_DOMAIN).
const isDev = process.env.NODE_ENV !== "production";

const scriptSrc = isDev
  ? "script-src 'self' 'unsafe-inline' 'unsafe-eval'"
  : "script-src 'self' 'unsafe-inline'";

const CSP = [
  "default-src 'self'",
  scriptSrc,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  "connect-src 'self' ws: wss:",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

const securityHeaders = [
  { key: "Content-Security-Policy", value: CSP },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  },
  { key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" },
];

// Durcissement cache (audit externe) : Next.js pose s-maxage=31536000 sur les
// pages prerendues — trop agressif pour du HTML applicatif (une correction sur
// /legal ne se propagerait pas pendant un an côté CDN). On borne le cache CDN
// à 10 minutes tout en gardant le bénéfice de la mise en cache.
const HTML_CACHE = [{ key: "Cache-Control", value: "public, max-age=0, s-maxage=600" }];

const nextConfig: NextConfig = {
  output: "standalone",
  reactStrictMode: false,
  // F-12 : ne pas divulguer la pile technique (en-tête X-Powered-By: Next.js).
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: securityHeaders,
      },
      {
        source: "/",
        headers: HTML_CACHE,
      },
      {
        source: "/legal",
        headers: HTML_CACHE,
      },
    ];
  },
  // Dev-only : le sandbox accède à l'app via 127.0.0.1 — sans ceci, Next 16
  // bloque les upgrades WebSocket /_next/hmr (cross-origin) et l'hydratation
  // React reste bloquée sur l'écran de boot (canal debug RSC sur le WS HMR).
  allowedDevOrigins: ["127.0.0.1", "localhost"],
};

export default nextConfig;
