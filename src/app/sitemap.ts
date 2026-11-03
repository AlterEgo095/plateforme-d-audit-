import type { MetadataRoute } from "next";

// Sitemap minimal — SPA mono-page + page légale. La base est dérivable via
// NEXT_PUBLIC_SITE_URL (ex. https://auditforge.aenews.online), défaut cohérent
// avec le déploiement production actuel.
const BASE = (process.env.NEXT_PUBLIC_SITE_URL ?? "https://auditforge.aenews.online").replace(
  /\/+$/,
  ""
);

export default function sitemap(): MetadataRoute.Sitemap {
  return [
    {
      url: `${BASE}/`,
      lastModified: new Date(),
      changeFrequency: "monthly",
      priority: 0.5,
    },
    {
      url: `${BASE}/legal`,
      lastModified: new Date(),
      changeFrequency: "yearly",
      priority: 0.2,
    },
  ];
}
