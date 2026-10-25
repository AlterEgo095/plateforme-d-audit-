# ── AuditForge — image de l'application Next.js (API REST + frontend) ───────
# Build multi-stage basé sur Bun. Sortie standalone (next.config.ts).

# ── 1) Dépendances ──────────────────────────────────────────────────────────
FROM oven/bun:1 AS deps
WORKDIR /app
# Le schéma est requis avant l'installation (postinstall @prisma/client).
COPY package.json bun.lock ./
COPY prisma ./prisma
RUN bun install --frozen-lockfile

# ── 2) Construction ─────────────────────────────────────────────────────────
FROM oven/bun:1 AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
# DATABASE_URL factice : seule la génération du client Prisma est requise ici.
ENV DATABASE_URL="file:/tmp/build.db"
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN bunx prisma generate \
  && bun run build

# ── 3) Exécution ────────────────────────────────────────────────────────────
FROM oven/bun:1 AS runner
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0
COPY --from=build /app /app
# La base SQLite vit dans un volume monté sur /data (DATABASE_URL de docker-compose).
VOLUME ["/data"]
EXPOSE 3000

# Application du schéma au premier démarrage, puis serveur standalone.
# (exec : SIGTERM est bien délivré au serveur → arrêt gracieux.)
CMD ["sh", "-c", "mkdir -p /data && bunx prisma db push --skip-generate && exec bun .next/standalone/server.js"]

# Santé : /api/auth/me répond 401 sans cookie = serveur opérationnel.
HEALTHCHECK --interval=10s --timeout=5s --start-period=60s --retries=12 \
  CMD bun -e "try { const r = await fetch('http://127.0.0.1:3000/api/auth/me'); if (r.status !== 401 && r.status !== 200) process.exit(1); } catch { process.exit(1); }"
