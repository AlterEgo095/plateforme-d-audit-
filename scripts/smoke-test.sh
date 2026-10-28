#!/usr/bin/env bash
# ── AuditForge — smoke test E2E (garde-fou anti-récidive RF1) ────────────────
# Vérifie le chemin complet app ⇄ moteur : login → campagne séquentielle →
# scans COMPLETED (détail et variables : scripts/smoke-test.ts).
#   SMOKE_BASE_URL=http://127.0.0.1:3000 ./scripts/smoke-test.sh
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_URL="${SMOKE_BASE_URL:-http://127.0.0.1:3000}"

command -v bun >/dev/null 2>&1 || { echo "❌ bun introuvable — https://bun.sh"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "❌ curl introuvable"; exit 1; }

echo "▶ attente de ${BASE_URL} (120 s max)…"
up=0
for _ in $(seq 1 60); do
  if curl -sf -o /dev/null --max-time 3 "${BASE_URL}/"; then up=1; break; fi
  sleep 2
done
if [ "$up" != "1" ]; then
  echo "❌ application injoignable sur ${BASE_URL} après 120 s"
  exit 1
fi

exec bun "${DIR}/smoke-test.ts"
