#!/usr/bin/env bash
# ── AuditForge — Sprint 3 « navigateur headless » : déploiement VPS ──────────
# Prérequis : vps-tools/.env.local (VPS_HOST/VPS_USER/VPS_PASS) — chmod 600.
# Portée : app (UI + API tools) + moteur (arsenal BROWSER + browser-tools) +
# Dockerfile.engine (bun install browser-tools + paquet Debian chromium).
# Le compose VPS (/opt/auditforge/docker-compose.yml) porte déjà
# build.args WITH_ARSENAL=1 / WITH_SECLISTS=1 → docker compose build suffit.
# Usage : bash scripts/deploy-sprint3.sh
#
# NB procédure : le build distant DOIT tourner en nohup (le CLI vps exec
# coupe la session SSH bien avant 10 min) puis être suivi par polling :
#   tail -f n'est pas persistant — boucler sur
#   `pgrep -f '[d]ocker compose build' && echo RUNNING || echo DONE`
#   (le pattern [d] évite au pgrep de matcher son propre shell).
set -euo pipefail
cd "$(dirname "$0")/.."

vps() { (bun run vps-tools/vps.ts "$@"); }
R=/opt/auditforge

echo "── 1/6 — Garde-fou : aucun scan en cours ─────────────────────────────"
vps exec "sudo docker exec auditforge-app-1 bun -e 'const {PrismaClient}=require(\"@prisma/client\");const p=new PrismaClient();p.scan.findMany({where:{status:{in:[\"RUNNING\",\"QUEUED\"]}}}).then(s=>{console.log(\"ACTIFS:\"+s.length);process.exit(s.length?1:0)})'" || {
  echo "!! Des scans sont actifs — attendre/arrêter avant rebuild."; exit 1; }

echo "── 2/6 — Envoi des fichiers Sprint 3 (app + moteur + browser-tools) ──"
for f in \
  src/lib/types.ts \
  src/lib/dto.ts \
  "src/app/api/tools/route.ts" \
  src/components/audit/campaigns-view.tsx \
  src/components/audit/status-badges.tsx \
  src/components/audit/tools-view.tsx \
  mini-services/scan-engine/src/types.ts \
  mini-services/scan-engine/src/index.ts \
  mini-services/scan-engine/src/templates.ts \
  "mini-services/scan-engine/src/real-exec/env.ts" \
  "mini-services/scan-engine/src/real-exec/arsenal.ts" \
  "mini-services/scan-engine/src/real-exec/index.ts" \
  mini-services/browser-tools/package.json \
  mini-services/browser-tools/bun.lock \
  mini-services/browser-tools/src/resolve.ts \
  mini-services/browser-tools/src/analyze.ts \
  mini-services/browser-tools/src/cli.ts \
  scripts/Dockerfile.engine ; do
  echo "  put $f"
  vps put "$f" "$R/$f"
done

echo "── 3/6 — Build app + engine (arsenal 1, seclists 1 — args du compose) ─"
# nohup + redirection complète : la session SSH se coupe, le build survit.
vps exec "cd $R && rm -f /tmp/af-build-s3.log && nohup sudo docker compose build app engine </dev/null > /tmp/af-build-s3.log 2>&1 & sleep 4; echo build_lance"

echo "── 4/6 — Polling du build (toutes les ~2 min, ~15 min max) ───────────"
for i in $(seq 1 8); do
  sleep 110
  ST="$(vps exec "pgrep -f '[d]ocker compose build' >/dev/null && echo RUNNING || echo DONE; grep -c 'Image auditforge-.* Built' /tmp/af-build-s3.log" 2>/dev/null | tail -2 | tr '\n' ' ')"
  echo "  poll $i : $ST"
  echo "$ST" | grep -q "DONE" && break
done
vps exec "grep -E 'af-browser-tools|Built|ERROR' /tmp/af-build-s3.log | tail -6"
# La sonde du build doit avoir imprimé : af-browser-tools 1.0.0 (chromium: /usr/bin/chromium)
vps exec "grep -q 'af-browser-tools 1.0.0' /tmp/af-build-s3.log" || {
  echo "!! Sonde Chromium du build absente — l'image moteur est suspecte."; exit 1; }

echo "── 5/6 — Redémarrage + vérifications ─────────────────────────────────"
vps exec "cd $R && sudo docker compose up -d app engine 2>&1 | tail -4; sleep 12; sudo docker compose ps --format '{{.Name}} {{.Status}}' | head -8"
# Sonde CLI navigateur DANS le conteneur moteur (runtime) :
vps exec "sudo docker exec auditforge-engine-1 af-browser-tools --version"
# Santé moteur interne (exec_mode attendu : real) :
vps exec "T=\$(grep '^ENGINE_INTERNAL_TOKEN=' $R/.env | cut -d= -f2 | tr -d '\"'); sudo docker exec auditforge-engine-1 curl -s -H \"x-internal-token: \$T\" http://127.0.0.1:3030/internal/health"

echo "── 6/6 — Vérification HTTPS publique ─────────────────────────────────"
vps exec "curl -s -o /dev/null -w '%{http_code}' https://auditforge.aenews.online/robots.txt" && echo " ← robots.txt"
vps exec "curl -s -o /dev/null -w '%{http_code}' -X POST https://auditforge.aenews.online/api/cases -H 'Content-Type: application/json' -d '{}'" && echo " ← POST /api/cases (401 attendu)"

echo "✅ Déploiement Sprint 3 terminé — valider ensuite :"
echo "   - GET /api/tools (session admin) : famille BROWSER + 4 outils ;"
echo "   - campagne URL sur http://172.17.0.1:8092 (cible VulnApp, allowlist)"
echo "     avec les 4 outils BROWSER → 4 scans COMPLETED + constats réels ;"
echo "   - vues UI Outils/Campagnes/Vulnérabilités."
