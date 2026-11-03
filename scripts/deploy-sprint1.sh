#!/usr/bin/env bash
# ── AuditForge — Sprint 1 « élargissement de l'arsenal » : déploiement VPS ──
# Prérequis : vps-tools/.env.local (VPS_HOST/VPS_USER/VPS_PASS) — chmod 600.
# Usage : bash scripts/deploy-sprint1.sh
set -euo pipefail
cd "$(dirname "$0")/.."

VPS="cd vps-tools && bun run vps.ts"
R=/opt/auditforge

echo "── 1/7 — Garde-fou : aucun scan en cours ─────────────────────────────"
$VPS exec "sudo docker exec auditforge-app-1 bun -e 'const {PrismaClient}=require(\"@prisma/client\");const p=new PrismaClient();p.scan.findMany({where:{status:{in:[\"RUNNING\",\"QUEUED\"]}}}).then(s=>{console.log(\"ACTIFS:\"+s.length);process.exit(s.length?1:0)})'" || {
  echo "!! Des scans sont actifs — attente/reprise plus tard ou arrêt manuel avant rebuild."; exit 1; }

echo "── 2/7 — Envoi des fichiers (moteur + app) ───────────────────────────"
for f in \
  mini-services/scan-engine/src/types.ts \
  mini-services/scan-engine/src/templates.ts \
  mini-services/scan-engine/src/index.ts \
  mini-services/scan-engine/src/real-exec/arsenal.ts \
  mini-services/scan-engine/src/real-exec/env.ts \
  mini-services/scan-engine/src/real-exec/index.ts \
  Dockerfile.engine \
  src/lib/types.ts \
  src/lib/dto.ts \
  src/app/api/tools/route.ts \
  src/components/audit/status-badges.tsx \
  src/components/audit/campaigns-view.tsx ; do
  echo "  put $f"
  $VPS put "$f" "$R/$f"
done

echo "── 3/7 — Rebuild image moteur (installe les 7 outils — long, ~10 min) ─"
$VPS exec "cd $R && sudo docker compose build engine"

echo "── 4/7 — Redémarrage moteur ──────────────────────────────────────────"
$VPS exec "cd $R && sudo docker compose up -d engine && sleep 8 && sudo docker compose ps engine"

echo "── 5/7 — Rebuild app (catalogue/familles/presets) ────────────────────"
$VPS exec "cd $R && sudo docker compose build app && sudo docker compose up -d app && sleep 8"

echo "── 6/7 — Vérification : statut réel des 22 outils ────────────────────"
$VPS exec "sudo docker exec auditforge-engine-1 bun -e \"fetch('http://localhost:3030/internal/tools-status',{headers:{'x-internal-token':process.env.ENGINE_INTERNAL_TOKEN}}).then(r=>r.json()).then(d=>{console.log('mode',d.mode,'—',d.tools.length,'outils');for(const t of d.tools)if(['WPSCAN','DALFOX','WHATWEB','TESTSSL','WAFW00F','HYDRA','JOHN'].includes(t.tool))console.log(' ',t.tool.padEnd(8),t.realAvailable?'RÉEL':'indisponible:',(t.reason||'').slice(0,60))})\""

echo "── 7/7 — Vérification HTTPS publique ─────────────────────────────────"
$VPS exec "curl -s -o /dev/null -w '%{http_code}' https://auditforge.aenews.online/robots.txt" && echo " ← robots.txt"

echo "✅ Déploiement Sprint 1 terminé — lancer les E2E réels (cibles locales autorisées)."
