#!/usr/bin/env bash
# ── AuditForge — Sprint 2 « dossiers clients + autorisation + SARIF » : déploiement VPS ──
# Prérequis : vps-tools/.env.local (VPS_HOST/VPS_USER/VPS_PASS) — chmod 600.
# Moteur NON touché (aucun fichier mini-services modifié) — rebuild app uniquement.
# Usage : bash scripts/deploy-sprint2.sh
set -euo pipefail
cd "$(dirname "$0")/.."

VPS="cd vps-tools && bun run vps.ts"
R=/opt/auditforge

echo "── 1/5 — Garde-fou : aucun scan en cours ─────────────────────────────"
$VPS exec "sudo docker exec auditforge-app-1 bun -e 'const {PrismaClient}=require(\"@prisma/client\");const p=new PrismaClient();p.scan.findMany({where:{status:{in:[\"RUNNING\",\"QUEUED\"]}}}).then(s=>{console.log(\"ACTIFS:\"+s.length);process.exit(s.length?1:0)})'" || {
  echo "!! Des scans sont actifs — attendre/arrêter avant rebuild app."; exit 1; }

echo "── 2/5 — Envoi des fichiers app (Sprint 2) ───────────────────────────"
for f in \
  prisma/schema.prisma \
  src/lib/types.ts \
  src/lib/dto.ts \
  src/lib/case-auth.ts \
  "src/app/api/cases/route.ts" \
  "src/app/api/cases/[id]/route.ts" \
  "src/app/api/cases/[id]/authorizations/route.ts" \
  "src/app/api/cases/[id]/authorizations/[authId]/revoke/route.ts" \
  "src/app/api/cases/[id]/report/route.ts" \
  "src/app/api/reports/sarif/route.ts" \
  "src/app/api/campaigns/route.ts" \
  "src/app/api/campaigns/[id]/launch/route.ts" \
  src/app/page.tsx \
  src/components/audit/app-shell.tsx \
  src/components/audit/campaigns-view.tsx \
  src/components/audit/cases-view.tsx \
  src/components/audit/status-badges.tsx ; do
  echo "  put $f"
  $VPS put "$f" "$R/$f"
done

echo "── 3/5 — Rebuild image app (prisma generate + next build) ────────────"
$VPS exec "cd $R && sudo docker compose build app" &
BUILD_PID=$!
echo "  build lancé (pid $BUILD_PID) — polling…"
wait $BUILD_PID

echo "── 4/5 — Redémarrage app + migrations (db push additif) ──────────────"
$VPS exec "cd $R && sudo docker compose up -d app && sleep 10 && sudo docker compose ps app"
$VPS exec "sudo docker exec auditforge-app-1 bun -e 'const {PrismaClient}=require(\"@prisma/client\");const p=new PrismaClient();p.case.count().then(c=>{console.log(\"CASES:\",c);process.exit(0)}).catch(e=>{console.log(\"ERR:\",e.message.slice(0,120));process.exit(1)})' || (cd $R && sudo docker compose exec -T app bunx prisma db push --skip-generate)"

echo "── 5/5 — Vérification HTTPS publique ─────────────────────────────────"
$VPS exec "curl -s -o /dev/null -w '%{http_code}' https://auditforge.aenews.online/robots.txt" && echo " ← robots.txt"
$VPS exec "curl -s -o /dev/null -w '%{http_code}' -X POST https://auditforge.aenews.online/api/cases -H 'Content-Type: application/json' -d '{}'" && echo " ← POST /api/cases (401 attendu — route présente)"

echo "✅ Déploiement Sprint 2 terminé."
