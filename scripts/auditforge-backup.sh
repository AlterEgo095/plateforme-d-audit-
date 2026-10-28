#!/bin/bash
# AuditForge — sauvegarde de auditforge.db (WAL-aware)
# P0-1 audit plateforme v2 (Task 21). Rotation : KEEP sauvegardes (défaut 7).
# P1 : paramétrable par variables d'environnement — deux modes d'emploi :
#   1. Cron HÔTE (défauts) : DB dans le volume Docker, sauvegardes sous
#      /opt/auditforge/backups — ex. crontab :
#        30 3 * * * /opt/auditforge/scripts/auditforge-backup.sh >> /opt/auditforge/backups/backup.log 2>&1
#   2. Sidecar Compose (P1) : service `backup` de docker-compose.prod.yml —
#      DB_PATH=/data/auditforge.db BACKUP_DIR=/backups (déjà posés dans l'image).
set -uo pipefail

# ── Paramètres (surchargables par env — sidecar P1) ─────────────────────────
DB_PATH="${DB_PATH:-/var/lib/docker/volumes/auditforge_auditforge-data/_data/auditforge.db}"
BACKUP_DIR="${BACKUP_DIR:-/opt/auditforge/backups}"
KEEP="${KEEP:-7}"

DB="$DB_PATH"
TS=$(date +%Y%m%d-%H%M%S)
# Horodatage de journal : GNU et BusyBox (alpine — sidecar P1) acceptés.
now() { date -Iseconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z'; }

mkdir -p "$BACKUP_DIR"

if [ ! -f "$DB" ]; then
  echo "$(now) ERREUR: $DB introuvable"
  exit 1
fi

# 1. Checkpoint WAL (fusionne -wal dans le .db principal ; sûr en multi-process)
sqlite3 "$DB" "PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null 2>&1 || echo "$(now) WARN: checkpoint WAL échoué (poursuite)"

# 2. Copie froide
if ! cp "$DB" "$BACKUP_DIR/auditforge-$TS.db"; then
  echo "$(now) ERREUR: copie impossible"
  exit 1
fi
[ -f "$DB-wal" ] && cp "$DB-wal" "$BACKUP_DIR/auditforge-$TS.db-wal" 2>/dev/null
[ -f "$DB-shm" ] && cp "$DB-shm" "$BACKUP_DIR/auditforge-$TS.db-shm" 2>/dev/null

# 3. Contrôle d'intégrité
INTEG=$(sqlite3 "$BACKUP_DIR/auditforge-$TS.db" "PRAGMA integrity_check;" 2>/dev/null | head -1)
if [ "$INTEG" != "ok" ]; then
  echo "$(now) ERREUR: intégrité KO ($INTEG) — sauvegarde $TS conservée pour analyse"
  exit 1
fi

# 4. Rotation (garder les KEEP plus récents)
ls -1t "$BACKUP_DIR"/auditforge-*.db 2>/dev/null | tail -n +$((KEEP + 1)) | while read -r old; do
  rm -f "$old" "$old-wal" "$old-shm"
done

SIZE=$(du -h "$BACKUP_DIR/auditforge-$TS.db" | cut -f1)
echo "$(now) OK: auditforge-$TS.db ($SIZE, intégrité ok, rotation ${KEEP})"
