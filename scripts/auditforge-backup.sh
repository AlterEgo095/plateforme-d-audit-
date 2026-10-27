#!/bin/bash
# AuditForge — sauvegarde quotidienne de auditforge.db (WAL-aware)
# P0-1 audit plateforme v2 (Task 21). Rotation : 7 jours.
set -uo pipefail

DATA_DIR="/var/lib/docker/volumes/auditforge_auditforge-data/_data"
DB="$DATA_DIR/auditforge.db"
BACKUP_DIR="/opt/auditforge/backups"
KEEP=7
TS=$(date +%Y%m%d-%H%M%S)
LOG_TAG=""

mkdir -p "$BACKUP_DIR"

if [ ! -f "$DB" ]; then
  echo "$(date -Is) ERREUR: $DB introuvable"
  exit 1
fi

# 1. Checkpoint WAL (fusionne -wal dans le .db principal ; sûr en multi-process)
sqlite3 "$DB" "PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null 2>&1 || echo "$(date -Is) WARN: checkpoint WAL échoué (poursuite)"

# 2. Copie froide
if ! cp "$DB" "$BACKUP_DIR/auditforge-$TS.db"; then
  echo "$(date -Is) ERREUR: copie impossible"
  exit 1
fi
[ -f "$DB-wal" ] && cp "$DB-wal" "$BACKUP_DIR/auditforge-$TS.db-wal" 2>/dev/null
[ -f "$DB-shm" ] && cp "$DB-shm" "$BACKUP_DIR/auditforge-$TS.db-shm" 2>/dev/null

# 3. Contrôle d'intégrité
INTEG=$(sqlite3 "$BACKUP_DIR/auditforge-$TS.db" "PRAGMA integrity_check;" 2>/dev/null | head -1)
if [ "$INTEG" != "ok" ]; then
  echo "$(date -Is) ERREUR: intégrité KO ($INTEG) — sauvegarde $TS conservée pour analyse"
  exit 1
fi

# 4. Rotation (garder les KEEP plus récents)
ls -1t "$BACKUP_DIR"/auditforge-*.db 2>/dev/null | tail -n +$((KEEP + 1)) | while read -r old; do
  rm -f "$old" "$old-wal" "$old-shm"
done

SIZE=$(du -h "$BACKUP_DIR/auditforge-$TS.db" | cut -f1)
echo "$(date -Is) OK: auditforge-$TS.db ($SIZE, intégrité ok, rotation ${KEEP}j)"
