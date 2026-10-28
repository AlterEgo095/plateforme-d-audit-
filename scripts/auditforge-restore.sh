#!/bin/bash
# AuditForge — restauration d'une sauvegarde (P1 — miroir de auditforge-backup.sh)
#
# Usage :
#   sudo ./auditforge-restore.sh /opt/auditforge/backups/auditforge-YYYYMMDD-HHMMSS.db [options]
#
# Options :
#   --auto          arrête les conteneurs app/engine/backup (compose -p auditforge),
#                   restaure, puis les relance — sinon, refuse si des conteneurs
#                   écrivent la base (SQLite = écriture concurrente interdite).
#   --force         restaure SANS toucher aux conteneurs (à n'utiliser que si la
#                   pile est déjà arrêtée — vérification désactivée).
#   --dry-run       affiche le plan d'exécution sans rien modifier.
#
# Chemins (surchargables par env, mêmes défauts que auditforge-backup.sh) :
#   DB_PATH (défaut : volume Docker du VPS)   — destination de la restauration
#   Compose projet : AUDITFORGE_PROJECT (défaut : auditforge)
#
# Garde-fous : intégrité de la sauvegarde vérifiée AVANT toute modification ;
# l'état courant est déplacé (jamais écrasé) vers auditforge.db.pre-restore-<TS>.
set -uo pipefail

DB_PATH="${DB_PATH:-/var/lib/docker/volumes/auditforge_auditforge-data/_data/auditforge.db}"
PROJECT="${AUDITFORGE_PROJECT:-auditforge}"
TS=$(date +%Y%m%d-%H%M%S)
now() { date -Iseconds 2>/dev/null || date '+%Y-%m-%d %H:%M:%S'; }

BACKUP_FILE=""
DRY_RUN=0
AUTO=0
FORCE=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --auto) AUTO=1 ;;
    --force) FORCE=1 ;;
    -h|--help)
      sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      if [ -z "$BACKUP_FILE" ]; then BACKUP_FILE="$arg"; else
        echo "$(now) ERREUR: argument inattendu : $arg"; exit 2
      fi
      ;;
  esac
done

if [ -z "$BACKUP_FILE" ]; then
  echo "$(now) ERREUR: fichier de sauvegarde requis — usage : $0 <auditforge-YYYYMMDD-HHMMSS.db> [--auto|--force] [--dry-run]"
  exit 2
fi
if [ ! -f "$BACKUP_FILE" ]; then
  echo "$(now) ERREUR: sauvegarde introuvable : $BACKUP_FILE"
  exit 1
fi

echo "$(now) Restauration de $BACKUP_FILE vers $DB_PATH (projet compose : $PROJECT)"

# ── 0. Dépendances ───────────────────────────────────────────────────────────
if ! command -v sqlite3 >/dev/null 2>&1; then
  echo "$(now) ERREUR: sqlite3 introuvable (apt install sqlite3 / apk add sqlite)"
  exit 1
fi

# ── 1. Intégrité de la SAUVEGARDE (sur copie temporaire — trio .db/-wal/-shm) ─
TMPDIR_RESTORE=$(mktemp -d /tmp/auditforge-restore-XXXXXX)
cp "$BACKUP_FILE" "$TMPDIR_RESTORE/restore.db"
for ext in wal shm; do
  [ -f "$BACKUP_FILE-$ext" ] && cp "$BACKUP_FILE-$ext" "$TMPDIR_RESTORE/restore.db-$ext"
done
INTEG_SRC=$(sqlite3 "$TMPDIR_RESTORE/restore.db" "PRAGMA integrity_check;" 2>/dev/null | head -1)
if [ "$INTEG_SRC" != "ok" ]; then
  echo "$(now) ERREUR: intégrité KO sur la sauvegarde ($INTEG_SRC) — abandon (rien modifié)"
  rm -rf "$TMPDIR_RESTORE"
  exit 1
fi
echo "$(now) Intégrité de la sauvegarde : ok"

# ── 2. Conteneurs actifs ? ───────────────────────────────────────────────────
COMPOSE=""
RUNNING=""
if command -v docker >/dev/null 2>&1; then
  RUNNING=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -E "^${PROJECT}-(app|engine|backup)" | sort || true)
  if [ -n "$RUNNING" ] && [ "$FORCE" -eq 0 ] && [ "$AUTO" -eq 0 ]; then
    echo "$(now) ERREUR: conteneurs actifs détectés — SQLite ne tolère pas une restauration concurrente :"
    echo "$RUNNING" | sed 's/^/    - /'
    echo "    Relancez avec --auto (arrêt/restauration/relance) ou --force (pile déjà arrêtée)."
    rm -rf "$TMPDIR_RESTORE"
    exit 1
  fi
  COMPOSE="docker compose -p $PROJECT"
fi

stop_stack() {
  [ -n "$COMPOSE" ] || return 0
  echo "$(now) Arrêt des services (app, engine, backup)…"
  $COMPOSE stop app engine backup || echo "$(now) WARN: arrêt compose incomplet (poursuite)"
}
start_stack() {
  [ -n "$COMPOSE" ] || return 0
  echo "$(now) Relance des services…"
  $COMPOSE start app engine backup || echo "$(now) WARN: relance compose incomplète — vérifiez : $COMPOSE ps"
}

if [ "$DRY_RUN" -eq 1 ]; then
  echo "$(now) DRY-RUN — plan :"
  [ "$AUTO" -eq 1 ] && echo "    1. $COMPOSE stop app engine backup"
  echo "    2. mv $DB_PATH → $DB_PATH.pre-restore-$TS (+ -wal/-shm si présents)"
  echo "    3. cp $BACKUP_FILE → $DB_PATH (+ -wal/-shm si présents)"
  echo "    4. sqlite3 $DB_PATH 'PRAGMA integrity_check;'"
  [ "$AUTO" -eq 1 ] && echo "    5. $COMPOSE start app engine backup"
  rm -rf "$TMPDIR_RESTORE"
  exit 0
fi

# ── 3. Arrêt éventuel de la pile ─────────────────────────────────────────────
[ "$AUTO" -eq 1 ] && stop_stack

# ── 4. Déplacement de l'état courant (jamais détruit) ────────────────────────
if [ -f "$DB_PATH" ]; then
  if ! mv "$DB_PATH" "$DB_PATH.pre-restore-$TS"; then
    echo "$(now) ERREUR: déplacement impossible (permissions ?) — abandon"
    rm -rf "$TMPDIR_RESTORE"
    [ "$AUTO" -eq 1 ] && start_stack
    exit 1
  fi
  for ext in wal shm; do
    [ -f "$DB_PATH-$ext" ] && mv "$DB_PATH-$ext" "$DB_PATH.pre-restore-$TS-$ext"
  done
  echo "$(now) État courant conservé : $DB_PATH.pre-restore-$TS"
fi

# ── 5. Installation de la sauvegarde ─────────────────────────────────────────
if ! cp "$TMPDIR_RESTORE/restore.db" "$DB_PATH"; then
  echo "$(now) ERREUR: copie impossible — restauration de l'état précédent"
  mv "$DB_PATH.pre-restore-$TS" "$DB_PATH" 2>/dev/null
  rm -rf "$TMPDIR_RESTORE"
  [ "$AUTO" -eq 1 ] && start_stack
  exit 1
fi
for ext in wal shm; do
  [ -f "$TMPDIR_RESTORE/restore.db-$ext" ] && cp "$TMPDIR_RESTORE/restore.db-$ext" "$DB_PATH-$ext"
done
rm -rf "$TMPDIR_RESTORE"

# ── 6. Contrôle final sur place ──────────────────────────────────────────────
INTEG_DST=$(sqlite3 "$DB_PATH" "PRAGMA integrity_check;" 2>/dev/null | head -1)
if [ "$INTEG_DST" != "ok" ]; then
  echo "$(now) ERREUR: intégrité KO après installation ($INTEG_DST) — rollback :"
  mv "$DB_PATH" "$DB_PATH.bad-restore-$TS"
  mv "$DB_PATH.pre-restore-$TS" "$DB_PATH"
  for ext in wal shm; do
    [ -f "$DB_PATH.pre-restore-$TS-$ext" ] && mv "$DB_PATH.pre-restore-$TS-$ext" "$DB_PATH-$ext"
  done
  echo "$(now)    état précédent restauré ; fichier fautif : $DB_PATH.bad-restore-$TS"
  [ "$AUTO" -eq 1 ] && start_stack
  exit 1
fi

echo "$(now) OK: restauration terminée (integrity_check: ok)"
[ "$AUTO" -eq 1 ] && start_stack
echo "$(now) Rappel : la pile relancée repart sur les données restaurées — vérifiez la connexion et les campagnes."
