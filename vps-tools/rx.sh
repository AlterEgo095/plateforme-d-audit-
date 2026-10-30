#!/usr/bin/env bash
# Retry wrapper for vps.ts exec — retries up to 3x when output indicates HTTP 403.
cd "$(dirname "$0")" || exit 9
c="$1"; out=""; rc=1
for i in 1 2 3; do
  out=$(bun run vps.ts exec "$c" 2>&1)
  rc=$?
  if [ $rc -eq 0 ] || ! printf '%s' "$out" | rg -qi '403'; then
    printf '%s\n' "$out"; exit $rc
  fi
  echo "## 403 detected, retry $i/3"; sleep 4
done
printf '%s\n' "$out"; exit $rc
