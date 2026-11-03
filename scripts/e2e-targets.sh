#!/usr/bin/env bash
# ── AuditForge — Sprint 1 : préparation des cibles E2E locales (sur le VPS) ──
# Toutes les cibles sont LOCALES au VPS ou lui appartiennent (autorisées) :
#   1. WordPress de test (containers wordpress+mariadb, réseau dédié, :8091)
#   2. Réflecteur XSS volontaire (python3 stdlib, :8092)
#   3. Dépôt git avec hashes faibles (servi en HTTP dumb, :8093)
# Usage : bash scripts/e2e-targets.sh   (à exécuter via vps.ts exec ou ssh)
set -euo pipefail

echo "── 1. WordPress de test (wpscan) ─────────────────────────────────────"
sudo docker network create wp-test 2>/dev/null || true
sudo docker rm -f af-wpdb af-wp 2>/dev/null || true
sudo docker run -d --name af-wpdb --network wp-test \
  -e MARIADB_ROOT_PASSWORD=rootpw -e MARIADB_DATABASE=wordpress \
  -e MARIADB_USER=wp -e MARIADB_PASSWORD=wppw mariadb:10.11
sudo docker run -d --name af-wp --network wp-test -p 8091:80 \
  -e WORDPRESS_DB_HOST=af-wpdb -e WORDPRESS_DB_USER=wp \
  -e WORDPRESS_DB_PASSWORD=wppw -e WORDPRESS_DB_NAME=wordpress \
  wordpress:php8.2-apache
echo "  → wp http://172.17.0.1:8091 (attendre ~30 s d'install)"

echo "── 2. Réflecteur XSS (dalfox) ────────────────────────────────────────"
sudo docker rm -f af-reflect 2>/dev/null || true
sudo docker run -d --name af-reflect -p 8092:8092 python:3.12-slim \
  python3 -c '
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
        body = f"<html><body><h1>VulnApp</h1><p>Result for: {q}</p></body></html>".encode()
        self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self,*a): pass
HTTPServer(("0.0.0.0", 8092), H).serve_forever()'
echo "  → réflecteur http://172.17.0.1:8092/?q=… (réfléchit q sans encodage)"

echo "── 3. Dépôt git avec hashes faibles (john) ───────────────────────────"
rm -rf /tmp/john-test && mkdir -p /tmp/john-test/deploy && cd /tmp/john-test
git init -q && git config user.email t@t.local && git config user.name t
APR1=$(openssl passwd -apr1 abc123)
SHA6=$(openssl passwd -6 password123)
printf "admin:%s\nsvc-backup:%s\n" "$APR1" "$SHA6" > deploy/htpasswd
git add . && git commit -qm "fixtures htpasswd" && git update-server-info
cd / && sudo mv /tmp/john-test /srv/john-test.git
(sudo pkill -f "http.server 8093" 2>/dev/null || true)
(cd /srv && sudo nohup python3 -m http.server 8093 > /tmp/john-http.log 2>&1 &)
sleep 1
curl -s -o /dev/null -w "  clone HTTP dumb: %{http_code}\n" http://172.17.0.1:8093/john-test.git/info/refs
echo "  → dépôt http://172.17.0.1:8093/john-test.git (apr1 abc123 + sha512 password123)"

echo "── 4. Cibles autorisées AuditForge ───────────────────────────────────"
echo "  whatweb/wafw00f/testssl → https://auditforge.aenews.online (notre site)"
echo "  hydra → 172.17.0.1 (ssh du VPS, liste fixe 14 paires, plafonné)"

echo "✅ Cibles prêtes."
