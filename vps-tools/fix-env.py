#!/usr/bin/env python3
"""Répare le .env : restitue les 4 variables avalées par le patch, depuis le backup."""
import re, subprocess

BAK = "/opt/auditforge/.env.bak-llm-20261029-213403"
CUR = "/opt/auditforge/.env"

bak = open(BAK).read()
cur = open(CUR).read()

lost = ["PHANTOM_IMAGE", "REAL_SCAN_TIMEOUT_MIN", "COOKIE_SECURE", "ZAP_API_KEY"]
add = []
for k in lost:
    m = re.search(rf"^{k}=(.*)$", bak, re.M)
    if not m:
        print(f"ERREUR: {k} introuvable dans le backup"); raise SystemExit(1)
    v = m.group(1).strip()
    if re.search(rf"^{k}=", cur, re.M):
        print(f"{k} : déjà présent — inchangé")
    else:
        add.append(f"{k}={v}")
        print(f"{k} : restauré")

cur = cur.rstrip("\n") + "\n\n# ── Variables restaurées (avalées par le patch LLM — valeur d'origine) ──\n" + "\n".join(add) + "\n"
open(CUR, "w").write(cur)
print(".env réparé")
