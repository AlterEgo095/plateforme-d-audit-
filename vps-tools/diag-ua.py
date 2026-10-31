#!/usr/bin/env python3
"""Try several User-Agents against login to find one Cloudflare accepts."""
import json
import urllib.error
import urllib.request
from af_secrets import admin_credentials

# F-02 : identifiants admin hors du dépôt (env ou vps-tools/.env.local — échec clair sinon)
USER, PASSWORD = admin_credentials()
BODIES = json.dumps({"username": USER, "password": PASSWORD}).encode()
UAS = [
    None,  # default Python-urllib
    "curl/8.5.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "AuditForgeE2E/1.0",
]

for ua in UAS:
    headers = {"content-type": "application/json"}
    label = "DEFAULT"
    if ua:
        headers["User-Agent"] = ua
        label = ua
    req = urllib.request.Request(
        "https://auditforge.aenews.online/api/auth/login",
        method="POST", data=BODIES, headers=headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            print(f"[{label[:60]}] -> {r.status} {r.read()[:80]}")
    except urllib.error.HTTPError as e:
        print(f"[{label[:60]}] -> HTTP {e.code} body={e.read()[:60]}")
    except Exception as e:
        print(f"[{label[:60]}] -> ERR {e}")
