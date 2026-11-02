#!/usr/bin/env python3
"""Fusionne les secrets du tunnel dans /opt/auditforge/.env (idempotent).
- TUNNEL_TOKEN / LLM_TUNNEL_KEY / AF_TUNNEL_MODELS : upsert depuis /tmp/tunnel-secrets.env
- AF_UPSTREAMS : ajoute l'upstream « sandbox » s'il est absent.
N'affiche JAMAIS les valeurs de secrets."""
import re

ENV_PATH = "/opt/auditforge/.env"
SECRETS_PATH = "/tmp/tunnel-secrets.env"
UPSTREAM_NAME = "sandbox"
UPSTREAM_BASE = "http://llm-tunnel:3032/v1"
SECRET_KEYS = ("TUNNEL_TOKEN", "LLM_TUNNEL_KEY", "AF_TUNNEL_MODELS")

secrets = {}
with open(SECRETS_PATH) as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        secrets[k.strip()] = v.strip()

with open(ENV_PATH) as f:
    lines = f.read().splitlines()

seen = set()
out = []
upstream_added = False
for line in lines:
    m = re.match(r"^([A-Z_][A-Z0-9_]*)=(.*)$", line)
    if m:
        key, val = m.group(1), m.group(2)
        seen.add(key)
        if key == "AF_UPSTREAMS":
            if f"{UPSTREAM_NAME}|" not in val:
                val = val.rstrip(";") + f";{UPSTREAM_NAME}|{UPSTREAM_BASE}|" + secrets.get("LLM_TUNNEL_KEY", "") + "|primary"
                upstream_added = True
            out.append(f"{key}={val}")
            continue
        if key in SECRET_KEYS and key in secrets:
            out.append(f"{key}={secrets[key]}")
            continue
    out.append(line)

for k in SECRET_KEYS:
    if k in secrets and k not in seen:
        out.append(f"{k}={secrets[k]}")

with open(ENV_PATH, "w") as f:
    f.write("\n".join(out) + "\n")

print(f"MERGE_OK lignes={len(out)} upstream_ajoute={upstream_added} secrets_present={all(k in secrets for k in ('TUNNEL_TOKEN','LLM_TUNNEL_KEY'))}")
