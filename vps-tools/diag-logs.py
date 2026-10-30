#!/usr/bin/env python3
"""Fetch FULL logs for all scans of the latest campaigns (diag)."""
import json
import sys
import urllib.request

BASE = "https://auditforge.aenews.online"
COOKIE = {"v": None}


def api(method, path, body=None, timeout=30):
    req = urllib.request.Request(
        BASE + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"content-type": "application/json", "User-Agent": "AuditForgeE2E/1.0"},
    )
    if COOKIE["v"]:
        req.add_header("cookie", COOKIE["v"])
    with urllib.request.urlopen(req, timeout=timeout) as res:
        sc = res.headers.get("set-cookie")
        if sc and "af_session=" in sc:
            COOKIE["v"] = sc.split(";")[0]
        return res.status, json.loads(res.read().decode() or "{}")


st, _ = api("POST", "/api/auth/login",
            {"username": "admin", "password": "REDACTED-ROTATE-ME"})
print("login:", st)
cid = sys.argv[1]
st, cur = api("GET", f"/api/campaigns/{cid}")
c = cur["campaign"]
print("campaign", c["id"], c["status"], "target:", c.get("target"))
for s in c["scans"]:
    print(f"SCAN {s['id']} {s['tool']} {s['status']} findings={s.get('findingsCount')} dur={s.get('durationMs')}")
    st2, lg = api("GET", f"/api/scans/{s['id']}/logs")
    logs = lg.get("logs", lg) if isinstance(lg, dict) else lg
    if isinstance(logs, list):
        print(f"  total log lines: {len(logs)}")
        for l in logs:
            msg = l.get("message", "") if isinstance(l, dict) else str(l)
            lv = l.get("level", "?") if isinstance(l, dict) else "?"
            print(f"    [{lv}] {msg}")
    else:
        print("  RAW:", str(lg)[:2000])
