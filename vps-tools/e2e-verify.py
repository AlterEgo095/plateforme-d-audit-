#!/usr/bin/env python3
"""AuditForge E2E post-fix verification (dead-target honesty + real nikto/zap)."""
import json
import sys
import time
import urllib.error
import urllib.request

BASE, TARGET, TOOLS = sys.argv[1], sys.argv[2], sys.argv[3]
DEADLINE = int(sys.argv[4]) if len(sys.argv) > 4 else 300
USER, PASS = "admin", "REDACTED-ROTATE-ME"
COOKIE = {"v": None}


def api(method, path, body=None, timeout=30):
    req = urllib.request.Request(
        BASE + path,
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"content-type": "application/json"},
    )
    if COOKIE["v"]:
        req.add_header("cookie", COOKIE["v"])
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            sc = res.headers.get("set-cookie")
            if sc and "af_session=" in sc:
                COOKIE["v"] = sc.split(";")[0]
            return res.status, json.loads(res.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


def main():
    st, login = api("POST", "/api/auth/login", {"username": USER, "password": PASS})
    print(f"login: {st}")
    if st != 200:
        print(json.dumps(login)[:300]); sys.exit(1)
    st, out = api("POST", "/api/campaigns", {
        "name": f"e2e-verify-{int(time.time())}",
        "description": "Post-fix verification (auto, deletable)",
        "target": TARGET, "targetType": "URL", "profile": "QUICK",
        "tools": [t.strip() for t in TOOLS.split(",")],
        "sequential": True, "launchNow": True,
    })
    print(f"create: {st}")
    if st != 201:
        print(json.dumps(out)[:400]); sys.exit(1)
    cid = out["campaign"]["id"]
    print(f"campaign: {cid}")
    t0 = time.time(); last = ""
    while time.time() - t0 < DEADLINE:
        time.sleep(5)
        st, cur = api("GET", f"/api/campaigns/{cid}")
        if st != 200:
            print(f"poll {st}"); continue
        c = cur["campaign"]
        row = " | ".join(f"{s['tool']}:{s['status']}:{s.get('findingsCount','?')}" for s in c["scans"])
        if row != last:
            print(f"[{int(time.time()-t0):>4}s] {c['status']} — {row}"); last = row
        if c["status"] in ("COMPLETED", "FAILED", "CANCELLED"):
            break
    st, fin = api("GET", f"/api/campaigns/{cid}")
    c = fin["campaign"]
    print("FINAL:", c["status"])
    for s in c["scans"]:
        print(f"  {s['tool']:<10} {s['status']:<10} findings={s.get('findingsCount','?')}")
        try:
            st2, lg = api("GET", f"/api/scans/{s['id']}/logs")
            if st2 == 200:
                logs = lg.get("logs", lg) if isinstance(lg, dict) else lg
                tail = logs[-8:] if isinstance(logs, list) else []
                print(f"  --- logs {s['tool']} ---")
                for l in tail:
                    msg = l.get("message", "") if isinstance(l, dict) else str(l)
                    lv = l.get("level", "?") if isinstance(l, dict) else "?"
                    print(f"    [{lv}] {msg[:230]}")
        except Exception as e:
            print(f"  logs {s['tool']}: {e}")


if __name__ == "__main__":
    main()
