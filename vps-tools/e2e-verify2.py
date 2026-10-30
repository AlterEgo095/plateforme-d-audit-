#!/usr/bin/env python3
"""AuditForge full-platform verification v2: targetType arg, background-safe, JSON summary."""
import json
import sys
import time
import urllib.error
import urllib.request

BASE, TARGET, TTYPE, TOOLS = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
DEADLINE = int(sys.argv[5]) if len(sys.argv) > 5 else 3600
USER, PASS = "admin", "REDACTED-ROTATE-ME"
COOKIE = {"v": None}


def api(method, path, body=None, timeout=30):
    req = urllib.request.Request(
        BASE + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"content-type": "application/json", "user-agent": "AuditForgeE2E/2.0"},
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
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except Exception:
            return e.code, {}


def main():
    st, login = api("POST", "/api/auth/login", {"username": USER, "password": PASS})
    print(f"login: {st}", flush=True)
    if st != 200:
        print(json.dumps(login)[:300], flush=True); sys.exit(1)
    st, out = api("POST", "/api/campaigns", {
        "name": f"audit-complet-{int(time.time())}-{TTYPE.lower()}",
        "description": "Validation integrale plateforme (auto, supprimable)",
        "target": TARGET, "targetType": TTYPE, "profile": "QUICK",
        "tools": [t.strip() for t in TOOLS.split(",")],
        "sequential": True, "launchNow": True,
    })
    print(f"create: {st}", flush=True)
    if st != 201:
        print(json.dumps(out)[:400], flush=True); sys.exit(1)
    cid = out["campaign"]["id"]
    print(f"campaign: {cid}", flush=True)
    t0 = time.time(); last = ""
    while time.time() - t0 < DEADLINE:
        time.sleep(10)
        st, cur = api("GET", f"/api/campaigns/{cid}")
        if st != 200:
            continue
        c = cur["campaign"]
        row = " | ".join(f"{s['tool']}:{s['status']}:{s.get('findingsCount','?')}" for s in c["scans"])
        if row != last:
            print(f"[{int(time.time()-t0):>5}s] {c['status']} — {row}", flush=True)
            last = row
        if c["status"] in ("COMPLETED", "FAILED", "CANCELLED"):
            break
    st, fin = api("GET", f"/api/campaigns/{cid}")
    c = fin["campaign"]
    summary = {"campaign": cid, "status": c["status"], "scans": []}
    for s in c["scans"]:
        entry = {"tool": s["tool"], "status": s["status"], "findings": s.get("findingsCount", 0),
                 "durationMs": s.get("durationMs"), "id": s["id"]}
        summary["scans"].append(entry)
        try:
            st2, lg = api("GET", f"/api/scans/{s['id']}/logs")
            if st2 == 200:
                logs = lg.get("logs", lg) if isinstance(lg, dict) else lg
                tail = logs[-10:] if isinstance(logs, list) else []
                entry["logtail"] = [
                    f"[{l.get('level','?') if isinstance(l,dict) else '?'}] {(l.get('message','') if isinstance(l,dict) else str(l))[:200]}"
                    for l in tail
                ]
        except Exception as e:
            entry["logtail"] = [f"logs-error: {e}"]
        print(f"  {s['tool']:<10} {s['status']:<10} findings={s.get('findingsCount','?')} dur={s.get('durationMs')}", flush=True)
    with open(f"/tmp/summary-{cid}.json", "w") as f:
        json.dump(summary, f, indent=1)
    print("SUMMARY-SAVED " + cid, flush=True)


if __name__ == "__main__":
    main()
