#!/usr/bin/env python3
"""Resume-monitor an existing AuditForge campaign; resilient to transient URLError."""
import json
import sys
import time
import urllib.error
import urllib.request
from af_secrets import admin_credentials

BASE, CID = sys.argv[1], sys.argv[2]
DEADLINE = int(sys.argv[3]) if len(sys.argv) > 3 else 5400
# F-02 : identifiants admin hors du dépôt (env ou vps-tools/.env.local — échec clair sinon)
USER, PASS = admin_credentials()
COOKIE = {"v": None}


def api(method, path, body=None, timeout=30):
    req = urllib.request.Request(
        BASE + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"content-type": "application/json", "user-agent": "AuditForgeE2E/2.1"},
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
    except Exception as e:  # URLError, ConnectionResetError, socket.timeout...
        return 0, {"_err": f"{type(e).__name__}: {e}"}


def main():
    print("waiting 480s for login rate-limit window to clear...", flush=True)
    time.sleep(480)
    for attempt in range(15):
        st, login = api("POST", "/api/auth/login", {"username": USER, "password": PASS})
        if st == 200:
            break
        if attempt % 5 == 0 or st == 200:
            print(f"login-retry {attempt}: {st} {json.dumps(login)[:200]}", flush=True)
        time.sleep(60)
    print(f"login: {st}", flush=True)
    if st != 200:
        sys.exit(1)
    print(f"resume-monitor: {CID}", flush=True)
    t0 = time.time(); last = ""; errstreak = 0
    while time.time() - t0 < DEADLINE:
        time.sleep(10)
        st, cur = api("GET", f"/api/campaigns/{CID}")
        if st != 200:
            errstreak += 1
            if errstreak <= 3 or errstreak % 12 == 0:
                e = cur.get("_err", "")
                print(f"[{int(time.time()-t0):>5}s] poll-error #{errstreak} status={st} {e}", flush=True)
            continue
        errstreak = 0
        c = cur["campaign"]
        row = " | ".join(f"{s['tool']}:{s['status']}:{s.get('findingsCount','?')}" for s in c["scans"])
        if row != last:
            print(f"[{int(time.time()-t0):>5}s] {c['status']} — {row}", flush=True)
            last = row
        if c["status"] in ("COMPLETED", "FAILED", "CANCELLED"):
            break
    st, fin = api("GET", f"/api/campaigns/{CID}")
    c = fin["campaign"]
    summary = {"campaign": CID, "status": c["status"], "scans": []}
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
    with open(f"/tmp/summary-{CID}.json", "w") as f:
        json.dump(summary, f, indent=1)
    print("SUMMARY-SAVED " + CID, flush=True)


if __name__ == "__main__":
    main()
