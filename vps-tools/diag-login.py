#!/usr/bin/env python3
"""Diagnose raw urllib response for login (status code, headers, body)."""
import urllib.error
import urllib.request

req = urllib.request.Request(
    "https://auditforge.aenews.online/api/auth/login",
    method="POST",
    data=b'{"username":"admin","password":"REDACTED-ROTATE-ME"}',
    headers={"content-type": "application/json"},
)
try:
    with urllib.request.urlopen(req, timeout=30) as r:
        print("OK", r.status)
        print(r.read()[:300])
except urllib.error.HTTPError as e:
    print("HTTP", e.code)
    print(dict(e.headers))
    body = e.read()
    print("BODY:", body[:600])
