#!/usr/bin/env python3
"""Runner SSH vers le VPS AuditForge (remplace .vps-audit/run.js perdu).

Usage: python3 vps-run.py '<commande>' [timeout_sec]
Auth: mot de passe fourni par l'utilisateur (var d'env VPS_PASS possible).
Sortie: stdout+stderr entrelacés; exit code = exit code distant.
"""
import sys
import os
import time
import threading
import paramiko
from vps_secrets import load_vps_secrets

# F-02 : plus de mot de passe par défaut — env ou scripts/.secrets.local, échec clair sinon
HOST, USER, PASS = load_vps_secrets()
PORT = 22


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: vps-run.py '<cmd>' [timeout_s]", file=sys.stderr)
        return 2
    cmd = sys.argv[1]
    timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 540

    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(
        HOST, port=PORT, username=USER, password=PASS,
        look_for_keys=False, allow_agent=False, timeout=25,
        banner_timeout=25, auth_timeout=25,
    )
    try:
        transport = cli.get_transport()
        transport.set_keepalive(30)
        chan = transport.open_session(timeout=25)
        chan.settimeout(timeout)
        chan.set_combine_stderr(True)
        chan.exec_command(cmd)

        def reader() -> None:
            try:
                while True:
                    data = chan.recv(65536)
                    if not data:
                        break
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
            except Exception:
                pass

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        rc = None
        deadline = time.time() + timeout
        while time.time() < deadline:
            if chan.exit_status_ready():
                rc = chan.recv_exit_status()
                break
            time.sleep(0.3)
        t.join(timeout=5)
        if rc is None:
            print(f"\n[vps-run] TIMEOUT {timeout}s atteint", file=sys.stderr)
            return 124
        return rc
    finally:
        cli.close()


if __name__ == "__main__":
    sys.exit(main())
