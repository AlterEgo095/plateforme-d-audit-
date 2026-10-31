#!/usr/bin/env python3
"""Upload de fichiers vers le VPS via SFTP.
Usage: python3 vps-put.py <local1> <remote1> [<local2> <remote2> ...]
"""
import os
import sys
import paramiko
from vps_secrets import load_vps_secrets

# F-02 : plus de mot de passe par défaut — env ou scripts/.secrets.local, échec clair sinon
HOST, USER, PASS = load_vps_secrets()


def main() -> int:
    args = sys.argv[1:]
    if not args or len(args) % 2 != 0:
        print("usage: vps-put.py <local> <remote> ...", file=sys.stderr)
        return 2
    t = paramiko.Transport((HOST, 22))
    t.connect(username=USER, password=PASS)
    sftp = paramiko.SFTPClient.from_transport(t)
    try:
        for local, remote in zip(args[::2], args[1::2]):
            sftp.put(local, remote)
            print(f"OK {local} -> {remote} ({os.path.getsize(local)} octets)")
    finally:
        sftp.close()
        t.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
