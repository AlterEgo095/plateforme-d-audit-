#!/usr/bin/env python3
"""Upload de fichiers vers le VPS via SFTP.
Usage: python3 vps-put.py <local1> <remote1> [<local2> <remote2> ...]
"""
import os
import sys
import paramiko

HOST = "95.111.226.63"
USER = "aenews"
PASS = os.environ.get("VPS_PASS", "REDACTED")


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
