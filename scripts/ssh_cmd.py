#!/usr/bin/env python3
"""SSH command executor via paramiko (password auth)."""
import sys
import paramiko

HOST = "95.111.226.63"
USER = "aenews"
PASSWORD = "REDACTED"

def run(cmd: str, timeout: int = 60) -> int:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(HOST, port=22, username=USER, password=PASSWORD,
                       timeout=25, allow_agent=False, look_for_keys=False)
        stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        code = stdout.channel.recv_exit_status()
        if out:
            print(out)
        if err:
            print("[STDERR]", err, file=sys.stderr)
        return code
    finally:
        client.close()

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "echo SSH-OK && hostname"
    t = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    sys.exit(run(cmd, t))
