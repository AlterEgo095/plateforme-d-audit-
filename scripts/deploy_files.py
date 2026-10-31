#!/usr/bin/env python3
"""Upload des fichiers AuditForge modifiés vers le VPS (SFTP + backup)."""
import sys
import time
import paramiko
from vps_secrets import load_vps_secrets

# F-01 : identifiants hors du dépôt (env ou scripts/.secrets.local — échec clair sinon)
HOST, USER, PASSWORD = load_vps_secrets()

# (local, distant)
FILES = [
    ("/home/z/my-project/mini-services/scan-engine/src/real-exec/deepaudit.ts",
     "/opt/auditforge/mini-services/scan-engine/src/real-exec/deepaudit.ts"),
    ("/home/z/my-project/src/components/audit/status-badges.tsx",
     "/opt/auditforge/src/components/audit/status-badges.tsx"),
]

def main() -> int:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(HOST, port=22, username=USER, password=PASSWORD,
                timeout=25, allow_agent=False, look_for_keys=False)
    sftp = ssh.open_sftp()
    stamp = time.strftime("%Y%m%d-%H%M%S")
    for local, remote in FILES:
        # backup distant
        try:
            ssh.exec_command(f"cp {remote} {remote}.bak-{stamp}")[1].channel.recv_exit_status()
        except Exception as e:
            print(f"[warn] backup {remote}: {e}")
        sftp.put(local, remote)
        print(f"[ok] {local.split('/my-project/')[1]} -> {remote}")
    sftp.close()
    # permissions
    ssh.exec_command("chmod -R a+r /opt/auditforge/src /opt/auditforge/mini-services 2>/dev/null; true")
    ssh.close()
    print("UPLOAD-DONE")
    return 0

if __name__ == "__main__":
    sys.exit(main())
