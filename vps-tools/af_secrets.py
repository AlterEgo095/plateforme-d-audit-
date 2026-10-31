#!/usr/bin/env python3
"""Identifiants admin AuditForge — env d'abord, sinon vps-tools/.env.local.

F-02 : plus aucun mot de passe en dur dans les scripts trackés (diag-*, e2e-*).
Précédence : variables d'environnement AF_ADMIN_USER / AF_ADMIN_PASSWORD puis
fichier local non tracké `vps-tools/.env.local` (clé=valeur, chmod 600).
Échec CLAIR si une valeur est absente — aucun repli par défaut.
"""
import os
import sys
from pathlib import Path
from typing import Dict, Tuple

_KEYS = ("AF_ADMIN_USER", "AF_ADMIN_PASSWORD")


def parse_env_file(path: Path) -> Dict[str, str]:
    """Parse minimaliste clé=valeur (lignes # ignorées, guillemets retirés)."""
    values: Dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            values[key.strip()] = val.strip().strip('"').strip("'")
    except OSError:
        pass  # fichier absent → seules les variables d'environnement comptent
    return values


def admin_credentials() -> Tuple[str, str]:
    """Retourne (utilisateur, mot de passe) admin — sys.exit clair si absents."""
    env = {k: os.environ.get(k, "") for k in _KEYS}
    if not all(env.values()):
        local = Path(__file__).resolve().parent / ".env.local"
        file_vals = parse_env_file(local)
        for key in _KEYS:
            if not env[key]:
                env[key] = file_vals.get(key, "")
    if not all(env.values()):
        missing = ", ".join(k for k in _KEYS if not env[k])
        local = Path(__file__).resolve().parent / ".env.local"
        sys.exit(
            f"[secrets] variables manquantes : {missing}. Définissez-les dans "
            f"l'environnement (AF_ADMIN_USER/AF_ADMIN_PASSWORD) ou dans {local} "
            "(non tracké, chmod 600)."
        )
    return env["AF_ADMIN_USER"], env["AF_ADMIN_PASSWORD"]
