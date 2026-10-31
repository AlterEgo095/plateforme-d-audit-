#!/usr/bin/env python3
"""Identifiants VPS AuditForge — env d'abord, sinon scripts/.secrets.local.

F-01/F-02 : plus aucun identifiant en dur dans les fichiers trackés.
Précédence : variables d'environnement (VPS_HOST/VPS_USER/VPS_PASSWORD,
VPS_PASSWORD accepte l'alias historique VPS_PASS) puis fichier local non
tracké `scripts/.secrets.local` (clé=valeur, chmod 600).
Échec CLAIR si une valeur est absente — aucun repli par défaut.
"""
import os
import sys
from pathlib import Path
from typing import Dict, Tuple

_KEYS = ("VPS_HOST", "VPS_USER", "VPS_PASSWORD")


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


def load_vps_secrets() -> Tuple[str, str, str]:
    """Retourne (hôte, utilisateur, mot de passe) — sys.exit clair si absents."""
    env = {"VPS_HOST": os.environ.get("VPS_HOST", ""),
           "VPS_USER": os.environ.get("VPS_USER", ""),
           "VPS_PASSWORD": os.environ.get("VPS_PASSWORD") or os.environ.get("VPS_PASS") or ""}
    if not all(env.values()):
        local = Path(__file__).resolve().parent / ".secrets.local"
        file_vals = parse_env_file(local)
        for key in _KEYS:
            if not env[key]:
                env[key] = file_vals.get(key, "")
    if not all(env.values()):
        missing = ", ".join(k for k in _KEYS if not env[k])
        local = Path(__file__).resolve().parent / ".secrets.local"
        sys.exit(
            f"[secrets] variables manquantes : {missing}. Définissez-les dans "
            f"l'environnement (VPS_HOST/VPS_USER/VPS_PASSWORD) ou dans {local} "
            "(non tracké, chmod 600)."
        )
    return env["VPS_HOST"], env["VPS_USER"], env["VPS_PASSWORD"]
