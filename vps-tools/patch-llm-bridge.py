#!/usr/bin/env python3
"""AuditForge — patch VPS : .env (config LLM bridge v2) + docker-compose.yml (service llm-bridge).
Exécuter avec sudo depuis /opt/auditforge. Sauvegardes .bak-llm avant modifications.
"""
import os, re, sys, subprocess, datetime
from pathlib import Path

ROOT = "/opt/auditforge"
STAMP = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")


def _env_local(path):
    """Parse minimaliste clé=valeur d'un .env.local non tracké."""
    values = {}
    try:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            values[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return values


# F-03 : clés LLM hors du dépôt — env (LLM_API_KEY / LLM_FALLBACK_KEY / AF_UPSTREAMS)
# puis vps-tools/.env.local (non tracké). Échec CLAIR si la clé primaire absente.
_ENV_LOCAL = _env_local(Path(__file__).resolve().parent / ".env.local")
NEW_KEY = os.environ.get("LLM_API_KEY") or _ENV_LOCAL.get("LLM_API_KEY", "")
FALLBACK_KEY = os.environ.get("LLM_FALLBACK_KEY") or _ENV_LOCAL.get("LLM_FALLBACK_KEY", "")
UPSTREAMS = (os.environ.get("AF_UPSTREAMS")
             or _ENV_LOCAL.get("AF_UPSTREAMS")
             or (f"maas|https://dashscope-intl.aliyuncs.com/compatible-mode/v1|{NEW_KEY}|primary"
                 + (f";router|https://api.anyrouter.dev/v1|{FALLBACK_KEY}|fallback" if FALLBACK_KEY else "")))
if not NEW_KEY or not UPSTREAMS:
    sys.exit("[secrets] LLM_API_KEY (et AF_UPSTREAMS si souhaité) manquant(s) — "
             "définissez-les dans l'environnement ou dans vps-tools/.env.local (non tracké, chmod 600)")

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()

# ── 1. Clé d'accès du pont (générée une fois, conservée si déjà présente) ────
env_path = os.path.join(ROOT, ".env")
env_raw = open(env_path).read()
m = re.search(r"^LLM_BRIDGE_KEY=(\S+)", env_raw, re.M)
bridge_key = m.group(1) if m else sh("openssl rand -hex 32")
print(f"bridge_key: {'existante' if m else 'générée'} ({bridge_key[:8]}…)")

# ── 2. Patch .env ─────────────────────────────────────────────────────────────
sh(f"cp {env_path} {env_path}.bak-llm-{STAMP}")

lines = env_raw.splitlines()
out, skip_until_blank = [], False
for i, ln in enumerate(lines):
    if ln.startswith("# ── Fournisseur LLM"):
        # remplacer tout le bloc de commentaire par le nouveau
        out.append("# ── Fournisseur LLM : pont v2 rotation round-robin (dashscope-intl + fallback) ──")
        skip_until_blank = True
        continue
    if skip_until_blank:
        if ln.strip() == "":
            skip_until_blank = False
            out.append(ln)
        continue
    out.append(ln)
env_raw = "\n".join(out) + "\n"

def set_var(env: str, key: str, value: str, comment: str | None = None) -> str:
    pat = re.compile(rf"^{key}=.*$", re.M)
    if pat.search(env):
        env = pat.sub(f"{key}={value}", env, count=1)
    else:
        env += ("" if env.endswith("\n") else "\n") + (f"{comment}\n" if comment else "") + f"{key}={value}\n"
    return env

env_raw = set_var(env_raw, "LLM_BRIDGE_KEY", bridge_key, "# Clé d'accès au pont (moteur → bridge)")
env_raw = set_var(env_raw, "LLM_API_KEY", bridge_key, "# Le moteur parle au pont avec la clé du pont")
env_raw = set_var(env_raw, "LLM_API_BASE", "http://172.17.0.1:3031/v1", "# Endpoint = pont local (docker0 — joignable moteur + sandboxes, jamais Internet)")
env_raw = set_var(env_raw, "PHANTOM_LLM", "openai/auditforge-auto", "# Alias de rotation → round-robin sur tout le pool")
env_raw = set_var(env_raw, "PHANTOM_COMPRESSOR_LLM", "openai/auditforge-auto", "# Compresseur mémoire phantom → rotation")
env_raw = set_var(env_raw, "BASALT_MODEL", "auditforge-auto", "# Basalt → rotation")
env_raw = set_var(env_raw, "AF_UPSTREAMS", UPSTREAMS,
                  "# Upstreams : DashScope intl (Alibaba — ~55 modèles chat) en rotation principale ; ancien routeur en secours")
env_raw = set_var(env_raw, "AF_STATIC_MODELS", "qwen3.8-flash,qwen3.7-flash,qwen3.5-flash,qwen-plus,qwen-max,qwen3-coder-flash,deepseek-v4.1-flash-1017",
                  "# Pool instantané au boot (confirmés par la découverte ensuite)")

open(env_path, "w").write(env_raw)
print(".env patché")

# ── 3. Patch docker-compose.yml : bloc commenté → service actif ──────────────
compose_path = os.path.join(ROOT, "docker-compose.yml")
compose = open(compose_path).read()
sh(f"cp {compose_path} {compose_path}.bak-llm-{STAMP}")

OLD = """  # llm-bridge:
  #   build:
  #     context: .
  #     dockerfile: Dockerfile.bridge
  #   environment:
  #     LLM_BRIDGE_KEY: ${LLM_BRIDGE_KEY:-}
  #     BIND_HOST: 0.0.0.0
  #   restart: unless-stopped"""

NEW = """  llm-bridge:
    build:
      context: .
      dockerfile: Dockerfile.bridge
    image: auditforge-llm-bridge:v2
    environment:
      LLM_BRIDGE_KEY: ${LLM_BRIDGE_KEY:-}
      BIND_HOST: 0.0.0.0 # le port n'est publié que sur 172.17.0.1 (docker0) côté hôte
      AF_UPSTREAMS: ${AF_UPSTREAMS:-}
      AF_STATIC_MODELS: ${AF_STATIC_MODELS:-}
    ports:
      - "172.17.0.1:3031:3031" # docker0 uniquement : moteur + sandboxes, jamais Internet
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    cap_drop: [ALL]
    read_only: false
    mem_limit: 256m
    healthcheck:
      test: ["CMD", "bun", "-e", "const r = await fetch('http://127.0.0.1:3031/health'); process.exit(r.ok ? 0 : 1)"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 30s"""

if OLD in compose:
    compose = compose.replace(OLD, NEW)
    open(compose_path, "w").write(compose)
    print("docker-compose.yml : bloc llm-bridge activé")
else:
    if re.search(r"^  llm-bridge:", compose, re.M):
        print("docker-compose.yml : service llm-bridge déjà actif — inchangé")
    else:
        print("ERREUR: bloc commenté introuvable et service absent — à patcher manuellement")
        sys.exit(1)

# ── 4. Validation compose ────────────────────────────────────────────────────
r = subprocess.run(f"cd {ROOT} && sudo docker compose config --quiet && echo COMPOSE_VALID",
                   shell=True, capture_output=True, text=True)
print(r.stdout.strip() or r.stderr.strip()[:400])
