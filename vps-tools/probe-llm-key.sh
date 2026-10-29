#!/usr/bin/env bash
# AuditForge — sonde clé LLM : teste la clé contre un panel d'endpoints
# OpenAI-compatibles (GET /models) pour identifier la base URL qui l'accepte.
KEY="${1:-}"
if [ -z "$KEY" ]; then echo "usage: probe-llm-key.sh <api-key>"; exit 1; fi
BODY="/tmp/pb.$$"
BASES=(
  "https://api.anyrouter.dev/v1"
  "https://api.openai.com/v1"
  "https://openrouter.ai/api/v1"
  "https://api.siliconflow.cn/v1"
  "https://api.siliconflow.com/v1"
  "https://api.nanogpt.com/v1"
  "https://api.chutes.ai/v1"
  "https://aihubmix.com/v1"
  "https://api.deepinfra.com/v1"
  "https://api.together.xyz/v1"
  "https://api.fireworks.ai/inference/v1"
  "https://api.groq.com/openai/v1"
  "https://api.cerebras.ai/v1"
  "https://api.moonshot.cn/v1"
  "https://api.modelscope.cn/v1"
  "https://dashscope.aliyuncs.com/compatible-mode/v1"
  "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
  "https://api.deepseek.com/v1"
  "https://api.mistral.ai/v1"
  "https://api.x.ai/v1"
  "https://api.ppinfra.com/v1"
  "https://api.wisdomgate.cn/v1"
  "https://api.ws-gpt.com/v1"
  "https://api.wsgpt.cn/v1"
  "https://api.chatanywhere.tech/v1"
  "https://api.chatanywhere.org/v1"
  "https://api.openai-hk.com/v1"
  "https://api.gptsapi.net/v1"
  "https://api.aiproxy.io/v1"
  "https://api.requesty.ai/v1"
  "https://api.apipie.ai/v1"
  "https://api.proxyapi.ai/v1"
  "https://api.wavespeed.ai/v1"
  "https://ws-h.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1"
  "https://api.wsara.ai/v1"
  "https://api.wushengai.com/v1"
)
HITS=0
for b in "${BASES[@]}"; do
  code=$(curl -s -o "$BODY" -w '%{http_code}' -m 12 -H "Authorization: Bearer $KEY" "$b/models" 2>/dev/null)
  if [ "$code" = "200" ]; then
    info=$(python3 - "$BODY" <<'PYEOF'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    data = d.get("data") if isinstance(d, dict) else None
    ids = [m.get("id") for m in data if isinstance(m, dict) and m.get("id")] if isinstance(data, list) else []
    print(f"{len(ids)}|" + ",".join(ids[:12]))
except Exception as e:
    print(f"parse_err|{e}")
PYEOF
)
    n="${info%%|*}"; ex="${info#*|}"
    echo "HIT  $b -> 200, $n modeles  [${ex:0:160}]"
    HITS=$((HITS+1))
  else
    snippet=$(head -c 100 "$BODY" 2>/dev/null | tr '\n' ' ')
    echo "miss $b -> HTTP $code ${snippet:0:80}"
  fi
done
rm -f "$BODY"
echo "== done, $HITS endpoint(s) acceptent la clé =="
