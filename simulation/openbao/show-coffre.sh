#!/usr/bin/env bash
# Affiche le coffre Switch stocké dans OpenBao (lecture seule).
ADDR="${OPENBAO_ADDR:-http://127.0.0.1:8200}"
TOKEN="${OPENBAO_TOKEN:-payhsm-dev-token}"
PATH_KV="${OPENBAO_KV_PATH:-payhsm/switch-coffre}"

URL="${ADDR%/}/v1/secret/data/${PATH_KV}"

echo "GET $URL"
echo ""

if command -v curl >/dev/null 2>&1; then
  curl -s -H "X-Vault-Token: $TOKEN" "$URL" | python3 -m json.tool 2>/dev/null \
    || curl -s -H "X-Vault-Token: $TOKEN" "$URL"
  echo ""
  exit 0
fi

echo "curl requis."
exit 1
