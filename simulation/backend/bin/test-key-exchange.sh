#!/usr/bin/env bash
# Test échange de clés Switch (nécessite HSM démarré + Switch INIT)
set -e
BASE="${PAYHSM_SIM_URL:-http://127.0.0.1:4000}"
HSM="${PAYHSM_URL:-http://127.0.0.1:8765}"

echo "=== Health HSM ==="
curl -sf "$HSM/api/health" | head -c 200
echo ""

h=$(curl -sf "$HSM/api/health")
if echo "$h" | grep -q '"initialized":0'; then
  echo "HSM non démarré — Provision + Démarrer sur http://127.0.0.1:8765"
  exit 1
fi

echo "=== Switch INIT + provision-keys ==="
curl -sf -X POST "$BASE/api/switch/init" -H 'Content-Type: application/json' -d '{}'
echo ""
curl -sf -X POST "$BASE/api/switch/provision-keys" -H 'Content-Type: application/json' -d '{}' | python3 -m json.tool 2>/dev/null || true

echo "=== Vault ==="
curl -sf "$BASE/api/vault" | python3 -m json.tool 2>/dev/null | head -40
