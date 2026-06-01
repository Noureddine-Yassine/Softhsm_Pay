#!/bin/sh
# Serve bank-flow-sim (port 8080) — nécessite payhsm-httpd sur 8765
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SIM="$ROOT/bank-flow-sim"
PORT="${1:-8080}"

if ! curl -sf "http://127.0.0.1:8765/api/health" >/dev/null 2>&1; then
  echo "Attention: payhsm-httpd ne répond pas sur :8765"
  echo "  Lancez d'abord: ./scripts/start-console.sh"
  echo ""
fi

echo "Simulation GAB/Switch: http://127.0.0.1:$PORT"
echo "  HSM API: http://127.0.0.1:8765"
cd "$SIM"
exec python3 -m http.server "$PORT" --bind 127.0.0.1
