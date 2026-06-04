#!/bin/sh
# Démarre payhsm-httpd + console web sur http://127.0.0.1:8765
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PAYHSM="$ROOT/src/lib/payhsm"
FRONT="$ROOT/frontend"
PORT="${1:-8765}"

cd "$PAYHSM"
if [ -f Makefile ]; then
  echo "Compilation payhsm-httpd (make)..."
  make bin/payhsm-httpd
elif [ ! -x bin/payhsm-httpd ]; then
  echo "Compilation payhsm-httpd (script)..."
  "$ROOT/scripts/build-payhsm-httpd.sh"
fi

pkill -f "payhsm-httpd $PORT" 2>/dev/null || true
sleep 1

echo "PayHSM — http://127.0.0.1:$PORT"
echo "  Simulation GAB/Switch : ./scripts/start-bank-flow.sh  →  http://127.0.0.1:8080"
echo "  (ne pas ouvrir index.html en file:// — utiliser ces URLs)"
exec ./bin/payhsm-httpd "$PORT" "$FRONT"
