#!/usr/bin/env bash
# Démarre backend + frontend de la simulation.
# Le HSM réel (payhsm-httpd) doit être lancé séparément.

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

free_port() {
  local port=$1
  if command -v fuser >/dev/null 2>&1; then
    fuser -k "${port}/tcp" 2>/dev/null || true
  elif command -v lsof >/dev/null 2>&1; then
    lsof -ti:"$port" | xargs -r kill -9 2>/dev/null || true
  fi
  sleep 0.5
}

echo "▶ PayHSM Simulation — démarrage"
echo "  HSM réel attendu sur http://127.0.0.1:8765"
echo

free_port 4000

cd "$SCRIPT_DIR/backend"
if [ ! -d node_modules ]; then
  echo "▶ Installation deps backend…"
  npm install --no-audit --no-fund
fi

echo "▶ Backend (nouvelles routes Core Banking / vault / EMV / MAC) sur :4000"
npm start &
BACK_PID=$!
echo $BACK_PID > /tmp/payhsm-sim-backend.pid

for i in 1 2 3 4 5 6 7 8 9 10; do
  if curl -sf http://127.0.0.1:4000/api/health | grep -qE '"apiVersion":(2|3)'; then
    echo "  ✓ Backend prêt"
    break
  fi
  sleep 0.5
done

if ! curl -sf http://127.0.0.1:4000/api/health | grep -qE '"apiVersion":(2|3)'; then
  echo "  ✗ Backend ne répond pas correctement — vérifiez les logs"
  exit 1
fi

cd "$SCRIPT_DIR/frontend"
if [ ! -d node_modules ]; then
  echo "▶ Installation deps frontend…"
  npm install --no-audit --no-fund
fi

echo "▶ Frontend sur http://127.0.0.1:5173"
exec npm run dev
