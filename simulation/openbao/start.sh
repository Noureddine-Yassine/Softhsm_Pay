#!/usr/bin/env bash
# Démarre OpenBao (dev) pour le coffre Switch PayHSM.
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker requis pour OpenBao."
  exit 1
fi

docker compose up -d

echo ""
echo "▶ OpenBao (dev) API : http://127.0.0.1:8200"
echo "  (L’image Docker officielle n’inclut PAS l’UI web — normal.)"
echo ""
echo "  Exportez avant le simulateur :"
echo "    export OPENBAO_ADDR=http://127.0.0.1:8200"
echo "    export OPENBAO_TOKEN=payhsm-dev-token"
echo ""
echo "  Puis : cd simulation/backend && npm start"
echo "  Coffre Switch → KV secret/payhsm/switch-coffre"
echo ""
echo "  UI web coffre (simulateur) :"
echo "    cd simulation/frontend && npm run dev"
echo "    → http://127.0.0.1:5173  onglet « OpenBao »"
echo ""
echo "  CLI :"
echo "    ./simulation/openbao/show-coffre.sh"
echo "    curl -s http://127.0.0.1:4000/api/openbao/status"
echo ""
