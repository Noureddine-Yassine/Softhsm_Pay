#!/usr/bin/env bash
# PayHSM — Arrêt de tous les composants
ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "Arrêt des composants PayHSM..."
pkill -f "payhsm-httpd"              2>/dev/null && echo "[✓] payhsm-httpd arrêté"      || echo "[!] payhsm-httpd non trouvé"
pkill -f "simulation/backend/server" 2>/dev/null && echo "[✓] sim-backend arrêté"       || echo "[!] sim-backend non trouvé"
pkill -f "vite"                      2>/dev/null && echo "[✓] sim-frontend arrêté"      || echo "[!] sim-frontend non trouvé"

if command -v docker >/dev/null 2>&1; then
  if docker ps -q --filter "name=payhsm-openbao" | grep -q .; then
    DC_CMD=""
    docker compose version >/dev/null 2>&1 && DC_CMD="docker compose"
    [ -z "$DC_CMD" ] && command -v docker-compose >/dev/null 2>&1 && DC_CMD="docker-compose"
    if [ -n "$DC_CMD" ]; then
      (cd "$ROOT/simulation/openbao" && $DC_CMD down 2>/dev/null) \
        && echo "[✓] OpenBao arrêté" || echo "[!] Erreur arrêt OpenBao"
    fi
  else
    echo "[!] OpenBao non trouvé"
  fi
fi

echo "Terminé."
