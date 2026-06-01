#!/usr/bin/env bash
# ============================================================
# PayHSM — Démarrage complet (une seule commande)
#
# Lance dans l'ordre :
#   1. OpenBao      (port 8200) — coffre Switch via Docker
#   2. payhsm-httpd (port 8765) — backend HSM C + console
#   3. sim/backend  (port 4000) — simulateur bancaire Node.js
#   4. sim/frontend (port 5173) — interface React/Vite
#
# Usage : ./start.sh
# Arrêt  : Ctrl+C (ou ./stop.sh)
# ============================================================

ROOT="$(cd "$(dirname "$0")" && pwd)"
HSM_DIR="$ROOT/src/lib/payhsm"
SIM_BACK="$ROOT/simulation/backend"
SIM_FRONT="$ROOT/simulation/frontend"
FRONTEND_DIR="$ROOT/frontend"
OPENBAO_DIR="$ROOT/simulation/openbao"
BINARY="$HSM_DIR/bin/payhsm-httpd"
LOG_DIR="$ROOT/logs"

HSM_PORT=8765
SIM_BACK_PORT=4000
SIM_FRONT_PORT=5173
OPENBAO_PORT=8200
OPENBAO_TOKEN="payhsm-dev-token"

# Couleurs
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

log()  { echo -e "${GREEN}[✓]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
err()  { echo -e "${RED}[✗]${RESET} $*"; }
info() { echo -e "${CYAN}[→]${RESET} $*"; }

banner() {
  echo ""
  echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════╗${RESET}"
  echo -e "${BOLD}${CYAN}║         PayHSM — Démarrage complet           ║${RESET}"
  echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════╝${RESET}"
  echo ""
}

# ── Détection docker compose vs docker-compose ────────────
docker_compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose "$@"
  else
    echo "Ni 'docker compose' ni 'docker-compose' disponible." >&2
    return 1
  fi
}

# ── Nettoyage à la sortie ──────────────────────────────────
BAO_STARTED=0
cleanup() {
  echo ""
  warn "Arrêt de tous les composants PayHSM..."
  [ -n "$HSM_PID"      ] && kill "$HSM_PID"      2>/dev/null || true
  [ -n "$SIM_BACK_PID" ] && kill "$SIM_BACK_PID" 2>/dev/null || true
  [ -n "$SIM_FRONT_PID"] && kill "$SIM_FRONT_PID" 2>/dev/null || true
  if [ "$BAO_STARTED" -eq 1 ]; then
    info "Arrêt du conteneur OpenBao..."
    (cd "$OPENBAO_DIR" && docker_compose down 2>/dev/null) || true
  fi
  log "Tous les processus arrêtés."
}
trap cleanup EXIT INT TERM

mkdir -p "$LOG_DIR"
banner

# ── 1. OpenBao (Docker) ────────────────────────────────────
info "Démarrage OpenBao (coffre Switch, port $OPENBAO_PORT)..."
if ! command -v docker >/dev/null 2>&1; then
  warn "Docker introuvable — OpenBao désactivé."
  warn "  Installez Docker pour activer le coffre Switch."
  OPENBAO_OK=0
else
  # Stopper un éventuel conteneur orphelin sur le port 8200
  if docker ps -q --filter "name=payhsm-openbao" | grep -q .; then
    warn "Conteneur OpenBao déjà actif, réutilisation..."
    OPENBAO_OK=1
    BAO_STARTED=0  # On ne l'a pas démarré, on ne le stoppera pas
  else
    if (cd "$OPENBAO_DIR" && docker_compose up -d 2>"$LOG_DIR/openbao.log"); then
      BAO_STARTED=1
      # Attendre que l'API réponde (max 30 s)
      OPENBAO_OK=0
      for i in $(seq 1 30); do
        sleep 1
        if curl -sf "http://127.0.0.1:$OPENBAO_PORT/v1/sys/health" >/dev/null 2>&1; then
          OPENBAO_OK=1
          log "OpenBao opérationnel → http://127.0.0.1:$OPENBAO_PORT"
          break
        fi
      done
      if [ "$OPENBAO_OK" -eq 0 ]; then
        warn "OpenBao ne répond pas après 30 s (logs : $LOG_DIR/openbao.log)"
        warn "Le simulateur continuera sans coffre Switch."
      fi
    else
      warn "Échec docker compose (logs : $LOG_DIR/openbao.log)"
      warn "Le simulateur continuera sans coffre Switch."
      OPENBAO_OK=0
    fi
  fi
fi

# Exporter les variables pour le backend Node.js
export OPENBAO_ADDR="http://127.0.0.1:$OPENBAO_PORT"
export OPENBAO_TOKEN="$OPENBAO_TOKEN"

# ── 2. Compilation payhsm-httpd ────────────────────────────
info "Compilation payhsm-httpd..."
if (cd "$HSM_DIR" && make bin/payhsm-httpd 2>&1); then
  log "payhsm-httpd compilé → $BINARY"
else
  err "Échec de compilation ! Vérifiez les erreurs ci-dessus."
  exit 1
fi

# ── 3. Lancement payhsm-httpd ──────────────────────────────
info "Démarrage HSM backend (port $HSM_PORT)..."
cd "$ROOT"
"$BINARY" "$HSM_PORT" "$FRONTEND_DIR" >"$LOG_DIR/payhsm-httpd.log" 2>&1 &
HSM_PID=$!

HSM_OK=0
for i in $(seq 1 20); do
  sleep 0.5
  if curl -sf "http://127.0.0.1:$HSM_PORT/api/health" >/dev/null 2>&1; then
    HSM_OK=1
    log "HSM backend opérationnel → http://127.0.0.1:$HSM_PORT"
    log "Console HSM               → http://127.0.0.1:$HSM_PORT/"
    break
  fi
done
if [ "$HSM_OK" -eq 0 ]; then
  err "HSM backend ne répond pas. Logs : $LOG_DIR/payhsm-httpd.log"
  cat "$LOG_DIR/payhsm-httpd.log"
  exit 1
fi

# ── 4. Lancement simulation backend (Node.js) ──────────────
info "Démarrage simulateur bancaire backend (port $SIM_BACK_PORT)..."
cd "$SIM_BACK"
if [ ! -d node_modules ]; then
  info "Installation des dépendances backend..."
  npm install --no-audit --no-fund
fi
# Libérer le port s'il était déjà occupé
if command -v lsof >/dev/null 2>&1; then
  lsof -ti:"$SIM_BACK_PORT" | xargs -r kill -9 2>/dev/null || true
fi
node server.js >"$LOG_DIR/sim-backend.log" 2>&1 &
SIM_BACK_PID=$!

BACK_OK=0
for i in $(seq 1 20); do
  sleep 0.5
  if curl -sf "http://127.0.0.1:$SIM_BACK_PORT/api/health" >/dev/null 2>&1; then
    BACK_OK=1
    log "Simulateur backend opérationnel → http://127.0.0.1:$SIM_BACK_PORT"
    break
  fi
done
if [ "$BACK_OK" -eq 0 ]; then
  warn "Simulateur backend lent à démarrer (vérifiez $LOG_DIR/sim-backend.log)"
fi

# ── 5. Lancement simulation frontend (Vite/React) ──────────
info "Démarrage simulateur frontend React (port $SIM_FRONT_PORT)..."
cd "$SIM_FRONT"
if [ ! -d node_modules ]; then
  info "Installation des dépendances frontend..."
  npm install --no-audit --no-fund
fi
if command -v lsof >/dev/null 2>&1; then
  lsof -ti:"$SIM_FRONT_PORT" | xargs -r kill -9 2>/dev/null || true
fi
npm run dev >"$LOG_DIR/sim-frontend.log" 2>&1 &
SIM_FRONT_PID=$!

FRONT_OK=0
for i in $(seq 1 30); do
  sleep 0.5
  if curl -sf "http://127.0.0.1:$SIM_FRONT_PORT" >/dev/null 2>&1; then
    FRONT_OK=1
    log "Simulateur frontend opérationnel → http://127.0.0.1:$SIM_FRONT_PORT"
    break
  fi
done
if [ "$FRONT_OK" -eq 0 ]; then
  warn "Frontend Vite lent à démarrer (vérifiez $LOG_DIR/sim-frontend.log)"
fi

# ── Résumé ─────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  PayHSM — DÉMARRÉ${RESET}"
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════${RESET}"
echo ""

if [ "${OPENBAO_OK:-0}" -eq 1 ]; then
  echo -e "  ${BOLD}OpenBao (coffre Switch)${RESET}  http://127.0.0.1:${OPENBAO_PORT}"
else
  echo -e "  ${YELLOW}OpenBao${RESET}                  désactivé (Docker manquant ou erreur)"
fi
echo -e "  ${BOLD}Console HSM${RESET}              http://127.0.0.1:${HSM_PORT}/"
echo -e "  ${BOLD}API HSM${RESET}                  http://127.0.0.1:${HSM_PORT}/api/health"
echo -e "  ${BOLD}Simulateur bancaire${RESET}      http://127.0.0.1:${SIM_FRONT_PORT}/"
echo -e "  ${BOLD}Backend simulateur${RESET}       http://127.0.0.1:${SIM_BACK_PORT}/api/health"
echo ""
echo -e "  Logs : ${CYAN}$LOG_DIR/${RESET}"
echo ""
echo -e "  ${YELLOW}Étapes suivantes :${RESET}"
echo -e "  1. Console HSM  → Provision (créer la LMK)"
echo -e "  2. Console HSM  → Démarrer HSM"
echo -e "  3. Simulateur   → lancer un scénario (GAB, EMV, MAC...)"
echo ""
echo -e "  ${BOLD}Ctrl+C pour tout arrêter${RESET}"
echo ""

# ── Attente ────────────────────────────────────────────────
wait "$HSM_PID" "$SIM_BACK_PID" "$SIM_FRONT_PID"
