#!/usr/bin/env bash
# ============================================================
# PayHSM — Tests commandes wire (mode INTERNAL + PAYSHIELD_COMPAT)
# ============================================================
HSM="${1:-http://127.0.0.1:8765}"
EP="$HSM/api/hsm/cmd"
PASS=0; FAIL=0

RED='\033[31m'; GRN='\033[32m'; YLW='\033[33m'; CYN='\033[36m'
BOLD='\033[1m'; RST='\033[0m'

ok()   { echo -e "  ${GRN}[PASS]${RST} $*"; PASS=$((PASS+1)); }
fail() { echo -e "  ${RED}[FAIL]${RST} $*"; FAIL=$((FAIL+1)); }
hdr()  { echo -e "\n${BOLD}${CYN}══ $* ══${RST}"; }

send() { curl -sf -X POST "$EP" -H "Content-Type:application/json" -d "{\"cmd\":\"$1\"}" 2>/dev/null; }
mode() { curl -sf -X POST "$HSM/api/hsm/mode" -H "Content-Type:application/json" -d "{\"mode\":\"$1\"}" 2>/dev/null; }
jf()   { echo "$1" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('$2',''))" 2>/dev/null; }
jrc()  { jf "$1" "rc"; }
jraw() { jf "$1" "rawResponse"; }

# Vérifie HSM disponible + initialisé
H=$(curl -sf "$HSM/api/health" 2>/dev/null)
[[ "$(jf "$H" initialized)" != "1" ]] && echo -e "${RED}HSM non initialisé${RST}" && exit 1

# ═══════════════════════════════════════════════════════════
hdr "B2/B3 — Echo (tous modes)"

R=$(send "0001B2"); [[ "$(jraw "$R")" == "0001B300" ]] && ok "B2 sans data → 0001B300" || fail "B2 sans data: $(jraw "$R")"
R=$(send "0001B2HELLO"); [[ "$(jraw "$R")" == "0001B300HELLO" ]] && ok "B2 avec data HELLO" || fail "B2 data: $(jraw "$R")"
R=$(send "ABCDB2TEST"); [[ "$(jraw "$R")" == "ABCDB300TEST" ]] && ok "B2 header ABCD preservé" || fail "B2 header: $(jraw "$R")"

# ═══════════════════════════════════════════════════════════
hdr "N0/N1 — Random (tous modes)"

R=$(send "0001N010"); raw="$(jraw "$R")"; [[ ${#raw} -eq 40 && "$raw" == 0001N100* ]] && ok "N0 16 octets (32 hex)" || fail "N0: $raw"
R=$(send "0001N001"); [[ "$(jraw "$R")" == *"04"* ]] && ok "N0 taille < 8 → err 04" || fail "N0 min: $(jraw "$R")"
R=$(send "0001N080"); [[ "$(jraw "$R")" == *"04"* ]] && ok "N0 taille > 64 → err 04" || fail "N0 max: $(jraw "$R")"

# ═══════════════════════════════════════════════════════════
hdr "NO/NP + NI/NJ + NC/ND — Diagnostics (tous modes)"

R=$(send "0001NO"); [[ "$(jraw "$R")" == 0001NP00* ]] && ok "NO statut OK" || fail "NO: $(jraw "$R")"
R=$(send "0001NI"); [[ "$(jraw "$R")" == 0001NJ00* ]] && ok "NI réseau OK" || fail "NI: $(jraw "$R")"
R=$(send "0001NC"); [[ "$(jraw "$R")" == 0001ND00* ]] && ok "NC diagnostics OK" || fail "NC: $(jraw "$R")"

# ═══════════════════════════════════════════════════════════
hdr "Modes — Basculement INTERNAL ↔ PAYSHIELD_COMPAT ↔ LAB"

mode "INTERNAL" > /dev/null
R=$(curl -sf "$HSM/api/hsm/mode" 2>/dev/null); [[ "$(jf "$R" mode)" == "INTERNAL" ]] && ok "Mode INTERNAL" || fail "Mode INTERNAL"

mode "PAYSHIELD_COMPAT" > /dev/null
R=$(curl -sf "$HSM/api/hsm/mode" 2>/dev/null); [[ "$(jf "$R" mode)" == "PAYSHIELD_COMPAT" ]] && ok "Mode PAYSHIELD_COMPAT" || fail "Mode PAYSHIELD_COMPAT"

mode "LAB" > /dev/null
R=$(curl -sf "$HSM/api/hsm/mode" 2>/dev/null); [[ "$(jf "$R" mode)" == "LAB" ]] && ok "Mode LAB" || fail "Mode LAB"

mode "INTERNAL" > /dev/null

# ═══════════════════════════════════════════════════════════
hdr "A0/A1 — Generate Key (mode INTERNAL)"

R=$(send "0001A01001U"); KCV=$(jf "$R" kcv); [[ "$(jrc "$R")" == "0" && ${#KCV} -eq 6 ]] && ok "A0 wire TMK AES-128 (KCV $KCV)" || fail "A0 wire: $(jraw "$R")"
R=$(send "0001A01002U"); [[ "$(jrc "$R")" == "0" ]] && ok "A0 wire ZMK" || fail "A0 wire ZMK"
R=$(send "0001A0|ZPK|16|U|1"); ZPK_ID=$(jf "$R" keyId); [[ "$ZPK_ID" == ZPK_* ]] && ok "A0 pipe ZPK → $ZPK_ID" || fail "A0 pipe: $(jraw "$R")"
R=$(send "0001A0|ZMK|16|U|1"); ZMK_ID=$(jf "$R" keyId); [[ "$ZMK_ID" == ZMK_* ]] && ok "A0 pipe ZMK → $ZMK_ID" || fail "A0 pipe ZMK"
R=$(send "0001A0"); [[ "$(jrc "$R")" == "-1" ]] && ok "A0 trame courte → erreur" || fail "A0 format check"

# ═══════════════════════════════════════════════════════════
hdr "A8/A9 — Sécurité flag V"

R=$(send "0001A01001U"); CRYPT=$(jf "$R" cryptogram)
R=$(send "0001A810V${CRYPT}"); [[ "$(jf "$R" errorCode)" == "31" ]] && ok "A8 flagV INTERNAL → err 31 (LAB only)" || fail "A8 flagV INTERNAL: $(jf "$R" errorCode)"
mode "LAB" > /dev/null
R=$(send "0001A810V${CRYPT}"); [[ "$(jrc "$R")" == "0" && -n "$(jf "$R" keyClear)" ]] && ok "A8 flagV LAB → keyClear disponible" || fail "A8 flagV LAB: $(jraw "$R")"
mode "INTERNAL" > /dev/null
R=$(send "0001A810H${CRYPT}"); [[ "$(jrc "$R")" == "0" && -z "$(jf "$R" keyClear)" ]] && ok "A8 flagH → KCV seulement" || fail "A8 flagH"

# ═══════════════════════════════════════════════════════════
hdr "KA/KB — KCV wire format"

R=$(send "0001A01001U"); CRYPT=$(jf "$R" cryptogram); KCV_A0=$(jf "$R" kcv)
R=$(send "0001KA10U${CRYPT}"); KCV_KA=$(jf "$R" kcv)
[[ "$(jrc "$R")" == "0" ]] && ok "KA wire rc=0" || fail "KA wire: $(jraw "$R")"
[[ "$KCV_A0" == "$KCV_KA" ]] && ok "KCV A0 == KCV KA ($KCV_A0)" || fail "KCV mismatch A0=$KCV_A0 KA=$KCV_KA"

# ═══════════════════════════════════════════════════════════
hdr "A0/KA — Mode PAYSHIELD_COMPAT [PS-INSPIRED]"

mode "PAYSHIELD_COMPAT" > /dev/null
R=$(send "0001A0000U"); [[ "$(jrc "$R")" == "0" && "$(jf "$R" mode)" == "PAYSHIELD_COMPAT" ]] && ok "A0 PS ZMK (000)" || fail "A0 PS ZMK: $(jraw "$R")"
R=$(send "0001A0001U"); PS_CRYPT="$(jraw "$R")"; PS_CRYPT="${PS_CRYPT:9:88}"; PS_KCV=$(jf "$R" kcv)
[[ "$(jrc "$R")" == "0" ]] && ok "A0 PS ZPK (001) kcv=$PS_KCV" || fail "A0 PS ZPK"
R=$(send "0001KA001U${PS_CRYPT}"); KA_KCV=$(jf "$R" kcv)
[[ "$(jrc "$R")" == "0" ]] && ok "KA PS rc=0 kcv=$KA_KCV" || fail "KA PS: $(jraw "$R")"
[[ "$PS_KCV" == "$KA_KCV" ]] && ok "KCV A0 PS == KA PS ($PS_KCV)" || fail "KCV PS mismatch $PS_KCV vs $KA_KCV"

# BU payShield : accepte KEY_UNDER_LMK seulement
R=$(send "0001BUG001U${PS_CRYPT}"); [[ "$(jrc "$R")" == "0" ]] && ok "BU PS G (clé sous LMK) rc=0" || fail "BU PS: $(jraw "$R")"
R=$(send "0001BUG00112233445566778899AABBCCDDEEFF")
[[ "$(jf "$R" errorCode)" == "02" ]] && ok "BU PS : clé en clair refusée (trop courte=err02)" || fail "BU PS clear key: $(jf "$R" errorCode)"

mode "INTERNAL" > /dev/null

# ═══════════════════════════════════════════════════════════
hdr "Coffre étendu — BS/BW/CS"

R=$(send "0001BS"); [[ "$(jraw "$R")" == *"CLEARED"* ]] && ok "BS → CLEARED" || fail "BS: $(jraw "$R")"
R=$(send "0001BW"); [[ "$(jrc "$R")" == "0" ]] && ok "BW re-wrap OK migrated=$(jf "$R" migrated)" || fail "BW: $(jraw "$R")"

# ═══════════════════════════════════════════════════════════
hdr "CA/CB + CC/CD — Translation PIN block (clés sous LMK)"

# Générer TPK (06) et ZPK (03) en mode INTERNAL wire → récupérer les cryptogrammes
R=$(send "0001A01006U"); TPK=$(jf "$R" cryptogram)
R=$(send "0001A01003U"); ZPK=$(jf "$R" cryptogram)
PB="1122334455667788"
if [[ ${#TPK} -eq 88 && ${#ZPK} -eq 88 ]]; then
    ok "TPK/ZPK sous LMK générés (88 hex)"
    R=$(send "0001CA${TPK}${ZPK}${PB}"); PBZ=$(jf "$R" pinBlockOut)
    [[ "$(jrc "$R")" == "0" && ${#PBZ} -eq 16 ]] && ok "CA TPK→ZPK → pinBlockOut=$PBZ" || fail "CA: $(jraw "$R")"
    R=$(send "0002CC${ZPK}${TPK}${PBZ}"); PBBACK=$(jf "$R" pinBlockOut)
    [[ "$PBBACK" == "$PB" ]] && ok "CC ZPK→TPK aller-retour ($PBBACK)" || fail "CC round-trip: $PBBACK != $PB"
    R=$(send "0003CA"); [[ "$(jf "$R" errorCode)" == "02" ]] && ok "CA trame courte → err 02" || fail "CA format: $(jf "$R" errorCode)"
else
    fail "TPK/ZPK non générés (TPK=${#TPK} ZPK=${#ZPK})"
fi

# ═══════════════════════════════════════════════════════════
hdr "Commande inconnue + LMK absente"

R=$(send "0001ZZ"); [[ "$(jf "$R" errorCode)" == "40" ]] && ok "ZZ inconnue → err 40" || fail "ZZ: $(jf "$R" errorCode)"

# ═══════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}══════════════════════════════════════════${RST}"
echo -e "${BOLD}  Résultats : ${GRN}$PASS PASS${RST}  ${RED}$FAIL FAIL${RST}"
echo -e "${BOLD}══════════════════════════════════════════${RST}"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
