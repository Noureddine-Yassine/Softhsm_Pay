#!/usr/bin/env bash
# ============================================================
# PayHSM — Tests gestion des clés style payShield 10K
# A0 A4 A6 A8 B0 BS BW CS K8 KA NE + régressions A0/A6/A8
#
# Usage : ./test-keymgr.sh [http://host:port]
# Requis : HSM démarré + LMK initialisée (Shamir reconstruct)
# ============================================================
HSM_URL="${1:-http://127.0.0.1:8765}"
EP="$HSM_URL/api/hsm/cmd"
PASS=0; FAIL=0

RED='\033[31m'; GRN='\033[32m'; YLW='\033[33m'
CYN='\033[36m'; BOLD='\033[1m'; RST='\033[0m'

ok()   { echo -e "  ${GRN}[PASS]${RST} $*"; ((PASS++)); }
fail() { echo -e "  ${RED}[FAIL]${RST} $*"; ((FAIL++)); }
hdr()  { echo -e "\n${BOLD}${CYN}══ $* ══${RST}"; }

send() {
    curl -sf -X POST "$EP" \
         -H "Content-Type: application/json" \
         -d "{\"cmd\":\"$1\"}" 2>/dev/null
}

jval() { echo "$1" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('$2',''))" 2>/dev/null; }
jrc()  { jval "$1" "rc"; }
jraw() { jval "$1" "rawResponse"; }

# ── Vérifier que le HSM est prêt ──────────────────────────────
H=$(curl -sf "$HSM_URL/api/health" 2>/dev/null)
if [[ "$(jval "$H" initialized)" != "1" ]]; then
    echo -e "${RED}HSM non initialisé — lancez Shamir reconstruct d'abord${RST}"
    exit 1
fi
echo -e "${GRN}HSM OK${RST} — tests démarrent\n"

# ═══════════════════════════════════════════════════════════
# A0 / A1 — Generate Key
# ═══════════════════════════════════════════════════════════
hdr "A0 / A1 — Generate Key"

R=$(send "0001A0|ZMK|16|U|1")
ZMK_ID=$(jval "$R" keyId); KCV_ZMK=$(jval "$R" kcv)
if [[ "$ZMK_ID" == ZMK_* && ${#KCV_ZMK} -eq 6 ]]; then
    ok "A0 ZMK → id=$ZMK_ID kcv=$KCV_ZMK"
else fail "A0 ZMK : $R"; fi

R=$(send "0001A0|ZPK|16|U|1")
ZPK_ID=$(jval "$R" keyId); KCV_ZPK=$(jval "$R" kcv)
[[ "$ZPK_ID" == ZPK_* ]] && ok "A0 ZPK → $ZPK_ID" || fail "A0 ZPK : $R"

R=$(send "0001A0|TPK|16|U|1")
TPK_ID=$(jval "$R" keyId)
[[ "$TPK_ID" == TPK_* ]] && ok "A0 TPK → $TPK_ID" || fail "A0 TPK"

R=$(send "0001A0|KEK|16|U|0")
KEK_ID=$(jval "$R" keyId)
[[ "$KEK_ID" == KEK_* ]] && ok "A0 KEK → $KEK_ID (non-exportable)" || fail "A0 KEK"

R=$(send "0001A0|INVALID|16|U|1")
[[ "$(jraw "$R")" == *"04"* ]] && ok "A0 type invalide → erreur 04" || fail "A0 type invalide"

R=$(send "0001A0|ZPK|99|U|1")
[[ "$(jraw "$R")" == *"02"* ]] && ok "A0 longueur invalide → erreur 02" || fail "A0 longueur invalide"

# ═══════════════════════════════════════════════════════════
# A4 / A5 — Form Key from Components
# ═══════════════════════════════════════════════════════════
hdr "A4 / A5 — Form Key from Components"

C1="00112233445566778899AABBCCDDEEFF"
C2="FEDCBA9876543210FEDCBA9876543210"
C3=$(python3 -c "
a=bytes.fromhex('$C1'); b=bytes.fromhex('$C2')
print(bytes(x^y for x,y in zip(a,b)).hex().upper())")
# C1 XOR C2 XOR C3 = 0 (key = 0x00...); 3rd component = C1^C2
# Actually we want a non-zero key
C1="00112233445566778899AABBCCDDEEFF"
C2="AABBCCDDEEFF00112233445566778899"
C3_EXPECTED=$(python3 -c "
a=bytes.fromhex('$C1'); b=bytes.fromhex('$C2')
print(bytes(x^y for x,y in zip(a,b)).hex().upper())")
R=$(send "0001A4|ZMK|U|2|${C1}|${C2}")
A4_ID=$(jval "$R" keyId)
if [[ "$A4_ID" == ZMK_* ]]; then
    ok "A4 2 composants → $A4_ID KCV=$(jval "$R" kcv)"
else fail "A4 2 composants : $R"; fi

R=$(send "0001A4|ZMK|U|3|${C1}|${C2}|AABB334455667788")
[[ "$(jraw "$R")" == *"11"* ]] && ok "A4 composant invalide (longueur) → erreur 11" || fail "A4 composant invalide"

# ═══════════════════════════════════════════════════════════
# A6 / A7 — Import Key (format étendu)
# ═══════════════════════════════════════════════════════════
hdr "A6 / A7 — Import Key (étendu)"

# On exporte d'abord ZPK sous ZMK pour avoir une clé à importer
EXP=$(send "0001A8|${ZPK_ID}|ZMK|${ZMK_ID}|U")
ENC_KEY=$(jval "$EXP" exportedKey)
if [[ ${#ENC_KEY} -eq 32 ]]; then
    R=$(send "0001A6|ZMK|${ZMK_ID}|ZPK|U|${ENC_KEY}")
    A6_ID=$(jval "$R" keyId)
    [[ "$A6_ID" == ZPK_* ]] && ok "A6 import ZPK sous ZMK → $A6_ID" || fail "A6 import"
else fail "A6 prérequis A8 échoué : exported=$ENC_KEY"; fi

R=$(send "0001A6|ZMK|ZMK_99999|ZPK|U|AABBCCDDEEFF00112233445566778899")
[[ "$(jraw "$R")" == *"13"* ]] && ok "A6 transport inexistant → erreur 13" || fail "A6 transport inexistant"

# ═══════════════════════════════════════════════════════════
# A8 / A9 — Export Key (format étendu)
# ═══════════════════════════════════════════════════════════
hdr "A8 / A9 — Export Key (étendu)"

R=$(send "0001A8|${ZPK_ID}|ZMK|${ZMK_ID}|U")
EK=$(jval "$R" exportedKey); [[ $(jrc "$R") -eq 0 && ${#EK} -eq 32 ]] && \
    ok "A8 export ZPK sous ZMK → KCV=$(jval "$R" kcv)" || fail "A8 export: rc=$(jrc "$R") ek_len=${#EK}"

R=$(send "0001A8|${KEK_ID}|ZMK|${ZMK_ID}|U")
[[ "$(jraw "$R")" == *"09"* ]] && ok "A8 clé non-exportable → erreur 09" || fail "A8 non-exportable"

R=$(send "0001A8|${ZPK_ID}|ZMK|ZMK_99999|U")
[[ "$(jraw "$R")" == *"13"* ]] && ok "A8 transport inexistant → erreur 13" || fail "A8 transport inexistant"

# ═══════════════════════════════════════════════════════════
# B0 / B1 — Translate Key Scheme
# ═══════════════════════════════════════════════════════════
hdr "B0 / B1 — Translate Key Scheme"

R=$(send "0001B0|${ZPK_ID}|T")
[[ $(jrc "$R") -eq 0 ]] && ok "B0 U→T OK" || fail "B0 schéma T"

R=$(send "0001B0|${ZPK_ID}|U")
[[ $(jrc "$R") -eq 0 ]] && ok "B0 T→U OK" || fail "B0 schéma U"

R=$(send "0001B0|${ZPK_ID}|Z")
[[ "$(jraw "$R")" == *"10"* ]] && ok "B0 schéma invalide → erreur 10" || fail "B0 schéma invalide"

# ═══════════════════════════════════════════════════════════
# BS / BT — Clear Key Change Storage
# ═══════════════════════════════════════════════════════════
hdr "BS / BT — Clear Key Change Storage"

R=$(send "0001BS")
[[ "$(jraw "$R")" == *"CLEARED"* ]] && ok "BS → KEY_CHANGE_STORAGE_CLEARED" || fail "BS"

# ═══════════════════════════════════════════════════════════
# BW / BX — Re-wrap under current LMK
# ═══════════════════════════════════════════════════════════
hdr "BW / BX — Re-wrap vault under LMK"

R=$(send "0001BW")
M=$(jval "$R" migrated)
if [[ $(jrc "$R") -eq 0 && -n "$M" ]]; then
    ok "BW migrated=$M failed=$(jval "$R" failed)"
else fail "BW : $R"; fi

# ═══════════════════════════════════════════════════════════
# CS / CT — Modify Key Block Header
# ═══════════════════════════════════════════════════════════
hdr "CS / CT — Modify Key Block Header"

R=$(send "0001CS|${ZPK_ID}|SCHEME|T")
[[ $(jrc "$R") -eq 0 ]] && ok "CS SCHEME→T" || fail "CS SCHEME"

R=$(send "0001CS|${ZPK_ID}|ACTIVE|0")
[[ $(jrc "$R") -eq 0 ]] && ok "CS ACTIVE=0 (retire)" || fail "CS ACTIVE"

R=$(send "0001CS|${ZPK_ID}|ACTIVE|1")
[[ $(jrc "$R") -eq 0 ]] && ok "CS ACTIVE=1 (restaure)" || fail "CS ACTIVE restore"

R=$(send "0001CS|${KEK_ID}|EXPORT|1")
[[ "$(jraw "$R")" == *"09"* ]] && ok "CS rendre KEK exportable → refusé 09" || fail "CS KEK export non bloqué"

# ═══════════════════════════════════════════════════════════
# K8 / K9 — Export Key under KEK
# ═══════════════════════════════════════════════════════════
hdr "K8 / K9 — Export Key under KEK"

R=$(send "0001K8|${ZPK_ID}|${KEK_ID}|U")
KUK=$(jval "$R" keyUnderKek); [[ $(jrc "$R") -eq 0 && ${#KUK} -eq 32 ]] && \
    ok "K8 export ZPK sous KEK → KCV=$(jval "$R" kcv)" || fail "K8 export: $(jraw "$R")"

R=$(send "0001K8|${KEK_ID}|${KEK_ID}|U")
[[ "$(jraw "$R")" == *"09"* ]] && ok "K8 KEK non-exportable → erreur 09" || fail "K8 non-exportable"

R=$(send "0001K8|${ZPK_ID}|KEK_99999|U")
[[ "$(jraw "$R")" == *"13"* ]] && ok "K8 KEK inexistant → erreur 13" || fail "K8 KEK inexistant"

# ═══════════════════════════════════════════════════════════
# KA / KB — Generate KCV
# ═══════════════════════════════════════════════════════════
hdr "KA / KB — Generate KCV"

R=$(send "0001KA|${ZPK_ID}")
[[ $(jrc "$R") -eq 0 && $(jval "$R" kcv) == "$KCV_ZPK" ]] && \
    ok "KA par ID → KCV=$KCV_ZPK (vérifié vs génération)" || fail "KA par ID"

R=$(send "0001KA|RAW|AES|00112233445566778899AABBCCDDEEFF")
RAWKCV=$(jval "$R" kcv); [[ $(jrc "$R") -eq 0 && ${#RAWKCV} -eq 6 ]] && \
    ok "KA RAW AES-128 → KCV=$RAWKCV" || fail "KA RAW"

R=$(send "0001KA|ZPK_99999")
[[ "$(jraw "$R")" == *"06"* ]] && ok "KA ID inexistant → erreur 06" || fail "KA ID inexistant"

# ═══════════════════════════════════════════════════════════
# NE / NF — Generate Key Components
# ═══════════════════════════════════════════════════════════
hdr "NE / NF — Generate Key Components"

R=$(send "0001NE|ZMK|16|3|Y")
if [[ $(jrc "$R") -eq 0 && "$(jraw "$R")" == *"COMP1="* && "$(jraw "$R")" == *"COMP3="* ]]; then
    ok "NE 3 composants ZMK → id=$(jval "$R" keyId) kcv=$(jraw "$R" | grep -oP 'KCV=\K[A-F0-9]+')"
else fail "NE 3 composants : $R"; fi

R=$(send "0001NE|ZPK|16|2|N")
[[ $(jrc "$R") -eq 0 && "$(jraw "$R")" == *"COMP2="* ]] && \
    ok "NE 2 composants sans stockage" || fail "NE 2 composants"

R=$(send "0001NE|ZMK|16|10|N")
[[ "$(jraw "$R")" == *"11"* ]] && ok "NE NC=10 > max 9 → erreur 11" || fail "NE NC invalide"

# ═══════════════════════════════════════════════════════════
# Régressions — anciennes commandes A0 A6 A8 (format original)
# ═══════════════════════════════════════════════════════════
hdr "Régressions — Anciennes commandes A0/A6/A8"

R=$(send "0001A01001U")
KCV_OLD=$(jval "$R" kcv); CRYPT_OLD=$(jval "$R" cryptogram)
if [[ $(jrc "$R") -eq 0 && ${#KCV_OLD} -eq 6 ]]; then
    ok "A0 old format (TMK AES-128) → KCV=$KCV_OLD"
else fail "A0 old format : $R"; fi

R=$(send "0001A01002U")
[[ $(jrc "$R") -eq 0 ]] && ok "A0 old ZMK code=02" || fail "A0 old ZMK"

R=$(send "0001B2")
[[ "$(jraw "$R")" == "0001B300" ]] && ok "B2 Echo (régression)" || fail "B2 Echo"

R=$(send "0001NO")
[[ "$(jraw "$R")" == 0001NP00* ]] && ok "NO Status (régression)" || fail "NO Status"

R=$(send "0001N010")
[[ "$(jraw "$R")" == 0001N100* ]] && ok "N0 Random (régression)" || fail "N0 Random"

# ═══════════════════════════════════════════════════════════
# Sécurité — vérifier que les clés claires ne sont pas loggées
# ═══════════════════════════════════════════════════════════
hdr "Sécurité"

if grep -q "KEY_HEX\|key_clear\|plaintext" /tmp/httpd.log 2>/dev/null; then
    fail "SECURITE: clés potentiellement loggées!"
else ok "Aucune clé claire dans les logs serveur"; fi

# ═══════════════════════════════════════════════════════════
# Résumé
# ═══════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}══════════════════════════════════════════${RST}"
echo -e "${BOLD}  Résultats : ${GRN}$PASS PASS${RST}  ${RED}$FAIL FAIL${RST}"
echo -e "${BOLD}══════════════════════════════════════════${RST}"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
