#!/usr/bin/env bash
# ============================================================
# PayHSM — Tests commandes wire style payShield 10K
# B2/B3  NO/NP  NI/NJ  NC/ND  N0/N1  BU/BV
#
# Usage : ./test-hsm-cmds.sh [http://host:port]
# ============================================================

HSM_URL="${1:-http://127.0.0.1:8765}"
ENDPOINT="$HSM_URL/api/hsm/cmd"
PASS=0; FAIL=0

RED='\033[31m'; GRN='\033[32m'; YLW='\033[33m'
CYN='\033[36m'; BOLD='\033[1m'; RST='\033[0m'

ok()  { echo -e "  ${GRN}[PASS]${RST} $*"; ((PASS++)); }
fail(){ echo -e "  ${RED}[FAIL]${RST} $*"; ((FAIL++)); }
hdr() { echo -e "\n${BOLD}${CYN}══ $* ══${RST}"; }

send() {
    curl -sf -X POST "$ENDPOINT" \
         -H "Content-Type: application/json" \
         -d "{\"cmd\":\"$1\"}" 2>/dev/null
}

# Extraire un champ JSON simple
jfield() { echo "$1" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('$2',''))" 2>/dev/null; }
jraw()   { jfield "$1" rawResponse; }
jrc()    { jfield "$1" rc; }

# ── B2 / B3 — Echo ──────────────────────────────────────────
hdr "B2 / B3 — Echo command"

r=$(send "0001B2")
raw=$(jraw "$r")
if [[ "$raw" == "0001B300" ]]; then
    ok "B2 sans données → $raw"
else
    fail "B2 sans données : attendu 0001B300, obtenu $raw"
fi

r=$(send "0001B2HELLO")
raw=$(jraw "$r")
if [[ "$raw" == "0001B300HELLO" ]]; then
    ok "B2 avec données HELLO → $raw"
else
    fail "B2 avec données : attendu 0001B300HELLO, obtenu $raw"
fi

r=$(send "FFFEB2TEST123")
raw=$(jraw "$r")
if [[ "$raw" == "FFFEB300TEST123" ]]; then
    ok "B2 header FFFE → $raw"
else
    fail "B2 header FFFE : obtenu $raw"
fi

# ── NO / NP — HSM Status ────────────────────────────────────
hdr "NO / NP — HSM Status"

r=$(send "0001NO")
raw=$(jraw "$r")
if [[ "$raw" == 0001NP00* ]]; then
    ok "NO header correct : ${raw:0:10}…"
    if echo "$raw" | grep -q "LMK_LOADED="; then
        ok "NO contient LMK_LOADED"
    else
        fail "NO: champ LMK_LOADED absent dans $raw"
    fi
    if echo "$raw" | grep -q "HOST=RUNNING"; then
        ok "NO contient HOST=RUNNING"
    else
        fail "NO: champ HOST=RUNNING absent"
    fi
    if echo "$raw" | grep -q "KEYS="; then
        ok "NO contient KEYS"
    else
        fail "NO: champ KEYS absent"
    fi
else
    fail "NO : attendu 0001NP00..., obtenu $raw"
fi

# ── NI / NJ — Network Information ───────────────────────────
hdr "NI / NJ — Network Information"

r=$(send "0001NI")
raw=$(jraw "$r")
if [[ "$raw" == 0001NJ00* ]]; then
    ok "NI header correct : ${raw:0:10}…"
    if echo "$raw" | grep -q "HOST="; then ok "NI contient HOST"; else fail "NI: HOST absent"; fi
    if echo "$raw" | grep -q "PORT="; then ok "NI contient PORT"; else fail "NI: PORT absent"; fi
    if echo "$raw" | grep -q "PROTO="; then ok "NI contient PROTO"; else fail "NI: PROTO absent"; fi
    if echo "$raw" | grep -q "SERVER=RUNNING"; then
        ok "NI SERVER=RUNNING"
    else
        fail "NI: SERVER=RUNNING absent"
    fi
else
    fail "NI : attendu 0001NJ00..., obtenu $raw"
fi

# ── NC / ND — Diagnostics ───────────────────────────────────
hdr "NC / ND — Diagnostics"

r=$(send "0001NC")
raw=$(jraw "$r")
if [[ "$raw" == 0001ND00* ]]; then
    ok "NC header correct : ${raw:0:10}…"
    for field in MEMORY VAULT AUDIT RNG LMK UPTIME; do
        if echo "$raw" | grep -q "${field}="; then
            ok "NC contient ${field}"
        else
            fail "NC: ${field} absent dans $raw"
        fi
    done
else
    fail "NC : attendu 0001ND00..., obtenu $raw"
fi

# ── N0 / N1 — Generate Random ───────────────────────────────
hdr "N0 / N1 — Generate Random Value"

# Taille valide : 0x10 = 16 octets
r=$(send "0001N010")
raw=$(jraw "$r")
if [[ "$raw" == 0001N100* ]]; then
    rng_hex="${raw:8}"
    rlen=${#rng_hex}
    if [[ "$rlen" -eq 32 ]]; then
        ok "N0 0x10 (16 octets) → 32 hex chars : ${rng_hex:0:16}…"
    else
        fail "N0 0x10 : longueur hex attendue 32, obtenu $rlen dans $raw"
    fi
else
    fail "N0 0x10 : attendu 0001N100..., obtenu $raw"
fi

# Taille valide : 0x20 = 32 octets
r=$(send "0001N020")
raw=$(jraw "$r")
rng_hex="${raw:8}"
rlen=${#rng_hex}
if [[ "$raw" == 0001N100* && "$rlen" -eq 64 ]]; then
    ok "N0 0x20 (32 octets) → 64 hex chars"
else
    fail "N0 0x20 : obtenu $raw (len=$rlen)"
fi

# Taille invalide : 0x01 = 1 octet (< min 8)
r=$(send "0001N001")
raw=$(jraw "$r")
if [[ "$raw" == 0001N104 ]]; then
    ok "N0 taille invalide 0x01 → erreur 04 correct"
else
    fail "N0 taille invalide 0x01 : attendu erreur 04, obtenu $raw"
fi

# Taille invalide : 0x80 = 128 octets (> max 64)
r=$(send "0001N080")
raw=$(jraw "$r")
if [[ "$raw" == 0001N104 ]]; then
    ok "N0 taille invalide 0x80 → erreur 04 correct"
else
    fail "N0 taille invalide 0x80 : attendu erreur 04, obtenu $raw"
fi

# Format invalide (trop court)
r=$(send "0001N0")
if echo "$r" | grep -q '"rc":-1'; then
    ok "N0 format invalide → erreur détectée"
else
    fail "N0 format invalide : erreur non détectée"
fi

# ── BU / BV — Generate / Verify KCV ────────────────────────
hdr "BU / BV — Generate / Verify KCV"

KEY_AES="00112233445566778899AABBCCDDEEFF"

# Génération KCV AES-128
r=$(send "0001BUG${KEY_AES}")
raw=$(jraw "$r")
if [[ "$raw" == 0001BV00* ]]; then
    KCV_AES="${raw:8:6}"
    ok "BU G AES-128 → KCV=${KCV_AES}"
else
    fail "BU G AES-128 : attendu 0001BV00..., obtenu $raw"
    KCV_AES="XXXXXX"
fi

# Vérification KCV correct
CMD_V=$(python3 -c "print('0001BUV${KEY_AES}${KCV_AES}')" 2>/dev/null)
r=$(send "$CMD_V")
raw=$(jraw "$r")
if [[ "$raw" == "0001BV00KCV_OK" ]]; then
    ok "BU V KCV correct → KCV_OK"
else
    fail "BU V KCV correct : attendu 0001BV00KCV_OK, obtenu $raw"
fi

# Vérification KCV incorrect
CMD_VI=$(python3 -c "print('0001BUV${KEY_AES}000000')" 2>/dev/null)
r=$(send "$CMD_VI")
raw=$(jraw "$r")
if [[ "$raw" == *"KCV_INVALID"* ]]; then
    ok "BU V KCV incorrect → KCV_INVALID (${raw:0:40}…)"
else
    fail "BU V KCV incorrect : attendu KCV_INVALID, obtenu $raw"
fi

# Génération KCV clé 3DES 24 octets (AES-192 équivalent)
KEY_3DES="0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
r=$(send "0001BUG${KEY_3DES}")
raw=$(jraw "$r")
if [[ "$raw" == 0001BV00* ]]; then
    KCV_3DES="${raw:8:6}"
    ok "BU G AES-192/3DES → KCV=${KCV_3DES}"
else
    fail "BU G AES-192/3DES : obtenu $raw"
fi

# Mode invalide
r=$(send "0001BUX${KEY_AES}")
raw=$(jraw "$r")
if [[ "$raw" == 0001BV04 ]]; then
    ok "BU mode invalide 'X' → erreur 04"
else
    fail "BU mode invalide : attendu erreur 04, obtenu $raw"
fi

# ── Commandes déjà existantes — régression ──────────────────
hdr "Régression A0 / A6 / A8"

# A0 (nécessite HSM initialisé)
r=$(send "0001A01001U")
rc=$(jrc "$r")
if [[ "$rc" == "0" ]]; then
    kcv=$(jfield "$r" kcv)
    ok "A0 ZMK AES-128 fonctionnel → KCV=$kcv"
elif echo "$r" | grep -q "non demarre\|NOT_INIT"; then
    echo -e "  ${YLW}[SKIP]${RST} A0 : HSM non initialisé (lancer Shamir reconstruct depuis :8765)"
else
    fail "A0 : rc=$rc réponse=$r"
fi

# A6 (nécessite HSM initialisé + ZMK)
if [[ "$rc" == "0" ]]; then
    cryptogram=$(jfield "$r" cryptogram)
    # Générer une clé test pour A6
    r2=$(send "0001A01002U")
    if [[ $(jrc "$r2") == "0" ]]; then
        ok "A0 ZPK AES-128 fonctionnel (prereq A6)"
    fi
fi

# B2 Echo (jamais de régression possible)
r=$(send "0002B2REGTEST")
raw=$(jraw "$r")
if [[ "$raw" == "0002B300REGTEST" ]]; then
    ok "B2 régression : header 0002 préservé"
else
    fail "B2 régression : $raw"
fi

# Commande inconnue
r=$(send "0001ZZ")
if [[ "$(jrc "$r")" == "-1" ]] && echo "$r" | grep -q '"errorCode":"01"'; then
    ok "Commande inconnue ZZ → errorCode=01"
else
    fail "Commande inconnue ZZ : $r"
fi

# Header invalide (trop court)
r=$(send "001A0")
if [[ "$(jrc "$r")" == "-1" ]] || [[ -z "$r" ]]; then
    ok "Header trop court → erreur détectée"
else
    fail "Header trop court non détecté : $r"
fi

# ── Résumé ──────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════${RST}"
echo -e "${BOLD}  Résultats : ${GRN}$PASS PASS${RST}  ${RED}$FAIL FAIL${RST}"
echo -e "${BOLD}══════════════════════════════════════${RST}"
echo ""
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
