#include <ctype.h>
/*
 * payhsm-cmd-table.c — Architecture propre des commandes HSM
 * Inclus dans payhsm-httpd.c
 *
 * Contient :
 *   1. Codes erreur centralisés
 *   2. Système de modes (INTERNAL / PAYSHIELD_COMPAT / LAB)
 *   3. Table de mapping des types de clés
 *   4. Fonction unifiée calculate_kcv()
 *   5. Constructeurs de réponse hsm_ok() / hsm_err()
 *   6. CommandRegistry (table)
 *   7. Dispatcher hsm_dispatch_wire()
 *
 * IMPORTANT : Ce module N'INVENTE PAS de vrais codes payShield.
 * Les formats en mode PAYSHIELD_COMPAT sont inspirés de la documentation
 * publique du payShield 10K Host Command Reference. Ils sont marqués
 * "payShield-inspired" et non "officiellement conformes".
 * Sans la documentation officielle Thales, on ne peut pas prétendre
 * à une conformité totale.
 */

/* ═══════════════════════════════════════════════════════════════════════════
   1. CODES ERREUR CENTRALISÉS
   (Inspiré de la table d'erreurs payShield 10K standard)
   ═══════════════════════════════════════════════════════════════════════════ */

#define HSM_ERR_OK              "00"   /* Succès */
#define HSM_ERR_GENERAL         "01"   /* Erreur générale */
#define HSM_ERR_FORMAT          "02"   /* Format de trame invalide */
#define HSM_ERR_UNAUTHORIZED    "03"   /* Opération non autorisée / HSM non initialisé */
#define HSM_ERR_KEYLEN          "04"   /* Longueur de clé invalide */
#define HSM_ERR_CRYPTO          "05"   /* Échec opération cryptographique */
#define HSM_ERR_KEY_NOT_FOUND   "06"   /* Clé introuvable dans le coffre */
#define HSM_ERR_KCV_FAIL        "07"   /* KCV incorrect */
#define HSM_ERR_KEY_PARITY      "08"   /* Parité de clé incorrecte */
#define HSM_ERR_LMK_ABSENT      "10"   /* LMK absente ou non chargée */
#define HSM_ERR_KEY_TYPE        "11"   /* Type de clé non supporté */
#define HSM_ERR_KEY_SCHEME      "12"   /* Schéma de clé invalide */
#define HSM_ERR_HSM_NOT_INIT    "15"   /* HSM non initialisé */
#define HSM_ERR_KEY_INVALID     "20"   /* Clé invalide ou cryptogramme corrompu */
#define HSM_ERR_NOT_EXPORTABLE  "21"   /* Clé non exportable */
#define HSM_ERR_COMPONENT       "22"   /* Composant de clé invalide */
#define HSM_ERR_TRANSPORT       "23"   /* Clé de transport introuvable */
#define HSM_ERR_MODE_FORBIDDEN  "30"   /* Opération interdite dans ce mode */
#define HSM_ERR_LAB_ONLY        "31"   /* Fonctionnalité LAB uniquement */
#define HSM_ERR_UNSUPPORTED     "40"   /* Commande non supportée */
#define HSM_ERR_INTERNAL        "99"   /* Erreur interne du serveur */

/* ═══════════════════════════════════════════════════════════════════════════
   2. MODES D'OPÉRATION
   ═══════════════════════════════════════════════════════════════════════════ */

typedef enum {
    HSM_MODE_INTERNAL  = 1,  /* Formats pipe-étendus du projet (défaut) */
    HSM_MODE_PAYSHIELD = 2,  /* Formats inspirés payShield 10K host command */
    HSM_MODE_LAB       = 3,  /* INTERNAL + flags debug (exposer clés claires) */
} hsm_mode_t;

static hsm_mode_t g_hsm_mode = HSM_MODE_INTERNAL;

static const char *hsm_mode_name(hsm_mode_t m) {
    switch(m) {
    case HSM_MODE_PAYSHIELD: return "PAYSHIELD_COMPAT";
    case HSM_MODE_LAB:       return "LAB";
    default:                 return "INTERNAL";
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
   3. MAPPING DES TYPES DE CLÉS
   NOTE : Les codes 3 chars ci-dessous sont INTERNES au projet.
   Ils sont inspirés des conventions payShield mais NE SONT PAS
   les vrais codes officiels Thales sans la documentation officielle.
   ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    const char *code3;    /* Code 3 chars utilisé dans les trames PAYSHIELD mode */
    const char *name;     /* Nom court */
    const char *fullname; /* Nom complet */
    int  default_len;     /* Longueur par défaut en octets */
    int  exportable;      /* Exportable par défaut */
} hsm_keytype_def_t;

/* [PROJET-INTERNE] Codes inspirés payShield — non officiels sans doc Thales */
static const hsm_keytype_def_t KEY_TYPE_TABLE[] = {
    { "000", "ZMK",  "Zone Master Key",           16, 1 },
    { "001", "ZPK",  "Zone PIN Key",               16, 1 },
    { "002", "TPK",  "Terminal PIN Key",           16, 1 },
    { "003", "TAK",  "Terminal Auth Key",          16, 1 },
    { "006", "TPK",  "Terminal PIN Key (alt)",      16, 1 },
    { "007", "TMK",  "Terminal Master Key",         16, 1 },
    { "008", "PVK",  "PIN Verification Key",       16, 0 },
    { "009", "ZAK",  "Zone Auth Key",               16, 1 },
    { "109", "IMK",  "Issuer Master Key (EMV AC)", 16, 0 },
    { "009", "ZAK",  "Zone Auth Key",               16, 1 },
    { "00A", "ZEK",  "Zone Encryption Key",         16, 1 },
    { "00B", "IMK",  "Issuer Master Key (alt)",     16, 0 },
    { "00C", "KEK",  "Key Encryption Key",          16, 0 },
    { "00D", "BDK",  "Base Derivation Key",         16, 0 },
    { NULL, NULL, NULL, 0, 0 },
};

static const hsm_keytype_def_t *ktype_by_code(const char *code3) {
    for (int i = 0; KEY_TYPE_TABLE[i].code3; i++)
        if (!strncasecmp(KEY_TYPE_TABLE[i].code3, code3, 3)) return &KEY_TYPE_TABLE[i];
    return NULL;
}
static const hsm_keytype_def_t *ktype_by_name(const char *name) {
    for (int i = 0; KEY_TYPE_TABLE[i].name; i++)
        if (!strcasecmp(KEY_TYPE_TABLE[i].name, name)) return &KEY_TYPE_TABLE[i];
    return NULL;
}

/* Schémas de clé */
static int valid_scheme(char c) {
    c = (char)toupper((unsigned char)c);
    return c == 'U' || c == 'T' || c == 'X' || c == 'Y' || c == 'Z' || c == 'R' || c == 'S';
}

/* ═══════════════════════════════════════════════════════════════════════════
   4. FONCTION UNIFIÉE DE CALCUL DU KCV
   Remplace hsm_kcv_hex(), cmd_kcv_hex(), ekm_kcv() — une seule source de vérité.
   KCV = AES-ECB(key, 16_zeros)[0..2] pour AES
         3DES-ECB(key, 8_zeros)[0..2]  pour 3DES/DES
   ═══════════════════════════════════════════════════════════════════════════ */
static void calculate_kcv(const uint8_t *key, size_t keylen, char kcv_out[7]) {
    uint8_t zeros[16] = {0};
    uint8_t result[16] = {0};
    int outl = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { strncpy(kcv_out, "000000", 7); return; }

    const EVP_CIPHER *cipher;
    int zero_len;
    if      (keylen == 16) { cipher = EVP_aes_128_ecb(); zero_len = 16; }
    else if (keylen == 24) { cipher = EVP_aes_192_ecb(); zero_len = 16; }
    else if (keylen == 32) { cipher = EVP_aes_256_ecb(); zero_len = 16; }
    else if (keylen ==  8) { cipher = EVP_des_ecb();     zero_len =  8; }
    else                   { cipher = EVP_des_ede3_ecb(); zero_len = 8; }

    EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptUpdate(ctx, result, &outl, zeros, zero_len);
    EVP_CIPHER_CTX_free(ctx);
    snprintf(kcv_out, 7, "%02X%02X%02X", result[0], result[1], result[2]);
}

/* ═══════════════════════════════════════════════════════════════════════════
   5. CONSTRUCTEURS DE RÉPONSE
   Format normalisé : [HDR][RESP_CMD][ERR_CODE][DATA_OPT]
   JSON : {"rc":0/1, "rawResponse":"...", "errorCode":"...", "message":"..."}
   ═══════════════════════════════════════════════════════════════════════════ */

/* Tampon de réponse brute élargi — assez pour NE avec 9 composants (9×32+headers) */
#define HSM_RAW_BUF  2048
#define HSM_JSON_BUF 2048

static void hsm_ok(const char *hdr, const char *resp_cmd, const char *data,
                   char *out, size_t n) {
    char raw[HSM_RAW_BUF];
    snprintf(raw, sizeof(raw), "%s%s" HSM_ERR_OK "%s", hdr, resp_cmd, data ? data : "");
    snprintf(out, n,
        "{\"rc\":0,\"rawResponse\":\"%s\",\"errorCode\":\"00\"}",
        raw);
}

static void hsm_err(const char *hdr, const char *resp_cmd, const char *errcode,
                    const char *msg, char *out, size_t n) {
    char raw[128];
    snprintf(raw, sizeof(raw), "%s%s%s", hdr, resp_cmd, errcode);

    /* Loguer l'erreur (sans données sensibles) */
    {
        char aline[120];
        snprintf(aline, sizeof(aline), "HSM_ERR cmd=%s code=%s", resp_cmd, errcode);
        audit_log(aline);
    }

    snprintf(out, n,
        "{\"rc\":-1,\"rawResponse\":\"%s\",\"errorCode\":\"%s\",\"message\":\"%s\"}",
        raw, errcode, msg ? msg : "");
}

/* Réponse OK avec JSON supplémentaire */
static void hsm_ok_json(const char *hdr, const char *resp_cmd, const char *data,
                         const char *json_extra, char *out, size_t n) {
    char raw[HSM_RAW_BUF];
    snprintf(raw, sizeof(raw), "%s%s" HSM_ERR_OK "%s", hdr, resp_cmd, data ? data : "");
    snprintf(out, n,
        "{\"rc\":0,\"rawResponse\":\"%s\",\"errorCode\":\"00\"%s}",
        raw, json_extra ? json_extra : "");
}

/* ═══════════════════════════════════════════════════════════════════════════
   6. HANDLERS payShield-compat (PAYSHIELD / LAB mode)
   Formats inspirés du payShield 10K Host Command Reference.
   Marqués [PS-INSPIRED] — non conformes sans documentation officielle.
   ═══════════════════════════════════════════════════════════════════════════ */

static int payhsm_thales_block_wrap_lmk(const uint8_t clear[PAYHSM_KEY_LEN], char scheme,
                                        char out33[PAYHSM_THALES_BLOCK_LEN + 1]) {
    uint8_t lmk[32];
    if (recompose_for_op(lmk) != 0) return PAYHSM_RC_ERR;
    int rc = payhsm_thales_block_wrap(lmk, scheme, clear, out33);
    secure_zero(lmk, sizeof(lmk));
    return rc;
}

/* Déchiffre ZMK depuis champ trame : 88 hex GCM (coffre) ou bloc Thales U+32hex */
static int parse_zmk_under_lmk_field(const char *field, size_t flen, uint8_t zmk_clear[PAYHSM_KEY_LEN]) {
    if (flen >= PAYHSM_GCM_BLOB_HEX) {
        int all_hex = 1;
        for (size_t i = 0; i < PAYHSM_GCM_BLOB_HEX; i++) {
            if (!isxdigit((unsigned char)field[i])) { all_hex = 0; break; }
        }
        if (all_hex) {
            char gcm[PAYHSM_GCM_BLOB_HEX + 1];
            strncpy(gcm, field, PAYHSM_GCM_BLOB_HEX);
            gcm[PAYHSM_GCM_BLOB_HEX] = '\0';
            return payhsm_unwrap_lmk_gcm_hex(gcm, zmk_clear);
        }
    }
    if (flen >= PAYHSM_THALES_BLOCK_LEN) {
        char blk[PAYHSM_THALES_BLOCK_LEN + 1];
        strncpy(blk, field, PAYHSM_THALES_BLOCK_LEN);
        blk[PAYHSM_THALES_BLOCK_LEN] = '\0';
        return payhsm_thales_block_unwrap_lmk(blk, zmk_clear);
    }
    return PAYHSM_RC_ERR;
}

/*
 * [Thales-style] A0 mode 1 — Generate Key + export immédiat sous ZMK
 * Request : [HDR:4][A0:2][1][KEY_TYPE:3][LMK_SCH:1][ZMK:88|33][ZMK_SCH:1][EXPORT:1]
 * Response: [HDR:4][A1:2][00][LMK_BLK:33][ZMK_BLK:33][KCV:6][KCV:6]
 */
static void handle_A0_payshield_mode1(const char *hdr, const char *cmd_str, size_t cmdlen,
                                        char *out, size_t n) {
    if (cmdlen < 46) {
        hsm_err(hdr, "A1", HSM_ERR_FORMAT,
                "[PS] A0 mode 1: [HDR][A0][1][TYPE:3][LMK_SCH][ZMK:88|33][ZMK_SCH][EXP:1] min 46",
                out, n);
        return;
    }

    char ktype_code[4], lmk_sch[2], zmk_sch[2], exp_flag[2];
    strncpy(ktype_code, cmd_str + 7, 3); ktype_code[3] = '\0';
    for (int i = 0; ktype_code[i]; i++)
        ktype_code[i] = (char)toupper((unsigned char)ktype_code[i]);
    lmk_sch[0] = (char)toupper((unsigned char)cmd_str[10]);
    lmk_sch[1] = '\0';

    const hsm_keytype_def_t *kt = ktype_by_code(ktype_code);
    if (!kt) {
        hsm_err(hdr, "A1", HSM_ERR_KEY_TYPE, "[PS] A0/1: KEY_TYPE inconnu", out, n);
        return;
    }
    if (!valid_scheme(lmk_sch[0])) {
        hsm_err(hdr, "A1", HSM_ERR_KEY_SCHEME, "[PS] A0/1: LMK scheme invalide", out, n);
        return;
    }

    size_t zmk_off = 11;
    size_t zmk_len = PAYHSM_THALES_BLOCK_LEN;
    if (cmdlen >= zmk_off + PAYHSM_GCM_BLOB_HEX + 2)
        zmk_len = PAYHSM_GCM_BLOB_HEX;
    if (cmdlen < zmk_off + zmk_len + 2) {
        hsm_err(hdr, "A1", HSM_ERR_FORMAT, "[PS] A0/1: trame ZMK incomplete", out, n);
        return;
    }

    uint8_t zmk[PAYHSM_KEY_LEN];
    if (parse_zmk_under_lmk_field(cmd_str + zmk_off, zmk_len, zmk) != PAYHSM_RC_OK) {
        hsm_err(hdr, "A1", HSM_ERR_CRYPTO, "[PS] A0/1: ZMK dechiffrement echec", out, n);
        return;
    }

    zmk_sch[0] = (char)toupper((unsigned char)cmd_str[zmk_off + zmk_len]);
    zmk_sch[1] = '\0';
    exp_flag[0] = cmd_str[zmk_off + zmk_len + 1];
    exp_flag[1] = '\0';
    if (!valid_scheme(zmk_sch[0])) {
        secure_zero(zmk, sizeof(zmk));
        hsm_err(hdr, "A1", HSM_ERR_KEY_SCHEME, "[PS] A0/1: ZMK scheme invalide", out, n);
        return;
    }

    uint8_t key[PAYHSM_KEY_LEN];
    if (RAND_bytes(key, PAYHSM_KEY_LEN) != 1) {
        secure_zero(zmk, sizeof(zmk));
        hsm_err(hdr, "A1", HSM_ERR_CRYPTO, "[PS] A0/1: RAND_bytes echec", out, n);
        return;
    }

    char kcv[7];
    calculate_kcv(key, PAYHSM_KEY_LEN, kcv);

    char cryptogram[256];
    if (payhsm_wrap_lmk_gcm_hex(key, cryptogram) != 0) {
        secure_zero(zmk, sizeof(zmk));
        secure_zero(key, sizeof(key));
        hsm_err(hdr, "A1", HSM_ERR_CRYPTO, "[PS] A0/1: LMK wrap echec", out, n);
        return;
    }

    char blk_lmk[PAYHSM_THALES_BLOCK_LEN + 1], blk_zmk[PAYHSM_THALES_BLOCK_LEN + 1];
    if (payhsm_thales_block_wrap_lmk(key, lmk_sch[0], blk_lmk) != PAYHSM_RC_OK ||
        payhsm_thales_block_wrap(zmk, zmk_sch[0], key, blk_zmk) != PAYHSM_RC_OK) {
        secure_zero(zmk, sizeof(zmk));
        secure_zero(key, sizeof(key));
        hsm_err(hdr, "A1", HSM_ERR_CRYPTO, "[PS] A0/1: wrap Thales echec", out, n);
        return;
    }

    ekm_ensure();
    char key_id[EKM_KEY_ID_LEN];
    ekm_gen_id(kt->name, key_id);
    uint8_t key2[PAYHSM_KEY_LEN], lmk[32];
    if (payhsm_unwrap_lmk_gcm_hex(cryptogram, key2) == 0 && recompose_for_op(lmk) == 0) {
        vault_store_16(lmk, key2, kt->name, "", kcv);
        secure_zero(lmk, sizeof(lmk));
        secure_zero(key2, sizeof(key2));
        ekm_upsert(key_id, kt->name, PAYHSM_KEY_LEN, lmk_sch, kcv, kt->exportable, cryptogram);
        ekm_save();
    }
    secure_zero(zmk, sizeof(zmk));
    secure_zero(key, sizeof(key));

    char data[HSM_RAW_BUF];
    snprintf(data, sizeof(data), "%s%s%s%s",
             blk_lmk, blk_zmk, kcv, kcv);

    char enc32[33];
    memcpy(enc32, blk_zmk + 1, 32);
    enc32[32] = '\0';

    char je[512];
    snprintf(je, sizeof(je),
             ",\"a0Mode\":\"1\",\"keyId\":\"%s\",\"keyType\":\"%s\","
             "\"cryptogram\":\"%s\",\"keyUnderLmk\":\"%.33s\","
             "\"keyUnderZmk\":\"%.33s\",\"exportedKey\":\"%s\","
             "\"kcv\":\"%s\",\"kcvZmk\":\"%s\",\"exportable\":\"%s\","
             "\"mode\":\"PAYSHIELD_COMPAT\"",
             key_id, kt->name, cryptogram, blk_lmk, blk_zmk, enc32, kcv, kcv, exp_flag);

    audit_log("KEY_GENERATED+EXPORT [PS/Thales] A0/1");
    hsm_ok_json(hdr, "A1", data, je, out, n);
}

/*
 * [PS-INSPIRED] A0 simple — génération seule
 * Request : [HDR:4][A0:2][KEY_TYPE:3][KEY_SCHEME:1]
 */
static void handle_A0_payshield_simple(const char *hdr, const char *cmd_str, size_t cmdlen,
                                         char *out, size_t n) {
    if (cmdlen < 10) {
        hsm_err(hdr, "A1", HSM_ERR_FORMAT,
                "[PS] A0: [HDR:4][A0:2][KEY_TYPE:3][KEY_SCHEME:1] min 10 chars", out, n);
        return;
    }

    char ktype_code[4], kscheme[2];
    strncpy(ktype_code, cmd_str + 6, 3); ktype_code[3] = '\0';
    for (int i = 0; ktype_code[i]; i++)
        ktype_code[i] = (char)toupper((unsigned char)ktype_code[i]);
    kscheme[0] = (char)toupper((unsigned char)cmd_str[9]);
    kscheme[1] = '\0';

    const hsm_keytype_def_t *kt = ktype_by_code(ktype_code);
    if (!kt) {
        hsm_err(hdr, "A1", HSM_ERR_KEY_TYPE,
                "[PS] A0: KEY_TYPE inconnu — voir table KEY_TYPE_TABLE", out, n);
        return;
    }
    if (!valid_scheme(kscheme[0])) {
        hsm_err(hdr, "A1", HSM_ERR_KEY_SCHEME,
                "[PS] A0: KEY_SCHEME invalide (U/T/X/Y/Z/R/S)", out, n);
        return;
    }

    uint8_t key[PAYHSM_KEY_LEN];
    if (RAND_bytes(key, PAYHSM_KEY_LEN) != 1) {
        hsm_err(hdr, "A1", HSM_ERR_CRYPTO, "[PS] A0: RAND_bytes echec", out, n);
        return;
    }

    char cryptogram[256];
    if (payhsm_wrap_lmk_gcm_hex(key, cryptogram) != 0) {
        secure_zero(key, sizeof(key));
        hsm_err(hdr, "A1", HSM_ERR_CRYPTO, "[PS] A0: LMK wrap echec", out, n);
        return;
    }

    char kcv[7]; calculate_kcv(key, PAYHSM_KEY_LEN, kcv);
    secure_zero(key, sizeof(key));

    ekm_ensure();
    char key_id[EKM_KEY_ID_LEN];
    ekm_gen_id(kt->name, key_id);

    uint8_t key2[PAYHSM_KEY_LEN], lmk[32];
    if (payhsm_unwrap_lmk_gcm_hex(cryptogram, key2) == 0 &&
        recompose_for_op(lmk) == 0) {
        vault_store_16(lmk, key2, kt->name, "", kcv);
        secure_zero(lmk, sizeof(lmk));
        secure_zero(key2, sizeof(key2));
        ekm_upsert(key_id, kt->name, PAYHSM_KEY_LEN, kscheme, kcv, kt->exportable, cryptogram);
        ekm_save();
    }

    char data[HSM_RAW_BUF];
    snprintf(data, sizeof(data), "%s%s%s", kscheme, cryptogram, kcv);

    char je[256];
    snprintf(je, sizeof(je),
             ",\"keyId\":\"%s\",\"keyType\":\"%s\",\"scheme\":\"%s\","
             "\"kcv\":\"%s\",\"mode\":\"PAYSHIELD_COMPAT\"",
             key_id, kt->name, kscheme, kcv);

    {
        char al[96];
        snprintf(al, sizeof(al), "KEY_GENERATED [PS] type=%s id=%s KCV=%s",
                 kt->name, key_id, kcv);
        audit_log(al);
    }

    hsm_ok_json(hdr, "A1", data, je, out, n);
}

/*
 * [Thales] A0 mode 0 — génération seule (pas d'export ZMK)
 * Request : [HDR:4][A0:2][0][KEY_TYPE:3][KEY_SCHEME:1][LMK_ID:2]
 *           ex. 0001A00001U00 (ZPK type 001)
 */
static void handle_A0_payshield_mode0(const char *hdr, const char *cmd_str, size_t cmdlen,
                                        char *out, size_t n) {
    if (cmdlen < 13) {
        hsm_err(hdr, "A1", HSM_ERR_FORMAT,
                "[PS] A0 mode 0: 0001A00001U00 (13 car.) — TYPE sur 3 chiffres (001=ZPK)", out, n);
        return;
    }
    char ktype_code[4], kscheme[2];
    strncpy(ktype_code, cmd_str + 7, 3); ktype_code[3] = '\0';
    for (int i = 0; ktype_code[i]; i++)
        ktype_code[i] = (char)toupper((unsigned char)ktype_code[i]);
    kscheme[0] = (char)toupper((unsigned char)cmd_str[10]);
    kscheme[1] = '\0';
    /* LMK identifier optionnel : positions 11-12 (ex. 00) */

    const hsm_keytype_def_t *kt = ktype_by_code(ktype_code);
    if (!kt) {
        char hint[128];
        snprintf(hint, sizeof(hint),
                 "[PS] A0/0: KEY_TYPE '%.3s' inconnu — format: 0001A00001U00 "
                 "(HDR+A0+0+TYPE3+SCHEME+LMK_ID00), ex. ZPK=001",
                 ktype_code);
        hsm_err(hdr, "A1", HSM_ERR_KEY_TYPE, hint, out, n);
        return;
    }
    if (!valid_scheme(kscheme[0])) {
        hsm_err(hdr, "A1", HSM_ERR_KEY_SCHEME, "[PS] A0/0: scheme invalide", out, n);
        return;
    }

    uint8_t key[PAYHSM_KEY_LEN];
    if (RAND_bytes(key, PAYHSM_KEY_LEN) != 1) {
        hsm_err(hdr, "A1", HSM_ERR_CRYPTO, "[PS] A0/0: RAND_bytes echec", out, n);
        return;
    }
    char cryptogram[256];
    if (payhsm_wrap_lmk_gcm_hex(key, cryptogram) != 0) {
        secure_zero(key, sizeof(key));
        hsm_err(hdr, "A1", HSM_ERR_CRYPTO, "[PS] A0/0: LMK wrap echec", out, n);
        return;
    }
    char kcv[7]; calculate_kcv(key, PAYHSM_KEY_LEN, kcv);
    char blk_lmk[PAYHSM_THALES_BLOCK_LEN + 1];
    if (payhsm_thales_block_wrap_lmk(key, kscheme[0], blk_lmk) != PAYHSM_RC_OK) {
        secure_zero(key, sizeof(key));
        hsm_err(hdr, "A1", HSM_ERR_CRYPTO, "[PS] A0/0: bloc LMK echec", out, n);
        return;
    }
    secure_zero(key, sizeof(key));

    ekm_ensure();
    char key_id[EKM_KEY_ID_LEN];
    ekm_gen_id(kt->name, key_id);
    uint8_t key2[PAYHSM_KEY_LEN], lmk[32];
    if (payhsm_unwrap_lmk_gcm_hex(cryptogram, key2) == 0 && recompose_for_op(lmk) == 0) {
        vault_store_16(lmk, key2, kt->name, "", kcv);
        secure_zero(lmk, sizeof(lmk));
        secure_zero(key2, sizeof(key2));
        ekm_upsert(key_id, kt->name, PAYHSM_KEY_LEN, kscheme, kcv, kt->exportable, cryptogram);
        ekm_save();
    }

    char data[HSM_RAW_BUF];
    snprintf(data, sizeof(data), "%s%s", blk_lmk, kcv);
    char je[256];
    snprintf(je, sizeof(je),
             ",\"a0Mode\":\"0\",\"keyId\":\"%s\",\"keyType\":\"%s\","
             "\"cryptogram\":\"%s\",\"keyUnderLmk\":\"%.33s\",\"kcv\":\"%s\","
             "\"mode\":\"PAYSHIELD_COMPAT\"",
             key_id, kt->name, cryptogram, blk_lmk, kcv);
    audit_log("KEY_GENERATED [PS/Thales] A0/0");
    hsm_ok_json(hdr, "A1", data, je, out, n);
}

static void handle_A0_payshield(const char *hdr, const char *cmd_str, size_t cmdlen,
                                  char *out, size_t n) {
    if (cmdlen >= 11 && cmd_str[6] == '1')
        handle_A0_payshield_mode1(hdr, cmd_str, cmdlen, out, n);
    else if (cmdlen >= 11 && cmd_str[6] == '0')
        handle_A0_payshield_mode0(hdr, cmd_str, cmdlen, out, n);
    else
        handle_A0_payshield_simple(hdr, cmd_str, cmdlen, out, n);
}

static int a6_is_thales_type_first(const char *cmd_str, size_t cmdlen) {
    return cmdlen >= 9 &&
           isdigit((unsigned char)cmd_str[6]) &&
           isdigit((unsigned char)cmd_str[7]) &&
           isxdigit((unsigned char)cmd_str[8]);
}

static int a6_import_core(const char *hdr, char key_sch, const uint8_t zmk[PAYHSM_KEY_LEN],
                          const char *key_blk33, const char *kcv_expected,
                          char *out, size_t n) {
    uint8_t key_clear[PAYHSM_KEY_LEN];
    if (payhsm_thales_block_unwrap(zmk, key_blk33, key_clear) != PAYHSM_RC_OK) {
        hsm_err(hdr, "A7", HSM_ERR_CRYPTO, "[PS] A6: cle sous ZMK dechiffrement echec", out, n);
        return -1;
    }

    char kcv[7];
    calculate_kcv(key_clear, PAYHSM_KEY_LEN, kcv);

    if (kcv_expected && kcv_expected[0]) {
        char exp[7];
        size_t el = strlen(kcv_expected);
        for (size_t i = 0; i < el && i < 6; i++)
            exp[i] = (char)toupper((unsigned char)kcv_expected[i]);
        exp[el < 6 ? el : 6] = '\0';
        if (strcmp(kcv, exp) != 0) {
            secure_zero(key_clear, sizeof(key_clear));
            char msg[96];
            snprintf(msg, sizeof(msg),
                     "KCV mismatch attendu=%s calcule=%s", exp, kcv);
            hsm_err(hdr, "A7", HSM_ERR_KCV_FAIL, msg, out, n);
            return -1;
        }
    }

    char new_crypt[256];
    if (payhsm_wrap_lmk_gcm_hex(key_clear, new_crypt) != 0) {
        secure_zero(key_clear, sizeof(key_clear));
        hsm_err(hdr, "A7", HSM_ERR_CRYPTO, "[PS] A6: LMK wrap echec", out, n);
        return -1;
    }

    char blk_lmk[PAYHSM_THALES_BLOCK_LEN + 1];
    if (payhsm_thales_block_wrap_lmk(key_clear, key_sch, blk_lmk) != PAYHSM_RC_OK) {
        secure_zero(key_clear, sizeof(key_clear));
        hsm_err(hdr, "A7", HSM_ERR_CRYPTO, "[PS] A6: bloc LMK echec", out, n);
        return -1;
    }
    secure_zero(key_clear, sizeof(key_clear));

    audit_log("KEY_IMPORTED [PS/Thales] A6");
    char data[HSM_RAW_BUF];
    snprintf(data, sizeof(data), "%s%s", blk_lmk, kcv);
    char je[256];
    snprintf(je, sizeof(je),
             ",\"kcv\":\"%s\",\"cryptogram\":\"%s\",\"keyUnderLmk\":\"%.33s\","
             "\"mode\":\"PAYSHIELD_COMPAT\"",
             kcv, new_crypt, blk_lmk);
    hsm_ok_json(hdr, "A7", data, je, out, n);
    return 0;
}

/*
 * [Thales-style] A6 — Import Key
 * [HDR][A6][KEY_TYPE:3][ZMK:88|33][KEY_ZMK:33][KEY_SCH:1][ZMK_SCH:1][KCV:6]
 * Legacy : [HDR][A6][ZMK_SCH][ZMK:88][KEY_SCH][KEY:32hex]
 */
static void handle_A6_payshield(const char *hdr, const char *cmd_str, size_t cmdlen,
                                  char *out, size_t n) {
    if (a6_is_thales_type_first(cmd_str, cmdlen)) {
        if (cmdlen < 83) {
            hsm_err(hdr, "A7", HSM_ERR_FORMAT,
                    "[PS] A6 Thales: [TYPE:3][ZMK][KEY:33][SCH][SCH][KCV] min 83", out, n);
            return;
        }
        char ktype_code[4];
        strncpy(ktype_code, cmd_str + 6, 3); ktype_code[3] = '\0';
        if (!ktype_by_code(ktype_code)) {
            hsm_err(hdr, "A7", HSM_ERR_KEY_TYPE, "[PS] A6: KEY_TYPE inconnu", out, n);
            return;
        }

        size_t zmk_off = 9;
        size_t zmk_len = (cmdlen >= zmk_off + PAYHSM_GCM_BLOB_HEX + 40)
                         ? PAYHSM_GCM_BLOB_HEX : PAYHSM_THALES_BLOCK_LEN;
        size_t key_off = zmk_off + zmk_len;

        uint8_t zmk[PAYHSM_KEY_LEN];
        if (parse_zmk_under_lmk_field(cmd_str + zmk_off, zmk_len, zmk) != PAYHSM_RC_OK) {
            hsm_err(hdr, "A7", HSM_ERR_CRYPTO, "[PS] A6: ZMK dechiffrement echec", out, n);
            return;
        }

        char key_blk[PAYHSM_THALES_BLOCK_LEN + 1];
        strncpy(key_blk, cmd_str + key_off, PAYHSM_THALES_BLOCK_LEN);
        key_blk[PAYHSM_THALES_BLOCK_LEN] = '\0';

        char key_sch = (char)toupper((unsigned char)cmd_str[key_off + PAYHSM_THALES_BLOCK_LEN]);
        char kcv_exp[7] = "";
        if (cmdlen >= key_off + PAYHSM_THALES_BLOCK_LEN + 2 + 6)
            strncpy(kcv_exp, cmd_str + key_off + PAYHSM_THALES_BLOCK_LEN + 2, 6);

        if (!valid_scheme(key_sch) || !valid_scheme(key_blk[0])) {
            secure_zero(zmk, sizeof(zmk));
            hsm_err(hdr, "A7", HSM_ERR_KEY_SCHEME, "[PS] A6: schema invalide", out, n);
            return;
        }

        a6_import_core(hdr, key_sch, zmk, key_blk, kcv_exp[0] ? kcv_exp : NULL, out, n);
        secure_zero(zmk, sizeof(zmk));
        return;
    }

    if (cmdlen < 128) {
        hsm_err(hdr, "A7", HSM_ERR_FORMAT,
                "[PS] A6 legacy: [ZMK_SCH][ZMK:88][KEY_SCH][KEY:32] = 128 min", out, n);
        return;
    }

    char zmk_scheme[2], zmk_enc[89], key_scheme[2], key_blk[PAYHSM_THALES_BLOCK_LEN + 1];
    zmk_scheme[0] = (char)toupper((unsigned char)cmd_str[6]);
    zmk_scheme[1] = '\0';
    strncpy(zmk_enc, cmd_str + 7, 88); zmk_enc[88] = '\0';
    key_scheme[0] = (char)toupper((unsigned char)cmd_str[95]);
    key_scheme[1] = '\0';
    key_blk[0] = key_scheme[0];
    strncpy(key_blk + 1, cmd_str + 96, 32);
    key_blk[33] = '\0';

    uint8_t zmk[PAYHSM_KEY_LEN];
    if (payhsm_unwrap_lmk_gcm_hex(zmk_enc, zmk) != PAYHSM_RC_OK) {
        hsm_err(hdr, "A7", HSM_ERR_CRYPTO, "[PS] A6: ZMK dechiffrement echec", out, n);
        return;
    }
    a6_import_core(hdr, key_scheme[0], zmk, key_blk, NULL, out, n);
    secure_zero(zmk, sizeof(zmk));
}

/*
 * [PS-INSPIRED] A8 payShield-compat — Export Key under ZMK
 * Request (complet): [HDR:4][A8:2][ZMK_SCHEME:1][ZMK_LMK:88][KEY_TYPE:3][KEY_SCHEME:1][KEY_LMK:88] = 187
 * Request (auto)  : [HDR:4][A8:2][L:1][KEY_TYPE:3][KEY_SCHEME:1][KEY_LMK:88] = 99 — ZMK/TMK depuis coffre
 * Response: [HDR:4][A9:2][00:2][KEY_UNDER_ZMK:33][KCV:6]
 */
static void a8_ps_export_core(const char *hdr, const char *zmk_enc,
                              const char *ktype_code, char kscheme,
                              const char *key_enc, char *out, size_t n) {
    if (payhsm_validate_export_hierarchy(ktype_code) != PAYHSM_RC_OK) {
        hsm_err(hdr, "A9", HSM_ERR_KEY_TYPE,
                "[PS] A8: KEY_TYPE invalide pour export", out, n);
        return;
    }

    uint8_t zmk[PAYHSM_KEY_LEN], key_clear[PAYHSM_KEY_LEN];
    if (payhsm_unwrap_lmk_gcm_hex(zmk_enc, zmk) != PAYHSM_RC_OK) {
        hsm_err(hdr, "A9", HSM_ERR_CRYPTO, "[PS] A8: ZMK dechiffrement echec", out, n);
        return;
    }
    if (payhsm_unwrap_lmk_gcm_hex(key_enc, key_clear) != PAYHSM_RC_OK) {
        secure_zero(zmk, sizeof(zmk));
        hsm_err(hdr, "A9", HSM_ERR_CRYPTO, "[PS] A8: cle source dechiffrement echec", out, n);
        return;
    }

    uint8_t enc_under_zmk[PAYHSM_KEY_LEN];
    int ecb_rc = -1;
    {
        int outl = 0;
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (ctx) {
            EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, zmk, NULL);
            EVP_CIPHER_CTX_set_padding(ctx, 0);
            EVP_EncryptUpdate(ctx, enc_under_zmk, &outl, key_clear, PAYHSM_KEY_LEN);
            EVP_CIPHER_CTX_free(ctx);
            ecb_rc = (outl == PAYHSM_KEY_LEN) ? 0 : -1;
        }
    }
    if (ecb_rc != 0) {
        secure_zero(zmk, sizeof(zmk));
        secure_zero(key_clear, sizeof(key_clear));
        hsm_err(hdr, "A9", HSM_ERR_CRYPTO, "[PS] A8: ECB wrap sous ZMK echec", out, n);
        return;
    }

    char kcv[7];
    calculate_kcv(key_clear, PAYHSM_KEY_LEN, kcv);

    char blk_zmk[PAYHSM_THALES_BLOCK_LEN + 1];
    if (payhsm_thales_block_wrap(zmk, kscheme, key_clear, blk_zmk) != PAYHSM_RC_OK) {
        secure_zero(zmk, sizeof(zmk));
        secure_zero(key_clear, sizeof(key_clear));
        hsm_err(hdr, "A9", HSM_ERR_CRYPTO, "[PS] A8: bloc transport echec", out, n);
        return;
    }
    secure_zero(zmk, sizeof(zmk));
    secure_zero(key_clear, sizeof(key_clear));

    audit_log("KEY_EXPORTED [PS/Thales] A8");

    char data[HSM_RAW_BUF];
    snprintf(data, sizeof(data), "%s%s", blk_zmk, kcv);
    char enc32[33];
    memcpy(enc32, blk_zmk + 1, 32);
    enc32[32] = '\0';
    char je[256];
    snprintf(je, sizeof(je),
             ",\"exportedKey\":\"%s\",\"keyUnderZmk\":\"%.33s\",\"kcv\":\"%s\","
             "\"keyType\":\"%.3s\",\"mode\":\"PAYSHIELD_COMPAT\"",
             enc32, blk_zmk, kcv, ktype_code);
    hsm_ok_json(hdr, "A9", data, je, out, n);
}

static void handle_A8_payshield(const char *hdr, const char *cmd_str, size_t cmdlen,
                                  char *out, size_t n) {
    if (cmdlen > 6 && cmd_str[6] == '|') {
        handle_A8_ext(hdr, cmd_str, cmdlen, out, n);
        return;
    }

    /* Auto : ZMK/TMK depuis coffre — 0001A8L001U + KEY_88hex (99 car.) */
    if (cmdlen >= 99 && toupper((unsigned char)cmd_str[6]) == 'L') {
        char ktype_code[4], kscheme[2], key_enc[89], zmk_enc[89], tid[64];
        strncpy(ktype_code, cmd_str + 7, 3); ktype_code[3] = '\0';
        for (int i = 0; ktype_code[i]; i++)
            ktype_code[i] = (char)toupper((unsigned char)ktype_code[i]);
        kscheme[0] = (char)toupper((unsigned char)cmd_str[10]); kscheme[1] = '\0';
        strncpy(key_enc, cmd_str + 11, 88); key_enc[88] = '\0';
        if (!valid_scheme(kscheme[0])) {
            hsm_err(hdr, "A9", HSM_ERR_KEY_SCHEME, "[PS] A8/L: scheme invalide", out, n);
            return;
        }
        if (payhsm_ekm_lookup_transport_gcm(ktype_code, zmk_enc, tid) != PAYHSM_RC_OK) {
            hsm_err(hdr, "A9", HSM_ERR_KEY_TYPE,
                    "[PS] A8/L: ZMK/TMK absente du coffre — A4 ou STORE avant export", out, n);
            return;
        }
        char aline[96];
        snprintf(aline, sizeof(aline), "KEY_EXPORTED [PS/Thales] A8/L via=%s", tid);
        audit_log(aline);
        a8_ps_export_core(hdr, zmk_enc, ktype_code, kscheme[0], key_enc, out, n);
        return;
    }

    if (cmdlen < 187) {
        hsm_err(hdr, "A9", HSM_ERR_FORMAT,
                "[PS] A8: 187 car. (ZMK explicite) ou 99 car. 0001A8L001U+KEY_88 (ZMK coffre)",
                out, n);
        return;
    }

    char zmk_scheme[2], zmk_enc[89];
    char ktype_code[4], kscheme[2], key_enc[89];
    zmk_scheme[0] = (char)toupper((unsigned char)cmd_str[6]); zmk_scheme[1] = '\0';
    strncpy(zmk_enc, cmd_str + 7, 88); zmk_enc[88] = '\0';
    strncpy(ktype_code, cmd_str + 95, 3); ktype_code[3] = '\0';
    for (int i = 0; ktype_code[i]; i++) ktype_code[i] = (char)toupper((unsigned char)ktype_code[i]);
    kscheme[0] = (char)toupper((unsigned char)cmd_str[98]); kscheme[1] = '\0';
    strncpy(key_enc, cmd_str + 99, 88); key_enc[88] = '\0';

    a8_ps_export_core(hdr, zmk_enc, ktype_code, kscheme[0], key_enc, out, n);
}

/*
 * [PS-INSPIRED] KA payShield-compat — Generate KCV
 * Request: [HDR:4][KA:2][KEY_TYPE:3][KEY_SCHEME:1][KEY_UNDER_LMK:88]
 *           → total: 4+2+3+1+88 = 98 chars
 * Response: [HDR:4][KB:2][00:2][KCV:6]
 */
static void handle_KA_payshield(const char *hdr, const char *cmd_str, size_t cmdlen,
                                  char *out, size_t n) {
    if (cmdlen < 98) {
        hsm_err(hdr, "KB", HSM_ERR_FORMAT,
                "[PS] KA: [HDR:4][KA:2][KEY_TYPE:3][KEY_SCH:1][KEY_LMK:88] = 98 chars min",
                out, n);
        return;
    }

    char ktype_code[4], kscheme[2], key_enc[89];
    strncpy(ktype_code, cmd_str + 6, 3); ktype_code[3] = '\0';
    for (int i = 0; ktype_code[i]; i++) ktype_code[i] = (char)toupper((unsigned char)ktype_code[i]);
    kscheme[0] = (char)toupper((unsigned char)cmd_str[9]); kscheme[1] = '\0';
    strncpy(key_enc, cmd_str + 10, 88); key_enc[88] = '\0';

    uint8_t key_clear[PAYHSM_KEY_LEN];
    if (payhsm_unwrap_lmk_gcm_hex(key_enc, key_clear) != PAYHSM_RC_OK) {
        hsm_err(hdr, "KB", HSM_ERR_CRYPTO, "[PS] KA: dechiffrement LMK echec", out, n);
        return;
    }

    char kcv[7]; calculate_kcv(key_clear, PAYHSM_KEY_LEN, kcv);
    secure_zero(key_clear, sizeof(key_clear));

    audit_log("KCV_GENERATED [PS]");

    char je[128];
    snprintf(je, sizeof(je), ",\"kcv\":\"%s\",\"mode\":\"PAYSHIELD_COMPAT\"", kcv);
    hsm_ok_json(hdr, "KB", kcv, je, out, n);
    (void)ktype_code; (void)kscheme;
}

/*
 * [PS-INSPIRED] BU payShield-compat — Generate / Verify KCV
 * SÉCURITÉ : BU accepte uniquement une clé SOUS LMK (jamais en clair).
 * C'est le comportement correct d'un HSM bancaire.
 *
 * Mode G (génération) :
 *   Request : [HDR:4][BU:2][G:1][KEY_TYPE:3][KEY_SCHEME:1][KEY_UNDER_LMK:88] = 99 chars
 *   Response: [HDR:4][BV:2][00:2][KCV:6]
 *
 * Mode V (vérification) :
 *   Request : [HDR:4][BU:2][V:1][KEY_TYPE:3][KEY_SCHEME:1][KEY_UNDER_LMK:88][KCV:6] = 105 chars
 *   Response OK:  [HDR:4][BV:2][00:2]
 *   Response ERR: [HDR:4][BV:2][07:2]EXPECTED=XX|COMPUTED=YY
 */
static void handle_BU_payshield(const char *hdr, const char *cmd_str, size_t cmdlen,
                                  char *out, size_t n) {
    if (cmdlen < 99) {
        hsm_err(hdr, "BV", HSM_ERR_FORMAT,
                "[PS] BU: [G/V][KEY_TYPE:3][KEY_SCH:1][KEY_LMK:88][KCV_OPT:6]",
                out, n);
        return;
    }

    char mode = (char)toupper((unsigned char)cmd_str[6]);
    if (mode != 'G' && mode != 'V') {
        hsm_err(hdr, "BV", HSM_ERR_FORMAT, "[PS] BU: mode G ou V attendu", out, n);
        return;
    }

    /* KEY_TYPE:3, KEY_SCHEME:1, KEY_UNDER_LMK:88 */
    char key_enc[89];
    strncpy(key_enc, cmd_str + 11, 88); key_enc[88] = '\0';

    uint8_t key_clear[PAYHSM_KEY_LEN];
    if (payhsm_unwrap_lmk_gcm_hex(key_enc, key_clear) != PAYHSM_RC_OK) {
        hsm_err(hdr, "BV", HSM_ERR_CRYPTO,
                "[PS] BU: dechiffrement LMK echec — cle sous LMK invalide", out, n);
        return;
    }

    char computed_kcv[7]; calculate_kcv(key_clear, PAYHSM_KEY_LEN, computed_kcv);
    secure_zero(key_clear, sizeof(key_clear));

    if (mode == 'G') {
        audit_log("KCV_GENERATED [PS] BU (cle sous LMK)");
        char je[128];
        snprintf(je, sizeof(je), ",\"kcv\":\"%s\",\"mode\":\"PAYSHIELD_COMPAT\"", computed_kcv);
        hsm_ok_json(hdr, "BV", computed_kcv, je, out, n);
    } else {
        /* Vérification : extraire le KCV attendu */
        if (cmdlen < 105) {
            hsm_err(hdr, "BV", HSM_ERR_FORMAT,
                    "[PS] BU V: [KEY_UNDER_LMK:88][KCV:6] = 105 chars min", out, n);
            return;
        }
        char expected_kcv[7];
        strncpy(expected_kcv, cmd_str + 99, 6); expected_kcv[6] = '\0';
        for (int i = 0; expected_kcv[i]; i++)
            expected_kcv[i] = (char)toupper((unsigned char)expected_kcv[i]);

        if (strncasecmp(computed_kcv, expected_kcv, 6) == 0) {
            audit_log("KCV_VERIFIED [PS] BU OK");
            char je[128];
            snprintf(je, sizeof(je), ",\"kcvMatch\":true,\"kcv\":\"%s\","
                     "\"mode\":\"PAYSHIELD_COMPAT\"", computed_kcv);
            hsm_ok_json(hdr, "BV", "", je, out, n);
        } else {
            audit_log("KCV_MISMATCH [PS] BU FAIL");
            char data[64];
            snprintf(data, sizeof(data), "EXPECTED=%s|COMPUTED=%s",
                     expected_kcv, computed_kcv);
            char je[128];
            snprintf(je, sizeof(je),
                     ",\"kcvMatch\":false,\"expected\":\"%s\",\"computed\":\"%s\","
                     "\"mode\":\"PAYSHIELD_COMPAT\"", expected_kcv, computed_kcv);
            /* Écriture directe avec erreur 07 */
            char raw[64];
            snprintf(raw, sizeof(raw), "%sBV" HSM_ERR_KCV_FAIL "%s", hdr, data);
            snprintf(out, n,
                "{\"rc\":-1,\"rawResponse\":\"%s\",\"errorCode\":\"07\","
                "\"kcvMatch\":false,\"expected\":\"%s\",\"computed\":\"%s\","
                "\"mode\":\"PAYSHIELD_COMPAT\"}",
                raw, expected_kcv, computed_kcv);
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
   7. REGISTRY DES COMMANDES
   ═══════════════════════════════════════════════════════════════════════════ */

typedef void (*hsm_handler_fn)(const char *hdr, const char *cmd_str,
                                size_t cmdlen, char *out, size_t n);

typedef struct {
    char           cmd[4];       /* Code commande : "A0", "B2"… */
    char           resp[4];      /* Code réponse  : "A1", "B3"… */
    char           desc[64];     /* Description */
    int            min_len_int;  /* Longueur min trame INTERNAL (0=pas de vérification) */
    int            min_len_ps;   /* Longueur min trame PAYSHIELD */
    int            requires_init;/* 1 = LMK obligatoire */
    hsm_handler_fn handler_int;  /* Handler mode INTERNAL (peut être NULL) */
    hsm_handler_fn handler_ps;   /* Handler mode PAYSHIELD (NULL=même qu'internal) */
} hsm_cmd_entry_t;

/* Déclarations forward des handlers existants (définis dans payhsm-cmds.c + payhsm-keymgr.c) */
/* INTERNAL handlers */
static void _int_A0(const char *h, const char *s, size_t l, char *o, size_t n);
static void _int_A4(const char *h, const char *s, size_t l, char *o, size_t n);
static void _int_A6(const char *h, const char *s, size_t l, char *o, size_t n);
static void _int_A8(const char *h, const char *s, size_t l, char *o, size_t n);
static void _int_B0(const char *h, const char *s, size_t l, char *o, size_t n);
static void _int_B2(const char *h, const char *s, size_t l, char *o, size_t n);
static void _int_BS(const char *h, const char *s, size_t l, char *o, size_t n);
static void _int_BU(const char *h, const char *s, size_t l, char *o, size_t n);
static void _int_BW(const char *h, const char *s, size_t l, char *o, size_t n);
static void _int_CS(const char *h, const char *s, size_t l, char *o, size_t n);
static void handle_CA(const char *h, const char *s, size_t l, char *o, size_t n);
static void handle_CC(const char *h, const char *s, size_t l, char *o, size_t n);
static void _int_K8(const char *h, const char *s, size_t l, char *o, size_t n);
static void _int_KA(const char *h, const char *s, size_t l, char *o, size_t n);
static void _int_KA_wire(const char *h, const char *s, size_t l, char *o, size_t n);
static void _int_N0(const char *h, const char *s, size_t l, char *o, size_t n);
static void _int_NC(const char *h, const char *s, size_t l, char *o, size_t n);
static void _int_NE(const char *h, const char *s, size_t l, char *o, size_t n);
static void _int_NI(const char *h, const char *s, size_t l, char *o, size_t n);
static void _int_NO(const char *h, const char *s, size_t l, char *o, size_t n);

/* Tableau du registre — source unique de vérité pour toutes les commandes */
static const hsm_cmd_entry_t HSM_CMD_TABLE[] = {
    /* cmd  resp  description                      min_int min_ps init  handler_int    handler_ps */
    { "A0", "A1", "Generate Key",                       13,   10,   1,  _int_A0,       handle_A0_payshield },
    { "A4", "A5", "Form Key from Components",            0,    0,   1,  _int_A4,       NULL },
    { "A6", "A7", "Import Key",                        128,   83,   1,  _int_A6,       handle_A6_payshield },
    { "A8", "A9", "Export Key",                         97,   99,   1,  _int_A8,       handle_A8_payshield },
    { "B0", "B1", "Translate Key Scheme",                0,    0,   1,  _int_B0,       NULL },
    { "B2", "B3", "Echo Command",                        6,    6,   0,  _int_B2,       NULL },
    { "BS", "BT", "Clear Key Change Storage",            6,    6,   0,  _int_BS,       NULL },
    { "BU", "BV", "Generate/Verify KCV",                 8,   99,   1,  _int_BU,       handle_BU_payshield },
    { "BW", "BX", "Re-wrap Vault under LMK",             6,    6,   1,  _int_BW,       NULL },
    { "CA", "CB", "Translate PIN block TPK->ZPK",      198,  198,   1,  handle_CA,     handle_CA },
    { "CC", "CD", "Translate PIN block ZPK->ZPK",      198,  198,   1,  handle_CC,     handle_CC },
    { "CS", "CT", "Modify Key Block Header",             0,    0,   1,  _int_CS,       NULL },
    { "K8", "K9", "Export Key under KEK",                0,    0,   1,  _int_K8,       NULL },
    { "KA", "KB", "Generate KCV",                        6,   98,   1,  _int_KA,       handle_KA_payshield },
    { "N0", "N1", "Generate Random Number",              8,    8,   0,  _int_N0,       NULL },
    { "NC", "ND", "HSM Diagnostics",                     6,    6,   0,  _int_NC,       NULL },
    { "NE", "NF", "Generate Key Components",             0,    0,   1,  _int_NE,       NULL },
    { "NI", "NJ", "Network Information",                 6,    6,   0,  _int_NI,       NULL },
    { "NO", "NP", "HSM Status",                          6,    6,   0,  _int_NO,       NULL },
    { "",   "",   "",                                    0,    0,   0,  NULL,           NULL }, /* sentinelle */
};

/* ═══════════════════════════════════════════════════════════════════════════
   8. DISPATCHER PRINCIPAL
   Remplace l'if-else chain de 440 lignes.
   ═══════════════════════════════════════════════════════════════════════════ */
static void hsm_dispatch_wire(const char *hdr, const char *cmd_str,
                               size_t cmdlen, char *out, size_t n) {
    /* Extraire le code commande (déjà uppercase chez l'appelant) */
    char code[3];
    strncpy(code, cmd_str + 4, 2); code[2] = '\0';
    for (int i = 0; code[i]; i++)
        if (code[i] >= 'a' && code[i] <= 'z') code[i] = (char)(code[i] - 32);

    /* Chercher dans le registre */
    for (int i = 0; HSM_CMD_TABLE[i].cmd[0]; i++) {
        if (strcmp(HSM_CMD_TABLE[i].cmd, code) != 0) continue;

        const hsm_cmd_entry_t *e = &HSM_CMD_TABLE[i];

        /* Vérification LMK */
        if (e->requires_init && !payhsm_ctx()->initialized) {
            char al[64];
            snprintf(al, sizeof(al), "CMD %s refusee: LMK non initialisee", code);
            audit_log(al);
            hsm_err(hdr, e->resp, HSM_ERR_LMK_ABSENT,
                    "LMK non initialisee — demarrer le HSM depuis la console", out, n);
            return;
        }

        /* Sélection du handler selon le mode */
        hsm_handler_fn handler;
        int min_len;

        if (g_hsm_mode == HSM_MODE_PAYSHIELD && e->handler_ps != NULL) {
            handler = e->handler_ps;
            min_len = e->min_len_ps;
        } else {
            handler = e->handler_int;
            min_len = e->min_len_int;
        }

        if (!handler) {
            hsm_err(hdr, e->resp, HSM_ERR_UNSUPPORTED,
                    "Commande non implementee dans ce mode", out, n);
            return;
        }

        /* Vérification longueur minimale */
        if (min_len > 0 && (int)cmdlen < min_len) {
            char msg[96];
            snprintf(msg, sizeof(msg),
                     "%s: trame trop courte (%zu chars, min %d) — mode=%s",
                     code, cmdlen, min_len, hsm_mode_name(g_hsm_mode));
            hsm_err(hdr, e->resp, HSM_ERR_FORMAT, msg, out, n);
            return;
        }

        /* Appel du handler */
        handler(hdr, cmd_str, cmdlen, out, n);
        return;
    }

    /* Commande inconnue */
    char resp[8];
    snprintf(resp, sizeof(resp), "%.2sFE", code); /* Convention: XX → XXFE pour erreur */
    char msg[64];
    snprintf(msg, sizeof(msg), "Commande inconnue: %s", code);
    hsm_err(hdr, resp, HSM_ERR_UNSUPPORTED, msg, out, n);
}

/* ═══════════════════════════════════════════════════════════════════════════
   CA/CB et CC/CD — Translation de PIN block (réutilise translate_pin_block, pin.c)

   Modèle « clés sous LMK » : les deux clés sont des cryptogrammes GCM 88 hex.
   Format interne du simulateur (CE N'EST PAS un format Thales officiel) :

     CA req : [HDR:4][CA][TPK_SOUS_LMK:88][ZPK_SOUS_LMK:88][PIN_BLOCK:16hex]
     CB rép : [HDR:4][CB][00][PIN_BLOCK_SOUS_ZPK:16hex]
     CC req : [HDR:4][CC][ZPK_SRC_SOUS_LMK:88][ZPK_DST_SOUS_LMK:88][PIN_BLOCK:16hex]
     CD rép : [HDR:4][CD][00][PIN_BLOCK_SOUS_ZPK_DST:16hex]

   Un PAN optionnel peut suivre en fin de trame ; il est ignoré car
   translate_pin_block() re-chiffre le bloc tel quel (ISO-0 simplifié, voir pin.c).

   Sécurité : clés source/destination déchiffrées temporairement sous LMK,
   jamais loggées, zéroïsées immédiatement. Le PIN clair n'apparaît jamais. */
static void translate_pinblock_under_lmk(const char *hdr, const char *resp_cmd,
                                         const char *cmd_str, size_t cmdlen,
                                         char *out, size_t n) {
    if (cmdlen < 198) {
        hsm_err(hdr, resp_cmd, HSM_ERR_FORMAT,
                "Format: [HDR][CMD][SRC_LMK:88][DST_LMK:88][PINBLK:16]", out, n);
        return;
    }
    char src_blob[89], dst_blob[89], pinblk_hex[17];
    strncpy(src_blob,   cmd_str + 6,       88); src_blob[88]   = '\0';
    strncpy(dst_blob,   cmd_str + 6 + 88,  88); dst_blob[88]   = '\0';
    strncpy(pinblk_hex, cmd_str + 6 + 176, 16); pinblk_hex[16] = '\0';

    uint8_t src_key[PAYHSM_KEY_LEN], dst_key[PAYHSM_KEY_LEN];
    uint8_t pin_in[8], pin_out[8];

    if (payhsm_unwrap_lmk_gcm_hex(src_blob, src_key) != PAYHSM_RC_OK) {
        hsm_err(hdr, resp_cmd, HSM_ERR_CRYPTO,
                "Cle source: dechiffrement LMK echec", out, n);
        return;
    }
    if (payhsm_unwrap_lmk_gcm_hex(dst_blob, dst_key) != PAYHSM_RC_OK) {
        secure_zero(src_key, sizeof(src_key));
        hsm_err(hdr, resp_cmd, HSM_ERR_CRYPTO,
                "Cle destination: dechiffrement LMK echec", out, n);
        return;
    }
    if (hex_decode(pinblk_hex, pin_in, 8) != 0) {
        secure_zero(src_key, sizeof(src_key));
        secure_zero(dst_key, sizeof(dst_key));
        hsm_err(hdr, resp_cmd, HSM_ERR_FORMAT,
                "PIN block invalide (16 hex attendus)", out, n);
        return;
    }

    int rc = translate_pin_block(pin_in, "", src_key, PAYHSM_KEY_LEN,
                                 dst_key, PAYHSM_KEY_LEN, pin_out);
    secure_zero(src_key, sizeof(src_key));
    secure_zero(dst_key, sizeof(dst_key));
    secure_zero(pin_in,  sizeof(pin_in));

    if (rc != 0) {
        secure_zero(pin_out, sizeof(pin_out));
        hsm_err(hdr, resp_cmd, HSM_ERR_CRYPTO,
                "Translation PIN block echec", out, n);
        return;
    }

    char out_hex[20];
    hex_encode(pin_out, 8, out_hex);
    secure_zero(pin_out, sizeof(pin_out));

    char je[96];
    snprintf(je, sizeof(je), ",\"pinBlockOut\":\"%s\"", out_hex);
    audit_log("PIN_TRANSLATED — bloc re-chiffre (cles src/dst sous LMK, PIN jamais expose)");
    hsm_ok_json(hdr, resp_cmd, out_hex, je, out, n);
}

static void handle_CA(const char *hdr, const char *cmd_str, size_t cmdlen,
                      char *out, size_t n) {   /* TPK → ZPK */
    translate_pinblock_under_lmk(hdr, "CB", cmd_str, cmdlen, out, n);
}
static void handle_CC(const char *hdr, const char *cmd_str, size_t cmdlen,
                      char *out, size_t n) {   /* ZPK → ZPK */
    translate_pinblock_under_lmk(hdr, "CD", cmd_str, cmdlen, out, n);
}

/* ═══════════════════════════════════════════════════════════════════════════
   9. WRAPPERS _int_* — Adaptateurs vers les handlers existants
   Ces fonctions font le pont entre la nouvelle signature uniforme
   (handler_fn) et les handlers existants dans payhsm-cmds.c / payhsm-keymgr.c.
   ═══════════════════════════════════════════════════════════════════════════ */

/* A0 internal : wrapper vers le code existant dans api_hsm_cmd_raw */
static void _int_A0(const char *hdr, const char *cmd_str, size_t cmdlen,
                    char *out, size_t n) {
    /* Format étendu pipe : 0001A0|TYPE|LEN|SCHEME|EXPORT */
    if (cmdlen > 6 && cmd_str[6] == '|') {
        handle_A0_ext(hdr, cmd_str, cmdlen, out, n);
        return;
    }
    /* Format wire classique : 0001A01001U */
    if (cmdlen < 11) {
        hsm_err(hdr, "A1", HSM_ERR_FORMAT,
                "A0 INTERNAL: [HDR:4][A0:2][KEYLEN:2][KEYTYPE:2][SCHEME:1] = 11 chars", out, n);
        return;
    }
    char keylen_hex[3], keytype_hex[3], schema[2];
    strncpy(keylen_hex,  cmd_str + 6, 2);  keylen_hex[2]  = '\0';
    strncpy(keytype_hex, cmd_str + 8, 2);  keytype_hex[2] = '\0';
    schema[0] = cmd_str[10]; schema[1] = '\0';
    if (schema[0] >= 'a' && schema[0] <= 'z') schema[0] = (char)(schema[0] - 32);

    /* Le code wire 2 chars (01..07) doit être converti en nom de clé avant
       le stockage vault, sinon parse_key_type() ne matche pas et tout finit en ZMK. */
    const char *keytype_name = keytype_hex_to_name(keytype_hex);

    unsigned int keylen_val = 0;
    sscanf(keylen_hex, "%2x", &keylen_val);
    if (keylen_val != 16 && keylen_val != 24 && keylen_val != 32) {
        hsm_err(hdr, "A1", HSM_ERR_KEYLEN,
                "A0: taille invalide (0x10=16, 0x18=24, 0x20=32)", out, n);
        return;
    }

    uint8_t key[32];
    if (RAND_bytes(key, (int)keylen_val) != 1) {
        hsm_err(hdr, "A1", HSM_ERR_CRYPTO, "A0: RAND_bytes echec", out, n);
        return;
    }

    uint8_t lmk[32];
    if (check_integrity() != 0 || recompose_for_op(lmk) != 0) {
        secure_zero(key, sizeof(key));
        hsm_err(hdr, "A1", HSM_ERR_LMK_ABSENT, "A0: LMK indisponible", out, n);
        return;
    }

    size_t blob_len = LMK_BLOB_OVERHEAD + keylen_val;
    uint8_t blob[LMK_MAX_BLOB_LEN];
    int rc = lmk_gcm_encrypt_n(lmk, key, keylen_val, blob);

    /* Vault storage pendant que lmk + key sont disponibles */
    char kcv[7]; calculate_kcv(key, keylen_val, kcv);
    if (rc == 0 && keylen_val == PAYHSM_KEY_LEN)
        vault_store_16(lmk, key, keytype_name, "", kcv);
    secure_zero(lmk, sizeof(lmk));

    if (rc != 0) {
        secure_zero(key, sizeof(key));
        hsm_err(hdr, "A1", HSM_ERR_CRYPTO, "A0: chiffrement GCM echec", out, n);
        return;
    }

    secure_zero(key, sizeof(key));

    char blobhex[LMK_MAX_BLOB_LEN * 2 + 1];
    hex_encode(blob, blob_len, blobhex);

    char data[HSM_RAW_BUF];
    snprintf(data, sizeof(data), "%s%s%s", schema, blobhex, kcv);

    char je[256];
    snprintf(je, sizeof(je),
        ",\"kcv\":\"%s\",\"cryptogram\":\"%s\",\"keyLen\":%u,"
        "\"keyType\":\"%s\",\"schema\":\"%s\","
        "\"hint\":\"IV(12)+TAG(16)+CT(%u) = %zu hex chars\"",
        kcv, blobhex, keylen_val, keytype_name, schema,
        keylen_val, blob_len * 2);

    {
        char al[80];
        snprintf(al, sizeof(al), "KEY_GENERATED [INT] type=%s len=%u KCV=%s",
                 keytype_name, keylen_val, kcv);
        audit_log(al);
    }
    hsm_ok_json(hdr, "A1", data, je, out, n);
}

static void _int_A4(const char *h, const char *s, size_t l, char *o, size_t n) {
    if (l <= 6 || s[6] != '|') {
        hsm_err(h, "A5", HSM_ERR_FORMAT, "A4: format |TYPE|SCHEME|NC|C1|C2|...", o, n);
        return;
    }
    char tmp_raw[HSM_RAW_BUF] = "", tmp_je[HSM_JSON_BUF] = "";
    handle_A4(h, s, l, tmp_raw, sizeof(tmp_raw), tmp_je, sizeof(tmp_je), o, n);
    if (!o[0]) hsm_ok_json(h, "A5", tmp_raw + 10, tmp_je, o, n);
}

static void _int_A6(const char *hdr, const char *cmd_str, size_t cmdlen,
                    char *out, size_t n) {
    if (cmdlen > 6 && cmd_str[6] == '|') {
        handle_A6_ext(hdr, cmd_str, cmdlen, out, n); return;
    }
    /* Wire format hérité — code existant préservé */
    if (cmdlen < 128) {
        hsm_err(hdr, "A7", HSM_ERR_FORMAT,
                "A6 INT: [HDR][A6][TYPE:2][U][ZMK:88][U][KEY:32] = 128 min", out, n);
        return;
    }
    char keytype_hex[3], zmk_enc[89], key_enc[33];
    strncpy(keytype_hex, cmd_str + 6, 2); keytype_hex[2] = '\0';
    strncpy(zmk_enc, cmd_str + 9, 88);   zmk_enc[88] = '\0';
    char key_schema = cmd_str[97];
    strncpy(key_enc, cmd_str + 98, 32);   key_enc[32] = '\0';

    /* Convertir le code wire 2 chars en nom de clé pour le stockage vault. */
    const char *keytype_name = keytype_hex_to_name(keytype_hex);

    uint8_t zmk[PAYHSM_KEY_LEN], key_clear[PAYHSM_KEY_LEN];
    if (payhsm_unwrap_lmk_gcm_hex(zmk_enc, zmk) != PAYHSM_RC_OK) {
        hsm_err(hdr, "A7", HSM_ERR_CRYPTO, "A6: ZMK dechiffrement echec", out, n);
        return;
    }
    if (payhsm_unwrap_ecb_hex(zmk, key_enc, key_clear) != PAYHSM_RC_OK) {
        secure_zero(zmk, sizeof(zmk));
        hsm_err(hdr, "A7", HSM_ERR_CRYPTO, "A6: cle sous ZMK echec", out, n);
        return;
    }
    secure_zero(zmk, sizeof(zmk));

    char new_blob[256];
    if (payhsm_wrap_lmk_gcm_hex(key_clear, new_blob) != PAYHSM_RC_OK) {
        secure_zero(key_clear, sizeof(key_clear));
        hsm_err(hdr, "A7", HSM_ERR_CRYPTO, "A6: LMK wrap echec", out, n);
        return;
    }

    char kcv[7]; calculate_kcv(key_clear, PAYHSM_KEY_LEN, kcv);

    uint8_t lmk[32];
    if (recompose_for_op(lmk) == 0) {
        vault_store_16(lmk, key_clear, keytype_name, "", kcv);
        secure_zero(lmk, sizeof(lmk));
    }
    secure_zero(key_clear, sizeof(key_clear));

    char key_schema_str[2] = { key_schema, '\0' };
    char data[HSM_RAW_BUF];
    snprintf(data, sizeof(data), "%s%s%s", key_schema_str, new_blob, kcv);
    char je[256];
    snprintf(je, sizeof(je), ",\"kcv\":\"%s\",\"cryptogram\":\"%s\","
             "\"keyType\":\"%s\"", kcv, new_blob, keytype_name);
    audit_log("KEY_IMPORTED [INT]");
    hsm_ok_json(hdr, "A7", data, je, out, n);
}

static void _int_A8(const char *hdr, const char *cmd_str, size_t cmdlen,
                    char *out, size_t n) {
    if (cmdlen > 6 && cmd_str[6] == '|') {
        handle_A8_ext(hdr, cmd_str, cmdlen, out, n); return;
    }
    if (cmdlen < 97) {
        hsm_err(hdr, "A9", HSM_ERR_FORMAT,
                "A8 INT: [HDR][A8][KEYLEN:2][FLAG:1][KEY_LMK:88] = 97 min", out, n);
        return;
    }
    char keylen_hex[3], flag[2], key_enc[89];
    strncpy(keylen_hex, cmd_str + 6, 2); keylen_hex[2] = '\0';
    flag[0] = (char)toupper((unsigned char)cmd_str[8]); flag[1] = '\0';
    strncpy(key_enc, cmd_str + 9, 88); key_enc[88] = '\0';

    /* FLAG V (clair) : uniquement mode LAB */
    if (flag[0] == 'V' && g_hsm_mode != HSM_MODE_LAB) {
        hsm_err(hdr, "A9", HSM_ERR_LAB_ONLY,
                "A8 flag V (cle claire) interdit hors mode LAB — PAYSHIELD recommande A8 payShield pour export", out, n);
        return;
    }

    uint8_t key_clear[PAYHSM_KEY_LEN];
    if (payhsm_unwrap_lmk_gcm_hex(key_enc, key_clear) != PAYHSM_RC_OK) {
        hsm_err(hdr, "A9", HSM_ERR_CRYPTO, "A8: dechiffrement LMK echec", out, n);
        return;
    }

    char kcv[7]; calculate_kcv(key_clear, PAYHSM_KEY_LEN, kcv);

    if (flag[0] == 'V') {
        char keyhex[33]; hex_encode(key_clear, PAYHSM_KEY_LEN, keyhex);
        secure_zero(key_clear, sizeof(key_clear));
        char data[HSM_RAW_BUF];
        snprintf(data, sizeof(data), "%s%s%s", keylen_hex, keyhex, kcv);
        char je[256];
        snprintf(je, sizeof(je), ",\"flag\":\"V\",\"kcv\":\"%s\","
                 "\"keyClear\":\"%s\",\"warning\":\"LAB_MODE_ONLY\"", kcv, keyhex);
        audit_log("A8 FLAG_V [LAB] cle temporairement exposee");
        hsm_ok_json(hdr, "A9", data, je, out, n);
    } else {
        secure_zero(key_clear, sizeof(key_clear));
        char data[HSM_RAW_BUF];
        snprintf(data, sizeof(data), "%s%s", keylen_hex, kcv);
        char je[128];
        snprintf(je, sizeof(je), ",\"flag\":\"H\",\"kcv\":\"%s\"", kcv);
        audit_log("A8 FLAG_H KCV consulte");
        hsm_ok_json(hdr, "A9", data, je, out, n);
    }
}

/* B0, BS, BU, BW, CS, K8, NE, NI, NO, NC, N0 — wrappers minces */
static void _int_B0(const char *h, const char *s, size_t l, char *o, size_t n) {
    if (l <= 6 || s[6] != '|') {
        hsm_err(h, "B1", HSM_ERR_FORMAT, "B0: format |KEY_ID|NEW_SCHEME", o, n); return;
    }
    char tr[HSM_RAW_BUF]="", je[HSM_JSON_BUF]="";
    handle_B0(h, s, l, tr, sizeof(tr), je, sizeof(je), o, n);
    if (!o[0]) hsm_ok_json(h, "B1", tr + 10, je, o, n);
}

static void _int_B2(const char *h, const char *s, size_t l, char *o, size_t n) {
    char tr[HSM_RAW_BUF]="", je[HSM_JSON_BUF]="";
    handle_B2_echo(h, s, l, tr, sizeof(tr), je, sizeof(je));
    if (!o[0]) hsm_ok_json(h, "B3", tr + 8, je, o, n);
}

static void _int_BS(const char *h, const char *s, size_t l, char *o, size_t n) {
    char tr[HSM_RAW_BUF]="", je[HSM_JSON_BUF]="";
    handle_BS(h, s, l, tr, sizeof(tr), je, sizeof(je), o, n);
    if (!o[0]) { char d[64]; snprintf(d,sizeof(d),"%s",tr+8); hsm_ok_json(h,"BT",d,je,o,n); }
}

static void _int_BU(const char *h, const char *s, size_t l, char *o, size_t n) {
    /* INTERNAL mode BU : accepte clé claire — marqué non-sécurisé */
    char tr[HSM_RAW_BUF]="", je[HSM_JSON_BUF]="";
    handle_BU_kcv(h, s, l, tr, sizeof(tr), je, sizeof(je), o, n);
    if (!o[0]) {
        /* BU/BV errors already written via EKM_ERR if needed */
        if (tr[0]) hsm_ok_json(h, "BV", tr + 8, je, o, n);
    }
}

static void _int_BW(const char *h, const char *s, size_t l, char *o, size_t n) {
    char tr[HSM_RAW_BUF]="", je[HSM_JSON_BUF]="";
    handle_BW(h, s, l, tr, sizeof(tr), je, sizeof(je), o, n);
    if (!o[0]) hsm_ok_json(h, "BX", tr + 8, je, o, n);
}

static void _int_CS(const char *h, const char *s, size_t l, char *o, size_t n) {
    if (l <= 6 || s[6] != '|') {
        hsm_err(h, "CT", HSM_ERR_FORMAT, "CS: format |KEY_ID|FIELD|VALUE", o, n); return;
    }
    char tr[HSM_RAW_BUF]="", je[HSM_JSON_BUF]="";
    handle_CS(h, s, l, tr, sizeof(tr), je, sizeof(je), o, n);
    if (!o[0]) hsm_ok_json(h, "CT", tr + 8, je, o, n);
}

static void _int_K8(const char *h, const char *s, size_t l, char *o, size_t n) {
    if (l <= 6 || s[6] != '|') {
        hsm_err(h, "K9", HSM_ERR_FORMAT, "K8: format |KEY_ID|KEK_ID|SCHEME", o, n); return;
    }
    char tr[HSM_RAW_BUF]="", je[HSM_JSON_BUF]="";
    handle_K8(h, s, l, tr, sizeof(tr), je, sizeof(je), o, n);
    if (!o[0]) hsm_ok_json(h, "K9", tr + 8, je, o, n);
}

static void _int_KA(const char *h, const char *s, size_t l, char *o, size_t n) {
    if (l > 6 && s[6] == '|') {
        /* Extended : |KEY_ID ou |RAW|ALGO|HEX */
        char tr[HSM_RAW_BUF]="", je[HSM_JSON_BUF]="";
        handle_KA(h, s, l, tr, sizeof(tr), je, sizeof(je), o, n);
        if (!o[0]) hsm_ok_json(h, "KB", tr + 8, je, o, n);
        return;
    }
    /* Wire format : [KA][KEYLEN:2][SCHEME:1][KEY:88] */
    _int_KA_wire(h, s, l, o, n);
}

static void _int_KA_wire(const char *hdr, const char *cmd_str, size_t cmdlen,
                          char *out, size_t n) {
    if (cmdlen < 97) {
        hsm_err(hdr, "KB", HSM_ERR_FORMAT,
                "KA wire: [HDR][KA][KEYLEN:2][SCHEME:1][KEY_LMK:88] = 97 chars", out, n);
        return;
    }
    char keylen_hex[3], scheme[2], key_enc[89];
    strncpy(keylen_hex, cmd_str + 6, 2); keylen_hex[2] = '\0';
    scheme[0] = (char)toupper((unsigned char)cmd_str[8]); scheme[1] = '\0';
    strncpy(key_enc, cmd_str + 9, 88); key_enc[88] = '\0';

    uint8_t key_clear[PAYHSM_KEY_LEN];
    if (payhsm_unwrap_lmk_gcm_hex(key_enc, key_clear) != PAYHSM_RC_OK) {
        hsm_err(hdr, "KB", HSM_ERR_CRYPTO, "KA: dechiffrement LMK echec", out, n);
        return;
    }
    char kcv[7]; calculate_kcv(key_clear, PAYHSM_KEY_LEN, kcv);
    secure_zero(key_clear, sizeof(key_clear));
    audit_log("KCV_GENERATED [INT] KA wire");

    char data[HSM_RAW_BUF];
    snprintf(data, sizeof(data), "%s%s%s", keylen_hex, scheme, kcv);
    char je[128];
    snprintf(je, sizeof(je), ",\"kcv\":\"%s\"", kcv);
    hsm_ok_json(hdr, "KB", data, je, out, n);
}

static void _int_N0(const char *h, const char *s, size_t l, char *o, size_t n) {
    char tr[HSM_RAW_BUF]="", je[HSM_JSON_BUF]="";
    handle_N0_random(h, s, l, tr, sizeof(tr), je, sizeof(je), o, n);
    if (!o[0]) hsm_ok_json(h, "N1", tr + 8, je, o, n);
}

static void _int_NC(const char *h, const char *s, size_t l, char *o, size_t n) {
    char tr[HSM_RAW_BUF]="", je[HSM_JSON_BUF]="";
    handle_NC_diagnostics(h, tr, sizeof(tr), je, sizeof(je));
    if (!o[0]) hsm_ok_json(h, "ND", tr + 8, je, o, n);
    (void)s; (void)l;
}

static void _int_NE(const char *h, const char *s, size_t l, char *o, size_t n) {
    if (l <= 6 || s[6] != '|') {
        hsm_err(h, "NF", HSM_ERR_FORMAT, "NE: format |TYPE|LEN|NC|STORE", o, n); return;
    }
    char tr[HSM_RAW_BUF]="", je[HSM_JSON_BUF]="";
    handle_NE(h, s, l, tr, sizeof(tr), je, sizeof(je), o, n);
    if (!o[0]) { /* rawResponse déjà dans tr */ snprintf(o, n, "{\"rc\":0,\"rawResponse\":\"%s\"%s}", tr, je); }
}

static void _int_NI(const char *h, const char *s, size_t l, char *o, size_t n) {
    char tr[HSM_RAW_BUF]="", je[HSM_JSON_BUF]="";
    handle_NI_network_info(h, tr, sizeof(tr), je, sizeof(je));
    if (!o[0]) hsm_ok_json(h, "NJ", tr + 8, je, o, n);
    (void)s; (void)l;
}

static void _int_NO(const char *h, const char *s, size_t l, char *o, size_t n) {
    char tr[HSM_RAW_BUF]="", je[HSM_JSON_BUF]="";
    handle_NO_status(h, tr, sizeof(tr), je, sizeof(je));
    if (!o[0]) hsm_ok_json(h, "NP", tr + 8, je, o, n);
    (void)s; (void)l;
}

/* ═══════════════════════════════════════════════════════════════════════════
   10. API ADMIN — Endpoint /api/hsm/mode pour changer le mode
   ═══════════════════════════════════════════════════════════════════════════ */
static void api_hsm_mode_get(char *out, size_t n) {
    snprintf(out, n,
        "{\"rc\":0,\"mode\":\"%s\",\"modeId\":%d,"
        "\"modes\":{\"1\":\"INTERNAL\",\"2\":\"PAYSHIELD_COMPAT\",\"3\":\"LAB\"},"
        "\"warning_payshield\":\"[PS-INSPIRED] Formats inspires payShield 10K — "
        "non conformes sans documentation officielle Thales.\","
        "\"warning_lab\":\"[LAB] Mode debug: A8 flag V actif — INTERDIT en production.\"}",
        hsm_mode_name(g_hsm_mode), (int)g_hsm_mode);
}

static void api_hsm_mode_set(const char *body, char *out, size_t n) {
    char mode_str[32] = {0};
    json_field(body, "mode", mode_str, sizeof(mode_str));
    hsm_mode_t new_mode;
    if (!strcmp(mode_str, "INTERNAL") || !strcmp(mode_str, "1"))
        new_mode = HSM_MODE_INTERNAL;
    else if (!strcmp(mode_str, "PAYSHIELD") || !strcmp(mode_str, "PAYSHIELD_COMPAT") || !strcmp(mode_str, "2"))
        new_mode = HSM_MODE_PAYSHIELD;
    else if (!strcmp(mode_str, "LAB") || !strcmp(mode_str, "3"))
        new_mode = HSM_MODE_LAB;
    else {
        snprintf(out, n,
            "{\"rc\":-1,\"message\":\"Mode invalide. Valeurs: INTERNAL, PAYSHIELD_COMPAT, LAB\"}");
        return;
    }
    hsm_mode_t old_mode = g_hsm_mode;
    g_hsm_mode = new_mode;
    {
        char al[64];
        snprintf(al, sizeof(al), "HSM_MODE_CHANGED %s -> %s",
                 hsm_mode_name(old_mode), hsm_mode_name(new_mode));
        audit_log(al);
    }
    if (new_mode == HSM_MODE_LAB) {
        snprintf(out, n,
            "{\"rc\":0,\"mode\":\"%s\",\"warning\":\"LAB MODE ACTIF — A8 flag V disponible — INTERDIT en production\"}",
            hsm_mode_name(new_mode));
    } else {
        snprintf(out, n,
            "{\"rc\":0,\"mode\":\"%s\",\"message\":\"Mode change avec succes\"}",
            hsm_mode_name(new_mode));
    }
}
