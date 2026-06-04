/*
 * payhsm-keymgr.c — Gestion des clés style Thales payShield 10K
 * Inclus dans payhsm-httpd.c après payhsm-cmds.c
 *
 * Nouvelles commandes (format étendu séparé par '|') :
 *   A0/A1  Generate Key         : 0001A0|TYPE|LEN|SCHEME|EXPORT
 *   A4/A5  Form Key Components  : 0001A4|TYPE|SCHEME|NC|C1|C2|...|Cn
 *   A6/A7  Import Key (ext)     : 0001A6|TTYPE|TID|KTYPE|SCHEME|ENC32HEX
 *   A8/A9  Export Key (ext)     : 0001A8|KEY_ID|TTYPE|TID|SCHEME
 *   B0/B1  Translate Scheme     : 0001B0|KEY_ID|NEW_SCHEME
 *   BS/BT  Clear Key Storage    : 0001BS
 *   BW/BX  Re-wrap under LMK   : 0001BW
 *   CS/CT  Modify Header        : 0001CS|KEY_ID|FIELD|VALUE
 *   K8/K9  Export under KEK     : 0001K8|KEY_ID|KEK_ID|SCHEME
 *   KA/KB  Generate KCV         : 0001KA|KEY_ID  ou  0001KA|RAW|ALGO|KEYHEX
 *   NE/NF  Generate Components  : 0001NE|TYPE|LEN|NC|STORE
 *
 * Détection format étendu : cmd_str[6] == '|'
 * Ancien format A0/A6/A8 conservé si cmd_str[6] != '|'
 *
 * Codes erreur payShield utilisés :
 *   00 OK  02 format  03 non-init  04 type invalide  05 crypto
 *   06 introuvable  07 KCV invalide  08 LMK absente  09 non-exportable
 *   10 schéma  11 composant  12 key block  13 transport introuvable
 *   99 erreur interne
 */

/* ═══════════════════════════════════════════════════════════════════════════
   1. COFFRE ÉTENDU — Métadonnées complètes par clé
   ═══════════════════════════════════════════════════════════════════════════ */

#define EKM_KEY_ID_LEN    32
#define EKM_KEY_TYPE_LEN   8
#define EKM_SCHEME_LEN     4
#define EKM_KCV_LEN        8
#define EKM_CRYPT_LEN    256  /* GCM blob hex — 88 chars pour AES-128 */
#define EKM_VAULT_MAX     64
#define EKM_VAULT_FILE   "ext_keys.vault"
#define EKM_NTYPES        12  /* compteurs d'ID par type */

typedef struct {
    char key_id[EKM_KEY_ID_LEN];
    char key_type[EKM_KEY_TYPE_LEN];
    int  key_len;       /* octets */
    char scheme[EKM_SCHEME_LEN];
    char kcv[EKM_KCV_LEN];
    int  exportable;    /* 1 = exportable */
    int  active;        /* 1 = active, 0 = retiré */
    long created_at;
    char cryptogram[EKM_CRYPT_LEN]; /* clé chiffrée sous LMK (GCM hex) */
} ekm_key_t;

typedef struct {
    ekm_key_t keys[EKM_VAULT_MAX];
    int       count;
    int       counters[EKM_NTYPES]; /* compteurs par type de clé */
    char      path[256];
    /* Stockage temporaire pour key-change */
    char      temp_id[EKM_KEY_ID_LEN];
    char      temp_crypt[EKM_CRYPT_LEN];
    int       temp_used;
} ekm_vault_t;

static ekm_vault_t g_ekm = {0};

/* ─ Table des types de clés ─ */
typedef struct {
    const char *name;
    int    min_len;
    int    max_len;
    int    def_export; /* exportable par défaut */
    int    idx;        /* indice dans counters[] */
} ekm_ktype_t;

static const ekm_ktype_t EKM_KTYPES[] = {
    {"ZMK", 16, 32, 1,  0},
    {"ZPK", 16, 16, 1,  1},
    {"TPK", 16, 16, 1,  2},
    {"TMK", 16, 32, 1,  3},
    {"CVK", 16, 32, 0,  4},
    {"PVK", 16, 16, 0,  5},
    {"TAK", 16, 16, 1,  6},
    {"ZAK", 16, 16, 1,  7},
    {"ZEK", 16, 32, 1,  8},
    {"KEK", 16, 32, 0,  9},
    {"BDK", 16, 32, 0, 10},
    {NULL,  0,  0,  0, 11},
};

static const ekm_ktype_t *ekm_ktype(const char *name) {
    for (int i = 0; EKM_KTYPES[i].name; i++)
        if (!strcmp(EKM_KTYPES[i].name, name)) return &EKM_KTYPES[i];
    return NULL;
}

/* ─ Persistence ─ */
static void ekm_save(void) {
    if (!g_ekm.path[0]) return;
    FILE *f = fopen(g_ekm.path, "wb");
    if (!f) return;
    fwrite(&g_ekm, sizeof(g_ekm), 1, f);
    fclose(f);
}

static void ekm_load(void) {
    const char *dir = payhsm_ctx()->data_dir;
    if (!dir || !dir[0]) return;
    snprintf(g_ekm.path, sizeof(g_ekm.path), "%s/" EKM_VAULT_FILE, dir);
    FILE *f = fopen(g_ekm.path, "rb");
    if (!f) return;
    fread(&g_ekm, sizeof(g_ekm), 1, f);
    fclose(f);
    /* Recalculer le path (peut avoir bougé) */
    snprintf(g_ekm.path, sizeof(g_ekm.path), "%s/" EKM_VAULT_FILE, dir);
}

static void ekm_ensure(void) {
    static int loaded = 0;
    static unsigned long loaded_boot = 0;
    if (!payhsm_ctx()->initialized) return;
    unsigned long boot = payhsm_get_boot_id();
    if (loaded && loaded_boot == boot) return;
    ekm_load();
    loaded = 1;
    loaded_boot = boot;
}

static void ekm_reset_loaded(void) {
    memset(&g_ekm, 0, sizeof(g_ekm));
}

/* ─ ID auto-généré ─ */
static void ekm_gen_id(const char *ktype, char id[EKM_KEY_ID_LEN]) {
    const ekm_ktype_t *kt = ekm_ktype(ktype);
    int idx = kt ? kt->idx : 11;
    g_ekm.counters[idx]++;
    snprintf(id, EKM_KEY_ID_LEN, "%s_%05d", ktype, g_ekm.counters[idx]);
}

static ekm_key_t *ekm_find_first_transport(const char *tname) {
    for (int i = g_ekm.count - 1; i >= 0; i--) {
        ekm_key_t *k = &g_ekm.keys[i];
        if (k->active && !strcmp(k->key_type, tname)) return k;
    }
    return NULL;
}

static const char *ekm_transport_name_for_key(const char *src_ktype) {
    if (!src_ktype) return NULL;
    if (!strcmp(src_ktype, "TPK") || !strcmp(src_ktype, "TAK")) return "TMK";
    if (!strcmp(src_ktype, "ZPK") || !strcmp(src_ktype, "PVK") || !strcmp(src_ktype, "IMK"))
        return "ZMK";
    return NULL;
}

/* ─ Recherche par ID (actif seulement) ─ */
static ekm_key_t *ekm_find(const char *id) {
    for (int i = 0; i < g_ekm.count; i++)
        if (g_ekm.keys[i].active && !strcmp(g_ekm.keys[i].key_id, id))
            return &g_ekm.keys[i];
    return NULL;
}
/* ─ Recherche par ID (tous statuts — pour CS, BW) ─ */
static ekm_key_t *ekm_find_any(const char *id) {
    for (int i = 0; i < g_ekm.count; i++)
        if (!strcmp(g_ekm.keys[i].key_id, id))
            return &g_ekm.keys[i];
    return NULL;
}

/* ─ Ajouter / mettre à jour ─ */
static int ekm_upsert(const char *key_id, const char *ktype,
                       int klen, const char *scheme, const char *kcv,
                       int exportable, const char *cryptogram) {
    /* Mise à jour si existe */
    for (int i = 0; i < g_ekm.count; i++) {
        if (!strcmp(g_ekm.keys[i].key_id, key_id)) {
            ekm_key_t *e = &g_ekm.keys[i];
            e->key_len = klen;
            strncpy(e->scheme, scheme, EKM_SCHEME_LEN - 1);
            strncpy(e->kcv, kcv, EKM_KCV_LEN - 1);
            e->exportable = exportable;
            e->active = 1;
            strncpy(e->cryptogram, cryptogram, EKM_CRYPT_LEN - 1);
            return 0;
        }
    }
    if (g_ekm.count >= EKM_VAULT_MAX) return -1;
    ekm_key_t *e = &g_ekm.keys[g_ekm.count++];
    memset(e, 0, sizeof(*e));
    strncpy(e->key_id,     key_id, EKM_KEY_ID_LEN  - 1);
    strncpy(e->key_type,   ktype,  EKM_KEY_TYPE_LEN - 1);
    e->key_len   = klen;
    strncpy(e->scheme,     scheme, EKM_SCHEME_LEN   - 1);
    strncpy(e->kcv,        kcv,    EKM_KCV_LEN      - 1);
    e->exportable = exportable;
    e->active     = 1;
    e->created_at = (long)time(NULL);
    strncpy(e->cryptogram, cryptogram, EKM_CRYPT_LEN - 1);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
   2. UTILITAIRES CRYPTOGRAPHIQUES
   ═══════════════════════════════════════════════════════════════════════════ */

/* Parseur de tokens séparés par '|' */
#define EKM_NTOK  14
#define EKM_TLEN 200
static int ekm_split(const char *s, char toks[EKM_NTOK][EKM_TLEN], int max) {
    int n = 0;
    if (max > EKM_NTOK) max = EKM_NTOK;
    const char *p = s;
    while (*p && n < max) {
        const char *end = strchr(p, '|');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (len >= EKM_TLEN) len = EKM_TLEN - 1;
        strncpy(toks[n], p, len);
        toks[n][len] = '\0';
        n++;
        if (!end) break;
        p = end + 1;
    }
    return n;
}

/* ECB encrypt 16 bytes sous clé 16 bytes (via EVP pour compatibilité OpenSSL 3) */
static int ekm_ecb_enc(const uint8_t key[PAYHSM_KEY_LEN],
                        const uint8_t pt[PAYHSM_KEY_LEN],
                        uint8_t ct[PAYHSM_KEY_LEN]) {
    int outl = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptUpdate(ctx, ct, &outl, pt, PAYHSM_KEY_LEN);
    EVP_CIPHER_CTX_free(ctx);
    return outl == PAYHSM_KEY_LEN ? 0 : -1;
}

/* KCV pour clé de longueur variable (réutilise hsm_kcv_hex) */
static void ekm_kcv(const uint8_t *key, int klen, char out[7]) {
    hsm_kcv_hex(key, (size_t)klen, out);
}

/* Envelopper une clé de longueur variable sous LMK (GCM) → hex blob */
static int ekm_wrap_lmk(const uint8_t *key, int klen, char crypt_out[EKM_CRYPT_LEN]) {
    if (klen == PAYHSM_KEY_LEN) {
        return payhsm_wrap_lmk_gcm_hex(key, crypt_out);
    }
    uint8_t lmk[32];
    if (recompose_for_op(lmk) != 0) return -1;
    uint8_t blob[LMK_MAX_BLOB_LEN];
    int rc = lmk_gcm_encrypt_n(lmk, key, (size_t)klen, blob);
    secure_zero(lmk, sizeof(lmk));
    if (rc != 0) return -1;
    size_t blen = LMK_BLOB_OVERHEAD + (size_t)klen;
    hex_encode(blob, blen, crypt_out);
    return 0;
}

/* Déverrouiller une clé 16 bytes depuis son cryptogramme LMK */
static int ekm_unwrap_lmk(const char *crypt, uint8_t key_out[PAYHSM_KEY_LEN]) {
    return payhsm_unwrap_lmk_gcm_hex(crypt, key_out);
}

/* Macro de réponse d'erreur */
#define EKM_ERR(resp_cmd, err_code, msg_str) \
    snprintf(out, n, "{\"rc\":-1,\"rawResponse\":\"%s%s%s\"," \
             "\"errorCode\":\"%s\",\"message\":\"%s\"}", \
             hdr, resp_cmd, err_code, err_code, msg_str); return

/* ═══════════════════════════════════════════════════════════════════════════
   3. A0/A1 — GENERATE KEY (format étendu)
   Format : 0001A0|TYPE|LEN|SCHEME|EXPORT
   ═══════════════════════════════════════════════════════════════════════════ */
static void handle_A0_ext(const char *hdr, const char *cmd_str, size_t cmdlen,
                           char *out, size_t n) {
    char raw_resp[512] = "";
    char json_extra[512] = "";
    size_t rlen = sizeof(raw_resp);
    size_t jlen = sizeof(json_extra);
    (void)cmdlen;
    if (!payhsm_ctx()->initialized) { EKM_ERR("A1","03","HSM non initialise"); }
    ekm_ensure();

    char toks[EKM_NTOK][EKM_TLEN];
    int nt = ekm_split(cmd_str + 7, toks, EKM_NTOK); /* skip '|' at [6] */
    if (nt < 3) { EKM_ERR("A1","02","A0: |TYPE|LEN|SCHEME|EXPORT attendu"); }

    const char *ktype  = toks[0];
    int         klen   = atoi(toks[1]);
    const char *scheme = toks[2];
    int         xport  = (nt >= 4) ? atoi(toks[3]) : 1;

    const ekm_ktype_t *kt = ekm_ktype(ktype);
    if (!kt) { EKM_ERR("A1","04","A0: type de cle invalide"); }
    if (klen != 16 && klen != 24 && klen != 32) { EKM_ERR("A1","02","A0: longueur invalide"); }
    if (strcmp(scheme,"U") && strcmp(scheme,"T") && strcmp(scheme,"X"))
        { EKM_ERR("A1","10","A0: schema invalide — U T X"); }

    uint8_t key[32];
    if (RAND_bytes(key, klen) != 1) { EKM_ERR("A1","99","A0: RAND_bytes echec"); }

    char crypt[EKM_CRYPT_LEN];
    if (ekm_wrap_lmk(key, klen, crypt) != 0) {
        secure_zero(key, sizeof(key));
        EKM_ERR("A1","05","A0: chiffrement LMK echec");
    }

    char kcv[7]; ekm_kcv(key, klen, kcv);
    secure_zero(key, sizeof(key));

    char key_id[EKM_KEY_ID_LEN];
    ekm_gen_id(ktype, key_id);
    ekm_upsert(key_id, ktype, klen, scheme, kcv, xport, crypt);
    ekm_save();

    char aline[128];
    snprintf(aline, sizeof(aline), "KEY_GENERATED id=%s type=%s len=%d KCV=%s",
             key_id, ktype, klen, kcv);
    audit_log(aline);

    snprintf(raw_resp, rlen, "%sA100KEY_ID=%s|KEY_BLOCK=%s|KCV=%s", hdr, key_id, crypt, kcv);
    snprintf(json_extra, jlen,
             ",\"keyId\":\"%s\",\"keyType\":\"%s\",\"keyLen\":%d,"
             "\"scheme\":\"%s\",\"exportable\":%d,\"kcv\":\"%s\","
             "\"message\":\"Cle generee et protegee sous LMK\"",
             key_id, ktype, klen, scheme, xport, kcv);
    snprintf(out, n, "{\"rc\":0,\"rawResponse\":\"%s\"%s}", raw_resp, json_extra);
}

/* ═══════════════════════════════════════════════════════════════════════════
   4. A4/A5 — FORM KEY FROM ENCRYPTED COMPONENTS
   Format : 0001A4|TYPE|SCHEME|NC|C1_HEX|C2_HEX|...|CN_HEX
   Chaque composant = 32 hex chars (16 bytes en clair, XOR combinés)
   ═══════════════════════════════════════════════════════════════════════════ */
static void handle_A4(const char *hdr, const char *cmd_str, size_t cmdlen,
                      char *raw_resp, size_t rlen,
                      char *json_extra, size_t jlen,
                      char *out, size_t n) {
    (void)cmdlen;
    if (!payhsm_ctx()->initialized) { EKM_ERR("A5","03","HSM non initialise"); }
    ekm_ensure();

    char toks[EKM_NTOK][EKM_TLEN];
    int nt = ekm_split(cmd_str + 7, toks, EKM_NTOK);
    /* toks[0]=TYPE toks[1]=SCHEME toks[2]=NC toks[3..]=components */
    if (nt < 5) { EKM_ERR("A5","02","A4: |TYPE|SCHEME|NC|C1|C2|... (min 2 composants)"); }

    const char *ktype  = toks[0];
    const char *scheme = toks[1];
    int         nc     = atoi(toks[2]);

    const ekm_ktype_t *kt = ekm_ktype(ktype);
    if (!kt) { EKM_ERR("A5","04","A4: type de cle invalide"); }
    if (nc < 2 || nc > 9) { EKM_ERR("A5","11","A4: NC invalide — 2 a 9 composants"); }
    if (nt < 3 + nc) { EKM_ERR("A5","11","A4: nombre de composants insuffisant"); }

    uint8_t result[PAYHSM_KEY_LEN];
    memset(result, 0, sizeof(result));

    for (int i = 0; i < nc; i++) {
        const char *comp_hex = toks[3 + i];
        if (strlen(comp_hex) != 32) {
            secure_zero(result, sizeof(result));
            EKM_ERR("A5","11","A4: composant invalide — 32 hex chars attendus");
        }
        uint8_t comp[PAYHSM_KEY_LEN];
        if (hex_decode(comp_hex, comp, PAYHSM_KEY_LEN) != 0) {
            secure_zero(result, sizeof(result));
            EKM_ERR("A5","11","A4: composant hex invalide");
        }
        for (int j = 0; j < PAYHSM_KEY_LEN; j++) result[j] ^= comp[j];
        secure_zero(comp, sizeof(comp));
    }

    char crypt[EKM_CRYPT_LEN];
    if (ekm_wrap_lmk(result, PAYHSM_KEY_LEN, crypt) != 0) {
        secure_zero(result, sizeof(result));
        EKM_ERR("A5","05","A4: chiffrement LMK echec");
    }

    char kcv[7]; ekm_kcv(result, PAYHSM_KEY_LEN, kcv);

    /* Coffre classique keys.vault (onglet UI) — même clé que ext_keys */
    {
        uint8_t lmk[32];
        if (check_integrity() == 0 && recompose_for_op(lmk) == 0) {
            vault_store_16(lmk, result, ktype, "", kcv);
            secure_zero(lmk, sizeof(lmk));
        }
    }

    secure_zero(result, sizeof(result));

    char key_id[EKM_KEY_ID_LEN];
    ekm_gen_id(ktype, key_id);
    ekm_upsert(key_id, ktype, PAYHSM_KEY_LEN, scheme, kcv, 1, crypt);
    ekm_save();

    char aline[128];
    snprintf(aline, sizeof(aline), "KEY_COMPONENTS_FORMED id=%s type=%s NC=%d KCV=%s",
             key_id, ktype, nc, kcv);
    audit_log(aline);

    snprintf(raw_resp, rlen, "%sA500KEY_ID=%s|KEY_BLOCK=%s|KCV=%s", hdr, key_id, crypt, kcv);
    snprintf(json_extra, jlen,
             ",\"keyId\":\"%s\",\"keyType\":\"%s\",\"kcv\":\"%s\","
             "\"components\":%d,\"message\":\"Cle formee depuis %d composants (XOR)\"",
             key_id, ktype, kcv, nc, nc);
}

/* ═══════════════════════════════════════════════════════════════════════════
   5. A6/A7 — IMPORT KEY (format étendu)
   Format : 0001A6|TTYPE|TID|KTYPE|SCHEME|ENC_KEY_32HEX
   TTYPE = type de clé de transport (ZMK, TMK, KEK)
   TID   = ID de la clé de transport dans le coffre étendu
   ENC_KEY = clé importée chiffrée sous TTYPE (AES-ECB, 32 hex)
   ═══════════════════════════════════════════════════════════════════════════ */
static void handle_A6_ext(const char *hdr, const char *cmd_str, size_t cmdlen,
                           char *out, size_t n) {
    char raw_resp[512] = "";
    char json_extra[512] = "";
    size_t rlen = sizeof(raw_resp);
    size_t jlen = sizeof(json_extra);
    (void)cmdlen;
    if (!payhsm_ctx()->initialized) { EKM_ERR("A7","03","HSM non initialise"); }
    ekm_ensure();

    char toks[EKM_NTOK][EKM_TLEN];
    int nt = ekm_split(cmd_str + 7, toks, EKM_NTOK);
    if (nt < 5) { EKM_ERR("A7","02","A6: |TTYPE|TID|KTYPE|SCHEME|ENC32HEX attendu"); }

    const char *ttype    = toks[0]; /* ZMK, TMK, KEK */
    const char *tid      = toks[1]; /* ZMK_00001 */
    const char *ktype    = toks[2]; /* ZPK */
    const char *scheme   = toks[3]; /* U */
    const char *enc_hex  = toks[4]; /* 32 hex chars */

    if (strlen(enc_hex) != 32) { EKM_ERR("A7","02","A6: ENC_KEY doit etre 32 hex chars"); }
    if (!ekm_ktype(ktype))     { EKM_ERR("A7","04","A6: type de cle invalide"); }

    /* Retrouver la clé de transport */
    ekm_key_t *transport = ekm_find(tid);
    if (!transport) { EKM_ERR("A7","13","A6: cle de transport introuvable"); }
    if (strcmp(transport->key_type, ttype)) { EKM_ERR("A7","13","A6: type transport incorrect"); }

    /* Déchiffrer la clé de transport depuis LMK */
    uint8_t transport_key[PAYHSM_KEY_LEN];
    if (ekm_unwrap_lmk(transport->cryptogram, transport_key) != 0) {
        EKM_ERR("A7","05","A6: dechiffrement cle transport echec");
    }

    /* Déchiffrer la clé importée sous la clé de transport (ECB) */
    uint8_t key_clear[PAYHSM_KEY_LEN];
    if (payhsm_unwrap_ecb_hex(transport_key, enc_hex, key_clear) != 0) {
        secure_zero(transport_key, sizeof(transport_key));
        EKM_ERR("A7","05","A6: dechiffrement cle importee echec");
    }
    secure_zero(transport_key, sizeof(transport_key));

    /* Rechiffrer sous LMK */
    char crypt[EKM_CRYPT_LEN];
    if (ekm_wrap_lmk(key_clear, PAYHSM_KEY_LEN, crypt) != 0) {
        secure_zero(key_clear, sizeof(key_clear));
        EKM_ERR("A7","05","A6: chiffrement LMK echec");
    }

    char kcv[7]; ekm_kcv(key_clear, PAYHSM_KEY_LEN, kcv);
    secure_zero(key_clear, sizeof(key_clear));

    char key_id[EKM_KEY_ID_LEN];
    ekm_gen_id(ktype, key_id);
    ekm_upsert(key_id, ktype, PAYHSM_KEY_LEN, scheme, kcv, 1, crypt);
    ekm_save();

    char aline[128];
    snprintf(aline, sizeof(aline), "KEY_IMPORTED id=%s type=%s via=%s KCV=%s",
             key_id, ktype, tid, kcv);
    audit_log(aline);

    snprintf(raw_resp, rlen, "%sA700KEY_ID=%s|KEY_BLOCK=%s|KCV=%s", hdr, key_id, crypt, kcv);
    snprintf(json_extra, jlen,
             ",\"keyId\":\"%s\",\"keyType\":\"%s\",\"kcv\":\"%s\","
             "\"importedVia\":\"%s\",\"message\":\"Cle importee et rechiffree sous LMK\"",
             key_id, ktype, kcv, tid);
    snprintf(out, n, "{\"rc\":0,\"rawResponse\":\"%s\"%s}", raw_resp, json_extra);
}

/* ═══════════════════════════════════════════════════════════════════════════
   6. A8/A9 — EXPORT KEY (format étendu)
   Format : 0001A8|KEY_ID|TTYPE|TID|SCHEME
   ═══════════════════════════════════════════════════════════════════════════ */
static void handle_A8_ext(const char *hdr, const char *cmd_str, size_t cmdlen,
                           char *out, size_t n) {
    char raw_resp[512] = "";
    char json_extra[512] = "";
    size_t rlen = sizeof(raw_resp);
    size_t jlen = sizeof(json_extra);
    (void)cmdlen;
    if (!payhsm_ctx()->initialized) { EKM_ERR("A9","03","HSM non initialise"); }
    ekm_ensure();

    char toks[EKM_NTOK][EKM_TLEN];
    int nt = ekm_split(cmd_str + 7, toks, EKM_NTOK);

    const char *key_id;
    const char *ttype;
    const char *tid;
    const char *scheme = "U";
    ekm_key_t *transport = NULL;

    if (nt == 1) {
        /* 0001A8|ZPK_00029 — ZMK/TMK depuis le coffre (pas dans la trame) */
        key_id = toks[0];
        ekm_key_t *src0 = ekm_find(key_id);
        if (!src0) { EKM_ERR("A9","06","A8: cle introuvable"); }
        ttype = ekm_transport_name_for_key(src0->key_type);
        if (!ttype) { EKM_ERR("A9","04","A8: type cle non exportable"); }
        transport = ekm_find_first_transport(ttype);
        if (!transport) { EKM_ERR("A9","13","A8: cle de transport introuvable (A4 ZMK/TMK)"); }
        tid = transport->key_id;
    } else if (nt < 4) {
        EKM_ERR("A9","02","A8: |KEY_ID| ou |KEY_ID|TTYPE|TID|SCHEME");
    } else {
        key_id = toks[0];
        ttype  = toks[1];
        tid    = toks[2];
        scheme = toks[3];
    }
    (void)scheme;

    ekm_key_t *src = ekm_find(key_id);
    if (!src) { EKM_ERR("A9","06","A8: cle introuvable"); }
    if (!src->exportable) {
        audit_log("UNAUTHORIZED_KEY_EXPORT tentative refusee");
        EKM_ERR("A9","09","A8: cle non exportable");
    }

    if (!transport) {
        transport = ekm_find(tid);
        if (!transport) { EKM_ERR("A9","13","A8: cle de transport introuvable"); }
        if (strcmp(transport->key_type, ttype)) { EKM_ERR("A9","13","A8: type transport incorrect"); }
    }

    /* Déchiffrer la clé source depuis LMK */
    uint8_t key_clear[PAYHSM_KEY_LEN];
    if (ekm_unwrap_lmk(src->cryptogram, key_clear) != 0) {
        EKM_ERR("A9","05","A8: dechiffrement cle source echec");
    }

    /* Déchiffrer la clé de transport depuis LMK */
    uint8_t transport_key[PAYHSM_KEY_LEN];
    if (ekm_unwrap_lmk(transport->cryptogram, transport_key) != 0) {
        secure_zero(key_clear, sizeof(key_clear));
        EKM_ERR("A9","05","A8: dechiffrement cle transport echec");
    }

    /* Chiffrer la clé source sous la clé de transport (ECB) */
    uint8_t enc_key[PAYHSM_KEY_LEN];
    int rc_enc = ekm_ecb_enc(transport_key, key_clear, enc_key);
    secure_zero(transport_key, sizeof(transport_key));
    secure_zero(key_clear, sizeof(key_clear));

    if (rc_enc != 0) { EKM_ERR("A9","05","A8: chiffrement ECB echec"); }

    char enc_hex[33]; hex_encode(enc_key, PAYHSM_KEY_LEN, enc_hex);
    secure_zero(enc_key, sizeof(enc_key));

    /* KCV depuis src */
    char aline[128];
    snprintf(aline, sizeof(aline), "KEY_EXPORTED id=%s via=%s KCV=%s",
             key_id, tid, src->kcv);
    audit_log(aline);

    snprintf(raw_resp, rlen, "%sA900EXPORTED_KEY=%s|KCV=%s", hdr, enc_hex, src->kcv);
    snprintf(json_extra, jlen,
             ",\"exportedKey\":\"%s\",\"kcv\":\"%s\","
             "\"exportedVia\":\"%s\",\"message\":\"Cle exportee sous %s (ECB)\"",
             enc_hex, src->kcv, tid, ttype);
    snprintf(out, n, "{\"rc\":0,\"rawResponse\":\"%s\"%s}", raw_resp, json_extra);
}

/* ═══════════════════════════════════════════════════════════════════════════
   7. B0/B1 — TRANSLATE KEY SCHEME
   Format : 0001B0|KEY_ID|NEW_SCHEME
   ═══════════════════════════════════════════════════════════════════════════ */
static void handle_B0(const char *hdr, const char *cmd_str, size_t cmdlen,
                      char *raw_resp, size_t rlen,
                      char *json_extra, size_t jlen,
                      char *out, size_t n) {
    (void)cmdlen;
    if (!payhsm_ctx()->initialized) { EKM_ERR("B1","03","HSM non initialise"); }
    ekm_ensure();

    char toks[EKM_NTOK][EKM_TLEN];
    int nt = ekm_split(cmd_str + 7, toks, EKM_NTOK);
    if (nt < 2) { EKM_ERR("B1","02","B0: |KEY_ID|NEW_SCHEME attendu"); }

    const char *key_id    = toks[0];
    const char *new_scheme = toks[1];

    if (strcmp(new_scheme,"U") && strcmp(new_scheme,"T") && strcmp(new_scheme,"X"))
        { EKM_ERR("B1","10","B0: schema invalide — U T X"); }

    ekm_key_t *k = ekm_find(key_id);
    if (!k) { EKM_ERR("B1","06","B0: cle introuvable"); }

    char old_scheme[EKM_SCHEME_LEN];
    strncpy(old_scheme, k->scheme, EKM_SCHEME_LEN - 1);
    strncpy(k->scheme, new_scheme, EKM_SCHEME_LEN - 1);
    ekm_save();

    char aline[128];
    snprintf(aline, sizeof(aline),
             "KEY_SCHEME_TRANSLATED id=%s %s->%s", key_id, old_scheme, new_scheme);
    audit_log(aline);

    snprintf(raw_resp, rlen, "%sB100KEY_ID=%s|NEW_KEY_BLOCK=%s|KCV=%s",
             hdr, key_id, k->cryptogram, k->kcv);
    snprintf(json_extra, jlen,
             ",\"keyId\":\"%s\",\"oldScheme\":\"%s\",\"newScheme\":\"%s\","
             "\"kcv\":\"%s\",\"message\":\"Schema traduit\"",
             key_id, old_scheme, new_scheme, k->kcv);
}

/* ═══════════════════════════════════════════════════════════════════════════
   8. BS/BT — CLEAR KEY CHANGE STORAGE
   Format : 0001BS
   ═══════════════════════════════════════════════════════════════════════════ */
static void handle_BS(const char *hdr, const char *cmd_str, size_t cmdlen,
                      char *raw_resp, size_t rlen,
                      char *json_extra, size_t jlen,
                      char *out, size_t n) {
    (void)cmd_str; (void)cmdlen; (void)out; (void)n;
    ekm_ensure();

    secure_zero(g_ekm.temp_id, sizeof(g_ekm.temp_id));
    secure_zero(g_ekm.temp_crypt, sizeof(g_ekm.temp_crypt));
    g_ekm.temp_used = 0;
    ekm_save();

    audit_log("KEY_CHANGE_STORAGE_CLEARED");

    snprintf(raw_resp, rlen, "%sBT00KEY_CHANGE_STORAGE_CLEARED", hdr);
    snprintf(json_extra, jlen, ",\"message\":\"Stockage temporaire efface\"");
}

/* ═══════════════════════════════════════════════════════════════════════════
   9. BW/BX — RE-WRAP ALL KEYS UNDER CURRENT LMK (rotation LMK)
   Format : 0001BW
   Dans cette implémentation : déchiffre et rechiffre chaque clé sous la LMK
   courante (rafraîchit l'IV GCM). Rapport de migration retourné.
   ═══════════════════════════════════════════════════════════════════════════ */
static void handle_BW(const char *hdr, const char *cmd_str, size_t cmdlen,
                      char *raw_resp, size_t rlen,
                      char *json_extra, size_t jlen,
                      char *out, size_t n) {
    (void)cmd_str; (void)cmdlen;
    if (!payhsm_ctx()->initialized) { EKM_ERR("BX","03","HSM non initialise"); }
    ekm_ensure();

    int migrated = 0, failed = 0;

    audit_log("LMK_TRANSLATION_STARTED");

    for (int i = 0; i < g_ekm.count; i++) {
        ekm_key_t *k = &g_ekm.keys[i];
        if (!k->active) continue;

        uint8_t key_clear[PAYHSM_KEY_LEN];
        if (ekm_unwrap_lmk(k->cryptogram, key_clear) != 0) {
            failed++;
            continue;
        }

        char new_crypt[EKM_CRYPT_LEN];
        if (ekm_wrap_lmk(key_clear, k->key_len, new_crypt) != 0) {
            secure_zero(key_clear, sizeof(key_clear));
            failed++;
            continue;
        }
        secure_zero(key_clear, sizeof(key_clear));

        strncpy(k->cryptogram, new_crypt, EKM_CRYPT_LEN - 1);
        migrated++;

        char aline[80];
        snprintf(aline, sizeof(aline), "LMK_KEY_REWRAPPED id=%s", k->key_id);
        audit_log(aline);
    }

    ekm_save();

    char aline[96];
    snprintf(aline, sizeof(aline), "LMK_TRANSLATION_COMPLETED migrated=%d failed=%d",
             migrated, failed);
    audit_log(aline);

    snprintf(raw_resp, rlen, "%sBX00MIGRATED=%d|FAILED=%d", hdr, migrated, failed);
    snprintf(json_extra, jlen,
             ",\"migrated\":%d,\"failed\":%d,"
             "\"message\":\"Cles ré-enveloppées sous LMK courante\"",
             migrated, failed);
}

/* ═══════════════════════════════════════════════════════════════════════════
   10. CS/CT — MODIFY KEY BLOCK HEADER
   Format : 0001CS|KEY_ID|FIELD|VALUE
   FIELD : EXPORT (0/1), SCHEME (U/T/X), ACTIVE (0/1)
   ═══════════════════════════════════════════════════════════════════════════ */
static void handle_CS(const char *hdr, const char *cmd_str, size_t cmdlen,
                      char *raw_resp, size_t rlen,
                      char *json_extra, size_t jlen,
                      char *out, size_t n) {
    (void)cmdlen;
    if (!payhsm_ctx()->initialized) { EKM_ERR("CT","03","HSM non initialise"); }
    ekm_ensure();

    char toks[EKM_NTOK][EKM_TLEN];
    int nt = ekm_split(cmd_str + 7, toks, EKM_NTOK);
    if (nt < 3) { EKM_ERR("CT","02","CS: |KEY_ID|FIELD|VALUE attendu"); }

    const char *key_id = toks[0];
    const char *field  = toks[1];
    const char *value  = toks[2];

    ekm_key_t *k = ekm_find_any(key_id);
    if (!k) { EKM_ERR("CT","06","CS: cle introuvable"); }

    char change_desc[64];
    if (!strcmp(field, "EXPORT")) {
        int new_val = atoi(value);
        /* Sécurité : impossible de rendre exportable une clé CVK/PVK/KEK/BDK */
        if (new_val == 1) {
            const ekm_ktype_t *kt = ekm_ktype(k->key_type);
            if (kt && !kt->def_export) {
                audit_log("UNAUTHORIZED_KEY_EXPORT modification refusee");
                EKM_ERR("CT","09","CS: type de cle non modifiable vers exportable");
            }
        }
        snprintf(change_desc, sizeof(change_desc),
                 "EXPORT %d->%d", k->exportable, new_val);
        k->exportable = new_val;
    } else if (!strcmp(field, "SCHEME")) {
        if (strcmp(value,"U") && strcmp(value,"T") && strcmp(value,"X"))
            { EKM_ERR("CT","10","CS: schema invalide"); }
        snprintf(change_desc, sizeof(change_desc),
                 "SCHEME %s->%s", k->scheme, value);
        strncpy(k->scheme, value, EKM_SCHEME_LEN - 1);
    } else if (!strcmp(field, "ACTIVE")) {
        int new_val = atoi(value);
        snprintf(change_desc, sizeof(change_desc),
                 "ACTIVE %d->%d", k->active, new_val);
        k->active = new_val;
    } else {
        EKM_ERR("CT","12","CS: champ inconnu — EXPORT SCHEME ACTIVE");
    }

    ekm_save();

    char aline[128];
    snprintf(aline, sizeof(aline),
             "KEY_BLOCK_HEADER_MODIFIED id=%s %s", key_id, change_desc);
    audit_log(aline);

    snprintf(raw_resp, rlen, "%sCT00KEY_ID=%s|KCV=%s", hdr, key_id, k->kcv);
    snprintf(json_extra, jlen,
             ",\"keyId\":\"%s\",\"field\":\"%s\",\"value\":\"%s\","
             "\"kcv\":\"%s\",\"message\":\"Header modifie\"",
             key_id, field, value, k->kcv);
}

/* ═══════════════════════════════════════════════════════════════════════════
   11. K8/K9 — EXPORT KEY UNDER KEK
   Format : 0001K8|KEY_ID|KEK_ID|SCHEME
   Identique à A8 mais dédié KEK
   ═══════════════════════════════════════════════════════════════════════════ */
static void handle_K8(const char *hdr, const char *cmd_str, size_t cmdlen,
                      char *raw_resp, size_t rlen,
                      char *json_extra, size_t jlen,
                      char *out, size_t n) {
    (void)cmdlen;
    if (!payhsm_ctx()->initialized) { EKM_ERR("K9","03","HSM non initialise"); }
    ekm_ensure();

    char toks[EKM_NTOK][EKM_TLEN];
    int nt = ekm_split(cmd_str + 7, toks, EKM_NTOK);
    if (nt < 2) { EKM_ERR("K9","02","K8: |KEY_ID|KEK_ID|SCHEME attendu"); }

    const char *key_id = toks[0];
    const char *kek_id = toks[1];

    ekm_key_t *src = ekm_find(key_id);
    if (!src) { EKM_ERR("K9","06","K8: cle introuvable"); }
    if (!src->exportable) {
        audit_log("UNAUTHORIZED_KEY_EXPORT via KEK refusee");
        EKM_ERR("K9","09","K8: cle non exportable");
    }

    ekm_key_t *kek = ekm_find(kek_id);
    if (!kek) { EKM_ERR("K9","13","K8: KEK introuvable"); }
    if (strcmp(kek->key_type, "KEK")) { EKM_ERR("K9","13","K8: cle de type KEK attendue"); }

    uint8_t key_clear[PAYHSM_KEY_LEN];
    if (ekm_unwrap_lmk(src->cryptogram, key_clear) != 0)
        { EKM_ERR("K9","05","K8: dechiffrement cle source echec"); }

    uint8_t kek_clear[PAYHSM_KEY_LEN];
    if (ekm_unwrap_lmk(kek->cryptogram, kek_clear) != 0) {
        secure_zero(key_clear, sizeof(key_clear));
        EKM_ERR("K9","05","K8: dechiffrement KEK echec");
    }

    uint8_t enc_key[PAYHSM_KEY_LEN];
    int rc = ekm_ecb_enc(kek_clear, key_clear, enc_key);
    secure_zero(kek_clear, sizeof(kek_clear));
    secure_zero(key_clear, sizeof(key_clear));
    if (rc != 0) { EKM_ERR("K9","05","K8: chiffrement ECB sous KEK echec"); }

    char enc_hex[33]; hex_encode(enc_key, PAYHSM_KEY_LEN, enc_hex);
    secure_zero(enc_key, sizeof(enc_key));

    char aline[128];
    snprintf(aline, sizeof(aline), "KEY_EXPORTED id=%s via_kek=%s KCV=%s",
             key_id, kek_id, src->kcv);
    audit_log(aline);

    snprintf(raw_resp, rlen, "%sK900KEY_UNDER_KEK=%s|KCV=%s", hdr, enc_hex, src->kcv);
    snprintf(json_extra, jlen,
             ",\"keyUnderKek\":\"%s\",\"kcv\":\"%s\","
             "\"kekId\":\"%s\",\"message\":\"Cle exportee sous KEK\"",
             enc_hex, src->kcv, kek_id);
}

/* ═══════════════════════════════════════════════════════════════════════════
   12. KA/KB — GENERATE KCV
   Mode 1 : 0001KA|KEY_ID
   Mode 2 : 0001KA|RAW|ALGO|KEYHEX
   ═══════════════════════════════════════════════════════════════════════════ */
static void handle_KA(const char *hdr, const char *cmd_str, size_t cmdlen,
                      char *raw_resp, size_t rlen,
                      char *json_extra, size_t jlen,
                      char *out, size_t n) {
    (void)cmdlen;
    if (!payhsm_ctx()->initialized) { EKM_ERR("KB","03","HSM non initialise"); }
    ekm_ensure();

    char toks[EKM_NTOK][EKM_TLEN];
    int nt = ekm_split(cmd_str + 7, toks, EKM_NTOK);
    if (nt < 1) { EKM_ERR("KB","02","KA: |KEY_ID  ou  |RAW|ALGO|KEYHEX"); }

    char kcv[7];

    if (!strcmp(toks[0], "RAW")) {
        /* Mode 2 : clé brute */
        if (nt < 3) { EKM_ERR("KB","02","KA RAW: |RAW|ALGO|KEYHEX attendu"); }
        /* const char *algo = toks[1]; */ /* AES ou 3DES — ignoré, détecté par taille */
        const char *key_hex = toks[2];
        size_t hex_len = strlen(key_hex);
        if (hex_len != 32 && hex_len != 48 && hex_len != 64)
            { EKM_ERR("KB","02","KA RAW: KEY_HEX = 32|48|64 chars"); }
        size_t klen = hex_len / 2;
        uint8_t key[32];
        if (hex_decode(key_hex, key, klen) != 0) {
            EKM_ERR("KB","02","KA RAW: KEY_HEX invalide");
        }
        ekm_kcv(key, (int)klen, kcv);
        secure_zero(key, sizeof(key));
        audit_log("KCV_GENERATED mode=RAW (key not logged)");
    } else {
        /* Mode 1 : par ID */
        ekm_key_t *k = ekm_find(toks[0]);
        if (!k) { EKM_ERR("KB","06","KA: cle introuvable"); }

        uint8_t key_clear[PAYHSM_KEY_LEN];
        if (ekm_unwrap_lmk(k->cryptogram, key_clear) != 0)
            { EKM_ERR("KB","05","KA: dechiffrement echec"); }
        ekm_kcv(key_clear, k->key_len, kcv);
        secure_zero(key_clear, sizeof(key_clear));

        char aline[80];
        snprintf(aline, sizeof(aline), "KCV_GENERATED id=%s KCV=%s", toks[0], kcv);
        audit_log(aline);
    }

    snprintf(raw_resp, rlen, "%sKB00%s", hdr, kcv);
    snprintf(json_extra, jlen, ",\"kcv\":\"%s\",\"message\":\"KCV calcule\"", kcv);
}

/* ═══════════════════════════════════════════════════════════════════════════
   13. NE/NF — GENERATE KEY COMPONENTS (cérémonie de clés)
   Format : 0001NE|TYPE|LEN|NC|STORE
   NC = 2 à 9 composants, STORE = Y/N (stocker la clé finale sous LMK)
   Réponse : components en clair (cérémonie manuelle)
   ═══════════════════════════════════════════════════════════════════════════ */
static void handle_NE(const char *hdr, const char *cmd_str, size_t cmdlen,
                      char *raw_resp, size_t rlen,
                      char *json_extra, size_t jlen,
                      char *out, size_t n) {
    (void)cmdlen;
    if (!payhsm_ctx()->initialized) { EKM_ERR("NF","03","HSM non initialise"); }
    ekm_ensure();

    char toks[EKM_NTOK][EKM_TLEN];
    int nt = ekm_split(cmd_str + 7, toks, EKM_NTOK);
    if (nt < 3) { EKM_ERR("NF","02","NE: |TYPE|LEN|NC|STORE attendu"); }

    const char *ktype = toks[0];
    int klen  = atoi(toks[1]);
    int nc    = atoi(toks[2]);
    int store = (nt >= 4 && (toks[3][0] == 'Y' || toks[3][0] == 'y' || toks[3][0] == '1'));

    if (!ekm_ktype(ktype)) { EKM_ERR("NF","04","NE: type de cle invalide"); }
    if (klen != 16 && klen != 24 && klen != 32) { EKM_ERR("NF","02","NE: longueur invalide"); }
    if (nc < 2 || nc > 9) { EKM_ERR("NF","11","NE: NC invalide — 2 a 9"); }

    /* Générer la clé finale */
    uint8_t key[32];
    if (RAND_bytes(key, klen) != 1) { EKM_ERR("NF","99","NE: RAND_bytes echec"); }

    /* Générer NC-1 composants aléatoires, dernier = XOR de tous */
    uint8_t comps[9][16];
    memset(comps, 0, sizeof(comps));

    for (int i = 0; i < nc - 1; i++) {
        if (RAND_bytes(comps[i], PAYHSM_KEY_LEN) != 1) {
            secure_zero(key, sizeof(key));
            secure_zero(comps, sizeof(comps));
            EKM_ERR("NF","99","NE: RAND_bytes composant echec");
        }
    }
    /* Dernier composant = key XOR comp1 XOR ... XOR comp(NC-1) */
    memcpy(comps[nc-1], key, PAYHSM_KEY_LEN);
    for (int i = 0; i < nc - 1; i++)
        for (int j = 0; j < PAYHSM_KEY_LEN; j++)
            comps[nc-1][j] ^= comps[i][j];

    char kcv[7]; ekm_kcv(key, klen, kcv);

    char key_id[EKM_KEY_ID_LEN] = "NOT_STORED";
    if (store) {
        char crypt[EKM_CRYPT_LEN];
        if (ekm_wrap_lmk(key, klen, crypt) == 0) {
            ekm_gen_id(ktype, key_id);
            ekm_upsert(key_id, ktype, klen, "U", kcv, 1, crypt);
            ekm_save();
        }
    }
    secure_zero(key, sizeof(key));

    /* Assembler la réponse avec les composants en clair */
    char resp_buf[1024];
    int pos = snprintf(resp_buf, sizeof(resp_buf),
                       "%sNF00KEY_ID=%s|KCV=%s", hdr, key_id, kcv);
    for (int i = 0; i < nc && pos < (int)sizeof(resp_buf) - 40; i++) {
        char comp_hex[33]; hex_encode(comps[i], PAYHSM_KEY_LEN, comp_hex);
        pos += snprintf(resp_buf + pos, sizeof(resp_buf) - (size_t)pos,
                        "|COMP%d=%s", i+1, comp_hex);
    }
    secure_zero(comps, sizeof(comps));

    audit_log("COMPONENTS_GENERATED (composants non loggues)");

    strncpy(raw_resp, resp_buf, rlen - 1);

    /* JSON extra with components */
    char je[512];
    int jp = snprintf(je, sizeof(je),
                      ",\"keyId\":\"%s\",\"kcv\":\"%s\","
                      "\"components\":%d,\"stored\":%s",
                      key_id, kcv, nc, store ? "true" : "false");
    if (jp < (int)sizeof(je) - 4) snprintf(je + jp, sizeof(je) - (size_t)jp, "%s", "");
    strncpy(json_extra, je, jlen - 1);
}

/* ═══════════════════════════════════════════════════════════════════════════
   14. VAULT LIST — Lister toutes les clés étendues
   ═══════════════════════════════════════════════════════════════════════════ */
static void handle_EKM_LIST(char *out, size_t n) {
    ekm_ensure();
    int pos = snprintf(out, n, "{\"rc\":0,\"extKeys\":[");
    for (int i = 0; i < g_ekm.count && pos < (int)n - 120; i++) {
        const ekm_key_t *k = &g_ekm.keys[i];
        if (!k->active) continue;
        pos += snprintf(out + pos, n - (size_t)pos,
            "%s{\"id\":\"%s\",\"type\":\"%s\",\"len\":%d,"
            "\"scheme\":\"%s\",\"kcv\":\"%s\","
            "\"exportable\":%d,\"created\":%ld}",
            (pos > 13 && out[pos - 1] != '[') ? "," : "",
            k->key_id, k->key_type, k->key_len,
            k->scheme, k->kcv, k->exportable, k->created_at);
    }
    snprintf(out + pos, n - (size_t)pos, "]}");
}

/* Transport (ZMK/TMK) pour export A8 auto — premier enregistrement actif du bon type */
int payhsm_ekm_lookup_transport_gcm(const char *op_key_type_code3,
                                    char crypt88[89],
                                    char transport_id[64]) {
    if (!crypt88 || !op_key_type_code3) return PAYHSM_RC_ERR;
    ekm_ensure();
    payhsm_kek_kind_t kind = payhsm_export_kek_kind(op_key_type_code3);
    const char *tname = (kind == PAYHSM_KEK_ZMK) ? "ZMK"
                      : (kind == PAYHSM_KEK_TMK) ? "TMK" : NULL;
    if (!tname) return PAYHSM_RC_ERR;
    for (int i = g_ekm.count - 1; i >= 0; i--) {
        const ekm_key_t *k = &g_ekm.keys[i];
        if (!k->active || strcmp(k->key_type, tname) != 0) continue;
        if (strlen(k->cryptogram) < 88) continue;
        strncpy(crypt88, k->cryptogram, 88);
        crypt88[88] = '\0';
        if (transport_id)
            snprintf(transport_id, 64, "%s", k->key_id);
        return PAYHSM_RC_OK;
    }
    return PAYHSM_RC_ERR;
}

int payhsm_ekm_clear_vault(void) {
    if (!payhsm_ctx()->initialized) return -1;
    ekm_ensure();
    int removed = 0;
    for (int i = 0; i < g_ekm.count; i++)
        if (g_ekm.keys[i].active) removed++;
    char saved_path[256];
    strncpy(saved_path, g_ekm.path, sizeof(saved_path) - 1);
    saved_path[sizeof(saved_path) - 1] = '\0';
    memset(&g_ekm, 0, sizeof(g_ekm));
    if (saved_path[0]) {
        strncpy(g_ekm.path, saved_path, sizeof(g_ekm.path) - 1);
        g_ekm.path[sizeof(g_ekm.path) - 1] = '\0';
        ekm_save();
    }
    return removed;
}

int payhsm_ekm_lookup_transport_by_name(const char *transport_name,
                                        char crypt88[89],
                                        char transport_id[64]) {
    if (!transport_name || !crypt88) return PAYHSM_RC_ERR;
    ekm_ensure();
    const char *tname = transport_name;
    char upper[8];
    size_t n = strlen(transport_name);
    if (n >= sizeof(upper)) n = sizeof(upper) - 1;
    for (size_t i = 0; i < n; i++)
        upper[i] = (char)toupper((unsigned char)transport_name[i]);
    upper[n] = '\0';
    tname = upper;
    if (strcmp(tname, "ZMK") != 0 && strcmp(tname, "TMK") != 0)
        return PAYHSM_RC_ERR;
    for (int i = g_ekm.count - 1; i >= 0; i--) {
        const ekm_key_t *k = &g_ekm.keys[i];
        if (!k->active || strcmp(k->key_type, tname) != 0) continue;
        if (strlen(k->cryptogram) < 88) continue;
        strncpy(crypt88, k->cryptogram, 88);
        crypt88[88] = '\0';
        if (transport_id)
            snprintf(transport_id, 64, "%s", k->key_id);
        return PAYHSM_RC_OK;
    }
    return PAYHSM_RC_ERR;
}

/* Ajoute les clés ext_keys.vault au JSON /api/vault (évite coffre « vide » après A4) */
static int payhsm_ekm_append_vault_json(char *out, size_t n, int pos) {
    ekm_ensure();
    for (int i = 0; i < g_ekm.count && pos < (int)n - 160; i++) {
        const ekm_key_t *k = &g_ekm.keys[i];
        if (!k->active) continue;
        pos += snprintf(out + pos, n - (size_t)pos,
                        "%s{\"id\":\"%s\",\"type\":\"%s\",\"terminal\":\"\","
                        "\"kcv\":\"%s\",\"storage\":\"ext_keys.vault\"}",
                        (pos > 0 && out[pos - 1] != '[') ? "," : "",
                        k->key_id, k->key_type, k->kcv);
    }
    return pos;
}
