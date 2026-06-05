/*
 * payhsm-cmds.c — Commandes HSM additionnelles style Thales payShield 10K
 *
 * Inclus (#include) dans payhsm-httpd.c juste avant dispatch_api.
 * Toutes les fonctions statiques de httpd.c (audit_log, hex_encode,
 * hex_decode, hsm_kcv_hex, payhsm_ctx, check_integrity, secure_zero…)
 * sont accessibles.
 *
 * Commandes implémentées :
 *   B2/B3  — Echo command
 *   NO/NP  — HSM Status
 *   NI/NJ  — Network Information
 *   NC/ND  — Diagnostics
 *   N0/N1  — Generate Random Value
 *   BU/BV  — Generate / Verify KCV
 *
 * Codes d'erreur standardisés :
 *   00 OK  01 commande inconnue  02 format invalide
 *   03 HSM non initialisé       04 paramètre invalide
 *   05 erreur cryptographique   06 clé introuvable
 *   07 KCV invalide             99 erreur interne
 */

/* g_start_time et g_server_port sont définis dans payhsm-httpd.c */

/* ═══════════════════════════════════════════════════════════════════════════
   Utilitaires internes
   ═══════════════════════════════════════════════════════════════════════════ */

/* KCV AES/3DES — généralisation pour toutes tailles de clé */
static void cmd_kcv_hex(const uint8_t *key, size_t keylen, char kcv_out[7]) {
    hsm_kcv_hex(key, keylen, kcv_out);
}

/* ═══════════════════════════════════════════════════════════════════════════
   B2 / B3 — Echo command
   Rôle : tester la communication switch ↔ HSM (pas d'init requise)
   Format : [HDR:4][B2][DATA:opt]
   Réponse: [HDR][B3][00][DATA:opt]
   ═══════════════════════════════════════════════════════════════════════════ */
static void handle_B2_echo(const char *hdr,
                            const char *cmd_str, size_t cmdlen,
                            char *raw_resp, size_t rlen,
                            char *json_extra, size_t jlen) {
    /* Données optionnelles après le code de commande (offset 6) */
    const char *data = cmdlen > 6 ? cmd_str + 6 : "";
    snprintf(raw_resp,  rlen, "%sB300%s", hdr, data);
    snprintf(json_extra, jlen, ",\"echoData\":\"%s\","
             "\"message\":\"Echo OK — communication HSM operationnelle\"", data);
}

/* ═══════════════════════════════════════════════════════════════════════════
   NO / NP — HSM Status
   Rôle : état opérationnel complet du HSM
   Format : [HDR:4][NO]
   Réponse: [HDR][NP][00][STATE|KEY=VAL|...]
   ═══════════════════════════════════════════════════════════════════════════ */
static void handle_NO_status(const char *hdr,
                              char *raw_resp, size_t rlen,
                              char *json_extra, size_t jlen) {
    const payhsm_ctx_t *ctx = payhsm_ctx();
    int initialized = ctx->initialized;
    int key_count   = ctx->vault.count;

    /* État LMK */
    payhsm_lmk_status_t lmk_st;
    memset(&lmk_st, 0, sizeof(lmk_st));
    int lmk_ok = (payhsm_get_lmk_status(&lmk_st) == 0 && lmk_st.fragmented
                  && lmk_st.integrity_ok);

    const char *state = initialized ? "READY" : "NOT_INITIALIZED";
    char status[256];
    snprintf(status, sizeof(status),
        "%s|LMK_LOADED=%s|HOST=RUNNING|TLS=NO|KEYS=%d|INTEGRITY=%s",
        state,
        lmk_ok ? "YES" : "NO",
        key_count,
        lmk_ok ? "OK" : "UNKNOWN");

    snprintf(raw_resp,  rlen, "%sNP00%s", hdr, status);
    snprintf(json_extra, jlen,
        ",\"status\":\"%s\",\"initialized\":%d,"
        "\"lmkLoaded\":%d,\"keyCount\":%d,\"integrity\":\"%s\"",
        state, initialized, lmk_ok, key_count, lmk_ok ? "OK" : "UNKNOWN");

    audit_log("NO: HSM_STATUS queried");
}

/* ═══════════════════════════════════════════════════════════════════════════
   NI / NJ — Network Information
   Rôle : informations réseau du serveur HSM
   Format : [HDR:4][NI]
   Réponse: [HDR][NJ][00][HOST=x|PORT=y|PROTO=z|...]
   ═══════════════════════════════════════════════════════════════════════════ */
static void handle_NI_network_info(const char *hdr,
                                   char *raw_resp, size_t rlen,
                                   char *json_extra, size_t jlen) {
    char netinfo[256];
    snprintf(netinfo, sizeof(netinfo),
        "HOST=127.0.0.1|PORT=%d|PROTO=TCP|SERVER=RUNNING|CLIENTS=1|TIMEOUT=30|TLS=NO",
        g_server_port);

    snprintf(raw_resp,  rlen, "%sNJ00%s", hdr, netinfo);
    snprintf(json_extra, jlen,
        ",\"host\":\"127.0.0.1\",\"port\":%d,"
        "\"proto\":\"TCP\",\"server\":\"RUNNING\","
        "\"tls\":false,\"timeout\":30",
        g_server_port);

    audit_log("NI: NETWORK_INFO queried");
}

/* ═══════════════════════════════════════════════════════════════════════════
   NC / ND — Diagnostics
   Rôle : état détaillé de tous les sous-systèmes du HSM
   Format : [HDR:4][NC]
   Réponse: [HDR][ND][00][MODULE=STATE|...]
   ═══════════════════════════════════════════════════════════════════════════ */
static void handle_NC_diagnostics(const char *hdr,
                                  char *raw_resp, size_t rlen,
                                  char *json_extra, size_t jlen) {
    /* Mémoire — test malloc basique */
    void *probe = malloc(256);
    const char *mem_st = probe ? "OK" : "ERROR";
    if (probe) free(probe);

    /* Vault */
    const payhsm_ctx_t *ctx = payhsm_ctx();
    const char *vault_st = ctx->vault.vault_path[0] ? "OK" : "NOT_CONFIGURED";

    /* Audit log */
    const char *audit_st = g_audit_count >= 0 ? "OK" : "ERROR";

    /* RNG — test RAND_bytes */
    uint8_t rng_test[4];
    const char *rng_st = RAND_bytes(rng_test, sizeof(rng_test)) == 1 ? "OK" : "ERROR";
    secure_zero(rng_test, sizeof(rng_test));

    /* LMK */
    const char *lmk_st = ctx->initialized ? "LOADED" : "NOT_LOADED";

    /* Intégrité fragments */
    const char *integ_st = "UNKNOWN";
    if (ctx->initialized) {
        integ_st = check_integrity() == 0 ? "OK" : "FAIL";
    }

    /* Uptime */
    long uptime = g_start_time ? (long)(time(NULL) - g_start_time) : 0;

    /* Dernière erreur */
    const char *last_err = "NONE";
    if (g_audit_count > 0) {
        /* Chercher le dernier log contenant ERROR/ECHEC/FAIL */
        for (int i = g_audit_count - 1; i >= 0; i--) {
            if (strstr(g_audit[i].msg, "ECHEC") || strstr(g_audit[i].msg, "ERROR")
                || strstr(g_audit[i].msg, "FAIL")) {
                last_err = "SEE_AUDIT_LOG";
                break;
            }
        }
    }

    char diag[512];
    snprintf(diag, sizeof(diag),
        "MEMORY=%s|VAULT=%s|AUDIT=%s|RNG=%s|LMK=%s|INTEGRITY=%s|UPTIME=%ld|LAST_ERROR=%s",
        mem_st, vault_st, audit_st, rng_st, lmk_st, integ_st, uptime, last_err);

    snprintf(raw_resp,  rlen, "%sND00%s", hdr, diag);
    snprintf(json_extra, jlen,
        ",\"memory\":\"%s\",\"vault\":\"%s\",\"audit\":\"%s\","
        "\"rng\":\"%s\",\"lmk\":\"%s\",\"integrity\":\"%s\","
        "\"uptime\":%ld,\"lastError\":\"%s\"",
        mem_st, vault_st, audit_st, rng_st, lmk_st, integ_st, uptime, last_err);

    audit_log("NC: DIAGNOSTICS queried");
}

/* ═══════════════════════════════════════════════════════════════════════════
   N0 / N1 — Generate Random Value
   Rôle : générer une valeur aléatoire cryptographiquement sécurisée
   Format : [HDR:4][N0][LENGTH_HEX:2]   LENGTH_HEX en hex (ex: 10 = 16 octets)
   Réponse: [HDR][N1][00][RANDOM_HEX]
   Contraintes : min 8 octets, max 64 octets
   ═══════════════════════════════════════════════════════════════════════════ */
static void handle_N0_random(const char *hdr,
                              const char *cmd_str, size_t cmdlen,
                              char *raw_resp, size_t rlen,
                              char *json_extra, size_t jlen,
                              char *out, size_t n) {
    if (cmdlen < 8) {
        snprintf(out, n,
            "{\"rc\":-1,\"rawResponse\":\"%sN102\","
            "\"message\":\"N0: format invalide — [HDR:4][N0][LEN:2] attendu\","
            "\"errorCode\":\"02\"}", hdr);
        return;
    }

    char len_hex[3];
    strncpy(len_hex, cmd_str + 6, 2); len_hex[2] = '\0';
    unsigned int rng_len = 0;
    if (sscanf(len_hex, "%2x", &rng_len) != 1) {
        snprintf(out, n,
            "{\"rc\":-1,\"rawResponse\":\"%sN104\","
            "\"message\":\"N0: longueur invalide — hex 2 chars attendu\","
            "\"errorCode\":\"04\"}", hdr);
        return;
    }

    if (rng_len < 8 || rng_len > 64) {
        snprintf(out, n,
            "{\"rc\":-1,\"rawResponse\":\"%sN104\","
            "\"message\":\"N0: taille %u invalide — min 8 (0x08), max 64 (0x40) octets\","
            "\"errorCode\":\"04\"}", hdr, rng_len);
        return;
    }

    uint8_t rng_buf[64];
    if (RAND_bytes(rng_buf, (int)rng_len) != 1) {
        secure_zero(rng_buf, sizeof(rng_buf));
        snprintf(out, n,
            "{\"rc\":-1,\"rawResponse\":\"%sN105\","
            "\"message\":\"N0: echec generateur aleatoire (RAND_bytes)\","
            "\"errorCode\":\"05\"}", hdr);
        return;
    }

    char rng_hex[130]; /* 64 * 2 + 1 */
    hex_encode(rng_buf, rng_len, rng_hex);
    secure_zero(rng_buf, sizeof(rng_buf));

    snprintf(raw_resp,  rlen, "%sN100%s", hdr, rng_hex);
    snprintf(json_extra, jlen,
        ",\"randomHex\":\"%s\",\"length\":%u,"
        "\"message\":\"Valeur aleatoire generee via RAND_bytes (TRNG)\"",
        rng_hex, rng_len);

    audit_log("N0: RANDOM generated");
}

/* ═══════════════════════════════════════════════════════════════════════════
   BU / BV — Generate / Verify KCV
   Rôle : calculer ou vérifier le Key Check Value d'une clé
   Format génération : [HDR:4][BU][G][KEY_HEX:32/48/64]
   Format vérif      : [HDR:4][BU][V][KEY_HEX:32/48/64][KCV_ATTENDU:6]
   Réponse génér.    : [HDR][BV][00][KCV:6]
   Réponse vérif OK  : [HDR][BV][00]KCV_OK
   Réponse vérif ERR : [HDR][BV][07]KCV_INVALID|EXPECTED=XXXXXX|COMPUTED=YYYYYY
   KCV AES  : AES-ECB(16 zéros)[0..2] en hex majuscule
   KCV 3DES : 3DES-ECB(8 zéros)[0..2] en hex majuscule (24-octet key)
   ═══════════════════════════════════════════════════════════════════════════ */
static void handle_BU_kcv(const char *hdr,
                           const char *cmd_str, size_t cmdlen,
                           char *raw_resp, size_t rlen,
                           char *json_extra, size_t jlen,
                           char *out, size_t n) {
    if (cmdlen < 8) {
        snprintf(out, n,
            "{\"rc\":-1,\"rawResponse\":\"%sBV02\","
            "\"message\":\"BU: format invalide — [HDR:4][BU][G|V][KEY_HEX] attendu\","
            "\"errorCode\":\"02\"}", hdr);
        return;
    }

    char mode = cmd_str[6];
    if (mode >= 'a' && mode <= 'z') mode = (char)(mode - 32); /* uppercase */
    if (mode != 'G' && mode != 'V') {
        snprintf(out, n,
            "{\"rc\":-1,\"rawResponse\":\"%sBV04\","
            "\"message\":\"BU: mode invalide '%c' — G (generer) ou V (verifier) attendu\","
            "\"errorCode\":\"04\"}", hdr, mode);
        return;
    }

    /* Key hex starts at offset 7 */
    const char *key_hex_start = cmd_str + 7;
    size_t remaining = cmdlen - 7;

    /* Detect key length: 32=AES-128/2K3DES, 48=AES-192/3K3DES, 64=AES-256 */
    /* For verify mode: key_hex is followed by 6-char KCV */
    size_t key_hex_len = 0;
    char expected_kcv[8] = {0};
    int  is_des = 0; /* flag: use 3DES-ECB instead of AES-ECB */

    if (mode == 'G') {
        /* Génération : toute la suite est la clé */
        key_hex_len = remaining;
    } else {
        /* Vérification : clé + 6 chars KCV */
        if (remaining < 6 + 32) {
            snprintf(out, n,
                "{\"rc\":-1,\"rawResponse\":\"%sBV02\","
                "\"message\":\"BU V: format invalide — KEY_HEX + 6 chars KCV attendus\","
                "\"errorCode\":\"02\"}", hdr);
            return;
        }
        key_hex_len = remaining - 6;
        strncpy(expected_kcv, key_hex_start + key_hex_len, 6);
        expected_kcv[6] = '\0';
        /* Upper-case expected_kcv */
        for (int i = 0; expected_kcv[i]; i++)
            if (expected_kcv[i] >= 'a') expected_kcv[i] = (char)(expected_kcv[i] - 32);
    }

    /* Valider la longueur de clé (en hex) */
    if (key_hex_len != 32 && key_hex_len != 48 && key_hex_len != 64
        && key_hex_len != 16 /* DES 8o */) {
        snprintf(out, n,
            "{\"rc\":-1,\"rawResponse\":\"%sBV04\","
            "\"message\":\"BU: taille cle %zu invalide — 16|32|48|64 hex attendus\","
            "\"errorCode\":\"04\"}", hdr, key_hex_len);
        return;
    }

    /* Decoder la clé */
    size_t key_bytes = key_hex_len / 2;
    uint8_t key_buf[32];

    /* Copier et decoder */
    char key_hex_copy[130];
    if (key_hex_len > 128) key_hex_len = 128;
    strncpy(key_hex_copy, key_hex_start, key_hex_len);
    key_hex_copy[key_hex_len] = '\0';

    if (hex_decode(key_hex_copy, key_buf, key_bytes) != 0) {
        snprintf(out, n,
            "{\"rc\":-1,\"rawResponse\":\"%sBV04\","
            "\"message\":\"BU: KEY_HEX invalide — valeurs hexadecimales attendues\","
            "\"errorCode\":\"04\"}", hdr);
        return;
    }

    /* Calculer le KCV — utiliser 3DES-ECB pour clés de 8 octets */
    is_des = (key_bytes == 8);
    char computed_kcv[7];
    if (is_des) {
        /* 3DES-ECB sur 8 octets à zéro */
        uint8_t zeros[8] = {0};
        uint8_t kcv_out[8] = {0};
        int len = 0;
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (ctx) {
            EVP_EncryptInit_ex(ctx, EVP_des_ecb(), NULL, key_buf, NULL);
            EVP_CIPHER_CTX_set_padding(ctx, 0);
            EVP_EncryptUpdate(ctx, kcv_out, &len, zeros, 8);
            EVP_CIPHER_CTX_free(ctx);
        }
        snprintf(computed_kcv, sizeof(computed_kcv), "%02X%02X%02X",
                 kcv_out[0], kcv_out[1], kcv_out[2]);
    } else {
        /* AES-ECB pour toutes les autres tailles */
        cmd_kcv_hex(key_buf, key_bytes, computed_kcv);
    }
    secure_zero(key_buf, sizeof(key_buf));

    if (mode == 'G') {
        /* Réponse génération */
        snprintf(raw_resp,  rlen, "%sBV00%s", hdr, computed_kcv);
        snprintf(json_extra, jlen,
            ",\"kcv\":\"%s\",\"keyLenBytes\":%zu,"
            "\"algorithm\":\"%s\",\"message\":\"KCV calcule avec succes\"",
            computed_kcv, key_bytes,
            is_des ? "DES-ECB" : (key_bytes == 16 ? "AES-128-ECB" :
                                  key_bytes == 24 ? "AES-192-ECB" : "AES-256-ECB"));
        audit_log("BU G: KCV generated (key not logged)");

    } else {
        /* Vérification */
        int kcv_match = (strncasecmp(computed_kcv, expected_kcv, 6) == 0);
        if (kcv_match) {
            snprintf(raw_resp,  rlen, "%sBV00KCV_OK", hdr);
            snprintf(json_extra, jlen,
                ",\"kcvMatch\":true,\"kcv\":\"%s\","
                "\"message\":\"KCV correct\"", computed_kcv);
            audit_log("BU V: KCV verified OK");
        } else {
            snprintf(raw_resp,  rlen, "%sBV07KCV_INVALID|EXPECTED=%s|COMPUTED=%s",
                     hdr, expected_kcv, computed_kcv);
            snprintf(json_extra, jlen,
                ",\"kcvMatch\":false,"
                "\"expectedKcv\":\"%s\",\"computedKcv\":\"%s\","
                "\"errorCode\":\"07\",\"message\":\"KCV invalide\"",
                expected_kcv, computed_kcv);
            audit_log("BU V: KCV verification FAILED");
            /* Réponse spéciale avec errorCode 07 */
            snprintf(out, n,
                "{\"rc\":-1,\"rawResponse\":\"%s\"%s}",
                raw_resp, json_extra);
            return;
        }
    }
}
