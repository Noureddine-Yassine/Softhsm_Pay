/**
 * API Switch : le HSM ne conserve que la LMK ; les clés de travail
 * sont fournies par le Switch (ENC(LMK,*) ou ENC(TMK,*)).
 */
#include "payhsm_switch.h"
#include "payhsm_core.h"
#include "payhsm.h"
#include "payment/pin.h"
#include "payment/mac.h"
#include "payment/emv.h"
#include "payment/key_exchange.h"

#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/* Session EMV 2 étapes (ARQC puis verify HTTP) — conserve SK/MK de l'étape ① */
#define EMV_SESS_TX_MAX 64
typedef struct {
    int    active;
    char   pan[32];
    char   psn[8];
    char   atc[8];
    char   arqc_hex[17];
    char   issuer_arpc_hex[17];
    int    issuer_arpc_ready;
    char   tx[EMV_SESS_TX_MAX];
    size_t tx_len;
    uint8_t sk[16];
    uint8_t mk[16];
} emv_sess_t;

static emv_sess_t g_emv_sess;

void payhsm_emv_clear_session(void) {
    secure_zero(&g_emv_sess, sizeof(g_emv_sess));
    g_emv_sess.active = 0;
    g_emv_sess.issuer_arpc_ready = 0;
}

static int emv_sess_matches(const char *pan, const char *psn,
                            const char *atc, const char *arqc_hex) {
    if (!g_emv_sess.active || !pan || !psn || !atc || !arqc_hex) return 0;
    return strcmp(g_emv_sess.pan, pan) == 0 &&
           strcmp(g_emv_sess.psn, psn) == 0 &&
           strcmp(g_emv_sess.atc, atc) == 0 &&
           strcasecmp(g_emv_sess.arqc_hex, arqc_hex) == 0;
}

static void emv_sess_store(const char *pan, const char *psn, const char *atc,
                           const char *arqc_hex, const char *tx, size_t tx_len,
                           const uint8_t mk[16], const uint8_t sk[16]) {
    payhsm_emv_clear_session();
    strncpy(g_emv_sess.pan, pan, sizeof(g_emv_sess.pan) - 1);
    strncpy(g_emv_sess.psn, psn, sizeof(g_emv_sess.psn) - 1);
    strncpy(g_emv_sess.atc, atc, sizeof(g_emv_sess.atc) - 1);
    strncpy(g_emv_sess.arqc_hex, arqc_hex, sizeof(g_emv_sess.arqc_hex) - 1);
    if (tx_len >= EMV_SESS_TX_MAX) tx_len = EMV_SESS_TX_MAX - 1;
    memcpy(g_emv_sess.tx, tx, tx_len);
    g_emv_sess.tx[tx_len] = '\0';
    g_emv_sess.tx_len = tx_len;
    memcpy(g_emv_sess.mk, mk, 16);
    memcpy(g_emv_sess.sk, sk, 16);
    g_emv_sess.issuer_arpc_ready = 0;
    g_emv_sess.issuer_arpc_hex[0] = '\0';
    g_emv_sess.active = 1;
}

#define LMK_IV_LEN  12
#define LMK_TAG_LEN 16

static int hex_decode_local(const char *hex, uint8_t *out, size_t nbytes) {
    if (!hex || strlen(hex) != nbytes * 2) return -1;
    for (size_t i = 0; i < nbytes; i++) {
        unsigned int b;
        if (sscanf(hex + i * 2, "%2x", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    return 0;
}

static void hex_encode_local(const uint8_t *in, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) sprintf(out + i * 2, "%02X", in[i]);
    out[len * 2] = '\0';
}

static int lmk_gcm_decrypt_blob(const uint8_t lmk[32],
                                const uint8_t blob[PAYHSM_GCM_BLOB_BYTES],
                                uint8_t pt_out[PAYHSM_KEY_LEN]) {
    const uint8_t *iv  = blob;
    const uint8_t *tag = blob + LMK_IV_LEN;
    const uint8_t *ct  = blob + LMK_IV_LEN + LMK_TAG_LEN;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int ret = -1, len = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, lmk, iv) != 1) goto done;
    if (EVP_DecryptUpdate(ctx, pt_out, &len, ct, PAYHSM_KEY_LEN) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, LMK_TAG_LEN, (void *)tag) != 1) goto done;
    ret = (EVP_DecryptFinal_ex(ctx, pt_out + len, &len) == 1) ? 0 : -1;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

static int lmk_gcm_encrypt_blob(const uint8_t lmk[32],
                                  const uint8_t pt[PAYHSM_KEY_LEN],
                                  uint8_t blob[PAYHSM_GCM_BLOB_BYTES]) {
    uint8_t iv[LMK_IV_LEN];
    if (RAND_bytes(iv, LMK_IV_LEN) != 1) return -1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int ret = -1, len = 0;
    uint8_t ct[PAYHSM_KEY_LEN], tag[LMK_TAG_LEN];
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, lmk, iv) != 1) goto done;
    if (EVP_EncryptUpdate(ctx, ct, &len, pt, PAYHSM_KEY_LEN) != 1) goto done;
    if (EVP_EncryptFinal_ex(ctx, ct + len, &len) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, LMK_TAG_LEN, tag) != 1) goto done;
    memcpy(blob, iv, LMK_IV_LEN);
    memcpy(blob + LMK_IV_LEN, tag, LMK_TAG_LEN);
    memcpy(blob + LMK_IV_LEN + LMK_TAG_LEN, ct, PAYHSM_KEY_LEN);
    ret = 0;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

typedef struct { const char *blob88; uint8_t *out; int rc; } unwrap_gcm_arg_t;

static void unwrap_gcm_cb(const uint8_t lmk[32], void *v) {
    unwrap_gcm_arg_t *a = (unwrap_gcm_arg_t *)v;
    uint8_t blob[PAYHSM_GCM_BLOB_BYTES];
    a->rc = -1;
    if (hex_decode_local(a->blob88, blob, sizeof(blob)) != 0) return;
    a->rc = lmk_gcm_decrypt_blob(lmk, blob, a->out);
}

static int with_lmk_op(int (*fn)(const uint8_t lmk[32], void *arg), void *arg) {
    if (!payhsm_ctx()->initialized) return PAYHSM_RC_NOT_INIT;
    if (check_integrity() != 0) return PAYHSM_RC_ERR;
    uint8_t lmk[32];
    if (recompose_for_op(lmk) != 0) return PAYHSM_RC_ERR;
    int rc = fn(lmk, arg);
    secure_zero(lmk, sizeof(lmk));
    /* Mutation XOR après chaque op crypto : P1/P2/P3 changent, LMK logique inchangée */
    if (mutate_fragments() != 0) return PAYHSM_RC_ERR;
    if (verify_integrity_quiet() != 0) return PAYHSM_RC_ERR;
    return rc;
}

static int unwrap_gcm_fn(const uint8_t lmk[32], void *v) {
    unwrap_gcm_cb(lmk, v);
    return ((unwrap_gcm_arg_t *)v)->rc == 0 ? PAYHSM_RC_OK : PAYHSM_RC_ERR;
}

int payhsm_unwrap_lmk_gcm_hex(const char *blob88, uint8_t key_out[PAYHSM_KEY_LEN]) {
    unwrap_gcm_arg_t a = { blob88, key_out, -1 };
    return with_lmk_op(unwrap_gcm_fn, &a);
}

/* ENC(parent, child) — AES-128-ECB (32 hex), parent = TMK 16 octets */
static int ecb_encrypt_under(const uint8_t parent[PAYHSM_KEY_LEN],
                             const uint8_t key[PAYHSM_KEY_LEN],
                             uint8_t enc[PAYHSM_KEY_LEN]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len = 0, ok = -1;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, parent, NULL) != 1) goto done;
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (EVP_EncryptUpdate(ctx, enc, &len, key, PAYHSM_KEY_LEN) != 1 || len != (int)PAYHSM_KEY_LEN)
        goto done;
    int fin = 0;
    if (EVP_EncryptFinal_ex(ctx, enc + len, &fin) != 1) goto done;
    ok = 0;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int ecb_decrypt_under(const uint8_t parent[PAYHSM_KEY_LEN],
                             const uint8_t enc[PAYHSM_KEY_LEN],
                             uint8_t key_out[PAYHSM_KEY_LEN]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len = 0, ok = -1;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, parent, NULL) != 1) goto done;
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (EVP_DecryptUpdate(ctx, key_out, &len, enc, PAYHSM_KEY_LEN) != 1 ||
        len != (int)PAYHSM_KEY_LEN)
        goto done;
    int fin = 0;
    if (EVP_DecryptFinal_ex(ctx, key_out + len, &fin) != 1) goto done;
    ok = 0;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int payhsm_unwrap_ecb_hex(const uint8_t parent_key[PAYHSM_KEY_LEN],
                            const char *enc32hex,
                            uint8_t key_out[PAYHSM_KEY_LEN]) {
    uint8_t enc[PAYHSM_KEY_LEN];
    if (hex_decode_local(enc32hex, enc, PAYHSM_KEY_LEN) != 0) return PAYHSM_RC_ERR;
    return ecb_decrypt_under(parent_key, enc, key_out) == 0 ? PAYHSM_RC_OK : PAYHSM_RC_ERR;
}

int payhsm_wrap_ecb_hex(const uint8_t parent_key[PAYHSM_KEY_LEN],
                        const uint8_t clear[PAYHSM_KEY_LEN],
                        char enc32hex[33]) {
    uint8_t enc[PAYHSM_KEY_LEN];
    if (ecb_encrypt_under(parent_key, clear, enc) != 0) return PAYHSM_RC_ERR;
    hex_encode_local(enc, PAYHSM_KEY_LEN, enc32hex);
    return PAYHSM_RC_OK;
}

int payhsm_thales_block_wrap(const uint8_t parent_key[PAYHSM_KEY_LEN], char scheme,
                             const uint8_t clear[PAYHSM_KEY_LEN], char out33[PAYHSM_THALES_BLOCK_LEN + 1]) {
    char enc32[33];
    if (payhsm_wrap_ecb_hex(parent_key, clear, enc32) != PAYHSM_RC_OK) return PAYHSM_RC_ERR;
    out33[0] = (char)toupper((unsigned char)scheme);
    memcpy(out33 + 1, enc32, 32);
    out33[33] = '\0';
    return PAYHSM_RC_OK;
}

static int thales_scheme_ok(char c) {
    c = (char)toupper((unsigned char)c);
    return c == 'U' || c == 'T' || c == 'X' || c == 'Y' || c == 'Z' || c == 'R' || c == 'S';
}

int payhsm_thales_block_unwrap(const uint8_t parent_key[PAYHSM_KEY_LEN],
                               const char in33[PAYHSM_THALES_BLOCK_LEN + 1],
                               uint8_t clear[PAYHSM_KEY_LEN]) {
    if (!in33 || !thales_scheme_ok(in33[0])) return PAYHSM_RC_ERR;
    return payhsm_unwrap_ecb_hex(parent_key, in33 + 1, clear);
}

typedef struct {
    const char *in33;
    uint8_t *clear;
    int rc;
} thales_lmk_arg_t;

static int thales_unwrap_lmk_fn(const uint8_t lmk[32], void *v) {
    thales_lmk_arg_t *a = (thales_lmk_arg_t *)v;
    a->rc = payhsm_thales_block_unwrap(lmk, a->in33, a->clear);
    return a->rc == PAYHSM_RC_OK ? PAYHSM_RC_OK : PAYHSM_RC_ERR;
}

int payhsm_thales_block_unwrap_lmk(const char in33[PAYHSM_THALES_BLOCK_LEN + 1],
                                   uint8_t clear[PAYHSM_KEY_LEN]) {
    thales_lmk_arg_t a = { in33, clear, PAYHSM_RC_ERR };
    return with_lmk_op(thales_unwrap_lmk_fn, &a);
}

typedef struct {
    const uint8_t *key;
    char *blob88;
    int rc;
} wrap_arg_t;

static int wrap_fn(const uint8_t lmk[32], void *v) {
    wrap_arg_t *a = (wrap_arg_t *)v;
    uint8_t blob[PAYHSM_GCM_BLOB_BYTES];
    a->rc = lmk_gcm_encrypt_blob(lmk, a->key, blob);
    if (a->rc == 0) hex_encode_local(blob, PAYHSM_GCM_BLOB_BYTES, a->blob88);
    return a->rc == 0 ? PAYHSM_RC_OK : PAYHSM_RC_ERR;
}

int payhsm_wrap_lmk_gcm_hex(const uint8_t key[PAYHSM_KEY_LEN], char blob88[PAYHSM_GCM_BLOB_HEX + 1]) {
    wrap_arg_t a = { key, blob88, -1 };
    return with_lmk_op(wrap_fn, &a);
}

/* ZPK : 88 hex GCM sous LMK (SWITCH PULL / A6) ou 32 hex ECB sous ZMK (export Thales). */
static int unwrap_zpk_under_zmk(const char *zmk_gcm88,
                                const char *zpk_field,
                                uint8_t zpk_out[PAYHSM_KEY_LEN]) {
    if (!zpk_field || !zpk_out) return PAYHSM_RC_ERR;
    size_t n = strlen(zpk_field);
    if (n == 88)
        return payhsm_unwrap_lmk_gcm_hex(zpk_field, zpk_out);
    if (n == 32 && zmk_gcm88 && zmk_gcm88[0]) {
        uint8_t zmk[PAYHSM_KEY_LEN];
        if (payhsm_unwrap_lmk_gcm_hex(zmk_gcm88, zmk) != PAYHSM_RC_OK)
            return PAYHSM_RC_ERR;
        int rc = payhsm_unwrap_ecb_hex(zmk, zpk_field, zpk_out);
        secure_zero(zmk, sizeof(zmk));
        return rc;
    }
    return PAYHSM_RC_ERR;
}

int payhsm_switch_wrap_lmk_gcm_under_zmk(const char *zmk_gcm88,
                                          const char *key_gcm88,
                                          char key_under_zmk32[33],
                                          char kcv_out[7]) {
    uint8_t zmk[PAYHSM_KEY_LEN], key[PAYHSM_KEY_LEN], enc[PAYHSM_KEY_LEN], kcv[3];
    if (!zmk_gcm88 || !key_gcm88 || !key_under_zmk32) return PAYHSM_RC_ERR;
    if (payhsm_unwrap_lmk_gcm_hex(zmk_gcm88, zmk) != PAYHSM_RC_OK) return PAYHSM_RC_ERR;
    if (payhsm_unwrap_lmk_gcm_hex(key_gcm88, key) != PAYHSM_RC_OK) {
        secure_zero(zmk, sizeof(zmk));
        return PAYHSM_RC_ERR;
    }
    if (ecb_encrypt_under(zmk, key, enc) != 0) {
        secure_zero(zmk, sizeof(zmk));
        secure_zero(key, sizeof(key));
        return PAYHSM_RC_ERR;
    }
    hex_encode_local(enc, PAYHSM_KEY_LEN, key_under_zmk32);
    if (kcv_out) {
        compute_kcv(key, PAYHSM_KEY_LEN, kcv);
        snprintf(kcv_out, 7, "%02X%02X%02X", kcv[0], kcv[1], kcv[2]);
    }
    secure_zero(zmk, sizeof(zmk));
    secure_zero(key, sizeof(key));
    return PAYHSM_RC_OK;
}

int payhsm_switch_wrap_zpk_under_zmk(const char *zmk_gcm88,
                                      const uint8_t zpk[PAYHSM_KEY_LEN],
                                      char zpk_enc32hex[33],
                                      char kcv_out[7]) {
    uint8_t zmk[PAYHSM_KEY_LEN], enc[PAYHSM_KEY_LEN], kcv[3];
    if (!zmk_gcm88 || !zpk || !zpk_enc32hex) return PAYHSM_RC_ERR;
    if (payhsm_unwrap_lmk_gcm_hex(zmk_gcm88, zmk) != PAYHSM_RC_OK) return PAYHSM_RC_ERR;
    if (ecb_encrypt_under(zmk, zpk, enc) != 0) {
        secure_zero(zmk, sizeof(zmk));
        return PAYHSM_RC_ERR;
    }
    hex_encode_local(enc, PAYHSM_KEY_LEN, zpk_enc32hex);
    if (kcv_out) {
        compute_kcv(zpk, PAYHSM_KEY_LEN, kcv);
        snprintf(kcv_out, 7, "%02X%02X%02X", kcv[0], kcv[1], kcv[2]);
    }
    secure_zero(zmk, sizeof(zmk));
    return PAYHSM_RC_OK;
}

int payhsm_switch_derive_terminal(const char *tmk_gcm88,
                                  const char *terminal_id,
                                  char tpk_enc32hex[33],
                                  char tak_enc32hex[33],
                                  char tpk_kcv[7],
                                  char tak_kcv[7]) {
    uint8_t tmk[16], tpk[16], tak[16], enc[16], kcv[3];
    if (payhsm_unwrap_lmk_gcm_hex(tmk_gcm88, tmk) != PAYHSM_RC_OK) return PAYHSM_RC_ERR;
    if (derive_tpk_from_tmk(tmk, 16, terminal_id, tpk) != 0 ||
        derive_tak_from_tmk(tmk, 16, terminal_id, tak) != 0) {
        secure_zero(tmk, sizeof(tmk));
        return PAYHSM_RC_ERR;
    }
    if (ecb_encrypt_under(tmk, tpk, enc) != 0) {
        secure_zero(tmk, sizeof(tmk));
        return PAYHSM_RC_ERR;
    }
    hex_encode_local(enc, 16, tpk_enc32hex);
    compute_kcv(tpk, 16, kcv);
    snprintf(tpk_kcv, 7, "%02X%02X%02X", kcv[0], kcv[1], kcv[2]);
    if (ecb_encrypt_under(tmk, tak, enc) != 0) {
        secure_zero(tmk, sizeof(tmk));
        return PAYHSM_RC_ERR;
    }
    hex_encode_local(enc, 16, tak_enc32hex);
    compute_kcv(tak, 16, kcv);
    snprintf(tak_kcv, 7, "%02X%02X%02X", kcv[0], kcv[1], kcv[2]);
    secure_zero(tmk, sizeof(tmk));
    secure_zero(tpk, sizeof(tpk));
    secure_zero(tak, sizeof(tak));
    return PAYHSM_RC_OK;
}

/* TPK : 88 hex GCM sous LMK (PULL manuel) ou 32 hex ECB sous TMK (dérivation). */
static int unwrap_tpk_for_switch(const char *tmk_gcm88,
                                 const char *tpk_field,
                                 uint8_t tpk_clear[16]) {
    if (!tpk_field || !tpk_clear) return PAYHSM_RC_ERR;
    size_t n = strlen(tpk_field);
    if (n == 88)
        return payhsm_unwrap_lmk_gcm_hex(tpk_field, tpk_clear);
    if (n == 32 && tmk_gcm88 && tmk_gcm88[0]) {
        uint8_t tmk[16];
        if (payhsm_unwrap_lmk_gcm_hex(tmk_gcm88, tmk) != PAYHSM_RC_OK)
            return PAYHSM_RC_ERR;
        int rc = payhsm_unwrap_ecb_hex(tmk, tpk_field, tpk_clear);
        secure_zero(tmk, sizeof(tmk));
        return rc;
    }
    return PAYHSM_RC_ERR;
}

int payhsm_gap_switch(const char *tmk_gcm88,
                      const char *tpk_enc32hex,
                      const char *pin,
                      const char *pan,
                      uint8_t pin_block[8]) {
    uint8_t tpk[16];
    if (unwrap_tpk_for_switch(tmk_gcm88, tpk_enc32hex, tpk) != PAYHSM_RC_OK)
        return PAYHSM_RC_ERR;
    int r = generate_pin_block(pin, pan, tpk, 16, pin_block);
    secure_zero(tpk, sizeof(tpk));
    return r == 0 ? PAYHSM_RC_OK : PAYHSM_RC_ERR;
}

int payhsm_verify_pin_switch(const char *tmk_gcm88,
                             const char *tpk_enc32hex,
                             const char *pvk_gcm88,
                             const char *pan,
                             const char *pvv_stored,
                             const uint8_t pin_block[8],
                             int *rc_out) {
    /* PVV fourni par le Core Banking — le HSM ne le stocke plus */
    if (!pvv_stored || pvv_stored[0] == '\0') return PAYHSM_RC_ERR;

    uint8_t tpk[16], pvk[16];
    if (unwrap_tpk_for_switch(tmk_gcm88, tpk_enc32hex, tpk) != PAYHSM_RC_OK ||
        payhsm_unwrap_lmk_gcm_hex(pvk_gcm88, pvk) != PAYHSM_RC_OK) {
        secure_zero(tpk, sizeof(tpk));
        return PAYHSM_RC_ERR;
    }
    int ok = verify_encrypted_pin_block(pin_block, pan, tpk, 16, pvk, 16, pvv_stored);
    secure_zero(tpk, sizeof(tpk));
    secure_zero(pvk, sizeof(pvk));
    if (rc_out) *rc_out = (ok == 0) ? PAYHSM_RC_OK : PAYHSM_RC_DECLINED;
    return PAYHSM_RC_OK;
}

int payhsm_translate_pin_switch(const char *tmk_gcm88,
                                const char *tpk_enc32hex,
                                const char *zmk_gcm88,
                                const char *zpk_enc32hex,
                                const uint8_t pin_block_tpk[8],
                                uint8_t pin_block_zpk[8]) {
    uint8_t tpk[16], zpk[16];
    if (unwrap_tpk_for_switch(tmk_gcm88, tpk_enc32hex, tpk) != PAYHSM_RC_OK ||
        unwrap_zpk_under_zmk(zmk_gcm88, zpk_enc32hex, zpk) != PAYHSM_RC_OK) {
        secure_zero(tpk, sizeof(tpk));
        return PAYHSM_RC_ERR;
    }
    int r = translate_pin_block(pin_block_tpk, "", tpk, 16, zpk, 16, pin_block_zpk);
    secure_zero(tpk, sizeof(tpk));
    secure_zero(zpk, sizeof(zpk));
    return r == 0 ? PAYHSM_RC_OK : PAYHSM_RC_ERR;
}

int payhsm_translate_zpk_switch(const char *zmk_gcm88,
                                const char *zpk_a_enc32hex,
                                const char *zpk_b_enc32hex,
                                const uint8_t pin_block_in[8],
                                uint8_t pin_block_out[8]) {
    uint8_t zpk_a[16], zpk_b[16];
    if (unwrap_zpk_under_zmk(zmk_gcm88, zpk_a_enc32hex, zpk_a) != PAYHSM_RC_OK) return PAYHSM_RC_ERR;
    if (unwrap_zpk_under_zmk(zmk_gcm88, zpk_b_enc32hex, zpk_b) != PAYHSM_RC_OK) {
        secure_zero(zpk_a, sizeof(zpk_a));
        return PAYHSM_RC_ERR;
    }
    int r = translate_pin_block(pin_block_in, "", zpk_a, 16, zpk_b, 16, pin_block_out);
    secure_zero(zpk_a, sizeof(zpk_a));
    secure_zero(zpk_b, sizeof(zpk_b));
    return r == 0 ? PAYHSM_RC_OK : PAYHSM_RC_ERR;
}

int payhsm_verify_pin_zpk_switch(const char *zmk_gcm88,
                                 const char *zpk_enc32hex,
                                 const char *pvk_gcm88,
                                 const char *pan,
                                 const uint8_t pin_block[8],
                                 int *rc_out) {
    char pvv[8];
    if (payhsm_corebanking_get_pvv(pan, pvv) != PAYHSM_RC_OK) return PAYHSM_RC_ERR;

    uint8_t zpk[16], pvk[16];
    if (unwrap_zpk_under_zmk(zmk_gcm88, zpk_enc32hex, zpk) != PAYHSM_RC_OK) return PAYHSM_RC_ERR;
    if (payhsm_unwrap_lmk_gcm_hex(pvk_gcm88, pvk) != PAYHSM_RC_OK) {
        secure_zero(zpk, sizeof(zpk));
        return PAYHSM_RC_ERR;
    }
    int ok = verify_encrypted_pin_block(pin_block, pan, zpk, 16, pvk, 16, pvv);
    secure_zero(zpk, sizeof(zpk));
    secure_zero(pvk, sizeof(pvk));
    if (rc_out) *rc_out = (ok == 0) ? PAYHSM_RC_OK : PAYHSM_RC_DECLINED;
    return PAYHSM_RC_OK;
}

int payhsm_mac_tak_switch(const char *tmk_gcm88,
                          const char *tak_enc32hex,
                          const uint8_t *msg,
                          size_t msg_len,
                          uint8_t mac_out[8]) {
    uint8_t tmk[16], tak[16];
    if (payhsm_unwrap_lmk_gcm_hex(tmk_gcm88, tmk) != PAYHSM_RC_OK) return PAYHSM_RC_ERR;
    if (payhsm_unwrap_ecb_hex(tmk, tak_enc32hex, tak) != PAYHSM_RC_OK) {
        secure_zero(tmk, sizeof(tmk));
        return PAYHSM_RC_ERR;
    }
    int r = calculate_mac_tak(msg, msg_len, tak, 16, mac_out);
    secure_zero(tmk, sizeof(tmk));
    secure_zero(tak, sizeof(tak));
    return r == 0 ? PAYHSM_RC_OK : PAYHSM_RC_ERR;
}

int payhsm_mac_verify_switch(const char *tmk_gcm88,
                             const char *tak_enc32hex,
                             const uint8_t *msg,
                             size_t msg_len,
                             const uint8_t mac[8]) {
    uint8_t tmk[16], tak[16];
    if (payhsm_unwrap_lmk_gcm_hex(tmk_gcm88, tmk) != PAYHSM_RC_OK) return PAYHSM_RC_ERR;
    if (payhsm_unwrap_ecb_hex(tmk, tak_enc32hex, tak) != PAYHSM_RC_OK) {
        secure_zero(tmk, sizeof(tmk));
        return PAYHSM_RC_ERR;
    }
    int r = verify_mac(msg, msg_len, tak, 16, mac);
    secure_zero(tmk, sizeof(tmk));
    secure_zero(tak, sizeof(tak));
    return r == 0 ? PAYHSM_RC_OK : PAYHSM_RC_ERR;
}

int payhsm_corebanking_issue_pvv_switch(const char *pan,
                                        const char *pin,
                                        const char *pvk_gcm88,
                                        char pvv_out[5]) {
    uint8_t pvk[16];
    if (payhsm_unwrap_lmk_gcm_hex(pvk_gcm88, pvk) != PAYHSM_RC_OK) return PAYHSM_RC_ERR;
    if (pin_compute_pvv(pin, pan, pvk, 16, pvv_out) != 0) {
        secure_zero(pvk, sizeof(pvk));
        return PAYHSM_RC_ERR;
    }
    secure_zero(pvk, sizeof(pvk));
    return payhsm_set_card_pvv(pan, pvv_out);
}

static int hex_decode_atc(const char *atc_hex, uint8_t atc_b[2]) {
    return hex_decode_local(atc_hex, atc_b, 2);
}

/* Une seule recomposition LMK : déchiffre ENC(LMK,IMK) puis exécute l'opération */
typedef struct {
    const char *gcm88;
    int (*fn)(const uint8_t imk[16], void *ctx);
    void *ctx;
    int rc;
} imk_gcm_op_t;

static int imk_gcm_op_lmk(const uint8_t lmk[32], void *v) {
    imk_gcm_op_t *a = (imk_gcm_op_t *)v;
    uint8_t blob[PAYHSM_GCM_BLOB_BYTES], imk[16];
    int fn_rc;
    if (hex_decode_local(a->gcm88, blob, sizeof(blob)) != 0) return PAYHSM_RC_ERR;
    if (lmk_gcm_decrypt_blob(lmk, blob, imk) != 0) return PAYHSM_RC_ERR;
    fn_rc = a->fn(imk, a->ctx);
    secure_zero(imk, sizeof(imk));
    return fn_rc == 0 ? PAYHSM_RC_OK : PAYHSM_RC_ERR;
}

static int with_imk_from_gcm(const char *gcm88,
                             int (*fn)(const uint8_t imk[16], void *ctx),
                             void *ctx) {
    imk_gcm_op_t a = { gcm88, fn, ctx, -1 };
    return with_lmk_op(imk_gcm_op_lmk, &a);
}

static int emv_derive_sk(const uint8_t imk[16],
                         const char *pan,
                         const char *psn,
                         const char *atc_hex,
                         uint8_t mk[16],
                         uint8_t sk[16]) {
    uint8_t atc_b[2];
    if (derive_card_keys(imk, 16, pan, psn, mk) != 0) return -1;
    if (hex_decode_atc(atc_hex, atc_b) != 0) return -1;
    return derive_sk_ac(mk, atc_b, sk);
}

typedef struct {
    const char *pan;
    const char *psn;
    const char *atc_hex;
    unsigned long amount_cents;
    const char *currency_code3;
    const char *date_yymmdd6;
    const char *terminal_id;
    char *arqc_hex;
    char *tx_data_out;
    size_t tx_cap;
    size_t *tx_len_out;
    int rc;
} emv_arqc_ctx_t;

static int emv_arqc_with_imk(const uint8_t imk[16], void *v) {
    emv_arqc_ctx_t *a = (emv_arqc_ctx_t *)v;
    uint8_t mk[16], sk[16], arqc[8];
    size_t tx_len = 0;

    a->rc = -1;
    if (emv_build_tx_data(a->amount_cents, a->currency_code3,
                          a->date_yymmdd6, a->atc_hex, a->terminal_id,
                          a->tx_data_out, a->tx_cap, &tx_len) != 0)
        return -1;
    if (emv_derive_sk(imk, a->pan, a->psn, a->atc_hex, mk, sk) != 0 ||
        emv_compute_arqc(sk, (const uint8_t *)a->tx_data_out, tx_len, arqc) != 0) {
        secure_zero(mk, sizeof(mk));
        secure_zero(sk, sizeof(sk));
        return -1;
    }
    hex_encode_local(arqc, 8, a->arqc_hex);
    *a->tx_len_out = tx_len;
    emv_sess_store(a->pan, a->psn, a->atc_hex, a->arqc_hex,
                   a->tx_data_out, tx_len, mk, sk);
    secure_zero(mk, sizeof(mk));
    secure_zero(sk, sizeof(sk));
    a->rc = 0;
    return 0;
}


int payhsm_emv_arqc_switch(const char *imk_gcm88,
                           const char *pan,
                           const char *psn,
                           const char *atc_hex,
                           unsigned long amount_cents,
                           const char *currency_code3,
                           const char *date_yymmdd6,
                           const char *terminal_id,
                           char arqc_hex[17],
                           char tx_data_out[256],
                           size_t tx_cap,
                           size_t *tx_len_out) {
    if (!arqc_hex || !tx_data_out || !tx_len_out) return PAYHSM_RC_ERR;
    if (payhsm_corebanking_card_enrolled(pan) != PAYHSM_RC_OK)
        return PAYHSM_RC_CARD_UNKNOWN;
    arqc_hex[0] = '\0';
    *tx_len_out = 0;

    emv_arqc_ctx_t ctx = {
        pan, psn, atc_hex, amount_cents, currency_code3, date_yymmdd6, terminal_id,
        arqc_hex, tx_data_out, tx_cap, tx_len_out, -1,
    };
    return with_imk_from_gcm(imk_gcm88, emv_arqc_with_imk, &ctx);
}

typedef struct {
    const char *pan;
    const char *psn;
    const char *atc_hex;
    const uint8_t *tx_data;
    size_t tx_len;
    const char *arqc_hex;
    int *valid_out;
    char *arpc_hex;
    int *arpc_card_valid_out;
    char *arpc_expected_hex;
    int rc;
} emv_verify_ctx_t;

static int emv_verify_with_imk(const uint8_t imk[16], void *v) {
    emv_verify_ctx_t *a = (emv_verify_ctx_t *)v;
    uint8_t mk[16], sk[16], arqc[8], arpc[8];
    int use_sess = 0;

    (void)imk;
    a->rc = -1;
    if (hex_decode_local(a->arqc_hex, arqc, 8) != 0) return -1;

    if (emv_sess_matches(a->pan, a->psn, a->atc_hex, a->arqc_hex) &&
        a->tx_len == g_emv_sess.tx_len &&
        memcmp(a->tx_data, g_emv_sess.tx, a->tx_len) == 0) {
        memcpy(mk, g_emv_sess.mk, 16);
        memcpy(sk, g_emv_sess.sk, 16);
        use_sess = 1;
    } else if (emv_derive_sk(imk, a->pan, a->psn, a->atc_hex, mk, sk) != 0) {
        secure_zero(mk, sizeof(mk));
        secure_zero(sk, sizeof(sk));
        return -1;
    }

    int ok = (verify_arqc(sk, a->tx_data, a->tx_len, arqc) == 0);
    if (a->valid_out) *a->valid_out = ok ? 1 : 0;
    if (a->arpc_card_valid_out) *a->arpc_card_valid_out = 0;
    if (a->arpc_expected_hex) a->arpc_expected_hex[0] = '\0';
    if (ok && a->arpc_hex) {
        uint8_t arc[2] = {0x00, 0x00};
        generate_arpc(mk, arqc, arc, arpc);
        hex_encode_local(arpc, 8, a->arpc_hex);
        if (a->arpc_expected_hex)
            strncpy(a->arpc_expected_hex, a->arpc_hex, 16);
        if (a->arpc_card_valid_out)
            *a->arpc_card_valid_out =
                (verify_arpc(mk, arqc, arc, arpc) == 0) ? 1 : 0;
        if (g_emv_sess.active) {
            memcpy(g_emv_sess.mk, mk, 16);
            memcpy(g_emv_sess.sk, sk, 16);
            strncpy(g_emv_sess.issuer_arpc_hex, a->arpc_hex,
                    sizeof(g_emv_sess.issuer_arpc_hex) - 1);
            g_emv_sess.issuer_arpc_ready = 1;
        }
        payhsm_emv_clear_session();
    }
    secure_zero(mk, sizeof(mk));
    secure_zero(sk, sizeof(sk));
    a->rc = ok ? 0 : -1;
    (void)use_sess;
    return a->rc;
}

int payhsm_emv_verify_switch(const char *imk_gcm88,
                             const char *pan,
                             const char *psn,
                             const char *atc_hex,
                             const uint8_t *tx_data,
                             size_t tx_len,
                             const char *arqc_hex,
                             int *valid_out,
                             char arpc_hex[17],
                             int *arpc_card_valid_out,
                             char arpc_expected_hex[17]) {
    if (valid_out) *valid_out = 0;
    if (arpc_hex) arpc_hex[0] = '\0';
    if (arpc_card_valid_out) *arpc_card_valid_out = 0;
    if (arpc_expected_hex) arpc_expected_hex[0] = '\0';
    if (!tx_data || !arqc_hex) return PAYHSM_RC_ERR;
    if (payhsm_corebanking_card_enrolled(pan) != PAYHSM_RC_OK)
        return PAYHSM_RC_CARD_UNKNOWN;

    emv_verify_ctx_t ctx = {
        pan, psn, atc_hex, tx_data, tx_len, arqc_hex,
        valid_out, arpc_hex, arpc_card_valid_out, arpc_expected_hex, -1,
    };
    return with_imk_from_gcm(imk_gcm88, emv_verify_with_imk, &ctx);
}

typedef struct {
    const char *pan;
    const char *psn;
    const char *atc_hex;
    const char *arqc_hex;
    const char *arpc_hex;
    const char *arc_hex4;
    int *valid_out;
    char *arpc_expected_hex;
    int rc;
} emv_verify_arpc_ctx_t;

static int emv_verify_arpc_with_imk(const uint8_t imk[16], void *v) {
    emv_verify_arpc_ctx_t *a = (emv_verify_arpc_ctx_t *)v;
    uint8_t mk[16], sk[16], arqc[8], arpc_rx[8], arpc_exp[8], arc[2] = {0x00, 0x00};

    a->rc = -1;
    if (a->valid_out) *a->valid_out = 0;
    if (a->arpc_expected_hex) a->arpc_expected_hex[0] = '\0';

    /* MK-AC de l'émetteur (après verify), pas celle du seul ARQC */
    if (g_emv_sess.active && g_emv_sess.issuer_arpc_ready &&
        emv_sess_matches(a->pan, a->psn, a->atc_hex, a->arqc_hex)) {
        memcpy(mk, g_emv_sess.mk, 16);
    } else if (emv_derive_sk(imk, a->pan, a->psn, a->atc_hex, mk, sk) != 0) {
        secure_zero(mk, sizeof(mk));
        return -1;
    }

    if (hex_decode_local(a->arqc_hex, arqc, 8) != 0 ||
        hex_decode_local(a->arpc_hex, arpc_rx, 8) != 0) {
        secure_zero(mk, sizeof(mk));
        return -1;
    }
    if (a->arc_hex4 && strlen(a->arc_hex4) >= 4) {
        uint8_t ab[2];
        if (hex_decode_local(a->arc_hex4, ab, 2) == 0) {
            arc[0] = ab[0];
            arc[1] = ab[1];
        }
    }

    if (generate_arpc(mk, arqc, arc, arpc_exp) != 0) {
        secure_zero(mk, sizeof(mk));
        return -1;
    }
    if (a->arpc_expected_hex)
        hex_encode_local(arpc_exp, 8, a->arpc_expected_hex);

    int ok = (verify_arpc(mk, arqc, arc, arpc_rx) == 0);
    if (g_emv_sess.active && g_emv_sess.issuer_arpc_ready && ok &&
        strcasecmp(g_emv_sess.issuer_arpc_hex, a->arpc_hex) != 0)
        ok = 0;
    if (a->valid_out) *a->valid_out = ok ? 1 : 0;
    a->rc = ok ? 0 : -1;
    secure_zero(mk, sizeof(mk));
    secure_zero(sk, sizeof(sk));
    payhsm_emv_clear_session();
    return a->rc;
}

int payhsm_emv_verify_arpc_switch(const char *imk_gcm88,
                                  const char *pan,
                                  const char *psn,
                                  const char *atc_hex,
                                  const char *arqc_hex,
                                  const char *arpc_hex,
                                  const char *arc_hex4,
                                  int *valid_out,
                                  char arpc_expected_hex[17]) {
    if (valid_out) *valid_out = 0;
    if (arpc_expected_hex) arpc_expected_hex[0] = '\0';
    if (!pan || !psn || !atc_hex || !arqc_hex || !arpc_hex) return PAYHSM_RC_ERR;
    if (payhsm_corebanking_card_enrolled(pan) != PAYHSM_RC_OK)
        return PAYHSM_RC_CARD_UNKNOWN;

    emv_verify_arpc_ctx_t ctx = {
        pan, psn, atc_hex, arqc_hex, arpc_hex, arc_hex4,
        valid_out, arpc_expected_hex, -1,
    };
    return with_imk_from_gcm(imk_gcm88, emv_verify_arpc_with_imk, &ctx);
}

typedef struct {
    const char *imk_gcm88;
    const char *pan;
    const char *psn;
    const char *atc_hex;
    unsigned long amount_cents;
    const char *currency_code3;
    const char *date_yymmdd6;
    const char *terminal_id;
    payhsm_emv_purchase_t *result;
} emv_purchase_ctx_t;

static int emv_purchase_with_imk(const uint8_t imk[16], void *v) {
    emv_purchase_ctx_t *a = (emv_purchase_ctx_t *)v;
    payhsm_emv_purchase_t *r = a->result;
    uint8_t mk[16], sk[16], atc_b[2], arqc[8], arpc[8];
    size_t tx_len = 0;

    if (emv_build_tx_data(a->amount_cents, a->currency_code3,
                          a->date_yymmdd6, a->atc_hex, a->terminal_id,
                          r->tx_data, sizeof(r->tx_data), &tx_len) != 0)
        return -1;
    if (derive_card_keys(imk, 16, a->pan, a->psn, mk) != 0 ||
        hex_decode_atc(a->atc_hex, atc_b) != 0 ||
        derive_sk_ac(mk, atc_b, sk) != 0)
        return -1;
    if (emv_compute_arqc(sk, (const uint8_t *)r->tx_data, tx_len, arqc) != 0)
        return -1;
    hex_encode_local(arqc, 8, r->arqc_hex);
    if (verify_arqc(sk, (const uint8_t *)r->tx_data, tx_len, arqc) != 0) {
        r->approved = 0;
        r->rc = PAYHSM_RC_DECLINED;
        strncpy(r->message, "ARQC invalide (emv.c)", sizeof(r->message) - 1);
        secure_zero(mk, sizeof(mk));
        secure_zero(sk, sizeof(sk));
        return 0;
    }
    uint8_t arc[2] = {0x00, 0x00};
    generate_arpc(mk, arqc, arc, arpc);
    hex_encode_local(arpc, 8, r->arpc_hex);
    secure_zero(mk, sizeof(mk));
    secure_zero(sk, sizeof(sk));
    r->approved = 1;
    r->rc = PAYHSM_RC_OK;
    strncpy(r->message, "Paiement EMV approuve (emv.c)", sizeof(r->message) - 1);
    return 0;
}

static int emv_purchase_lmk(const uint8_t lmk[32], void *v) {
    emv_purchase_ctx_t *a = (emv_purchase_ctx_t *)v;
    uint8_t blob[PAYHSM_GCM_BLOB_BYTES], imk[16];
    if (hex_decode_local(a->imk_gcm88, blob, sizeof(blob)) != 0) return PAYHSM_RC_ERR;
    if (lmk_gcm_decrypt_blob(lmk, blob, imk) != 0) return PAYHSM_RC_ERR;
    int r = emv_purchase_with_imk(imk, a);
    secure_zero(imk, sizeof(imk));
    return r == 0 ? PAYHSM_RC_OK : PAYHSM_RC_ERR;
}

int payhsm_emv_purchase_switch(const char *imk_gcm88,
                               const char *pan,
                               const char *psn,
                               const char *atc_hex,
                               unsigned long amount_cents,
                               const char *currency_code3,
                               const char *date_yymmdd6,
                               const char *terminal_id,
                               payhsm_emv_purchase_t *result) {
    if (!result) return PAYHSM_RC_ERR;
    if (payhsm_corebanking_card_enrolled(pan) != PAYHSM_RC_OK)
        return PAYHSM_RC_CARD_UNKNOWN;
    memset(result, 0, sizeof(*result));
    snprintf(result->amount_display, sizeof(result->amount_display),
             "%lu.%02lu %s", amount_cents / 100, amount_cents % 100, currency_code3);

    emv_purchase_ctx_t ctx = {
        imk_gcm88, pan, psn, atc_hex, amount_cents, currency_code3,
        date_yymmdd6, terminal_id, result,
    };
    return with_lmk_op(emv_purchase_lmk, &ctx);
}
