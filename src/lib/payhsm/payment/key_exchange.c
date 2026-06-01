#include "key_exchange.h"
#include "../defense/defense.h"

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

int derive_tpk_from_tmk(const uint8_t *tmk, size_t tmk_len,
                        const char *terminal_id,
                        uint8_t tpk_out[16]) {
    if (!tmk || !terminal_id || !tpk_out) return -1;

    /* HMAC-SHA256(TMK, "TPK" || terminal_id) → tronqué à 16 octets */
    uint8_t mac[32];
    unsigned int mlen = 32;
    char info[128];
    snprintf(info, sizeof(info), "TPK:%s", terminal_id);

    HMAC(EVP_sha256(), tmk, (int)tmk_len,
         (uint8_t *)info, strlen(info), mac, &mlen);

    memcpy(tpk_out, mac, 16);
    secure_zero(mac, 32);

    fprintf(stderr, "[KX] TPK derivee depuis TMK pour %s\n", terminal_id);
    return 0;
}

int derive_tak_from_tmk(const uint8_t *tmk, size_t tmk_len,
                        const char *terminal_id,
                        uint8_t tak_out[16]) {
    if (!tmk || !terminal_id || !tak_out) return -1;

    uint8_t mac[32];
    unsigned int mlen = 32;
    char info[128];
    snprintf(info, sizeof(info), "TAK:%s", terminal_id);

    HMAC(EVP_sha256(), tmk, (int)tmk_len,
         (uint8_t *)info, strlen(info), mac, &mlen);

    memcpy(tak_out, mac, 16);
    secure_zero(mac, 32);

    fprintf(stderr, "[KX] TAK derivee depuis TMK pour %s\n", terminal_id);
    return 0;
}

int encrypt_zpk_under_zmk(const uint8_t *zpk, size_t zpk_len,
                          const uint8_t *zmk, size_t zmk_len,
                          uint8_t *out, size_t *out_len) {
    if (!zpk || !zmk || !out || !out_len) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *c = (zmk_len == 16) ? EVP_aes_128_ecb() : EVP_aes_256_ecb();
    int len, total = 0;

    EVP_EncryptInit_ex(ctx, c, NULL, zmk, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 1);
    EVP_EncryptUpdate(ctx, out, &len, zpk, (int)zpk_len);
    total = len;
    EVP_EncryptFinal_ex(ctx, out + len, &len);
    total += len;
    EVP_CIPHER_CTX_free(ctx);

    *out_len = total;
    fprintf(stderr, "[KX] ZPK chiffree sous ZMK\n");
    return 0;
}

int decrypt_zpk_under_zmk(const uint8_t *enc_zpk, size_t enc_len,
                          const uint8_t *zmk, size_t zmk_len,
                          uint8_t zpk_out[16]) {
    if (!enc_zpk || !zmk || !zpk_out) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *c = (zmk_len == 16) ? EVP_aes_128_ecb() : EVP_aes_256_ecb();
    int len;
    uint8_t buf[32];

    EVP_DecryptInit_ex(ctx, c, NULL, zmk, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 1);
    EVP_DecryptUpdate(ctx, buf, &len, enc_zpk, (int)enc_len);
    int final_len;
    EVP_DecryptFinal_ex(ctx, buf + len, &final_len);
    EVP_CIPHER_CTX_free(ctx);

    memcpy(zpk_out, buf, 16);
    secure_zero(buf, 32);

    fprintf(stderr, "[KX] ZPK dechiffree depuis ZMK\n");
    return 0;
}

int compute_kcv(const uint8_t *key, size_t key_len, uint8_t kcv_out[3]) {
    if (!key || !kcv_out) return -1;

    uint8_t zero[16] = {0}, enc[16];
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *c = (key_len == 16) ? EVP_aes_128_ecb() : EVP_aes_256_ecb();
    int len;

    EVP_EncryptInit_ex(ctx, c, NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptUpdate(ctx, enc, &len, zero, 16);
    EVP_CIPHER_CTX_free(ctx);

    memcpy(kcv_out, enc, 3);
    secure_zero(enc, 16);
    return 0;
}