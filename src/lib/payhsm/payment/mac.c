#include "mac.h"
#include "../defense/defense.h"

#include <stdio.h>
#include <string.h>
#include <openssl/cmac.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>

/* MAC CMAC-AES-128 tronqué à 8 octets (équivalent ISO 9797-1 algo 3) */
static int cmac_aes(const uint8_t *msg, size_t mlen,
                    const uint8_t *key, size_t klen,
                    uint8_t mac_out[8]) {
#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
    const char *cipher_name = (klen == 16) ? "AES-128-CBC" : "AES-256-CBC";
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
    if (!mac) return -1;

    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if (!ctx) return -1;

    char cipher_param[16];
    snprintf(cipher_param, sizeof(cipher_param), "%s", cipher_name);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, cipher_param, 0),
        OSSL_PARAM_construct_end()
    };

    uint8_t full[16];
    size_t out_len;

    if (!EVP_MAC_init(ctx, key, klen, params) ||
        !EVP_MAC_update(ctx, msg, mlen) ||
        !EVP_MAC_final(ctx, full, &out_len, sizeof(full))) {
        EVP_MAC_CTX_free(ctx);
        return -1;
    }

    EVP_MAC_CTX_free(ctx);
#else
    CMAC_CTX *ctx = CMAC_CTX_new();
    if (!ctx) return -1;

    const EVP_CIPHER *c = (klen == 16) ? EVP_aes_128_cbc() : EVP_aes_256_cbc();
    uint8_t full[16];
    size_t out_len;

    if (!CMAC_Init(ctx, key, klen, c, NULL) ||
        !CMAC_Update(ctx, msg, mlen) ||
        !CMAC_Final(ctx, full, &out_len)) {
        CMAC_CTX_free(ctx);
        return -1;
    }

    CMAC_CTX_free(ctx);
#endif

    memcpy(mac_out, full, 8);
    secure_zero(full, 16);
    return 0;
}

int calculate_mac_tak(const uint8_t *msg, size_t msg_len,
                      const uint8_t *tak, size_t tak_len,
                      uint8_t mac_out[8]) {
    if (!msg || !tak || !mac_out) return -1;
    int r = cmac_aes(msg, msg_len, tak, tak_len, mac_out);
    if (r == 0) fprintf(stderr, "[MAC] MAC TAK calcule OK\n");
    return r;
}

int calculate_mac_zak(const uint8_t *msg, size_t msg_len,
                      const uint8_t *zak, size_t zak_len,
                      uint8_t mac_out[8]) {
    if (!msg || !zak || !mac_out) return -1;
    int r = cmac_aes(msg, msg_len, zak, zak_len, mac_out);
    if (r == 0) fprintf(stderr, "[MAC] MAC ZAK calcule OK\n");
    return r;
}

/* Comparaison en temps constant pour résister aux timing attacks */
static int constant_time_eq(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

int verify_mac(const uint8_t *msg, size_t msg_len,
               const uint8_t *key, size_t key_len,
               const uint8_t mac_received[8]) {
    if (!msg || !key || !mac_received) return -1;

    uint8_t mac_calc[8];
    cmac_aes(msg, msg_len, key, key_len, mac_calc);

    int ok = constant_time_eq(mac_calc, mac_received, 8);
    secure_zero(mac_calc, 8);

    fprintf(stderr, "[MAC] Verification MAC : %s\n", ok ? "OK" : "KO");
    return ok ? 0 : -1;
}