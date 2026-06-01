#include "emv.h"
#include "../defense/defense.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/cmac.h>
#include <openssl/core_names.h>

int derive_card_keys(const uint8_t *imk, size_t imk_len,
                     const char *pan, const char *psn,
                     uint8_t mk_ac_out[16]) {
    if (!imk || !pan || !psn || !mk_ac_out) return -1;

    /* Concaténer PAN + PSN en 8 octets BCD */
    uint8_t input[16] = {0};
    int plen = (int)strlen(pan);
    const char *p14 = pan + (plen - 14);
    uint8_t n[16] = {0};
    for (int i = 0; i < 14; i++) n[i] = p14[i] - '0';
    n[14] = psn[0] - '0';
    n[15] = psn[1] - '0';
    for (int i = 0; i < 8; i++) input[i] = (n[2*i] << 4) | n[2*i+1];

    /* Bloc Y = ~X */
    uint8_t input_inv[8];
    for (int i = 0; i < 8; i++) input_inv[i] = ~input[i];

    /* AES-ECB(IMK, X) || AES-ECB(IMK, ~X) → 16 octets */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *c = (imk_len == 16) ? EVP_aes_128_ecb() : EVP_aes_256_ecb();
    int len;
    EVP_EncryptInit_ex(ctx, c, NULL, imk, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptUpdate(ctx, mk_ac_out, &len, input, 8);
    EVP_EncryptUpdate(ctx, mk_ac_out + 8, &len, input_inv, 8);
    EVP_CIPHER_CTX_free(ctx);

    secure_zero(input,     16);
    secure_zero(input_inv, 8);

    fprintf(stderr, "[EMV] MK-AC derivee pour PAN %s PSN %s\n", pan, psn);
    return 0;
}

int derive_sk_ac(const uint8_t mk_ac[16], const uint8_t atc[2],
                 uint8_t sk_ac_out[16]) {
    if (!mk_ac || !atc || !sk_ac_out) return -1;

    uint8_t block[8];
    memcpy(block, atc, 2);
    memset(block + 2, 0, 6);

    uint8_t block_inv[8];
    for (int i = 0; i < 8; i++) block_inv[i] = ~block[i];

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, mk_ac, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptUpdate(ctx, sk_ac_out, &len, block, 8);
    EVP_EncryptUpdate(ctx, sk_ac_out + 8, &len, block_inv, 8);
    EVP_CIPHER_CTX_free(ctx);

    secure_zero(block, 8);
    secure_zero(block_inv, 8);
    return 0;
}

int verify_arqc(const uint8_t sk_ac[16],
                const uint8_t *transaction_data, size_t tx_len,
                const uint8_t arqc_received[8]) {
    if (!sk_ac || !transaction_data || !arqc_received) return -1;

    uint8_t expected[8];
    if (emv_compute_arqc(sk_ac, transaction_data, tx_len, expected) != 0)
        return -1;

    uint8_t diff = 0;
    for (int i = 0; i < 8; i++) diff |= expected[i] ^ arqc_received[i];

    int ok = (diff == 0);
    fprintf(stderr, "[EMV] Verification ARQC : %s\n", ok ? "OK" : "KO");
    return ok ? 0 : -1;
}

int generate_arpc(const uint8_t *mk_ac,
                  const uint8_t arqc[8],
                  const uint8_t auth_response[2],
                  uint8_t arpc_out[8]) {
    if (!mk_ac || !arqc || !auth_response || !arpc_out) return -1;

    /* ARPC Method 1 (EMV) : AES-128-ECB(MK-AC, bloc 16o)
       = ARQC[0..7] avec ARC XOR sur les 2 premiers octets, reste à zéro */
    uint8_t block[16], out[16];
    memset(block, 0, sizeof(block));
    memcpy(block, arqc, 8);
    block[0] ^= auth_response[0];
    block[1] ^= auth_response[1];

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len = 0, fin = 0;
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, mk_ac, NULL) ||
        !EVP_CIPHER_CTX_set_padding(ctx, 0) ||
        !EVP_EncryptUpdate(ctx, out, &len, block, 16) ||
        !EVP_EncryptFinal_ex(ctx, out + len, &fin)) {
        EVP_CIPHER_CTX_free(ctx);
        secure_zero(block, sizeof(block));
        return -1;
    }
    EVP_CIPHER_CTX_free(ctx);
    memcpy(arpc_out, out, 8);

    secure_zero(block, sizeof(block));
    secure_zero(out, sizeof(out));

    fprintf(stderr, "[EMV] ARPC genere OK\n");
    return 0;
}

int verify_arpc(const uint8_t mk_ac[16],
                const uint8_t arqc[8],
                const uint8_t auth_response[2],
                const uint8_t arpc_received[8]) {
    if (!mk_ac || !arqc || !auth_response || !arpc_received) return -1;

    uint8_t expected[8];
    if (generate_arpc(mk_ac, arqc, auth_response, expected) != 0)
        return -1;

    uint8_t diff = 0;
    for (int i = 0; i < 8; i++) diff |= expected[i] ^ arpc_received[i];

    int ok = (diff == 0);
    fprintf(stderr, "[EMV] Verification ARPC puce : %s\n", ok ? "OK" : "KO");
    return ok ? 0 : -1;
}

int emv_compute_arqc(const uint8_t sk_ac[16],
                     const uint8_t *transaction_data,
                     size_t tx_len,
                     uint8_t arqc_out[8]) {
    if (!sk_ac || !transaction_data || !arqc_out) return -1;

#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_MAC *mac_obj = EVP_MAC_fetch(NULL, "CMAC", NULL);
    if (!mac_obj) return -1;
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac_obj);
    EVP_MAC_free(mac_obj);
    if (!ctx) return -1;
    char cipher_name[] = "AES-128-CBC";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, cipher_name, 0),
        OSSL_PARAM_construct_end()
    };
    uint8_t full[16];
    size_t mlen = 16;
    if (!EVP_MAC_init(ctx, sk_ac, 16, params) ||
        !EVP_MAC_update(ctx, transaction_data, tx_len) ||
        !EVP_MAC_final(ctx, full, &mlen, sizeof(full))) {
        EVP_MAC_CTX_free(ctx);
        return -1;
    }
    EVP_MAC_CTX_free(ctx);
#else
    CMAC_CTX *ctx = CMAC_CTX_new();
    if (!ctx) return -1;
    uint8_t full[16];
    size_t mlen = 16;
    if (!CMAC_Init(ctx, sk_ac, 16, EVP_aes_128_cbc(), NULL) ||
        !CMAC_Update(ctx, transaction_data, tx_len) ||
        !CMAC_Final(ctx, full, &mlen)) {
        CMAC_CTX_free(ctx);
        return -1;
    }
    CMAC_CTX_free(ctx);
#endif
    memcpy(arqc_out, full, 8);
    return 0;
}

int emv_build_tx_data(unsigned long amount_cents,
                      const char *currency_code3,
                      const char *date_yymmdd6,
                      const char *atc_hex4,
                      const char *terminal_id,
                      char *tx_out,
                      size_t tx_cap,
                      size_t *tx_len_out) {
    if (!currency_code3 || !atc_hex4 || !tx_out || !tx_len_out) return -1;

    char date6[7] = "000000";
    if (date_yymmdd6 && strlen(date_yymmdd6) >= 6)
        memcpy(date6, date_yymmdd6, 6);
    else {
        time_t now = time(NULL);
        struct tm tm;
#if defined(_WIN32)
        localtime_s(&tm, &now);
#else
        localtime_r(&now, &tm);
#endif
        snprintf(date6, sizeof(date6), "%02d%02d%02d",
                 tm.tm_year % 100, tm.tm_mon + 1, tm.tm_mday);
    }

    const char *term = (terminal_id && terminal_id[0]) ? terminal_id : "TPE0001";
    char atc4[5];
    snprintf(atc4, sizeof(atc4), "%.4s", atc_hex4);

    int n = snprintf(tx_out, tx_cap,
                     "AMT%06lu|CUR%s|DAT%s|ATC%s|TRM%s",
                     amount_cents, currency_code3, date6, atc4, term);
    if (n < 0 || (size_t)n >= tx_cap) return -1;
    *tx_len_out = (size_t)n;
    return 0;
}