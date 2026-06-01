#include "integrity.h"
#include "../defense/defense.h"

#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

static uint8_t g_hmac_ref[PAYHSM_HMAC_SIZE];
static int     g_has_ref = 0;

static void xor_frag(const uint8_t *p1, const uint8_t *p2, const uint8_t *p3,
                     uint8_t out[PAYHSM_LMK_SIZE]) {
    for (size_t i = 0; i < PAYHSM_LMK_SIZE; i++)
        out[i] = p1[i] ^ p2[i] ^ p3[i];
}

int integrity_set_reference(const uint8_t lmk[PAYHSM_LMK_SIZE]) {
    unsigned int hlen = PAYHSM_HMAC_SIZE;
    HMAC(EVP_sha256(), "hmac_key_ref", 12,
         lmk, PAYHSM_LMK_SIZE, g_hmac_ref, &hlen);
    g_has_ref = 1;
    return 0;
}

int integrity_verify_fragments(const uint8_t p1[PAYHSM_LMK_SIZE],
                               const uint8_t *p2,
                               const uint8_t p3[PAYHSM_LMK_SIZE]) {
    if (!g_has_ref || !p2) return -1;

    uint8_t recon[PAYHSM_LMK_SIZE], hmac_calc[PAYHSM_HMAC_SIZE];
    unsigned int hlen = PAYHSM_HMAC_SIZE;

    xor_frag(p1, p2, p3, recon);
    HMAC(EVP_sha256(), "hmac_key_ref", 12,
         recon, PAYHSM_LMK_SIZE, hmac_calc, &hlen);

    int ok = (memcmp(hmac_calc, g_hmac_ref, PAYHSM_HMAC_SIZE) == 0);

    secure_zero(recon, PAYHSM_LMK_SIZE);
    secure_zero(hmac_calc, PAYHSM_HMAC_SIZE);

    return ok ? 0 : -1;
}

void integrity_clear_reference(void) {
    secure_zero(g_hmac_ref, PAYHSM_HMAC_SIZE);
    g_has_ref = 0;
}

void integrity_ref_prefix(char hex[9]) {
    if (!hex) return;
    if (!g_has_ref) {
        snprintf(hex, 9, "--------");
        return;
    }
    snprintf(hex, 9, "%02X%02X%02X%02X",
             g_hmac_ref[0], g_hmac_ref[1], g_hmac_ref[2], g_hmac_ref[3]);
}
