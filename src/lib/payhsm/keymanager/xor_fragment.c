#include "xor_fragment.h"
#include "integrity.h"
#include "mutation.h"
#include "../defense/defense.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

static uint8_t  g_P1[LMK_SIZE] = {0};
static uint8_t *g_P2           = NULL;
uint8_t         g_P3[LMK_SIZE] = {0};

static void xor_buf(uint8_t *out, const uint8_t *a, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) out[i] = a[i] ^ b[i];
}

int fragment_lmk(uint8_t *lmk) {
    if (!lmk) return -1;

    if (integrity_set_reference(lmk) != 0) return -1;

    if (RAND_bytes(g_P1, LMK_SIZE) != 1) return -1;

    g_P2 = (uint8_t *)malloc(LMK_SIZE);
    if (!g_P2 || RAND_bytes(g_P2, LMK_SIZE) != 1) return -1;

    xor_buf(g_P3, lmk, g_P1, LMK_SIZE);
    xor_buf(g_P3, g_P3, g_P2, LMK_SIZE);

    secure_zero(lmk, LMK_SIZE);
    mutation_stats_reset();
    return 0;
}

int recompose_for_op(uint8_t out[LMK_SIZE]) {
    if (!g_P2) return -1;
    xor_buf(out, g_P1, g_P2, LMK_SIZE);
    xor_buf(out, out, g_P3, LMK_SIZE);
    return 0;
}

int check_integrity(void) {
    if (!g_P2) return -1;
    if (integrity_verify_fragments(g_P1, g_P2, g_P3) != 0) {
        emergency_shutdown("corruption fragments detectee");
        return -1;
    }
    return 0;
}

int mutate_fragments(void) {
    if (!g_P2) return -1;
    return mutation_apply(g_P1, &g_P2, g_P3);
}

int verify_integrity_quiet(void) {
    if (!g_P2) return -1;
    return integrity_verify_fragments(g_P1, g_P2, g_P3);
}

void tamper_fragment_test(void) {
    if (g_P2) g_P3[0] ^= 0xFF;
}

void fragment_fingerprint_prefix(int which, char hex[9]) {
    const uint8_t *frag = NULL;
    static const char keys[3][11] = { "frag_fp_p1", "frag_fp_p2", "frag_fp_p3" };

    if (!hex) return;
    if (which == 1) frag = g_P1;
    else if (which == 2) frag = g_P2;
    else if (which == 3) frag = g_P3;

    if (!frag || (which == 2 && !g_P2)) {
        snprintf(hex, 9, "--------");
        return;
    }

    uint8_t hmac[32];
    unsigned int hlen = 32;
    HMAC(EVP_sha256(), keys[which - 1], 10,
         frag, LMK_SIZE, hmac, &hlen);
    snprintf(hex, 9, "%02X%02X%02X%02X",
             hmac[0], hmac[1], hmac[2], hmac[3]);
}

void zero_all_fragments(void) {
    secure_zero(g_P1, LMK_SIZE);
    if (g_P2) {
        secure_zero(g_P2, LMK_SIZE);
        free(g_P2);
        g_P2 = NULL;
    }
    secure_zero(g_P3, LMK_SIZE);
    integrity_clear_reference();
}
