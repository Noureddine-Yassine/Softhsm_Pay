#include "mutation.h"
#include "../defense/defense.h"

#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>

static mutation_stats_t g_stats;

static void xor_buf(uint8_t *out, const uint8_t *a, const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) out[i] = a[i] ^ b[i];
}

int mutation_apply(uint8_t p1[PAYHSM_LMK_SIZE],
                   uint8_t **p2,
                   uint8_t p3[PAYHSM_LMK_SIZE]) {
    if (!p1 || !p2 || !*p2 || !p3) return -1;

    uint8_t Ma[PAYHSM_LMK_SIZE], Mb[PAYHSM_LMK_SIZE], MaMb[PAYHSM_LMK_SIZE];

    if (RAND_bytes(Ma, PAYHSM_LMK_SIZE) != 1 ||
        RAND_bytes(Mb, PAYHSM_LMK_SIZE) != 1)
        return -1;

    xor_buf(MaMb, Ma, Mb, PAYHSM_LMK_SIZE);
    xor_buf(p1, p1, Ma, PAYHSM_LMK_SIZE);
    xor_buf(*p2, *p2, Mb, PAYHSM_LMK_SIZE);
    xor_buf(p3, p3, MaMb, PAYHSM_LMK_SIZE);

    uint8_t *new_p2 = (uint8_t *)malloc(PAYHSM_LMK_SIZE);
    if (!new_p2) return -1;
    memcpy(new_p2, *p2, PAYHSM_LMK_SIZE);
    secure_zero(*p2, PAYHSM_LMK_SIZE);
    free(*p2);
    *p2 = new_p2;

    secure_zero(Ma, PAYHSM_LMK_SIZE);
    secure_zero(Mb, PAYHSM_LMK_SIZE);
    secure_zero(MaMb, PAYHSM_LMK_SIZE);

    g_stats.count++;
    g_stats.last_ts = time(NULL);
    return 0;
}

void mutation_stats_get(mutation_stats_t *out) {
    if (out) *out = g_stats;
}

void mutation_stats_reset(void) {
    g_stats.count = 0;
    g_stats.last_ts = 0;
}
