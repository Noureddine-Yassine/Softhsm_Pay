#include "shamir.h"
#include "../defense/defense.h"

#include <string.h>
#include <openssl/rand.h>

/*
 * GF(2^8) avec polynôme irréductible x^8 + x^4 + x^3 + x^2 + 1 (0x11D).
 * Même corps que AES — multiplication par décalage + réduction.
 */
static uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    while (b) {
        if (b & 1) r ^= a;
        b >>= 1;
        if (a & 0x80)
            a = (uint8_t)((a << 1) ^ 0x1D);
        else
            a <<= 1;
    }
    return r;
}

/* Évalue le polynôme f(x) = secret ⊕ a1·x ⊕ a2·x² en GF(2^8), octet par octet. */
static void poly_eval(const uint8_t secret[SHAMIR_SECRET_LEN],
                      const uint8_t a1[SHAMIR_SECRET_LEN],
                      const uint8_t a2[SHAMIR_SECRET_LEN],
                      uint8_t x, uint8_t out[SHAMIR_SECRET_LEN]) {
    uint8_t x2 = gf_mul(x, x);
    for (int i = 0; i < SHAMIR_SECRET_LEN; i++)
        out[i] = secret[i] ^ gf_mul(a1[i], x) ^ gf_mul(a2[i], x2);
}

int shamir_split(const uint8_t secret[SHAMIR_SECRET_LEN],
                 uint8_t shares[3][SHAMIR_SHARE_LEN]) {
    uint8_t a1[SHAMIR_SECRET_LEN], a2[SHAMIR_SECRET_LEN];

    if (RAND_bytes(a1, SHAMIR_SECRET_LEN) != 1) return -1;
    if (RAND_bytes(a2, SHAMIR_SECRET_LEN) != 1) {
        secure_zero(a1, sizeof(a1));
        return -1;
    }

    shares[0][0] = 1;  poly_eval(secret, a1, a2, 1, shares[0] + 1);
    shares[1][0] = 2;  poly_eval(secret, a1, a2, 2, shares[1] + 1);
    shares[2][0] = 3;  poly_eval(secret, a1, a2, 3, shares[2] + 1);

    secure_zero(a1, sizeof(a1));
    secure_zero(a2, sizeof(a2));
    return 0;
}

/*
 * Interpolation de Lagrange en x=0 avec parts en x∈{1,2,3}.
 * Dans GF(2^8) : L_i(0) = Π_{j≠i}(x_j) / Π_{j≠i}(x_i⊕x_j) = 1 pour tout i.
 * Donc : secret = f(1) ⊕ f(2) ⊕ f(3).
 */
int shamir_reconstruct(const uint8_t shares[3][SHAMIR_SHARE_LEN],
                       uint8_t secret_out[SHAMIR_SECRET_LEN]) {
    /* Vérifier que les indices sont exactement {1, 2, 3} sans doublon */
    uint8_t seen = 0;
    for (int i = 0; i < 3; i++) {
        uint8_t idx = shares[i][0];
        if (idx < 1 || idx > 3) return -1;
        if (seen & (uint8_t)(1u << idx)) return -1;   /* doublon */
        seen |= (uint8_t)(1u << idx);
    }
    if (seen != 0x0E) return -1;   /* {1,2,3} → bits 1+2+3 = 0b00001110 = 0x0E */

    for (int b = 0; b < SHAMIR_SECRET_LEN; b++)
        secret_out[b] = shares[0][b + 1] ^ shares[1][b + 1] ^ shares[2][b + 1];

    return 0;
}
