#ifndef PAYHSM_SHAMIR_H
#define PAYHSM_SHAMIR_H

#include <stdint.h>

/*
 * Shamir Secret Sharing (3/3) sur GF(2^8)
 *
 * Polynôme de degré 2 : f(x) = secret ⊕ a1·x ⊕ a2·x²  dans GF(2^8)
 * Parts : (1, f(1)), (2, f(2)), (3, f(3))
 * Format d'une part : 1 octet d'index + 32 octets de données = 33 octets = 66 hex chars
 *
 * Reconstruction par interpolation de Lagrange en x=0 :
 *   Pour x∈{1,2,3}, L_i(0)=1 dans GF(2^8) → secret = f(1)⊕f(2)⊕f(3)
 */

#define SHAMIR_SECRET_LEN  32   /* 256 bits */
#define SHAMIR_SHARE_LEN   33   /* 1 octet index + 32 octets données */
#define SHAMIR_SHARE_HEX   67   /* 66 hex chars + '\0' */

/* Divise secret[32] en 3 parts shares[3][33] via un polynôme GF(2^8) de degré 2.
 * Retourne 0 si OK, -1 si erreur (RAND_bytes). */
int shamir_split(const uint8_t secret[SHAMIR_SECRET_LEN],
                 uint8_t shares[3][SHAMIR_SHARE_LEN]);

/* Reconstitue secret[32] depuis 3 parts (indices attendus : {1,2,3}, tous requis).
 * Retourne 0 si OK, -1 si indices invalides ou doublons. */
int shamir_reconstruct(const uint8_t shares[3][SHAMIR_SHARE_LEN],
                       uint8_t secret_out[SHAMIR_SECRET_LEN]);

#endif /* PAYHSM_SHAMIR_H */
