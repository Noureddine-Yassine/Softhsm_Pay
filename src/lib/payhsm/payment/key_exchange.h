#ifndef PAYHSM_KEY_EXCHANGE_H
#define PAYHSM_KEY_EXCHANGE_H

#include <stdint.h>
#include <stddef.h>

/* Dérive une TPK depuis une TMK (méthode AES-CMAC simplifiée) */
int derive_tpk_from_tmk(const uint8_t *tmk, size_t tmk_len,
                        const char *terminal_id,
                        uint8_t tpk_out[16]);

/* Dérive une TAK depuis une TMK */
int derive_tak_from_tmk(const uint8_t *tmk, size_t tmk_len,
                        const char *terminal_id,
                        uint8_t tak_out[16]);

/* Chiffre une ZPK sous ZMK pour transport */
int encrypt_zpk_under_zmk(const uint8_t *zpk, size_t zpk_len,
                          const uint8_t *zmk, size_t zmk_len,
                          uint8_t *out, size_t *out_len);

/* Déchiffre une ZPK reçue sous ZMK */
int decrypt_zpk_under_zmk(const uint8_t *enc_zpk, size_t enc_len,
                          const uint8_t *zmk, size_t zmk_len,
                          uint8_t zpk_out[16]);

/* KCV = 3 premiers octets de AES-ECB(key, 000...00) */
int compute_kcv(const uint8_t *key, size_t key_len, uint8_t kcv_out[3]);

#endif