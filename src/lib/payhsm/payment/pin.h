#ifndef PAYHSM_PIN_H
#define PAYHSM_PIN_H

#include <stdint.h>
#include <stddef.h>

/* Génère un PIN Block ISO 9564 Format 0 chiffré sous TPK */
int generate_pin_block(const char *pin, const char *pan,
                       const uint8_t *tpk, size_t tpk_len,
                       uint8_t out[8]);

/* Translate un PIN Block de TPK vers ZPK
   Sans jamais exposer le PIN en clair */
int translate_pin_block(const uint8_t *pin_block_in,
                        const char *pan,
                        const uint8_t *tpk, size_t tpk_len,
                        const uint8_t *zpk, size_t zpk_len,
                        uint8_t pin_block_out[8]);

/* Vérifie un PIN par méthode PVV (VISA)
   Retourne 0 si valide, -1 si invalide */
int verify_pin_pvv(const char *pin, const char *pan,
                   const uint8_t *pvk, size_t pvk_len,
                   const char *pvv_stored);

/* Déchiffre PIN Block sous TPK puis vérifie PVV — PIN jamais loggé */
int verify_encrypted_pin_block(const uint8_t pin_block_enc[8],
                               const char *pan,
                               const uint8_t *tpk, size_t tpk_len,
                               const uint8_t *pvk, size_t pvk_len,
                               const char *pvv_stored);

/* Champs ISO 9564 Format 0 (pour tests / debug contrôlé) */
int pin_build_clear_block(const char *pin, const char *pan, uint8_t clr[8]);

/* Déchiffre un PIN Block 8 octets (AES-128-ECB, padding zéro) */
int pin_decrypt_block(const uint8_t *key, size_t key_len,
                      const uint8_t enc[8], uint8_t clr[8]);

/* Calcule le PVV VISA (4 chiffres décimaux) */
int pin_compute_pvv(const char *pin, const char *pan,
                    const uint8_t *pvk, size_t pvk_len,
                    char pvv_out[5]);

#endif