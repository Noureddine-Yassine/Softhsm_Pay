#ifndef PAYHSM_LMK_STORE_H
#define PAYHSM_LMK_STORE_H

#include <stdint.h>
#include <stddef.h>

#define PAYHSM_LMK_SIZE   32
#define PAYHSM_SALT_SIZE  16
#define PAYHSM_NONCE_SIZE 12
#define PAYHSM_TAG_SIZE   16

/* Persiste la LMK chiffrée sous KEK (AES-256-GCM) dans path */
int lmk_store_save(const char *path,
                   const uint8_t kek[PAYHSM_LMK_SIZE],
                   const uint8_t lmk[PAYHSM_LMK_SIZE]);

/* Charge et déchiffre la LMK — kek fourni par kek_provider */
int lmk_store_load(const char *path,
                   const uint8_t kek[PAYHSM_LMK_SIZE],
                   uint8_t lmk_out[PAYHSM_LMK_SIZE]);

/* Initialise un nouveau fichier LMK (génère sel + chiffre) */
int lmk_store_create(const char *path,
                     const uint8_t kek[PAYHSM_LMK_SIZE],
                     const uint8_t lmk[PAYHSM_LMK_SIZE]);

/* Crée le fichier avec un sel fourni (provision déterministe KEK) */
int lmk_store_create_with_salt(const char *path,
                               const uint8_t kek[PAYHSM_LMK_SIZE],
                               const uint8_t lmk[PAYHSM_LMK_SIZE],
                               const uint8_t salt[PAYHSM_SALT_SIZE]);

/* Lit uniquement le sel (pour dérivation KEK avant déchiffrement) */
int lmk_store_read_salt(const char *path, uint8_t salt[PAYHSM_SALT_SIZE]);

#endif
