#ifndef PAYHSM_KEY_VAULT_H
#define PAYHSM_KEY_VAULT_H

#include <stdint.h>
#include <stddef.h>

#define PAYHSM_KEY_LEN     16
#define PAYHSM_KCV_LEN     3
#define PAYHSM_MAX_KEYS    32
#define PAYHSM_TERM_ID_LEN 32

typedef enum {
    PAYHSM_KEY_LMK = 0,
    PAYHSM_KEY_TMK,
    PAYHSM_KEY_TPK,
    PAYHSM_KEY_TAK,
    PAYHSM_KEY_ZMK,
    PAYHSM_KEY_ZPK,
    PAYHSM_KEY_PVK,
    PAYHSM_KEY_IMK
} payhsm_key_type_t;

typedef struct {
    char              id[48];
    payhsm_key_type_t type;
    char              terminal_id[PAYHSM_TERM_ID_LEN];
    uint8_t           enc[PAYHSM_KEY_LEN]; /* chiffré sous LMK (AES-ECB) */
    uint8_t           kcv[PAYHSM_KCV_LEN];
    int               active;
} payhsm_key_entry_t;

typedef struct {
    payhsm_key_entry_t keys[PAYHSM_MAX_KEYS];
    int                count;
    char               vault_path[256];
} payhsm_key_vault_t;

/* Dérive une clé 16 octets depuis la LMK (label unique) */
int vault_derive_from_lmk(const uint8_t lmk[32],
                          const char *label,
                          uint8_t key_out[PAYHSM_KEY_LEN]);

/* Chiffre / déchiffre une clé sous LMK pour stockage */
int vault_encrypt_under_lmk(const uint8_t lmk[32],
                            const uint8_t key[PAYHSM_KEY_LEN],
                            uint8_t enc_out[PAYHSM_KEY_LEN]);

int vault_decrypt_under_lmk(const uint8_t lmk[32],
                            const uint8_t enc[PAYHSM_KEY_LEN],
                            uint8_t key_out[PAYHSM_KEY_LEN]);

int vault_add_key(payhsm_key_vault_t *vault,
                  const char *id,
                  payhsm_key_type_t type,
                  const char *terminal_id,
                  const uint8_t enc[PAYHSM_KEY_LEN],
                  const uint8_t kcv[PAYHSM_KCV_LEN]);

int vault_find(const payhsm_key_vault_t *vault,
               payhsm_key_type_t type,
               const char *terminal_id,
               const payhsm_key_entry_t **out);

int vault_find_by_id(const payhsm_key_vault_t *vault,
                     const char *id,
                     const payhsm_key_entry_t **out);

int vault_save(const payhsm_key_vault_t *vault);
int vault_load(payhsm_key_vault_t *vault, const char *path);

void vault_clear(payhsm_key_vault_t *vault);

#endif
