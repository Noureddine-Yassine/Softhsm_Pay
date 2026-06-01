#include "key_vault.h"
#include "../payment/key_exchange.h"

#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

int vault_derive_from_lmk(const uint8_t lmk[32],
                          const char *label,
                          uint8_t key_out[PAYHSM_KEY_LEN]) {
    if (!lmk || !label || !key_out) return -1;
    uint8_t mac[32];
    unsigned int mlen = 32;
    if (HMAC(EVP_sha256(), lmk, 32,
             (const uint8_t *)label, strlen(label), mac, &mlen) != NULL) {
        memcpy(key_out, mac, PAYHSM_KEY_LEN);
        return 0;
    }
    return -1;
}

int vault_encrypt_under_lmk(const uint8_t lmk[32],
                            const uint8_t key[PAYHSM_KEY_LEN],
                            uint8_t enc_out[PAYHSM_KEY_LEN]) {
    AES_KEY ak;
    if (AES_set_encrypt_key(lmk, 256, &ak) != 0) return -1;
    AES_encrypt(key, enc_out, &ak);
    return 0;
}

int vault_decrypt_under_lmk(const uint8_t lmk[32],
                            const uint8_t enc[PAYHSM_KEY_LEN],
                            uint8_t key_out[PAYHSM_KEY_LEN]) {
    AES_KEY ak;
    if (AES_set_decrypt_key(lmk, 256, &ak) != 0) return -1;
    AES_decrypt(enc, key_out, &ak);
    return 0;
}

int vault_add_key(payhsm_key_vault_t *vault,
                  const char *id,
                  payhsm_key_type_t type,
                  const char *terminal_id,
                  const uint8_t enc[PAYHSM_KEY_LEN],
                  const uint8_t kcv[PAYHSM_KCV_LEN]) {
    if (!vault || !id) return -1;
    /* Update existing entry if same ID (upsert) */
    for (int i = 0; i < vault->count; i++) {
        if (strcmp(vault->keys[i].id, id) == 0) {
            payhsm_key_entry_t *e = &vault->keys[i];
            e->type = type;
            if (terminal_id)
                strncpy(e->terminal_id, terminal_id, sizeof(e->terminal_id) - 1);
            memcpy(e->enc, enc, PAYHSM_KEY_LEN);
            memcpy(e->kcv, kcv, PAYHSM_KCV_LEN);
            e->active = 1;
            return 0;
        }
    }
    if (vault->count >= PAYHSM_MAX_KEYS) return -1;
    payhsm_key_entry_t *e = &vault->keys[vault->count++];
    memset(e, 0, sizeof(*e));
    strncpy(e->id, id, sizeof(e->id) - 1);
    e->type = type;
    if (terminal_id)
        strncpy(e->terminal_id, terminal_id, sizeof(e->terminal_id) - 1);
    memcpy(e->enc, enc, PAYHSM_KEY_LEN);
    memcpy(e->kcv, kcv, PAYHSM_KCV_LEN);
    e->active = 1;
    return 0;
}

int vault_find(const payhsm_key_vault_t *vault,
               payhsm_key_type_t type,
               const char *terminal_id,
               const payhsm_key_entry_t **out) {
    if (!vault || !out) return -1;
    for (int i = 0; i < vault->count; i++) {
        const payhsm_key_entry_t *e = &vault->keys[i];
        if (!e->active || e->type != type) continue;
        if (terminal_id && terminal_id[0] &&
            strcmp(e->terminal_id, terminal_id) != 0)
            continue;
        *out = e;
        return 0;
    }
    return -1;
}

int vault_find_by_id(const payhsm_key_vault_t *vault,
                     const char *id,
                     const payhsm_key_entry_t **out) {
    if (!vault || !id || !out) return -1;
    for (int i = 0; i < vault->count; i++) {
        const payhsm_key_entry_t *e = &vault->keys[i];
        if (e->active && strcmp(e->id, id) == 0) {
            *out = e;
            return 0;
        }
    }
    return -1;
}

int vault_save(const payhsm_key_vault_t *vault) {
    if (!vault || !vault->vault_path[0]) return -1;
    FILE *f = fopen(vault->vault_path, "wb");
    if (!f) return -1;
    uint32_t n = (uint32_t)vault->count;
    fwrite(&n, 1, sizeof(n), f);
    for (int i = 0; i < vault->count; i++)
        fwrite(&vault->keys[i], 1, sizeof(payhsm_key_entry_t), f);
    fclose(f);
    return 0;
}

int vault_load(payhsm_key_vault_t *vault, const char *path) {
    if (!vault || !path) return -1;
    strncpy(vault->vault_path, path, sizeof(vault->vault_path) - 1);
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    uint32_t n = 0;
    if (fread(&n, 1, sizeof(n), f) != sizeof(n) || n > PAYHSM_MAX_KEYS) {
        fclose(f);
        return -1;
    }
    vault->count = (int)n;
    for (uint32_t i = 0; i < n; i++) {
        if (fread(&vault->keys[i], 1, sizeof(payhsm_key_entry_t), f) !=
            sizeof(payhsm_key_entry_t)) {
            fclose(f);
            return -1;
        }
    }
    fclose(f);
    return 0;
}

void vault_clear(payhsm_key_vault_t *vault) {
    if (!vault) return;
    memset(vault, 0, sizeof(*vault));
}
