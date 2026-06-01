#include "lmk_store.h"
#include "../defense/defense.h"

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

static int write_encrypted_blob(FILE *f, const uint8_t kek[PAYHSM_LMK_SIZE],
                                const uint8_t lmk[PAYHSM_LMK_SIZE],
                                const uint8_t salt_fixed[PAYHSM_SALT_SIZE],
                                uint8_t salt_out[PAYHSM_SALT_SIZE]) {
    uint8_t salt[PAYHSM_SALT_SIZE], nonce[PAYHSM_NONCE_SIZE];
    uint8_t ct[PAYHSM_LMK_SIZE], tag[PAYHSM_TAG_SIZE];
    int len;

    if (salt_fixed)
        memcpy(salt, salt_fixed, PAYHSM_SALT_SIZE);
    else if (RAND_bytes(salt, PAYHSM_SALT_SIZE) != 1)
        return -1;
    if (RAND_bytes(nonce, PAYHSM_NONCE_SIZE) != 1)
        return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, kek, nonce);
    EVP_EncryptUpdate(ctx, ct, &len, lmk, PAYHSM_LMK_SIZE);
    EVP_EncryptFinal_ex(ctx, ct + len, &len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, PAYHSM_TAG_SIZE, tag);
    EVP_CIPHER_CTX_free(ctx);

    if (fwrite(salt, 1, PAYHSM_SALT_SIZE, f) != PAYHSM_SALT_SIZE ||
        fwrite(nonce, 1, PAYHSM_NONCE_SIZE, f) != PAYHSM_NONCE_SIZE ||
        fwrite(ct, 1, PAYHSM_LMK_SIZE, f) != PAYHSM_LMK_SIZE ||
        fwrite(tag, 1, PAYHSM_TAG_SIZE, f) != PAYHSM_TAG_SIZE) {
        return -1;
    }

    if (salt_out) memcpy(salt_out, salt, PAYHSM_SALT_SIZE);
    secure_zero(salt, PAYHSM_SALT_SIZE);
    secure_zero(nonce, PAYHSM_NONCE_SIZE);
    secure_zero(ct, PAYHSM_LMK_SIZE);
    return 0;
}

int lmk_store_read_salt(const char *path, uint8_t salt[PAYHSM_SALT_SIZE]) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(salt, 1, PAYHSM_SALT_SIZE, f);
    fclose(f);
    return (n == PAYHSM_SALT_SIZE) ? 0 : -1;
}

int lmk_store_create(const char *path,
                     const uint8_t kek[PAYHSM_LMK_SIZE],
                     const uint8_t lmk[PAYHSM_LMK_SIZE]) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    int r = write_encrypted_blob(f, kek, lmk, NULL, NULL);
    fclose(f);
    return r;
}

int lmk_store_create_with_salt(const char *path,
                               const uint8_t kek[PAYHSM_LMK_SIZE],
                               const uint8_t lmk[PAYHSM_LMK_SIZE],
                               const uint8_t salt[PAYHSM_SALT_SIZE]) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    int r = write_encrypted_blob(f, kek, lmk, salt, NULL);
    fclose(f);
    return r;
}

int lmk_store_save(const char *path,
                   const uint8_t kek[PAYHSM_LMK_SIZE],
                   const uint8_t lmk[PAYHSM_LMK_SIZE]) {
    return lmk_store_create(path, kek, lmk);
}

int lmk_store_load(const char *path,
                   const uint8_t kek[PAYHSM_LMK_SIZE],
                   uint8_t lmk_out[PAYHSM_LMK_SIZE]) {
    uint8_t salt[PAYHSM_SALT_SIZE], nonce[PAYHSM_NONCE_SIZE];
    uint8_t ct[PAYHSM_LMK_SIZE], tag[PAYHSM_TAG_SIZE];
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    if (fread(salt, 1, PAYHSM_SALT_SIZE, f) != PAYHSM_SALT_SIZE ||
        fread(nonce, 1, PAYHSM_NONCE_SIZE, f) != PAYHSM_NONCE_SIZE ||
        fread(ct, 1, PAYHSM_LMK_SIZE, f) != PAYHSM_LMK_SIZE ||
        fread(tag, 1, PAYHSM_TAG_SIZE, f) != PAYHSM_TAG_SIZE) {
        fclose(f);
        return -1;
    }
    fclose(f);

    int len, ok;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, kek, nonce);
    EVP_DecryptUpdate(ctx, lmk_out, &len, ct, PAYHSM_LMK_SIZE);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, PAYHSM_TAG_SIZE, tag);
    ok = EVP_DecryptFinal_ex(ctx, lmk_out + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    secure_zero(salt, PAYHSM_SALT_SIZE);
    secure_zero(nonce, PAYHSM_NONCE_SIZE);
    secure_zero(ct, PAYHSM_LMK_SIZE);

    return (ok > 0) ? 0 : -1;
}
