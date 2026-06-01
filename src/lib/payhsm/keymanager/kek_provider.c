#include "kek_provider.h"
#include "../defense/defense.h"

#include <string.h>
#include <openssl/evp.h>

int kek_derive_from_passphrase(const char *passphrase,
                               const uint8_t salt[PAYHSM_SALT_SIZE],
                               uint8_t kek_out[PAYHSM_KEK_SIZE]) {
    if (!passphrase || !salt || !kek_out) return -1;

    if (PKCS5_PBKDF2_HMAC(passphrase, (int)strlen(passphrase),
                          salt, PAYHSM_SALT_SIZE, PAYHSM_PBKDF2_ITER,
                          EVP_sha256(), PAYHSM_KEK_SIZE, kek_out) != 1)
        return -1;

    return 0;
}
