#ifndef PAYHSM_KEK_PROVIDER_H
#define PAYHSM_KEK_PROVIDER_H

#include <stdint.h>
#include "lmk_store.h"

#define PAYHSM_KEK_SIZE PAYHSM_LMK_SIZE
#define PAYHSM_PBKDF2_ITER 100000

/* Dérive le KEK depuis passphrase + sel (PBKDF2-SHA256) */
int kek_derive_from_passphrase(const char *passphrase,
                               const uint8_t salt[PAYHSM_SALT_SIZE],
                               uint8_t kek_out[PAYHSM_KEK_SIZE]);

#endif
