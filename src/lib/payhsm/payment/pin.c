#include "pin.h"
#include "../defense/defense.h"

#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/des.h>

static void xor_buf(uint8_t *o, const uint8_t *a,
                    const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) o[i] = a[i] ^ b[i];
}

/* ISO 9564 PIN block : DES-ECB 8 octets (clé = 8 premiers octets de TPK/ZPK) */
static int des_pin_block(const uint8_t *key16, const uint8_t in[8],
                         uint8_t out[8], int encrypt) {
    DES_key_schedule ks;
    DES_cblock k, ib, ob;
    memcpy(k, key16, 8);
    DES_set_key_unchecked(&k, &ks);
    memcpy(ib, in, 8);
    DES_ecb_encrypt(&ib, &ob, &ks, encrypt ? DES_ENCRYPT : DES_DECRYPT);
    memcpy(out, ob, 8);
    return 0;
}

/* PVV / données 8o : AES-128-ECB avec padding zéro sur 16 octets */
static AES_KEY g_aes_enc;

static int aes_ecb_pvv(const uint8_t *key, size_t klen,
                       const uint8_t *in8, uint8_t *out8, int encrypt) {
    if (klen != 16) return -1;
    uint8_t blk[16] = {0}, out[16];
    memcpy(blk, in8, 8);
    if (encrypt) {
        if (AES_set_encrypt_key(key, 128, &g_aes_enc) != 0) return -1;
        AES_encrypt(blk, out, &g_aes_enc);
        memcpy(out8, out, 8);
    } else {
        AES_KEY dec;
        if (AES_set_decrypt_key(key, 128, &dec) != 0) return -1;
        memcpy(blk, in8, 8);
        AES_decrypt(blk, out, &dec);
        memcpy(out8, out, 8);
    }
    secure_zero(blk, sizeof(blk));
    secure_zero(out, sizeof(out));
    return 0;
}

static uint8_t bcd_nibble(const uint8_t *buf, int idx) {
    return (idx & 1) ? (buf[idx / 2] & 0x0F) : (buf[idx / 2] >> 4);
}

static void build_pin_field(const char *pin, uint8_t out[8]) {
    uint8_t n[16];
    int len = (int)strlen(pin);
    n[0] = 0x0;
    n[1] = (uint8_t)len;
    for (int i = 0; i < len; i++) n[2 + i] = (uint8_t)(pin[i] - '0');
    for (int i = 2 + len; i < 16; i++) n[i] = 0xF;
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)((n[2 * i] << 4) | n[2 * i + 1]);
}

static void build_pan_field(const char *pan, uint8_t out[8]) {
    uint8_t n[16] = {0};
    int plen = (int)strlen(pan);
    const char *p12 = pan + (plen - 13);
    for (int i = 0; i < 12; i++) n[4 + i] = (uint8_t)(p12[i] - '0');
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)((n[2 * i] << 4) | n[2 * i + 1]);
}

static int pin_from_clear_block(const uint8_t clr[8], const char *pan,
                                char pin_out[13]) {
    uint8_t panf[8], pinf[8];
    build_pan_field(pan, panf);
    xor_buf(pinf, clr, panf, 8);

    int len = (int)bcd_nibble(pinf, 1);
    if (len < 4 || len > 12) {
        secure_zero(panf, 8);
        secure_zero(pinf, 8);
        return -1;
    }
    for (int i = 0; i < len; i++) {
        uint8_t nib = bcd_nibble(pinf, 2 + i);
        if (nib > 9) {
            secure_zero(panf, 8);
            secure_zero(pinf, 8);
            return -1;
        }
        pin_out[i] = (char)('0' + nib);
    }
    pin_out[len] = '\0';
    secure_zero(panf, 8);
    secure_zero(pinf, 8);
    return 0;
}

int pin_decrypt_block(const uint8_t *key, size_t key_len,
                      const uint8_t enc[8], uint8_t clr[8]) {
    if (!key || !enc || !clr || key_len < 8) return -1;
    return des_pin_block(key, enc, clr, 0);
}

int pin_build_clear_block(const char *pin, const char *pan, uint8_t clr[8]) {
    if (!pin || !pan || !clr) return -1;
    uint8_t pinf[8], panf[8];
    build_pin_field(pin, pinf);
    build_pan_field(pan, panf);
    xor_buf(clr, pinf, panf, 8);
    secure_zero(pinf, 8);
    secure_zero(panf, 8);
    return 0;
}

int generate_pin_block(const char *pin, const char *pan,
                       const uint8_t *tpk, size_t tpk_len,
                       uint8_t out[8]) {
    if (!pin || !pan || !tpk || !out) return -1;
    if (strlen(pin) < 4 || strlen(pin) > 12) return -1;

    uint8_t clr[8];
    if (pin_build_clear_block(pin, pan, clr) != 0) return -1;
    if (des_pin_block(tpk, clr, out, 1) != 0) {
        secure_zero(clr, 8);
        return -1;
    }
    secure_zero(clr, 8);
    return 0;
}

int translate_pin_block(const uint8_t *pin_block_in,
                        const char *pan,
                        const uint8_t *tpk, size_t tpk_len,
                        const uint8_t *zpk, size_t zpk_len,
                        uint8_t pin_block_out[8]) {
    (void)pan;
    if (!pin_block_in || !tpk || !zpk || !pin_block_out) return -1;

    uint8_t clr[8];
    if (des_pin_block(tpk, pin_block_in, clr, 0) != 0) return -1;
    if (des_pin_block(zpk, clr, pin_block_out, 1) != 0) {
        secure_zero(clr, 8);
        return -1;
    }
    secure_zero(clr, 8);
    return 0;
}

int pin_compute_pvv(const char *pin, const char *pan,
                    const uint8_t *pvk, size_t pvk_len,
                    char pvv_out[5]) {
    if (!pin || !pan || !pvk || !pvv_out) return -1;

    uint8_t tsp[8] = {0};
    int plen = (int)strlen(pan);
    const char *p11 = pan + (plen - 12);
    uint8_t n[16] = {0};
    for (int i = 0; i < 11; i++) n[i] = (uint8_t)(p11[i] - '0');
    n[11] = 1;
    for (int i = 0; i < 4; i++) n[12 + i] = (uint8_t)(pin[i] - '0');
    for (int i = 0; i < 8; i++) tsp[i] = (uint8_t)((n[2 * i] << 4) | n[2 * i + 1]);

    uint8_t enc[8];
    if (aes_ecb_pvv(pvk, pvk_len, tsp, enc, 1) != 0) {
        secure_zero(tsp, 8);
        return -1;
    }

    static const uint8_t dec[16] = {0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5};
    for (int i = 0; i < 4; i++) {
        uint8_t nib = bcd_nibble(enc, i);
        pvv_out[i] = (char)('0' + dec[nib]);
    }
    pvv_out[4] = '\0';

    /* Ne pas zeroiser enc avant copie PVV — déjà dans pvv_out */
    secure_zero(tsp, 8);
    return 0;
}

int verify_pin_pvv(const char *pin, const char *pan,
                   const uint8_t *pvk, size_t pvk_len,
                   const char *pvv_stored) {
    if (!pin || !pan || !pvk || !pvv_stored) return -1;

    char pvv_calc[5];
    if (pin_compute_pvv(pin, pan, pvk, pvk_len, pvv_calc) != 0) return -1;

    int ok = (strncmp(pvv_calc, pvv_stored, 4) == 0);
    secure_zero(pvv_calc, 5);
    return ok ? 0 : -1;
}

int verify_encrypted_pin_block(const uint8_t pin_block_enc[8],
                               const char *pan,
                               const uint8_t *tpk, size_t tpk_len,
                               const uint8_t *pvk, size_t pvk_len,
                               const char *pvv_stored) {
    if (!pin_block_enc || !pan || !tpk || !pvk || !pvv_stored) return -1;

    uint8_t clr[8], expected[8];
    char pin[13];

    if (des_pin_block(tpk, pin_block_enc, clr, 0) != 0) return -1;
    if (pin_from_clear_block(clr, pan, pin) != 0) {
        secure_zero(clr, 8);
        return -1;
    }
    if (pin_build_clear_block(pin, pan, expected) != 0 ||
        memcmp(clr, expected, 8) != 0) {
        secure_zero(clr, 8);
        secure_zero(expected, 8);
        secure_zero(pin, sizeof(pin));
        return -1;
    }

    int r = verify_pin_pvv(pin, pan, pvk, pvk_len, pvv_stored);
    secure_zero(clr, 8);
    secure_zero(expected, 8);
    secure_zero(pin, sizeof(pin));
    return r;
}
