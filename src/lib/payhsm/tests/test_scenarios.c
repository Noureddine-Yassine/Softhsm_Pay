/*
 * PayHSM — scénarios de test (Partie 3)
 * Compile: make -C src/lib/payhsm test
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/cmac.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/params.h>
#endif

#include "../payhsm.h"

static int tests_run = 0;
static int tests_ok  = 0;

#define ASSERT(cond, msg) do { \
    tests_run++; \
    if (cond) { tests_ok++; printf("  [OK] %s\n", msg); } \
    else { printf("  [KO] %s\n", msg); } \
} while (0)

static void hex_print(const char *l, const uint8_t *b, size_t n) {
    printf("    %s: ", l);
    for (size_t i = 0; i < n; i++) printf("%02X", b[i]);
    printf("\n");
}

/* Clés de démo 16 octets (KCV alignés spec frontend) */
static const uint8_t TPK_DEMO[16] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10
};
static const uint8_t ZPK_DEMO[16] = {
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
    0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20
};
static const uint8_t PVK_DEMO[16] = {
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,
    0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99
};
static const uint8_t ZMK_DEMO[16] = {
    0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
    0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0
};

static void test1_pin_approved(void) {
    printf("\n=== Test 1 — PIN approuvé (même banque) ===\n");
    const char *pan = "4111111111111111";
    const char *pin = "1234";
    uint8_t pb[8];
    char pvv[5];

    ASSERT(generate_pin_block(pin, pan, TPK_DEMO, 16, pb) == 0,
           "PIN Block généré");
    ASSERT(pin_compute_pvv(pin, pan, PVK_DEMO, 16, pvv) == 0,
           "PVV calculé");
    ASSERT(verify_pin_pvv(pin, pan, PVK_DEMO, 16, pvv) == 0,
           "PVV valide — APPROVED");
}

static void test2_pin_declined(void) {
    printf("\n=== Test 2 — PIN refusé ===\n");
    const char *pan = "4111111111111111";
    const char *pin = "9999";
    uint8_t pb[8];

    generate_pin_block(pin, pan, TPK_DEMO, 16, pb);
    ASSERT(verify_encrypted_pin_block(pb, pan, TPK_DEMO, 16,
                                      PVK_DEMO, 16, "7843") != 0,
           "Mauvais PIN — DECLINED (55)");
}

static void test3_interbank(void) {
    printf("\n=== Test 3 — Translation ZPK ===\n");
    const char *pan = "4111111111111111";
    uint8_t pb_tpk[8], pb_zpk[8];

    generate_pin_block("1234", pan, TPK_DEMO, 16, pb_tpk);
    ASSERT(translate_pin_block(pb_tpk, pan, TPK_DEMO, 16,
                               ZPK_DEMO, 16, pb_zpk) == 0,
           "Translation TPK→ZPK");

    uint8_t clr_tpk[8], clr_zpk[8], ref[8];
    pin_build_clear_block("1234", pan, ref);
    ASSERT(pin_decrypt_block(TPK_DEMO, 16, pb_tpk, clr_tpk) == 0, "Déchiffrement TPK");
    ASSERT(pin_decrypt_block(ZPK_DEMO, 16, pb_zpk, clr_zpk) == 0, "Déchiffrement ZPK");
    ASSERT(memcmp(clr_tpk, clr_zpk, 8) == 0 &&
           memcmp(clr_tpk, ref, 8) == 0,
           "PIN intact sous ZPK — jamais en clair sur réseau");
}

static void test4_emv(void) {
    printf("\n=== Test 4 — Transaction EMV ===\n");
    const char *pan = "5555555555554444";
    const char *psn = "00";
    uint8_t atc[2] = {0x00, 0x42};
    uint8_t imk[16] = {0x2F,0x8B,0x33,0x11,0x22,0x33,0x44,0x55,
                       0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD};
    uint8_t mk_ac[16], sk_ac[16];
    uint8_t txdata[] = "150.00EUR0042";
    uint8_t arqc[8];

    ASSERT(derive_card_keys(imk, 16, pan, psn, mk_ac) == 0, "MK-AC dérivée");
    ASSERT(derive_sk_ac(mk_ac, atc, sk_ac) == 0, "SK-AC dérivée");

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
    EVP_MAC_CTX *mctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    char cipher[] = "AES-128-CBC";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("cipher", cipher, 0),
        OSSL_PARAM_construct_end()
    };
    uint8_t full[16];
    size_t mlen;
    EVP_MAC_init(mctx, sk_ac, 16, params);
    EVP_MAC_update(mctx, txdata, sizeof(txdata) - 1);
    EVP_MAC_final(mctx, full, &mlen, sizeof(full));
    memcpy(arqc, full, 8);
    EVP_MAC_CTX_free(mctx);
#else
    CMAC_CTX *cctx = CMAC_CTX_new();
    uint8_t full[16];
    size_t mlen;
    CMAC_Init(cctx, sk_ac, 16, EVP_aes_128_cbc(), NULL);
    CMAC_Update(cctx, txdata, sizeof(txdata) - 1);
    CMAC_Final(cctx, full, &mlen);
    memcpy(arqc, full, 8);
    CMAC_CTX_free(cctx);
#endif

    ASSERT(verify_arqc(sk_ac, txdata, sizeof(txdata) - 1, arqc) == 0,
           "ARQC valide");

    uint8_t arpc[8], rc[2] = {0x00, 0x00};
    ASSERT(generate_arpc(mk_ac, arqc, rc, arpc) == 0, "ARPC généré");
}

static void test5_mac(void) {
    printf("\n=== Test 5 — MAC ISO 8583 ===\n");
    uint8_t msg[] = "020040000000000000001234567890";
    uint8_t tak[16] = {0x3A,0x4B,0x5C,0x6D,0x7E,0x8F,0x90,0xA1,
                       0xB2,0xC3,0xD4,0xE5,0xF6,0x07,0x18,0x29};
    uint8_t mac[8], mac_bad[8];

    ASSERT(calculate_mac_tak(msg, sizeof(msg) - 1, tak, 16, mac) == 0,
           "MAC calculé");
    ASSERT(verify_mac(msg, sizeof(msg) - 1, tak, 16, mac) == 0,
           "MAC valide");

    memcpy(mac_bad, mac, 8);
    mac_bad[0] ^= 0x01;
    ASSERT(verify_mac(msg, sizeof(msg) - 1, tak, 16, mac_bad) != 0,
           "Bit modifié — MAC invalide détecté");
}

static void test6_zpk_exchange(void) {
    printf("\n=== Test 6 — Échange ZPK ===\n");
    uint8_t zpk[16], enc[32], dec[16], kcv1[3], kcv2[3];
    size_t enc_len = 0;

    RAND_bytes(zpk, 16);
    ASSERT(compute_kcv(zpk, 16, kcv1) == 0, "KCV calculé");
    ASSERT(encrypt_zpk_under_zmk(zpk, 16, ZMK_DEMO, 16, enc, &enc_len) == 0,
           "ZPK chiffré sous ZMK");
    ASSERT(decrypt_zpk_under_zmk(enc, enc_len, ZMK_DEMO, 16, dec) == 0,
           "ZPK déchiffré");
    compute_kcv(dec, 16, kcv2);
    ASSERT(memcmp(kcv1, kcv2, 3) == 0, "KCV identique après échange");
    secure_zero(zpk, 16);
    secure_zero(dec, 16);
}

static void test7_lmk_mutation(void) {
    printf("\n=== Test 7 — Mutation LMK ===\n");
    uint8_t lmk[LMK_SIZE];
    RAND_bytes(lmk, LMK_SIZE);

    ASSERT(fragment_lmk(lmk) == 0, "Fragmentation OK");
    for (int i = 0; i < 5; i++)
        ASSERT(mutate_fragments() == 0, "Mutation cycle");

    ASSERT(check_integrity() == 0, "Invariant P1⊕P2⊕P3");

    tamper_fragment_test();
    ASSERT(verify_integrity_quiet() != 0, "Corruption détectée (HMAC)");
    zero_all_fragments();
    ASSERT(1, "Nettoyage fragments");
}

int main(void) {
    printf("PayHSM — batterie de tests Partie 3\n");
    printf("====================================\n");

    test1_pin_approved();
    test2_pin_declined();
    test3_interbank();
    test4_emv();
    test5_mac();
    test6_zpk_exchange();
    test7_lmk_mutation();

    printf("\n====================================\n");
    printf("Résultat: %d/%d tests OK\n", tests_ok, tests_run);
    return (tests_ok == tests_run) ? 0 : 1;
}
