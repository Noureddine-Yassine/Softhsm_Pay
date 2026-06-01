/* Test EMV arqc + verify via payhsm_switch (même binaire que httpd) */
#include "../payhsm_core.h"
#include "../payhsm_switch.h"
#include "../payment/emv.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/rand.h>

int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : "/tmp/payhsm-test-data";
    const char *pass = argc > 2 ? argv[2] : "test1234";

    if (payhsm_startup(pass, dir) != PAYHSM_RC_OK) {
        fprintf(stderr, "startup failed\n");
        return 1;
    }

    uint8_t imk[16];
    if (RAND_bytes(imk, 16) != 1) return 1;
    char gcm[89];
    if (payhsm_wrap_lmk_gcm_hex(imk, gcm) != PAYHSM_RC_OK) {
        fprintf(stderr, "wrap failed\n");
        return 1;
    }

    if (payhsm_set_card_pvv("4111111111111111", "1234") != PAYHSM_RC_OK) {
        fprintf(stderr, "core banking enroll failed\n");
        return 1;
    }

    char arqc_hex[17], tx[256];
    size_t tx_len = 0;
    if (payhsm_emv_arqc_switch(gcm, "4111111111111111", "01", "0001", 4250, "978",
                               "250517", "TPE001",
                               arqc_hex, tx, sizeof(tx), &tx_len) != PAYHSM_RC_OK) {
        fprintf(stderr, "arqc failed\n");
        return 1;
    }
    printf("arqc=%s tx=%s len=%zu\n", arqc_hex, tx, tx_len);

    int valid = 0;
    char arpc[17];
    int arpc_card = 0;
    char arpc_exp[17];
    int rc = payhsm_emv_verify_switch(gcm, "4111111111111111", "01", "0001",
                                      (const uint8_t *)tx, tx_len, arqc_hex,
                                      &valid, arpc, &arpc_card, arpc_exp);
    printf("verify rc=%d valid=%d arpc=%s\n", rc, valid, arpc);

    /* direct emv.c in-process */
    uint8_t mk[16], sk[16], atc_b[2] = {0x00, 0x01}, arqc[8];
    derive_card_keys(imk, 16, "4111111111111111", "01", mk);
    derive_sk_ac(mk, atc_b, sk);
    emv_compute_arqc(sk, (const uint8_t *)tx, tx_len, arqc);
    char ah[17];
    for (int i = 0; i < 8; i++) sprintf(ah + i * 2, "%02X", arqc[i]);
    int v2 = verify_arqc(sk, (const uint8_t *)tx, tx_len, arqc);
    printf("direct compute+verify=%d arqc=%s\n", v2, ah);

    payhsm_emv_purchase_t pr;
    memset(&pr, 0, sizeof(pr));
    rc = payhsm_emv_purchase_switch(gcm, "4111111111111111", "01", "0001", 4250, "978",
                                    "250517", "TPE001", &pr);
    printf("purchase rc=%d approved=%d msg=%s\n", rc, pr.approved, pr.message);

    return (valid && pr.approved) ? 0 : 2;
}
