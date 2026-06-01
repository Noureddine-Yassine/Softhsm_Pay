#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

#define KEY_SIZE    32
#define NONCE_SIZE  12
#define TAG_SIZE    16
#define SALT_SIZE   16
#define PBKDF2_ITER 100000
#define FILENAME    "lmk.bin"

static uint8_t P3_data_segment[KEY_SIZE];

/* ─── UTILITAIRES ─── */

void secure_zero(void *v, size_t n) {
    volatile uint8_t *p = (volatile uint8_t *)v;
    while (n--) *p++ = 0;
    __asm__ __volatile__("" ::: "memory");
}

void print_hex(const char *label, const uint8_t *buf, size_t len) {
    printf("  %-35s : ", label);
    for (size_t i = 0; i < len; i++) printf("%02X ", buf[i]);
    printf("\n");
}

void xor_buf(uint8_t *out, const uint8_t *a,
             const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) out[i] = a[i] ^ b[i];
}

void derive_kek(const char *pass, const uint8_t *salt,
                size_t slen, uint8_t *kek) {
    PKCS5_PBKDF2_HMAC(pass, (int)strlen(pass),
                      salt, (int)slen, PBKDF2_ITER,
                      EVP_sha256(), KEY_SIZE, kek);
}

void verifier_integrite(const uint8_t *p1, const uint8_t *p2,
                        const uint8_t *p3, const uint8_t *hmac_ref) {
    uint8_t recon[KEY_SIZE], hmac_calc[32];
    unsigned int hlen = 32;
    xor_buf(recon, p1, p2, KEY_SIZE);
    xor_buf(recon, recon, p3, KEY_SIZE);
    HMAC(EVP_sha256(), "hmac_key_ref", 12,
         recon, KEY_SIZE, hmac_calc, &hlen);
    int ok = (memcmp(hmac_calc, hmac_ref, 32) == 0);
    printf("  %-35s : %s\n", "Integrite (HMAC P1^P2^P3)",
           ok ? "\033[32m[OK] LMK VALIDE\033[0m"
              : "\033[31m[KO] CORRUPTION\033[0m");
    secure_zero(recon, KEY_SIZE);
    secure_zero(hmac_calc, 32);
}

/* ─── PARTIE 1 : PROVISIONNEMENT ─── */

void provisionner_hsm(const uint8_t *kek, const uint8_t *salt) {
    uint8_t lmk[KEY_SIZE] = {
        0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
        0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
        0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00
    };
    uint8_t nonce[NONCE_SIZE], ct[KEY_SIZE], tag[TAG_SIZE];
    int len;

    if (RAND_bytes(nonce, NONCE_SIZE) != 1) return;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, kek, nonce);
    EVP_EncryptUpdate(ctx, ct, &len, lmk, KEY_SIZE);
    EVP_EncryptFinal_ex(ctx, ct + len, &len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag);
    EVP_CIPHER_CTX_free(ctx);

    /* Format : sel(16) || nonce(12) || ciphertext(32) || tag(16) */
    FILE *f = fopen(FILENAME, "wb");
    fwrite(salt,  1, SALT_SIZE,  f);
    fwrite(nonce, 1, NONCE_SIZE, f);
    fwrite(ct,    1, KEY_SIZE,   f);
    fwrite(tag,   1, TAG_SIZE,   f);
    fclose(f);

    secure_zero(lmk, KEY_SIZE);
    printf("[OK] LMK stockee AES-256-GCM dans %s\n", FILENAME);
}

/* ─── PARTIE 2 : INITIALISATION ET FRAGMENTATION ─── */

void initialiser_runtime(const uint8_t *kek, uint8_t *p1,
                         uint8_t **p2, uint8_t *p3,
                         uint8_t *hmac_ref_out) {
    uint8_t salt[SALT_SIZE], nonce[NONCE_SIZE];
    uint8_t ct[KEY_SIZE], tag[TAG_SIZE], lmk[KEY_SIZE];
    int len, ok;

    FILE *f = fopen(FILENAME, "rb");
    if (!f) { printf("Erreur: lancez --init\n"); exit(1); }
    fread(salt,  1, SALT_SIZE,  f);
    fread(nonce, 1, NONCE_SIZE, f);
    fread(ct,    1, KEY_SIZE,   f);
    fread(tag,   1, TAG_SIZE,   f);
    fclose(f);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, kek, nonce);
    EVP_DecryptUpdate(ctx, lmk, &len, ct, KEY_SIZE);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag);
    ok = EVP_DecryptFinal_ex(ctx, lmk + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ok <= 0) {
        fprintf(stderr, "[ERREUR] Tag GCM invalide\n");
        secure_zero(lmk, KEY_SIZE);
        exit(1);
    }

    /* HMAC de reference — jamais stocker la LMK en clair */
    unsigned int hlen = 32;
    HMAC(EVP_sha256(), "hmac_key_ref", 12,
         lmk, KEY_SIZE, hmac_ref_out, &hlen);

    /* Fragmentation avec RAND_bytes — pas de fake_random */
    if (RAND_bytes(p1, KEY_SIZE) != 1) exit(1);
    *p2 = malloc(KEY_SIZE);
    if (RAND_bytes(*p2, KEY_SIZE) != 1) exit(1);

    /* P3 = LMK XOR P1 XOR P2 */
    xor_buf(p3, lmk, p1, KEY_SIZE);
    xor_buf(p3, p3, *p2, KEY_SIZE);

    secure_zero(lmk, KEY_SIZE);
    secure_zero(salt, SALT_SIZE);
    printf("[OK] LMK fragmentee P1/P2/P3 — LMK effacee\n");
}

/* ─── PARTIE 3 : MUTATION CYCLIQUE ─── */

void mutate_fragments(uint8_t *p1, uint8_t **p2_heap,
                      uint8_t *p3) {
    uint8_t Ma[KEY_SIZE], Mb[KEY_SIZE], MaMb[KEY_SIZE];

    /* Masques aleatoires — RAND_bytes, pas fake_random */
    if (RAND_bytes(Ma, KEY_SIZE) != 1) exit(1);
    if (RAND_bytes(Mb, KEY_SIZE) != 1) exit(1);
    xor_buf(MaMb, Ma, Mb, KEY_SIZE);

    /*
     * P1' = P1 ^ Ma
     * P2' = P2 ^ Mb
     * P3' = P3 ^ (Ma^Mb)
     * => P1'^P2'^P3' = P1^P2^P3 = LMK (invariant)
     */
    xor_buf(p1,       p1,       Ma,   KEY_SIZE);
    xor_buf(*p2_heap, *p2_heap, Mb,   KEY_SIZE);
    xor_buf(p3,       p3,       MaMb, KEY_SIZE);

    /* Shuffling physique de P2 */
    uint8_t *new_p2 = malloc(KEY_SIZE);
    memcpy(new_p2, *p2_heap, KEY_SIZE);
    secure_zero(*p2_heap, KEY_SIZE);
    free(*p2_heap);
    *p2_heap = new_p2;

    secure_zero(Ma,   KEY_SIZE);
    secure_zero(Mb,   KEY_SIZE);
    secure_zero(MaMb, KEY_SIZE);
}

/* ─── AFFICHAGE ─── */

void afficher_etat(const char *titre, const uint8_t *p1,
                   const uint8_t *p2, const uint8_t *p3,
                   const uint8_t *hmac_ref) {
    printf("\n╔══════════════════════════════════════════════╗\n");
    printf("║  %-44s║\n", titre);
    printf("╚══════════════════════════════════════════════╝\n");
    print_hex("P1 (stack)",  p1, KEY_SIZE);
    printf("  %-35s : %p\n", "P2 addr (heap)", (void *)p2);
    print_hex("P2 (heap)",   p2, KEY_SIZE);
    print_hex("P3 (.data)",  p3, KEY_SIZE);
    verifier_integrite(p1, p2, p3, hmac_ref);

    printf("\n  [PAUSE] PID = %d\n", getpid());
    printf("  sudo gcore %d && strings core.%d | grep -i DEAD\n",
           getpid(), getpid());
    printf("  >> Entree pour continuer...\n");
    getchar();
}

/* ─── MAIN ─── */

int main(int argc, char *argv[]) {
    uint8_t salt[SALT_SIZE], kek[KEY_SIZE];
    char passphrase[128];

    printf("Passphrase admin : ");
    fflush(stdout);
    if (!fgets(passphrase, sizeof(passphrase), stdin)) return 1;
    passphrase[strcspn(passphrase, "\n")] = '\0';

    if (argc > 1 && strcmp(argv[1], "--init") == 0) {
        if (RAND_bytes(salt, SALT_SIZE) != 1) return 1;
        derive_kek(passphrase, salt, SALT_SIZE, kek);
        secure_zero(passphrase, sizeof(passphrase));
        provisionner_hsm(kek, salt);
        secure_zero(kek, KEY_SIZE);
        secure_zero(salt, SALT_SIZE);
        return 0;
    }

    /* Lire le sel depuis lmk.bin */
    FILE *f = fopen(FILENAME, "rb");
    if (!f) { printf("Lancez --init d'abord\n"); return 1; }
    fread(salt, 1, SALT_SIZE, f);
    fclose(f);

    derive_kek(passphrase, salt, SALT_SIZE, kek);
    secure_zero(passphrase, sizeof(passphrase));

    uint8_t P1_stack[KEY_SIZE], *P2_heap = NULL, hmac_ref[32];

    initialiser_runtime(kek, P1_stack, &P2_heap,
                        P3_data_segment, hmac_ref);
    secure_zero(kek,  KEY_SIZE);
    secure_zero(salt, SALT_SIZE);

    afficher_etat("CYCLE 0 — INITIAL",
                  P1_stack, P2_heap, P3_data_segment, hmac_ref);

    for (int c = 1; c <= 3; c++) {
        mutate_fragments(P1_stack, &P2_heap, P3_data_segment);
        char titre[64];
        snprintf(titre, sizeof(titre), "CYCLE %d — APRES MUTATION", c);
        afficher_etat(titre, P1_stack, P2_heap,
                      P3_data_segment, hmac_ref);
    }

    secure_zero(hmac_ref, 32);
    secure_zero(P1_stack, KEY_SIZE);
    secure_zero(P2_heap,  KEY_SIZE);
    free(P2_heap);
    return 0;
}