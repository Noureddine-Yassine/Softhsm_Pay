#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

#include "defense/defense.h"

#define KEY_SIZE    32
#define NONCE_SIZE  12
#define TAG_SIZE    16
#define SALT_SIZE   16
#define PBKDF2_ITER 100000
#define FILENAME    "lmk.bin"

/* ─── FRAGMENTS — trois zones mémoire distinctes ─── */
static uint8_t  g_P1[KEY_SIZE] = {0};   /* stack simulé  */
static uint8_t *g_P2            = NULL;  /* heap          */
uint8_t         g_P3[KEY_SIZE] = {0};   /* .data         */

/* HMAC de référence — jamais la LMK elle-même */
static uint8_t g_hmac_ref[32] = {0};

/* ─────────────────────────────────────────────
   UTILITAIRES
   ───────────────────────────────────────────── */

void xor_buf(uint8_t *out, const uint8_t *a,
             const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) out[i] = a[i] ^ b[i];
}

void print_hex(const char *label, const uint8_t *buf, size_t len) {
    printf("  %-35s : ", label);
    for (size_t i = 0; i < len; i++) printf("%02X ", buf[i]);
    printf("\n");
}

void derive_kek(const char *pass, const uint8_t *salt,
                size_t slen, uint8_t *kek) {
    PKCS5_PBKDF2_HMAC(pass, (int)strlen(pass),
                      salt, (int)slen, PBKDF2_ITER,
                      EVP_sha256(), KEY_SIZE, kek);
}

/* ─────────────────────────────────────────────
   VÉRIFICATION D'INTÉGRITÉ
   Recompose P1⊕P2⊕P3 et compare le HMAC
   ───────────────────────────────────────────── */
void verifier_integrite(void) {
    uint8_t recon[KEY_SIZE], hmac_calc[32];
    unsigned int hlen = 32;

    xor_buf(recon, g_P1, g_P2, KEY_SIZE);
    xor_buf(recon, recon, g_P3, KEY_SIZE);

    HMAC(EVP_sha256(), "hmac_key_ref", 12,
         recon, KEY_SIZE, hmac_calc, &hlen);

    int ok = (memcmp(hmac_calc, g_hmac_ref, 32) == 0);
    printf("  %-35s : %s\n", "Integrite (HMAC P1^P2^P3)",
           ok ? "\033[32m[OK] LMK VALIDE\033[0m"
              : "\033[31m[KO] CORRUPTION DETECTEE\033[0m");

    secure_zero(recon,     KEY_SIZE);
    secure_zero(hmac_calc, 32);
}

/* ─────────────────────────────────────────────
   FRAGMENTATION
   P1 ⊕ P2 ⊕ P3 = LMK
   LMK effacée immédiatement après
   ───────────────────────────────────────────── */
void fragmenter(uint8_t *lmk) {
    /* Calcul du HMAC avant d'effacer la LMK */
    unsigned int hlen = 32;
    HMAC(EVP_sha256(), "hmac_key_ref", 12,
         lmk, KEY_SIZE, g_hmac_ref, &hlen);

    /* P1 et P2 aléatoires */
    if (RAND_bytes(g_P1, KEY_SIZE) != 1) exit(1);
    g_P2 = malloc(KEY_SIZE);
    if (RAND_bytes(g_P2, KEY_SIZE) != 1) exit(1);

    /* P3 = LMK ⊕ P1 ⊕ P2 */
    xor_buf(g_P3, lmk, g_P1, KEY_SIZE);
    xor_buf(g_P3, g_P3, g_P2, KEY_SIZE);

    /* LMK effacée immédiatement */
    secure_zero(lmk, KEY_SIZE);
    printf("[OK] LMK fragmentee P1/P2/P3 — LMK effacee\n");
}

/* ─────────────────────────────────────────────
   MUTATION CYCLIQUE
   P1' = P1 ⊕ Ma
   P2' = P2 ⊕ Mb
   P3' = P3 ⊕ (Ma⊕Mb)
   LMK invariante : P1'⊕P2'⊕P3' = LMK
   ───────────────────────────────────────────── */
void mutate_fragments(int cycle) {
    uint8_t Ma[KEY_SIZE], Mb[KEY_SIZE], MaMb[KEY_SIZE];

    if (RAND_bytes(Ma, KEY_SIZE) != 1) exit(1);
    if (RAND_bytes(Mb, KEY_SIZE) != 1) exit(1);
    xor_buf(MaMb, Ma, Mb, KEY_SIZE);

    xor_buf(g_P1, g_P1, Ma,   KEY_SIZE);
    xor_buf(g_P2, g_P2, Mb,   KEY_SIZE);
    xor_buf(g_P3, g_P3, MaMb, KEY_SIZE);

    /* Shuffling physique — P2 change d'adresse */
    uint8_t *new_p2 = malloc(KEY_SIZE);
    memcpy(new_p2, g_P2, KEY_SIZE);
    secure_zero(g_P2, KEY_SIZE);
    free(g_P2);
    g_P2 = new_p2;

    secure_zero(Ma,   KEY_SIZE);
    secure_zero(Mb,   KEY_SIZE);
    secure_zero(MaMb, KEY_SIZE);

    printf("\n=== APRES MUTATION — Cycle %d ===\n", cycle);
    print_hex("P1 (stack)",  g_P1, KEY_SIZE);
    printf("  %-35s : %p\n", "P2 addr (heap)", (void *)g_P2);
    print_hex("P2 (heap)",   g_P2, KEY_SIZE);
    print_hex("P3 (.data)",  g_P3, KEY_SIZE);
    verifier_integrite();
}

/* ─────────────────────────────────────────────
   AFFICHAGE ÉTAT
   ───────────────────────────────────────────── */
void afficher_etat(const char *titre) {
    printf("\n=== %s ===\n", titre);
    print_hex("P1 (stack)",  g_P1, KEY_SIZE);
    printf("  %-35s : %p\n", "P2 addr (heap)", (void *)g_P2);
    print_hex("P2 (heap)",   g_P2, KEY_SIZE);
    print_hex("P3 (.data)",  g_P3, KEY_SIZE);
    verifier_integrite();

    printf("\n  [PAUSE] PID = %d\n", getpid());
    printf("  Terminal 2 :\n");
    printf("    gdb -p %d           (sans sudo, doit echouer)\n", getpid());
    printf("    sudo gcore %d\n", getpid());
    printf("    strings core.%d | grep -i DEAD\n", getpid());
    printf("  >> Entree pour continuer...\n");
    getchar();
}

/* ─────────────────────────────────────────────
   NETTOYAGE FINAL
   ───────────────────────────────────────────── */
void cleanup(void) {
    secure_zero(g_P1,      KEY_SIZE);
    secure_zero(g_P3,      KEY_SIZE);
    secure_zero(g_hmac_ref, 32);
    if (g_P2) {
        secure_zero(g_P2, KEY_SIZE);
        free(g_P2);
        g_P2 = NULL;
    }
    printf("[OK] Fragments zeroises — arret propre\n");
}

/* ─────────────────────────────────────────────
   MAIN
   ───────────────────────────────────────────── */
int main(void) {

    /* ─── 1. DEFENSES AVANT TOUT SECRET ─── */
    printf("[1] Installation des defenses...\n");
    if (anti_dump_setup()   != 0) return 1;
    if (anti_ptrace_setup() != 0) return 1;

    /* ─── 2. PASSPHRASE ─── */
    char passphrase[128];
    printf("Passphrase admin : ");
    fflush(stdout);
    if (!fgets(passphrase, sizeof(passphrase), stdin)) return 1;
    passphrase[strcspn(passphrase, "\n")] = '\0';

    /* ─── 3. LIRE LE SEL DEPUIS lmk.bin ─── */
    uint8_t salt[SALT_SIZE], kek[KEY_SIZE];
    FILE *f = fopen(FILENAME, "rb");
    if (!f) { printf("Lancez demo_frag --init d'abord\n"); return 1; }
    fread(salt, 1, SALT_SIZE, f);
    fclose(f);

    derive_kek(passphrase, salt, SALT_SIZE, kek);
    secure_zero(passphrase, sizeof(passphrase));

    /* ─── 4. DÉCHIFFRER lmk.bin ─── */
    uint8_t nonce[NONCE_SIZE], ct[KEY_SIZE], tag[TAG_SIZE];
    uint8_t lmk[KEY_SIZE];
    int len, ok;

    f = fopen(FILENAME, "rb");
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
        return 1;
    }

    secure_zero(kek,  KEY_SIZE);
    secure_zero(salt, SALT_SIZE);

    /* ─── 5. FRAGMENTER ─── */
    printf("[2] Fragmentation LMK...\n");
    fragmenter(lmk);

    /* ─── 6. ÉTAT INITIAL + PAUSE POUR TESTS ─── */
    afficher_etat("CYCLE 0 — INITIAL");

    /* ─── 7. MUTATION CYCLIQUE ─── */
    for (int c = 1; c <= 3; c++) {
        anti_ptrace_check();   /* vérification active à chaque cycle */
        mutate_fragments(c);
    }

    /* ─── 8. NETTOYAGE ─── */
    cleanup();
    return 0;
}