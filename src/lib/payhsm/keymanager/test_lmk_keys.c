/*
 * test_lmk_keys.c — Test de sécurité : rotation LMK
 *
 * Scénario :
 *   1. Provision HSM #1  → LMK_1 générée aléatoirement, fragmentée
 *   2. Chiffrement TMK + ZMK sous LMK_1 (AES-256-GCM)
 *   3. Re-provision HSM #2 → LMK_2 différente, nouveaux fragments
 *   4. Tentative de déchiffrement des blobs avec LMK_2
 *      → DOIT échouer (tag GCM invalide)
 *   5. Déchiffrement des blobs avec LMK_1 (restaurée)
 *      → DOIT réussir
 *
 * Compile :
 *   cd ~/payhsm/payhsm
 *   gcc -Wall -Wextra -I src/lib/payhsm \
 *       src/lib/payhsm/keymanager/test_lmk_keys.c \
 *       src/lib/payhsm/keymanager/xor_fragment.c  \
 *       src/lib/payhsm/keymanager/integrity.c     \
 *       src/lib/payhsm/keymanager/mutation.c      \
 *       src/lib/payhsm/keymanager/lmk_store.c    \
 *       src/lib/payhsm/defense/defense.c          \
 *       src/lib/payhsm/defense/seccomp_policy.c  \
 *       -lssl -lcrypto -lseccomp -o test_lmk_keys && ./test_lmk_keys
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#include "xor_fragment.h"
#include "../defense/defense.h"

/* ------------------------------------------------------------------ */
/* Constantes                                                          */
/* ------------------------------------------------------------------ */
#define KEY_LEN     16   /* TMK / ZMK : 128 bits                      */
#define GCM_IV_LEN  12
#define GCM_TAG_LEN 16
#define BLOB_LEN    (GCM_IV_LEN + GCM_TAG_LEN + KEY_LEN)  /* 44 octets */

/* ------------------------------------------------------------------ */
/* Affichage                                                           */
/* ------------------------------------------------------------------ */
static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printf("  %-26s : ", label);
    for (size_t i = 0; i < len; i++) printf("%02X", buf[i]);
    printf("\n");
}

static void separator(const char *title)
{
    printf("\n┌─────────────────────────────────────────────────────────┐\n");
    printf("│  %-55s│\n", title);
    printf("└─────────────────────────────────────────────────────────┘\n");
}

/* ------------------------------------------------------------------ */
/* AES-256-GCM  :  chiffrement/déchiffrement d'une clé sous LMK       */
/*  Format blob : IV(12) || TAG(16) || CT(16)   = 44 octets           */
/* ------------------------------------------------------------------ */
static int gcm_encrypt(const uint8_t lmk[LMK_SIZE],
                        const uint8_t pt[KEY_LEN],
                        uint8_t blob[BLOB_LEN])
{
    uint8_t iv[GCM_IV_LEN];
    if (RAND_bytes(iv, GCM_IV_LEN) != 1) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ret = -1, len = 0;
    uint8_t ct[KEY_LEN], tag[GCM_TAG_LEN];

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, lmk, iv)                 != 1) goto done;
    if (EVP_EncryptUpdate(ctx, ct, &len, pt, KEY_LEN)                != 1) goto done;
    if (EVP_EncryptFinal_ex(ctx, ct + len, &len)                     != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag) != 1) goto done;

    memcpy(blob,                              iv,  GCM_IV_LEN);
    memcpy(blob + GCM_IV_LEN,                tag, GCM_TAG_LEN);
    memcpy(blob + GCM_IV_LEN + GCM_TAG_LEN,  ct,  KEY_LEN);
    ret = 0;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/*
 * Retourne  0  si déchiffrement OK (tag valide)
 *          -1  si tag invalide ou erreur  ← cas attendu avec mauvaise LMK
 */
static int gcm_decrypt(const uint8_t lmk[LMK_SIZE],
                        const uint8_t blob[BLOB_LEN],
                        uint8_t pt_out[KEY_LEN])
{
    const uint8_t *iv  = blob;
    const uint8_t *tag = blob + GCM_IV_LEN;
    const uint8_t *ct  = blob + GCM_IV_LEN + GCM_TAG_LEN;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ret = -1, len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, lmk, iv)                 != 1) goto done;
    if (EVP_DecryptUpdate(ctx, pt_out, &len, ct, KEY_LEN)            != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                             GCM_TAG_LEN, (void *)tag)               != 1) goto done;
    /* EVP_DecryptFinal_ex retourne 0 si le tag GCM ne correspond pas */
    ret = (EVP_DecryptFinal_ex(ctx, pt_out + len, &len) == 1) ? 0 : -1;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* ------------------------------------------------------------------ */
/* Provision HSM  :  génère une LMK aléatoire et la fragmente         */
/* ------------------------------------------------------------------ */
static int provision_hsm(const char *label, uint8_t lmk_save[LMK_SIZE])
{
    printf("\n  [PROVISION] %s\n", label);

    /* Génération LMK */
    uint8_t lmk[LMK_SIZE];
    if (RAND_bytes(lmk, LMK_SIZE) != 1) {
        fprintf(stderr, "  [FATAL] RAND_bytes() échoué\n");
        return -1;
    }

    /* Sauvegarde de la LMK en clair pour les tests de déchiffrement */
    memcpy(lmk_save, lmk, LMK_SIZE);
    print_hex("LMK générée", lmk, LMK_SIZE);

    /* Fragmentation (efface lmk[] en RAM) */
    if (fragment_lmk(lmk) != 0) {
        fprintf(stderr, "  [ECHEC] fragment_lmk()\n");
        secure_zero(lmk_save, LMK_SIZE);
        return -1;
    }
    printf("  LMK fragmentée en P1/P2/P3 — effacée de la RAM\n");

    /* Vérification : recomposer doit redonner la même LMK */
    uint8_t recomp[LMK_SIZE];
    if (recompose_for_op(recomp) != 0) {
        fprintf(stderr, "  [ECHEC] recompose_for_op()\n");
        return -1;
    }

    int ok = (memcmp(lmk_save, recomp, LMK_SIZE) == 0);
    secure_zero(recomp, LMK_SIZE);
    secure_zero(lmk,    LMK_SIZE);

    if (!ok) {
        fprintf(stderr, "  [ECHEC] Recomposition LMK incorrecte\n");
        return -1;
    }
    printf("  Recomposition vérifiée OK\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */
int main(void)
{
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║  PayHSM — Test rotation LMK : TMK/ZMK restent opaques    ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");

    int pass = 0, fail = 0;

    /* ── Clés de paiement ── */
    uint8_t tmk[KEY_LEN], zmk[KEY_LEN];
    if (RAND_bytes(tmk, KEY_LEN) != 1 ||
        RAND_bytes(zmk, KEY_LEN) != 1) {
        fprintf(stderr, "[FATAL] RAND_bytes()\n");
        return 1;
    }
    printf("\n  Clés de paiement générées :\n");
    print_hex("TMK (clair)", tmk, KEY_LEN);
    print_hex("ZMK (clair)", zmk, KEY_LEN);

    /* ============================================================
     * ÉTAPE 1 — Provision HSM #1, chiffrement TMK + ZMK
     * ============================================================ */
    separator("ÉTAPE 1 : Provision HSM #1 — chiffrement TMK et ZMK");

    uint8_t lmk1[LMK_SIZE];
    if (provision_hsm("HSM #1", lmk1) != 0) return 1;

    /* Recomposer LMK_1 pour chiffrer (puis re-effacer) */
    uint8_t lmk1_tmp[LMK_SIZE];
    if (recompose_for_op(lmk1_tmp) != 0) return 1;

    uint8_t blob_tmk[BLOB_LEN], blob_zmk[BLOB_LEN];

    if (gcm_encrypt(lmk1_tmp, tmk, blob_tmk) != 0) {
        fprintf(stderr, "  [ECHEC] Chiffrement TMK\n"); return 1;
    }
    printf("\n  TMK chiffré sous LMK_1 :\n");
    print_hex("  blob_TMK (IV||TAG||CT)", blob_tmk, BLOB_LEN);

    if (gcm_encrypt(lmk1_tmp, zmk, blob_zmk) != 0) {
        fprintf(stderr, "  [ECHEC] Chiffrement ZMK\n"); return 1;
    }
    printf("\n  ZMK chiffré sous LMK_1 :\n");
    print_hex("  blob_ZMK (IV||TAG||CT)", blob_zmk, BLOB_LEN);

    secure_zero(lmk1_tmp, LMK_SIZE);

    /* ============================================================
     * ÉTAPE 2 — Re-provision HSM #2 (nouvelle LMK)
     * ============================================================ */
    separator("ÉTAPE 2 : Re-provision HSM #2 — nouvelle LMK différente");

    /* Efface les fragments de LMK_1 */
    zero_all_fragments();
    printf("  Anciens fragments LMK_1 effacés\n");

    uint8_t lmk2[LMK_SIZE];
    if (provision_hsm("HSM #2", lmk2) != 0) return 1;

    /* Vérifier que LMK_1 ≠ LMK_2 */
    if (memcmp(lmk1, lmk2, LMK_SIZE) == 0) {
        printf("  [AVERTISSEMENT] LMK_1 == LMK_2 — génération aléatoire suspecte !\n");
        fail++;
    } else {
        printf("\n  LMK_1 ≠ LMK_2 → deux HSM distincts confirmés\n");
        print_hex("  LMK_1", lmk1, LMK_SIZE);
        print_hex("  LMK_2", lmk2, LMK_SIZE);
    }

    /* ============================================================
     * ÉTAPE 3 — Tentative déchiffrement avec LMK_2 (DOIT ÉCHOUER)
     * ============================================================ */
    separator("ÉTAPE 3 : Déchiffrement avec LMK_2 — DOIT ÉCHOUER");

    uint8_t lmk2_tmp[LMK_SIZE];
    if (recompose_for_op(lmk2_tmp) != 0) return 1;

    uint8_t bad_tmk[KEY_LEN] = {0};
    uint8_t bad_zmk[KEY_LEN] = {0};

    printf("\n  Tentative déchiffrement blob_TMK avec LMK_2...\n");
    if (gcm_decrypt(lmk2_tmp, blob_tmk, bad_tmk) != 0) {
        printf("  [OK] blob_TMK rejeté par GCM — tag invalide\n");
        pass++;
    } else {
        printf("  [ECHEC SÉCURITÉ] blob_TMK déchiffré avec une mauvaise LMK !\n");
        print_hex("  Résultat (ne devrait pas apparaître)", bad_tmk, KEY_LEN);
        fail++;
    }

    printf("\n  Tentative déchiffrement blob_ZMK avec LMK_2...\n");
    if (gcm_decrypt(lmk2_tmp, blob_zmk, bad_zmk) != 0) {
        printf("  [OK] blob_ZMK rejeté par GCM — tag invalide\n");
        pass++;
    } else {
        printf("  [ECHEC SÉCURITÉ] blob_ZMK déchiffré avec une mauvaise LMK !\n");
        print_hex("  Résultat (ne devrait pas apparaître)", bad_zmk, KEY_LEN);
        fail++;
    }

    secure_zero(lmk2_tmp, LMK_SIZE);
    secure_zero(bad_tmk,  KEY_LEN);
    secure_zero(bad_zmk,  KEY_LEN);

    /* ============================================================
     * ÉTAPE 4 — Déchiffrement avec LMK_1 restaurée (DOIT RÉUSSIR)
     * ============================================================ */
    separator("ÉTAPE 4 : Déchiffrement avec LMK_1 restaurée — DOIT RÉUSSIR");

    uint8_t rec_tmk[KEY_LEN] = {0};
    uint8_t rec_zmk[KEY_LEN] = {0};

    printf("\n  Déchiffrement blob_TMK avec LMK_1...\n");
    if (gcm_decrypt(lmk1, blob_tmk, rec_tmk) == 0) {
        if (memcmp(rec_tmk, tmk, KEY_LEN) == 0) {
            printf("  [OK] TMK récupéré identique à l'original\n");
            print_hex("  TMK récupéré", rec_tmk, KEY_LEN);
            pass++;
        } else {
            printf("  [ECHEC] TMK récupéré différent de l'original !\n");
            fail++;
        }
    } else {
        printf("  [ECHEC] Déchiffrement TMK avec LMK_1 refusé\n");
        fail++;
    }

    printf("\n  Déchiffrement blob_ZMK avec LMK_1...\n");
    if (gcm_decrypt(lmk1, blob_zmk, rec_zmk) == 0) {
        if (memcmp(rec_zmk, zmk, KEY_LEN) == 0) {
            printf("  [OK] ZMK récupéré identique à l'original\n");
            print_hex("  ZMK récupéré", rec_zmk, KEY_LEN);
            pass++;
        } else {
            printf("  [ECHEC] ZMK récupéré différent de l'original !\n");
            fail++;
        }
    } else {
        printf("  [ECHEC] Déchiffrement ZMK avec LMK_1 refusé\n");
        fail++;
    }

    /* ============================================================
     * Résumé
     * ============================================================ */
    printf("\n╔═══════════════════════════════════════════════════════════╗\n");
    printf("║                       RÉSUMÉ                             ║\n");
    printf("╠═══════════════════════════════════════════════════════════╣\n");
    printf("║  Tests réussis  : %-3d                                    ║\n", pass);
    printf("║  Tests échoués  : %-3d                                    ║\n", fail);
    if (fail == 0) {
        printf("║                                                           ║\n");
        printf("║  ✓ La LMK protège bien TMK et ZMK.                       ║\n");
        printf("║  ✓ Un re-provisionnement rend les blobs illisibles.       ║\n");
        printf("║  ✓ Seule la LMK d'origine peut déchiffrer ses clés.      ║\n");
    } else {
        printf("║  ✗ PROBLÈME DE SÉCURITÉ DÉTECTÉ                          ║\n");
    }
    printf("╚═══════════════════════════════════════════════════════════╝\n");

    /* Nettoyage */
    secure_zero(lmk1,    LMK_SIZE);
    secure_zero(lmk2,    LMK_SIZE);
    secure_zero(tmk,     KEY_LEN);
    secure_zero(zmk,     KEY_LEN);
    secure_zero(rec_tmk, KEY_LEN);
    secure_zero(rec_zmk, KEY_LEN);
    zero_all_fragments();

    return (fail == 0) ? 0 : 1;
}
