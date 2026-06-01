#ifndef XOR_FRAGMENT_H
#define XOR_FRAGMENT_H

#include <stdint.h>
#include <stddef.h>

#define LMK_SIZE 32

/* P3 dans .data — accessible par defense.c */
extern uint8_t g_P3[LMK_SIZE];

/* Fragmente la LMK en P1/P2/P3 — zéroïse la LMK après */
int fragment_lmk(uint8_t *lmk);

/* Recompose temporairement la LMK — appeler secure_zero après */
int recompose_for_op(uint8_t out[LMK_SIZE]);

/* Vérifie l'intégrité HMAC des fragments */
int check_integrity(void);

/* Applique la mutation cyclique + shuffling P2 */
int mutate_fragments(void);

/* Zéroïse tous les fragments — arrêt ou urgence */
void zero_all_fragments(void);

/* Vérification sans arrêt d'urgence (tests) */
int verify_integrity_quiet(void);

/* Corrompt P3 pour test d'intégrité */
void tamper_fragment_test(void);

/* 8 car. hex — HMAC non réversible du fragment (dashboard, sans exposer Pn) */
void fragment_fingerprint_prefix(int which, char hex[9]);

#endif