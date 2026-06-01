#ifndef PAYHSM_INTEGRITY_H
#define PAYHSM_INTEGRITY_H

#include <stdint.h>
#include "lmk_store.h"

#define PAYHSM_HMAC_SIZE 32

/* Calcule le HMAC-SHA256 de référence sur la LMK (avant fragmentation) */
int integrity_set_reference(const uint8_t lmk[PAYHSM_LMK_SIZE]);

/* Vérifie P1⊕P2⊕P3 contre le HMAC de référence */
int integrity_verify_fragments(const uint8_t p1[PAYHSM_LMK_SIZE],
                               const uint8_t *p2,
                               const uint8_t p3[PAYHSM_LMK_SIZE]);

/* Efface la référence HMAC */
void integrity_clear_reference(void);

/* 8 car. hex — empreinte HMAC de référence (sans exposer la LMK) */
void integrity_ref_prefix(char hex[9]);

#endif
