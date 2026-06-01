#ifndef PAYHSM_MUTATION_H
#define PAYHSM_MUTATION_H

#include <stdint.h>
#include <time.h>
#include "lmk_store.h"

/* Applique mutation XOR + shuffle heap sur P1/P2/P3 */
int mutation_apply(uint8_t p1[PAYHSM_LMK_SIZE],
                   uint8_t **p2,
                   uint8_t p3[PAYHSM_LMK_SIZE]);

/* Statistiques exposées au dashboard / logs */
typedef struct {
    unsigned long count;
    time_t      last_ts;
} mutation_stats_t;

void mutation_stats_get(mutation_stats_t *out);
void mutation_stats_reset(void);

#endif
