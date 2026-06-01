#ifndef PAYHSM_MAC_H
#define PAYHSM_MAC_H

#include <stdint.h>
#include <stddef.h>

/* Calcule un MAC ISO 9797-1 algo 3 (Retail MAC) sous TAK */
int calculate_mac_tak(const uint8_t *msg, size_t msg_len,
                      const uint8_t *tak, size_t tak_len,
                      uint8_t mac_out[8]);

/* Calcule un MAC inter-bancaire sous ZAK */
int calculate_mac_zak(const uint8_t *msg, size_t msg_len,
                      const uint8_t *zak, size_t zak_len,
                      uint8_t mac_out[8]);

/* Vérifie un MAC reçu en temps constant */
int verify_mac(const uint8_t *msg, size_t msg_len,
               const uint8_t *key, size_t key_len,
               const uint8_t mac_received[8]);

#endif