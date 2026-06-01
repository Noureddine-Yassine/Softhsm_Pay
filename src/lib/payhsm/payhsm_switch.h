#ifndef PAYHSM_SWITCH_H
#define PAYHSM_SWITCH_H

#include <stdint.h>
#include "payhsm_core.h"
#include "keymanager/key_vault.h"

#define PAYHSM_GCM_BLOB_BYTES 44
#define PAYHSM_GCM_BLOB_HEX   88
#define PAYHSM_ECB_KEY_HEX    32

/* Déchiffre ENC(LMK) format GCM IV+Tag+CT (88 hex) */
int payhsm_unwrap_lmk_gcm_hex(const char *blob88, uint8_t key_out[PAYHSM_KEY_LEN]);

/* Déchiffre ENC(parent, child) — 32 hex ECB */
int payhsm_unwrap_ecb_hex(const uint8_t parent_key[PAYHSM_KEY_LEN],
                            const char *enc32hex,
                            uint8_t key_out[PAYHSM_KEY_LEN]);

/* Dérive TPK/TAK sous TMK (Switch fournit ENC(LMK,TMK)) → ENC(TMK,TPK/TAK) en hex */
int payhsm_switch_derive_terminal(const char *tmk_gcm88,
                                  const char *terminal_id,
                                  char tpk_enc32hex[33],
                                  char tak_enc32hex[33],
                                  char tpk_kcv[7],
                                  char tak_kcv[7]);

/* Opérations monétiques avec clés fournies par le Switch (pas le coffre HSM) */
int payhsm_gap_switch(const char *tmk_gcm88,
                      const char *tpk_enc32hex,
                      const char *pin,
                      const char *pan,
                      uint8_t pin_block[8]);

int payhsm_verify_pin_switch(const char *tmk_gcm88,
                             const char *tpk_enc32hex,
                             const char *pvk_gcm88,
                             const char *pan,
                             const char *pvv_stored,
                             const uint8_t pin_block[8],
                             int *rc_out);

/* ZPK sous ZMK (32 hex ECB) ; ZMK sous LMK (88 hex GCM) */
int payhsm_switch_wrap_zpk_under_zmk(const char *zmk_gcm88,
                                      const uint8_t zpk[PAYHSM_KEY_LEN],
                                      char zpk_enc32hex[33],
                                      char kcv_out[7]);

int payhsm_translate_pin_switch(const char *tmk_gcm88,
                                const char *tpk_enc32hex,
                                const char *zmk_gcm88,
                                const char *zpk_enc32hex,
                                const uint8_t pin_block_tpk[8],
                                uint8_t pin_block_zpk[8]);

int payhsm_translate_zpk_switch(const char *zmk_gcm88,
                                const char *zpk_a_enc32hex,
                                const char *zpk_b_enc32hex,
                                const uint8_t pin_block_in[8],
                                uint8_t pin_block_out[8]);

int payhsm_verify_pin_zpk_switch(const char *zmk_gcm88,
                                 const char *zpk_enc32hex,
                                 const char *pvk_gcm88,
                                 const char *pan,
                                 const uint8_t pin_block[8],
                                 int *rc_out);

int payhsm_mac_tak_switch(const char *tmk_gcm88,
                          const char *tak_enc32hex,
                          const uint8_t *msg,
                          size_t msg_len,
                          uint8_t mac_out[8]);

int payhsm_mac_verify_switch(const char *tmk_gcm88,
                             const char *tak_enc32hex,
                             const uint8_t *msg,
                             size_t msg_len,
                             const uint8_t mac[8]);

int payhsm_corebanking_issue_pvv_switch(const char *pan,
                                        const char *pin,
                                        const char *pvk_gcm88,
                                        char pvv_out[5]);

int payhsm_emv_arqc_switch(const char *imk_gcm88,
                           const char *pan,
                           const char *psn,
                           const char *atc_hex,
                           unsigned long amount_cents,
                           const char *currency_code3,
                           const char *date_yymmdd6,
                           const char *terminal_id,
                           char arqc_hex[17],
                           char tx_data_out[256],
                           size_t tx_cap,
                           size_t *tx_len_out);

int payhsm_emv_verify_switch(const char *imk_gcm88,
                             const char *pan,
                             const char *psn,
                             const char *atc_hex,
                             const uint8_t *tx_data,
                             size_t tx_len,
                             const char *arqc_hex,
                             int *valid_out,
                             char arpc_hex[17],
                             int *arpc_card_valid_out,
                             char arpc_expected_hex[17]);

/** Puce : MK-AC (session ou IMK+PAN+PSN) → recalcul ARPC, compare à arpc_hex reçu */
int payhsm_emv_verify_arpc_switch(const char *imk_gcm88,
                                  const char *pan,
                                  const char *psn,
                                  const char *atc_hex,
                                  const char *arqc_hex,
                                  const char *arpc_hex,
                                  const char *arc_hex4,
                                  int *valid_out,
                                  char arpc_expected_hex[17]);

int payhsm_emv_purchase_switch(const char *imk_gcm88,
                               const char *pan,
                               const char *psn,
                               const char *atc_hex,
                               unsigned long amount_cents,
                               const char *currency_code3,
                               const char *date_yymmdd6,
                               const char *terminal_id,
                               payhsm_emv_purchase_t *result);

/* Chiffre une clé 16o sous LMK (GCM) — pour initialisation Switch */
int payhsm_wrap_lmk_gcm_hex(const uint8_t key[PAYHSM_KEY_LEN], char blob88[PAYHSM_GCM_BLOB_HEX + 1]);

/* Efface la session EMV (ARQC → verify) après verify ou shutdown */
void payhsm_emv_clear_session(void);

#endif
