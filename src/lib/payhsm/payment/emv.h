#ifndef PAYHSM_EMV_H
#define PAYHSM_EMV_H

#include <stdint.h>
#include <stddef.h>

/* Dérive les clés carte MK-AC depuis l'IMK et le PAN/PSN
   (méthode A de EMV Book 2) */
int derive_card_keys(const uint8_t *imk, size_t imk_len,
                     const char *pan, const char *psn,
                     uint8_t mk_ac_out[16]);

/* Dérive SK-AC depuis MK-AC et ATC (EMV Book 2) */
int derive_sk_ac(const uint8_t mk_ac[16], const uint8_t atc[2],
                 uint8_t sk_ac_out[16]);

/* Valide un ARQC reçu (CMAC sous SK-AC) */
int verify_arqc(const uint8_t sk_ac[16],
                const uint8_t *transaction_data, size_t tx_len,
                const uint8_t arqc_received[8]);

/* Génère un ARPC en réponse à un ARQC validé */
int generate_arpc(const uint8_t *mk_ac,
                  const uint8_t arqc[8],
                  const uint8_t auth_response[2],
                  uint8_t arpc_out[8]);

/* Puce : recalcule ARPC (MK-AC + ARQC + ARC) et compare à l'ARPC reçu */
int verify_arpc(const uint8_t mk_ac[16],
                const uint8_t arqc[8],
                const uint8_t auth_response[2],
                const uint8_t arpc_received[8]);

/* Calcule ARQC = CMAC(SK-AC, données transaction) */
int emv_compute_arqc(const uint8_t sk_ac[16],
                     const uint8_t *transaction_data,
                     size_t tx_len,
                     uint8_t arqc_out[8]);

/* Données transaction EMV (ASCII) : montant, devise, date YYMMDD, ATC, terminal TPE */
int emv_build_tx_data(unsigned long amount_cents,
                      const char *currency_code3,
                      const char *date_yymmdd6,
                      const char *atc_hex4,
                      const char *terminal_id,
                      char *tx_out,
                      size_t tx_cap,
                      size_t *tx_len_out);

#endif