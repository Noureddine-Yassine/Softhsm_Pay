#ifndef PAYHSM_CORE_H
#define PAYHSM_CORE_H

#include <stdint.h>
#include <stddef.h>
#include "keymanager/key_vault.h"

#define PAYHSM_RC_OK           0
#define PAYHSM_RC_ERR         -1
#define PAYHSM_RC_DECLINED    55
#define PAYHSM_RC_NOT_INIT    -2
#define PAYHSM_RC_CARD_UNKNOWN -3

#define PAYHSM_PATH_MAX 256

typedef struct {
    int                 initialized;
    char                data_dir[PAYHSM_PATH_MAX];
    char                lmk_path[PAYHSM_PATH_MAX];
    payhsm_key_vault_t  vault;
} payhsm_ctx_t;

payhsm_ctx_t *payhsm_ctx(void);

/* Provision : génère LMK aléatoire + dérive toutes les clés + fragmente */
int payhsm_provision(const char *passphrase,
                     const char *data_dir,
                     const char *const *terminals,
                     int n_terminals);

/* Provision LMK seule — coffre HSM vide (clés chez le Switch) */
int payhsm_provision_lmk_only(const char *passphrase, const char *data_dir);

/* Démarrage : charge lmk.bin + keys.vault, vérifie intégrité fragments */
int payhsm_startup(const char *passphrase, const char *data_dir);

/* Démarrage depuis une MK reconstituée (Shamir) — pas de lmk.bin, fragmentation directe */
int payhsm_startup_from_mk(const uint8_t mk[32], const char *data_dir);

void payhsm_shutdown(void);

/* Identifiant incrémenté à chaque payhsm_startup réussi (sync coffre Switch) */
unsigned long payhsm_get_boot_id(void);

/* Déverrouille une clé (recompose LMK brièvement) — effacer key_out après usage */
int payhsm_unwrap_key(payhsm_key_type_t type,
                      const char *terminal_id,
                      uint8_t key_out[PAYHSM_KEY_LEN]);

/* Enregistre PVV pour un PAN */
int payhsm_set_card_pvv(const char *pan, const char *pvv4);

/* Calcule PVV depuis PIN + PVK (vault) et enregistre la carte */
int payhsm_register_card(const char *pan, const char *pin);

/* Core Banking : émet le PVV pour un PAN (même calcul que register, retourne le PVV) */
int payhsm_corebanking_issue_pvv(const char *pan, const char *pin, char pvv_out[5]);

/* Lit le PVV déjà émis pour un PAN (0 si trouvé, -1 sinon) */
int payhsm_corebanking_get_pvv(const char *pan, char pvv_out[5]);

/* Carte émise en Core Banking (PVV présent dans le HSM) — requis pour EMV */
int payhsm_corebanking_card_enrolled(const char *pan);

/* GAP : génère PIN block chiffré sous TPK du terminal */
int payhsm_gap_generate_pin_block(const char *terminal_id,
                                  const char *pin,
                                  const char *pan,
                                  uint8_t pin_block[8]);

/* HSM : vérifie PIN block (TPK) contre PVV */
int payhsm_verify_pin_block(const char *terminal_id,
                            const char *pan,
                            const uint8_t pin_block[8],
                            int *rc_out);

/* Translation TPK → ZPK pour switch inter-banques */
int payhsm_translate_pin_to_zpk(const char *terminal_id,
                                const uint8_t pin_block_tpk[8],
                                uint8_t pin_block_zpk[8]);

/* Translation TPK → ZPK identifiée dans le coffre (ex. ZPK-BANK-A) */
int payhsm_translate_pin_to_zpk_id(const char *terminal_id,
                                 const uint8_t pin_block_tpk[8],
                                 const char *zpk_key_id,
                                 uint8_t pin_block_zpk[8]);

/* Translation réseau ZPK_A → ZPK_B (deux entrées coffre) */
int payhsm_translate_zpk_to_zpk(const char *src_zpk_id,
                              const uint8_t pin_block_in[8],
                              const char *dst_zpk_id,
                              uint8_t pin_block_out[8]);

/* Vérification PIN block chiffré sous ZPK (banque émettrice) */
int payhsm_verify_pin_block_zpk(const char *zpk_key_id,
                                const char *pan,
                                const uint8_t pin_block[8],
                                int *rc_out);

/* KCV d'une clé */
int payhsm_get_kcv(payhsm_key_type_t type,
                   const char *terminal_id,
                   char kcv_hex[7]);

int payhsm_get_kcv_by_id(const char *key_id, char kcv_hex[7]);

/* Liste terminaux / clés (texte dans buf) */
int payhsm_status_text(char *buf, size_t buflen);

#define PAYHSM_EMV_TX_MAX   64
#define PAYHSM_EMV_HEX_MAX  20

typedef struct {
    int   rc;
    int   approved;
    char  tx_data[PAYHSM_EMV_TX_MAX];
    char  arqc_hex[PAYHSM_EMV_HEX_MAX];
    char  arpc_hex[PAYHSM_EMV_HEX_MAX];
    char  amount_display[32];
    char  message[128];
} payhsm_emv_purchase_t;

/* Simulation paiement EMV : puce (ARQC) + HSM émetteur (vérif + ARPC) */
int payhsm_emv_simulate_purchase(const char *pan,
                                 const char *psn,
                                 const char *atc_hex,
                                 unsigned long amount_cents,
                                 const char *currency_code3,
                                 payhsm_emv_purchase_t *result);

/* État LMK fragmentée (dashboard) */
typedef struct {
    int  fragmented;
    int  integrity_ok;
    int  mutation_count;
    long mutation_last_ts;
    char active_token_id[64];
    char data_dir[PAYHSM_PATH_MAX];
} payhsm_lmk_status_t;

int payhsm_get_lmk_status(payhsm_lmk_status_t *st);
int payhsm_mutate_lmk_fragments(void);

#endif
