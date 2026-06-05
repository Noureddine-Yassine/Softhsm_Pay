#ifndef PAYHSM_KEY_RELATION_VALIDATOR_H
#define PAYHSM_KEY_RELATION_VALIDATOR_H

#include "payhsm_core.h"

/* Hiérarchie export A8 : clé métier → KEK de transport (ZMK ou TMK) */

typedef enum {
    PAYHSM_KEK_ZMK = 0,
    PAYHSM_KEK_TMK = 1,
} payhsm_kek_kind_t;

/** KEK requise pour un Key Type (3 car. hex). Retourne -1 si type inconnu. */
payhsm_kek_kind_t payhsm_export_kek_kind(const char *key_type_code3);

/**
 * Valide qu'une export A8 est autorisée pour ce type de clé.
 * @param op_key_type_code3  ex. "001" ZPK, "002" TPK, "003" TAK, "109" IMK
 * @return PAYHSM_RC_OK ou PAYHSM_RC_ERR (réponse A9 code 11 / 17)
 */
int payhsm_validate_export_hierarchy(const char *op_key_type_code3);

/**
 * Récupère le cryptogramme GCM (88 hex) de la clé de transport (ZMK/TMK)
 * depuis ext_keys.vault pour un export A8 sans fournir la ZMK dans la trame.
 * @return PAYHSM_RC_OK ou PAYHSM_RC_ERR
 */
int payhsm_ekm_lookup_transport_gcm(const char *op_key_type_code3,
                                    char crypt88[89],
                                    char transport_id[64]);

/** Même blob GCM que A8/L — recherche directe ZMK ou TMK dans ext_keys.vault */
int payhsm_ekm_lookup_transport_by_name(const char *transport_name,
                                          char crypt88[89],
                                          char transport_id[64]);

/** Vide ext_keys.vault (mémoire + disque). Retourne le nombre de clés actives supprimées, -1 si HSM non prêt. */
int payhsm_ekm_clear_vault(void);

#endif
