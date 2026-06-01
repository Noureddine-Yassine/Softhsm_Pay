#ifndef PAYHSM_ISO8583_MAPPER_H
#define PAYHSM_ISO8583_MAPPER_H

#include "iso8583_types.h"

/*
 * Map a validated ISO 8583 request to an HSM command descriptor.
 * Populates req->type based on MTI and present DEs.
 */
int iso8583_map_request(const iso8583_msg_t *msg, iso8583_hsm_req_t *req);

/*
 * Execute the HSM command described by req, using the in-memory LMK
 * and key vault.  Fills:
 *   rc_str     : 2-char response code (ISO_RC_*)
 *   mac_out    : 8-byte MAC for DE64 (only when has_mac_in is set)
 *   auth_code  : 6-char approval code (DE38, set on APPROVED)
 *   emv_resp   : DE55 response data (only for EMV commands)
 *   emv_resp_len : length of emv_resp
 * Returns ISO_OK or error.
 */
int iso8583_execute(const iso8583_msg_t *req_msg,
                    const iso8583_hsm_req_t *req,
                    char        rc_str[3],
                    uint8_t     mac_out[8],
                    int        *mac_computed,
                    char        auth_code[7],
                    uint8_t    *emv_resp,
                    int        *emv_resp_len);

#endif /* PAYHSM_ISO8583_MAPPER_H */
