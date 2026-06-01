#include "iso8583_mapper.h"
#include "iso8583_parser.h"
#include "iso8583_packer.h"
#include "../payhsm_core.h"
#include "../payment/mac.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ── Helper: copy field as C string ─────────────────────────── */

static void field_str(const iso8583_msg_t *msg, int de,
                      char *dst, int dst_len)
{
    if (!msg->fields[de].present || dst_len <= 0) {
        if (dst_len > 0) dst[0] = '\0';
        return;
    }
    int n = msg->fields[de].len < dst_len - 1
            ? msg->fields[de].len : dst_len - 1;
    memcpy(dst, msg->fields[de].data, n);
    dst[n] = '\0';
    /* right-strip spaces (FIXED fields are space-padded) */
    for (int i = n - 1; i >= 0 && dst[i] == ' '; i--) dst[i] = '\0';
}

/* ── Map request ─────────────────────────────────────────────── */

int iso8583_map_request(const iso8583_msg_t *msg, iso8583_hsm_req_t *req)
{
    memset(req, 0, sizeof(*req));

    /* ── Terminal / merchant ID ── */
    field_str(msg, 41, req->terminal_id, sizeof(req->terminal_id));
    field_str(msg, 42, req->merchant_id, sizeof(req->merchant_id));
    field_str(msg, 2,  req->pan,         sizeof(req->pan));
    field_str(msg, 3,  req->processing_code, sizeof(req->processing_code));
    field_str(msg, 4,  req->amount,      sizeof(req->amount));
    field_str(msg, 11, req->stan,        sizeof(req->stan));
    field_str(msg, 37, req->retrieval_ref, sizeof(req->retrieval_ref));
    field_str(msg, 38, req->auth_code,   sizeof(req->auth_code));
    field_str(msg, 49, req->currency,    sizeof(req->currency));

    /* ── PIN block (DE52, binary) ── */
    if (msg->fields[52].present && msg->fields[52].len == 8) {
        memcpy(req->pin_block, msg->fields[52].data, 8);
        req->has_pin_block = 1;
    }

    /* ── MAC (DE64, binary) ── */
    if (msg->fields[64].present && msg->fields[64].len == 8) {
        memcpy(req->mac_in, msg->fields[64].data, 8);
        req->has_mac = 1;
    }

    /* ── EMV data (DE55) ── */
    if (msg->fields[55].present && msg->fields[55].len > 0) {
        int n = msg->fields[55].len < (int)sizeof(req->emv_data)
                ? msg->fields[55].len : (int)sizeof(req->emv_data);
        memcpy(req->emv_data, msg->fields[55].data, n);
        req->emv_data_len = n;
    }

    /* ── Determine command type ── */
    const char *mti = msg->mti;

    if (strncmp(mti, ISO_MTI_NETMGMT_REQ, 4) == 0) {
        req->type = HSM_CMD_NETMGMT;
    } else if (strncmp(mti, ISO_MTI_REVERSAL_REQ, 4) == 0) {
        req->type = HSM_CMD_REVERSAL;
    } else {
        /* 0100 / 0200 */
        if (req->emv_data_len > 0)
            req->type = HSM_CMD_EMV_ARQC;
        else if (req->has_pin_block)
            req->type = HSM_CMD_PIN_VERIFY;
        else if (req->has_mac)
            req->type = HSM_CMD_MAC_VERIFY;
        else
            req->type = HSM_CMD_FINANCIAL;
    }

    return ISO_OK;
}

/* ── Build message bytes for MAC computation (DE64 zeroed) ──── */

static int build_mac_input(const iso8583_msg_t *req_msg,
                           uint8_t *buf, int buf_max)
{
    /* Clone the message, zero DE64 */
    iso8583_msg_t tmp;
    memcpy(&tmp, req_msg, sizeof(tmp));
    if (tmp.fields[64].present) {
        memset(tmp.fields[64].data, 0, 8);
    }
    return iso8583_pack(&tmp, buf, buf_max);
}

/* ── Execute ─────────────────────────────────────────────────── */

int iso8583_execute(const iso8583_msg_t *req_msg,
                    const iso8583_hsm_req_t *req,
                    char        rc_str[3],
                    uint8_t     mac_out[8],
                    int        *mac_computed,
                    char        auth_code[7],
                    uint8_t    *emv_resp,
                    int        *emv_resp_len)
{
    if (mac_computed)  *mac_computed  = 0;
    if (emv_resp_len)  *emv_resp_len  = 0;
    memset(rc_str,    0, 3);
    memset(auth_code, 0, 7);
#define SET_RC(s) do { rc_str[0]=(s)[0]; rc_str[1]=(s)[1]; rc_str[2]='\0'; } while(0)

    /* ── LMK guard ── */
    if (!payhsm_ctx()->initialized) {
        SET_RC(ISO_RC_NOT_INIT);
        return ISO_ERR_NOINIT;
    }

    /* ── Network management: echo ── */
    if (req->type == HSM_CMD_NETMGMT) {
        SET_RC(ISO_RC_APPROVED);
        return ISO_OK;
    }

    /* ── Reversal: always accepted ── */
    if (req->type == HSM_CMD_REVERSAL) {
        SET_RC(ISO_RC_APPROVED);
        return ISO_OK;
    }

    /* ── MAC verification (DE64) ── */
    if (req->type == HSM_CMD_MAC_VERIFY) {
        if (!req->has_mac) {
            SET_RC(ISO_RC_INVALID_FORMAT);
            return ISO_ERR_FIELD;
        }
        /* Unwrap TAK for this terminal */
        uint8_t tak[PAYHSM_KEY_LEN];
        if (payhsm_unwrap_key(PAYHSM_KEY_TAK, req->terminal_id, tak) != 0) {
            SET_RC(ISO_RC_SYSTEM_ERROR);
            return ISO_ERR_CRYPTO;
        }
        /* Build MAC input (message with DE64 zeroed) */
        uint8_t mac_buf[ISO8583_MSG_MAX];
        int mac_len = build_mac_input(req_msg, mac_buf, sizeof(mac_buf));
        if (mac_len < 0) {
            memset(tak, 0, sizeof(tak));
            SET_RC(ISO_RC_INVALID_FORMAT);
            return ISO_ERR_FORMAT;
        }
        int ok = verify_mac(mac_buf, mac_len, tak, sizeof(tak), req->mac_in);
        memset(tak, 0, sizeof(tak));

        if (ok != 0) {
            SET_RC(ISO_RC_MAC_ERROR);
            return ISO_OK;
        }
        SET_RC(ISO_RC_APPROVED);
        /* Compute response MAC */
        if (mac_out && mac_computed) {
            if (payhsm_unwrap_key(PAYHSM_KEY_TAK, req->terminal_id, tak) == 0) {
                if (calculate_mac_tak(mac_buf, mac_len, tak, sizeof(tak), mac_out) == 0)
                    *mac_computed = 1;
                memset(tak, 0, sizeof(tak));
            }
        }
        return ISO_OK;
    }

    /* ── PIN verification (DE52) ── */
    if (req->type == HSM_CMD_PIN_VERIFY) {
        if (!req->has_pin_block || !req->pan[0]) {
            SET_RC(ISO_RC_INVALID_FORMAT);
            return ISO_ERR_FIELD;
        }
        int pin_rc = 0;
        int ret = payhsm_verify_pin_block(req->terminal_id, req->pan,
                                          req->pin_block, &pin_rc);
        if (ret != 0) {
            SET_RC(ISO_RC_SYSTEM_ERROR);
            return ISO_OK;
        }
        if (pin_rc == 0)
            SET_RC(ISO_RC_APPROVED);
        else
            SET_RC(ISO_RC_PIN_INCORRECT);
        return ISO_OK;
    }

    /* ── EMV ARQC verification (DE55) ── */
    if (req->type == HSM_CMD_EMV_ARQC) {
        if (req->emv_data_len < 8 || !req->pan[0]) {
            SET_RC(ISO_RC_INVALID_FORMAT);
            return ISO_ERR_FIELD;
        }

        /* Extract ATC (bytes 0-1 of EMV data by convention) and build hex */
        char atc_hex[5]  = "0001"; /* fallback */
        if (req->emv_data_len >= 4) {
            snprintf(atc_hex, sizeof(atc_hex), "%02X%02X",
                     req->emv_data[2], req->emv_data[3]);
        }

        unsigned long cents = (unsigned long)strtoul(req->amount, NULL, 10);
        const char *currency = req->currency[0] ? req->currency : "978";

        payhsm_emv_purchase_t result;
        int ret = payhsm_emv_simulate_purchase(req->pan, "00",
                                               atc_hex, cents,
                                               currency, &result);
        if (ret != 0 || !result.approved) {
            SET_RC(ISO_RC_DECLINED);
            return ISO_OK;
        }
        SET_RC(ISO_RC_APPROVED);
        /* EMV response (ARPC hex → binary) */
        if (emv_resp && emv_resp_len && result.arpc_hex[0]) {
            int arpc_bytes = iso8583_hex2bin(result.arpc_hex,
                                             emv_resp, 8);
            if (arpc_bytes > 0) *emv_resp_len = arpc_bytes;
        }
        return ISO_OK;
    }

    /* ── Basic financial (no PIN/EMV/MAC) ── */
    /* Approve if HSM initialized and basic sanity checks pass */
    if (!req->pan[0] || !req->amount[0]) {
        SET_RC(ISO_RC_INVALID_FORMAT);
        return ISO_ERR_FIELD;
    }

    /* Generate a simple 6-char approval code from STAN */
    snprintf(auth_code, 7, "%06s", req->stan[0] ? req->stan : "000000");

    SET_RC(ISO_RC_APPROVED);
    return ISO_OK;
}
