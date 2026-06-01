#ifndef PAYHSM_ISO8583_PACKER_H
#define PAYHSM_ISO8583_PACKER_H

#include "iso8583_types.h"

/*
 * Set a fixed ASCII field (pads/truncates to def max_len if needed).
 */
int iso8583_set_field(iso8583_msg_t *msg, int de,
                      const char *value, int len);

/*
 * Set a binary field.
 */
int iso8583_set_field_bin(iso8583_msg_t *msg, int de,
                          const uint8_t *data, int len);

/*
 * Pack iso8583_msg_t into a raw byte buffer (without the 2-byte length prefix).
 * out     : destination buffer
 * out_max : size of destination buffer
 * Returns number of bytes written, or < 0 on error.
 */
int iso8583_pack(const iso8583_msg_t *msg, uint8_t *out, int out_max);

/*
 * Build a response message from a request:
 *   - flips MTI (e.g. 0200 → 0210, 0100 → 0110)
 *   - copies TPDU, bitmap, echo fields (DE2/3/4/7/11/12/13/37/41/42/49)
 *   - sets DE39 to rc_str ("00", "05", …)
 *   - if mac is non-NULL, sets DE64
 * Returns ISO_OK or error.
 */
int iso8583_build_response(const iso8583_msg_t *req,
                           iso8583_msg_t       *resp,
                           const char          *rc_str,
                           const uint8_t       *mac,    /* 8 bytes, or NULL */
                           const uint8_t       *auth_code, /* 6 bytes ASCII, or NULL */
                           const uint8_t       *emv_resp,  /* DE55 response data, or NULL */
                           int                  emv_resp_len);

#endif /* PAYHSM_ISO8583_PACKER_H */
