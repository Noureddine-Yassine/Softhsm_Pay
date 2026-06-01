#ifndef PAYHSM_ISO8583_PARSER_H
#define PAYHSM_ISO8583_PARSER_H

#include "iso8583_types.h"

/*
 * Parse raw bytes into iso8583_msg_t.
 *
 * buf      : raw message bytes (after the 2-byte length prefix)
 * buf_len  : number of bytes in buf
 * msg      : output struct (zeroed by caller or this function)
 * has_tpdu : 1 = first 5 bytes are TPDU, 0 = no TPDU
 *
 * Returns ISO_OK or ISO_ERR_*.
 */
int iso8583_parse(const uint8_t *buf, int buf_len,
                  iso8583_msg_t *msg, int has_tpdu);

/* Convert 2 ASCII hex chars to one byte */
int iso8583_hex2byte(const char *hex, uint8_t *out);

/* Convert binary buffer to hex string (out must hold 2*len+1 bytes) */
void iso8583_bin2hex(const uint8_t *bin, int len, char *hex_out);

/* Decode hex string to binary (out must hold len/2 bytes) */
int iso8583_hex2bin(const char *hex, uint8_t *out, int out_len);

/* Check if bit n (1-128) is set in the bitmap */
int iso8583_bitmap_get(const uint8_t *bitmap, int n);

#endif /* PAYHSM_ISO8583_PARSER_H */
