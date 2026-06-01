#include "iso8583_parser.h"
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>

/* ── Field definition table ─────────────────────────────────── */
const iso8583_field_def_t g_iso_field_defs[ISO8583_MAX_DE + 1] = {
    [0]  = { FT_NONE,      0,   "Reserved" },
    [1]  = { FT_FIXED_BIN, 8,   "Secondary Bitmap" }, /* handled separately */
    [2]  = { FT_LLVAR,    19,   "PAN" },
    [3]  = { FT_FIXED,     6,   "Processing Code" },
    [4]  = { FT_FIXED,    12,   "Amount Transaction" },
    [5]  = { FT_FIXED,    12,   "Amount Settlement" },
    [6]  = { FT_FIXED,    12,   "Amount Cardholder Billing" },
    [7]  = { FT_FIXED,    10,   "Transmission Date/Time" },
    [8]  = { FT_FIXED,     8,   "Amount Cardholder Billing Fee" },
    [9]  = { FT_FIXED,     8,   "Conversion Rate Settlement" },
    [10] = { FT_FIXED,     8,   "Conversion Rate Cardholder Billing" },
    [11] = { FT_FIXED,     6,   "STAN" },
    [12] = { FT_FIXED,     6,   "Local Transaction Time" },
    [13] = { FT_FIXED,     4,   "Local Transaction Date" },
    [14] = { FT_FIXED,     4,   "Expiration Date" },
    [15] = { FT_FIXED,     4,   "Settlement Date" },
    [16] = { FT_FIXED,     4,   "Currency Conversion Date" },
    [17] = { FT_FIXED,     4,   "Capture Date" },
    [18] = { FT_FIXED,     4,   "Merchant Type" },
    [19] = { FT_FIXED,     3,   "Acquiring Institution Country Code" },
    [20] = { FT_FIXED,     3,   "PAN Extended Country Code" },
    [21] = { FT_FIXED,     3,   "Forwarding Institution Country Code" },
    [22] = { FT_FIXED,     3,   "POS Entry Mode" },
    [23] = { FT_FIXED,     3,   "Card Sequence Number" },
    [24] = { FT_FIXED,     3,   "Network International ID" },
    [25] = { FT_FIXED,     2,   "POS Condition Code" },
    [26] = { FT_FIXED,     2,   "POS PIN Capture Code" },
    [27] = { FT_FIXED,     1,   "Authorization ID Response Length" },
    [28] = { FT_FIXED,     9,   "Amount Transaction Fee" },
    [29] = { FT_FIXED,     9,   "Amount Settlement Fee" },
    [30] = { FT_FIXED,     9,   "Amount Transaction Processing Fee" },
    [31] = { FT_FIXED,     9,   "Amount Settlement Processing Fee" },
    [32] = { FT_LLVAR,    11,   "Acquiring Institution ID Code" },
    [33] = { FT_LLVAR,    11,   "Forwarding Institution ID Code" },
    [34] = { FT_LLVAR,    28,   "PAN Extended" },
    [35] = { FT_LLVAR,    37,   "Track 2 Data" },
    [36] = { FT_LLLVAR,  104,   "Track 3 Data" },
    [37] = { FT_FIXED,    12,   "Retrieval Reference Number" },
    [38] = { FT_FIXED,     6,   "Authorization ID Response" },
    [39] = { FT_FIXED,     2,   "Response Code" },
    [40] = { FT_FIXED,     3,   "Service Restriction Code" },
    [41] = { FT_FIXED,     8,   "Terminal ID" },
    [42] = { FT_FIXED,    15,   "Merchant ID" },
    [43] = { FT_FIXED,    40,   "Merchant Name/Location" },
    [44] = { FT_LLVAR,    99,   "Additional Response Data" },
    [45] = { FT_LLVAR,    76,   "Track 1 Data" },
    [46] = { FT_LLLVAR,  999,   "Additional Data ISO" },
    [47] = { FT_LLLVAR,  999,   "Additional Data National" },
    [48] = { FT_LLLVAR,  999,   "Additional Data Private" },
    [49] = { FT_FIXED,     3,   "Currency Code Transaction" },
    [50] = { FT_FIXED,     3,   "Currency Code Settlement" },
    [51] = { FT_FIXED,     3,   "Currency Code Cardholder Billing" },
    [52] = { FT_FIXED_BIN, 8,   "PIN Block" },
    [53] = { FT_FIXED,    16,   "Security Related Control Info" },
    [54] = { FT_LLLVAR,  120,   "Additional Amounts" },
    [55] = { FT_LLLVAR_BIN, 255,"ICC Data (EMV)" },
    [56] = { FT_LLLVAR,   35,   "Reserved ISO" },
    [57] = { FT_LLLVAR,  999,   "Reserved National" },
    [58] = { FT_LLLVAR,  999,   "Reserved National" },
    [59] = { FT_LLLVAR,  999,   "Reserved National" },
    [60] = { FT_LLLVAR,  999,   "Reserved Private" },
    [61] = { FT_LLLVAR,  999,   "Reserved Private" },
    [62] = { FT_LLLVAR,  999,   "Reserved Private" },
    [63] = { FT_LLLVAR,  999,   "Reserved Private" },
    [64] = { FT_FIXED_BIN, 8,   "MAC" },
    /* Secondary bitmap (65-128) */
    [65] = { FT_NONE,      0,   "Extended Bitmap Indicator" },
    [66] = { FT_FIXED,     1,   "Settlement Code" },
    [67] = { FT_FIXED,     2,   "Extended Payment Code" },
    [68] = { FT_FIXED,     3,   "Receiving Institution Country Code" },
    [69] = { FT_FIXED,     3,   "Settlement Institution Country Code" },
    [70] = { FT_FIXED,     3,   "Network Management Information Code" },
    [71] = { FT_FIXED,     4,   "Message Number" },
    [72] = { FT_FIXED,     4,   "Message Number Last" },
    [73] = { FT_FIXED,     6,   "Date Action" },
    [74] = { FT_FIXED,    10,   "Credits Number" },
    [75] = { FT_FIXED,    10,   "Credits Reversal Number" },
    [76] = { FT_FIXED,    10,   "Debits Number" },
    [77] = { FT_FIXED,    10,   "Debits Reversal Number" },
    [78] = { FT_FIXED,    10,   "Transfer Number" },
    [79] = { FT_FIXED,    10,   "Transfer Reversal Number" },
    [80] = { FT_FIXED,    10,   "Inquiries Number" },
    [81] = { FT_FIXED,    10,   "Authorizations Number" },
    [82] = { FT_FIXED,    12,   "Credits Processing Fee Amount" },
    [83] = { FT_FIXED,    12,   "Credits Transaction Fee Amount" },
    [84] = { FT_FIXED,    12,   "Debits Processing Fee Amount" },
    [85] = { FT_FIXED,    12,   "Debits Transaction Fee Amount" },
    [86] = { FT_FIXED,    16,   "Credits Amount" },
    [87] = { FT_FIXED,    16,   "Credits Reversal Amount" },
    [88] = { FT_FIXED,    16,   "Debits Amount" },
    [89] = { FT_FIXED,    16,   "Debits Reversal Amount" },
    [90] = { FT_FIXED,    42,   "Original Data Elements" },
    [91] = { FT_FIXED,     1,   "File Update Code" },
    [92] = { FT_FIXED,     2,   "File Security Code" },
    [93] = { FT_FIXED,     5,   "Response Indicator" },
    [94] = { FT_FIXED,     7,   "Service Indicator" },
    [95] = { FT_FIXED,    42,   "Replacement Amounts" },
    [96] = { FT_FIXED_BIN, 8,   "Message Security Code" },
    [97] = { FT_FIXED,    17,   "Amount Net Settlement" },
    [98] = { FT_FIXED,    25,   "Payee" },
    [99] = { FT_LLVAR,    11,   "Settlement Institution ID" },
    [100] = { FT_LLVAR,   11,   "Receiving Institution ID" },
    [101] = { FT_LLVAR,   17,   "File Name" },
    [102] = { FT_LLVAR,   28,   "Account ID 1" },
    [103] = { FT_LLVAR,   28,   "Account ID 2" },
    [104] = { FT_LLLVAR, 100,   "Transaction Description" },
    [105] = { FT_LLLVAR, 999,   "Reserved ISO" },
    [106] = { FT_LLLVAR, 999,   "Reserved ISO" },
    [107] = { FT_LLLVAR, 999,   "Reserved ISO" },
    [108] = { FT_LLLVAR, 999,   "Reserved ISO" },
    [109] = { FT_LLLVAR, 999,   "Reserved ISO" },
    [110] = { FT_LLLVAR, 999,   "Reserved ISO" },
    [111] = { FT_LLLVAR, 999,   "Reserved ISO" },
    [112] = { FT_LLLVAR, 999,   "Reserved Private" },
    [113] = { FT_LLLVAR, 999,   "Reserved Private" },
    [114] = { FT_LLLVAR, 999,   "Reserved Private" },
    [115] = { FT_LLLVAR, 999,   "Reserved Private" },
    [116] = { FT_LLLVAR, 999,   "Reserved Private" },
    [117] = { FT_LLLVAR, 999,   "Reserved Private" },
    [118] = { FT_LLLVAR, 999,   "Reserved Private" },
    [119] = { FT_LLLVAR, 999,   "Reserved Private" },
    [120] = { FT_LLLVAR, 999,   "Reserved Private" },
    [121] = { FT_LLLVAR, 999,   "Reserved Private" },
    [122] = { FT_LLLVAR, 999,   "Reserved Private" },
    [123] = { FT_LLLVAR, 999,   "Reserved Private" },
    [124] = { FT_LLLVAR, 999,   "Reserved Private" },
    [125] = { FT_LLLVAR, 999,   "Reserved Private" },
    [126] = { FT_LLLVAR, 999,   "Reserved Private" },
    [127] = { FT_LLLVAR, 999,   "Reserved Private" },
    [128] = { FT_FIXED_BIN, 8,  "MAC2" },
};

/* ── Helpers ─────────────────────────────────────────────────── */

int iso8583_bitmap_get(const uint8_t *bitmap, int n) {
    if (n < 1 || n > 128) return 0;
    int idx = (n - 1) / 8;
    int bit = 7 - ((n - 1) % 8);
    return (bitmap[idx] >> bit) & 1;
}

static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return -1;
}

int iso8583_hex2byte(const char *hex, uint8_t *out) {
    int hi = hex_digit(hex[0]);
    int lo = hex_digit(hex[1]);
    if (hi < 0 || lo < 0) return -1;
    *out = (uint8_t)((hi << 4) | lo);
    return 0;
}

void iso8583_bin2hex(const uint8_t *bin, int len, char *hex_out) {
    static const char *h = "0123456789abcdef";
    for (int i = 0; i < len; i++) {
        hex_out[i*2]     = h[(bin[i] >> 4) & 0xF];
        hex_out[i*2 + 1] = h[ bin[i]       & 0xF];
    }
    hex_out[len*2] = '\0';
}

int iso8583_hex2bin(const char *hex, uint8_t *out, int out_len) {
    int hex_len = (int)strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 > out_len) return -1;
    for (int i = 0; i < hex_len / 2; i++) {
        if (iso8583_hex2byte(hex + i * 2, &out[i]) != 0) return -1;
    }
    return hex_len / 2;
}

/* ── Parser ──────────────────────────────────────────────────── */

int iso8583_parse(const uint8_t *buf, int buf_len,
                  iso8583_msg_t *msg, int has_tpdu)
{
    if (!buf || !msg || buf_len < 4) return ISO_ERR_FORMAT;
    memset(msg, 0, sizeof(*msg));

    int pos = 0;

    /* TPDU (5 bytes) */
    if (has_tpdu) {
        if (buf_len < pos + ISO8583_TPDU_LEN) return ISO_ERR_FORMAT;
        memcpy(msg->tpdu, buf + pos, ISO8583_TPDU_LEN);
        msg->has_tpdu = 1;
        pos += ISO8583_TPDU_LEN;
    }

    /* MTI (4 ASCII bytes) */
    if (buf_len < pos + 4) return ISO_ERR_FORMAT;
    memcpy(msg->mti, buf + pos, 4);
    msg->mti[4] = '\0';
    pos += 4;

    /* Primary bitmap (8 bytes) */
    if (buf_len < pos + 8) return ISO_ERR_FORMAT;
    memcpy(msg->bitmap, buf + pos, 8);
    msg->bitmap_len = 8;
    pos += 8;

    /* Secondary bitmap if bit 1 set */
    if (iso8583_bitmap_get(msg->bitmap, 1)) {
        if (buf_len < pos + 8) return ISO_ERR_FORMAT;
        memcpy(msg->bitmap + 8, buf + pos, 8);
        msg->bitmap_len = 16;
        pos += 8;
    }

    /* Data elements (DE2 to DE128) */
    for (int de = 2; de <= ISO8583_MAX_DE; de++) {
        if (!iso8583_bitmap_get(msg->bitmap, de)) continue;
        if (de == 65) continue;   /* secondary bitmap already consumed */

        const iso8583_field_def_t *def = &g_iso_field_defs[de];
        iso8583_field_t *f = &msg->fields[de];

        if (def->type == FT_NONE) {
            /* Unknown field — skip gracefully (can't know length) */
            return ISO_ERR_FIELD;
        }

        int prefix_digits = 0;
        int is_binary = 0;
        int fixed_len = 0;

        switch (def->type) {
            case FT_FIXED:
                fixed_len = def->max_len;
                break;
            case FT_FIXED_BIN:
                fixed_len = def->max_len;
                is_binary = 1;
                break;
            case FT_LLVAR:
                prefix_digits = 2;
                break;
            case FT_LLLVAR:
                prefix_digits = 3;
                break;
            case FT_LLVAR_BIN:
                prefix_digits = 2;
                is_binary = 1;
                break;
            case FT_LLLVAR_BIN:
                prefix_digits = 3;
                is_binary = 1;
                break;
            default:
                return ISO_ERR_FIELD;
        }

        int data_len = fixed_len;

        /* Read variable length prefix */
        if (prefix_digits > 0) {
            if (buf_len < pos + prefix_digits) return ISO_ERR_FORMAT;
            char nbuf[4] = {0};
            memcpy(nbuf, buf + pos, prefix_digits);
            /* Validate digits */
            for (int k = 0; k < prefix_digits; k++) {
                if (!isdigit((unsigned char)nbuf[k])) return ISO_ERR_FORMAT;
            }
            data_len = atoi(nbuf);
            if (data_len > def->max_len) return ISO_ERR_FIELD;
            pos += prefix_digits;
        }

        if (data_len < 0 || buf_len < pos + data_len) return ISO_ERR_FORMAT;
        if (data_len > ISO8583_FIELD_MAX - 1) return ISO_ERR_FIELD;

        memcpy(f->data, buf + pos, data_len);
        f->len     = data_len;
        f->present = 1;

        /* Null-terminate ASCII fields for convenience */
        if (!is_binary) f->data[data_len] = '\0';

        pos += data_len;
        (void)is_binary; /* suppress unused warning */
    }

    return ISO_OK;
}
