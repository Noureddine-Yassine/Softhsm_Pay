#ifndef PAYHSM_ISO8583_TYPES_H
#define PAYHSM_ISO8583_TYPES_H

#include <stdint.h>
#include <stddef.h>

/* ── MTI ── */
#define ISO_MTI_AUTH_REQ       "0100"
#define ISO_MTI_AUTH_RESP      "0110"
#define ISO_MTI_FINANCIAL_REQ  "0200"
#define ISO_MTI_FINANCIAL_RESP "0210"
#define ISO_MTI_REVERSAL_REQ   "0400"
#define ISO_MTI_REVERSAL_RESP  "0410"
#define ISO_MTI_NETMGMT_REQ    "0800"
#define ISO_MTI_NETMGMT_RESP   "0810"

/* ── Response codes DE39 ── */
#define ISO_RC_APPROVED        "00"
#define ISO_RC_DECLINED        "05"
#define ISO_RC_INVALID_FORMAT  "30"
#define ISO_RC_PIN_INCORRECT   "55"
#define ISO_RC_MAC_ERROR       "56"
#define ISO_RC_NOT_INIT        "91"
#define ISO_RC_SYSTEM_ERROR    "96"

/* ── Field types ── */
typedef enum {
    FT_NONE = 0,
    FT_FIXED,       /* fixed length, ASCII/numeric */
    FT_FIXED_BIN,   /* fixed length, binary */
    FT_LLVAR,       /* 2-digit ASCII length prefix + ASCII data */
    FT_LLLVAR,      /* 3-digit ASCII length prefix + ASCII data */
    FT_LLVAR_BIN,   /* 2-digit ASCII length prefix + binary data */
    FT_LLLVAR_BIN,  /* 3-digit ASCII length prefix + binary data */
} iso8583_ft_t;

typedef struct {
    iso8583_ft_t type;
    int          max_len;   /* bytes of data (not prefix) */
    const char  *name;
} iso8583_field_def_t;

#define ISO8583_MAX_DE    128
#define ISO8583_FIELD_MAX 512   /* max bytes per field */
#define ISO8583_MSG_MAX  4096   /* max raw message */
#define ISO8583_MTI_LEN     4
#define ISO8583_TPDU_LEN    5

typedef struct {
    uint8_t data[ISO8583_FIELD_MAX];
    int     len;
    int     present;
} iso8583_field_t;

typedef struct {
    char            mti[5];                         /* e.g. "0200" */
    uint8_t         bitmap[16];
    int             bitmap_len;                     /* 8 or 16 */
    iso8583_field_t fields[ISO8583_MAX_DE + 1];    /* 1-indexed */
    uint8_t         tpdu[ISO8583_TPDU_LEN];
    int             has_tpdu;
} iso8583_msg_t;

/* ── Internal HSM command (result of mapper) ── */
typedef enum {
    HSM_CMD_NONE = 0,
    HSM_CMD_FINANCIAL,      /* 0200 standard authorization */
    HSM_CMD_PIN_VERIFY,     /* DE52 present */
    HSM_CMD_PIN_TRANSLATE,  /* DE52 TPK→ZPK */
    HSM_CMD_MAC_VERIFY,     /* DE64 present */
    HSM_CMD_EMV_ARQC,       /* DE55 present */
    HSM_CMD_NETMGMT,        /* 0800 echo/sign-on */
    HSM_CMD_REVERSAL,       /* 0400 */
} iso8583_hsm_cmd_t;

typedef struct {
    iso8583_hsm_cmd_t type;
    char   terminal_id[9];      /* DE41 */
    char   merchant_id[16];     /* DE42 */
    char   pan[20];             /* DE2 */
    char   processing_code[7];  /* DE3 */
    char   amount[13];          /* DE4 */
    char   stan[7];             /* DE11 */
    char   currency[4];         /* DE49 */
    uint8_t pin_block[8];       /* DE52 */
    int     has_pin_block;
    uint8_t mac_in[8];          /* DE64 received */
    int     has_mac;
    uint8_t emv_data[512];      /* DE55 */
    int     emv_data_len;
    char    retrieval_ref[13];  /* DE37 */
    char    auth_code[7];       /* DE38 */
} iso8583_hsm_req_t;

/* ── Parser / Packer return codes ── */
#define ISO_OK           0
#define ISO_ERR_FORMAT  -1
#define ISO_ERR_FIELD   -2
#define ISO_ERR_CRYPTO  -3
#define ISO_ERR_NOINIT  -4

extern const iso8583_field_def_t g_iso_field_defs[ISO8583_MAX_DE + 1];

#endif /* PAYHSM_ISO8583_TYPES_H */
