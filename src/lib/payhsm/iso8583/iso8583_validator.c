#include "iso8583_validator.h"
#include "iso8583_parser.h"
#include <string.h>

/* ── Supported request MTIs ──────────────────────────────────── */

static const char *SUPPORTED_MTIS[] = {
    ISO_MTI_AUTH_REQ,       /* 0100 */
    ISO_MTI_FINANCIAL_REQ,  /* 0200 */
    ISO_MTI_REVERSAL_REQ,   /* 0400 */
    ISO_MTI_NETMGMT_REQ,    /* 0800 */
    NULL
};

int iso8583_mti_is_request(const char *mti)
{
    for (int i = 0; SUPPORTED_MTIS[i]; i++)
        if (strncmp(mti, SUPPORTED_MTIS[i], 4) == 0) return 1;
    return 0;
}

/* ── Mandatory DEs per MTI ───────────────────────────────────── */

/* DEs required for financial / auth requests */
static const int MANDATORY_FINANCIAL[] = { 3, 4, 11, 41, 0 };

/* DEs required for reversal */
static const int MANDATORY_REVERSAL[] = { 3, 4, 11, 37, 41, 0 };

/* 0800 network management only needs DE11, DE70 */
static const int MANDATORY_NETMGMT[] = { 11, 0 };

static const int *mandatory_for_mti(const char *mti)
{
    if (strncmp(mti, ISO_MTI_REVERSAL_REQ, 4) == 0)
        return MANDATORY_REVERSAL;
    if (strncmp(mti, ISO_MTI_NETMGMT_REQ, 4) == 0)
        return MANDATORY_NETMGMT;
    return MANDATORY_FINANCIAL; /* 0100, 0200 */
}

/* ── Main validator ──────────────────────────────────────────── */

int iso8583_validate(const iso8583_msg_t *msg, int *err_de)
{
    if (err_de) *err_de = 0;

    /* MTI */
    if (!iso8583_mti_is_request(msg->mti)) {
        return ISO_ERR_FORMAT;
    }

    /* Mandatory DE presence */
    const int *mandatory = mandatory_for_mti(msg->mti);
    for (int i = 0; mandatory[i]; i++) {
        int de = mandatory[i];
        if (!msg->fields[de].present) {
            if (err_de) *err_de = de;
            return ISO_ERR_FIELD;
        }
    }

    /* Per-field length check */
    for (int de = 1; de <= ISO8583_MAX_DE; de++) {
        const iso8583_field_t    *f   = &msg->fields[de];
        const iso8583_field_def_t *def = &g_iso_field_defs[de];
        if (!f->present) continue;
        if (f->len < 0 || f->len > def->max_len) {
            if (err_de) *err_de = de;
            return ISO_ERR_FIELD;
        }
    }

    return ISO_OK;
}
