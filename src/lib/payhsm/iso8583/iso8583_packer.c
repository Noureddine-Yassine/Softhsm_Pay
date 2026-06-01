#include "iso8583_packer.h"
#include "iso8583_parser.h"
#include <string.h>
#include <stdio.h>

/* ── helpers ─────────────────────────────────────────────────── */

static void bitmap_set(uint8_t *bitmap, int n)
{
    if (n < 1 || n > 128) return;
    int byte = (n - 1) / 8;
    int bit  = 7 - ((n - 1) % 8);
    bitmap[byte] |= (1u << bit);
}

/* ── field setters ───────────────────────────────────────────── */

int iso8583_set_field(iso8583_msg_t *msg, int de,
                      const char *value, int len)
{
    if (de < 1 || de > ISO8583_MAX_DE) return ISO_ERR_FIELD;
    const iso8583_field_def_t *def = &g_iso_field_defs[de];
    if (def->type == FT_NONE || def->type == FT_FIXED_BIN ||
        def->type == FT_LLVAR_BIN || def->type == FT_LLLVAR_BIN)
        return ISO_ERR_FIELD;

    int copy = len > def->max_len ? def->max_len : len;
    if (copy >= ISO8583_FIELD_MAX) copy = ISO8583_FIELD_MAX - 1;

    iso8583_field_t *f = &msg->fields[de];
    memcpy(f->data, value, copy);
    f->data[copy] = 0;
    f->len     = copy;
    f->present = 1;

    /* keep secondary bitmap flag */
    if (de > 64) bitmap_set(msg->bitmap, 1);
    bitmap_set(msg->bitmap, de);
    if (de > 64) msg->bitmap_len = 16;
    else if (msg->bitmap_len < 8) msg->bitmap_len = 8;

    return ISO_OK;
}

int iso8583_set_field_bin(iso8583_msg_t *msg, int de,
                          const uint8_t *data, int len)
{
    if (de < 1 || de > ISO8583_MAX_DE) return ISO_ERR_FIELD;
    const iso8583_field_def_t *def = &g_iso_field_defs[de];
    if (def->type != FT_FIXED_BIN && def->type != FT_LLVAR_BIN &&
        def->type != FT_LLLVAR_BIN)
        return ISO_ERR_FIELD;

    int copy = len > def->max_len ? def->max_len : len;
    if (copy >= ISO8583_FIELD_MAX) copy = ISO8583_FIELD_MAX - 1;

    iso8583_field_t *f = &msg->fields[de];
    memcpy(f->data, data, copy);
    f->len     = copy;
    f->present = 1;

    if (de > 64) { bitmap_set(msg->bitmap, 1); msg->bitmap_len = 16; }
    else if (msg->bitmap_len < 8) msg->bitmap_len = 8;
    bitmap_set(msg->bitmap, de);

    return ISO_OK;
}

/* ── pack ────────────────────────────────────────────────────── */

int iso8583_pack(const iso8583_msg_t *msg, uint8_t *out, int out_max)
{
    int pos = 0;

#define NEED(n) do { if (pos + (n) > out_max) return ISO_ERR_FORMAT; } while(0)

    /* TPDU (5 bytes) */
    if (msg->has_tpdu) {
        NEED(ISO8583_TPDU_LEN);
        memcpy(out + pos, msg->tpdu, ISO8583_TPDU_LEN);
        pos += ISO8583_TPDU_LEN;
    }

    /* MTI (4 ASCII bytes) */
    NEED(ISO8583_MTI_LEN);
    memcpy(out + pos, msg->mti, ISO8583_MTI_LEN);
    pos += ISO8583_MTI_LEN;

    /* Bitmap (8 or 16 bytes) */
    int blen = msg->bitmap_len > 0 ? msg->bitmap_len : 8;
    NEED(blen);
    memcpy(out + pos, msg->bitmap, blen);
    pos += blen;

    /* Data elements DE1..DE128 */
    for (int de = 1; de <= ISO8583_MAX_DE; de++) {
        if (!iso8583_bitmap_get(msg->bitmap, de)) continue;
        if (de == 1) continue; /* bitmap itself, not a real field */

        const iso8583_field_t    *f   = &msg->fields[de];
        const iso8583_field_def_t *def = &g_iso_field_defs[de];

        if (!f->present || def->type == FT_NONE) continue;

        switch (def->type) {
        case FT_FIXED:
            NEED(def->max_len);
            /* right-pad with spaces if shorter */
            memset(out + pos, ' ', def->max_len);
            memcpy(out + pos, f->data, f->len < def->max_len ? f->len : def->max_len);
            pos += def->max_len;
            break;

        case FT_FIXED_BIN:
            NEED(def->max_len);
            memset(out + pos, 0, def->max_len);
            memcpy(out + pos, f->data, f->len < def->max_len ? f->len : def->max_len);
            pos += def->max_len;
            break;

        case FT_LLVAR:
            NEED(2 + f->len);
            out[pos++] = '0' + (f->len / 10);
            out[pos++] = '0' + (f->len % 10);
            memcpy(out + pos, f->data, f->len);
            pos += f->len;
            break;

        case FT_LLLVAR:
            NEED(3 + f->len);
            out[pos++] = '0' + (f->len / 100);
            out[pos++] = '0' + ((f->len / 10) % 10);
            out[pos++] = '0' + (f->len % 10);
            memcpy(out + pos, f->data, f->len);
            pos += f->len;
            break;

        case FT_LLVAR_BIN:
            NEED(2 + f->len);
            out[pos++] = '0' + (f->len / 10);
            out[pos++] = '0' + (f->len % 10);
            memcpy(out + pos, f->data, f->len);
            pos += f->len;
            break;

        case FT_LLLVAR_BIN:
            NEED(3 + f->len);
            out[pos++] = '0' + (f->len / 100);
            out[pos++] = '0' + ((f->len / 10) % 10);
            out[pos++] = '0' + (f->len % 10);
            memcpy(out + pos, f->data, f->len);
            pos += f->len;
            break;

        default:
            break;
        }
    }

#undef NEED
    return pos;
}

/* ── MTI flip (request → response) ──────────────────────────── */

static void flip_mti(const char *req_mti, char *resp_mti)
{
    memcpy(resp_mti, req_mti, 5); /* copy including NUL */
    /* digit[2]: 0→1 (request→response), 1→0 already a response */
    if (resp_mti[2] == '0') resp_mti[2] = '1';
}

/* ── echo fields copied from request ────────────────────────── */

static const int ECHO_DES[] = { 2, 3, 4, 7, 11, 12, 13, 37, 41, 42, 49, 0 };

int iso8583_build_response(const iso8583_msg_t *req,
                           iso8583_msg_t       *resp,
                           const char          *rc_str,
                           const uint8_t       *mac,
                           const uint8_t       *auth_code,
                           const uint8_t       *emv_resp,
                           int                  emv_resp_len)
{
    memset(resp, 0, sizeof(*resp));

    /* TPDU echo */
    if (req->has_tpdu) {
        memcpy(resp->tpdu, req->tpdu, ISO8583_TPDU_LEN);
        resp->has_tpdu = 1;
    }

    /* MTI */
    flip_mti(req->mti, resp->mti);

    resp->bitmap_len = 8;

    /* Echo requested fields */
    for (int i = 0; ECHO_DES[i]; i++) {
        int de = ECHO_DES[i];
        const iso8583_field_t    *src = &req->fields[de];
        const iso8583_field_def_t *def = &g_iso_field_defs[de];
        if (!src->present) continue;
        if (def->type == FT_FIXED_BIN || def->type == FT_LLVAR_BIN ||
            def->type == FT_LLLVAR_BIN)
            iso8583_set_field_bin(resp, de, src->data, src->len);
        else
            iso8583_set_field(resp, de, (const char *)src->data, src->len);
    }

    /* DE39 response code */
    if (rc_str)
        iso8583_set_field(resp, 39, rc_str, (int)strlen(rc_str));

    /* DE38 auth code (6 ASCII chars) */
    if (auth_code)
        iso8583_set_field(resp, 38, (const char *)auth_code, 6);

    /* DE55 EMV response */
    if (emv_resp && emv_resp_len > 0)
        iso8583_set_field_bin(resp, 55, emv_resp, emv_resp_len);

    /* DE64 MAC */
    if (mac)
        iso8583_set_field_bin(resp, 64, mac, 8);

    return ISO_OK;
}
