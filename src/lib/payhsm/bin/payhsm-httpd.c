/* Passerelle HTTP → libpayhsm (crypto C réel) + fichiers statiques frontend */
#include "../payhsm_core.h"
#include "../payhsm_switch.h"
#include "../key_relation_validator.h"
#include "../payhsm.h"
#include "../payment/pin.h"          /* translate_pin_block — commandes CA/CB, CC/CD */
#include "../keymanager/integrity.h"
#include "../keymanager/xor_fragment.h"
#include "../keymanager/shamir.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/cmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>     /* serveur TCP brut HSM optionnel en TLS */
#include <time.h>
#include <signal.h>
#include <pthread.h>         /* serveur TCP brut HSM (thread séparé) + mutex dispatch */

#define HTTP_BUF   65536
#define AUDIT_MAX  128

/* Définies dans payhsm-admin.c (inclus plus bas) */
void payhsm_admin_reset_on_new_provision(const char *data_dir);
void payhsm_admin_reload_after_startup(void);
#define LMK_IV_LEN       12
#define LMK_TAG_LEN      16
#define LMK_KEY_LEN      16                              /* AES-128 (défaut / compatibilité) */
#define LMK_BLOB_LEN     (LMK_IV_LEN + LMK_TAG_LEN + LMK_KEY_LEN)  /* 44 octets = 88 hex */
#define LMK_BLOB_OVERHEAD (LMK_IV_LEN + LMK_TAG_LEN)   /* 28 octets (IV + TAG) */
#define LMK_MAX_KEY_LEN  32                              /* AES-256 */
#define LMK_MAX_BLOB_LEN (LMK_BLOB_OVERHEAD + LMK_MAX_KEY_LEN) /* 60 octets = 120 hex */

static int lmk_gcm_encrypt(const uint8_t lmk[32],
                           const uint8_t pt[LMK_KEY_LEN],
                           uint8_t blob[LMK_BLOB_LEN]);
static int lmk_gcm_decrypt(const uint8_t lmk[32],
                           const uint8_t blob[LMK_BLOB_LEN],
                           uint8_t pt_out[LMK_KEY_LEN]);
/* Racine fichiers statiques (console HSM) — passer en 2e argument ou lancer depuis la racine du dépôt */
#define STATIC_ROOT_DEFAULT "frontend"

static char   g_static_root[512] = STATIC_ROOT_DEFAULT;
/* Variables partagées avec payhsm-cmds.c */
static time_t g_start_time  = 0;
static int    g_server_port = 8765;

/* Sérialise tout le traitement de commandes (HTTP /api/* + TCP brut) pour
   protéger l'état global du HSM (coffre, fragments LMK) d'accès concurrents. */
static pthread_mutex_t g_dispatch_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    time_t ts;
    char   msg[240];
} audit_entry_t;

static audit_entry_t g_audit[AUDIT_MAX];
static int           g_audit_count = 0;

static void audit_log(const char *msg) {
    int idx;
    if (!msg) return;
    if (g_audit_count < AUDIT_MAX)
        idx = g_audit_count++;
    else {
        memmove(g_audit, g_audit + 1, (size_t)(AUDIT_MAX - 1) * sizeof(audit_entry_t));
        idx = AUDIT_MAX - 1;
    }
    g_audit[idx].ts = time(NULL);
    strncpy(g_audit[idx].msg, msg, sizeof(g_audit[idx].msg) - 1);
    g_audit[idx].msg[sizeof(g_audit[idx].msg) - 1] = '\0';
}

static void audit_mask_pan(const char *pan, char out[20]) {
    if (!out) return;
    out[0] = '\0';
    if (!pan || !pan[0]) {
        strcpy(out, "—");
        return;
    }
    size_t len = strlen(pan);
    if (len <= 4)
        snprintf(out, 20, "****%s", pan);
    else
        snprintf(out, 20, "****%s", pan + len - 4);
}

/* Journal : operation passee par le HSM (PAN masque, pas de secrets) */
static void audit_log_pan(const char *op, const char *pan, const char *detail) {
    char line[240];
    char masked[20];
    audit_mask_pan(pan, masked);
    if (detail && detail[0])
        snprintf(line, sizeof(line), "%s — PAN %s — %s", op, masked, detail);
    else if (pan && pan[0])
        snprintf(line, sizeof(line), "%s — PAN %s", op, masked);
    else
        snprintf(line, sizeof(line), "%s", op);
    audit_log(line);
}

static void json_escape(const char *s, char *out, size_t n) {
    size_t j = 0;
    for (size_t i = 0; s[i] && j + 2 < n; i++) {
        if (s[i] == '"' || s[i] == '\\' || s[i] == '\n' || s[i] == '\r') {
            out[j++] = '\\';
            if (j >= n - 1) break;
        }
        out[j++] = s[i];
    }
    out[j] = '\0';
}

static int json_field(const char *body, const char *key, char *out, size_t n) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(body, pat);
    if (!p) return -1;
    p = strchr(p, ':');
    if (!p) return -1;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '"') {
        p++;
        size_t i = 0;
        while (*p && *p != '"' && i + 1 < n) out[i++] = *p++;
        out[i] = '\0';
        return 0;
    }
    size_t i = 0;
    while (*p && *p != ',' && *p != '}' && i + 1 < n) out[i++] = *p++;
    out[i] = '\0';
    return 0;
}

static void hex_encode(const uint8_t *in, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) sprintf(out + i * 2, "%02X", in[i]);
    out[len * 2] = '\0';
}

static int hex_decode(const char *hex, uint8_t *out, size_t nbytes) {
    if (strlen(hex) != nbytes * 2) return -1;
    for (size_t i = 0; i < nbytes; i++) {
        unsigned int b;
        if (sscanf(hex + i * 2, "%2x", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    return 0;
}

static const char *key_type_name(payhsm_key_type_t t) {
    switch (t) {
    case PAYHSM_KEY_TMK: return "TMK";
    case PAYHSM_KEY_TPK: return "TPK";
    case PAYHSM_KEY_TAK: return "TAK";
    case PAYHSM_KEY_ZMK: return "ZMK";
    case PAYHSM_KEY_ZPK: return "ZPK";
    case PAYHSM_KEY_PVK: return "PVK";
    case PAYHSM_KEY_IMK: return "IMK";
    default: return "?";
    }
}

static void http_reply(int fd, int code, const char *ctype, const char *body) {
    const char *msg = (code == 200) ? "OK" : (code == 400) ? "Bad Request" : "Not Found";
    char hdr[512];
    int blen = body ? (int)strlen(body) : 0;
    snprintf(hdr, sizeof(hdr),
             "HTTP/1.1 %d %s\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %d\r\n"
             "Access-Control-Allow-Origin: *\r\n"
             "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
             "Access-Control-Allow-Headers: Content-Type\r\n"
             "Connection: close\r\n\r\n",
             code, msg, ctype, blen);
    send(fd, hdr, strlen(hdr), 0);
    if (body && blen > 0) send(fd, body, (size_t)blen, 0);
}

static void send_json(int fd, int code, const char *json) {
    http_reply(fd, code, "application/json; charset=utf-8", json);
}

static int body_length(const char *hdr) {
    const char *p = strstr(hdr, "Content-Length:");
    if (!p) p = strstr(hdr, "content-length:");
    if (!p) return 0;
    return atoi(p + 15);
}

/*
 * Lit une requête HTTP complète : en-têtes PUIS corps entier.
 *
 * L'ancienne version s'arrêtait dès "\r\n\r\n" et renvoyait souvent un corps
 * vide quand le client (Python requests, Postman, navigateur) envoie le corps
 * dans un paquet TCP séparé. On lit maintenant en deux temps :
 *   1. jusqu'à la fin des en-têtes "\r\n\r\n" ;
 *   2. exactement Content-Length octets de corps, en gérant le cas où une
 *      partie du corps est déjà dans le buffer et les corps fragmentés.
 *
 * Retourne le nombre total d'octets lus (en-têtes + corps), borné par `cap`.
 */
static int read_request(int fd, char *buf, size_t cap) {
    size_t n = 0;
    char  *hdr_end = NULL;

    /* 1. Lire jusqu'à la fin du bloc d'en-têtes. */
    while (n + 1 < cap) {
        ssize_t r = recv(fd, buf + n, cap - n - 1, 0);
        if (r <= 0) break;
        n += (size_t)r;
        buf[n] = '\0';
        hdr_end = strstr(buf, "\r\n\r\n");
        if (hdr_end) break;
    }
    if (!hdr_end) return (int)n;   /* pas d'en-têtes complets : renvoyer ce qu'on a */

    /* 2. Calculer combien d'octets de corps sont attendus. */
    int clen = body_length(buf);
    if (clen <= 0) return (int)n;  /* pas de corps (GET, ou Content-Length absent/0) */

    size_t header_len = (size_t)(hdr_end - buf) + 4;   /* inclut le "\r\n\r\n" */
    size_t want_total = header_len + (size_t)clen;
    if (want_total >= cap) want_total = cap - 1;        /* anti-dépassement de buffer */

    /* 3. Lire le reste du corps (peut arriver fragmenté). */
    while (n < want_total) {
        ssize_t r = recv(fd, buf + n, want_total - n, 0);
        if (r <= 0) break;          /* déconnexion ou erreur : renvoyer ce qu'on a */
        n += (size_t)r;
        buf[n] = '\0';
    }
    return (int)n;
}

static const char *request_body(char *req) {
    char *p = strstr(req, "\r\n\r\n");
    return p ? p + 4 : "";
}

static void api_health(char *out, size_t n) {
    snprintf(out, n,
             "{\"ok\":true,\"initialized\":%d,\"bootId\":%lu,\"apiVersion\":\"1.2\","
             "\"role\":\"hsm-crypto-gateway\","
             "\"features\":[\"corebanking\",\"gap\",\"verify\",\"translate\",\"emv\",\"mac\",\"vault-export\"]}",
             payhsm_ctx()->initialized ? 1 : 0,
             payhsm_get_boot_id());
}

static void api_lmk_status(char *out, size_t n) {
    payhsm_lmk_status_t st;
    if (payhsm_get_lmk_status(&st) != 0) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"statut indisponible\"}");
        return;
    }
    char ref[9];
    integrity_ref_prefix(ref);
    snprintf(out, n,
             "{\"rc\":0,\"fragmented\":%d,\"integrityOk\":%d,"
             "\"mutationCount\":%d,\"mutationLastTs\":%ld,"
             "\"hmacRefPrefix\":\"%s\",\"dataDir\":\"%s\"}",
             st.fragmented, st.integrity_ok, st.mutation_count,
             st.mutation_last_ts, ref, st.data_dir);
}

static void api_lmk_fragments(char *out, size_t n) {
    payhsm_lmk_status_t st;
    payhsm_get_lmk_status(&st);
    char lmk_ref[9], fp1[9], fp2[9], fp3[9];
    integrity_ref_prefix(lmk_ref);
    fragment_fingerprint_prefix(1, fp1);
    fragment_fingerprint_prefix(2, fp2);
    fragment_fingerprint_prefix(3, fp3);
    snprintf(out, n,
             "{\"rc\":0,\"lmkRefPrefix\":\"%s\",\"integrityOk\":%d,"
             "\"mutationCount\":%d,\"mutationLastTs\":%ld,"
             "\"xorModel\":\"P1 xor P2 xor P3 = LMK\","
             "\"hint\":\"Ref LMK stable; empreintes P1/P2/P3 changent apres chaque operation crypto (mutation)\","
             "\"fragments\":["
             "{\"id\":\"P1\",\"zone\":\"stack\",\"loaded\":%d,\"fingerprint\":\"%s\"},"
             "{\"id\":\"P2\",\"zone\":\"heap\",\"loaded\":%d,\"fingerprint\":\"%s\"},"
             "{\"id\":\"P3\",\"zone\":\".data\",\"loaded\":%d,\"fingerprint\":\"%s\"}"
             "]}",
             lmk_ref, st.integrity_ok,
             st.mutation_count, (long)st.mutation_last_ts,
             st.fragmented, fp1, st.fragmented, fp2, st.fragmented, fp3);
}

static void api_security_logs(char *out, size_t n) {
    int pos = snprintf(out, n, "{\"rc\":0,\"logs\":[");
    for (int j = 0; j < g_audit_count && pos < (int)n - 200; j++) {
        char esc[200];
        json_escape(g_audit[j].msg, esc, sizeof(esc));
        pos += snprintf(out + pos, n - (size_t)pos,
                        "%s{\"ts\":%ld,\"message\":\"%s\"}",
                        j ? "," : "", (long)g_audit[j].ts, esc);
    }
    snprintf(out + pos, n - (size_t)pos, "]}");
}

static void api_vault_export(char *out, size_t n) {
    if (!payhsm_ctx()->initialized) {
        snprintf(out, n, "{\"rc\":%d,\"keys\":[]}", PAYHSM_RC_NOT_INIT);
        return;
    }
    uint8_t lmk[32];
    if (check_integrity() != 0 || recompose_for_op(lmk) != 0) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"LMK indisponible\"}");
        return;
    }
    int pos = snprintf(out, n, "{\"rc\":0,\"format\":\"IV(12)+TAG(16)+CT(16)\",\"keys\":[");
    payhsm_ctx_t *c = payhsm_ctx();
    for (int i = 0; i < c->vault.count && pos < (int)n - 256; i++) {
        const payhsm_key_entry_t *e = &c->vault.keys[i];
        uint8_t clear[LMK_KEY_LEN];
        if (vault_decrypt_under_lmk(lmk, e->enc, clear) != 0) continue;
        uint8_t blob[LMK_BLOB_LEN];
        if (lmk_gcm_encrypt(lmk, clear, blob) != 0) {
            secure_zero(clear, sizeof(clear));
            continue;
        }
        secure_zero(clear, sizeof(clear));
        char blobhex[LMK_BLOB_LEN * 2 + 1];
        char kcv[8];
        hex_encode(blob, LMK_BLOB_LEN, blobhex);
        snprintf(kcv, sizeof(kcv), "%02X%02X%02X",
                 e->kcv[0], e->kcv[1], e->kcv[2]);
        pos += snprintf(out + pos, n - (size_t)pos,
                        "%s{\"keyId\":\"%s\",\"keyType\":\"%s\",\"terminal\":\"%s\","
                        "\"cryptogram\":\"%s\",\"kcv\":\"%s\"}",
                        i ? "," : "", e->id, key_type_name(e->type),
                        e->terminal_id, blobhex, kcv);
    }
    secure_zero(lmk, sizeof(lmk));
    snprintf(out + pos, n - (size_t)pos, "]}");
    audit_log("vault export (GCM blobs pour Switch)");
}

static void api_status(char *out, size_t n) {
    payhsm_ctx_t *c = payhsm_ctx();
    int integrity = c->initialized ? verify_integrity_quiet() : -1;
    int pos = snprintf(out, n,
        "{\"initialized\":%d,\"integrity\":%d,\"keyCount\":%d,\"keys\":[",
        c->initialized, integrity == 0 ? 1 : 0, c->vault.count);
    for (int i = 0; i < c->vault.count && (size_t)pos < n - 128; i++) {
        const payhsm_key_entry_t *e = &c->vault.keys[i];
        char esc[64];
        json_escape(e->id, esc, sizeof(esc));
        pos += snprintf(out + pos, n - (size_t)pos,
            "%s{\"id\":\"%s\",\"type\":\"%s\",\"terminal\":\"%s\","
            "\"kcv\":\"%02X%02X%02X\",\"active\":%d}",
            i ? "," : "", esc, key_type_name(e->type), e->terminal_id,
            e->kcv[0], e->kcv[1], e->kcv[2], e->active);
    }
    snprintf(out + pos, n - (size_t)pos, "],\"lmk\":{\"fragmented\":%d}}",
             c->initialized ? 1 : 0);
}

static void read_passphrase_json(const char *body, char *pass, size_t n) {
    json_field(body, "password", pass, n);
    if (pass[0] == '\0') json_field(body, "passphrase", pass, n);
}

static void api_provision(const char *body, char *out, size_t n);

static void api_keys_derive_terminal(const char *body, char *out, size_t n) {
    char tmk_gcm[96], term[64], tpk[36], tak[36], kcv_tpk[8], kcv_tak[8];
    json_field(body, "tmkCryptogram", tmk_gcm, sizeof(tmk_gcm));
    json_field(body, "terminal", term, sizeof(term));
    if (!term[0]) strncpy(term, "ATM001", sizeof(term) - 1);
    int rc = payhsm_switch_derive_terminal(tmk_gcm, term, tpk, tak, kcv_tpk, kcv_tak);

    /* Persist derived keys in vault so the HSM key view and coffre are populated */
    if (rc == 0) {
        uint8_t tmk_plain[16], tpk_plain[16], tak_plain[16];
        uint8_t lmk32[32], enc_tpk[16], enc_tak[16];
        uint8_t kcv_bytes_tpk[3], kcv_bytes_tak[3];
        int store_rc = 0;

        if (payhsm_unwrap_lmk_gcm_hex(tmk_gcm, tmk_plain) != 0 ||
            payhsm_unwrap_ecb_hex(tmk_plain, tpk, tpk_plain) != 0 ||
            payhsm_unwrap_ecb_hex(tmk_plain, tak, tak_plain) != 0)
            store_rc = -1;

        if (store_rc == 0 && recompose_for_op(lmk32) != 0)
            store_rc = -1;

        if (store_rc == 0 &&
            (vault_encrypt_under_lmk(lmk32, tpk_plain, enc_tpk) != 0 ||
             vault_encrypt_under_lmk(lmk32, tak_plain, enc_tak) != 0))
            store_rc = -1;

        if (store_rc == 0) {
            hex_decode(kcv_tpk, kcv_bytes_tpk, 3);
            hex_decode(kcv_tak, kcv_bytes_tak, 3);
            char tpk_id[68], tak_id[68];
            snprintf(tpk_id, sizeof(tpk_id), "TPK-%s", term);
            snprintf(tak_id, sizeof(tak_id), "TAK-%s", term);
            payhsm_ctx_t *ctx = payhsm_ctx();
            vault_add_key(&ctx->vault, tpk_id, PAYHSM_KEY_TPK, term, enc_tpk, kcv_bytes_tpk);
            vault_add_key(&ctx->vault, tak_id, PAYHSM_KEY_TAK, term, enc_tak, kcv_bytes_tak);
            vault_save(&ctx->vault);
        }

        secure_zero(tmk_plain, sizeof(tmk_plain));
        secure_zero(tpk_plain, sizeof(tpk_plain));
        secure_zero(tak_plain, sizeof(tak_plain));
        secure_zero(lmk32, sizeof(lmk32));
        secure_zero(enc_tpk, sizeof(enc_tpk));
        secure_zero(enc_tak, sizeof(enc_tak));

        audit_log(store_rc == 0
            ? "Switch derive — TPK/TAK stockés dans le coffre"
            : "Switch derive — vault storage ECHEC");
    }

    snprintf(out, n,
             "{\"rc\":%d,\"tpkCryptogram\":\"%s\",\"takCryptogram\":\"%s\","
             "\"tpkKcv\":\"%s\",\"takKcv\":\"%s\",\"message\":\"%s\"}",
             rc, rc == 0 ? tpk : "", rc == 0 ? tak : "",
             rc == 0 ? kcv_tpk : "", rc == 0 ? kcv_tak : "",
             rc == 0 ? "derive OK" : "echec");
    {
        char line[160];
        snprintf(line, sizeof(line), "%s — terminal %s (key_exchange.c)",
                 rc == 0 ? "Switch derive TPK/TAK OK" : "Switch derive ECHEC", term);
        audit_log(line);
    }
}

static void api_wrap_key(const char *body, char *out, size_t n) {
    char keyhex[40], blob[96];
    json_field(body, "keyHex", keyhex, sizeof(keyhex));
    uint8_t key[16];
    if (hex_decode(keyhex, key, 16) != 0) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"keyHex invalide\"}");
        return;
    }
    int rc = payhsm_wrap_lmk_gcm_hex(key, blob);
    secure_zero(key, sizeof(key));
    snprintf(out, n, "{\"rc\":%d,\"cryptogram\":\"%s\"}", rc, rc == 0 ? blob : "");
    audit_log(rc == 0 ? "Switch wrap-key OK (LMK GCM)" : "Switch wrap-key ECHEC");
}

/* A8 transport : ENC(LMK,key) → ENC(ZMK,key) — jamais de clé claire sur le réseau */
static void api_key_exchange_export_under_zmk(const char *body, char *out, size_t n) {
    if (!payhsm_ctx()->initialized) {
        snprintf(out, n, "{\"rc\":-1,\"cmd\":\"A8\",\"message\":\"HSM non demarre\"}");
        return;
    }
    char zmk_gcm[96], key_gcm[96];
    json_field(body, "zmkCryptogram", zmk_gcm, sizeof(zmk_gcm));
    json_field(body, "keyCryptogram", key_gcm, sizeof(key_gcm));
    if (!zmk_gcm[0] || !key_gcm[0]) {
        snprintf(out, n,
            "{\"rc\":-1,\"cmd\":\"A8\","
            "\"message\":\"zmkCryptogram et keyCryptogram (88 hex) requis\"}");
        return;
    }
    char enc32[33], kcv[8];
    int rc = payhsm_switch_wrap_lmk_gcm_under_zmk(zmk_gcm, key_gcm, enc32, kcv);
    snprintf(out, n,
             "{\"rc\":%d,\"cmd\":\"A8\",\"keyUnderZmk\":\"%s\",\"kcv\":\"%s\","
             "\"message\":\"%s\"}",
             rc, rc == 0 ? enc32 : "", rc == 0 ? kcv : "",
             rc == 0 ? "Export sous ZMK (ECB 32 hex)" : "echec export transport");
    if (rc == 0) audit_log("Key-exchange A8 export sous ZMK OK");
    else audit_log("Key-exchange A8 export ECHEC");
}

static void api_wrap_zpk(const char *body, char *out, size_t n) {
    char zmk_gcm[96], keyhex[40], enc[36], kcv[8];
    json_field(body, "zmkCryptogram", zmk_gcm, sizeof(zmk_gcm));
    json_field(body, "keyHex", keyhex, sizeof(keyhex));
    uint8_t key[16];
    if (hex_decode(keyhex, key, 16) != 0) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"keyHex invalide\"}");
        return;
    }
    int rc = payhsm_switch_wrap_zpk_under_zmk(zmk_gcm, key, enc, kcv);
    secure_zero(key, sizeof(key));
    snprintf(out, n,
             "{\"rc\":%d,\"zpkCryptogram\":\"%s\",\"kcv\":\"%s\",\"message\":\"%s\"}",
             rc, rc == 0 ? enc : "", rc == 0 ? kcv : "",
             rc == 0 ? "ZPK sous ZMK OK" : "echec");
    audit_log(rc == 0 ? "Switch wrap-ZPK OK (key_exchange.c)" : "Switch wrap-ZPK ECHEC");
}

static void api_startup(const char *body, char *out, size_t n) {
    (void)body;
    const payhsm_ctx_t *ctx = payhsm_ctx();
    if (!ctx->initialized) {
        snprintf(out, n,
            "{\"rc\":-2,\"message\":\"LMK absente ou non reconstruite —"
            " initialisez la LMK dans le panneau LMK (TRNG ou SSS) avant de démarrer\","
            "\"initialized\":0}");
        return;
    }
    payhsm_emv_clear_session();
    payhsm_admin_reload_after_startup();
    audit_log("Démarrage HSM — LMK fragmentée P1⊕P2⊕P3 déjà chargée");
    snprintf(out, n,
        "{\"rc\":0,\"message\":\"HSM démarré avec succès —"
        " LMK fragmentée (P1⊕P2⊕P3) chargée en mémoire, coffre prêt\","
        "\"initialized\":1}");
}

static void api_register(const char *body, char *out, size_t n) {
    char pan[32], pin[16], pvv[8];
    json_field(body, "pan", pan, sizeof(pan));
    json_field(body, "pin", pin, sizeof(pin));
    int rc = payhsm_corebanking_issue_pvv(pan, pin, pvv);
    snprintf(out, n, "{\"rc\":%d,\"pan\":\"%s\",\"pvv\":\"%s\",\"message\":\"%s\"}",
             rc, pan, rc == 0 ? pvv : "", rc == 0 ? "PVV emis" : "echec");
}

static void api_corebanking_issue(const char *body, char *out, size_t n) {
    char pan[32], pin[16], pvv[8];
    json_field(body, "pan", pan, sizeof(pan));
    json_field(body, "pin", pin, sizeof(pin));
    if (!payhsm_ctx()->initialized) {
        snprintf(out, n, "{\"rc\":%d,\"message\":\"HSM non demarre\"}", PAYHSM_RC_NOT_INIT);
        return;
    }
    char pvk_gcm[96];
    int rc = PAYHSM_RC_ERR;
    if (json_field(body, "pvkCryptogram", pvk_gcm, sizeof(pvk_gcm)) == 0)
        rc = payhsm_corebanking_issue_pvv_switch(pan, pin, pvk_gcm, pvv);
    snprintf(out, n,
             "{\"rc\":%d,\"pan\":\"%s\",\"pvv\":\"%s\","
             "\"message\":\"%s\","
             "\"hint\":\"Le HSM comparera ce PVV a l etape verification\"}",
             rc, pan, rc == 0 ? pvv : "",
             rc == 0 ? "Core Banking: PVV associe au PAN" : "echec");
    if (rc == 0)
        audit_log_pan("Core Banking: PVV emis via pin_compute_pvv (pin.c)", pan,
                      "/api/corebanking/issue");
    else
        audit_log_pan("Core Banking: ECHEC emission PVV", pan, "/api/corebanking/issue");
}

static void api_corebanking_lookup(const char *body, char *out, size_t n) {
    char pan[32], pvv[8];
    json_field(body, "pan", pan, sizeof(pan));
    if (!payhsm_ctx()->initialized) {
        snprintf(out, n,
                 "{\"rc\":%d,\"pan\":\"%s\",\"found\":false,"
                 "\"message\":\"HSM non demarre\"}",
                 PAYHSM_RC_NOT_INIT, pan);
        return;
    }
    int rc = payhsm_corebanking_get_pvv(pan, pvv);
    snprintf(out, n, "{\"rc\":%d,\"pan\":\"%s\",\"pvv\":\"%s\",\"found\":%s}",
             rc, pan, rc == 0 ? pvv : "", rc == 0 ? "true" : "false");
}

static void api_gap(const char *body, char *out, size_t n) {
    char term[64], pin[16], pan[32];
    json_field(body, "terminal", term, sizeof(term));
    json_field(body, "pin", pin, sizeof(pin));
    json_field(body, "pan", pan, sizeof(pan));

    const char *err = NULL;
    if (!payhsm_ctx()->initialized)
        err = "HSM non demarre — onglet Setup: Demarrer HSM (ou Provision)";
    else if (!term[0])
        err = "terminal manquant (ex: ATM001)";
    else if (!pin[0] || strlen(pin) < 4 || strlen(pin) > 12)
        err = "PIN invalide (4 a 12 chiffres)";
    else if (!pan[0])
        err = "PAN manquant";

    uint8_t pb[8];
    char hex[20] = "";
    int rc = PAYHSM_RC_ERR;

    char tmk_gcm[96], tpk_crypt[96];
    if (!err) {
        if (json_field(body, "tmkCryptogram", tmk_gcm, sizeof(tmk_gcm)) == 0 &&
            json_field(body, "tpkCryptogram", tpk_crypt, sizeof(tpk_crypt)) == 0) {
            rc = payhsm_gap_switch(tmk_gcm, tpk_crypt, pin, pan, pb);
        } else {
            err = "tmkCryptogram et tpkCryptogram requis (cles Switch)";
        }
        if (rc == 0)
            hex_encode(pb, 8, hex);
        else if (!err)
            err = "GAP echec — verifier cryptogrammes Switch";
    }
    secure_zero(pb, sizeof(pb));

    if (err)
        snprintf(out, n, "{\"rc\":%d,\"pinBlock\":\"\",\"message\":\"%s\"}", PAYHSM_RC_ERR, err);
    else
        snprintf(out, n, "{\"rc\":%d,\"pinBlock\":\"%s\",\"message\":\"OK\"}", rc, hex);
    if (!err) {
        char det[48];
        snprintf(det, sizeof(det), "terminal %s (pin.c GAP)", term);
        audit_log_pan(rc == 0 ? "GAP PIN block OK" : "GAP PIN block ECHEC", pan, det);
    }
}

static void api_verify(const char *body, char *out, size_t n) {
    char pan[32], hex[32], tmk_gcm[96], tpk_crypt[96], pvk_gcm[96], pvv[8];
    json_field(body, "pan",          pan,     sizeof(pan));
    json_field(body, "pinBlock",     hex,     sizeof(hex));
    json_field(body, "pvv",          pvv,     sizeof(pvv));  /* PVV fourni par le Core Banking */
    uint8_t pb[8];
    int vrc = -1;
    if (hex_decode(hex, pb, 8) != 0) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"hex invalide\"}");
        return;
    }
    int rc = PAYHSM_RC_ERR;
    if (json_field(body, "tmkCryptogram", tmk_gcm, sizeof(tmk_gcm)) == 0 &&
        json_field(body, "tpkCryptogram", tpk_crypt, sizeof(tpk_crypt)) == 0 &&
        json_field(body, "pvkCryptogram", pvk_gcm, sizeof(pvk_gcm)) == 0)
        rc = payhsm_verify_pin_switch(tmk_gcm, tpk_crypt, pvk_gcm, pan, pvv, pb, &vrc);
    else
        rc = PAYHSM_RC_ERR;
    secure_zero(pb, sizeof(pb));
  const char *res = (vrc == PAYHSM_RC_OK) ? "APPROVED" : "DECLINED";
    snprintf(out, n, "{\"rc\":%d,\"result\":\"%s\",\"code\":%d}", rc, res, vrc);
    audit_log_pan(vrc == PAYHSM_RC_OK ? "PIN verify APPROVED (pin.c)" : "PIN verify DECLINED (pin.c)",
                  pan, "/api/verify");
}

static void api_translate(const char *body, char *out, size_t n) {
    char hex[32], zpkId[48] = "ZPK-VISA";
    char tmk_gcm[96], tpk_crypt[96], zmk_gcm[96], zpk_crypt[96];
    json_field(body, "pinBlock", hex, sizeof(hex));
    json_field(body, "zpkId", zpkId, sizeof(zpkId));
    json_field(body, "zmkCryptogram", zmk_gcm, sizeof(zmk_gcm));
    json_field(body, "zpkCryptogram", zpk_crypt, sizeof(zpk_crypt));
    uint8_t in[8], pb[8];
    if (hex_decode(hex, in, 8) != 0) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"hex invalide\"}");
        return;
    }
    int rc = PAYHSM_RC_ERR;
    const char *errmsg = NULL;
    if (json_field(body, "tmkCryptogram", tmk_gcm, sizeof(tmk_gcm)) != 0 ||
        json_field(body, "tpkCryptogram", tpk_crypt, sizeof(tpk_crypt)) != 0)
        errmsg = "tmkCryptogram et tpkCryptogram requis";
    else if (!zmk_gcm[0])
        errmsg = "zmkCryptogram requis";
    else if (!zpk_crypt[0])
        errmsg = "zpkCryptogram requis";
    else {
        size_t zpk_len = strlen(zpk_crypt);
        size_t tpk_len = strlen(tpk_crypt);
        if (zpk_len != 88 && zpk_len != 32)
            errmsg = "zpkCryptogram tronque ou longueur invalide (attendu 88 ou 32 hex)";
        else if (tpk_len != 88 && tpk_len != 32)
            errmsg = "tpkCryptogram longueur invalide (attendu 88 ou 32 hex)";
        else
            rc = payhsm_translate_pin_switch(tmk_gcm, tpk_crypt, zmk_gcm, zpk_crypt, in, pb);
    }
    char outhex[20] = "";
    if (rc == 0) hex_encode(pb, 8, outhex);
    secure_zero(in, sizeof(in));
    secure_zero(pb, sizeof(pb));
    if (rc == 0)
        snprintf(out, n, "{\"rc\":0,\"pinBlockZpk\":\"%s\",\"zpkId\":\"%s\"}",
                 outhex, zpkId);
    else
        snprintf(out, n,
                 "{\"rc\":%d,\"pinBlockZpk\":\"\",\"zpkId\":\"%s\","
                 "\"message\":\"%s\"}",
                 PAYHSM_RC_ERR, zpkId,
                 errmsg ? errmsg :
                 "Translation TPK→ZPK — verifier LMK demarree et cryptogrammes Switch");
    {
        char line[160];
        snprintf(line, sizeof(line), "%s — ZPK %s (pin.c translate)",
                 rc == 0 ? "PIN translate OK" : "PIN translate ECHEC", zpkId);
        audit_log(line);
    }
}

static void api_translate_zpk(const char *body, char *out, size_t n) {
    char hex[32], fromId[48], toId[48];
    char zmk_gcm[96], zpk_a[96], zpk_b[96];
    json_field(body, "pinBlock", hex, sizeof(hex));
    json_field(body, "fromZpkId", fromId, sizeof(fromId));
    json_field(body, "toZpkId", toId, sizeof(toId));
    json_field(body, "zmkCryptogram", zmk_gcm, sizeof(zmk_gcm));
    json_field(body, "fromZpkCryptogram", zpk_a, sizeof(zpk_a));
    json_field(body, "toZpkCryptogram", zpk_b, sizeof(zpk_b));
    if (!fromId[0]) strncpy(fromId, "ZPK-BANK-A", sizeof(fromId) - 1);
    if (!toId[0]) strncpy(toId, "ZPK-BANK-B", sizeof(toId) - 1);
    uint8_t in[8], pb[8];
    if (hex_decode(hex, in, 8) != 0) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"hex invalide\"}");
        return;
    }
    int rc = PAYHSM_RC_ERR;
    if (zmk_gcm[0] && zpk_a[0] && zpk_b[0])
        rc = payhsm_translate_zpk_switch(zmk_gcm, zpk_a, zpk_b, in, pb);
    char outhex[20] = "";
    if (rc == 0) hex_encode(pb, 8, outhex);
    secure_zero(in, sizeof(in));
    secure_zero(pb, sizeof(pb));
    snprintf(out, n, "{\"rc\":%d,\"pinBlockZpk\":\"%s\",\"from\":\"%s\",\"to\":\"%s\"}",
             rc, outhex, fromId, toId);
    {
        char line[160];
        snprintf(line, sizeof(line), "%s — %s → %s (pin.c)",
                 rc == 0 ? "PIN translate ZPK OK" : "PIN translate ZPK ECHEC",
                 fromId, toId);
        audit_log(line);
    }
}

static void api_verify_zpk(const char *body, char *out, size_t n) {
    char pan[32], hex[32], zpkId[48] = "ZPK-BANK-B";
    json_field(body, "pan", pan, sizeof(pan));
    json_field(body, "pinBlock", hex, sizeof(hex));
    json_field(body, "zpkId", zpkId, sizeof(zpkId));
    uint8_t pb[8];
    int vrc = -1;
    if (hex_decode(hex, pb, 8) != 0) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"hex invalide\"}");
        return;
    }
    char zmk_gcm[96], zpk_crypt[96], pvk_gcm[96];
    int rc = PAYHSM_RC_ERR;
    if (json_field(body, "zmkCryptogram", zmk_gcm, sizeof(zmk_gcm)) == 0 &&
        json_field(body, "zpkCryptogram", zpk_crypt, sizeof(zpk_crypt)) == 0 &&
        json_field(body, "pvkCryptogram", pvk_gcm, sizeof(pvk_gcm)) == 0)
        rc = payhsm_verify_pin_zpk_switch(zmk_gcm, zpk_crypt, pvk_gcm, pan, pb, &vrc);
    secure_zero(pb, sizeof(pb));
    const char *res = (vrc == PAYHSM_RC_OK) ? "APPROVED" : "DECLINED";
    int code = (vrc == PAYHSM_RC_OK) ? 0 : 55;
    snprintf(out, n,
             "{\"rc\":%d,\"result\":\"%s\",\"code\":%d,\"zpkId\":\"%s\","
             "\"message\":\"%s\"}",
             rc, res, code, zpkId,
             vrc == PAYHSM_RC_OK ? "PIN correct (00)" : "PIN incorrect (55)");
    {
        char det[40];
        snprintf(det, sizeof(det), "ZPK %s inter", zpkId);
        audit_log_pan(vrc == PAYHSM_RC_OK ? "PIN verify ZPK APPROVED" : "PIN verify ZPK DECLINED",
                      pan, det);
    }
}

/* Vide entièrement le coffre (clés sous LMK) et persiste sur disque.
 * Utile pour purger des entrées de test périmées ou un coffre saturé.
 * vault_clear() fait un memset qui efface aussi vault_path → on le sauvegarde
 * et on le restaure avant vault_save(), sinon la persistance échoue. */
static void api_vault_clear(char *out, size_t n) {
    if (!payhsm_ctx()->initialized) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"HSM non demarre — rien a vider\"}");
        return;
    }
    payhsm_ctx_t *ctx = payhsm_ctx();
    int removed_classic = ctx->vault.count;
    int removed_ext = payhsm_ekm_clear_vault();
    if (removed_ext < 0) removed_ext = 0;

    char saved_path[256];
    strncpy(saved_path, ctx->vault.vault_path, sizeof(saved_path) - 1);
    saved_path[sizeof(saved_path) - 1] = '\0';

    vault_clear(&ctx->vault);
    strncpy(ctx->vault.vault_path, saved_path, sizeof(ctx->vault.vault_path) - 1);
    ctx->vault.vault_path[sizeof(ctx->vault.vault_path) - 1] = '\0';
    vault_save(&ctx->vault);

    int removed = removed_classic + removed_ext;
    {
        char al[120];
        snprintf(al, sizeof(al),
                 "VAULT_CLEARED — keys.vault=%d ext_keys.vault=%d (total %d)",
                 removed_classic, removed_ext, removed);
        audit_log(al);
    }
    snprintf(out, n,
        "{\"rc\":0,\"removed\":%d,\"removedClassic\":%d,\"removedExt\":%d,"
        "\"message\":\"Coffre HSM vide — keys.vault=%d + ext_keys.vault=%d supprime(s). "
        "Regenerez vos cles (NE/A4, A0, A8).\"}",
        removed, removed_classic, removed_ext, removed_classic, removed_ext);
}

static int payhsm_ekm_append_vault_json(char *out, size_t n, int pos);

/** GET /api/hsm/transport-gcm?transport=ZMK — blob GCM identique à A8/L */
static void api_transport_gcm(const char *query, char *out, size_t n) {
    if (!payhsm_ctx()->initialized) {
        snprintf(out, n, "{\"rc\":%d,\"message\":\"HSM non demarre\"}", PAYHSM_RC_NOT_INIT);
        return;
    }
    char transport[16] = "ZMK";
    if (query) {
        const char *p = strstr(query, "transport=");
        if (p) {
            p += 10;
            size_t i = 0;
            while (p[i] && p[i] != '&' && i < sizeof(transport) - 1) {
                transport[i] = (char)toupper((unsigned char)p[i]);
                i++;
            }
            transport[i] = '\0';
        }
    }
    char crypt[89], tid[64];
    if (payhsm_ekm_lookup_transport_by_name(transport, crypt, tid) != PAYHSM_RC_OK) {
        snprintf(out, n,
                 "{\"rc\":%d,\"message\":\"%s absente — cérémonie A4 (NE+A4) requise\"}",
                 PAYHSM_RC_ERR, transport);
        return;
    }
    snprintf(out, n,
             "{\"rc\":0,\"transport\":\"%s\",\"keyId\":\"%s\","
             "\"cryptogram\":\"%s\",\"source\":\"ext_keys.vault\"}",
             transport, tid, crypt);
}

static void api_vault_list(char *out, size_t n) {
    if (!payhsm_ctx()->initialized) {
        snprintf(out, n, "{\"rc\":%d,\"keys\":[],\"message\":\"HSM non demarre\"}",
                 PAYHSM_RC_NOT_INIT);
        return;
    }
    int pos = snprintf(out, n, "{\"rc\":0,\"dataDir\":\"%s\",\"keys\":[",
                       payhsm_ctx()->data_dir);
    for (int i = 0; i < payhsm_ctx()->vault.count && pos < (int)n - 120; i++) {
        const payhsm_key_entry_t *e = &payhsm_ctx()->vault.keys[i];
        char kcv[8];
        snprintf(kcv, sizeof(kcv), "%02X%02X%02X",
                 e->kcv[0], e->kcv[1], e->kcv[2]);
        pos += snprintf(out + pos, n - (size_t)pos,
                        "%s{\"id\":\"%s\",\"type\":\"%s\",\"terminal\":\"%s\","
                        "\"kcv\":\"%s\",\"storage\":\"keys.vault\"}",
                        (pos > 0 && out[pos - 1] != '[') ? "," : "",
                        e->id, key_type_name(e->type), e->terminal_id, kcv);
    }
    pos = payhsm_ekm_append_vault_json(out, n, pos);
    snprintf(out + pos, n - (size_t)pos, "]}");
}

static void api_kcv(const char *body, char *out, size_t n) {
    char type[16], term[64] = "";
    json_field(body, "type", type, sizeof(type));
    json_field(body, "terminal", term, sizeof(term));
    payhsm_key_type_t kt = PAYHSM_KEY_TPK;
    if (strcmp(type, "TMK") == 0) kt = PAYHSM_KEY_TMK;
    else if (strcmp(type, "TAK") == 0) kt = PAYHSM_KEY_TAK;
    else if (strcmp(type, "ZMK") == 0) kt = PAYHSM_KEY_ZMK;
    else if (strcmp(type, "ZPK") == 0) kt = PAYHSM_KEY_ZPK;
    else if (strcmp(type, "PVK") == 0) kt = PAYHSM_KEY_PVK;
    else if (strcmp(type, "IMK") == 0) kt = PAYHSM_KEY_IMK;
    char kcv[8];
    int rc = payhsm_get_kcv(kt, term, kcv);
    snprintf(out, n, "{\"rc\":%d,\"kcv\":\"%s\"}", rc, rc == 0 ? kcv : "");
}

static void api_mac_calc(const char *body, char *out, size_t n) {
    char msg[4096], tmk_gcm[96], tak_ecb[36];
    json_field(body, "message", msg, sizeof(msg));
    json_field(body, "tmkCryptogram", tmk_gcm, sizeof(tmk_gcm));
    json_field(body, "takCryptogram", tak_ecb, sizeof(tak_ecb));
    uint8_t mac[8];
    int rc = PAYHSM_RC_ERR;
    if (tmk_gcm[0] && tak_ecb[0])
        rc = payhsm_mac_tak_switch(tmk_gcm, tak_ecb,
                                   (const uint8_t *)msg, strlen(msg), mac);
    char hex[20] = "";
    if (rc == 0) hex_encode(mac, 8, hex);
    snprintf(out, n, "{\"rc\":%d,\"mac\":\"%s\"}", rc, hex);
    audit_log(rc == 0 ? "MAC calc OK (mac.c)" : "MAC calc ECHEC");
}

static void api_mac_verify(const char *body, char *out, size_t n) {
    char msg[4096], mhex[32], tmk_gcm[96], tak_ecb[36];
    json_field(body, "message", msg, sizeof(msg));
    json_field(body, "mac", mhex, sizeof(mhex));
    json_field(body, "tmkCryptogram", tmk_gcm, sizeof(tmk_gcm));
    json_field(body, "takCryptogram", tak_ecb, sizeof(tak_ecb));
    uint8_t mac[8];
    if (hex_decode(mhex, mac, 8) != 0) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"mac hex invalide\"}");
        return;
    }
    int ok = -1;
    if (tmk_gcm[0] && tak_ecb[0])
        ok = payhsm_mac_verify_switch(tmk_gcm, tak_ecb,
                                      (const uint8_t *)msg, strlen(msg), mac);
    snprintf(out, n, "{\"rc\":0,\"valid\":%s}", ok == 0 ? "true" : "false");
    audit_log(ok == 0 ? "MAC verify OK (mac.c)" : "MAC verify ECHEC");
}

static const char *emv_rc_user_message(int rc) {
    if (rc == PAYHSM_RC_CARD_UNKNOWN)
        return "Carte non enregistree — Core Banking (PVV) requis avant EMV";
    return "";
}

static void api_emv_arqc(const char *body, char *out, size_t n) {
    char imk_gcm[96], pan[32], psn[8], atc[8], cur[8], amt[24];
    char date[8] = "", term[32] = "";
    if (json_field(body, "imkCryptogram", imk_gcm, sizeof(imk_gcm)) != 0) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"imkCryptogram requis (Switch)\"}");
        return;
    }
    json_field(body, "pan", pan, sizeof(pan));
    json_field(body, "psn", psn, sizeof(psn));
    if (psn[0] == '\0') strcpy(psn, "01");
    json_field(body, "atc", atc, sizeof(atc));
    if (atc[0] == '\0') strcpy(atc, "0001");
    json_field(body, "currency", cur, sizeof(cur));
    if (cur[0] == '\0') strcpy(cur, "978");
    json_field(body, "amountCents", amt, sizeof(amt));
    json_field(body, "date", date, sizeof(date));
    json_field(body, "terminal", term, sizeof(term));
    unsigned long cents = strtoul(amt, NULL, 10);

    char arqc_hex[17], tx_data[256];
    size_t tx_len = 0;
    int rc = payhsm_emv_arqc_switch(imk_gcm, pan, psn, atc, cents, cur,
                                    date[0] ? date : NULL, term[0] ? term : NULL,
                                    arqc_hex, tx_data, sizeof(tx_data), &tx_len);
    const char *umsg = emv_rc_user_message(rc);
    char tx_esc[520];
    json_escape(tx_data, tx_esc, sizeof(tx_esc));
    snprintf(out, n,
             "{\"rc\":%d,\"message\":\"%s\",\"arqc\":\"%s\",\"txData\":\"%s\","
             "\"txDataLen\":%zu,\"engine\":\"payment/emv.c\"}",
             rc, umsg, rc == 0 ? arqc_hex : "", rc == 0 ? tx_esc : "",
             rc == 0 ? tx_len : (size_t)0);
    if (rc == 0) {
        char det[120];
        snprintf(det, sizeof(det), "PUCE ATC %s %s ct TRM %s — /api/emv/arqc",
                 atc, amt[0] ? amt : "0", term[0] ? term : "TPE001");
        audit_log_pan("EMV puce ARQC OK (emv.c)", pan, det);
    }
}

static void api_emv_verify(const char *body, char *out, size_t n) {
    char imk_gcm[96], pan[32], psn[8], atc[8], txhex[1024], arqchex[32];
    if (json_field(body, "imkCryptogram", imk_gcm, sizeof(imk_gcm)) != 0) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"imkCryptogram requis (Switch)\"}");
        return;
    }
    json_field(body, "pan", pan, sizeof(pan));
    json_field(body, "psn", psn, sizeof(psn));
    if (psn[0] == '\0') strcpy(psn, "01");
    json_field(body, "atc", atc, sizeof(atc));
    if (atc[0] == '\0') strcpy(atc, "0001");
    char lenstr[16];
    json_field(body, "txData", txhex, sizeof(txhex));
    json_field(body, "arqc", arqchex, sizeof(arqchex));
    uint8_t tx[256];
    size_t txlen = 0;
    if (json_field(body, "txDataLen", lenstr, sizeof(lenstr)) == 0)
        txlen = (size_t)strtoul(lenstr, NULL, 10);
    if (txlen == 0)
        txlen = strlen(txhex);
    if (txlen > sizeof(tx) - 1) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"txData trop long\"}");
        return;
    }
    memcpy(tx, txhex, txlen);
    tx[txlen] = '\0';
    int valid = 0;
    int arpc_card = 0;
    char arpc_hex[17] = "";
    char arpc_expected[17] = "";
    int rc = payhsm_emv_verify_switch(imk_gcm, pan, psn, atc, tx, txlen, arqchex,
                                      &valid, arpc_hex, &arpc_card, arpc_expected);
    const char *umsg = emv_rc_user_message(rc);
    if (rc == 0) {
        if (valid && arpc_card)
            umsg = "ARQC valide — ARPC emis — puce MK-AC OK";
        else if (valid)
            umsg = "ARQC valide — ARPC emis (puce non verifiee)";
        else
            umsg = "ARQC invalide — carte ou donnees transaction";
    }
    snprintf(out, n,
             "{\"rc\":%d,\"valid\":%s,\"approved\":%s,\"arpc\":\"%s\","
             "\"arpcCardValid\":%s,\"arpcExpected\":\"%s\","
             "\"message\":\"%s\",\"engine\":\"payment/emv.c\"}",
             rc,
             (rc == 0 && valid) ? "true" : "false",
             (rc == 0 && valid && arpc_card) ? "true" : "false",
             arpc_hex,
             (rc == 0 && valid && arpc_card) ? "true" : "false",
             arpc_expected,
             umsg);
    {
        char det[64];
        snprintf(det, sizeof(det), "Emetteur ATC %s — /api/emv/verify", atc);
        audit_log_pan((rc == 0 && valid) ? "EMV emetteur verify APPROVED (emv.c)"
                                          : "EMV emetteur verify DECLINED (emv.c)",
                      pan, det);
    }
}

static void api_emv_verify_arpc(const char *body, char *out, size_t n) {
    char imk_gcm[96], pan[32], psn[8], atc[8], arqchex[32], arpchex[32], arc[8] = "0000";
    if (json_field(body, "imkCryptogram", imk_gcm, sizeof(imk_gcm)) != 0) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"imkCryptogram requis (Switch)\"}");
        return;
    }
    json_field(body, "pan", pan, sizeof(pan));
    json_field(body, "psn", psn, sizeof(psn));
    if (psn[0] == '\0') strcpy(psn, "01");
    json_field(body, "atc", atc, sizeof(atc));
    if (atc[0] == '\0') strcpy(atc, "0001");
    json_field(body, "arqc", arqchex, sizeof(arqchex));
    json_field(body, "arpc", arpchex, sizeof(arpchex));
    json_field(body, "arc", arc, sizeof(arc));

    int valid = 0;
    char arpc_expected[17] = "";
    int rc = payhsm_emv_verify_arpc_switch(imk_gcm, pan, psn, atc, arqchex, arpchex, arc,
                                           &valid, arpc_expected);
    const char *umsg = emv_rc_user_message(rc);
    if (rc == 0) {
        umsg = valid
            ? "ARPC puce OK — MK-AC recalcule = ARPC emetteur"
            : "ARPC puce KO — ne correspond pas a l'emetteur";
    }
    snprintf(out, n,
             "{\"rc\":%d,\"valid\":%s,\"arpcReceived\":\"%s\","
             "\"arpcExpected\":\"%s\",\"arc\":\"%s\","
             "\"message\":\"%s\",\"engine\":\"payment/emv.c\"}",
             rc,
             (rc == 0 && valid) ? "true" : "false",
             arpchex,
             arpc_expected,
             arc,
             umsg);
    {
        char det[96];
        snprintf(det, sizeof(det),
                 "PUCE MK-AC recv %s expect %s ARC %s — /api/emv/verify-arpc",
                 arpchex, arpc_expected[0] ? arpc_expected : "—", arc);
        audit_log_pan((rc == 0 && valid) ? "EMV puce verify ARPC OK (emv.c)"
                                          : "EMV puce verify ARPC KO (emv.c)",
                      pan, det);
    }
}

static void api_payment_modules(char *out, size_t n) {
    snprintf(out, n,
             "{\"rc\":0,\"gateway\":\"payhsm-httpd\","
             "\"modules\":["
             "{\"api\":\"/api/gap\",\"c\":\"payment/pin.c\",\"fn\":\"generate_pin_block\"},"
             "{\"api\":\"/api/verify\",\"c\":\"payment/pin.c\",\"fn\":\"verify_encrypted_pin_block\"},"
             "{\"api\":\"/api/translate\",\"c\":\"payment/pin.c\",\"fn\":\"translate_pin_block\"},"
             "{\"api\":\"/api/corebanking/issue\",\"c\":\"payment/pin.c\",\"fn\":\"pin_compute_pvv\"},"
             "{\"api\":\"/api/mac/calc\",\"c\":\"payment/mac.c\",\"fn\":\"calculate_mac_tak\"},"
             "{\"api\":\"/api/mac/verify\",\"c\":\"payment/mac.c\",\"fn\":\"verify_mac\"},"
             "{\"api\":\"/api/emv/arqc\",\"c\":\"payment/emv.c\",\"fn\":\"emv_compute_arqc\"},"
             "{\"api\":\"/api/emv/verify\",\"c\":\"payment/emv.c\",\"fn\":\"verify_arqc,generate_arpc\"},"
             "{\"api\":\"/api/emv/verify-arpc\",\"c\":\"payment/emv.c\",\"fn\":\"verify_arpc (puce MK-AC)\"},"
             "{\"api\":\"/api/emv/purchase\",\"c\":\"payment/emv.c\",\"fn\":\"flux ARQC+verify\"},"
             "{\"api\":\"/api/switch/derive-terminal\",\"c\":\"payment/key_exchange.c\","
             "\"fn\":\"derive_tpk_from_tmk,derive_tak_from_tmk\"}"
             "],\"pkcs11\":\"payment/pkcs11_payment.cpp\"}");
}

/* ------------------------------------------------------------------ */
/* AES-256-GCM pour chiffrement/déchiffrement de clé sous LMK         */
/* Format blob : IV(12) || TAG(16) || CT(16) = 44 octets = 88 hex     */
/* ------------------------------------------------------------------ */
static int lmk_gcm_encrypt(const uint8_t lmk[32],
                             const uint8_t pt[LMK_KEY_LEN],
                             uint8_t blob[LMK_BLOB_LEN])
{
    uint8_t iv[LMK_IV_LEN];
    if (RAND_bytes(iv, LMK_IV_LEN) != 1) return -1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int ret = -1, len = 0;
    uint8_t ct[LMK_KEY_LEN], tag[LMK_TAG_LEN];
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto enc_done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, lmk, iv)                 != 1) goto enc_done;
    if (EVP_EncryptUpdate(ctx, ct, &len, pt, LMK_KEY_LEN)            != 1) goto enc_done;
    if (EVP_EncryptFinal_ex(ctx, ct + len, &len)                     != 1) goto enc_done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                             LMK_TAG_LEN, tag)                       != 1) goto enc_done;
    memcpy(blob,                              iv,  LMK_IV_LEN);
    memcpy(blob + LMK_IV_LEN,                tag, LMK_TAG_LEN);
    memcpy(blob + LMK_IV_LEN + LMK_TAG_LEN,  ct,  LMK_KEY_LEN);
    ret = 0;
enc_done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* Retourne 0 si OK, -1 si tag GCM invalide (mauvaise LMK ou blob corrompu) */
static int lmk_gcm_decrypt(const uint8_t lmk[32],
                             const uint8_t blob[LMK_BLOB_LEN],
                             uint8_t pt_out[LMK_KEY_LEN])
{
    const uint8_t *iv  = blob;
    const uint8_t *tag = blob + LMK_IV_LEN;
    const uint8_t *ct  = blob + LMK_IV_LEN + LMK_TAG_LEN;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int ret = -1, len = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto dec_done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, lmk, iv)                 != 1) goto dec_done;
    if (EVP_DecryptUpdate(ctx, pt_out, &len, ct, LMK_KEY_LEN)        != 1) goto dec_done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                             LMK_TAG_LEN, (void *)tag)               != 1) goto dec_done;
    ret = (EVP_DecryptFinal_ex(ctx, pt_out + len, &len) == 1) ? 0 : -1;
dec_done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* ------------------------------------------------------------------ */
/* Variantes longueur variable : pt_len ∈ {16, 24, 32}               */
/* Format blob : IV(12) || TAG(16) || CT(pt_len)                      */
/* blob doit être alloué avec au moins LMK_BLOB_OVERHEAD + pt_len     */
/* ------------------------------------------------------------------ */
static int lmk_gcm_encrypt_n(const uint8_t lmk[32],
                              const uint8_t *pt, size_t pt_len,
                              uint8_t *blob)
{
    if (pt_len == 0 || pt_len > LMK_MAX_KEY_LEN) return -1;
    uint8_t iv[LMK_IV_LEN];
    if (RAND_bytes(iv, LMK_IV_LEN) != 1) return -1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int ret = -1, len = 0;
    uint8_t ct[LMK_MAX_KEY_LEN], tag[LMK_TAG_LEN];
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto encn_done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, lmk, iv)                 != 1) goto encn_done;
    if (EVP_EncryptUpdate(ctx, ct, &len, pt, (int)pt_len)            != 1) goto encn_done;
    if (EVP_EncryptFinal_ex(ctx, ct + len, &len)                     != 1) goto encn_done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                             LMK_TAG_LEN, tag)                       != 1) goto encn_done;
    memcpy(blob,                     iv,  LMK_IV_LEN);
    memcpy(blob + LMK_IV_LEN,        tag, LMK_TAG_LEN);
    memcpy(blob + LMK_BLOB_OVERHEAD, ct,  pt_len);
    ret = 0;
encn_done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* ct_len = taille du texte chiffré = taille de la clé en clair (prévu pour A8 longueur variable) */
static int __attribute__((unused)) lmk_gcm_decrypt_n(const uint8_t lmk[32],
                              const uint8_t *blob, size_t ct_len,
                              uint8_t *pt_out)
{
    if (ct_len == 0 || ct_len > LMK_MAX_KEY_LEN) return -1;
    const uint8_t *iv  = blob;
    const uint8_t *tag = blob + LMK_IV_LEN;
    const uint8_t *ct  = blob + LMK_BLOB_OVERHEAD;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int ret = -1, len = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto decn_done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, lmk, iv)                 != 1) goto decn_done;
    if (EVP_DecryptUpdate(ctx, pt_out, &len, ct, (int)ct_len)        != 1) goto decn_done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                             LMK_TAG_LEN, (void *)tag)               != 1) goto decn_done;
    ret = (EVP_DecryptFinal_ex(ctx, pt_out + len, &len) == 1) ? 0 : -1;
decn_done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

static void api_lmk_encrypt(const char *body, char *out, size_t n)
{
    if (!payhsm_ctx()->initialized) {
        snprintf(out, n, "{\"ok\":false,\"message\":\"HSM non demarre\"}");
        return;
    }
    char label[16], keyhex[64];
    json_field(body, "label",  label,  sizeof(label));
    json_field(body, "keyHex", keyhex, sizeof(keyhex));

    uint8_t key[LMK_KEY_LEN];
    if (hex_decode(keyhex, key, LMK_KEY_LEN) != 0) {
        snprintf(out, n,
                 "{\"ok\":false,\"message\":\"keyHex invalide — 32 chars hex attendus (16 octets)\"}");
        return;
    }

    uint8_t lmk[32];
    if (check_integrity() != 0 || recompose_for_op(lmk) != 0) {
        snprintf(out, n, "{\"ok\":false,\"message\":\"LMK non disponible\"}");
        secure_zero(key, sizeof(key));
        return;
    }

    uint8_t blob[LMK_BLOB_LEN];
    int rc = lmk_gcm_encrypt(lmk, key, blob);
    secure_zero(lmk, sizeof(lmk));
    secure_zero(key,  sizeof(key));

    if (rc != 0) {
        snprintf(out, n, "{\"ok\":false,\"message\":\"Chiffrement GCM echoue\"}");
        return;
    }

    char blobhex[LMK_BLOB_LEN * 2 + 1];
    hex_encode(blob, LMK_BLOB_LEN, blobhex);
    char lbl[16]; json_escape(label, lbl, sizeof(lbl));
    snprintf(out, n, "{\"ok\":true,\"label\":\"%s\",\"blob\":\"%s\"}", lbl, blobhex);
}

static void api_lmk_decrypt(const char *body, char *out, size_t n)
{
    if (!payhsm_ctx()->initialized) {
        snprintf(out, n, "{\"ok\":false,\"message\":\"HSM non demarre\"}");
        return;
    }
    char label[16], blobhex[LMK_BLOB_LEN * 2 + 2];
    json_field(body, "label",   label,   sizeof(label));
    json_field(body, "blobHex", blobhex, sizeof(blobhex));

    uint8_t blob[LMK_BLOB_LEN];
    if (hex_decode(blobhex, blob, LMK_BLOB_LEN) != 0) {
        snprintf(out, n,
                 "{\"ok\":false,\"message\":\"blobHex invalide — 88 chars hex attendus (44 octets)\"}");
        return;
    }

    uint8_t lmk[32];
    if (check_integrity() != 0 || recompose_for_op(lmk) != 0) {
        snprintf(out, n, "{\"ok\":false,\"message\":\"LMK non disponible\"}");
        return;
    }

    uint8_t pt[LMK_KEY_LEN] = {0};
    int rc = lmk_gcm_decrypt(lmk, blob, pt);
    secure_zero(lmk, sizeof(lmk));

    if (rc != 0) {
        secure_zero(pt, sizeof(pt));
        snprintf(out, n,
                 "{\"ok\":false,\"message\":\"Tag GCM invalide — mauvaise LMK ou blob corrompu\"}");
        return;
    }

    char keyhex[LMK_KEY_LEN * 2 + 1];
    hex_encode(pt, LMK_KEY_LEN, keyhex);
    secure_zero(pt, sizeof(pt));
    char lbl[16]; json_escape(label, lbl, sizeof(lbl));
    snprintf(out, n, "{\"ok\":true,\"label\":\"%s\",\"keyHex\":\"%s\"}", lbl, keyhex);
}

static void api_emv_purchase(const char *body, char *out, size_t n) {
    char pan[32], psn[8], atc[8], cur[8], amt[24];
    char date[8] = "", term[32] = "";
    json_field(body, "pan", pan, sizeof(pan));
    json_field(body, "psn", psn, sizeof(psn));
    json_field(body, "atc", atc, sizeof(atc));
    json_field(body, "currency", cur, sizeof(cur));
    if (cur[0] == '\0') strcpy(cur, "978");
    json_field(body, "amountCents", amt, sizeof(amt));
    json_field(body, "date", date, sizeof(date));
    json_field(body, "terminal", term, sizeof(term));
    unsigned long cents = strtoul(amt, NULL, 10);

    char imk_gcm[96];
    payhsm_emv_purchase_t r;
    int rc = PAYHSM_RC_ERR;
    if (json_field(body, "imkCryptogram", imk_gcm, sizeof(imk_gcm)) == 0)
        rc = payhsm_emv_purchase_switch(imk_gcm, pan, psn, atc, cents, cur,
                                        date[0] ? date : NULL,
                                        term[0] ? term : NULL, &r);
    if (rc == PAYHSM_RC_CARD_UNKNOWN) {
        snprintf(r.message, sizeof(r.message), "%s", emv_rc_user_message(rc));
    }
    char esc[160];
    json_escape(r.message, esc, sizeof(esc));
    snprintf(out, n,
             "{\"rc\":%d,\"approved\":%s,\"amount\":\"%s\","
             "\"txData\":\"%s\",\"arqc\":\"%s\",\"arpc\":\"%s\","
             "\"message\":\"%s\","
             "\"steps\":["
             "{\"id\":\"card\",\"label\":\"Puce carte: ARQC calcule\",\"ok\":%s},"
             "{\"id\":\"net\",\"label\":\"Reseau: authorization request\",\"ok\":true},"
             "{\"id\":\"issuer\",\"label\":\"HSM emetteur: verification ARQC\",\"ok\":%s},"
             "{\"id\":\"arpc\",\"label\":\"HSM: ARPC retour TPE\",\"ok\":%s}"
             "],\"engine\":\"payment/emv.c\"}",
             rc, r.approved ? "true" : "false", r.amount_display,
             r.tx_data, r.arqc_hex, r.arpc_hex, esc,
             r.arqc_hex[0] ? "true" : "false",
             r.approved ? "true" : "false",
             r.approved ? "true" : "false");
    {
        char det[72];
        snprintf(det, sizeof(det), "ATC %s, %s ct — /api/emv/purchase", atc, amt);
        audit_log_pan(r.approved ? "EMV purchase APPROVED (emv.c)"
                                   : "EMV purchase DECLINED (emv.c)",
                      pan, det);
    }
}


/* ------------------------------------------------------------------ */
/* Commandes HSM standard (style Thales) : A0, A6, A8                 */
/* ------------------------------------------------------------------ */

/*
 * KCV Thales payShield :
 *   AES-128/192/256 → AES-ECB encrypt 16 octets nuls, 3 premiers octets en hex
 *   Autre taille    → DES-EDE ECB sur 8 octets nuls (compatibilité DES)
 */
static void hsm_kcv_hex(const uint8_t *key, size_t keylen, char kcv[7]) {
    uint8_t zeros[16] = {0};
    uint8_t out[16]   = {0};
    int len = 0;
    const EVP_CIPHER *cipher;
    int zeros_len;

    if (keylen == 16) {
        cipher = EVP_aes_128_ecb(); zeros_len = 16;
    } else if (keylen == 24) {
        cipher = EVP_aes_192_ecb(); zeros_len = 16;
    } else if (keylen == 32) {
        cipher = EVP_aes_256_ecb(); zeros_len = 16;
    } else {
        cipher = (keylen >= 16) ? EVP_des_ede_ecb() : EVP_des_ecb(); zeros_len = 8;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx) {
        EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL);
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        EVP_EncryptUpdate(ctx, out, &len, zeros, zeros_len);
        EVP_CIPHER_CTX_free(ctx);
    }
    snprintf(kcv, 7, "%02X%02X%02X", out[0], out[1], out[2]);
}

static payhsm_key_type_t parse_key_type(const char *s) {
    if (!s) return PAYHSM_KEY_ZMK;
    if (!strcmp(s,"TMK")) return PAYHSM_KEY_TMK;
    if (!strcmp(s,"TPK")) return PAYHSM_KEY_TPK;
    if (!strcmp(s,"TAK")) return PAYHSM_KEY_TAK;
    if (!strcmp(s,"ZMK")) return PAYHSM_KEY_ZMK;
    if (!strcmp(s,"ZPK")) return PAYHSM_KEY_ZPK;
    if (!strcmp(s,"PVK")) return PAYHSM_KEY_PVK;
    if (!strcmp(s,"IMK")) return PAYHSM_KEY_IMK;
    return PAYHSM_KEY_ZMK;
}

/*
 * Convertit un code type 2 caractères du format wire INTERNAL (01..07)
 * en nom de clé ("TMK", "ZMK"...). Aligné sur KEY_CODE_MAP de payhsm-admin.c
 * et sur l'exemple documenté dans docs/commands.md (0001A01001U → type 01 = TMK).
 *
 * Sans cette conversion, le code hex est passé tel quel à parse_key_type()
 * qui attend un nom, échoue à matcher, et stocke tout en ZMK par défaut.
 *
 * Retourne le nom mappé, ou la chaîne d'origine si c'est déjà un nom
 * (ZMK/ZPK...) ou un code inconnu — parse_key_type() gère alors le fallback.
 */
static const char *keytype_hex_to_name(const char *code2) {
    if (!code2) return "ZMK";
    if (!strcmp(code2,"01")) return "TMK";
    if (!strcmp(code2,"02")) return "ZMK";
    if (!strcmp(code2,"03")) return "ZPK";
    if (!strcmp(code2,"04")) return "PVK";
    if (!strcmp(code2,"05")) return "IMK";
    if (!strcmp(code2,"06")) return "TPK";
    if (!strcmp(code2,"07")) return "TAK";
    return code2;
}

/* Chiffre key (16 o) sous LMK ECB et l'ajoute au vault — appelé depuis A0/A6/A8.
 * Retourne 0 si la clé a été ajoutée/mise à jour, -1 sinon (chiffrement échoué
 * ou coffre plein). L'échec « coffre plein » est audité pour ne plus être
 * silencieux : sans cela une nouvelle clé semble générée mais n'apparaît jamais. */
static int vault_store_16(const uint8_t lmk32[32],
                          const uint8_t key16[PAYHSM_KEY_LEN],
                          const char *keytype, const char *terminal_id,
                          const char *kcv6hex) {
    uint8_t enc[PAYHSM_KEY_LEN], kcv_bytes[3];
    if (vault_encrypt_under_lmk(lmk32, key16, enc) != 0) return -1;
    hex_decode(kcv6hex, kcv_bytes, 3);
    char key_id[48];
    snprintf(key_id, sizeof(key_id), "%s-%s", keytype, kcv6hex);
    payhsm_ctx_t *ctx = payhsm_ctx();
    int rc = vault_add_key(&ctx->vault, key_id, parse_key_type(keytype),
                           terminal_id ? terminal_id : "", enc, kcv_bytes);
    if (rc != 0) {
        char al[96];
        snprintf(al, sizeof(al),
                 "VAULT_FULL — cle %s NON stockee (coffre plein: %d/%d)",
                 key_id, ctx->vault.count, PAYHSM_MAX_KEYS);
        audit_log(al);
        return -1;
    }
    vault_save(&ctx->vault);
    return 0;
}

/*
 * A0 — Générer une clé aléatoire et la chiffrer sous LMK (AES-256-GCM)
 *
 * Entrée JSON :
 *   keyType : type de clé (ex. "ZMK", "ZPK", "TMK" …)  — défaut "ZMK"
 *   keyLen  : taille en octets : 16 (AES-128), 24 (AES-192), 32 (AES-256) — défaut 16
 *
 * Sortie JSON :
 *   cryptogram : IV(12)+TAG(16)+CT(keyLen) en hex  → 88 / 104 / 120 chars
 *   kcv        : AES-ECB(16 zéros)[0..2] en hex (6 chars)
 *   keyLen     : taille effective de la clé (octets)
 */
static void api_hsm_a0(const char *body, char *out, size_t n) {
    if (!payhsm_ctx()->initialized) {
        snprintf(out, n, "{\"rc\":-1,\"cmd\":\"A0\",\"message\":\"HSM non demarre\"}");
        return;
    }
    char keytype[16]   = "ZMK";
    char keylen_str[8] = "16";
    json_field(body, "keyType", keytype,    sizeof(keytype));
    json_field(body, "keyLen",  keylen_str, sizeof(keylen_str));

    unsigned int keylen = (unsigned int)atoi(keylen_str);
    if (keylen == 0) keylen = 16;
    if (keylen != 16 && keylen != 24 && keylen != 32) {
        snprintf(out, n,
            "{\"rc\":-1,\"cmd\":\"A0\","
            "\"message\":\"keyLen invalide — valeurs acceptees: 16 (AES-128), 24 (AES-192), 32 (AES-256)\"}");
        return;
    }

    uint8_t key[LMK_MAX_KEY_LEN];
    if (RAND_bytes(key, (int)keylen) != 1) {
        snprintf(out, n, "{\"rc\":-1,\"cmd\":\"A0\",\"message\":\"RAND_bytes echec\"}");
        return;
    }

    uint8_t lmk[32];
    if (check_integrity() != 0 || recompose_for_op(lmk) != 0) {
        secure_zero(key, sizeof(key));
        snprintf(out, n, "{\"rc\":-1,\"cmd\":\"A0\",\"message\":\"LMK indisponible\"}");
        return;
    }

    size_t blob_len = LMK_BLOB_OVERHEAD + keylen;
    uint8_t blob[LMK_MAX_BLOB_LEN];
    int rc = lmk_gcm_encrypt_n(lmk, key, keylen, blob);

    /* Vault storage: persist 16-byte keys under LMK (ECB) while lmk is available.
       vault_full=1 si le coffre est plein (clé générée mais non stockée). */
    char kcv[7];
    hsm_kcv_hex(key, keylen, kcv);
    int vault_full = 0;
    if (rc == 0 && keylen == PAYHSM_KEY_LEN)
        vault_full = (vault_store_16(lmk, key, keytype, "", kcv) != 0);

    secure_zero(lmk, sizeof(lmk));
    if (rc != 0) {
        secure_zero(key, sizeof(key));
        snprintf(out, n, "{\"rc\":-1,\"cmd\":\"A0\",\"message\":\"Chiffrement GCM LMK echec\"}");
        return;
    }

    char blobhex[LMK_MAX_BLOB_LEN * 2 + 1];
    hex_encode(blob, blob_len, blobhex);
    secure_zero(key, sizeof(key));

    char tesc[16];
    json_escape(keytype, tesc, sizeof(tesc));
    snprintf(out, n,
        "{\"rc\":0,\"cmd\":\"A0\",\"keyType\":\"%s\","
        "\"scheme\":\"U\",\"cryptogram\":\"%s\",\"kcv\":\"%s\","
        "\"keyLen\":%u,\"vaultStored\":%s,"
        "\"message\":\"%s\","
        "\"hint\":\"Cryptogramme = IV(12)+TAG(16)+CT(%u) = %zu chars hex\"}",
        tesc, blobhex, kcv, keylen,
        (keylen == PAYHSM_KEY_LEN && !vault_full) ? "true" : "false",
        vault_full
            ? "Cle generee mais NON stockee — coffre plein (32 cles max). Videz le coffre."
            : "Cle generee et protegee sous LMK (AES-256-GCM)",
        keylen, blob_len * 2);
    {
        char line[128];
        snprintf(line, sizeof(line), "A0 Generate Key: type=%s keylen=%u KCV=%s",
                 keytype, keylen, kcv);
        audit_log(line);
    }
}

/*
 * A6 — Importer une clé externe chiffrée sous ZMK → rechiffrer sous LMK
 *
 * Entrée JSON :
 *   zmkCryptogram  : ZMK protégée sous LMK (88 hex, format AES-256-GCM IV+TAG+CT)
 *   keyUnderZmk    : clé externe chiffrée sous ZMK (32 hex, AES-128-ECB)
 *   keyType        : type de la clé importée (ex. "ZPK", "TPK", "TAK")
 *
 * Traitement (identique Thales payShield) :
 *   1. Déchiffrer ZMK depuis LMK
 *   2. Déchiffrer la clé importée sous ZMK (AES-128-ECB)
 *   3. Rechiffrer immédiatement sous LMK (AES-256-GCM)
 *   4. Calculer KCV (3DES-ECB de 8 zéros, 3 premiers octets)
 *   5. Zéroïser toutes les versions claires en mémoire
 */
static void api_hsm_a6(const char *body, char *out, size_t n) {
    if (!payhsm_ctx()->initialized) {
        snprintf(out, n, "{\"rc\":-1,\"cmd\":\"A6\",\"message\":\"HSM non demarre\"}");
        return;
    }

    char zmk_gcm[LMK_BLOB_LEN * 2 + 2];
    char key_enc_zmk[40];
    char keytype[16] = "ZPK";
    json_field(body, "zmkCryptogram", zmk_gcm,     sizeof(zmk_gcm));
    json_field(body, "keyUnderZmk",   key_enc_zmk, sizeof(key_enc_zmk));
    json_field(body, "keyType",       keytype,      sizeof(keytype));

    if (!zmk_gcm[0] || !key_enc_zmk[0]) {
        snprintf(out, n,
            "{\"rc\":-1,\"cmd\":\"A6\","
            "\"message\":\"zmkCryptogram (88 hex) et keyUnderZmk (32 hex) requis\","
            "\"hint\":\"zmkCryptogram = IV(12)+TAG(16)+CT(16) — obtenu via A0 ou wrap-key\"}");
        return;
    }

    /* Étape 1 : déchiffrer la ZMK depuis la LMK locale */
    uint8_t zmk[LMK_KEY_LEN];
    if (payhsm_unwrap_lmk_gcm_hex(zmk_gcm, zmk) != PAYHSM_RC_OK) {
        snprintf(out, n,
            "{\"rc\":-1,\"cmd\":\"A6\","
            "\"message\":\"Dechiffrement ZMK echec — blob LMK invalide ou LMK incorrecte\"}");
        return;
    }

    /* Étape 2 : déchiffrer la clé importée sous ZMK (AES-128-ECB, 32 hex) */
    uint8_t key_clear[LMK_KEY_LEN];
    int rc2 = payhsm_unwrap_ecb_hex(zmk, key_enc_zmk, key_clear);
    secure_zero(zmk, sizeof(zmk));
    if (rc2 != PAYHSM_RC_OK) {
        snprintf(out, n,
            "{\"rc\":-1,\"cmd\":\"A6\","
            "\"message\":\"Dechiffrement cle sous ZMK echec — keyUnderZmk ou ZMK incorrect\"}");
        return;
    }

    /* Étape 3 : rechiffrer immédiatement sous LMK (AES-256-GCM) */
    char new_cryptogram[PAYHSM_GCM_BLOB_HEX + 2];
    if (payhsm_wrap_lmk_gcm_hex(key_clear, new_cryptogram) != PAYHSM_RC_OK) {
        secure_zero(key_clear, sizeof(key_clear));
        snprintf(out, n, "{\"rc\":-1,\"cmd\":\"A6\",\"message\":\"Chiffrement LMK echec\"}");
        return;
    }

    /* Étape 4 : calculer le KCV (3DES-ECB sur 8 zéros, 3 premiers octets) */
    char kcv[7];
    hsm_kcv_hex(key_clear, LMK_KEY_LEN, kcv);

    /* Vault storage: re-encrypt under LMK ECB and persist */
    {
        uint8_t lmk_v[32];
        if (recompose_for_op(lmk_v) == 0) {
            vault_store_16(lmk_v, key_clear, keytype, "", kcv);
            secure_zero(lmk_v, sizeof(lmk_v));
        }
    }

    /* Étape 5 : zéroïser la clé claire */
    secure_zero(key_clear, sizeof(key_clear));

    char tesc[16];
    json_escape(keytype, tesc, sizeof(tesc));
    snprintf(out, n,
        "{\"rc\":0,\"cmd\":\"A6\",\"keyType\":\"%s\","
        "\"scheme\":\"U\",\"cryptogram\":\"%s\",\"kcv\":\"%s\","
        "\"message\":\"Cle importee ZMK → LMK (AES-128-ECB + AES-256-GCM)\","
        "\"hint\":\"cryptogram = IV(12)+TAG(16)+CT(16) = 88 chars hex — a conserver pour operations HSM\"}",
        tesc, new_cryptogram, kcv);
    {
        char line[128];
        snprintf(line, sizeof(line), "A6 Import Key: type=%s KCV=%s (ZMK→LMK)", keytype, kcv);
        audit_log(line);
    }
}

/* A6 + verification KCV optionnelle (key-exchange) */
static void api_key_exchange_import(const char *body, char *out, size_t n) {
    char kcv_expected[16] = "";
    json_field(body, "kcvExpected", kcv_expected, sizeof(kcv_expected));
    api_hsm_a6(body, out, n);
    if (!kcv_expected[0]) return;
    if (strstr(out, "\"rc\":0") == NULL) return;
    char kcv_got[16] = "";
    const char *p = strstr(out, "\"kcv\":\"");
    if (p) {
        p += 7;
        size_t i = 0;
        while (p[i] && p[i] != '"' && i < 15) {
            kcv_got[i] = (char)toupper((unsigned char)p[i]);
            i++;
        }
        kcv_got[i] = '\0';
    }
    char exp_up[16];
    size_t el = strlen(kcv_expected);
    for (size_t i = 0; i < el && i < 15; i++)
        exp_up[i] = (char)toupper((unsigned char)kcv_expected[i]);
    exp_up[el < 15 ? el : 15] = '\0';
    if (kcv_got[0] && strcmp(kcv_got, exp_up) != 0) {
        snprintf(out, n,
            "{\"rc\":-1,\"cmd\":\"A6\",\"errorCode\":\"07\","
            "\"message\":\"KCV mismatch apres import\","
            "\"kcvExpected\":\"%s\",\"kcvComputed\":\"%s\"}",
            exp_up, kcv_got);
        audit_log("Key-exchange A6 KCV mismatch");
    }
}

/*
 * A8 — Consultation temporaire d'une clé protégée sous LMK
 *
 * Entrée JSON :
 *   keyCryptogram : clé sous LMK (88 hex, format AES-256-GCM IV+TAG+CT)
 *   flag          : "H" = retourner seulement le KCV (défaut)
 *                   "V" = retourner la clé en clair + KCV (sensible, maintenance)
 *   keyType       : type de la clé (informatif)
 *
 * Traitement (identique Thales payShield) :
 *   1. Déchiffrer temporairement la clé depuis la LMK locale
 *   2. Calculer le KCV (3DES-ECB sur 8 zéros, 3 premiers octets)
 *   3. Si flag H : retourner uniquement le KCV
 *      Si flag V : retourner la clé claire + KCV
 *   4. Zéroïser la clé claire après usage
 */
static void api_hsm_a8(const char *body, char *out, size_t n) {
    if (!payhsm_ctx()->initialized) {
        snprintf(out, n, "{\"rc\":-1,\"cmd\":\"A8\",\"message\":\"HSM non demarre\"}");
        return;
    }

    char key_gcm[LMK_BLOB_LEN * 2 + 2];
    char flag_str[4] = "H";
    char keytype[16] = "";
    json_field(body, "keyCryptogram", key_gcm,   sizeof(key_gcm));
    json_field(body, "flag",          flag_str,  sizeof(flag_str));
    json_field(body, "keyType",       keytype,   sizeof(keytype));

    if (!key_gcm[0]) {
        snprintf(out, n,
            "{\"rc\":-1,\"cmd\":\"A8\","
            "\"message\":\"keyCryptogram requis (88 hex = IV+TAG+CT protege sous LMK)\"}");
        return;
    }

    /* Étape 1 : déchiffrer temporairement la clé depuis la LMK locale */
    uint8_t key_clear[LMK_KEY_LEN];
    if (payhsm_unwrap_lmk_gcm_hex(key_gcm, key_clear) != PAYHSM_RC_OK) {
        snprintf(out, n,
            "{\"rc\":-1,\"cmd\":\"A8\","
            "\"message\":\"Dechiffrement LMK echec — blob invalide ou LMK incorrecte\"}");
        return;
    }

    /* Étape 2 : calculer le KCV (3DES-ECB sur 8 zéros, 3 premiers octets) */
    char kcv[7];
    hsm_kcv_hex(key_clear, LMK_KEY_LEN, kcv);

    char tesc[16];
    json_escape(keytype, tesc, sizeof(tesc));

    int show_clear = (flag_str[0] == 'V' || flag_str[0] == 'v');

    if (show_clear) {
        /* Étape 3a (flag V) : retourner clé claire + KCV */
        char keyhex[LMK_KEY_LEN * 2 + 1];
        hex_encode(key_clear, LMK_KEY_LEN, keyhex);
        /* Étape 4 : zéroïser */
        secure_zero(key_clear, sizeof(key_clear));
        snprintf(out, n,
            "{\"rc\":0,\"cmd\":\"A8\",\"keyType\":\"%s\","
            "\"flag\":\"V\",\"keyClear\":\"%s\",\"kcv\":\"%s\","
            "\"keyLen\":%d,"
            "\"message\":\"Cle claire + KCV retournes (flag V) — usage maintenance uniquement\","
            "\"warning\":\"SENSIBLE — la cle est exposee en clair — utiliser flag H en production\"}",
            tesc, keyhex, kcv, LMK_KEY_LEN);
    } else {
        /* Étape 3b (flag H) : retourner KCV seulement, clé non révélée */
        secure_zero(key_clear, sizeof(key_clear));
        snprintf(out, n,
            "{\"rc\":0,\"cmd\":\"A8\",\"keyType\":\"%s\","
            "\"flag\":\"H\",\"kcv\":\"%s\",\"keyLen\":%d,"
            "\"message\":\"KCV retourne (flag H) — cle non revelee\"}",
            tesc, kcv, LMK_KEY_LEN);
    }
    {
        char line[144];
        snprintf(line, sizeof(line),
                 "A8 Consult Key: type=%s flag=%s KCV=%s%s",
                 keytype, flag_str, kcv,
                 show_clear ? " [CLE EN CLAIR RETOURNEE — SENSIBLE]" : "");
        audit_log(line);
    }
}

/* ── Module commandes additionnelles B2/NO/NI/NC/N0/BU ── */
#include "payhsm-cmds.c"

/* ── Module gestion des clés payShield 10K ── */
#include "payhsm-keymgr.c"

/* ── Registre commandes + dispatcher unifié (modes INTERNAL/PAYSHIELD/LAB) ── */
#include "payhsm-cmd-table.c"

/*
 * api_hsm_cmd_raw — Wrapper mince → CommandRegistry + hsm_dispatch_wire()
 *
 * Modes disponibles via POST /api/hsm/mode :
 *   INTERNAL        — formats pipe-étendus du projet (défaut, rétrocompatible)
 *   PAYSHIELD_COMPAT — inspiré payShield 10K [PS-INSPIRED, non officiel]
 *   LAB             — INTERNAL + A8 flag V autorisé (interdit en production)
 */
static void api_hsm_cmd_raw(const char *body, char *out, size_t n) {
    char cmd_str[512];
    cmd_str[0] = '\0';
    json_field(body, "cmd", cmd_str, sizeof(cmd_str));

    size_t cmdlen = strlen(cmd_str);
    if (cmdlen < 6) {
        snprintf(out, n,
            "{\"rc\":-1,\"errorCode\":\"02\","
            "\"message\":\"Trame trop courte (min 6 chars): [HDR:4][CMD:2][...]\"}");
        return;
    }

    char hdr[5];
    strncpy(hdr, cmd_str, 4); hdr[4] = '\0';
    hsm_dispatch_wire(hdr, cmd_str, cmdlen, out, n);
}

/* ── MK / Shamir Secret Sharing (2 étapes séparées) ── */

#define MK_FILE      "mk.bin"
#define SHARE1_FILE  "lmk_share_1.sss"
#define SHARE2_FILE  "lmk_share_2.sss"
#define SHARE3_FILE  "lmk_share_3.sss"

static int file_exists(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    fclose(f);
    return 1;
}

/* Sauvegarde une part (33 octets) en hex ASCII dans un fichier texte */
static int share_save(const char *path, const uint8_t share[SHAMIR_SHARE_LEN]) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    for (int i = 0; i < SHAMIR_SHARE_LEN; i++)
        fprintf(f, "%02x", share[i]);
    fprintf(f, "\n");
    fclose(f);
    return 0;
}

/* Charge une part depuis un fichier texte hex (66 chars) */
static int share_load(const char *path, uint8_t share[SHAMIR_SHARE_LEN]) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char buf[72] = {0};
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return -1; }
    fclose(f);
    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
        buf[--len] = '\0';
    if (len != 66) return -1;
    return hex_decode(buf, share, SHAMIR_SHARE_LEN);
}

/* ── Étape 0 : Génération de la MK ── */
static void api_mk_generate(const char *body, char *out, size_t n) {
    char pass[256] = {0}, dir[256] = {0}, mk_path[512] = {0};
    read_passphrase_json(body, pass, sizeof(pass));
    json_field(body, "dataDir", dir, sizeof(dir));

    if (!pass[0]) {
        snprintf(out, n,
            "{\"rc\":-1,\"message\":\"passphrase requise pour chiffrer la MK\"}");
        return;
    }
    if (!dir[0]) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"dataDir requis\"}");
        return;
    }
    mkdir(dir, 0700);   /* crée le répertoire si absent, ignore EEXIST */
    snprintf(mk_path, sizeof(mk_path), "%s/" MK_FILE, dir);

    uint8_t mk[32], kek[32], salt[PAYHSM_SALT_SIZE];
    if (RAND_bytes(mk, sizeof(mk)) != 1 || RAND_bytes(salt, sizeof(salt)) != 1) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"génération aléatoire MK échouée\"}");
        return;
    }
    if (kek_derive_from_passphrase(pass, salt, kek) != 0) {
        secure_zero(mk, sizeof(mk));
        snprintf(out, n, "{\"rc\":-1,\"message\":\"dérivation KEK échouée\"}");
        return;
    }
    if (lmk_store_create_with_salt(mk_path, kek, mk, salt) != 0) {
        secure_zero(mk, sizeof(mk));
        secure_zero(kek, sizeof(kek));
        snprintf(out, n, "{\"rc\":-1,\"message\":\"sauvegarde mk.bin échouée\"}");
        return;
    }
    secure_zero(mk, sizeof(mk));
    secure_zero(kek, sizeof(kek));
    secure_zero(salt, sizeof(salt));

    audit_log("MK générée et stockée dans mk.bin (AES-256-GCM) — parts SSS à générer");
    snprintf(out, n,
        "{\"rc\":0,\"message\":\"MK générée et stockée dans mk.bin (chiffrée AES-256-GCM)."
        " Procéder à la génération des parts SSS.\","
        "\"mkFile\":\"" MK_FILE "\",\"dataDir\":\"%s\"}",
        dir);
}

/* ── Statut : mk.bin + fichiers parts ── */
static void api_mk_status(const char *body, char *out, size_t n) {
    char dir[256] = {0};
    json_field(body, "dataDir", dir, sizeof(dir));
    if (!dir[0] && payhsm_ctx()->data_dir[0])
        snprintf(dir, sizeof(dir), "%s", payhsm_ctx()->data_dir);

    int mk_ok = 0, s1_ok = 0, s2_ok = 0, s3_ok = 0;
    if (dir[0]) {
        char p[512];
        snprintf(p, sizeof(p), "%s/" MK_FILE,     dir); mk_ok = file_exists(p);
        snprintf(p, sizeof(p), "%s/" SHARE1_FILE, dir); s1_ok = file_exists(p);
        snprintf(p, sizeof(p), "%s/" SHARE2_FILE, dir); s2_ok = file_exists(p);
        snprintf(p, sizeof(p), "%s/" SHARE3_FILE, dir); s3_ok = file_exists(p);
    }
    snprintf(out, n,
        "{\"rc\":0,\"mkExists\":%d,\"sharesReady\":%d,"
        "\"shares\":{\"admin1\":%d,\"admin2\":%d,\"admin3\":%d},"
        "\"dataDir\":\"%s\"}",
        mk_ok, (s1_ok && s2_ok && s3_ok) ? 1 : 0,
        s1_ok, s2_ok, s3_ok, dir);
}

/* ── TRNG : Initialiser LMK depuis mk.bin (sans SSS) ── */
static void api_lmk_init_trng(const char *body, char *out, size_t n) {
    char pass[256] = {0}, dir[256] = {0}, mk_path[512] = {0};
    read_passphrase_json(body, pass, sizeof(pass));
    json_field(body, "dataDir", dir, sizeof(dir));

    if (!dir[0] && payhsm_ctx()->data_dir[0])
        snprintf(dir, sizeof(dir), "%s", payhsm_ctx()->data_dir);
    if (!pass[0]) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"passphrase requise pour déchiffrer mk.bin\"}");
        return;
    }
    if (!dir[0]) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"dataDir requis\"}");
        return;
    }
    snprintf(mk_path, sizeof(mk_path), "%s/" MK_FILE, dir);

    if (!file_exists(mk_path)) {
        snprintf(out, n,
            "{\"rc\":-1,\"message\":\"mk.bin introuvable — générer la MK d'abord (mk-generate)\"}");
        return;
    }

    uint8_t mk[32], kek[32], salt[PAYHSM_SALT_SIZE];
    if (lmk_store_read_salt(mk_path, salt) != 0) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"lecture sel mk.bin échouée\"}");
        return;
    }
    if (kek_derive_from_passphrase(pass, salt, kek) != 0) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"dérivation KEK échouée\"}");
        return;
    }
    if (lmk_store_load(mk_path, kek, mk) != 0) {
        secure_zero(kek, sizeof(kek));
        snprintf(out, n,
            "{\"rc\":-1,\"message\":\"déchiffrement mk.bin échoué — passphrase incorrecte ?\"}");
        return;
    }
    secure_zero(kek, sizeof(kek));
    secure_zero(salt, sizeof(salt));

    int rc = payhsm_startup_from_mk(mk, dir);
    secure_zero(mk, sizeof(mk));

    if (rc != 0) {
        snprintf(out, n,
            "{\"rc\":-1,\"message\":\"initialisation HSM via TRNG échouée (rc=%d)\"}",
            rc);
        return;
    }

    payhsm_admin_reload_after_startup();
    audit_log("TRNG: MK chargée depuis mk.bin — LMK fragmentée P1/P2/P3");
    char esc_dir[256];
    json_escape(dir, esc_dir, sizeof(esc_dir));
    snprintf(out, n,
        "{\"rc\":0,\"message\":\"LMK initialisée via TRNG (mk.bin déchiffré, MK effacée)."
        " HSM prêt. LMK fragmentée en P1/P2/P3.\","
        "\"dataDir\":\"%s\",\"initialized\":1}",
        esc_dir);
}

/* ── Étape 1 : Génération des 3 parts SSS depuis la MK ── */
static void api_shamir_generate(const char *body, char *out, size_t n) {
    char pass[256] = {0}, dir[256] = {0}, mk_path[512] = {0};
    read_passphrase_json(body, pass, sizeof(pass));
    json_field(body, "dataDir", dir, sizeof(dir));

    if (!dir[0] && payhsm_ctx()->data_dir[0])
        snprintf(dir, sizeof(dir), "%s", payhsm_ctx()->data_dir);
    if (!pass[0]) {
        snprintf(out, n,
            "{\"rc\":-1,\"message\":\"passphrase requise pour déchiffrer la MK\"}");
        return;
    }
    if (!dir[0]) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"dataDir requis\"}");
        return;
    }
    snprintf(mk_path, sizeof(mk_path), "%s/" MK_FILE, dir);

    /* Règle : la MK doit exister avant de générer les parts */
    if (!file_exists(mk_path)) {
        snprintf(out, n,
            "{\"rc\":-1,"
            "\"message\":\"Impossible de générer les parts SSS : aucune MK n'a été générée.\","
            "\"hint\":\"Utiliser d'abord /api/lmk/mk-generate\"}");
        return;
    }

    /* Charger la MK chiffrée */
    uint8_t mk[32], kek[32], salt[PAYHSM_SALT_SIZE];
    if (lmk_store_read_salt(mk_path, salt) != 0) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"lecture sel mk.bin échouée\"}");
        return;
    }
    if (kek_derive_from_passphrase(pass, salt, kek) != 0) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"dérivation KEK échouée\"}");
        return;
    }
    if (lmk_store_load(mk_path, kek, mk) != 0) {
        secure_zero(kek, sizeof(kek));
        snprintf(out, n,
            "{\"rc\":-1,\"message\":\"déchiffrement mk.bin échoué — passphrase incorrecte ?\"}");
        return;
    }
    secure_zero(kek, sizeof(kek));
    secure_zero(salt, sizeof(salt));

    /* Diviser la MK en 3 parts */
    uint8_t shares[3][SHAMIR_SHARE_LEN];
    if (shamir_split(mk, shares) != 0) {
        secure_zero(mk, sizeof(mk));
        snprintf(out, n, "{\"rc\":-1,\"message\":\"Shamir split échoué\"}");
        return;
    }
    secure_zero(mk, sizeof(mk));

    /* Répertoire de sortie des .sss (optionnel — mk.bin reste dans dataDir) */
    char share_dir[256];
    json_field(body, "shareDir", share_dir, sizeof(share_dir));
    if (!share_dir[0])
        snprintf(share_dir, sizeof(share_dir), "%s", dir);
    mkdir(share_dir, 0700);

    char sp1[512], sp2[512], sp3[512];
    snprintf(sp1, sizeof(sp1), "%s/" SHARE1_FILE, share_dir);
    snprintf(sp2, sizeof(sp2), "%s/" SHARE2_FILE, share_dir);
    snprintf(sp3, sizeof(sp3), "%s/" SHARE3_FILE, share_dir);

    int err = (share_save(sp1, shares[0]) != 0 ||
               share_save(sp2, shares[1]) != 0 ||
               share_save(sp3, shares[2]) != 0);
    secure_zero(shares, sizeof(shares));

    if (err) {
        snprintf(out, n,
            "{\"rc\":-1,\"message\":\"sauvegarde fichiers parts SSS échouée\"}");
        return;
    }

    audit_log("Shamir: 3 parts LMK générées → lmk_share_1.sss, lmk_share_2.sss, lmk_share_3.sss");
    char esc_share[256];
    json_escape(share_dir, esc_share, sizeof(esc_share));
    snprintf(out, n,
        "{\"rc\":0,"
        "\"message\":\"Les 3 parts SSS ont été générées et stockées avec succès.\","
        "\"files\":[\"" SHARE1_FILE "\",\"" SHARE2_FILE "\",\"" SHARE3_FILE "\"],"
        "\"dataDir\":\"%s\",\"shareDir\":\"%s\",\"threshold\":\"3/3\"}",
        dir, esc_share);
}

/* ── Étape 2 : Reconstruction MK depuis les 3 parts + init HSM ── */
static void api_shamir_reconstruct(const char *body, char *out, size_t n) {
    char dir[256] = {0};
    json_field(body, "dataDir", dir, sizeof(dir));
    if (!dir[0] && payhsm_ctx()->data_dir[0])
        snprintf(dir, sizeof(dir), "%s", payhsm_ctx()->data_dir);
    if (!dir[0]) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"dataDir requis\"}");
        return;
    }

    uint8_t shares[3][SHAMIR_SHARE_LEN];
    int from_files = 0;
    int from_upload = 0;

    /* Priorité 1 : parts envoyées par l'UI (fichiers choisis dans le navigateur) */
    {
        char s1[SHAMIR_SHARE_HEX], s2[SHAMIR_SHARE_HEX], s3[SHAMIR_SHARE_HEX];
        if (json_field(body, "share1", s1, sizeof(s1)) == 0 &&
            json_field(body, "share2", s2, sizeof(s2)) == 0 &&
            json_field(body, "share3", s3, sizeof(s3)) == 0 &&
            strlen(s1) == 66 && strlen(s2) == 66 && strlen(s3) == 66) {
            if (hex_decode(s1, shares[0], SHAMIR_SHARE_LEN) == 0 &&
                hex_decode(s2, shares[1], SHAMIR_SHARE_LEN) == 0 &&
                hex_decode(s3, shares[2], SHAMIR_SHARE_LEN) == 0)
                from_upload = 1;
        }
    }

    /* Priorité 2 : lire lmk_share_*.sss sur disque (shareDir optionnel, sinon dataDir) */
    if (!from_upload) {
        char share_dir[256] = {0};
        json_field(body, "shareDir", share_dir, sizeof(share_dir));
        const char *scan = share_dir[0] ? share_dir : dir;
        char sp1[512], sp2[512], sp3[512];
        snprintf(sp1, sizeof(sp1), "%s/" SHARE1_FILE, scan);
        snprintf(sp2, sizeof(sp2), "%s/" SHARE2_FILE, scan);
        snprintf(sp3, sizeof(sp3), "%s/" SHARE3_FILE, scan);

        if (file_exists(sp1) && file_exists(sp2) && file_exists(sp3)) {
            if (share_load(sp1, shares[0]) == 0 &&
                share_load(sp2, shares[1]) == 0 &&
                share_load(sp3, shares[2]) == 0)
                from_files = 1;
        }
    }

    if (!from_upload && !from_files) {
        snprintf(out, n,
            "{\"rc\":-1,\"message\":\"Parts SSS introuvables — "
            "sélectionnez les 3 fichiers .sss ou placez-les dans shareDir/dataDir\"}");
        return;
    }

    uint8_t mk[32];
    if (shamir_reconstruct(shares, mk) != 0) {
        secure_zero(shares, sizeof(shares));
        snprintf(out, n,
            "{\"rc\":-1,\"message\":\"Shamir reconstruct échoué — indices invalides ou parts dupliquées\"}");
        return;
    }
    secure_zero(shares, sizeof(shares));

    int rc = payhsm_startup_from_mk(mk, dir);
    secure_zero(mk, sizeof(mk));

    if (rc != 0) {
        snprintf(out, n,
            "{\"rc\":-1,\"message\":\"initialisation HSM depuis MK échouée (rc=%d)\"}",
            rc);
        return;
    }

    payhsm_admin_reload_after_startup();
    const char *src = from_upload ? "fichiers UI (upload)"
                    : (from_files ? "fichiers lmk_share_*.sss" : "parts");
    audit_log("Shamir: MK reconstituée (3/3) — HSM initialisé, LMK fragmentée P1/P2/P3");
    char esc_dir[256];
    json_escape(dir, esc_dir, sizeof(esc_dir));
    snprintf(out, n,
        "{\"rc\":0,\"message\":\"MK reconstituée — HSM initialisé. LMK fragmentée en P1/P2/P3."
        " Si le Switch était provisionné pour cette LMK, son état est restauré depuis switch_state.bin.\","
        "\"source\":\"%s\",\"dataDir\":\"%s\",\"initialized\":1}",
        src, esc_dir);
}

/* ── Module administration Switch/ATM (inclus en compilation unique) ── */
#include "payhsm-admin.c"

static void provision_unlink(const char *dir, const char *name) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    unlink(path);
}

/* Provision = nouvel HSM : arrêt, effacement artefacts LMK/coffre/Switch admin */
static void api_provision(const char *body, char *out, size_t n) {
    char dir[256] = {0};
    json_field(body, "dataDir", dir, sizeof(dir));
    if (!dir[0]) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"Répertoire données manquant\"}");
        return;
    }
    struct stat st_chk;
    if (stat(dir, &st_chk) != 0) {
        if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
            snprintf(out, n, "{\"rc\":-1,\"message\":\"Impossible de créer le répertoire : %s\"}", strerror(errno));
            return;
        }
    }

    payhsm_shutdown();
    static const char *const WIPE[] = {
        "mk.bin", "lmk.bin", "keys.vault", "ext_keys.vault", "cards.pvv",
        "lmk_share_1.sss", "lmk_share_2.sss", "lmk_share_3.sss",
        NULL
    };
    for (int i = 0; WIPE[i]; i++)
        provision_unlink(dir, WIPE[i]);
    payhsm_admin_reset_on_new_provision(dir);

    audit_log("Provision HSM — reset complet (nouvelle LMK requise via panneau LMK)");
    char esc_dir[256];
    json_escape(dir, esc_dir, sizeof(esc_dir));
    snprintf(out, n,
        "{\"rc\":0,\"message\":\"Nouveau cycle HSM : ancienne LMK et coffre effacés. "
        "Étapes : (1) LMK T0 mk-generate + parts SSS, (2) reconstruction SSS ou init TRNG, "
        "(3) Démarrer HSM, (4) SWITCH INIT puis SWITCH PROVISION, "
        "(5) simulation : POST /api/switch/init puis provision-keys.\","
        "\"dataDir\":\"%s\",\"reset\":1}",
        esc_dir);
}

static void dispatch_api(const char *path, const char *method, const char *body, char *out, size_t n) {
    if (strcmp(path, "/api/health") == 0) api_health(out, n);
    else if (strcmp(path, "/api/status") == 0) api_status(out, n);
    else if (strcmp(path, "/api/provision") == 0) api_provision(body, out, n);
    else if (strcmp(path, "/api/startup") == 0) api_startup(body, out, n);
    else if (strcmp(path, "/api/register") == 0) api_register(body, out, n);
    else if (strcmp(path, "/api/corebanking/issue") == 0) api_corebanking_issue(body, out, n);
    else if (strcmp(path, "/api/corebanking/lookup") == 0) api_corebanking_lookup(body, out, n);
    else if (strcmp(path, "/api/gap") == 0) api_gap(body, out, n);
    else if (strcmp(path, "/api/verify") == 0) api_verify(body, out, n);
    else if (strcmp(path, "/api/translate") == 0) api_translate(body, out, n);
    else if (strcmp(path, "/api/translate-zpk") == 0) api_translate_zpk(body, out, n);
    else if (strcmp(path, "/api/verify-zpk") == 0) api_verify_zpk(body, out, n);
    else if (strcmp(path, "/api/vault") == 0) api_vault_list(out, n);
    else if (strcmp(path, "/api/vault/clear") == 0) api_vault_clear(out, n);
    else if (strcmp(path, "/api/kcv") == 0) api_kcv(body, out, n);
    else if (strcmp(path, "/api/mac/calc") == 0) api_mac_calc(body, out, n);
    else if (strcmp(path, "/api/mac/verify") == 0) api_mac_verify(body, out, n);
    else if (strcmp(path, "/api/emv/arqc") == 0) api_emv_arqc(body, out, n);
    else if (strcmp(path, "/api/emv/verify") == 0) api_emv_verify(body, out, n);
    else if (strcmp(path, "/api/emv/verify-arpc") == 0) api_emv_verify_arpc(body, out, n);
    else if (strcmp(path, "/api/emv/purchase") == 0) api_emv_purchase(body, out, n);
    else if (strcmp(path, "/api/payment/modules") == 0) api_payment_modules(out, n);
    else if (strcmp(path, "/api/lmk/mutate") == 0) {
        int rc = payhsm_mutate_lmk_fragments();
        if (rc == 0) audit_log("mutation fragments LMK");
        snprintf(out, n, "{\"rc\":%d,\"message\":\"%s\"}", rc,
                 rc == 0 ? "mutation OK" : "echec mutation");
    }
    else if (strcmp(path, "/api/lmk/status") == 0) api_lmk_status(out, n);
    else if (strcmp(path, "/api/lmk/fragments") == 0) api_lmk_fragments(out, n);
    else if (strcmp(path, "/api/lmk/mk-generate") == 0) api_mk_generate(body, out, n);
    else if (strcmp(path, "/api/lmk/mk-status") == 0) api_mk_status(body, out, n);
    else if (strcmp(path, "/api/lmk/shamir-generate") == 0) api_shamir_generate(body, out, n);
    else if (strcmp(path, "/api/lmk/shamir-reconstruct") == 0) api_shamir_reconstruct(body, out, n);
    else if (strcmp(path, "/api/lmk/init-trng") == 0) api_lmk_init_trng(body, out, n);
    else if (strcmp(path, "/api/security/logs") == 0) api_security_logs(out, n);
    else if (strcmp(path, "/api/vault/export") == 0) api_vault_export(out, n);
    else if (strncmp(path, "/api/hsm/transport-gcm", 22) == 0) {
        const char *q = strchr(path, '?');
        api_transport_gcm(q ? q + 1 : NULL, out, n);
    }
    else if (strcmp(path, "/api/ext/vault") == 0) handle_EKM_LIST(out, n);
    else if (strcmp(path, "/api/switch/derive-terminal") == 0) api_keys_derive_terminal(body, out, n);
    else if (strcmp(path, "/api/switch/wrap-key") == 0) api_wrap_key(body, out, n);
    else if (strcmp(path, "/api/switch/wrap-zpk") == 0) api_wrap_zpk(body, out, n);
    /* ── Admin Switch ── */
    else if (strcmp(path, "/api/admin/switch/init") == 0) api_admin_switch_init(out, n);
    else if (strcmp(path, "/api/admin/switch/status") == 0) api_admin_switch_status(out, n);
    else if (strcmp(path, "/api/admin/switch/provision") == 0) api_admin_switch_provision(out, n);
    else if (strcmp(path, "/api/admin/switch/logs") == 0) api_admin_switch_logs(out, n);
    /* ── Admin ATM ── */
    else if (strcmp(path, "/api/admin/atm/add") == 0) api_admin_atm_add(body, out, n);
    else if (strcmp(path, "/api/admin/atm/list") == 0) api_admin_atm_list(out, n);
    else if (strcmp(path, "/api/admin/atm/status") == 0) api_admin_atm_status(body, out, n);
    else if (strcmp(path, "/api/admin/atm/provision") == 0) api_admin_atm_provision(body, out, n);
    else if (strcmp(path, "/api/admin/atm/enable") == 0) api_admin_atm_set_status(body, out, n, ATM_ACTIVE);
    else if (strcmp(path, "/api/admin/atm/disable") == 0) api_admin_atm_set_status(body, out, n, ATM_INACTIVE);
    else if (strcmp(path, "/api/admin/atm/block") == 0) api_admin_atm_set_status(body, out, n, ATM_BLOCKED);
    else if (strcmp(path, "/api/admin/atm/remove") == 0) api_admin_atm_remove(body, out, n);
    else if (strcmp(path, "/api/admin/atm/kcv") == 0) api_admin_atm_kcv(body, out, n);
    else if (strcmp(path, "/api/admin/atm/connect") == 0) api_admin_atm_connect(body, out, n);
    else if (strcmp(path, "/api/admin/atm/disconnect") == 0) api_admin_atm_disconnect(body, out, n);
    else if (strcmp(path, "/api/admin/atm/rotate-keys") == 0) api_admin_atm_rotate(body, out, n);
    else if (strcmp(path, "/api/lmk/encrypt") == 0) api_lmk_encrypt(body, out, n);
    else if (strcmp(path, "/api/lmk/decrypt") == 0) api_lmk_decrypt(body, out, n);
    else if (strcmp(path, "/api/hsm/a0") == 0) api_hsm_a0(body, out, n);
    else if (strcmp(path, "/api/hsm/a6") == 0) api_hsm_a6(body, out, n);
    else if (strcmp(path, "/api/hsm/a8") == 0) api_hsm_a8(body, out, n);
    else if (strcmp(path, "/api/key-exchange/export-under-zmk") == 0)
        api_key_exchange_export_under_zmk(body, out, n);
    else if (strcmp(path, "/api/key-exchange/import") == 0)
        api_key_exchange_import(body, out, n);
    else if (strcmp(path, "/api/hsm/cmd") == 0) api_hsm_cmd_raw(body, out, n);
    else if (strcmp(path, "/api/hsm/mode") == 0 && strcmp(method, "GET")  == 0) api_hsm_mode_get(out, n);
    else if (strcmp(path, "/api/hsm/mode") == 0 && strcmp(method, "POST") == 0) api_hsm_mode_set(body, out, n);
    else if (strcmp(path, "/api/shutdown") == 0) {
        audit_log("shutdown HSM");
        payhsm_emv_clear_session();
        payhsm_shutdown();
        snprintf(out, n, "{\"rc\":0,\"message\":\"HSM arrete\"}");
    } else snprintf(out, n, "{\"rc\":-1,\"message\":\"route inconnue\"}");
}

static int serve_static(int fd, const char *path) {
    char file[768];
    char clean[256];
    strncpy(clean, path, sizeof(clean) - 1);
    clean[sizeof(clean) - 1] = '\0';
    char *q = strchr(clean, '?');
    if (q) *q = '\0';
    path = clean;
    if (strcmp(path, "/") == 0) path = "/index.html";
    /* Anti path traversal sur l'URL seulement (pas sur STATIC_ROOT qui peut contenir "..") */
    if (strstr(path, "..") || strchr(path, '\\')) {
        http_reply(fd, 403, "text/plain", "Forbidden");
        return 0;
    }
    snprintf(file, sizeof(file), "%s%s", g_static_root, path);
    FILE *f = fopen(file, "rb");
    if (!f) {
        http_reply(fd, 404, "text/plain", "Not found");
        return 0;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *body = (char *)malloc((size_t)sz + 1);
    if (!body) { fclose(f); return -1; }
    fread(body, 1, (size_t)sz, f);
    body[sz] = '\0';
    fclose(f);
    const char *ct = "application/octet-stream";
    if      (strstr(path, ".html")) ct = "text/html; charset=utf-8";
    else if (strstr(path, ".css"))  ct = "text/css";
    else if (strstr(path, ".js"))   ct = "application/javascript";
    else if (strstr(path, ".png"))  ct = "image/png";
    else if (strstr(path, ".jpg") || strstr(path, ".jpeg")) ct = "image/jpeg";
    else if (strstr(path, ".svg"))  ct = "image/svg+xml";
    else if (strstr(path, ".ico"))  ct = "image/x-icon";
    {
        char hdr[640];
        snprintf(hdr, sizeof(hdr),
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: %s\r\n"
                 "Content-Length: %ld\r\n"
                 "Cache-Control: no-cache\r\n"
                 "Access-Control-Allow-Origin: *\r\n"
                 "Connection: close\r\n\r\n",
                 ct, sz);
        send(fd, hdr, strlen(hdr), 0);
        if (body && sz > 0) send(fd, body, (size_t)sz, 0);
    }
    free(body);
    return 0;
}

static void handle_client(int fd) {
    char *req = (char *)malloc(HTTP_BUF);
    char *resp = (char *)calloc(1, HTTP_BUF);  /* calloc garantit resp[0]=' ' */
    if (!req || !resp) { free(req); free(resp); close(fd); return; }

    int n = read_request(fd, req, HTTP_BUF);
    if (n <= 0) { free(req); free(resp); close(fd); return; }

    if (strncmp(req, "OPTIONS", 7) == 0) {
        http_reply(fd, 200, "text/plain", "");
        free(req); free(resp); close(fd);
        return;
    }

    char method[16], path[256];
    sscanf(req, "%15s %255s", method, path);

    if (strncmp(path, "/api/", 5) == 0) {
        /* read_request() a déjà lu le corps complet (Content-Length octets). */
        const char *body = request_body(req);
        pthread_mutex_lock(&g_dispatch_lock);
        dispatch_api(path, method, body, resp, HTTP_BUF);
        pthread_mutex_unlock(&g_dispatch_lock);
        send_json(fd, 200, resp);
    } else if (strcmp(method, "GET") == 0) {
        serve_static(fd, path);
    } else {
        http_reply(fd, 405, "text/plain", "Method not allowed");
    }

    free(req);
    free(resp);
    close(fd);
}

/* ════════════════════════════════════════════════════════════════════════
   SERVEUR TCP BRUT HSM (mode "wire" sans framing ISO 8583)
   ────────────────────────────────────────────────────────────────────────
   Le client envoie une trame HSM brute, ex :   0001B2HELLO
   Le serveur répond la trame brute, ex     :   0001B300HELLO

   - Réutilise le dispatcher existant hsm_dispatch_wire() (aucune logique dupliquée).
   - Indépendant du serveur ISO 8583 (net/tcp_server.c) qui lui garde son
     framing longueur 2 octets — on ne casse pas l'existant.
   - Port configurable via env PAYHSM_TCP_PORT (défaut 1500 ; 0 = désactivé).
   - TLS optionnel : PAYHSM_TCP_TLS=1 + PAYHSM_TCP_CERT + PAYHSM_TCP_KEY.
     TLS mal configuré → message clair + repli TCP simple.
     TLS désactivé    → warning "TLS disabled: development mode only".
   - Sécurité : log = code commande (2 lettres) + longueur ; jamais de clé/PIN.
   - Concurrence : g_dispatch_lock sérialise l'accès au HSM (partagé avec HTTP).
   ════════════════════════════════════════════════════════════════════════ */

/* Extrait la valeur de "rawResponse":"..." du JSON renvoyé par le dispatcher. */
static void extract_raw_response(const char *json, char *out, size_t cap) {
    out[0] = '\0';
    const char *key = "\"rawResponse\":\"";
    const char *p = strstr(json, key);
    if (!p) return;
    p += strlen(key);
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < cap) out[i++] = *p++;
    out[i] = '\0';
}

/* Trame brute → réponse brute. Sérialisé via g_dispatch_lock. */
static void raw_dispatch_locked(const char *frame, size_t flen,
                                char *raw_out, size_t cap) {
    raw_out[0] = '\0';
    if (flen < 6) {
        snprintf(raw_out, cap, "%.4sFE02", flen >= 4 ? frame : "0000");
        return;
    }
    char hdr[5];
    strncpy(hdr, frame, 4); hdr[4] = '\0';

    char json[HTTP_BUF];
    pthread_mutex_lock(&g_dispatch_lock);
    hsm_dispatch_wire(hdr, frame, flen, json, sizeof(json));
    pthread_mutex_unlock(&g_dispatch_lock);

    extract_raw_response(json, raw_out, cap);
}

typedef struct { int fd; SSL *ssl; } raw_conn_t;
typedef struct { int port; SSL_CTX *ctx; } raw_srv_t;

/* Lit une trame : jusqu'à fin de ligne (\r ou \n), EOF (half-close type nc),
   buffer plein, ou timeout SO_RCVTIMEO. */
static int raw_read(raw_conn_t *c, char *buf, size_t cap) {
    size_t n = 0;
    while (n + 1 < cap) {
        int r = c->ssl ? SSL_read(c->ssl, buf + n, (int)(cap - n - 1))
                       : (int)recv(c->fd, buf + n, cap - n - 1, 0);
        if (r <= 0) break;
        n += (size_t)r;
        buf[n] = '\0';
        char *nl = strpbrk(buf, "\r\n");
        if (nl) { *nl = '\0'; n = (size_t)(nl - buf); break; }
    }
    return (int)n;
}

static void *raw_conn_thread(void *arg) {
    raw_conn_t *c = (raw_conn_t *)arg;
    if (c->ssl && SSL_accept(c->ssl) <= 0) goto done;

    char frame[1024], raw[2048];
    int n = raw_read(c, frame, sizeof(frame));
    if (n >= 1) {
        raw_dispatch_locked(frame, (size_t)n, raw, sizeof(raw));
        /* Log non sensible : seules les 2 lettres de commande + longueurs. */
        fprintf(stderr, "[tcp] cmd=%c%c len=%d -> %zu octets\n",
                n >= 6 ? frame[4] : '?', n >= 6 ? frame[5] : '?',
                n, strlen(raw));
        if (raw[0]) {
            if (c->ssl) SSL_write(c->ssl, raw, (int)strlen(raw));
            else        send(c->fd, raw, strlen(raw), 0);
        }
    }
done:
    if (c->ssl) { SSL_shutdown(c->ssl); SSL_free(c->ssl); }
    close(c->fd);
    free(c);
    return NULL;
}

static void *raw_tcp_server_thread(void *arg) {
    raw_srv_t *s = (raw_srv_t *)arg;

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("[tcp] socket"); free(s); return NULL; }
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((uint16_t)s->port);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[tcp] bind port %d échec (%s) — mode TCP brut désactivé\n",
                s->port, strerror(errno));
        close(srv); if (s->ctx) SSL_CTX_free(s->ctx); free(s);
        return NULL;
    }
    if (listen(srv, 16) < 0) {
        perror("[tcp] listen");
        close(srv); if (s->ctx) SSL_CTX_free(s->ctx); free(s);
        return NULL;
    }
    fprintf(stderr, "[tcp] HSM brut sur 0.0.0.0:%d (TLS=%s)\n",
            s->port, s->ctx ? "oui" : "non");

    for (;;) {
        int cfd = accept(srv, NULL, NULL);
        if (cfd < 0) { if (errno == EINTR) continue; perror("[tcp] accept"); break; }

        /* Sans framing de longueur, on détecte la fin de trame par inactivité.
           1s : assez court pour que `nc` (sans half-close) reçoive vite la
           réponse, assez long pour un client piped. Pour une réponse instantanée,
           terminer la trame par '\n' (géré dans raw_read). */
        struct timeval tv = { 1, 0 };
        setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        raw_conn_t *c = (raw_conn_t *)calloc(1, sizeof(*c));
        if (!c) { close(cfd); continue; }
        c->fd = cfd;
        if (s->ctx) { c->ssl = SSL_new(s->ctx); SSL_set_fd(c->ssl, cfd); }

        pthread_t tid; pthread_attr_t at;
        pthread_attr_init(&at);
        pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&tid, &at, raw_conn_thread, c) != 0) { free(c); close(cfd); }
        pthread_attr_destroy(&at);
    }
    close(srv); if (s->ctx) SSL_CTX_free(s->ctx); free(s);
    return NULL;
}

/* Lance le serveur TCP brut dans un thread si PAYHSM_TCP_PORT != 0. */
static void raw_tcp_start_if_configured(void) {
    int port = 1500;
    const char *ps = getenv("PAYHSM_TCP_PORT");
    if (ps && ps[0]) port = atoi(ps);
    if (port <= 0) { fprintf(stderr, "[tcp] désactivé (PAYHSM_TCP_PORT=%d)\n", port); return; }

    SSL_CTX *ctx = NULL;
    const char *tls = getenv("PAYHSM_TCP_TLS");
    if (tls && (tls[0] == '1' || tls[0] == 'y' || tls[0] == 'Y')) {
        const char *cert = getenv("PAYHSM_TCP_CERT");
        const char *key  = getenv("PAYHSM_TCP_KEY");
        if (!cert || !cert[0] || !key || !key[0]) {
            fprintf(stderr, "[tcp] TLS demandé mais PAYHSM_TCP_CERT/PAYHSM_TCP_KEY "
                            "manquants — repli TCP simple\n");
        } else {
            SSL_load_error_strings();
            OpenSSL_add_ssl_algorithms();
            ctx = SSL_CTX_new(TLS_server_method());
            if (!ctx ||
                SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0 ||
                SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
                fprintf(stderr, "[tcp] TLS: chargement cert/clé échec — repli TCP simple\n");
                if (ctx) { SSL_CTX_free(ctx); ctx = NULL; }
            } else {
                SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
                fprintf(stderr, "[tcp] TLS activé (cert=%s)\n", cert);
            }
        }
    }
    if (!ctx)
        fprintf(stderr, "[tcp] TLS disabled: development mode only\n");

    raw_srv_t *s = (raw_srv_t *)calloc(1, sizeof(*s));
    if (!s) { if (ctx) SSL_CTX_free(ctx); return; }
    s->port = port; s->ctx = ctx;

    pthread_t tid; pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&tid, &at, raw_tcp_server_thread, s) != 0) {
        if (ctx) SSL_CTX_free(ctx);
        free(s);
    }
    pthread_attr_destroy(&at);
}

/* Exported: run the HTTP admin server (blocks until socket error). */
void payhsm_httpd_serve(int port, const char *static_root)
{
    signal(SIGPIPE, SIG_IGN);
    g_start_time  = time(NULL);
    g_server_port = port;
    raw_tcp_start_if_configured();   /* démarre le mode TCP brut HSM (port séparé) */
    if (static_root && static_root[0])
        strncpy(g_static_root, static_root, sizeof(g_static_root) - 1);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return; }
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(srv); return;
    }
    if (listen(srv, 16) < 0) { perror("listen"); close(srv); return; }

    fprintf(stderr, "[http] admin on http://127.0.0.1:%d\n", port);

    for (;;) {
        struct sockaddr_in cli;
        socklen_t clen = sizeof(cli);
        int cfd = accept(srv, (struct sockaddr *)&cli, &clen);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }
        handle_client(cfd);
    }
    close(srv);
}

#ifndef PAYHSM_HTTPD_NO_MAIN
int main(int argc, char **argv) {
    int port = 8765;
    if (argc > 1) port = atoi(argv[1]);
    const char *sroot = argc > 2 ? argv[2] : NULL;
    payhsm_httpd_serve(port, sroot);
    return 0;
}
#endif /* PAYHSM_HTTPD_NO_MAIN */
