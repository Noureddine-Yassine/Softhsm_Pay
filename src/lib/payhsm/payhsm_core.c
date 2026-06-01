#include "payhsm_core.h"
#include "payhsm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <openssl/rand.h>

#define VAULT_FILE "keys.vault"
#define LMK_FILE   "lmk.bin"
#define PVV_FILE   "cards.pvv"

typedef struct {
    char pan[20];
    char pvv[5];
} pvv_entry_t;

static payhsm_ctx_t    g_ctx;
static pvv_entry_t     g_pvv[256];
static int             g_pvv_count;
static unsigned long   g_boot_id;

static const char *lookup_pvv(const char *pan);

payhsm_ctx_t *payhsm_ctx(void) { return &g_ctx; }

static void path_join(char *out, size_t n, const char *dir, const char *file) {
    snprintf(out, n, "%s/%s", dir, file);
}

static int ensure_data_dir(const char *data_dir) {
    char tmp[PAYHSM_PATH_MAX];
    size_t len;

    if (!data_dir || !data_dir[0]) return PAYHSM_RC_ERR;
    strncpy(tmp, data_dir, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    len = strlen(tmp);
    if (len == 0) return PAYHSM_RC_ERR;
    if (tmp[len - 1] == '/') tmp[len - 1] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(tmp, 0700) != 0 && errno != EEXIST) {
            perror("[PAYHSM] mkdir");
            return PAYHSM_RC_ERR;
        }
        *p = '/';
    }
    if (mkdir(tmp, 0700) != 0 && errno != EEXIST) {
        perror("[PAYHSM] mkdir");
        return PAYHSM_RC_ERR;
    }
    return PAYHSM_RC_OK;
}

static int with_lmk(void (*fn)(const uint8_t lmk[32], void *arg), void *arg) {
    if (!g_ctx.initialized) return PAYHSM_RC_NOT_INIT;
    if (check_integrity() != 0) return PAYHSM_RC_ERR;
    uint8_t lmk[32];
    if (recompose_for_op(lmk) != 0) return PAYHSM_RC_ERR;
    fn(lmk, arg);
    secure_zero(lmk, sizeof(lmk));
    return PAYHSM_RC_OK;
}

typedef struct {
    payhsm_key_type_t type;
    const char       *terminal_id;
    uint8_t          *key_out;
} unwrap_arg_t;

static int g_unwrap_ok;

static void unwrap_cb(const uint8_t lmk[32], void *v) {
    unwrap_arg_t *a = (unwrap_arg_t *)v;
    const payhsm_key_entry_t *e = NULL;
    g_unwrap_ok = 0;
    if (vault_find(&g_ctx.vault, a->type, a->terminal_id, &e) != 0 || !e)
        return;
    if (vault_decrypt_under_lmk(lmk, e->enc, a->key_out) != 0)
        return;
    g_unwrap_ok = 1;
}

int payhsm_unwrap_key(payhsm_key_type_t type,
                      const char *terminal_id,
                      uint8_t key_out[PAYHSM_KEY_LEN]) {
    unwrap_arg_t a = { type, terminal_id, key_out };
    g_unwrap_ok = 0;
    memset(key_out, 0, PAYHSM_KEY_LEN);
    if (with_lmk(unwrap_cb, &a) != PAYHSM_RC_OK) return PAYHSM_RC_ERR;
    return g_unwrap_ok ? PAYHSM_RC_OK : PAYHSM_RC_ERR;
}

static int store_key_from_label(const char *id,
                                payhsm_key_type_t type,
                                const char *terminal_id,
                                const char *label) {
    uint8_t key[PAYHSM_KEY_LEN], enc[PAYHSM_KEY_LEN], kcv[PAYHSM_KCV_LEN];
    uint8_t lmk[32];

    if (check_integrity() != 0) return PAYHSM_RC_ERR;
    if (recompose_for_op(lmk) != 0) return PAYHSM_RC_ERR;
    if (vault_derive_from_lmk(lmk, label, key) != 0) {
        secure_zero(lmk, sizeof(lmk));
        return PAYHSM_RC_ERR;
    }
    vault_encrypt_under_lmk(lmk, key, enc);
    compute_kcv(key, PAYHSM_KEY_LEN, kcv);
    secure_zero(lmk, sizeof(lmk));
    secure_zero(key, sizeof(key));
    return vault_add_key(&g_ctx.vault, id, type, terminal_id, enc, kcv);
}

static int store_derived_terminal_keys(const char *term) {
    char id[64];
    uint8_t tmk[PAYHSM_KEY_LEN], tpk[PAYHSM_KEY_LEN], tak[PAYHSM_KEY_LEN];
    uint8_t enc[PAYHSM_KEY_LEN], kcv[PAYHSM_KCV_LEN], lmk[32];

    if (payhsm_unwrap_key(PAYHSM_KEY_TMK, term, tmk) != PAYHSM_RC_OK)
        return PAYHSM_RC_ERR;
    derive_tpk_from_tmk(tmk, PAYHSM_KEY_LEN, term, tpk);
    derive_tak_from_tmk(tmk, PAYHSM_KEY_LEN, term, tak);

    if (recompose_for_op(lmk) != 0) {
        secure_zero(tmk, sizeof(tmk));
        secure_zero(tpk, sizeof(tpk));
        secure_zero(tak, sizeof(tak));
        return PAYHSM_RC_ERR;
    }
    snprintf(id, sizeof(id), "TPK-%s", term);
    vault_encrypt_under_lmk(lmk, tpk, enc);
    compute_kcv(tpk, PAYHSM_KEY_LEN, kcv);
    vault_add_key(&g_ctx.vault, id, PAYHSM_KEY_TPK, term, enc, kcv);

    snprintf(id, sizeof(id), "TAK-%s", term);
    vault_encrypt_under_lmk(lmk, tak, enc);
    compute_kcv(tak, PAYHSM_KEY_LEN, kcv);
    vault_add_key(&g_ctx.vault, id, PAYHSM_KEY_TAK, term, enc, kcv);

    secure_zero(tmk, sizeof(tmk));
    secure_zero(tpk, sizeof(tpk));
    secure_zero(tak, sizeof(tak));
    secure_zero(lmk, sizeof(lmk));
    return PAYHSM_RC_OK;
}

static int provision_keys(const char *const *terminals, int n_terminals) {
    char label[128], id[64];

    if (store_key_from_label("ZMK-VISA", PAYHSM_KEY_ZMK, "", "ZMK:VISA:INTER") != 0)
        return PAYHSM_RC_ERR;
    if (store_key_from_label("PVK-VISA", PAYHSM_KEY_PVK, "", "PVK:VISA:ISSUER") != 0)
        return PAYHSM_RC_ERR;
    if (store_key_from_label("IMK-BANK", PAYHSM_KEY_IMK, "", "IMK:BANK:EMV") != 0)
        return PAYHSM_RC_ERR;

    uint8_t zpk[PAYHSM_KEY_LEN], zpk_enc[PAYHSM_KEY_LEN], kcv[PAYHSM_KCV_LEN];
    uint8_t lmk[32];
    if (recompose_for_op(lmk) != 0) return PAYHSM_RC_ERR;
    if (RAND_bytes(zpk, PAYHSM_KEY_LEN) != 1) {
        secure_zero(lmk, sizeof(lmk));
        return PAYHSM_RC_ERR;
    }
    vault_encrypt_under_lmk(lmk, zpk, zpk_enc);
    compute_kcv(zpk, PAYHSM_KEY_LEN, kcv);
    secure_zero(zpk, sizeof(zpk));
    secure_zero(lmk, sizeof(lmk));
    if (vault_add_key(&g_ctx.vault, "ZPK-VISA", PAYHSM_KEY_ZPK, "", zpk_enc, kcv) != 0)
        return PAYHSM_RC_ERR;

    if (store_key_from_label("ZPK-BANK-A", PAYHSM_KEY_ZPK, "", "ZPK:BANK:A:NETWORK") != 0)
        return PAYHSM_RC_ERR;
    if (store_key_from_label("ZPK-BANK-B", PAYHSM_KEY_ZPK, "", "ZPK:BANK:B:ISSUER") != 0)
        return PAYHSM_RC_ERR;

    for (int i = 0; i < n_terminals; i++) {
        const char *term = terminals[i];
        snprintf(label, sizeof(label), "TMK:%s", term);
        snprintf(id, sizeof(id), "TMK-%s", term);
        if (store_key_from_label(id, PAYHSM_KEY_TMK, term, label) != 0)
            return PAYHSM_RC_ERR;
        if (store_derived_terminal_keys(term) != PAYHSM_RC_OK)
            return PAYHSM_RC_ERR;
    }
    return PAYHSM_RC_OK;
}

static int pvv_save(void) {
    char path[PAYHSM_PATH_MAX];
    path_join(path, sizeof(path), g_ctx.data_dir, PVV_FILE);
    FILE *f = fopen(path, "wb");
    if (!f) return PAYHSM_RC_ERR;
    uint32_t n = (uint32_t)g_pvv_count;
    fwrite(&n, 1, sizeof(n), f);
    fwrite(g_pvv, sizeof(pvv_entry_t), (size_t)n, f);
    fclose(f);
    return PAYHSM_RC_OK;
}

static int pvv_load(void) {
    char path[PAYHSM_PATH_MAX];
    path_join(path, sizeof(path), g_ctx.data_dir, PVV_FILE);
    FILE *f = fopen(path, "rb");
    if (!f) {
        g_pvv_count = 0;
        return PAYHSM_RC_OK;
    }
    uint32_t n = 0;
    if (fread(&n, 1, sizeof(n), f) != sizeof(n) || n > 256) {
        fclose(f);
        return PAYHSM_RC_ERR;
    }
    g_pvv_count = (int)n;
    if (n > 0 && fread(g_pvv, sizeof(pvv_entry_t), n, f) != n) {
        fclose(f);
        return PAYHSM_RC_ERR;
    }
    fclose(f);
    return PAYHSM_RC_OK;
}

int payhsm_provision(const char *passphrase,
                     const char *data_dir,
                     const char *const *terminals,
                     int n_terminals) {
    if (!passphrase || !data_dir) return PAYHSM_RC_ERR;

    anti_dump_setup();
    anti_ptrace_setup();

    strncpy(g_ctx.data_dir, data_dir, sizeof(g_ctx.data_dir) - 1);
    if (ensure_data_dir(g_ctx.data_dir) != PAYHSM_RC_OK)
        return PAYHSM_RC_ERR;
    path_join(g_ctx.lmk_path, sizeof(g_ctx.lmk_path), data_dir, LMK_FILE);
    path_join(g_ctx.vault.vault_path, sizeof(g_ctx.vault.vault_path),
              data_dir, VAULT_FILE);

    uint8_t lmk[32], kek[32], salt[PAYHSM_SALT_SIZE];
    if (RAND_bytes(lmk, sizeof(lmk)) != 1) return PAYHSM_RC_ERR;
    if (RAND_bytes(salt, sizeof(salt)) != 1) return PAYHSM_RC_ERR;
    if (kek_derive_from_passphrase(passphrase, salt, kek) != 0)
        return PAYHSM_RC_ERR;
    if (lmk_store_create_with_salt(g_ctx.lmk_path, kek, lmk, salt) != 0) {
        secure_zero(lmk, sizeof(lmk));
        secure_zero(kek, sizeof(kek));
        return PAYHSM_RC_ERR;
    }
    secure_zero(kek, sizeof(kek));
    secure_zero(salt, sizeof(salt));

    if (fragment_lmk(lmk) != 0) {
        secure_zero(lmk, sizeof(lmk));
        return PAYHSM_RC_ERR;
    }
    secure_zero(lmk, sizeof(lmk));

    vault_clear(&g_ctx.vault);
    strncpy(g_ctx.vault.vault_path, g_ctx.data_dir, sizeof(g_ctx.vault.vault_path) - 1);
    strncat(g_ctx.vault.vault_path, "/" VAULT_FILE,
            sizeof(g_ctx.vault.vault_path) - strlen(g_ctx.vault.vault_path) - 1);

    g_pvv_count = 0;
    g_ctx.initialized = 1; /* requis pour dériver TPK/TAK depuis TMK pendant provision */

    if (provision_keys(terminals, n_terminals) != PAYHSM_RC_OK) {
        g_ctx.initialized = 0;
        return PAYHSM_RC_ERR;
    }

    if (vault_save(&g_ctx.vault) != 0) {
        g_ctx.initialized = 0;
        return PAYHSM_RC_ERR;
    }
    return PAYHSM_RC_OK;
}

int payhsm_startup(const char *passphrase, const char *data_dir) {
    if (!passphrase || !data_dir) return PAYHSM_RC_ERR;

    anti_dump_setup();
    anti_ptrace_setup();

    strncpy(g_ctx.data_dir, data_dir, sizeof(g_ctx.data_dir) - 1);
    if (ensure_data_dir(g_ctx.data_dir) != PAYHSM_RC_OK)
        return PAYHSM_RC_ERR;
    path_join(g_ctx.lmk_path, sizeof(g_ctx.lmk_path), data_dir, LMK_FILE);

    char vault_path[PAYHSM_PATH_MAX];
    path_join(vault_path, sizeof(vault_path), data_dir, VAULT_FILE);

    uint8_t lmk[32], kek[32], salt[PAYHSM_SALT_SIZE];
    if (lmk_store_read_salt(g_ctx.lmk_path, salt) != 0) return PAYHSM_RC_ERR;
    kek_derive_from_passphrase(passphrase, salt, kek);
    if (lmk_store_load(g_ctx.lmk_path, kek, lmk) != 0) {
        secure_zero(kek, sizeof(kek));
        return PAYHSM_RC_ERR;
    }
    secure_zero(kek, sizeof(kek));

    if (fragment_lmk(lmk) != 0) {
        secure_zero(lmk, sizeof(lmk));
        return PAYHSM_RC_ERR;
    }
    secure_zero(lmk, sizeof(lmk));

    if (vault_load(&g_ctx.vault, vault_path) != 0) {
        vault_clear(&g_ctx.vault);
        strncpy(g_ctx.vault.vault_path, vault_path, sizeof(g_ctx.vault.vault_path) - 1);
    }
    g_ctx.initialized = 1;
    g_boot_id++;
    if (pvv_load() != PAYHSM_RC_OK) {
        g_pvv_count = 0;
    }
    return PAYHSM_RC_OK;
}

unsigned long payhsm_get_boot_id(void) { return g_boot_id; }

int payhsm_startup_from_mk(const uint8_t mk[32], const char *data_dir) {
    if (!mk || !data_dir) return PAYHSM_RC_ERR;

    anti_dump_setup();
    anti_ptrace_setup();

    strncpy(g_ctx.data_dir, data_dir, sizeof(g_ctx.data_dir) - 1);
    g_ctx.data_dir[sizeof(g_ctx.data_dir) - 1] = '\0';
    if (ensure_data_dir(g_ctx.data_dir) != PAYHSM_RC_OK)
        return PAYHSM_RC_ERR;
    path_join(g_ctx.lmk_path, sizeof(g_ctx.lmk_path), data_dir, LMK_FILE);

    uint8_t lmk_copy[32];
    memcpy(lmk_copy, mk, 32);
    if (fragment_lmk(lmk_copy) != 0) {
        secure_zero(lmk_copy, sizeof(lmk_copy));
        return PAYHSM_RC_ERR;
    }
    secure_zero(lmk_copy, sizeof(lmk_copy));

    char vault_path[PAYHSM_PATH_MAX];
    path_join(vault_path, sizeof(vault_path), data_dir, VAULT_FILE);
    if (vault_load(&g_ctx.vault, vault_path) != 0) {
        vault_clear(&g_ctx.vault);
        strncpy(g_ctx.vault.vault_path, vault_path, sizeof(g_ctx.vault.vault_path) - 1);
    }
    g_ctx.initialized = 1;
    g_boot_id++;
    if (pvv_load() != PAYHSM_RC_OK)
        g_pvv_count = 0;
    return PAYHSM_RC_OK;
}

/* Provision LMK uniquement — aucune clé de travail dans le coffre HSM (modèle Switch) */
int payhsm_provision_lmk_only(const char *passphrase, const char *data_dir) {
    if (!passphrase || !data_dir) return PAYHSM_RC_ERR;

    anti_dump_setup();
    anti_ptrace_setup();

    strncpy(g_ctx.data_dir, data_dir, sizeof(g_ctx.data_dir) - 1);
    if (ensure_data_dir(g_ctx.data_dir) != PAYHSM_RC_OK)
        return PAYHSM_RC_ERR;
    path_join(g_ctx.lmk_path, sizeof(g_ctx.lmk_path), data_dir, LMK_FILE);

    uint8_t lmk[32], kek[32], salt[PAYHSM_SALT_SIZE];
    if (RAND_bytes(lmk, sizeof(lmk)) != 1) return PAYHSM_RC_ERR;
    if (RAND_bytes(salt, sizeof(salt)) != 1) return PAYHSM_RC_ERR;
    if (kek_derive_from_passphrase(passphrase, salt, kek) != 0)
        return PAYHSM_RC_ERR;
    if (lmk_store_create_with_salt(g_ctx.lmk_path, kek, lmk, salt) != 0) {
        secure_zero(lmk, sizeof(lmk));
        secure_zero(kek, sizeof(kek));
        return PAYHSM_RC_ERR;
    }
    secure_zero(kek, sizeof(kek));
    secure_zero(salt, sizeof(salt));

    if (fragment_lmk(lmk) != 0) {
        secure_zero(lmk, sizeof(lmk));
        return PAYHSM_RC_ERR;
    }
    secure_zero(lmk, sizeof(lmk));

    vault_clear(&g_ctx.vault);
    path_join(g_ctx.vault.vault_path, sizeof(g_ctx.vault.vault_path),
              data_dir, VAULT_FILE);
    g_pvv_count = 0;
    g_ctx.initialized = 1;
    return vault_save(&g_ctx.vault) == 0 ? PAYHSM_RC_OK : PAYHSM_RC_ERR;
}

void payhsm_shutdown(void) {
    zero_all_fragments();
    vault_clear(&g_ctx.vault);
    memset(&g_ctx, 0, sizeof(g_ctx));
    g_pvv_count = 0;
}

int payhsm_set_card_pvv(const char *pan, const char *pvv4) {
    if (!pan || !pvv4) return PAYHSM_RC_ERR;
    for (int i = 0; i < g_pvv_count; i++) {
        if (strcmp(g_pvv[i].pan, pan) == 0) {
            strncpy(g_pvv[i].pvv, pvv4, 4);
            g_pvv[i].pvv[4] = '\0';
            return pvv_save();
        }
    }
    if (g_pvv_count >= 256) return PAYHSM_RC_ERR;
    pvv_entry_t *e = &g_pvv[g_pvv_count++];
    strncpy(e->pan, pan, sizeof(e->pan) - 1);
    strncpy(e->pvv, pvv4, 4);
    e->pvv[4] = '\0';
    return pvv_save();
}

int payhsm_register_card(const char *pan, const char *pin) {
    char pvv[5];
    return payhsm_corebanking_issue_pvv(pan, pin, pvv);
}

int payhsm_corebanking_issue_pvv(const char *pan, const char *pin, char pvv_out[5]) {
    uint8_t pvk[PAYHSM_KEY_LEN];
    char pvv[5];

    if (!pan || !pin) return PAYHSM_RC_ERR;
    if (payhsm_unwrap_key(PAYHSM_KEY_PVK, "", pvk) != PAYHSM_RC_OK)
        return PAYHSM_RC_ERR;
    if (pin_compute_pvv(pin, pan, pvk, PAYHSM_KEY_LEN, pvv) != 0) {
        secure_zero(pvk, sizeof(pvk));
        return PAYHSM_RC_ERR;
    }
    secure_zero(pvk, sizeof(pvk));
    if (payhsm_set_card_pvv(pan, pvv) != PAYHSM_RC_OK)
        return PAYHSM_RC_ERR;
    if (pvv_out) {
        strncpy(pvv_out, pvv, 4);
        pvv_out[4] = '\0';
    }
    return PAYHSM_RC_OK;
}

int payhsm_corebanking_get_pvv(const char *pan, char pvv_out[5]) {
    const char *p = lookup_pvv(pan);
    if (!p || !pvv_out) return PAYHSM_RC_ERR;
    strncpy(pvv_out, p, 4);
    pvv_out[4] = '\0';
    return PAYHSM_RC_OK;
}

int payhsm_corebanking_card_enrolled(const char *pan) {
    if (!pan || !pan[0]) return PAYHSM_RC_ERR;
    if (!g_ctx.initialized) return PAYHSM_RC_NOT_INIT;
    return lookup_pvv(pan) ? PAYHSM_RC_OK : PAYHSM_RC_CARD_UNKNOWN;
}

static const char *lookup_pvv(const char *pan) {
    for (int i = 0; i < g_pvv_count; i++) {
        if (strcmp(g_pvv[i].pan, pan) == 0) return g_pvv[i].pvv;
    }
    return NULL;
}

int payhsm_gap_generate_pin_block(const char *terminal_id,
                                  const char *pin,
                                  const char *pan,
                                  uint8_t pin_block[8]) {
    uint8_t tpk[PAYHSM_KEY_LEN];
    if (payhsm_unwrap_key(PAYHSM_KEY_TPK, terminal_id, tpk) != PAYHSM_RC_OK)
        return PAYHSM_RC_ERR;
    int r = generate_pin_block(pin, pan, tpk, PAYHSM_KEY_LEN, pin_block);
    secure_zero(tpk, sizeof(tpk));
    return r == 0 ? PAYHSM_RC_OK : PAYHSM_RC_ERR;
}

int payhsm_verify_pin_block(const char *terminal_id,
                            const char *pan,
                            const uint8_t pin_block[8],
                            int *rc_out) {
    uint8_t tpk[PAYHSM_KEY_LEN], pvk[PAYHSM_KEY_LEN];
    const char *pvv = lookup_pvv(pan);

    if (!pvv) return PAYHSM_RC_ERR;

    if (payhsm_unwrap_key(PAYHSM_KEY_TPK, terminal_id, tpk) != PAYHSM_RC_OK)
        return PAYHSM_RC_ERR;
    if (payhsm_unwrap_key(PAYHSM_KEY_PVK, "", pvk) != PAYHSM_RC_OK) {
        secure_zero(tpk, sizeof(tpk));
        return PAYHSM_RC_ERR;
    }

    int ok = verify_encrypted_pin_block(pin_block, pan, tpk, PAYHSM_KEY_LEN,
                                        pvk, PAYHSM_KEY_LEN, pvv);
    secure_zero(tpk, sizeof(tpk));
    secure_zero(pvk, sizeof(pvk));
    if (rc_out) *rc_out = (ok == 0) ? PAYHSM_RC_OK : PAYHSM_RC_DECLINED;
    return PAYHSM_RC_OK;
}

int payhsm_translate_pin_to_zpk(const char *terminal_id,
                                const uint8_t pin_block_tpk[8],
                                uint8_t pin_block_zpk[8]) {
    return payhsm_translate_pin_to_zpk_id(terminal_id, pin_block_tpk,
                                          "ZPK-VISA", pin_block_zpk);
}

static int unwrap_vault_id(const char *key_id, uint8_t key_out[PAYHSM_KEY_LEN]) {
    const payhsm_key_entry_t *e = NULL;
    uint8_t lmk[32];

    if (!key_id || !key_out) return PAYHSM_RC_ERR;
    if (vault_find_by_id(&g_ctx.vault, key_id, &e) != 0 || !e)
        return PAYHSM_RC_ERR;
    if (check_integrity() != 0) return PAYHSM_RC_ERR;
    if (recompose_for_op(lmk) != 0) return PAYHSM_RC_ERR;
    if (vault_decrypt_under_lmk(lmk, e->enc, key_out) != 0) {
        secure_zero(lmk, sizeof(lmk));
        return PAYHSM_RC_ERR;
    }
    secure_zero(lmk, sizeof(lmk));
    return PAYHSM_RC_OK;
}

int payhsm_translate_pin_to_zpk_id(const char *terminal_id,
                                   const uint8_t pin_block_tpk[8],
                                   const char *zpk_key_id,
                                   uint8_t pin_block_zpk[8]) {
    uint8_t tpk[PAYHSM_KEY_LEN], zpk[PAYHSM_KEY_LEN];

    if (!terminal_id || !pin_block_tpk || !zpk_key_id || !pin_block_zpk)
        return PAYHSM_RC_ERR;
    if (payhsm_unwrap_key(PAYHSM_KEY_TPK, terminal_id, tpk) != PAYHSM_RC_OK)
        return PAYHSM_RC_ERR;
    if (unwrap_vault_id(zpk_key_id, zpk) != PAYHSM_RC_OK) {
        secure_zero(tpk, sizeof(tpk));
        return PAYHSM_RC_ERR;
    }
    int r = translate_pin_block(pin_block_tpk, "", tpk, PAYHSM_KEY_LEN,
                                zpk, PAYHSM_KEY_LEN, pin_block_zpk);
    secure_zero(tpk, sizeof(tpk));
    secure_zero(zpk, sizeof(zpk));
    return r == 0 ? PAYHSM_RC_OK : PAYHSM_RC_ERR;
}

int payhsm_translate_zpk_to_zpk(const char *src_zpk_id,
                              const uint8_t pin_block_in[8],
                              const char *dst_zpk_id,
                              uint8_t pin_block_out[8]) {
    uint8_t zpk_a[PAYHSM_KEY_LEN], zpk_b[PAYHSM_KEY_LEN];

    if (!src_zpk_id || !pin_block_in || !dst_zpk_id || !pin_block_out)
        return PAYHSM_RC_ERR;
    if (unwrap_vault_id(src_zpk_id, zpk_a) != PAYHSM_RC_OK)
        return PAYHSM_RC_ERR;
    if (unwrap_vault_id(dst_zpk_id, zpk_b) != PAYHSM_RC_OK) {
        secure_zero(zpk_a, sizeof(zpk_a));
        return PAYHSM_RC_ERR;
    }
    int r = translate_pin_block(pin_block_in, "", zpk_a, PAYHSM_KEY_LEN,
                                zpk_b, PAYHSM_KEY_LEN, pin_block_out);
    secure_zero(zpk_a, sizeof(zpk_a));
    secure_zero(zpk_b, sizeof(zpk_b));
    return r == 0 ? PAYHSM_RC_OK : PAYHSM_RC_ERR;
}

int payhsm_verify_pin_block_zpk(const char *zpk_key_id,
                                const char *pan,
                                const uint8_t pin_block[8],
                                int *rc_out) {
    uint8_t zpk[PAYHSM_KEY_LEN], pvk[PAYHSM_KEY_LEN];
    const char *pvv = lookup_pvv(pan);

    if (!zpk_key_id || !pan || !pin_block) return PAYHSM_RC_ERR;
    if (!pvv) return PAYHSM_RC_ERR;

    if (unwrap_vault_id(zpk_key_id, zpk) != PAYHSM_RC_OK)
        return PAYHSM_RC_ERR;
    if (payhsm_unwrap_key(PAYHSM_KEY_PVK, "", pvk) != PAYHSM_RC_OK) {
        secure_zero(zpk, sizeof(zpk));
        return PAYHSM_RC_ERR;
    }

    int ok = verify_encrypted_pin_block(pin_block, pan, zpk, PAYHSM_KEY_LEN,
                                        pvk, PAYHSM_KEY_LEN, pvv);
    secure_zero(zpk, sizeof(zpk));
    secure_zero(pvk, sizeof(pvk));
    if (rc_out) *rc_out = (ok == 0) ? PAYHSM_RC_OK : PAYHSM_RC_DECLINED;
    return PAYHSM_RC_OK;
}

int payhsm_get_kcv(payhsm_key_type_t type,
                   const char *terminal_id,
                   char kcv_hex[7]) {
    const payhsm_key_entry_t *e = NULL;
    if (vault_find(&g_ctx.vault, type, terminal_id, &e) != 0 || !e)
        return PAYHSM_RC_ERR;
    snprintf(kcv_hex, 7, "%02X%02X%02X", e->kcv[0], e->kcv[1], e->kcv[2]);
    return PAYHSM_RC_OK;
}

int payhsm_get_kcv_by_id(const char *key_id, char kcv_hex[7]) {
    const payhsm_key_entry_t *e = NULL;
    if (!key_id || !kcv_hex) return PAYHSM_RC_ERR;
    if (vault_find_by_id(&g_ctx.vault, key_id, &e) != 0 || !e)
        return PAYHSM_RC_ERR;
    snprintf(kcv_hex, 7, "%02X%02X%02X", e->kcv[0], e->kcv[1], e->kcv[2]);
    return PAYHSM_RC_OK;
}

int payhsm_get_lmk_status(payhsm_lmk_status_t *st) {
    if (!st) return PAYHSM_RC_ERR;
    memset(st, 0, sizeof(*st));
    payhsm_ctx_t *c = payhsm_ctx();
    st->fragmented = c->initialized ? 1 : 0;
    if (c->initialized) {
        st->integrity_ok = (verify_integrity_quiet() == 0) ? 1 : 0;
        strncpy(st->data_dir, c->data_dir, sizeof(st->data_dir) - 1);
    }
    mutation_stats_t ms;
    mutation_stats_get(&ms);
    st->mutation_count = (int)ms.count;
    st->mutation_last_ts = (long)ms.last_ts;
    return PAYHSM_RC_OK;
}

int payhsm_mutate_lmk_fragments(void) {
    if (!payhsm_ctx()->initialized) return PAYHSM_RC_NOT_INIT;
    if (check_integrity() != 0) return PAYHSM_RC_ERR;
    if (mutate_fragments() != 0) return PAYHSM_RC_ERR;
    return (verify_integrity_quiet() == 0) ? PAYHSM_RC_OK : PAYHSM_RC_ERR;
}

int payhsm_status_text(char *buf, size_t buflen) {
    if (!buf || buflen < 32) return PAYHSM_RC_ERR;
    int n = snprintf(buf, buflen,
                     "PayHSM %s\nLMK: fragmentee (P1/P2/P3)\nCles: %d | Cartes PVV: %d\n",
                     g_ctx.initialized ? "ACTIF" : "ARRETE",
                     g_ctx.vault.count, g_pvv_count);
    for (int i = 0; i < g_ctx.vault.count && (size_t)n < buflen - 80; i++) {
        const payhsm_key_entry_t *e = &g_ctx.vault.keys[i];
        char kcv[7];
        snprintf(kcv, sizeof(kcv), "%02X%02X%02X",
                 e->kcv[0], e->kcv[1], e->kcv[2]);
        n += snprintf(buf + n, buflen - (size_t)n,
                      "  %-16s %-6s KCV=%s term=%s\n",
                      e->id, e->active ? "ACTIF" : "-", kcv, e->terminal_id);
    }
    return PAYHSM_RC_OK;
}

static int hex_decode_local(const char *hex, uint8_t *out, size_t nbytes) {
    if (strlen(hex) != nbytes * 2) return -1;
    for (size_t i = 0; i < nbytes; i++) {
        unsigned int b;
        if (sscanf(hex + i * 2, "%2x", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    return 0;
}

static void hex_encode16(const uint8_t *in, size_t len, char *out) {
    for (size_t i = 0; i < len; i++)
        sprintf(out + i * 2, "%02X", in[i]);
    out[len * 2] = '\0';
}

int payhsm_emv_simulate_purchase(const char *pan,
                                 const char *psn,
                                 const char *atc_hex,
                                 unsigned long amount_cents,
                                 const char *currency_code3,
                                 payhsm_emv_purchase_t *result) {
    if (!result) return PAYHSM_RC_ERR;
    memset(result, 0, sizeof(*result));
    strncpy(result->message, "parametres invalides", sizeof(result->message) - 1);

    if (!g_ctx.initialized) {
        strncpy(result->message, "HSM non demarre", sizeof(result->message) - 1);
        return PAYHSM_RC_NOT_INIT;
    }
    if (!pan || !psn || !atc_hex || !currency_code3) return PAYHSM_RC_ERR;
    if (payhsm_corebanking_card_enrolled(pan) != PAYHSM_RC_OK) {
        strncpy(result->message,
                "Carte non enregistree — Core Banking (PVV) requis",
                sizeof(result->message) - 1);
        return PAYHSM_RC_CARD_UNKNOWN;
    }

    size_t tx_len = 0;
    if (emv_build_tx_data(amount_cents, currency_code3,
                          NULL, atc_hex, NULL,
                          result->tx_data, sizeof(result->tx_data), &tx_len) != 0)
        return PAYHSM_RC_ERR;

    snprintf(result->amount_display, sizeof(result->amount_display),
             "%lu.%02lu %s", amount_cents / 100, amount_cents % 100, currency_code3);

    uint8_t imk[16], mk[16], sk[16], atc_b[2], arqc[8], arpc[8];
    if (payhsm_unwrap_key(PAYHSM_KEY_IMK, "", imk) != PAYHSM_RC_OK) {
        strncpy(result->message, "IMK introuvable — provision requis", sizeof(result->message) - 1);
        return PAYHSM_RC_ERR;
    }
    if (derive_card_keys(imk, 16, pan, psn, mk) != 0 ||
        hex_decode_local(atc_hex, atc_b, 2) != 0 ||
        derive_sk_ac(mk, atc_b, sk) != 0) {
        secure_zero(imk, sizeof(imk));
        strncpy(result->message, "derive MK-AC / SK-AC echec", sizeof(result->message) - 1);
        return PAYHSM_RC_ERR;
    }

    if (emv_compute_arqc(sk, (const uint8_t *)result->tx_data, tx_len, arqc) != 0) {
        secure_zero(imk, sizeof(imk));
        secure_zero(mk, sizeof(mk));
        secure_zero(sk, sizeof(sk));
        strncpy(result->message, "calcul ARQC echec", sizeof(result->message) - 1);
        return PAYHSM_RC_ERR;
    }
    hex_encode16(arqc, 8, result->arqc_hex);

    int ok = verify_arqc(sk, (const uint8_t *)result->tx_data, tx_len, arqc);
    if (ok != 0) {
        secure_zero(imk, sizeof(imk));
        secure_zero(mk, sizeof(mk));
        secure_zero(sk, sizeof(sk));
        result->approved = 0;
        result->rc = PAYHSM_RC_DECLINED;
        strncpy(result->message, "ARQC invalide — paiement refuse", sizeof(result->message) - 1);
        return PAYHSM_RC_OK;
    }

    uint8_t arc[2] = {0x00, 0x00};
    if (generate_arpc(mk, arqc, arc, arpc) != 0) {
        secure_zero(imk, sizeof(imk));
        strncpy(result->message, "generation ARPC echec", sizeof(result->message) - 1);
        return PAYHSM_RC_ERR;
    }
    hex_encode16(arpc, 8, result->arpc_hex);

    secure_zero(imk, sizeof(imk));
    secure_zero(mk, sizeof(mk));
    secure_zero(sk, sizeof(sk));

    result->approved = 1;
    result->rc = PAYHSM_RC_OK;
    strncpy(result->message, "Paiement EMV approuve", sizeof(result->message) - 1);
    return PAYHSM_RC_OK;
}
