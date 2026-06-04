/*
 * payhsm-admin.c — Administration Switch/ATM style Thales payShield 10K
 *
 * Ce fichier est inclus (#include) dans payhsm-httpd.c juste avant le
 * dispatch, donc toutes les fonctions statiques de httpd.c sont accessibles.
 *
 * Toute génération de clé passe par le moteur HSM (même code qu'A0) :
 *   RAND_bytes → recompose_for_op → vault_store_16 → vault_save
 * Aucune clé en clair n'est stockée ou retournée.
 */

/* ═══════════════════════════════════════════════════════════════════════════
   1. TABLE DE MAPPING CLÉ/CODE — inspiré payShield 10K, remplaçable
   ═══════════════════════════════════════════════════════════════════════════ */

typedef struct { const char *name; const char *code; } key_code_map_t;
static const key_code_map_t KEY_CODE_MAP[] = {
    {"TMK","01"}, {"ZMK","02"}, {"ZPK","03"},
    {"PVK","04"}, {"IMK","05"}, {"TPK","06"}, {"TAK","07"},
    {NULL, NULL}
};
static const char *key_code(const char *name) {
    for (int i = 0; KEY_CODE_MAP[i].name; i++)
        if (strcmp(KEY_CODE_MAP[i].name, name) == 0) return KEY_CODE_MAP[i].code;
    return "00";
}

/* ═══════════════════════════════════════════════════════════════════════════
   2. STRUCTURES ÉTAT Switch / ATM
   ═══════════════════════════════════════════════════════════════════════════ */

#define ADMIN_KEY_NAMELEN  16
#define ADMIN_VAULT_IDLEN  52
#define ADMIN_KCV_LEN       8
#define ADMIN_SWITCH_KEYS  10
#define ADMIN_ATM_MAX      64
#define ADMIN_ATM_IDLEN    32
#define ADMIN_ATM_NAMELEN  64
#define ADMIN_ATM_LOCLEN   64

typedef struct {
    char key_name[ADMIN_KEY_NAMELEN]; /* "TMK", "ZMK", … */
    char vault_id[ADMIN_VAULT_IDLEN]; /* ID dans le coffre HSM */
    char kcv[ADMIN_KCV_LEN];          /* KCV hex 6 chars */
    int  present;
} admin_key_t;

typedef struct {
    int         initialized;
    admin_key_t keys[ADMIN_SWITCH_KEYS];
    int         key_count;
    long        last_updated;
} switch_state_t;

typedef enum { ATM_INACTIVE=0, ATM_ACTIVE=1, ATM_BLOCKED=2 } atm_status_e;
static const char *atm_status_str(atm_status_e s) {
    switch(s) {
    case ATM_ACTIVE:   return "ACTIVE";
    case ATM_BLOCKED:  return "BLOCKED";
    default:           return "INACTIVE";
    }
}

typedef struct {
    char        id[ADMIN_ATM_IDLEN];
    char        name[ADMIN_ATM_NAMELEN];
    char        location[ADMIN_ATM_LOCLEN];
    atm_status_e status;
    admin_key_t  tmk;
    admin_key_t  tpk;
    admin_key_t  tak;
    long        created_at;
    long        last_activity;
    int         alive; /* 0 = supprimé */
} atm_entry_t;

typedef struct {
    atm_entry_t entries[ADMIN_ATM_MAX];
    int count;
    char path[256];
} atm_registry_t;

static switch_state_t g_sw  = {0};
static atm_registry_t g_atm = {0};

/* ═══════════════════════════════════════════════════════════════════════════
   3. PERSISTANCE — fichiers binaires dans data_dir
   ═══════════════════════════════════════════════════════════════════════════ */

#define SWITCH_STATE_FILE "switch_state.bin"
#define ATM_REG_FILE      "atm_registry.bin"

static void switch_state_save(void) {
    const char *dir = payhsm_ctx()->data_dir;
    if (!dir[0]) return;
    char path[512];
    snprintf(path, sizeof(path), "%s/" SWITCH_STATE_FILE, dir);
    FILE *f = fopen(path, "wb");
    if (!f) return;
    fwrite(&g_sw, sizeof(g_sw), 1, f);
    fclose(f);
}

static void switch_state_load(void) {
    const char *dir = payhsm_ctx()->data_dir;
    if (!dir[0]) return;
    char path[512];
    snprintf(path, sizeof(path), "%s/" SWITCH_STATE_FILE, dir);
    FILE *f = fopen(path, "rb");
    if (!f) return;
    fread(&g_sw, sizeof(g_sw), 1, f);
    fclose(f);
}

static void atm_registry_save(void) {
    if (!g_atm.path[0]) {
        const char *dir = payhsm_ctx()->data_dir;
        if (!dir[0]) return;
        snprintf(g_atm.path, sizeof(g_atm.path), "%s/" ATM_REG_FILE, dir);
    }
    FILE *f = fopen(g_atm.path, "wb");
    if (!f) return;
    fwrite(&g_atm, sizeof(g_atm), 1, f);
    fclose(f);
}

static void atm_registry_load(void) {
    const char *dir = payhsm_ctx()->data_dir;
    if (!dir[0]) return;
    snprintf(g_atm.path, sizeof(g_atm.path), "%s/" ATM_REG_FILE, dir);
    FILE *f = fopen(g_atm.path, "rb");
    if (!f) return;
    fread(&g_atm, sizeof(g_atm), 1, f);
    fclose(f);
}

static int g_admin_loaded = 0;

/* Chargement paresseux : appelé au premier accès admin */
static int admin_ensure_loaded(void) {
    if (g_admin_loaded) return 0;
    if (!payhsm_ctx()->initialized) return -1;
    switch_state_load();
    atm_registry_load();
    g_admin_loaded = 1;
    return 0;
}

/* Nouveau cycle de provision HSM : efface l'état Switch/ATM (mémoire + disque) */
void payhsm_admin_reset_on_new_provision(const char *data_dir) {
    memset(&g_sw, 0, sizeof(g_sw));
    memset(&g_atm, 0, sizeof(g_atm));
    g_admin_loaded = 0;
    if (!data_dir || !data_dir[0]) return;
    char path[512];
    snprintf(path, sizeof(path), "%s/" SWITCH_STATE_FILE, data_dir);
    unlink(path);
    snprintf(path, sizeof(path), "%s/" ATM_REG_FILE, data_dir);
    unlink(path);
}

/* Après chargement LMK (SSS / TRNG / startup) : relire switch_state.bin si présent */
void payhsm_admin_reload_after_startup(void) {
    g_admin_loaded = 0;
    if (!payhsm_ctx()->initialized) return;
    switch_state_load();
    atm_registry_load();
    g_admin_loaded = 1;
}

/* ═══════════════════════════════════════════════════════════════════════════
   4. GÉNÉRATION CLÉ VIA MOTEUR HSM (même chemin qu'A0)
   ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Génère une clé AES-128 aléatoire via le moteur HSM (RAND_bytes) et la
 * protège sous LMK. Retourne vault_id (ex. "ZMK-A3F201") et KCV.
 * Commande équivalente payShield : 0001A0<CODE><KEYLEN>U
 */
static int hsm_generate_key(const char *keytype, const char *terminal_id,
                             char vault_id_out[ADMIN_VAULT_IDLEN],
                             char kcv_out[ADMIN_KCV_LEN]) {
    if (!payhsm_ctx()->initialized) return -1;

    uint8_t key[PAYHSM_KEY_LEN], lmk[32];
    if (RAND_bytes(key, PAYHSM_KEY_LEN) != 1) return -1;
    if (check_integrity() != 0 || recompose_for_op(lmk) != 0) {
        secure_zero(key, sizeof(key));
        return -1;
    }

    char kcv[7];
    hsm_kcv_hex(key, PAYHSM_KEY_LEN, kcv);
    vault_store_16(lmk, key, keytype, terminal_id ? terminal_id : "", kcv);
    secure_zero(lmk, sizeof(lmk));
    secure_zero(key, sizeof(key));

    snprintf(vault_id_out, ADMIN_VAULT_IDLEN, "%s-%s", keytype, kcv);
    strncpy(kcv_out, kcv, ADMIN_KCV_LEN - 1);
    kcv_out[ADMIN_KCV_LEN - 1] = '\0';
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
   5. API SWITCH
   ═══════════════════════════════════════════════════════════════════════════ */

static void api_admin_switch_init(char *out, size_t n) {
    if (!payhsm_ctx()->initialized) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"LMK non chargee — demarrez le HSM d'abord\"}");
        return;
    }
    admin_ensure_loaded();
    if (!g_sw.initialized) {
        g_sw.initialized = 1;
        g_sw.last_updated = (long)time(NULL);
        switch_state_save();
    }
    audit_log("SWITCH_INIT OK");
    snprintf(out, n,
        "{\"rc\":0,\"message\":\"Switch initialise avec succes\","
        "\"state\":\"READY\",\"initialized\":1}");
}

static void api_admin_switch_status(char *out, size_t n) {
    if (admin_ensure_loaded() != 0) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"HSM non demarre\"}");
        return;
    }
    int atm_count = 0;
    for (int i = 0; i < g_atm.count; i++)
        if (g_atm.entries[i].alive) atm_count++;

    int pos = snprintf(out, n,
        "{\"rc\":0,\"initialized\":%d,\"state\":\"%s\","
        "\"keyCount\":%d,\"atmCount\":%d,\"lastUpdated\":%ld,\"keys\":[",
        g_sw.initialized, g_sw.initialized ? "READY" : "NOT_INIT",
        g_sw.key_count, atm_count, g_sw.last_updated);
    for (int i = 0; i < g_sw.key_count && pos < (int)n - 80; i++) {
        const admin_key_t *k = &g_sw.keys[i];
        pos += snprintf(out + pos, n - (size_t)pos,
            "%s{\"name\":\"%s\",\"kcv\":\"%s\",\"present\":%d}",
            i ? "," : "", k->key_name, k->kcv, k->present);
    }
    snprintf(out + pos, n - (size_t)pos, "]}");
    audit_log("SWITCH_STATUS_CHECKED");
}

static void api_admin_switch_provision(char *out, size_t n) {
    if (!payhsm_ctx()->initialized) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"HSM non demarre\"}");
        return;
    }
    if (admin_ensure_loaded() != 0 || !g_sw.initialized) {
        snprintf(out, n,
            "{\"rc\":-1,\"message\":\"Switch non initialise — executer SWITCH INIT d'abord\"}");
        return;
    }

    /* Clés du Switch à provisionner — table de mapping payShield */
    static const char * const SWITCH_KEYS[] = {"TMK","ZMK","ZPK","PVK","IMK"};
    const int NK = 5;

    audit_log("SWITCH_PROVISION_START");

    int pos = snprintf(out, n, "{\"rc\":0,\"keys\":[");
    int errors = 0;
    g_sw.key_count = 0;

    for (int i = 0; i < NK; i++) {
        const char *kname = SWITCH_KEYS[i];
        char vid[ADMIN_VAULT_IDLEN], kcv[ADMIN_KCV_LEN];

        /* Commande HSM style payShield : 0001A0<CODE>10U */
        char hsm_cmd_log[64];
        snprintf(hsm_cmd_log, sizeof(hsm_cmd_log),
                 "HSM_CMD A0 keytype=%s code=%s (payShield style) OK",
                 kname, key_code(kname));

        int rc = hsm_generate_key(kname, "", vid, kcv);
        if (rc != 0) {
            errors++;
            char errlog[64];
            snprintf(errlog, sizeof(errlog), "HSM_CMD A0 keytype=%s FAILED", kname);
            audit_log(errlog);
            pos += snprintf(out + pos, n - (size_t)pos,
                "%s{\"key\":\"%s\",\"rc\":-1,\"message\":\"echec HSM\"}", i ? "," : "", kname);
            continue;
        }

        audit_log(hsm_cmd_log);

        admin_key_t *ke = &g_sw.keys[g_sw.key_count++];
        strncpy(ke->key_name, kname, ADMIN_KEY_NAMELEN - 1);
        strncpy(ke->vault_id, vid, ADMIN_VAULT_IDLEN - 1);
        strncpy(ke->kcv, kcv, ADMIN_KCV_LEN - 1);
        ke->present = 1;

        pos += snprintf(out + pos, n - (size_t)pos,
            "%s{\"key\":\"%s\",\"code\":\"%s\",\"kcv\":\"%s\","
            "\"vault_id\":\"%s\",\"rc\":0}",
            i ? "," : "", kname, key_code(kname), kcv, vid);
    }

    g_sw.last_updated = (long)time(NULL);
    switch_state_save();
    snprintf(out + pos, n - (size_t)pos,
        "],\"errors\":%d,\"message\":\"%s\"}",
        errors, errors == 0
            ? "Toutes les cles du Switch sont provisionnees via le moteur HSM"
            : "Provisionnement partiel — voir details");

    audit_log(errors == 0 ? "SWITCH_PROVISION_DONE status=OK"
                           : "SWITCH_PROVISION_DONE status=PARTIAL");
}

static void api_admin_switch_logs(char *out, size_t n) {
    /* Réutilise le journal d'audit existant */
    api_security_logs(out, n);
    audit_log("SWITCH_LOGS_VIEWED");
}

/* ═══════════════════════════════════════════════════════════════════════════
   6. API ATM/GAB
   ═══════════════════════════════════════════════════════════════════════════ */

static atm_entry_t *atm_find(const char *id) {
    for (int i = 0; i < g_atm.count; i++)
        if (g_atm.entries[i].alive && strcmp(g_atm.entries[i].id, id) == 0)
            return &g_atm.entries[i];
    return NULL;
}

static void api_admin_atm_add(const char *body, char *out, size_t n) {
    if (admin_ensure_loaded() != 0 || !g_sw.initialized) {
        snprintf(out, n,
            "{\"rc\":-1,\"message\":\"Switch non initialise — executer SWITCH INIT d'abord\"}");
        return;
    }
    char id[ADMIN_ATM_IDLEN], name[ADMIN_ATM_NAMELEN], loc[ADMIN_ATM_LOCLEN];
    json_field(body, "id",       id,   sizeof(id));
    json_field(body, "name",     name, sizeof(name));
    json_field(body, "location", loc,  sizeof(loc));
    if (!id[0]) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"id requis\"}");
        return;
    }
    if (atm_find(id)) {
        snprintf(out, n, "{\"rc\":-1,\"event\":\"ERROR_ATM_ALREADY_EXISTS\","
                         "\"message\":\"GAB %s existe deja\"}", id);
        audit_log("ERROR_ATM_ALREADY_EXISTS");
        return;
    }
    if (g_atm.count >= ADMIN_ATM_MAX) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"Registre ATM plein\"}");
        return;
    }
    atm_entry_t *e = &g_atm.entries[g_atm.count++];
    memset(e, 0, sizeof(*e));
    strncpy(e->id,       id,   ADMIN_ATM_IDLEN   - 1);
    strncpy(e->name,     name[0] ? name : id, ADMIN_ATM_NAMELEN - 1);
    strncpy(e->location, loc,  ADMIN_ATM_LOCLEN  - 1);
    e->status = ATM_INACTIVE;
    e->created_at = (long)time(NULL);
    e->alive = 1;
    atm_registry_save();

    char logline[96];
    snprintf(logline, sizeof(logline), "ATM_ADDED atm=%s status=OK", id);
    audit_log(logline);
    snprintf(out, n,
        "{\"rc\":0,\"id\":\"%s\",\"name\":\"%s\",\"location\":\"%s\","
        "\"status\":\"INACTIVE\",\"message\":\"GAB enregistre avec succes\"}",
        e->id, e->name, e->location);
}

static void api_admin_atm_list(char *out, size_t n) {
    admin_ensure_loaded();
    int pos = snprintf(out, n, "{\"rc\":0,\"atms\":[");
    int first = 1;
    for (int i = 0; i < g_atm.count; i++) {
        const atm_entry_t *e = &g_atm.entries[i];
        if (!e->alive) continue;
        pos += snprintf(out + pos, n - (size_t)pos,
            "%s{\"id\":\"%s\",\"name\":\"%s\",\"location\":\"%s\","
            "\"status\":\"%s\",\"keysProvisioned\":%d}",
            first ? "" : ",", e->id, e->name, e->location,
            atm_status_str(e->status),
            e->tmk.present && e->tpk.present && e->tak.present ? 1 : 0);
        first = 0;
    }
    snprintf(out + pos, n - (size_t)pos, "]}");
    audit_log("ATM_LISTED");
}

static void api_admin_atm_status(const char *body, char *out, size_t n) {
    admin_ensure_loaded();
    char id[ADMIN_ATM_IDLEN];
    json_field(body, "id", id, sizeof(id));
    const atm_entry_t *e = atm_find(id);
    if (!e) {
        snprintf(out, n, "{\"rc\":-1,\"event\":\"ERROR_ATM_NOT_FOUND\","
                         "\"message\":\"GAB %s introuvable\"}", id);
        audit_log("ERROR_ATM_NOT_FOUND");
        return;
    }
    snprintf(out, n,
        "{\"rc\":0,\"id\":\"%s\",\"name\":\"%s\",\"location\":\"%s\","
        "\"status\":\"%s\","
        "\"tmk\":{\"present\":%d,\"kcv\":\"%s\"},"
        "\"tpk\":{\"present\":%d,\"kcv\":\"%s\"},"
        "\"tak\":{\"present\":%d,\"kcv\":\"%s\"},"
        "\"createdAt\":%ld,\"lastActivity\":%ld}",
        e->id, e->name, e->location, atm_status_str(e->status),
        e->tmk.present, e->tmk.kcv,
        e->tpk.present, e->tpk.kcv,
        e->tak.present, e->tak.kcv,
        e->created_at, e->last_activity);
    char logline[96];
    snprintf(logline, sizeof(logline), "ATM_STATUS_CHECKED atm=%s", id);
    audit_log(logline);
}

static void api_admin_atm_provision(const char *body, char *out, size_t n) {
    if (!payhsm_ctx()->initialized) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"HSM non demarre\"}");
        return;
    }
    admin_ensure_loaded();
    char id[ADMIN_ATM_IDLEN];
    json_field(body, "id", id, sizeof(id));
    atm_entry_t *e = atm_find(id);
    if (!e) {
        snprintf(out, n, "{\"rc\":-1,\"event\":\"ERROR_ATM_NOT_FOUND\","
                         "\"message\":\"GAB %s introuvable\"}", id);
        audit_log("ERROR_ATM_NOT_FOUND");
        return;
    }
    if (!g_sw.initialized) {
        snprintf(out, n,
            "{\"rc\":-1,\"message\":\"Switch non initialise — executer SWITCH INIT d'abord\"}");
        return;
    }

    /* Génération TMK, TPK, TAK via moteur HSM (commande A0 style payShield) */
    typedef struct { const char *name; admin_key_t *slot; } slot_t;
    slot_t slots[] = {{"TMK", &e->tmk}, {"TPK", &e->tpk}, {"TAK", &e->tak}};
    int errors = 0;
    int pos = snprintf(out, n, "{\"rc\":0,\"id\":\"%s\",\"keys\":[", id);

    for (int i = 0; i < 3; i++) {
        char vid[ADMIN_VAULT_IDLEN], kcv[ADMIN_KCV_LEN];
        char hsm_log[80];
        snprintf(hsm_log, sizeof(hsm_log),
                 "HSM_CMD A0 keytype=%s atm=%s code=%s (payShield style) OK",
                 slots[i].name, id, key_code(slots[i].name));

        int rc = hsm_generate_key(slots[i].name, id, vid, kcv);
        if (rc != 0) {
            errors++;
            pos += snprintf(out + pos, n - (size_t)pos,
                "%s{\"key\":\"%s\",\"rc\":-1}", i ? "," : "", slots[i].name);
            continue;
        }
        audit_log(hsm_log);
        admin_key_t *k = slots[i].slot;
        strncpy(k->key_name, slots[i].name, ADMIN_KEY_NAMELEN - 1);
        strncpy(k->vault_id, vid, ADMIN_VAULT_IDLEN - 1);
        strncpy(k->kcv, kcv, ADMIN_KCV_LEN - 1);
        k->present = 1;
        pos += snprintf(out + pos, n - (size_t)pos,
            "%s{\"key\":\"%s\",\"code\":\"%s\",\"kcv\":\"%s\",\"rc\":0}",
            i ? "," : "", slots[i].name, key_code(slots[i].name), kcv);
    }
    e->last_activity = (long)time(NULL);
    atm_registry_save();

    snprintf(out + pos, n - (size_t)pos,
        "],\"errors\":%d,\"message\":\"%s\"}",
        errors, errors == 0 ? "Provisionnement ATM termine via moteur HSM" : "Erreurs partielles");

    char logline[96];
    snprintf(logline, sizeof(logline),
             errors == 0 ? "ATM_KEYS_PROVISIONED atm=%s status=OK"
                         : "ATM_KEYS_PROVISIONED atm=%s status=PARTIAL", id);
    audit_log(logline);
}

static void api_admin_atm_set_status(const char *body, char *out, size_t n,
                                     atm_status_e new_status) {
    admin_ensure_loaded();
    char id[ADMIN_ATM_IDLEN];
    json_field(body, "id", id, sizeof(id));
    atm_entry_t *e = atm_find(id);
    if (!e) {
        snprintf(out, n, "{\"rc\":-1,\"event\":\"ERROR_ATM_NOT_FOUND\","
                         "\"message\":\"GAB %s introuvable\"}", id);
        audit_log("ERROR_ATM_NOT_FOUND");
        return;
    }
    if (new_status == ATM_ACTIVE) {
        if (!g_sw.initialized) {
            snprintf(out, n,
                "{\"rc\":-1,\"message\":\"Switch non initialise\"}");
            return;
        }
        if (!e->tmk.present || !e->tpk.present || !e->tak.present) {
            snprintf(out, n,
                "{\"rc\":-1,\"event\":\"ERROR_KEYS_NOT_FOUND\","
                "\"message\":\"Cles manquantes — provisionner le GAB d'abord\"}");
            audit_log("ERROR_KEYS_NOT_FOUND");
            return;
        }
    }
    e->status = new_status;
    e->last_activity = (long)time(NULL);
    atm_registry_save();

    const char *ev = new_status == ATM_ACTIVE ? "ATM_ENABLED"
                   : new_status == ATM_BLOCKED ? "ATM_BLOCKED"
                   : "ATM_DISABLED";
    char logline[80];
    snprintf(logline, sizeof(logline), "%s atm=%s status=OK", ev, id);
    audit_log(logline);
    snprintf(out, n,
        "{\"rc\":0,\"id\":\"%s\",\"status\":\"%s\","
        "\"event\":\"%s\",\"message\":\"GAB %s\"}",
        id, atm_status_str(new_status), ev,
        new_status == ATM_ACTIVE ? "active" :
        new_status == ATM_BLOCKED ? "bloque" : "desactive");
}

static void api_admin_atm_remove(const char *body, char *out, size_t n) {
    admin_ensure_loaded();
    char id[ADMIN_ATM_IDLEN];
    json_field(body, "id", id, sizeof(id));
    atm_entry_t *e = atm_find(id);
    if (!e) {
        snprintf(out, n, "{\"rc\":-1,\"event\":\"ERROR_ATM_NOT_FOUND\","
                         "\"message\":\"GAB %s introuvable\"}", id);
        return;
    }
    e->alive = 0;
    e->status = ATM_INACTIVE;
    atm_registry_save();
    char logline[80];
    snprintf(logline, sizeof(logline), "ATM_REMOVED atm=%s status=OK", id);
    audit_log(logline);
    snprintf(out, n,
        "{\"rc\":0,\"id\":\"%s\","
        "\"message\":\"GAB supprime, cles archivees dans le coffre\"}",
        id);
}

static void api_admin_atm_kcv(const char *body, char *out, size_t n) {
    admin_ensure_loaded();
    char id[ADMIN_ATM_IDLEN];
    json_field(body, "id", id, sizeof(id));
    const atm_entry_t *e = atm_find(id);
    if (!e) {
        snprintf(out, n, "{\"rc\":-1,\"event\":\"ERROR_ATM_NOT_FOUND\","
                         "\"message\":\"GAB %s introuvable\"}", id);
        return;
    }
    snprintf(out, n,
        "{\"rc\":0,\"id\":\"%s\","
        "\"tmk_kcv\":\"%s\",\"tpk_kcv\":\"%s\",\"tak_kcv\":\"%s\","
        "\"tmk_present\":%d,\"tpk_present\":%d,\"tak_present\":%d}",
        id,
        e->tmk.kcv, e->tpk.kcv, e->tak.kcv,
        e->tmk.present, e->tpk.present, e->tak.present);
    char logline[80];
    snprintf(logline, sizeof(logline), "ATM_KCV_VIEWED atm=%s", id);
    audit_log(logline);
}

static void api_admin_atm_connect(const char *body, char *out, size_t n) {
    admin_ensure_loaded();
    char id[ADMIN_ATM_IDLEN];
    json_field(body, "id", id, sizeof(id));
    atm_entry_t *e = atm_find(id);
    if (!e) {
        snprintf(out, n, "{\"rc\":-1,\"event\":\"ERROR_ATM_NOT_FOUND\","
                         "\"message\":\"GAB %s introuvable\"}", id);
        return;
    }
    if (!g_sw.initialized) {
        snprintf(out, n,
            "{\"rc\":-1,\"message\":\"Switch non initialise\"}");
        return;
    }
    if (e->status != ATM_ACTIVE) {
        snprintf(out, n,
            "{\"rc\":-1,\"message\":\"GAB non actif (statut: %s)\"}",
            atm_status_str(e->status));
        return;
    }
    if (!e->tmk.present || !e->tpk.present || !e->tak.present) {
        snprintf(out, n,
            "{\"rc\":-1,\"event\":\"ERROR_KEYS_NOT_FOUND\","
            "\"message\":\"Cles manquantes\"}");
        return;
    }
    e->last_activity = (long)time(NULL);
    atm_registry_save();
    char logline[80];
    snprintf(logline, sizeof(logline), "ATM_CONNECTED atm=%s status=OK", id);
    audit_log(logline);
    snprintf(out, n,
        "{\"rc\":0,\"id\":\"%s\","
        "\"switchReady\":1,\"atmActive\":1,\"keysPresent\":1,"
        "\"message\":\"Connexion GAB acceptee\"}",
        id);
}

static void api_admin_atm_disconnect(const char *body, char *out, size_t n) {
    admin_ensure_loaded();
    char id[ADMIN_ATM_IDLEN];
    json_field(body, "id", id, sizeof(id));
    const atm_entry_t *e = atm_find(id);
    if (!e) {
        snprintf(out, n, "{\"rc\":-1,\"event\":\"ERROR_ATM_NOT_FOUND\","
                         "\"message\":\"GAB %s introuvable\"}", id);
        return;
    }
    char logline[80];
    snprintf(logline, sizeof(logline), "ATM_DISCONNECTED atm=%s status=OK", id);
    audit_log(logline);
    snprintf(out, n,
        "{\"rc\":0,\"id\":\"%s\",\"message\":\"Session GAB terminee\"}", id);
}

static void api_admin_atm_rotate(const char *body, char *out, size_t n) {
    if (!payhsm_ctx()->initialized) {
        snprintf(out, n, "{\"rc\":-1,\"message\":\"HSM non demarre\"}");
        return;
    }
    admin_ensure_loaded();
    char id[ADMIN_ATM_IDLEN];
    json_field(body, "id", id, sizeof(id));
    atm_entry_t *e = atm_find(id);
    if (!e) {
        snprintf(out, n, "{\"rc\":-1,\"event\":\"ERROR_ATM_NOT_FOUND\","
                         "\"message\":\"GAB %s introuvable\"}", id);
        return;
    }

    char vid[ADMIN_VAULT_IDLEN], kcv[ADMIN_KCV_LEN];
    int pos = snprintf(out, n, "{\"rc\":0,\"id\":\"%s\",\"keys\":[", id);
    int errors = 0;

    /* Rotation TPK et TAK (TMK optionnel — garder pour compatibilité) */
    typedef struct { const char *name; admin_key_t *slot; } slot_t;
    slot_t slots[] = {{"TPK",&e->tpk}, {"TAK",&e->tak}};

    for (int i = 0; i < 2; i++) {
        int rc = hsm_generate_key(slots[i].name, id, vid, kcv);
        if (rc != 0) { errors++; continue; }
        admin_key_t *k = slots[i].slot;
        strncpy(k->vault_id, vid, ADMIN_VAULT_IDLEN - 1);
        strncpy(k->kcv, kcv, ADMIN_KCV_LEN - 1);
        k->present = 1;
        pos += snprintf(out + pos, n - (size_t)pos,
            "%s{\"key\":\"%s\",\"kcv\":\"%s\",\"rc\":0}",
            i ? "," : "", slots[i].name, kcv);
        char logline[96];
        snprintf(logline, sizeof(logline),
                 "HSM_CMD A0 keytype=%s atm=%s (rotation) OK", slots[i].name, id);
        audit_log(logline);
    }
    e->last_activity = (long)time(NULL);
    atm_registry_save();

    snprintf(out + pos, n - (size_t)pos,
        "],\"errors\":%d,\"message\":\"%s\"}",
        errors, errors == 0 ? "Rotation des cles terminee" : "Erreurs partielles");

    char logline[96];
    snprintf(logline, sizeof(logline),
             "ATM_KEYS_ROTATED atm=%s status=%s", id, errors == 0 ? "OK" : "PARTIAL");
    audit_log(logline);
}
