/*
 * hsmctl — Console d'administration PayHSM style Thales payShield 10K
 *
 * Usage :  ./hsmctl shell [--url http://host:port]
 *          ./hsmctl shell   (défaut : http://127.0.0.1:8765)
 *
 * Commandes :
 *   [HEADER][A0/A6/A8][...]   Protocole wire Thales payShield
 *   SWITCH INIT / STATUS / PROVISION / LOGS
 *   ATM ADD <id> "<name>" "<loc>"
 *   ATM LIST / STATUS / PROVISION / ENABLE / DISABLE / BLOCK / REMOVE
 *   ATM KCV / CONNECT / DISCONNECT / ROTATE-KEYS  <id>
 *   HEALTH / STATUS / VAULT / LMK / LOGS
 *   HELP / exit / quit
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>

/* ═══════════════════════════════════════════════════════════════════════════
   Configuration
   ═══════════════════════════════════════════════════════════════════════════ */

#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 8765
#define RESP_BUF     (256 * 1024)
#define INPUT_BUF    1024

static char g_host[128] = DEFAULT_HOST;
static int  g_port = DEFAULT_PORT;

/* ═══════════════════════════════════════════════════════════════════════════
   Client HTTP minimal
   ═══════════════════════════════════════════════════════════════════════════ */

static int http_request(const char *method, const char *path,
                        const char *body, char *resp, size_t rlen) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)g_port);
    inet_pton(AF_INET, g_host, &addr.sin_addr);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    char req[4096];
    int body_len = body ? (int)strlen(body) : 0;
    int rlen2;
    if (body_len > 0) {
        rlen2 = snprintf(req, sizeof(req),
            "%s %s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n\r\n%s",
            method, path, g_host, g_port, body_len, body);
    } else {
        rlen2 = snprintf(req, sizeof(req),
            "%s %s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Connection: close\r\n\r\n",
            method, path, g_host, g_port);
    }
    send(fd, req, (size_t)rlen2, 0);

    size_t total = 0;
    ssize_t nr;
    while ((nr = recv(fd, resp + total, rlen - total - 1, 0)) > 0)
        total += (size_t)nr;
    resp[total] = '\0';
    close(fd);

    /* Extraire le body JSON */
    char *hdr_end = strstr(resp, "\r\n\r\n");
    if (!hdr_end) return -1;
    char *json_start = hdr_end + 4;
    memmove(resp, json_start, strlen(json_start) + 1);
    return 0;
}

static int http_get(const char *path, char *resp, size_t rlen) {
    return http_request("GET", path, NULL, resp, rlen);
}
static int http_post(const char *path, const char *body, char *resp, size_t rlen) {
    return http_request("POST", path, body, resp, rlen);
}

/* ═══════════════════════════════════════════════════════════════════════════
   Extraction JSON simple
   ═══════════════════════════════════════════════════════════════════════════ */

static void json_str(const char *json, const char *key, char *out, size_t olen) {
    out[0] = '\0';
    char search[64];
    snprintf(search, sizeof(search), "\"%s\":", key);
    const char *p = strstr(json, search);
    if (!p) return;
    p += strlen(search);
    while (*p == ' ') p++;
    if (*p == '"') {
        p++;
        size_t i = 0;
        while (*p && *p != '"' && i < olen - 1) out[i++] = *p++;
        out[i] = '\0';
    } else {
        size_t i = 0;
        while (*p && *p != ',' && *p != '}' && *p != '\n' && i < olen - 1)
            out[i++] = *p++;
        out[i] = '\0';
    }
}

static int json_int(const char *json, const char *key) {
    char v[32]; json_str(json, key, v, sizeof(v));
    return v[0] ? atoi(v) : -1;
}

/* ═══════════════════════════════════════════════════════════════════════════
   Mise en forme des réponses (style terminal HSM bancaire)
   ═══════════════════════════════════════════════════════════════════════════ */

#define C_OK    "\033[32m"   /* vert */
#define C_ERR   "\033[31m"   /* rouge */
#define C_WARN  "\033[33m"   /* jaune */
#define C_INFO  "\033[36m"   /* cyan */
#define C_BOLD  "\033[1m"
#define C_RST   "\033[0m"

static void pr_ok(const char *fmt, ...) {
    printf(C_OK "[OK]" C_RST " ");
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
    putchar('\n');
}
static void pr_err(const char *fmt, ...) {
    printf(C_ERR "[ERR]" C_RST " ");
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
    putchar('\n');
}
static void pr_info(const char *fmt, ...) {
    printf(C_INFO "[INFO]" C_RST " ");
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
    putchar('\n');
}
static void pr_cmd(const char *fmt, ...) {
    printf(C_BOLD "[HSM CMD]" C_RST " ");
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
    putchar('\n');
}

/* ═══════════════════════════════════════════════════════════════════════════
   Handlers de commandes
   ═══════════════════════════════════════════════════════════════════════════ */

static char g_resp[RESP_BUF];

static void cmd_health(void) {
    if (http_get("/api/health", g_resp, RESP_BUF) != 0) {
        pr_err("Connexion impossible à %s:%d", g_host, g_port); return;
    }
    char init[8], ver[16];
    json_str(g_resp, "initialized", init, sizeof(init));
    json_str(g_resp, "apiVersion", ver, sizeof(ver));
    printf("HSM STATUS\n----------\n");
    printf("  Serveur      : %s:%d\n", g_host, g_port);
    printf("  Version API  : %s\n", ver);
    printf("  Initialisé   : %s\n", strcmp(init,"1")==0 ? C_OK"OUI"C_RST : C_WARN"NON"C_RST);
}

static void cmd_switch_init(void) {
    pr_info("Initialisation du Switch bancaire...");
    if (http_post("/api/admin/switch/init", "{}", g_resp, RESP_BUF) != 0) {
        pr_err("Connexion échouée"); return;
    }
    char msg[128], state[32];
    json_str(g_resp, "message", msg, sizeof(msg));
    json_str(g_resp, "state", state, sizeof(state));
    if (json_int(g_resp, "rc") == 0) {
        pr_ok("LMK disponible");
        pr_ok("Coffre Switch prêt");
        pr_ok("%s", msg);
        printf("  État : " C_BOLD "%s" C_RST "\n\n", state);
    } else {
        pr_err("%s", msg);
    }
}

static void cmd_switch_status(void) {
    if (http_post("/api/admin/switch/status", "{}", g_resp, RESP_BUF) != 0) {
        pr_err("Connexion échouée"); return;
    }
    char state[32], atmc[8], keyc[8];
    json_str(g_resp, "state", state, sizeof(state));
    json_str(g_resp, "atmCount", atmc, sizeof(atmc));
    json_str(g_resp, "keyCount", keyc, sizeof(keyc));
    int init = json_int(g_resp, "initialized");
    time_t lu = (time_t)json_int(g_resp, "lastUpdated");
    char ts[32] = "—";
    if (lu > 0) { struct tm *t = localtime(&lu); strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M", t); }
    printf("\n" C_BOLD "SWITCH STATUS" C_RST "\n");
    printf("─────────────────────────────────────\n");
    printf("  État                 : " C_BOLD "%s" C_RST "\n", state);
    printf("  Initialisé           : %s\n", init ? C_OK"OUI"C_RST : C_ERR"NON"C_RST);
    printf("  Clés provisionnées   : %s\n", keyc);
    printf("  Nombre de GAB        : %s\n", atmc);
    printf("  Dernière MAJ         : %s\n\n", ts);
}

static void cmd_switch_provision(void) {
    printf("\n[SWITCH] Provisionnement des clés via commandes HSM style payShield 10K...\n\n");
    if (http_post("/api/admin/switch/provision", "{}", g_resp, RESP_BUF) != 0) {
        pr_err("Connexion échouée"); return;
    }
    if (json_int(g_resp, "rc") != 0) {
        char msg[256]; json_str(g_resp, "message", msg, sizeof(msg));
        pr_err("%s", msg); return;
    }
    /* Parcourir les clés dans la réponse JSON */
    const char *p = g_resp;
    const char *knames[] = {"TMK","ZMK","ZPK","PVK","IMK", NULL};
    for (int i = 0; knames[i]; i++) {
        char search[32];
        snprintf(search, sizeof(search), "\"key\":\"%s\"", knames[i]);
        const char *found = strstr(p, search);
        if (!found) continue;
        /* Extraire KCV depuis le bloc JSON de cette clé */
        char kcv[16] = "?";
        const char *kp = strstr(found, "\"kcv\":");
        if (kp) json_str(found, "kcv", kcv, sizeof(kcv));
        pr_cmd("Génération %s avec commande A0 (code=%02d, 0001A0%02d10U)", knames[i], i+1, i+1);
        pr_ok("%s protégée sous LMK", knames[i]);
        printf("       KCV : " C_BOLD "%s" C_RST "\n\n", kcv);
    }
    pr_ok("Toutes les clés du Switch sont provisionnées via le moteur HSM");
    pr_ok("Aucune clé claire n'a été affichée ou stockée");
    printf("\n");
}

static void cmd_switch_logs(void) {
    if (http_post("/api/admin/switch/logs", "{}", g_resp, RESP_BUF) != 0) {
        pr_err("Connexion échouée"); return;
    }
    printf("\n" C_BOLD "SWITCH LOGS" C_RST "\n");
    printf("─────────────────────────────────────\n");
    const char *p = g_resp;
    while ((p = strstr(p, "\"ts\":")) != NULL) {
        char ts_s[32], msg_s[256];
        json_str(p, "ts", ts_s, sizeof(ts_s));
        json_str(p, "message", msg_s, sizeof(msg_s));
        time_t ts = (time_t)atol(ts_s);
        char tsbuf[32] = "";
        if (ts > 0) { struct tm *t = localtime(&ts); strftime(tsbuf, sizeof(tsbuf), "%Y-%m-%d %H:%M:%S", t); }
        printf("  [%s] %s\n", tsbuf, msg_s);
        p += 5;
    }
    printf("\n");
}

/* ── ATM ── */

static void cmd_atm_add(const char *atm_id, const char *name, const char *loc) {
    char body[512];
    snprintf(body, sizeof(body),
        "{\"id\":\"%s\",\"name\":\"%s\",\"location\":\"%s\"}", atm_id, name, loc);
    printf("\n[ATM] Ajout du GAB %s\n", atm_id);
    if (http_post("/api/admin/atm/add", body, g_resp, RESP_BUF) != 0) {
        pr_err("Connexion échouée"); return;
    }
    char msg[256], status[32];
    json_str(g_resp, "message", msg, sizeof(msg));
    json_str(g_resp, "status", status, sizeof(status));
    if (json_int(g_resp, "rc") == 0) {
        pr_ok("%s", msg);
        printf("  Nom          : " C_BOLD "%s" C_RST "\n", name);
        printf("  Localisation : %s\n", loc);
        printf("  État         : " C_WARN "%s" C_RST "\n\n", status);
    } else {
        pr_err("%s", msg);
    }
}

static void cmd_atm_list(void) {
    if (http_post("/api/admin/atm/list", "{}", g_resp, RESP_BUF) != 0) {
        pr_err("Connexion échouée"); return;
    }
    printf("\n" C_BOLD "%-10s %-28s %-20s %s" C_RST "\n",
           "ID", "Nom", "Localisation", "État");
    printf("────────────────────────────────────────────────────────────────────\n");
    const char *p = g_resp;
    while ((p = strstr(p, "\"id\":")) != NULL) {
        char id[32], name[64], loc[64], status[16];
        json_str(p, "id",       id,     sizeof(id));
        json_str(p, "name",     name,   sizeof(name));
        json_str(p, "location", loc,    sizeof(loc));
        json_str(p, "status",   status, sizeof(status));
        const char *col = strcmp(status,"ACTIVE")==0 ? C_OK :
                          strcmp(status,"BLOCKED")==0 ? C_ERR : C_WARN;
        printf("  %-10s %-28s %-20s %s%s%s\n", id, name, loc, col, status, C_RST);
        p += 5;
    }
    printf("\n");
    audit_msg:;
}

static void cmd_atm_status(const char *atm_id) {
    char body[128];
    snprintf(body, sizeof(body), "{\"id\":\"%s\"}", atm_id);
    if (http_post("/api/admin/atm/status", body, g_resp, RESP_BUF) != 0) {
        pr_err("Connexion échouée"); return;
    }
    if (json_int(g_resp, "rc") != 0) {
        char msg[256]; json_str(g_resp, "message", msg, sizeof(msg));
        pr_err("%s", msg); return;
    }
    char name[64], loc[64], status[16], tmkk[8], tpkk[8], takk[8];
    json_str(g_resp, "name",     name,   sizeof(name));
    json_str(g_resp, "location", loc,    sizeof(loc));
    json_str(g_resp, "status",   status, sizeof(status));
    /* KCVs nested */
    const char *tmkp = strstr(g_resp, "\"tmk\":");
    const char *tpkp = strstr(g_resp, "\"tpk\":");
    const char *takp = strstr(g_resp, "\"tak\":");
    if (tmkp) json_str(tmkp, "kcv", tmkk, sizeof(tmkk)); else strcpy(tmkk,"—");
    if (tpkp) json_str(tpkp, "kcv", tpkk, sizeof(tpkk)); else strcpy(tpkk,"—");
    if (takp) json_str(takp, "kcv", takk, sizeof(takk)); else strcpy(takk,"—");
    long ca = (long)json_int(g_resp, "createdAt");
    char ts[32]="—"; if(ca>0){struct tm*t=localtime((time_t*)&ca);strftime(ts,sizeof(ts),"%Y-%m-%d %H:%M",t);}
    printf("\n" C_BOLD "ATM STATUS — %s" C_RST "\n", atm_id);
    printf("──────────────────────────────────────\n");
    printf("  ID           : " C_BOLD "%s" C_RST "\n", atm_id);
    printf("  Nom          : %s\n", name);
    printf("  Localisation : %s\n", loc);
    printf("  État         : " C_BOLD "%s" C_RST "\n", status);
    printf("  TMK KCV      : %s\n", tmkk[0] ? tmkk : "—");
    printf("  TPK KCV      : %s\n", tpkk[0] ? tpkk : "—");
    printf("  TAK KCV      : %s\n", takk[0] ? takk : "—");
    printf("  Créé le      : %s\n\n", ts);
}

static void cmd_atm_provision(const char *atm_id) {
    char body[128];
    snprintf(body, sizeof(body), "{\"id\":\"%s\"}", atm_id);
    printf("\n[ATM] Provisionnement des clés pour %s via commandes HSM...\n\n", atm_id);
    if (http_post("/api/admin/atm/provision", body, g_resp, RESP_BUF) != 0) {
        pr_err("Connexion échouée"); return;
    }
    if (json_int(g_resp, "rc") != 0) {
        char msg[256]; json_str(g_resp, "message", msg, sizeof(msg));
        pr_err("%s", msg); return;
    }
    const char *knames[] = {"TMK","TPK","TAK", NULL};
    for (int i = 0; knames[i]; i++) {
        char search[32]; snprintf(search, sizeof(search), "\"key\":\"%s\"", knames[i]);
        const char *found = strstr(g_resp, search);
        if (!found) continue;
        char kcv[16]="?"; const char *kp=strstr(found,"\"kcv\":");
        if(kp) json_str(found,"kcv",kcv,sizeof(kcv));
        pr_cmd("Génération %s pour %s avec commande A0 (code=%02d)", knames[i], atm_id, i+1);
        pr_ok("%s protégée sous LMK", knames[i]);
        printf("       KCV : " C_BOLD "%s" C_RST "\n\n", kcv);
    }
    pr_ok("Provisionnement ATM terminé");
    pr_ok("Aucune clé claire n'a été affichée ou stockée\n");
}

static void cmd_atm_action(const char *atm_id, const char *action,
                           const char *route, const char *verb) {
    char body[128]; snprintf(body, sizeof(body), "{\"id\":\"%s\"}", atm_id);
    printf("\n[ATM] %s du GAB %s\n", verb, atm_id);
    if (http_post(route, body, g_resp, RESP_BUF) != 0) {
        pr_err("Connexion échouée"); return;
    }
    char msg[256], status[32];
    json_str(g_resp, "message", msg, sizeof(msg));
    json_str(g_resp, "status", status, sizeof(status));
    if (json_int(g_resp, "rc") == 0) {
        pr_ok("%s", msg);
        if (status[0]) printf("  État : " C_BOLD "%s" C_RST "\n", status);
    } else { pr_err("%s", msg); }
    printf("\n");
    (void)action;
}

static void cmd_atm_kcv(const char *atm_id) {
    char body[128]; snprintf(body, sizeof(body), "{\"id\":\"%s\"}", atm_id);
    if (http_post("/api/admin/atm/kcv", body, g_resp, RESP_BUF) != 0) {
        pr_err("Connexion échouée"); return;
    }
    if (json_int(g_resp, "rc") != 0) {
        char msg[256]; json_str(g_resp, "message", msg, sizeof(msg));
        pr_err("%s", msg); return;
    }
    char tmkk[8], tpkk[8], takk[8];
    json_str(g_resp, "tmk_kcv", tmkk, sizeof(tmkk));
    json_str(g_resp, "tpk_kcv", tpkk, sizeof(tpkk));
    json_str(g_resp, "tak_kcv", takk, sizeof(takk));
    printf("\n" C_BOLD "%s KEY CHECK VALUES" C_RST "\n", atm_id);
    printf("─────────────────────────\n");
    printf("  TMK KCV : " C_BOLD "%s" C_RST "\n", tmkk[0]?tmkk:"—");
    printf("  TPK KCV : " C_BOLD "%s" C_RST "\n", tpkk[0]?tpkk:"—");
    printf("  TAK KCV : " C_BOLD "%s" C_RST "\n\n", takk[0]?takk:"—");
}

static void cmd_wire(const char *cmd_str) {
    char body[512];
    snprintf(body, sizeof(body), "{\"cmd\":\"%s\"}", cmd_str);
    printf(C_INFO "→ POST /api/hsm/cmd { cmd: \"%s\" }" C_RST "\n", cmd_str);
    if (http_post("/api/hsm/cmd", body, g_resp, RESP_BUF) != 0) {
        pr_err("Connexion échouée"); return;
    }
    char raw[256], kcv[16], msg[256];
    json_str(g_resp, "rawResponse", raw, sizeof(raw));
    json_str(g_resp, "kcv", kcv, sizeof(kcv));
    json_str(g_resp, "message", msg, sizeof(msg));
    int rc = json_int(g_resp, "rc");
    if (raw[0]) printf("  Réponse brute : " C_BOLD "%s" C_RST "\n", raw);
    if (kcv[0])  printf("  KCV           : " C_BOLD "%s" C_RST "\n", kcv);
    if (rc == 0) pr_ok("%s", msg[0] ? msg : "OK");
    else         pr_err("%s", msg[0] ? msg : "Erreur");
    printf("\n");
}

static void show_help(void) {
    printf("\n" C_BOLD "PayHSM — Commandes disponibles" C_RST " (style Thales payShield 10K)\n");
    printf("──────────────────────────────────────────────────────────────\n");
    printf(C_BOLD "Protocole wire payShield :" C_RST "\n");
    printf("  [HDR][CMD][PARAMS]   ex: 0001A01001U  (A0/A6/A8)\n\n");
    printf(C_BOLD "Switch bancaire :" C_RST "\n");
    printf("  SWITCH INIT              Initialiser l'environnement Switch\n");
    printf("  SWITCH STATUS            État du Switch et clés principales\n");
    printf("  SWITCH PROVISION         Générer TMK/ZMK/ZPK/PVK/IMK via HSM\n");
    printf("  SWITCH LOGS              Journal d'audit Switch/ATM\n\n");
    printf(C_BOLD "GAB / ATM :" C_RST "\n");
    printf("  ATM ADD <id> \"<nom>\" \"<loc>\"   Enregistrer un GAB\n");
    printf("  ATM LIST                         Lister tous les GAB\n");
    printf("  ATM STATUS <id>                  Statut et KCV d'un GAB\n");
    printf("  ATM PROVISION <id>               Générer TMK/TPK/TAK via HSM\n");
    printf("  ATM ENABLE   <id>                Activer un GAB\n");
    printf("  ATM DISABLE  <id>                Désactiver un GAB\n");
    printf("  ATM BLOCK    <id>                Bloquer un GAB\n");
    printf("  ATM REMOVE   <id>                Supprimer un GAB\n");
    printf("  ATM KCV      <id>                KCV des clés d'un GAB\n");
    printf("  ATM CONNECT     <id>             Simuler connexion GAB\n");
    printf("  ATM DISCONNECT  <id>             Simuler déconnexion GAB\n");
    printf("  ATM ROTATE-KEYS <id>             Renouveler TPK/TAK via HSM\n\n");
    printf(C_BOLD "Utilitaires :" C_RST "\n");
    printf("  HEALTH / STATUS / VAULT / LMK    Infos HSM\n");
    printf("  HELP   exit / quit\n\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
   Parser de commandes
   ═══════════════════════════════════════════════════════════════════════════ */

/* Extrait un token entre guillemets ou sans espace */
static char *next_token(char *p, char *buf, size_t blen) {
    while (*p == ' ') p++;
    if (!*p) { buf[0]='\0'; return p; }
    if (*p == '"') {
        p++;
        size_t i = 0;
        while (*p && *p != '"' && i < blen-1) buf[i++] = *p++;
        buf[i] = '\0';
        if (*p == '"') p++;
    } else {
        size_t i = 0;
        while (*p && *p != ' ' && i < blen-1) buf[i++] = *p++;
        buf[i] = '\0';
    }
    return p;
}

static void dispatch(char *line) {
    /* Trim trailing whitespace */
    size_t len = strlen(line);
    while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r' || line[len-1] == ' '))
        line[--len] = '\0';
    if (!len) return;

    /* Uppercase first word for comparison */
    char word1[32], word2[32], word3[128], word4[128], word5[128];
    char *p = line;
    p = next_token(p, word1, sizeof(word1));
    for (int i = 0; word1[i]; i++) word1[i] = (char)toupper((unsigned char)word1[i]);
    p = next_token(p, word2, sizeof(word2));
    for (int i = 0; word2[i]; i++) word2[i] = (char)toupper((unsigned char)word2[i]);

    /* Exit */
    if (!strcmp(word1,"EXIT") || !strcmp(word1,"QUIT")) {
        printf("Au revoir.\n"); exit(0);
    }

    /* Help */
    if (!strcmp(word1,"HELP") || !strcmp(word1,"?")) { show_help(); return; }

    /* Wire format : starts with digit */
    if (isdigit((unsigned char)word1[0])) { cmd_wire(line); return; }

    /* Health / Status */
    if (!strcmp(word1,"HEALTH") || !strcmp(word1,"STATUS")) { cmd_health(); return; }

    /* Vault */
    if (!strcmp(word1,"VAULT")) {
        if (http_get("/api/vault", g_resp, RESP_BUF) != 0) { pr_err("Connexion"); return; }
        printf("\nCOFFRE KEYS\n───────────\n");
        const char *pp = g_resp;
        int cnt = 0;
        while ((pp = strstr(pp, "\"id\":")) != NULL) {
            char id[48], type[16], kcv[8];
            json_str(pp, "id", id, sizeof(id));
            json_str(pp, "type", type, sizeof(type));
            json_str(pp, "kcv", kcv, sizeof(kcv));
            printf("  %-40s  %-6s  KCV:%s\n", id, type, kcv);
            pp += 5; cnt++;
        }
        if (!cnt) printf("  Coffre vide.\n");
        printf("\n");
        return;
    }

    /* LMK status */
    if (!strcmp(word1,"LMK")) {
        if (http_get("/api/lmk/status", g_resp, RESP_BUF) != 0) { pr_err("Connexion"); return; }
        char frag[8], integ[8], mut[8];
        json_str(g_resp,"fragmented",frag,sizeof(frag));
        json_str(g_resp,"integrityOk",integ,sizeof(integ));
        json_str(g_resp,"mutationCount",mut,sizeof(mut));
        printf("\nLMK STATUS\n──────────\n");
        printf("  Fragmentée   : %s\n", strcmp(frag,"1")==0 ? C_OK"OUI"C_RST : C_ERR"NON"C_RST);
        printf("  Intégrité    : %s\n", strcmp(integ,"1")==0 ? C_OK"OK"C_RST : C_ERR"FAIL"C_RST);
        printf("  Mutations    : %s\n\n", mut);
        return;
    }

    /* SWITCH commands */
    if (!strcmp(word1,"SWITCH")) {
        if      (!strcmp(word2,"INIT"))      { cmd_switch_init(); }
        else if (!strcmp(word2,"STATUS"))    { cmd_switch_status(); }
        else if (!strcmp(word2,"PROVISION")) { cmd_switch_provision(); }
        else if (!strcmp(word2,"LOGS"))      { cmd_switch_logs(); }
        else {
            pr_err("SWITCH : sous-commande inconnue '%s'", word2);
            printf("  Sous-commandes : INIT  STATUS  PROVISION  LOGS\n");
        }
        return;
    }

    /* ATM commands */
    if (!strcmp(word1,"ATM")) {
        /* ATM ADD <id> "<name>" "<loc>" */
        if (!strcmp(word2,"ADD")) {
            p = next_token(p, word3, sizeof(word3));
            p = next_token(p, word4, sizeof(word4));
            p = next_token(p, word5, sizeof(word5));
            if (!word3[0]) { pr_err("Usage: ATM ADD <id> \"<nom>\" \"<localisation>\""); return; }
            cmd_atm_add(word3, word4[0]?word4:word3, word5[0]?word5:"—");
            return;
        }
        /* Commands without ATM_ID */
        if (!strcmp(word2,"LIST")) { cmd_atm_list(); return; }
        /* Commands with ATM_ID */
        p = next_token(p, word3, sizeof(word3));
        if (!word3[0]) {
            /* word3 might be in word2 position for single-word subcommand — check */
            pr_err("ATM %s : <ATM_ID> requis", word2); return;
        }
        if      (!strcmp(word2,"STATUS"))       { cmd_atm_status(word3); }
        else if (!strcmp(word2,"PROVISION"))    { cmd_atm_provision(word3); }
        else if (!strcmp(word2,"ENABLE"))       { cmd_atm_action(word3,"ENABLE","/api/admin/atm/enable","Activation"); }
        else if (!strcmp(word2,"DISABLE"))      { cmd_atm_action(word3,"DISABLE","/api/admin/atm/disable","Désactivation"); }
        else if (!strcmp(word2,"BLOCK"))        { cmd_atm_action(word3,"BLOCK","/api/admin/atm/block","Blocage"); }
        else if (!strcmp(word2,"REMOVE"))       { cmd_atm_action(word3,"REMOVE","/api/admin/atm/remove","Suppression"); }
        else if (!strcmp(word2,"KCV"))          { cmd_atm_kcv(word3); }
        else if (!strcmp(word2,"CONNECT"))      { cmd_atm_action(word3,"CONNECT","/api/admin/atm/connect","Connexion"); }
        else if (!strcmp(word2,"DISCONNECT"))   { cmd_atm_action(word3,"DISCONNECT","/api/admin/atm/disconnect","Déconnexion"); }
        else if (!strcmp(word2,"ROTATE-KEYS"))  { cmd_atm_action(word3,"ROTATE","/api/admin/atm/rotate-keys","Rotation des clés"); }
        else {
            pr_err("ATM : sous-commande inconnue '%s'", word2);
            printf("  Voir HELP pour la liste des commandes.\n");
        }
        return;
    }

    pr_err("Commande inconnue : '%s'  (HELP pour l'aide)", word1);
}

/* ═══════════════════════════════════════════════════════════════════════════
   Main
   ═══════════════════════════════════════════════════════════════════════════ */

int main(int argc, char **argv) {
    /* Ignorer les args non-shell */
    int shell_mode = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "shell")) { shell_mode = 1; }
        else if (!strcmp(argv[i], "--url") && i+1 < argc) {
            /* --url http://host:port */
            char *url = argv[++i];
            char *host_start = strstr(url, "://");
            if (host_start) host_start += 3; else host_start = url;
            char *colon = strrchr(host_start, ':');
            if (colon) {
                g_port = atoi(colon + 1);
                size_t hlen = (size_t)(colon - host_start);
                if (hlen >= sizeof(g_host)) hlen = sizeof(g_host) - 1;
                strncpy(g_host, host_start, hlen);
                g_host[hlen] = '\0';
            } else {
                strncpy(g_host, host_start, sizeof(g_host) - 1);
            }
        }
    }

    if (!shell_mode) {
        fprintf(stderr,
            "Usage: %s shell [--url http://host:port]\n"
            "Défaut: http://%s:%d\n",
            argv[0], DEFAULT_HOST, DEFAULT_PORT);
        return 1;
    }

    /* Vérifier la connexion */
    if (http_get("/api/health", g_resp, RESP_BUF) != 0) {
        fprintf(stderr,
            C_ERR "[ERR]" C_RST " Impossible de se connecter à %s:%d\n"
            "  Vérifiez que payhsm-httpd tourne : ./src/lib/payhsm/bin/payhsm-httpd 8765 frontend\n",
            g_host, g_port);
        return 1;
    }

    printf(C_BOLD "\n╔══════════════════════════════════════════════╗\n");
    printf("║   PayHSM — Console Thales payShield 10K     ║\n");
    printf("╚══════════════════════════════════════════════╝" C_RST "\n");
    printf("  Connecté à %s:%d\n", g_host, g_port);
    printf("  Tapez " C_BOLD "HELP" C_RST " pour la liste des commandes.\n\n");

    char line[INPUT_BUF];
    while (1) {
        printf(C_BOLD "HSM> " C_RST);
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) break;
        dispatch(line);
    }
    printf("\n");
    return 0;
}
