#include "iso_config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

void iso_config_defaults(iso_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    strncpy(cfg->tcp_host,  "0.0.0.0", sizeof(cfg->tcp_host)  - 1);
    cfg->tcp_port    = 8583;
    cfg->tls_enabled = 0;
    cfg->mtls_enabled = 0;
    strncpy(cfg->http_host, "127.0.0.1", sizeof(cfg->http_host) - 1);
    cfg->http_port   = 8765;
    cfg->has_tpdu    = 0;
}

static void trim(char *s)
{
    int end = (int)strlen(s) - 1;
    while (end >= 0 && isspace((unsigned char)s[end])) s[end--] = '\0';
    char *p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
}

int iso_config_load(iso_config_t *cfg, const char *path)
{
    iso_config_defaults(cfg);

    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        /* strip comment */
        char *hash = strchr(line, '#');
        if (hash) *hash = '\0';
        trim(line);
        if (!line[0]) continue;

        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = line;
        char *val = eq + 1;
        trim(key);
        trim(val);

        if      (strcmp(key, "tcp_host")       == 0) strncpy(cfg->tcp_host,       val, sizeof(cfg->tcp_host)       - 1);
        else if (strcmp(key, "tcp_port")        == 0) cfg->tcp_port        = atoi(val);
        else if (strcmp(key, "tls_enabled")     == 0) cfg->tls_enabled     = atoi(val);
        else if (strcmp(key, "tls_cert_path")   == 0) strncpy(cfg->tls_cert_path,   val, sizeof(cfg->tls_cert_path)   - 1);
        else if (strcmp(key, "tls_key_path")    == 0) strncpy(cfg->tls_key_path,    val, sizeof(cfg->tls_key_path)    - 1);
        else if (strcmp(key, "mtls_enabled")    == 0) cfg->mtls_enabled    = atoi(val);
        else if (strcmp(key, "ca_cert_path")    == 0) strncpy(cfg->ca_cert_path,    val, sizeof(cfg->ca_cert_path)    - 1);
        else if (strcmp(key, "data_dir")        == 0) strncpy(cfg->data_dir,        val, sizeof(cfg->data_dir)        - 1);
        else if (strcmp(key, "has_tpdu")        == 0) cfg->has_tpdu        = atoi(val);
        else if (strcmp(key, "http_host")       == 0) strncpy(cfg->http_host,       val, sizeof(cfg->http_host)       - 1);
        else if (strcmp(key, "http_port")       == 0) cfg->http_port       = atoi(val);
    }
    fclose(f);
    return 0;
}
