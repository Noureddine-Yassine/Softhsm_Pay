#ifndef PAYHSM_ISO_CONFIG_H
#define PAYHSM_ISO_CONFIG_H

#define ISO_CFG_HOST_MAX  128
#define ISO_CFG_PATH_MAX  256

typedef struct {
    char tcp_host[ISO_CFG_HOST_MAX];  /* listen address, default "0.0.0.0" */
    int  tcp_port;                    /* ISO 8583 port, default 8583 */
    int  tls_enabled;                 /* 0 = plain, 1 = TLS */
    char tls_cert_path[ISO_CFG_PATH_MAX];
    char tls_key_path[ISO_CFG_PATH_MAX];
    int  mtls_enabled;                /* 0 = no mTLS, 1 = verify client cert */
    char ca_cert_path[ISO_CFG_PATH_MAX];
    char data_dir[ISO_CFG_PATH_MAX];  /* payhsm data directory */
    int  has_tpdu;                    /* 1 = messages include 5-byte TPDU */
    /* HTTP admin */
    char http_host[ISO_CFG_HOST_MAX];
    int  http_port;                   /* default 8765 */
} iso_config_t;

/*
 * Load configuration from file (INI-style key=value, # comments).
 * Missing keys get built-in defaults.
 * Returns 0 on success, -1 on file open error.
 */
int iso_config_load(iso_config_t *cfg, const char *path);

/* Fill cfg with built-in defaults. */
void iso_config_defaults(iso_config_t *cfg);

#endif /* PAYHSM_ISO_CONFIG_H */
