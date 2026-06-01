#ifndef PAYHSM_TCP_SERVER_H
#define PAYHSM_TCP_SERVER_H

#include "iso_config.h"
#include <openssl/ssl.h>

typedef struct {
    const iso_config_t *cfg;
    SSL_CTX            *ssl_ctx;   /* NULL if TLS disabled */
    int                 server_fd;
    volatile int        running;
} tcp_server_t;

/*
 * Initialise the TCP (and optionally TLS) server.
 * Creates the listen socket and SSL_CTX.
 * Returns 0 on success, -1 on error.
 */
int tcp_server_init(tcp_server_t *srv, const iso_config_t *cfg);

/*
 * Accept-and-serve loop (blocking).
 * Each accepted connection is handed off to a new pthread.
 * Returns when srv->running is set to 0.
 */
void tcp_server_run(tcp_server_t *srv);

/* Signal the server loop to stop. */
void tcp_server_stop(tcp_server_t *srv);

/* Free resources (SSL_CTX, close socket). */
void tcp_server_destroy(tcp_server_t *srv);

#endif /* PAYHSM_TCP_SERVER_H */
