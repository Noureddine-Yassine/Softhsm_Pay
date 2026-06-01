#include "tcp_server.h"
#include "../iso8583/iso8583_parser.h"
#include "../iso8583/iso8583_packer.h"
#include "../iso8583/iso8583_validator.h"
#include "../iso8583/iso8583_mapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/err.h>

/* ── Per-connection context ──────────────────────────────────── */

typedef struct {
    int         fd;
    SSL        *ssl;       /* NULL if no TLS */
    const iso_config_t *cfg;
} conn_ctx_t;

/* ── I/O helpers ─────────────────────────────────────────────── */

static int conn_read(conn_ctx_t *c, uint8_t *buf, int len)
{
    if (c->ssl)
        return SSL_read(c->ssl, buf, len);
    int n = 0;
    while (n < len) {
        int r = (int)recv(c->fd, buf + n, len - n, MSG_WAITALL);
        if (r <= 0) return r;
        n += r;
    }
    return n;
}

static int conn_write(conn_ctx_t *c, const uint8_t *buf, int len)
{
    if (c->ssl)
        return SSL_write(c->ssl, buf, len);
    return (int)send(c->fd, buf, len, 0);
}

/* ── Send ISO 8583 response with 2-byte length prefix ───────── */

static void send_response(conn_ctx_t *c, const iso8583_msg_t *resp)
{
    uint8_t raw[ISO8583_MSG_MAX];
    int n = iso8583_pack(resp, raw, sizeof(raw));
    if (n <= 0) return;

    uint8_t framed[ISO8583_MSG_MAX + 2];
    framed[0] = (uint8_t)((n >> 8) & 0xFF);
    framed[1] = (uint8_t)(n & 0xFF);
    memcpy(framed + 2, raw, n);
    conn_write(c, framed, n + 2);
}

/* ── Build and send an error response ───────────────────────── */

static void send_error_resp(conn_ctx_t *c, const iso8583_msg_t *req,
                            const char *rc)
{
    iso8583_msg_t resp;
    iso8583_build_response(req, &resp, rc, NULL, NULL, NULL, 0);
    send_response(c, &resp);
}

/* ── Process one ISO 8583 message ───────────────────────────── */

static void process_message(conn_ctx_t *c, const uint8_t *buf, int len)
{
    /* Parse */
    iso8583_msg_t req;
    memset(&req, 0, sizeof(req));
    if (iso8583_parse(buf, len, &req, c->cfg->has_tpdu) != ISO_OK) {
        fprintf(stderr, "[iso] parse error (len=%d)\n", len);
        return; /* can't build proper response without MTI */
    }

    /* Validate */
    int err_de = 0;
    if (iso8583_validate(&req, &err_de) != ISO_OK) {
        fprintf(stderr, "[iso] validate error DE%d MTI=%s\n",
                err_de, req.mti);
        send_error_resp(c, &req, ISO_RC_INVALID_FORMAT);
        return;
    }

    /* Map */
    iso8583_hsm_req_t hsm_req;
    iso8583_map_request(&req, &hsm_req);

    /* Execute */
    char    rc_str[3]  = {0};
    uint8_t mac_out[8] = {0};
    int     mac_ok     = 0;
    char    auth_code[7] = {0};
    uint8_t emv_resp[256] = {0};
    int     emv_resp_len  = 0;

    iso8583_execute(&req, &hsm_req, rc_str, mac_out, &mac_ok,
                    auth_code, emv_resp, &emv_resp_len);

    /* Build response */
    iso8583_msg_t resp;
    iso8583_build_response(
        &req, &resp, rc_str,
        mac_ok ? mac_out : NULL,
        auth_code[0] ? (const uint8_t *)auth_code : NULL,
        emv_resp_len > 0 ? emv_resp : NULL,
        emv_resp_len
    );

    send_response(c, &resp);
}

/* ── Connection thread ───────────────────────────────────────── */

static void *conn_thread(void *arg)
{
    conn_ctx_t *c = (conn_ctx_t *)arg;

    /* TLS handshake */
    if (c->ssl) {
        if (SSL_accept(c->ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            goto cleanup;
        }
    }

    /* Message loop: 2-byte length prefix framing */
    while (1) {
        uint8_t hdr[2];
        int r = conn_read(c, hdr, 2);
        if (r != 2) break; /* connection closed or error */

        int msg_len = ((int)hdr[0] << 8) | hdr[1];
        if (msg_len <= 0 || msg_len > ISO8583_MSG_MAX) {
            fprintf(stderr, "[iso] invalid length prefix %d\n", msg_len);
            break;
        }

        uint8_t buf[ISO8583_MSG_MAX];
        r = conn_read(c, buf, msg_len);
        if (r != msg_len) break;

        process_message(c, buf, msg_len);
    }

cleanup:
    if (c->ssl) { SSL_shutdown(c->ssl); SSL_free(c->ssl); }
    close(c->fd);
    free(c);
    return NULL;
}

/* ── TCP server init ─────────────────────────────────────────── */

int tcp_server_init(tcp_server_t *srv, const iso_config_t *cfg)
{
    memset(srv, 0, sizeof(*srv));
    srv->cfg     = cfg;
    srv->running = 1;

    /* TLS context */
    if (cfg->tls_enabled) {
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();

        srv->ssl_ctx = SSL_CTX_new(TLS_server_method());
        if (!srv->ssl_ctx) {
            ERR_print_errors_fp(stderr);
            return -1;
        }
        if (SSL_CTX_use_certificate_file(srv->ssl_ctx,
                cfg->tls_cert_path, SSL_FILETYPE_PEM) <= 0 ||
            SSL_CTX_use_PrivateKey_file(srv->ssl_ctx,
                cfg->tls_key_path, SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(srv->ssl_ctx);
            return -1;
        }
        if (cfg->mtls_enabled && cfg->ca_cert_path[0]) {
            SSL_CTX_set_verify(srv->ssl_ctx,
                SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
            SSL_CTX_load_verify_locations(srv->ssl_ctx,
                cfg->ca_cert_path, NULL);
        }
        /* Enforce TLS 1.2+ */
        SSL_CTX_set_min_proto_version(srv->ssl_ctx, TLS1_2_VERSION);
    }

    /* Listen socket */
    srv->server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv->server_fd < 0) { perror("socket"); return -1; }

    int opt = 1;
    setsockopt(srv->server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)cfg->tcp_port);
    inet_pton(AF_INET, cfg->tcp_host, &addr.sin_addr);

    if (bind(srv->server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(srv->server_fd);
        return -1;
    }
    if (listen(srv->server_fd, 16) < 0) {
        perror("listen");
        close(srv->server_fd);
        return -1;
    }
    printf("[iso] listening on %s:%d (TLS=%s)\n",
           cfg->tcp_host, cfg->tcp_port,
           cfg->tls_enabled ? "yes" : "no");
    return 0;
}

/* ── Accept loop ─────────────────────────────────────────────── */

void tcp_server_run(tcp_server_t *srv)
{
    while (srv->running) {
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        int fd = accept(srv->server_fd, (struct sockaddr *)&peer, &peer_len);
        if (fd < 0) {
            if (srv->running) perror("accept");
            continue;
        }

        conn_ctx_t *c = calloc(1, sizeof(*c));
        if (!c) { close(fd); continue; }
        c->fd  = fd;
        c->cfg = srv->cfg;

        if (srv->ssl_ctx) {
            c->ssl = SSL_new(srv->ssl_ctx);
            SSL_set_fd(c->ssl, fd);
        }

        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&tid, &attr, conn_thread, c) != 0) {
            free(c);
            close(fd);
        }
        pthread_attr_destroy(&attr);
    }
}

void tcp_server_stop(tcp_server_t *srv)
{
    srv->running = 0;
    shutdown(srv->server_fd, SHUT_RDWR);
}

void tcp_server_destroy(tcp_server_t *srv)
{
    if (srv->ssl_ctx) { SSL_CTX_free(srv->ssl_ctx); srv->ssl_ctx = NULL; }
    if (srv->server_fd >= 0) { close(srv->server_fd); srv->server_fd = -1; }
}
