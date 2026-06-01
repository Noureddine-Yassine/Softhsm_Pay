/*
 * payhsm-isod — PayHSM ISO 8583 daemon
 *
 * Starts two server threads in the same process:
 *   1. ISO 8583 TCP (+ optional TLS) on port 8583 — payment transactions
 *   2. HTTP admin REST API on port 8765 — lifecycle, LMK, vault
 *
 * Both threads share the global payhsm_ctx() (LMK fragments in memory).
 *
 * Usage:
 *   payhsm-isod [config.ini] [frontend-dir]
 *
 * Config file defaults to /etc/payhsm/isod.ini if not specified.
 */

#include "payhsm_httpd.h"
#include "../payhsm_core.h"
#include "../defense/defense.h"
#include "../net/tcp_server.h"
#include "../net/iso_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>

#define DEFAULT_CONFIG "/etc/payhsm/isod.ini"

static volatile int g_running = 1;
static tcp_server_t g_iso_srv;

/* ── Signal handler ──────────────────────────────────────────── */

static void on_signal(int sig)
{
    (void)sig;
    g_running = 0;
    tcp_server_stop(&g_iso_srv);
}

/* ── HTTP admin thread ───────────────────────────────────────── */

typedef struct {
    int  port;
    char static_root[ISO_CFG_PATH_MAX];
} http_thread_arg_t;

static void *http_thread(void *arg)
{
    http_thread_arg_t *a = (http_thread_arg_t *)arg;
    payhsm_httpd_serve(a->port, a->static_root[0] ? a->static_root : NULL);
    return NULL;
}

/* ── Entry point ─────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    const char *cfg_path    = argc > 1 ? argv[1] : DEFAULT_CONFIG;
    const char *frontend_dir = argc > 2 ? argv[2] : "";

    /* ── Defense: must happen before any secret is loaded ── */
    anti_dump_setup();
    anti_ptrace_setup();

    /* ── Load configuration ── */
    iso_config_t cfg;
    int cfg_rc = iso_config_load(&cfg, cfg_path);
    if (cfg_rc != 0) {
        fprintf(stderr, "[isod] config not found at %s — using defaults\n",
                cfg_path);
    } else {
        fprintf(stderr, "[isod] config loaded: %s\n", cfg_path);
    }

    /* Command-line frontend dir overrides config */
    if (frontend_dir && frontend_dir[0])
        strncpy(cfg.data_dir, frontend_dir, sizeof(cfg.data_dir) - 1);

    /* ── Signals ── */
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    /* ── Init ISO 8583 TCP server ── */
    if (tcp_server_init(&g_iso_srv, &cfg) != 0) {
        fprintf(stderr, "[isod] failed to start ISO 8583 server\n");
        return 1;
    }

    /* ── Start HTTP admin thread ── */
    http_thread_arg_t http_arg;
    memset(&http_arg, 0, sizeof(http_arg));
    http_arg.port = cfg.http_port;
    if (frontend_dir && frontend_dir[0])
        strncpy(http_arg.static_root, frontend_dir,
                sizeof(http_arg.static_root) - 1);

    pthread_t http_tid;
    if (pthread_create(&http_tid, NULL, http_thread, &http_arg) != 0) {
        perror("pthread_create (http)");
        tcp_server_destroy(&g_iso_srv);
        return 1;
    }
    pthread_detach(http_tid);

    fprintf(stderr,
            "[isod] PayHSM ISO 8583 daemon started\n"
            "[isod]   ISO 8583 : %s:%d (TLS=%s)\n"
            "[isod]   HTTP admin: http://%s:%d\n"
            "[isod]   data_dir  : %s\n",
            cfg.tcp_host, cfg.tcp_port,
            cfg.tls_enabled ? "yes" : "no",
            cfg.http_host, cfg.http_port,
            cfg.data_dir[0] ? cfg.data_dir : "(not set — init via HTTP admin)");

    /* ── ISO 8583 accept loop (main thread) ── */
    tcp_server_run(&g_iso_srv);

    /* ── Cleanup ── */
    tcp_server_destroy(&g_iso_srv);
    payhsm_shutdown();
    fprintf(stderr, "[isod] stopped\n");
    return 0;
}
