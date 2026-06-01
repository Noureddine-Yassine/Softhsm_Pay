/* Daemon PayHSM — socket Unix, protocole texte ligne par ligne */
#include "../payhsm_core.h"
#include "../defense/defense.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#define SOCK_PATH "/tmp/payhsm.sock"
#define LINE_MAX  4096

static void hex_encode(const uint8_t *in, size_t n, char *out) {
    for (size_t i = 0; i < n; i++)
        sprintf(out + i * 2, "%02X", in[i]);
    out[n * 2] = '\0';
}

static int hex_decode(const char *hex, uint8_t *out, size_t n) {
    size_t len = strlen(hex);
    if (len != n * 2) return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned int b;
        if (sscanf(hex + i * 2, "%2x", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    return 0;
}

static void reply(FILE *out, int rc, const char *msg) {
    fprintf(out, "%d %s\n", rc, msg ? msg : "");
    fflush(out);
}

static void handle_line(char *line, FILE *out) {
    char cmd[64];
    char *rest = line;
    while (*rest == ' ' || *rest == '\t') rest++;
    if (sscanf(rest, "%63s", cmd) != 1) {
        reply(out, PAYHSM_RC_ERR, "syntaxe");
        return;
    }
    char *arg = strchr(rest, ' ');
    if (arg) {
        arg++;
        while (*arg == ' ') arg++;
    } else {
        arg = "";
    }

    if (strcmp(cmd, "PING") == 0) {
        reply(out, PAYHSM_RC_OK, "PONG");
    } else if (strcmp(cmd, "STARTUP") == 0) {
        char pass[256], dir[PAYHSM_PATH_MAX];
        if (sscanf(arg, "%255s %255s", pass, dir) != 2) {
            reply(out, PAYHSM_RC_ERR, "STARTUP <pass> <datadir>");
            return;
        }
        int rc = payhsm_startup(pass, dir);
        reply(out, rc, rc == PAYHSM_RC_OK ? "OK" : "echec startup");
    } else if (strcmp(cmd, "PROVISION") == 0) {
        char pass[256], dir[PAYHSM_PATH_MAX], terms[512];
        if (sscanf(arg, "%255s %255s %511[^\n]", pass, dir, terms) < 2) {
            reply(out, PAYHSM_RC_ERR, "PROVISION <pass> <dir> [term1,term2]");
            return;
        }
        const char *tlist[16];
        int nt = 0;
        char *tok = strtok(terms, ",");
        while (tok && nt < 16) {
            while (*tok == ' ') tok++;
            if (*tok) tlist[nt++] = tok;
            tok = strtok(NULL, ",");
        }
        if (nt == 0) {
            tlist[0] = "ATM001";
            nt = 1;
        }
        int rc = payhsm_provision(pass, dir, tlist, nt);
        reply(out, rc, rc == PAYHSM_RC_OK ? "provision OK" : "echec provision");
    } else if (strcmp(cmd, "STATUS") == 0) {
        char buf[4096];
        if (payhsm_status_text(buf, sizeof(buf)) != PAYHSM_RC_OK)
            reply(out, PAYHSM_RC_ERR, "status");
        else
            reply(out, PAYHSM_RC_OK, buf);
    } else if (strcmp(cmd, "REGISTER") == 0) {
        char pan[32], pin[16];
        if (sscanf(arg, "%31s %15s", pan, pin) != 2) {
            reply(out, PAYHSM_RC_ERR, "REGISTER <pan> <pin>");
            return;
        }
        int rc = payhsm_register_card(pan, pin);
        reply(out, rc, rc == PAYHSM_RC_OK ? "carte enregistree" : "echec");
    } else if (strcmp(cmd, "GAP") == 0) {
        char term[64], pin[16], pan[32];
        if (sscanf(arg, "%63s %15s %31s", term, pin, pan) != 3) {
            reply(out, PAYHSM_RC_ERR, "GAP <term> <pin> <pan>");
            return;
        }
        uint8_t pb[8];
        char hex[17];
        int rc = payhsm_gap_generate_pin_block(term, pin, pan, pb);
        if (rc != PAYHSM_RC_OK) {
            reply(out, rc, "echec pin block");
            return;
        }
        hex_encode(pb, 8, hex);
        secure_zero(pb, sizeof(pb));
        reply(out, PAYHSM_RC_OK, hex);
    } else if (strcmp(cmd, "VERIFY") == 0) {
        char term[64], pan[32], hex[32];
        if (sscanf(arg, "%63s %31s %31s", term, pan, hex) != 3) {
            reply(out, PAYHSM_RC_ERR, "VERIFY <term> <pan> <pinblock_hex>");
            return;
        }
        uint8_t pb[8];
        int vrc;
        if (hex_decode(hex, pb, 8) != 0) {
            reply(out, PAYHSM_RC_ERR, "hex invalide");
            return;
        }
        int rc = payhsm_verify_pin_block(term, pan, pb, &vrc);
        secure_zero(pb, sizeof(pb));
        if (rc != PAYHSM_RC_OK) {
            reply(out, rc, "erreur verify");
            return;
        }
        reply(out, vrc, vrc == PAYHSM_RC_OK ? "APPROVED" : "DECLINED");
    } else if (strcmp(cmd, "TRANSLATE") == 0) {
        char term[64], hex[32];
        if (sscanf(arg, "%63s %31s", term, hex) != 2) {
            reply(out, PAYHSM_RC_ERR, "TRANSLATE <term> <pinblock_hex>");
            return;
        }
        uint8_t in[8], pb_out[8];
        char outhex[17];
        if (hex_decode(hex, in, 8) != 0) {
            reply(out, PAYHSM_RC_ERR, "hex invalide");
            return;
        }
        int rc = payhsm_translate_pin_to_zpk(term, in, pb_out);
        secure_zero(in, sizeof(in));
        if (rc != PAYHSM_RC_OK) {
            reply(out, rc, "echec translation");
            return;
        }
        hex_encode(pb_out, 8, outhex);
        secure_zero(pb_out, sizeof(pb_out));
        reply(out, PAYHSM_RC_OK, outhex);
    } else if (strcmp(cmd, "SHUTDOWN") == 0) {
        payhsm_shutdown();
        reply(out, PAYHSM_RC_OK, "bye");
    } else {
        reply(out, PAYHSM_RC_ERR, "commande inconnue");
    }
}

static void serve_client(int fd) {
    FILE *in = fdopen(fd, "r");
    FILE *out = fdopen(dup(fd), "w");
    if (!in || !out) {
        if (in) fclose(in);
        if (out) fclose(out);
        close(fd);
        return;
    }
    char line[LINE_MAX];
    while (fgets(line, sizeof(line), in)) {
        size_t n = strlen(line);
        if (n > 0 && line[n - 1] == '\n') line[n - 1] = '\0';
        if (strcmp(line, "QUIT") == 0) break;
        handle_line(line, out);
    }
    fclose(in);
    fclose(out);
}

int main(int argc, char **argv) {
    const char *sockpath = SOCK_PATH;
    if (argc > 1) sockpath = argv[1];

    unlink(sockpath);
    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) {
        perror("socket");
        return 1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sockpath, sizeof(addr.sun_path) - 1);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(srv, 8) < 0) {
        perror("listen");
        return 1;
    }
    fprintf(stderr, "payhsmd: ecoute sur %s\n", sockpath);

    for (;;) {
        int cli = accept(srv, NULL, NULL);
        if (cli < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }
        serve_client(cli);
    }
    close(srv);
    unlink(sockpath);
    return 0;
}
