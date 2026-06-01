/* Client CLI PayHSM — daemon Unix socket ou mode direct (lib C) */
#include "../payhsm_core.h"
#include "../defense/defense.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCK_PATH "/tmp/payhsm.sock"

static int daemon_send(const char *sockpath, const char *line, char *resp, size_t resplen) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sockpath, sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    FILE *w = fdopen(fd, "w");
    FILE *r = fdopen(dup(fd), "r");
    if (!w || !r) {
        if (w) fclose(w);
        if (r) fclose(r);
        close(fd);
        return -1;
    }
    fprintf(w, "%s\n", line);
    fflush(w);
    if (!fgets(resp, (int)resplen, r)) {
        fclose(w);
        fclose(r);
        return -1;
    }
    fclose(w);
    fclose(r);
    return 0;
}

static void hex_encode(const uint8_t *in, size_t n, char *out) {
    for (size_t i = 0; i < n; i++)
        sprintf(out + i * 2, "%02X", in[i]);
    out[n * 2] = '\0';
}

static int hex_decode(const char *hex, uint8_t *out, size_t n) {
    if (strlen(hex) != n * 2) return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned int b;
        if (sscanf(hex + i * 2, "%2x", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    return 0;
}

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s provision <pass> <datadir> [term1,term2]\n"
            "  %s startup <pass> <datadir>\n"
            "  %s status\n"
            "  %s register <pan> <pin>\n"
            "  %s gap <term> <pin> <pan>\n"
            "  %s verify <term> <pan> <pinblock_hex>\n"
            "  %s translate <term> <pinblock_hex>\n"
            "\nMode direct (sans payhsmd): PAYHSM_PASS + PAYHSM_DATA\n"
            "  %s --direct register|gap|verify|translate|status ...\n",
            prog, prog, prog, prog, prog, prog, prog, prog);
}

static const char *env_or(const char *name, const char *def) {
    const char *v = getenv(name);
    return (v && v[0]) ? v : def;
}

static int ensure_direct(const char *pass_override, const char *dir_override) {
    if (payhsm_ctx()->initialized) return 0;
    const char *pass = pass_override ? pass_override : env_or("PAYHSM_PASS", "");
    const char *dir  = dir_override  ? dir_override  : env_or("PAYHSM_DATA", "./payhsm-data");
    if (!pass[0]) {
        fprintf(stderr, "PAYHSM_PASS requis en mode direct\n");
        return -1;
    }
    return payhsm_startup(pass, dir);
}

int main(int argc, char **argv) {
    const char *sock = env_or("PAYHSM_SOCK", SOCK_PATH);
    char resp[8192];
    int force_direct = 0;

    if (argc >= 2 && strcmp(argv[1], "--direct") == 0) {
        force_direct = 1;
        argc--;
        argv++;
    }

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "provision") == 0) {
        if (argc < 4) { usage(argv[0]); return 1; }
        const char *pass = argv[2];
        const char *dir = argv[3];
        const char *terms = (argc > 4) ? argv[4] : "ATM001";
        char line[1024];
        snprintf(line, sizeof(line), "PROVISION %s %s %s", pass, dir, terms);
        if (!force_direct && daemon_send(sock, line, resp, sizeof(resp)) == 0) {
            printf("%s", resp);
            return 0;
        }
        const char *tlist[16];
        int nt = 0;
        char buf[512];
        strncpy(buf, terms, sizeof(buf) - 1);
        char *tok = strtok(buf, ",");
        while (tok && nt < 16) {
            tlist[nt++] = tok;
            tok = strtok(NULL, ",");
        }
        if (nt == 0) { tlist[0] = "ATM001"; nt = 1; }
        int rc = payhsm_provision(pass, dir, tlist, nt);
        printf("%d %s\n", rc, rc == 0 ? "provision OK" : "echec");
        payhsm_shutdown();
        return rc == 0 ? 0 : 1;
    }

    if (strcmp(cmd, "startup") == 0) {
        if (argc < 4) { usage(argv[0]); return 1; }
        if (!force_direct) {
            char line[512];
            snprintf(line, sizeof(line), "STARTUP %s %s", argv[2], argv[3]);
            if (daemon_send(sock, line, resp, sizeof(resp)) == 0) {
                printf("%s", resp);
                return 0;
            }
        }
        int rc = payhsm_startup(argv[2], argv[3]);
        printf("%d %s\n", rc, rc == 0 ? "startup OK" : "echec");
        return rc == 0 ? 0 : 1;
    }

    if (strcmp(cmd, "status") == 0) {
        if (!force_direct && daemon_send(sock, "STATUS", resp, sizeof(resp)) == 0) {
            printf("%s", resp);
            return 0;
        }
        if (ensure_direct(NULL, NULL) != 0) return 1;
        char buf[4096];
        payhsm_status_text(buf, sizeof(buf));
        fputs(buf, stdout);
        payhsm_shutdown();
        return 0;
    }

    if (strcmp(cmd, "register") == 0 && argc >= 4) {
        if (!force_direct) {
            char line[256];
            snprintf(line, sizeof(line), "REGISTER %s %s", argv[2], argv[3]);
            if (daemon_send(sock, line, resp, sizeof(resp)) == 0) {
                printf("%s", resp);
                return 0;
            }
        }
        if (ensure_direct(NULL, NULL) != 0) return 1;
        int rc = payhsm_register_card(argv[2], argv[3]);
        printf("%d %s\n", rc, rc == 0 ? "carte enregistree" : "echec");
        payhsm_shutdown();
        return rc == 0 ? 0 : 1;
    }

    if (strcmp(cmd, "gap") == 0 && argc >= 5) {
        if (!force_direct) {
            char line[512];
            snprintf(line, sizeof(line), "GAP %s %s %s", argv[2], argv[3], argv[4]);
            if (daemon_send(sock, line, resp, sizeof(resp)) == 0) {
                printf("%s", resp);
                return 0;
            }
        }
        if (ensure_direct(NULL, NULL) != 0) return 1;
        uint8_t pb[8];
        char hex[17];
        int rc = payhsm_gap_generate_pin_block(argv[2], argv[3], argv[4], pb);
        if (rc != PAYHSM_RC_OK) {
            printf("%d echec pin block\n", rc);
            payhsm_shutdown();
            return 1;
        }
        hex_encode(pb, 8, hex);
        secure_zero(pb, sizeof(pb));
        printf("0 %s\n", hex);
        payhsm_shutdown();
        return 0;
    }

    if (strcmp(cmd, "verify") == 0 && argc >= 5) {
        if (!force_direct) {
            char line[512];
            snprintf(line, sizeof(line), "VERIFY %s %s %s", argv[2], argv[3], argv[4]);
            if (daemon_send(sock, line, resp, sizeof(resp)) == 0) {
                printf("%s", resp);
                return 0;
            }
        }
        if (ensure_direct(NULL, NULL) != 0) return 1;
        uint8_t pb[8];
        int vrc;
        if (hex_decode(argv[4], pb, 8) != 0) {
            fprintf(stderr, "hex invalide\n");
            payhsm_shutdown();
            return 1;
        }
        int rc = payhsm_verify_pin_block(argv[2], argv[3], pb, &vrc);
        secure_zero(pb, sizeof(pb));
        if (rc != PAYHSM_RC_OK) {
            printf("%d erreur verify\n", rc);
            payhsm_shutdown();
            return 1;
        }
        printf("%d %s\n", vrc, vrc == PAYHSM_RC_OK ? "APPROVED" : "DECLINED");
        payhsm_shutdown();
        return vrc == PAYHSM_RC_OK ? 0 : 1;
    }

    if (strcmp(cmd, "translate") == 0 && argc >= 4) {
        if (!force_direct) {
            char line[512];
            snprintf(line, sizeof(line), "TRANSLATE %s %s", argv[2], argv[3]);
            if (daemon_send(sock, line, resp, sizeof(resp)) == 0) {
                printf("%s", resp);
                return 0;
            }
        }
        if (ensure_direct(NULL, NULL) != 0) return 1;
        uint8_t in[8], out[8];
        char hex[17];
        if (hex_decode(argv[3], in, 8) != 0) {
            fprintf(stderr, "hex invalide\n");
            payhsm_shutdown();
            return 1;
        }
        int rc = payhsm_translate_pin_to_zpk(argv[2], in, out);
        secure_zero(in, sizeof(in));
        if (rc != PAYHSM_RC_OK) {
            printf("%d echec translation\n", rc);
            payhsm_shutdown();
            return 1;
        }
        hex_encode(out, 8, hex);
        secure_zero(out, sizeof(out));
        printf("0 %s\n", hex);
        payhsm_shutdown();
        return 0;
    }

    usage(argv[0]);
    return 1;
}
