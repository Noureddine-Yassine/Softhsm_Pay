#include "defense.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>

/* -------------------------------------------------------
   secure_zero — zéroïsation résistante au compilateur
   Le volatile force l'écriture même si le compilateur
   pense que le buffer n'est plus utilisé après.
   ------------------------------------------------------- */
void secure_zero(void *ptr, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) *p++ = 0;
    __asm__ __volatile__("" ::: "memory"); /* barrière mémoire */
}

/* -------------------------------------------------------
   Pointeurs vers les fragments — définis dans xor_fragment.c
   On les zéroïse en cas d'urgence
   ------------------------------------------------------- */
extern unsigned char g_P3[32]; /* fragment .data */
extern void zero_all_fragments(void);

/* -------------------------------------------------------
   handler_fatal — handler des signaux fatals
   Zéroïse les secrets puis quitte proprement
   ------------------------------------------------------- */
static void handler_fatal(int sig __attribute__((unused)))

{
    /* Zéroïser P3 (.data) — le seul fragment accessible ici */
    secure_zero(g_P3, 32);

    /* Log minimal sans malloc (signal-safe) */
    const char msg[] = "[PAYHSM] signal fatal reçu — secrets effacés\n";
    write(STDERR_FILENO, msg, sizeof(msg) - 1);

    _exit(1); /* _exit et non exit() — signal-safe */
}

/* -------------------------------------------------------
   anti_dump_setup
   Désactive les core dumps et verrouille la mémoire.
   DOIT être appelé en premier.
   ------------------------------------------------------- */
int anti_dump_setup(void)
{
    /* 1. Désactiver les core dumps */
    struct rlimit rl = {0, 0};
    if (setrlimit(RLIMIT_CORE, &rl) != 0) {
        perror("[PAYHSM] setrlimit RLIMIT_CORE");
        return -1;
    }

    /* 2. Verrouiller toutes les pages en RAM (pas de swap) */
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
        perror("[PAYHSM] mlockall");
        return -1;
    }

    /* 3. Installer les handlers de signaux fatals */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler_fatal;
    sigemptyset(&sa.sa_mask);

    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
    sigaction(SIGFPE,  &sa, NULL);
    sigaction(SIGILL,  &sa, NULL);

    fprintf(stderr, "[PAYHSM] anti_dump_setup OK\n");
    return 0;
}

/* -------------------------------------------------------
   anti_ptrace_setup
   Bloque l'attachement d'un debugger.
   ------------------------------------------------------- */
int anti_ptrace_setup(void)
{
    /* 1. Bloquer ptrace sur ce processus */
    if (prctl(PR_SET_DUMPABLE, 0) != 0) {
        perror("[PAYHSM] prctl PR_SET_DUMPABLE");
        return -1;
    }

    /* 2. Empêcher toute élévation de privilèges */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("[PAYHSM] prctl PR_SET_NO_NEW_PRIVS");
        return -1;
    }

    fprintf(stderr, "[PAYHSM] anti_ptrace_setup OK\n");
    return 0;
}

/* -------------------------------------------------------
   anti_ptrace_check — vérification active
   Appelée en boucle pendant le fonctionnement.
   Lit /proc/self/status et vérifie TracerPid.
   ------------------------------------------------------- */
int anti_ptrace_check(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0; /* ne pas bloquer si lecture impossible */

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int tracer_pid = atoi(line + 10);
            fclose(f);
            if (tracer_pid != 0) {
                /* Un debugger est attaché */
                emergency_shutdown("debugger détecté (TracerPid != 0)");
            }
            return 0;
        }
    }

    fclose(f);
    return 0;
}

/* -------------------------------------------------------
   emergency_shutdown
   Zéroïse tous les secrets et termine le processus.
   ------------------------------------------------------- */
void emergency_shutdown(const char *reason)
{
    fprintf(stderr, "[PAYHSM] URGENCE : %s\n", reason);

    zero_all_fragments();
    _exit(99);
}