#include "seccomp_policy.h"

#include <stdio.h>
#include <stdlib.h>
#include <seccomp.h>

/* -------------------------------------------------------
   install_seccomp_filter
   Whitelist des syscalls autorisés pour payhsmd.
   Tout syscall absent de cette liste tue le processus.
   ------------------------------------------------------- */
int install_seccomp_filter(void)
{
    /* Initialise avec action par défaut : tuer le processus */
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    if (!ctx) {
        fprintf(stderr, "[PAYHSM] seccomp_init échoué\n");
        return -1;
    }

    /* Liste blanche des syscalls nécessaires au démon */
    int allowed[] = {
        SCMP_SYS(read),
        SCMP_SYS(write),
        SCMP_SYS(open),
        SCMP_SYS(openat),
        SCMP_SYS(close),
        SCMP_SYS(fstat),
        SCMP_SYS(mmap),
        SCMP_SYS(munmap),
        SCMP_SYS(mlock),
        SCMP_SYS(madvise),
        SCMP_SYS(brk),
        SCMP_SYS(exit_group),
        SCMP_SYS(getrandom),
        SCMP_SYS(prctl),
        SCMP_SYS(futex),
        SCMP_SYS(clock_gettime),
    };

    int n = sizeof(allowed) / sizeof(allowed[0]);
    for (int i = 0; i < n; i++) {
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, allowed[i], 0) != 0) {
            fprintf(stderr, "[PAYHSM] seccomp_rule_add échoué\n");
            seccomp_release(ctx);
            return -1;
        }
    }

    /* Charger le filtre dans le noyau */
    if (seccomp_load(ctx) != 0) {
        fprintf(stderr, "[PAYHSM] seccomp_load échoué\n");
        seccomp_release(ctx);
        return -1;
    }

    seccomp_release(ctx);
    fprintf(stderr, "[PAYHSM] filtre seccomp installé OK\n");
    return 0;
}