#ifndef SECCOMP_POLICY_H
#define SECCOMP_POLICY_H

/* Installe le filtre BPF whitelist.
   DOIT être appelé après anti_ptrace_setup(). */
int install_seccomp_filter(void);

#endif