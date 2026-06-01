#ifndef DEFENSE_H
#define DEFENSE_H
#include <stddef.h> 
/* Installe toutes les défenses passives.
   DOIT être appelé avant tout chargement de secret. */
int anti_dump_setup(void);
int anti_ptrace_setup(void);

/* Vérification active — appelée en boucle */
int anti_ptrace_check(void);

/* Zéroïsation résistante aux optimisations du compilateur */
void secure_zero(void *ptr, size_t len);

/* Arrêt d'urgence : zéroïse tout et quitte */
void emergency_shutdown(const char *reason);

#endif