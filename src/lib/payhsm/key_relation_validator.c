#include "key_relation_validator.h"
#include <ctype.h>
#include <string.h>

payhsm_kek_kind_t payhsm_export_kek_kind(const char *key_type_code3) {
    char c[4];
    if (!key_type_code3) return (payhsm_kek_kind_t)-1;
    strncpy(c, key_type_code3, 3);
    c[3] = '\0';
    for (int i = 0; c[i]; i++)
        c[i] = (char)toupper((unsigned char)c[i]);

    /* Sous ZMK */
    if (!strcmp(c, "001") || !strcmp(c, "000") || !strcmp(c, "008") || !strcmp(c, "00A"))
        return PAYHSM_KEK_ZMK;
    if (!strcmp(c, "109") || !strcmp(c, "00B") || !strcmp(c, "009"))
        return PAYHSM_KEK_ZMK;

    /* Sous TMK */
    if (!strcmp(c, "002") || !strcmp(c, "006") || !strcmp(c, "003") || !strcmp(c, "007"))
        return PAYHSM_KEK_TMK;

    return (payhsm_kek_kind_t)-1;
}

int payhsm_validate_export_hierarchy(const char *op_key_type_code3) {
    if (payhsm_export_kek_kind(op_key_type_code3) < 0)
        return PAYHSM_RC_ERR;
    return PAYHSM_RC_OK;
}
