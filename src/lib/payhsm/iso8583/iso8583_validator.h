#ifndef PAYHSM_ISO8583_VALIDATOR_H
#define PAYHSM_ISO8583_VALIDATOR_H

#include "iso8583_types.h"

/*
 * Validate a parsed ISO 8583 message:
 *   - MTI must be one of the supported request types
 *   - Mandatory fields (DE3, DE4, DE11, DE41) must be present
 *   - Field lengths within bounds
 *
 * Returns ISO_OK or ISO_ERR_FORMAT / ISO_ERR_FIELD.
 * err_de is set to the offending DE number (0 if MTI error).
 */
int iso8583_validate(const iso8583_msg_t *msg, int *err_de);

/* Returns 1 if MTI is a recognised request type, 0 otherwise. */
int iso8583_mti_is_request(const char *mti);

#endif /* PAYHSM_ISO8583_VALIDATOR_H */
