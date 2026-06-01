/*
 * PayHSM — pkcs11_payment.cpp
 *
 * Thin C++ shim around the payment C modules. Compiled into libsofthsm2.so
 * so the demo front-end (and any other client) can dlsym() these symbols
 * inside the same address space where the LMK is fragmented.
 *
 * Each call:
 *   1. verifies LMK fragment integrity (mutate_fragments() inside the
 *      individual C functions handles the actual rotation),
 *   2. forwards to the underlying C function,
 *   3. lets the C function do its own secure_zero of locals.
 */
#include "pkcs11_payment.h"

extern "C" {
#include "../defense/defense.h"
#include "../keymanager/xor_fragment.h"
#include "pin.h"
#include "mac.h"
#include "emv.h"
#include "key_exchange.h"
}

#include "log.h"

#define PAYHSM_VERSION_STR "PayHSM 1.0 — PFE 2026"

extern "C" const char *PayHSM_version(void)
{
    return PAYHSM_VERSION_STR;
}

extern "C" int PayHSM_is_ready(void)
{
    /* recompose_for_op() into a throw-away buffer is a cheap liveness check;
     * if g_P2 is NULL it returns -1. We do NOT keep the recomposed LMK. */
    uint8_t scratch[LMK_SIZE];
    int rv = recompose_for_op(scratch);
    secure_zero(scratch, LMK_SIZE);
    return (rv == 0) ? 1 : 0;
}

static int payhsm_precheck(void)
{
    if (!PayHSM_is_ready()) {
        ERROR_MSG("PayHSM: LMK fragmentation not initialised — refusing op");
        return -1;
    }
    if (verify_integrity_quiet() != 0) {
        ERROR_MSG("PayHSM: LMK fragment integrity check FAILED");
        return -1;
    }
    return 0;
}

extern "C" int PayHSM_PIN_translate(const uint8_t *pin_block_in,
                                    const char    *pan,
                                    const uint8_t *tpk, size_t tpk_len,
                                    const uint8_t *zpk, size_t zpk_len,
                                    uint8_t        pin_block_out[8])
{
    if (payhsm_precheck() != 0) return -1;
    return translate_pin_block(pin_block_in, pan, tpk, tpk_len,
                               zpk, zpk_len, pin_block_out);
}

extern "C" int PayHSM_PIN_build(const char    *pin,
                                const char    *pan,
                                const uint8_t *tpk, size_t tpk_len,
                                uint8_t        pin_block_out[8])
{
    if (payhsm_precheck() != 0) return -1;
    return generate_pin_block(pin, pan, tpk, tpk_len, pin_block_out);
}

extern "C" int PayHSM_ARQC_verify(const uint8_t  sk_ac[16],
                                  const uint8_t *transaction_data,
                                  size_t         tx_len,
                                  const uint8_t  arqc_received[8])
{
    if (payhsm_precheck() != 0) return -1;
    return verify_arqc(sk_ac, transaction_data, tx_len, arqc_received);
}

extern "C" int PayHSM_EMV_derive_sk_ac(const uint8_t mk_ac[16],
                                       const uint8_t atc[2],
                                       uint8_t       sk_ac_out[16])
{
    if (payhsm_precheck() != 0) return -1;
    return derive_sk_ac(mk_ac, atc, sk_ac_out);
}

extern "C" int PayHSM_EMV_compute_arqc(const uint8_t  sk_ac[16],
                                       const uint8_t *transaction_data,
                                       size_t         tx_len,
                                       uint8_t        arqc_out[8])
{
    if (payhsm_precheck() != 0) return -1;
    return emv_compute_arqc(sk_ac, transaction_data, tx_len, arqc_out);
}

extern "C" int PayHSM_MAC_calculate(const uint8_t *msg, size_t msg_len,
                                    const uint8_t *tak, size_t tak_len,
                                    uint8_t        mac_out[8])
{
    if (payhsm_precheck() != 0) return -1;
    return calculate_mac_tak(msg, msg_len, tak, tak_len, mac_out);
}
