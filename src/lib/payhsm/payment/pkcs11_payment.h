/*
 * PayHSM — pkcs11_payment.h
 *
 * Stable C ABI exported by libsofthsm2.so that lets external clients (a
 * Flask demo, a banking app, pkcs11-tool wrappers, etc.) call into the
 * payment functions while reusing the same process — i.e. the same
 * fragmented LMK, the same armed defenses.
 *
 * Two reasons we expose a C ABI rather than only vendor-defined PKCS#11
 * mechanisms (CKM_VENDOR_...):
 *   1. SoftHSMv2's PKCS#11 dispatcher is sensitive to changes; adding new
 *      vendor mechanisms cleanly requires registering them in several
 *      tables, defining parameter structs, etc. Out of scope for a PFE.
 *   2. A flat C ABI is trivial to call from Python via ctypes, which is
 *      what our web demo uses.
 *
 * Return convention: 0 on success, negative on error.
 */
#ifndef PAYHSM_PKCS11_PAYMENT_H
#define PAYHSM_PKCS11_PAYMENT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SoftHSMv2 builds with -fvisibility=hidden so every symbol that is meant to
 * be reachable from outside the library has to be explicitly exported. */
#if defined(__GNUC__) || defined(__clang__)
#  define PAYHSM_API __attribute__((visibility("default")))
#else
#  define PAYHSM_API
#endif

/* Self-test that the integration is alive — returns 1 if the LMK
 * fragmentation has been initialised, 0 otherwise. */
PAYHSM_API int PayHSM_is_ready(void);

/* Translate a PIN block from TPK to ZPK. PIN never appears in plaintext. */
PAYHSM_API int PayHSM_PIN_translate(const uint8_t *pin_block_in,
                         const char    *pan,
                         const uint8_t *tpk, size_t tpk_len,
                         const uint8_t *zpk, size_t zpk_len,
                         uint8_t        pin_block_out[8]);

/* Verify an ARQC received from a card. */
PAYHSM_API int PayHSM_ARQC_verify(const uint8_t  sk_ac[16],
                       const uint8_t *transaction_data, size_t tx_len,
                       const uint8_t  arqc_received[8]);

/* Calculate a Retail-MAC (ISO 9797-1 algo 3) under TAK. */
PAYHSM_API int PayHSM_MAC_calculate(const uint8_t *msg, size_t msg_len,
                         const uint8_t *tak, size_t tak_len,
                         uint8_t        mac_out[8]);

/* ---- demo helpers, useful for the PFE front-end ---- */

/* Build a PIN block on the fly (encrypted under TPK) — only meant for
 * demonstration; in a real deployment the PIN block is built by the
 * terminal/EPP, not by the HSM. */
PAYHSM_API int PayHSM_PIN_build(const char   *pin,
                     const char   *pan,
                     const uint8_t *tpk, size_t tpk_len,
                     uint8_t       pin_block_out[8]);

/* Derive an EMV session key SK-AC from MK-AC and ATC. */
PAYHSM_API int PayHSM_EMV_derive_sk_ac(const uint8_t mk_ac[16],
                            const uint8_t atc[2],
                            uint8_t       sk_ac_out[16]);

/* Compute an ARQC (for end-to-end demo where we play both sides). */
PAYHSM_API int PayHSM_EMV_compute_arqc(const uint8_t  sk_ac[16],
                            const uint8_t *transaction_data,
                            size_t         tx_len,
                            uint8_t        arqc_out[8]);

/* Returns the version string of the PayHSM extension. */
PAYHSM_API const char *PayHSM_version(void);

#ifdef __cplusplus
}
#endif

#endif /* PAYHSM_PKCS11_PAYMENT_H */
