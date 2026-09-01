#ifndef ROT_SECURE_BOOT_H
#define ROT_SECURE_BOOT_H

#include <stddef.h>
#include <stdint.h>

#include "rollback/rollback.h"

/*
 * Secure boot decision.
 *
 * Given a firmware image, the vendor ML-DSA-44 public key held in simulated
 * OTP, and the rollback-counter store, decide whether to boot. Checks, in
 * order: structural parse, signature, rollback-counter integrity,
 * anti-rollback version. The first failure wins.
 *
 * Image container (little-endian):
 *   [0:4]                 magic "SBI1"
 *   [4:6]                 hdr_version = 1
 *   [6:8]                 reserved (0)
 *   [8:16]               fw_version   (uint64)
 *   [16:24]              body_len     (uint64)
 *   [24 : 24+body_len]   body
 *   [.. : ..+4]          sig_len      (uint32, <= SB_SIG_MAX_BYTES)
 *   [.. : ..+sig_len]    ML-DSA-44 signature
 *
 * The signature covers image[0 : 24+body_len] -- the header fields and the
 * body, but not sig_len / sig.
 */

#define SB_MAGIC0 'S'
#define SB_MAGIC1 'B'
#define SB_MAGIC2 'I'
#define SB_MAGIC3 '1'

#define SB_PUBKEY_BYTES  1312u  /* PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES */
#define SB_SECKEY_BYTES  2560u  /* PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES */
#define SB_SIG_MAX_BYTES 2420u  /* PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES */

#define SB_AUTH_HDR_BYTES 24u
#define SB_MIN_IMAGE_BYTES (SB_AUTH_HDR_BYTES + 4u)

typedef struct {
    uint8_t vendor_pubkey[SB_PUBKEY_BYTES]; /* provisioned once; read-only here */
} secure_boot_otp;

typedef enum {
    SB_BOOT                 = 0,
    SB_REFUSE_MALFORMED     = 1, /* magic / sizes inconsistent */
    SB_REFUSE_BAD_SIGNATURE = 2, /* ML-DSA verify failed */
    SB_REFUSE_COUNTER       = 3, /* rollback store tampered or unreadable */
    SB_REFUSE_ROLLBACK      = 4, /* fw_version < authenticated counter */
} sb_decision;

typedef struct {
    sb_decision decision;
    uint64_t    fw_version;   /* parsed from the image (meaningful once past MALFORMED) */
    uint64_t    counter;      /* authenticated rollback counter (meaningful once past COUNTER) */
    int         rollback_rc;  /* raw rc from rollback_verify, for diagnostics */
} sb_result;

/*
 * Evaluate `image` (SB_MIN_IMAGE_BYTES .. image_len bytes). `out` may be NULL.
 * Returns the decision; SB_BOOT (0) means boot.
 */
sb_decision secure_boot_check(const secure_boot_otp *otp,
                              const uint8_t *image, size_t image_len,
                              const rollback_store *rb,
                              const uint8_t rb_key[ROLLBACK_KEY_BYTES],
                              sb_result *out);

/*
 * Build a signed image into `out` (needs 28 + body_len + SB_SIG_MAX_BYTES).
 * Server / test side only -- signs with `sk`. Returns 0 and *out_len, or
 * negative on a size error.
 */
int secure_boot_pack(uint64_t fw_version,
                     const uint8_t *body, size_t body_len,
                     const uint8_t sk[SB_SECKEY_BYTES],
                     uint8_t *out, size_t out_cap, size_t *out_len);

#endif /* ROT_SECURE_BOOT_H */
