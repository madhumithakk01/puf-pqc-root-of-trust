#ifndef ROT_ATTEST2_H
#define ROT_ATTEST2_H

#include <stddef.h>
#include <stdint.h>

/*
 * Attestation report ATR2, signed by the device's ML-DSA-44 identity key.
 * Extends ATR1 (unchanged) with the state the vendor needs before it
 * issues an update.
 *
 * Body (little-endian, 192 bytes):
 *    0   4  "ATR2"
 *    4   4  device_id
 *    8   8  running svn
 *   16   8  floor
 *   24  32  verifier nonce
 *   56  32  new one-time RoT nonce
 *   88  32  image digest of the running image
 *  120   1  active slot
 *  121   1  trial state
 *  122   1  reset cause (enum)
 *  123   1  flags (bit 0 SIM_PUF, bit 1 PMP_LOCKED)
 *  124   4  journal seq
 *  128   4  last receipt seq
 *  132   2  bits corrected
 *  134   1  worst block errors
 *  135   1  reserved (0)
 *  136  32  last receipt digest
 *  168  16  version string
 *  184   8  reserved (0)
 * Signed object: body || u32 sig_len || signature (2420 bytes).
 */

#define ATR2_BODY_BYTES  192u
#define ATR2_SIG_BYTES   2420u
#define ATR2_TOTAL_BYTES (ATR2_BODY_BYTES + 4u + ATR2_SIG_BYTES)
#define ATR2_PUBKEY_BYTES 1312u
#define ATR2_SECKEY_BYTES 2560u

#define ATR2_FLAG_SIM_PUF    0x01u
#define ATR2_FLAG_PMP_LOCKED 0x02u

typedef struct {
    uint32_t device_id;
    uint64_t svn;
    uint64_t floor;
    uint8_t  verifier_nonce[32];
    uint8_t  rot_nonce[32];
    uint8_t  image_digest[32];
    uint8_t  active_slot;
    uint8_t  trial_state;
    uint8_t  reset_cause;
    uint8_t  flags;
    uint32_t journal_seq;
    uint32_t last_receipt_seq;
    uint16_t bits_corrected;
    uint8_t  worst_block;
    uint8_t  last_receipt_digest[32];
    char     version[16];
} atr2_t;

void atr2_serialize(uint8_t out[ATR2_BODY_BYTES], const atr2_t *r);

/* 0 on success; -1 on bad magic or nonzero reserved bytes. */
int atr2_parse(const uint8_t body[ATR2_BODY_BYTES], atr2_t *r);

/* Sign `body`; writes ATR2_TOTAL_BYTES to `out`. Returns 0 or negative. */
int atr2_sign(const uint8_t body[ATR2_BODY_BYTES],
              const uint8_t sk[ATR2_SECKEY_BYTES],
              uint8_t out[ATR2_TOTAL_BYTES]);

/* Verify a signed object of `len` bytes. Returns 0 if valid. */
int atr2_verify(const uint8_t *obj, size_t len,
                const uint8_t pk[ATR2_PUBKEY_BYTES]);

#endif
