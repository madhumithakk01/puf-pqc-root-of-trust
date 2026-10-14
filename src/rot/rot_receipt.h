#ifndef ROT_RECEIPT_H
#define ROT_RECEIPT_H

#include <stddef.h>
#include <stdint.h>

/*
 * Install receipt RCP1, signed by the device. Receipts form a hash chain:
 * each one carries the digest of the previous receipt including its
 * signature, so a removed or reordered receipt is detectable.
 *
 * Body (little-endian, 256 bytes):
 *    0   4  "RCP1"
 *    4   4  seq
 *    8   4  device_id
 *   12   1  outcome: 1 COMMITTED, 2 ROLLED_BACK, 3 REFUSED
 *   13   1  reason (RCP_REASON_*)
 *   14   1  slot
 *   15   1  reserved (0)
 *   16   8  from_svn
 *   24   8  to_svn
 *   32   8  floor_before
 *   40   8  floor_after
 *   48  32  image digest (zero if not reached)
 *   80  32  package digest
 *  112  32  rot_nonce from the package (or zero)
 *  144  32  evidence digest (or zero)
 *  176  32  previous receipt digest = H("rcp/v1/chain" || previous object)
 *  208   4  journal seq
 *  212  16  target version string
 *  228  28  reserved (0)
 * Signed object: body || u32 sig_len || signature (2420 bytes).
 */

#define RCP_BODY_BYTES   256u
#define RCP_SIG_BYTES    2420u
#define RCP_TOTAL_BYTES  (RCP_BODY_BYTES + 4u + RCP_SIG_BYTES)
#define RCP_PUBKEY_BYTES 1312u
#define RCP_SECKEY_BYTES 2560u

enum { RCP_COMMITTED = 1, RCP_ROLLED_BACK = 2, RCP_REFUSED = 3 };

enum {
    RCP_REASON_OK = 0,
    RCP_REASON_PKG_MALFORMED = 1,
    RCP_REASON_PKG_UNKNOWN_SIGNER = 2,
    RCP_REASON_PKG_WRONG_DEVICE = 3,
    RCP_REASON_PKG_STALE_NONCE = 4,
    RCP_REASON_PKG_BELOW_FLOOR = 5,
    RCP_REASON_PKG_AUTH_FAILED = 6,
    RCP_REASON_PKG_MAC_FAILED = 7,
    RCP_REASON_IMG_MALFORMED = 8,
    RCP_REASON_IMG_BAD_SIGNATURE = 9,
    RCP_REASON_IMG_BELOW_FLOOR = 10,
    RCP_REASON_IMG_SVN_MISMATCH = 11,
    RCP_REASON_IMG_APM_INVALID = 12,
    RCP_REASON_HEALTH_FAIL_BPM = 20,
    RCP_REASON_HEALTH_FAIL_SPO2 = 21,
    RCP_REASON_HEALTH_FAIL_SENSOR = 22,
    RCP_REASON_HEALTH_TIMEOUT = 23,
    RCP_REASON_HEALTH_POWER_LOSS = 24,
    RCP_REASON_HEALTH_SVN_MISMATCH = 25,
};

typedef struct {
    uint32_t seq;
    uint32_t device_id;
    uint8_t  outcome;
    uint8_t  reason;
    uint8_t  slot;
    uint64_t from_svn;
    uint64_t to_svn;
    uint64_t floor_before;
    uint64_t floor_after;
    uint8_t  image_digest[32];
    uint8_t  package_digest[32];
    uint8_t  rot_nonce[32];
    uint8_t  evidence_digest[32];
    uint8_t  prev_digest[32];
    uint32_t journal_seq;
    char     version[16];
} rcp_t;

void rcp_serialize(uint8_t out[RCP_BODY_BYTES], const rcp_t *r);

/* 0 on success; -1 on bad magic or nonzero reserved bytes. */
int rcp_parse(const uint8_t body[RCP_BODY_BYTES], rcp_t *r);

int rcp_sign(const uint8_t body[RCP_BODY_BYTES],
             const uint8_t sk[RCP_SECKEY_BYTES],
             uint8_t out[RCP_TOTAL_BYTES]);

int rcp_verify(const uint8_t *obj, size_t len, const uint8_t pk[RCP_PUBKEY_BYTES]);

/* H("rcp/v1/chain" || signed receipt object); the next receipt's prev_digest. */
void rcp_chain_digest(const uint8_t obj[RCP_TOTAL_BYTES], uint8_t out[32]);

/*
 * Verify `n` consecutive signed receipts (each RCP_TOTAL_BYTES, oldest
 * first): every signature, consecutive seq, and every prev_digest equal to
 * the chain digest of its predecessor. `first_prev` is the expected
 * prev_digest of the first receipt (all zero for a chain from the start).
 * Returns 0, or the 1-based index of the first bad receipt.
 */
int rcp_verify_chain(const uint8_t *objs, size_t n,
                     const uint8_t pk[RCP_PUBKEY_BYTES],
                     const uint8_t first_prev[32]);

#endif
