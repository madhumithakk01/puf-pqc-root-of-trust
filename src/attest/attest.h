#ifndef ROT_ATTEST_H
#define ROT_ATTEST_H

#include <stddef.h>
#include <stdint.h>

/*
 * Remote attestation, device side.
 *
 * The device signs a report {device_id, fw_version, cnt, nonce} with its
 * attestation key (ML-DSA-44; in the full system derived from the PUF via
 * KDF "signing-identity"). A server verifies the device's enrollment
 * certificate against the CA key, then the report signature, then nonce
 * freshness.
 *
 * Report serialization (little-endian, fixed 56 bytes):
 *   [0:4]   magic "ATR1"
 *   [4:8]   device_id  (uint32)
 *   [8:16]  fw_version (uint64)
 *   [16:24] cnt        (uint64)
 *   [24:56] nonce      (32 bytes)
 */

#define ATTEST_MAGIC0 'A'
#define ATTEST_MAGIC1 'T'
#define ATTEST_MAGIC2 'R'
#define ATTEST_MAGIC3 '1'

#define ATTEST_NONCE_BYTES   32u
#define ATTEST_REPORT_BYTES  56u
#define ATTEST_PUBKEY_BYTES  1312u
#define ATTEST_SECKEY_BYTES  2560u
#define ATTEST_SIG_MAX_BYTES 2420u

void attest_report_serialize(uint32_t device_id, uint64_t fw_version,
                             uint64_t cnt,
                             const uint8_t nonce[ATTEST_NONCE_BYTES],
                             uint8_t report[ATTEST_REPORT_BYTES]);

/* Sign a serialized report. Returns 0 and *sig_len, or negative. */
int attest_report_sign(const uint8_t report[ATTEST_REPORT_BYTES],
                       const uint8_t sk[ATTEST_SECKEY_BYTES],
                       uint8_t *sig, size_t sig_cap, size_t *sig_len);

/* Verify a report signature. Returns 0 if valid, negative otherwise. */
int attest_report_verify(const uint8_t report[ATTEST_REPORT_BYTES],
                         const uint8_t *sig, size_t sig_len,
                         const uint8_t pk[ATTEST_PUBKEY_BYTES]);

#endif /* ROT_ATTEST_H */
