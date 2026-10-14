#ifndef ROT_SELFTEST_H
#define ROT_SELFTEST_H

#include <stdint.h>

/*
 * On-target known-answer self-test. Bits in the result are set for each
 * check that failed, so 0 means everything passed:
 *
 *   bit 0  SHAKE256("abc")
 *   bit 1  ML-DSA-44 verifies a signature made on the host
 *   bit 2  ML-DSA-44 rejects the same signature with a flipped bit
 *   bit 3  ML-KEM-512 decapsulates a host ciphertext to the host secret
 *   bit 4  keys derived from the fixed UDS have the host's fingerprints
 *
 * `cycles` (optional, may be NULL) receives the cycle count of each step in
 * the same order, via the supplied counter.
 */

#define ROT_ST_SHAKE   (1u << 0)
#define ROT_ST_VERIFY  (1u << 1)
#define ROT_ST_REJECT  (1u << 2)
#define ROT_ST_DECAPS  (1u << 3)
#define ROT_ST_KEYGEN  (1u << 4)

uint32_t rot_selftest_run(uint64_t (*counter)(void), uint64_t cycles[5]);

#endif
