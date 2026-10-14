#ifndef ROT_ENROLL_H
#define ROT_ENROLL_H

#include "rot/rot_helper.h"
#include "rot/rot_platform.h"

/*
 * Factory enrollment (portable core).
 *
 * Input: several fresh reads of the key window (five on the board, one per
 * Pstate refresh), the vendor's public key, and the window parameters.
 * Steps: majority vote -> reference; von Neumann pair selection (3,840
 * pairs, stable pairs only when flagged); debiased bits -> fuzzy_gen with a
 * TRNG message -> helper P and the UDS; key derivation; then the records are
 * written with HLP1 last, so an interrupted enrollment is simply redone.
 *
 * ENR1, the proof of possession handed to the vendor:
 *    0     4  "ENR1"
 *    4     4  device_id
 *    8  1312  pk_dsa
 * 1320   800  pk_kem
 * 2120     4  sig_len = 2420
 * 2124  2420  ML-DSA-44 signature over bytes [0:2120)
 */

#define ROT_ENR1_BODY   2120u
#define ROT_ENR1_BYTES  (ROT_ENR1_BODY + 4u + ROT_DSA_SIG)
#define ROT_ENROLL_MAX_READS 7u

typedef struct {
    uint16_t flags;        /* ROT_HLP_F_* */
    uint32_t window_addr;
    uint32_t t_off_ms;
} rot_enroll_params;

typedef struct {
    uint32_t device_id;
    uint8_t  fpr_dsa[32];
    uint8_t  fpr_kem[32];
    unsigned pairs_available;
    uint8_t  enr1[ROT_ENR1_BYTES];
} rot_enroll_result;

enum {
    ROT_ENR_OK = 0,
    ROT_ENR_ARGS = -1,
    ROT_ENR_FEW_PAIRS = -2,   /* fewer than 3,840 usable pairs */
    ROT_ENR_KEYGEN = -3,
    ROT_ENR_IO = -4,
    ROT_ENR_RNG = -5,
};

int rot_enroll_run(const rot_platform *p,
                   const uint8_t *const *reads, unsigned n_reads,
                   const uint8_t vendor_pk[ROT_DSA_PK],
                   const rot_enroll_params *prm,
                   rot_enroll_result *out);

/* Verify an ENR1 object (vendor side and tests). Returns 0 if valid. */
int rot_enr1_verify(const uint8_t *enr1, size_t len);

#endif
