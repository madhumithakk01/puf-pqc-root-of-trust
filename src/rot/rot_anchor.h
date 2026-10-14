#ifndef ROT_ANCHOR_H
#define ROT_ANCHOR_H

#include "rot/rot_platform.h"

/*
 * Sealed vendor public key (ANC1), replacing a fuse-held key.
 *
 *    0     4  "ANC1"
 *    4     2  version = 1
 *    6     2  reserved (0)
 *    8  1312  vendor ML-DSA-44 public key
 * 1320    32  tag = SHAKE256(anchor_key || "anchor/v1/tag" || bytes[0:1320])
 *
 * The tag key is derived from the PUF secret, so the record cannot be
 * forged or swapped without the device.
 */

#define ROT_ANCHOR_PK_BYTES   1312u
#define ROT_ANCHOR_TAG_OFF    1320u
#define ROT_ANCHOR_BYTES      1352u

enum {
    ROT_ANCHOR_OK = 0,
    ROT_ANCHOR_ABSENT = -1, /* sector blank */
    ROT_ANCHOR_BAD = -2,    /* present but malformed or tag mismatch */
};

int rot_anchor_seal(const rot_platform *p, const uint8_t anchor_key[32],
                    const uint8_t vendor_pk[ROT_ANCHOR_PK_BYTES]);

int rot_anchor_open(const rot_platform *p, const uint8_t anchor_key[32],
                    uint8_t vendor_pk[ROT_ANCHOR_PK_BYTES]);

#endif
