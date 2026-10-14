#ifndef ROT_COUNTER_H
#define ROT_COUNTER_H

#include "rot/rot_platform.h"
#include "rollback/rollback.h"

/*
 * Persistence of the existing MAC'd A/B rollback counter (RBC1) in
 * rot_data sectors 2 and 3, one 64-byte page per sector.
 *
 * A page that carries the magic but whose last byte is still erased (0xFF)
 * was interrupted while being programmed: complete pages end in zero
 * padding and flash programs in ascending order. Such a page is treated as
 * blank. Any other page with a bad MAC is tampering and is reported as such.
 */

enum {
    ROT_CTR_OK = 0,
    ROT_CTR_NONE = -1,    /* no valid page: not enrolled, or both destroyed */
    ROT_CTR_TAMPER = -2,  /* a complete page failed its MAC */
    ROT_CTR_IO = -3,
    ROT_CTR_MONOTONIC = -4, /* update refused: not strictly increasing */
};

int rot_counter_load(const rot_platform *p, rollback_store *rb);

int rot_counter_enroll(const rot_platform *p, const uint8_t key[ROLLBACK_KEY_BYTES],
                       uint64_t floor);

/* Authenticated floor. ROT_CTR_OK, ROT_CTR_NONE or ROT_CTR_TAMPER. */
int rot_counter_read(const rot_platform *p, const uint8_t key[ROLLBACK_KEY_BYTES],
                     uint64_t *floor);

/* Raise the floor. The non-current page is rewritten; the current one stays intact. */
int rot_counter_update(const rot_platform *p, const uint8_t key[ROLLBACK_KEY_BYTES],
                       uint64_t new_floor);

#endif
