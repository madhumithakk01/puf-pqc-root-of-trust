#ifndef ROT_STATE_H
#define ROT_STATE_H

#include "rot/rot_keys.h"
#include "rot/rot_platform.h"
#include "rollback/rollback.h"

/*
 * Everything a boot step needs once keys exist: the platform, the keys, the
 * unsealed vendor key and the authenticated rollback state. Lives only for
 * the RoT phase.
 */
typedef struct {
    const rot_platform *p;
    const rot_keys     *k;
    uint8_t             vendor_pk[ROT_DSA_PK];
    rollback_store      rb;      /* as persisted (torn pages scrubbed) */
    uint64_t            floor;   /* authenticated floor */
} rot_ctx;

#endif
