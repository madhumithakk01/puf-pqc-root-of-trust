#ifndef ROT_SLOT_H
#define ROT_SLOT_H

#include "apm/apm.h"
#include "rot/rot_receipt.h"
#include "rot/rot_state.h"

/*
 * Verification of an application slot in place, through the XIP pointer:
 * the unchanged SBI1 check (structure, ML-DSA-44 against the sealed vendor
 * key, counter integrity, SVN >= floor), then the APM1 manifest.
 */

#define ROT_SBI_DIGEST_LABEL "sbi/v1/digest"

typedef struct {
    uint64_t svn;
    uint32_t body_len;
    apm_t    apm;
    uint8_t  digest[32];   /* H("sbi/v1/digest" || SBI1[0 : 24 + body_len]) */
} rot_slot_info;

/* Return values: 0 on success, an RCP_REASON_IMG_* code, or this: */
#define ROT_SLOT_COUNTER (-1)   /* rollback store failed integrity */
#define ROT_SLOT_IO      (-2)

int rot_slot_verify(const rot_ctx *c, int slot, rot_slot_info *info);

/* SBI1 header version of a slot without verifying it. 0 and *svn, or -1. */
int rot_slot_header_svn(const rot_platform *p, int slot, uint64_t *svn);

#endif
