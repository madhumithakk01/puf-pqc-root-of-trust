#ifndef ROT_INSTALL_H
#define ROT_INSTALL_H

#include "rot/rot_journal.h"
#include "rot/rot_mailbox.h"
#include "rot/rot_slot.h"

/*
 * Install pipeline (steps U7 to U16 of the update flow).
 *
 *   U7  structure and sizes of DLV1
 *   U8  vendor signature against the sealed anchor
 *   U9  device id
 *   U10 one-time RoT nonce
 *   U11 svn >= floor
 *   U12 SHAKE256 digest of the OTA1 bytes
 *       -- nothing has been decapsulated or decrypted before this line --
 *   U13 ML-KEM-512 decapsulation, streamed MAC check
 *   U14 nonce consumed (journal), inactive slot erased, stream decrypt into it
 *   U15 secure_boot_check + APM1 + inner svn == manifest svn
 *   U16 journal: trial RUNNING for the new slot
 *
 * Every refusal writes a signed REFUSED receipt with the reason. The nonce
 * is consumed only after the MAC passes, so a corrupted transfer can be
 * retried; once consumed, a replay of the same package is refused as stale.
 */

typedef struct {
    int      refused;        /* 1: REFUSED receipt written */
    int      reason;         /* RCP reason when refused */
    int      trial_started;  /* 1: new image is in `slot`, trial RUNNING */
    uint8_t  slot;
    uint64_t svn;
    uint8_t  pkg_digest[32];
} rot_install_result;

enum { ROT_INST_OK = 0, ROT_INST_IO = -1, ROT_INST_COUNTER = -2 };

/*
 * Run the pipeline for an INSTALL_REQ mailbox request. Returns ROT_INST_OK
 * when the request was fully handled (installed for trial, or refused with a
 * receipt), or a negative code on a flash failure or counter integrity
 * failure. `attempts` counts earlier starts of this same request (a boot
 * loop guard held in POWMAN scratch on the board). `j` is updated and committed as the pipeline progresses.
 */
int rot_install_run(rot_ctx *c, rot_journal_t *j, const rot_mbx_t *req,
                    unsigned attempts, rot_install_result *out);

/* After this many failed attempts for one mailbox request, it is refused unread. */
#define ROT_INSTALL_MAX_ATTEMPTS 2u

#endif
