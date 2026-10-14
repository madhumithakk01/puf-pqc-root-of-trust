#ifndef ROT_JOURNAL_H
#define ROT_JOURNAL_H

#include "rot/rot_platform.h"

/*
 * RoT state journal (JNL1), two pages in rot_data sectors 4 and 5. The page
 * with the highest valid seq wins; a commit writes the other page, so a
 * power cut leaves the previous state intact. Pages with a bad tag (torn
 * writes included) are ignored. Written only when state changes.
 *
 *    0   4  "JNL1"
 *    4   4  seq
 *    8   1  active slot (0 A, 1 B)
 *    9   1  slot status A: 0 EMPTY, 1 GOOD, 2 TRIAL, 3 REJECTED
 *   10   1  slot status B
 *   11   1  trial state: 0 NONE, 1 RUNNING
 *   12   1  trial slot
 *   13   1  nonce state: 0 NONE, 1 OUTSTANDING
 *   14   2  reserved (0)
 *   16   8  trial SVN
 *   24  32  outstanding RoT nonce
 *   56   4  receipt seq
 *   60   4  reserved (0)
 *   64  32  last receipt digest
 *   96  32  tag = SHAKE256(journal_key || "journal/v1/tag" || bytes[0:96])
 */

#define ROT_JNL_BYTES 128u

enum { SLOT_EMPTY = 0, SLOT_GOOD = 1, SLOT_TRIAL = 2, SLOT_REJECTED = 3 };
enum { TRIAL_NONE = 0, TRIAL_RUNNING = 1 };
enum { NONCE_NONE = 0, NONCE_OUTSTANDING = 1 };

typedef struct {
    uint32_t seq;
    uint8_t  active;
    uint8_t  status[2];
    uint8_t  trial_state;
    uint8_t  trial_slot;
    uint8_t  nonce_state;
    uint64_t trial_svn;
    uint8_t  nonce[32];
    uint32_t receipt_seq;
    uint8_t  last_receipt_digest[32];
    int      page;   /* page the state was loaded from (0/1); set by load/commit */
} rot_journal_t;

enum {
    ROT_JNL_OK = 0,
    ROT_JNL_NONE = -1,  /* no valid page */
    ROT_JNL_IO = -2,
    ROT_JNL_BAD_FIELD = -3, /* tag valid but a field is out of range */
};

/* Factory: write page A with seq 1. */
int rot_journal_enroll(const rot_platform *p, const uint8_t key[32], const rot_journal_t *init);

int rot_journal_load(const rot_platform *p, const uint8_t key[32], rot_journal_t *j);

/* seq += 1, write the page that is not current. Updates j->seq and j->page. */
int rot_journal_commit(const rot_platform *p, const uint8_t key[32], rot_journal_t *j);

/* Serialization, exposed for the tests and the vendor inspection tool. */
void rot_journal_serialize(uint8_t out[ROT_JNL_BYTES], const rot_journal_t *j, const uint8_t key[32]);

#endif
