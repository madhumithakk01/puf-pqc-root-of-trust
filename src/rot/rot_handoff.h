#ifndef ROT_HANDOFF_H
#define ROT_HANDOFF_H

#include <stdint.h>

#include "rot/rot_keys.h"
#include "attest/attest2.h"

/*
 * HND1: public boot report the RoT leaves in RAM for the application
 * (region R4). Holds identity, public keys, versions, measurements and, when
 * requested, the signed attestation. No secret ever goes here.
 */

#define HND_MAGIC   0x31444E48u /* "HND1" little-endian */
#define HND_VERSION 1u

#define HND_F_TRIAL        0x0001u
#define HND_F_SIM_PUF      0x0002u
#define HND_F_PMP_LOCKED   0x0004u
#define HND_F_ATTEST       0x0008u
#define HND_F_NEW_RECEIPT  0x0010u

/* Stage cycle counts, indices into cycles[]. */
enum {
    HND_C_PUF_READ = 0, HND_C_VN, HND_C_FUZZY, HND_C_KDF, HND_C_DSA_KEYGEN,
    HND_C_KEM_KEYGEN, HND_C_RECORDS, HND_C_VERIFY, HND_C_INSTALL, HND_C_ATTEST,
    HND_C_TOTAL, HND_C_COUNT = 12
};

/* Reset-cause enum shared by ATR2 and HND1. */
enum {
    RC_UNKNOWN = 0, RC_POR = 1, RC_RUN = 2, RC_PSTATE = 3, RC_WATCHDOG = 4,
    RC_BROWNOUT = 5, RC_DEBUG = 6, RC_OTHER = 7
};

/* Events and reasons for last_event/last_reason. */
enum {
    EV_NONE = 0, EV_BOOT = 1, EV_ATTEST = 2, EV_COMMIT = 3, EV_ROLLBACK = 4, EV_REFUSED = 5,
    EV_TRIAL_START = 6
};

typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t size;
    uint32_t flags;
    uint32_t device_id;
    uint64_t svn;
    uint64_t floor;
    uint8_t  active_slot;
    uint8_t  trial_slot;
    uint8_t  trial_state;
    uint8_t  reset_cause;
    uint8_t  slot_status[2];
    uint8_t  worst_block;
    uint8_t  refresh_count;
    uint16_t bits_corrected;
    int16_t  die_temp_x10;
    uint32_t journal_seq;
    uint32_t receipt_seq;
    char     version_str[16];
    uint8_t  last_event;
    uint8_t  last_reason;
    uint16_t atr2_len;
    uint32_t cycles[HND_C_COUNT];
    uint32_t stack_hwm;
    uint8_t  build_id[20];
    uint8_t  pk_dsa[ROT_DSA_PK];
    uint8_t  pk_kem[ROT_KEM_PK];
    uint8_t  atr2[ATR2_TOTAL_BYTES];
    uint32_t crc;
} rot_handoff_t;

_Static_assert(sizeof(rot_handoff_t) < 5120, "HND1 must stay under 5 KB");
_Static_assert(__builtin_offsetof(rot_handoff_t, device_id) == 12, "HND1 layout");
_Static_assert(__builtin_offsetof(rot_handoff_t, svn) == 16, "HND1 layout");
_Static_assert(__builtin_offsetof(rot_handoff_t, active_slot) == 32, "HND1 layout");

/* Fill the CRC over everything before it. */
void rot_handoff_seal(rot_handoff_t *h);

/* 1 if magic, version, size and CRC are all right. */
int rot_handoff_valid(const rot_handoff_t *h);

#endif
