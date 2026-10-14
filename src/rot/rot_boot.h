#ifndef ROT_BOOT_H
#define ROT_BOOT_H

#include "rot/rot_handoff.h"
#include "rot/rot_helper.h"
#include "rot/rot_platform.h"

/*
 * RoT boot state machine, steps B4 to B15 of the boot sequence. The
 * platform layer has already done the freshness gate (B2) and copied the key
 * window (B3); it passes the copy in, and performs the final wipe and chain
 * (B16) from the result.
 *
 * The attestation step runs after the image is chosen (the report names the
 * running image); everything else keeps the order of the sequence.
 */

#define ROT_BOOT_WINDOW_BYTES ROT_HLP_WINDOW_BYTES

typedef struct {
    uint8_t  window[ROT_BOOT_WINDOW_BYTES]; /* wiped by rot_boot_run */
    uint8_t  reset_cause;                   /* original cause, RC_* */
    uint8_t  refresh_count;                 /* refreshes done to reach this boot */
    uint8_t  puf_retry;                     /* 1 if this boot already followed a mismatch refresh */
    uint8_t  install_attempts;              /* earlier starts of the current INSTALL request */
    uint8_t  sim_puf;
    int16_t  die_temp_x10;
    uint8_t  build_id[20];
} rot_boot_in;

typedef enum {
    BOOT_CHAIN = 0,    /* run the chosen application */
    BOOT_SAFE,         /* no application runs */
    BOOT_ENROLL,       /* unenrolled: wait for factory enrollment */
    BOOT_REFRESH,      /* key did not reconstruct: refresh SRAM once more */
} rot_boot_action;

typedef enum {
    SAFE_NONE = 0,
    SAFE_REFRESH = 1,
    SAFE_PUF_MISMATCH = 2,
    SAFE_ANCHOR = 3,
    SAFE_COUNTER = 4,
    SAFE_JOURNAL = 5,
    SAFE_NO_VALID_IMAGE = 6,
    SAFE_HELPER = 7,
    SAFE_INTERNAL = 8,
} rot_safe_reason;

typedef struct {
    rot_boot_action action;
    int      safe_reason;       /* rot_safe_reason, when action == BOOT_SAFE */
    int      image_reason;      /* last RCP_REASON_IMG_* seen while choosing an image */
    int      chain_slot;
    uint32_t chain_off;         /* flash offset of the application binary */
    uint32_t chain_len;         /* bytes, rounded up to 4 */
    int      trial;             /* chained image is a trial: arm the watchdog */
    uint32_t trial_deadline_ms;
    rot_handoff_t hnd;          /* public report for the application */
} rot_boot_out;

const char *rot_safe_name(int reason);

int rot_boot_run(const rot_platform *p, rot_boot_in *in, rot_boot_out *out);

#endif
