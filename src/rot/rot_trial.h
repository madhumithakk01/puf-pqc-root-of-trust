#ifndef ROT_TRIAL_H
#define ROT_TRIAL_H

#include "rot/rot_journal.h"
#include "rot/rot_mailbox.h"
#include "rot/rot_hev.h"
#include "rot/rot_slot.h"

/*
 * Trial judgement and commit.
 *
 * A freshly installed image runs once under a watchdog and reports evidence
 * (HEV1) before it starts Wi-Fi. The RoT compares the evidence with limits
 * inside the signed APM1 and decides. Commit order is: raise the floor,
 * store the signed receipt, commit the journal, and only then does the boot
 * erase the mailbox. A power cut at any point re-runs the same decision on
 * the next boot and arrives at the same state.
 */

/*
 * RCP reason for the evidence: 0 passes, otherwise HEALTH_FAIL_* or
 * HEALTH_SVN_MISMATCH. Order: svn, sensor, BPM, SpO2.
 */
int rot_trial_judge(const rot_hev_t *hev, uint64_t trial_svn, const apm_t *apm);

typedef struct {
    int      committed;      /* 1 commit, 0 rolled back */
    int      reason;         /* RCP reason (0 on commit) */
    uint64_t svn;
    uint64_t floor_after;
    uint8_t  slot;
} rot_trial_result;

enum { ROT_TRIAL_OK = 0, ROT_TRIAL_IO = -1, ROT_TRIAL_COUNTER = -2, ROT_TRIAL_NONE = -3 };

/*
 * Resolve a RUNNING trial. `report` is the mailbox content (NULL when empty
 * or invalid; only a HEALTH_REPORT counts). `saved_cause` is the reset cause
 * of the boot that ended the trial (RC_*). Updates `j`, `c->floor` and
 * `c->rb`; the caller erases the mailbox afterwards.
 */
int rot_trial_resolve(rot_ctx *c, rot_journal_t *j, const rot_mbx_t *report,
                      uint8_t saved_cause, rot_trial_result *out);

#endif
