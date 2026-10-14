#include "rot/rot_trial.h"

#include "rot/rot_counter.h"
#include "rot/rot_handoff.h"
#include "rot/rot_receipts.h"
#include "rot/rot_util.h"

#include "fips202.h"

#include <string.h>

static unsigned absdiff(unsigned a, unsigned b)
{
    return a > b ? a - b : b - a;
}

int rot_trial_judge(const rot_hev_t *hev, uint64_t trial_svn, const apm_t *apm)
{
    if (hev->svn != trial_svn) {
        return RCP_REASON_HEALTH_SVN_MISMATCH;
    }
    if (hev->part_id != HEV1_PART_ID_MAX30102 || hev->sensor_ok != 1
        || hev->live_samples < apm->min_live_samples) {
        return RCP_REASON_HEALTH_FAIL_SENSOR;
    }
    if (absdiff(hev->golden_bpm_x10, apm->golden_bpm_x10) > apm->tol_bpm_x10) {
        return RCP_REASON_HEALTH_FAIL_BPM;
    }
    if (apm->flags & APM_FLAG_HAS_SPO2) {
        if (hev->golden_spo2_x10 == APM_SPO2_NONE
            || absdiff(hev->golden_spo2_x10, apm->golden_spo2_x10) > apm->tol_spo2_x10) {
            return RCP_REASON_HEALTH_FAIL_SPO2;
        }
    }
    return 0;
}

static void evidence_digest(const uint8_t b[HEV1_BYTES], uint8_t out[32])
{
    shake256incctx st;
    shake256_inc_init(&st);
    shake256_inc_absorb(&st, (const uint8_t *)"hev/v1/digest", 13);
    shake256_inc_absorb(&st, b, HEV1_BYTES);
    shake256_inc_finalize(&st);
    shake256_inc_squeeze(out, 32, &st);
    shake256_inc_ctx_release(&st);
}

int rot_trial_resolve(rot_ctx *c, rot_journal_t *j, const rot_mbx_t *report,
                      uint8_t saved_cause, rot_trial_result *out)
{
    rot_slot_info info;
    rot_hev_t hev;
    rcp_t r;
    int slot, reason, have_hev = 0, vrc;
    uint64_t prev_svn = 0, floor_before = c->floor;

    if (j->trial_state != TRIAL_RUNNING) {
        return ROT_TRIAL_NONE;
    }
    slot = j->trial_slot;
    memset(&r, 0, sizeof r);
    memset(&info, 0, sizeof info);

    /* previous active image, for the receipt */
    if (j->status[j->active] == SLOT_GOOD) {
        rot_slot_header_svn(c->p, j->active, &prev_svn);
    }

    vrc = rot_slot_verify(c, slot, &info);
    if (vrc == ROT_SLOT_COUNTER) {
        return ROT_TRIAL_COUNTER;
    }
    if (vrc != 0) {
        reason = vrc > 0 ? vrc : RCP_REASON_IMG_MALFORMED;
    } else if (report && report->type == MBX_HEALTH_REPORT && rot_hev_parse(report->payload, &hev) == 0) {
        have_hev = 1;
        reason = rot_trial_judge(&hev, j->trial_svn, &info.apm);
        if (reason == 0 && info.svn != j->trial_svn) {
            reason = RCP_REASON_HEALTH_SVN_MISMATCH;
        }
    } else if (report && report->type == MBX_HEALTH_REPORT) {
        reason = RCP_REASON_HEALTH_FAIL_SENSOR;
    } else {
        reason = (saved_cause == RC_POR || saved_cause == RC_RUN || saved_cause == RC_PSTATE
                  || saved_cause == RC_BROWNOUT)
                     ? RCP_REASON_HEALTH_POWER_LOSS
                     : RCP_REASON_HEALTH_TIMEOUT;
    }

    r.slot = (uint8_t)slot;
    r.from_svn = prev_svn;
    r.to_svn = j->trial_svn;
    r.floor_before = floor_before;
    if (vrc == 0) {
        memcpy(r.image_digest, info.digest, 32);
    }
    memcpy(r.version, vrc == 0 ? info.apm.version : (const char[16]){0}, 16);
    if (have_hev) {
        evidence_digest(report->payload, r.evidence_digest);
    }

    if (reason == 0) {
        /* 1. floor first; equal values need no write */
        if (j->trial_svn > c->floor) {
            if (rot_counter_update(c->p, c->k->rb_key, j->trial_svn) != ROT_CTR_OK) {
                return ROT_TRIAL_IO;
            }
            rot_counter_load(c->p, &c->rb);
            c->floor = j->trial_svn;
        }
        r.outcome = RCP_COMMITTED;
        r.reason = 0;
        r.floor_after = c->floor;
        j->active = (uint8_t)slot;
        j->status[slot] = SLOT_GOOD;
    } else {
        r.outcome = RCP_ROLLED_BACK;
        r.reason = (uint8_t)reason;
        r.floor_after = c->floor;
        j->status[slot] = SLOT_REJECTED;
    }
    j->trial_state = TRIAL_NONE;
    j->trial_svn = 0;

    /* 2. receipt, 3. journal */
    if (rot_receipts_issue(c->p, c->k, j, &r) != ROT_RCPS_OK) {
        return ROT_TRIAL_IO;
    }
    if (rot_journal_commit(c->p, c->k->journal_key, j) != ROT_JNL_OK) {
        return ROT_TRIAL_IO;
    }

    if (out) {
        out->committed = reason == 0;
        out->reason = reason;
        out->svn = r.to_svn;
        out->floor_after = c->floor;
        out->slot = (uint8_t)slot;
    }
    return ROT_TRIAL_OK;
}
