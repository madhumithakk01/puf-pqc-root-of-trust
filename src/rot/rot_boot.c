#include "rot/rot_boot.h"

#include "rot/rot_anchor.h"
#include "rot/rot_counter.h"
#include "rot/rot_flash.h"
#include "rot/rot_install.h"
#include "rot/rot_journal.h"
#include "rot/rot_mailbox.h"
#include "rot/rot_rng.h"
#include "rot/rot_slot.h"
#include "rot/rot_state.h"
#include "rot/rot_trial.h"
#include "rot/rot_util.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static rot_hlp_t hlp;
static rot_keys keys;
static rot_ctx ctx;

const char *rot_safe_name(int reason)
{
    switch (reason) {
    case SAFE_NONE:           return "none";
    case SAFE_REFRESH:        return "REFRESH";
    case SAFE_PUF_MISMATCH:   return "PUF_MISMATCH";
    case SAFE_ANCHOR:         return "ANCHOR";
    case SAFE_COUNTER:        return "COUNTER";
    case SAFE_JOURNAL:        return "JOURNAL";
    case SAFE_NO_VALID_IMAGE: return "NO_VALID_IMAGE";
    case SAFE_HELPER:         return "HELPER";
    default:                  return "INTERNAL";
    }
}

static void jlog(const rot_platform *p, const char *fmt, ...)
{
    char line[256];
    va_list ap;

    if (!p->log) {
        return;
    }
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    p->log(p->ctx, line);
}

static uint32_t cyc(const rot_platform *p)
{
    return p->cycles ? (uint32_t)p->cycles(p->ctx) : 0;
}

static int finish_safe(rot_boot_out *out, int reason)
{
    out->action = BOOT_SAFE;
    out->safe_reason = reason;
    return 0;
}

static void cleanup(rot_boot_in *in)
{
    rot_wipe(in->window, sizeof in->window);
    rot_keys_wipe(&keys);
    rot_wipe(&ctx, sizeof ctx);
}

static int slot_usable(const rot_journal_t *j, int slot)
{
    if (j->status[slot] == SLOT_GOOD) {
        return 1;
    }
    return j->status[slot] == SLOT_TRIAL && j->trial_state == TRIAL_RUNNING && j->trial_slot == slot;
}

static uint8_t trial_flag(const rot_journal_t *j)
{
    return j->trial_state == TRIAL_RUNNING;
}

int rot_boot_run(const rot_platform *p, rot_boot_in *in, rot_boot_out *out)
{
    static uint8_t uds[ROT_UDS_BYTES];
    rot_journal_t j;
    rot_mbx_t req;
    rot_puf_stats st = { 0, 0 };
    int mbx_rc, have_req = 0, rc, chosen = -1, ev = EV_BOOT, ev_reason = 0;
    uint32_t t0, t1, tstart = cyc(p);
    rot_slot_info info;
    uint32_t cycles[HND_C_COUNT] = { 0 };

    memset(out, 0, sizeof *out);
    memset(&req, 0, sizeof req);
    memset(&info, 0, sizeof info);
    out->action = BOOT_CHAIN;

    /* B4: helper data */
    rc = rot_hlp_read(p, &hlp);
    if (rc == ROT_HLP_ABSENT) {
        out->action = BOOT_ENROLL;
        cleanup(in);
        return 0;
    }
    if (rc != ROT_HLP_OK) {
        finish_safe(out, SAFE_HELPER);
        cleanup(in);
        return 0;
    }

    /* B5: reconstruct the secret, rebuild the keys, compare fingerprints */
    rot_rng_init(p->trng_raw, p->ctx);
    t0 = cyc(p);
    if (rot_puf_reconstruct(in->window, &hlp, uds, &st) != 0) {
        rot_wipe(uds, sizeof uds);
        finish_safe(out, SAFE_HELPER);
        cleanup(in);
        return 0;
    }
    t1 = cyc(p);
    cycles[HND_C_FUZZY] = t1 - t0;
    rot_wipe(in->window, sizeof in->window);

    t0 = cyc(p);
    rc = rot_keys_derive(uds, &keys);
    cycles[HND_C_DSA_KEYGEN] = cyc(p) - t0;
    rot_wipe(uds, sizeof uds);
    if (rc != 0) {
        finish_safe(out, SAFE_INTERNAL);
        cleanup(in);
        return 0;
    }
    if (!rot_ct_equal(keys.fpr_dsa, hlp.fpr_dsa, 32) || !rot_ct_equal(keys.fpr_kem, hlp.fpr_kem, 32)) {
        jlog(p, "{\"ev\":\"puf_mismatch\",\"retry\":%u,\"bits\":%u,\"worst\":%u}",
             in->puf_retry, st.bits_corrected, st.worst_block);
        if (in->puf_retry == 0) {
            out->action = BOOT_REFRESH;
        } else {
            finish_safe(out, SAFE_PUF_MISMATCH);
        }
        cleanup(in);
        return 0;
    }

    ctx.p = p;
    ctx.k = &keys;

    /* B6: sealed vendor key */
    rc = rot_anchor_open(p, keys.anchor_key, ctx.vendor_pk);
    if (rc != ROT_ANCHOR_OK) {
        finish_safe(out, SAFE_ANCHOR);
        cleanup(in);
        return 0;
    }

    /* B7: rollback counter */
    t0 = cyc(p);
    if (rot_counter_read(p, keys.rb_key, &ctx.floor) != ROT_CTR_OK
        || rot_counter_load(p, &ctx.rb) != ROT_CTR_OK) {
        finish_safe(out, SAFE_COUNTER);
        cleanup(in);
        return 0;
    }

    /* B8: journal */
    if (rot_journal_load(p, keys.journal_key, &j) != ROT_JNL_OK) {
        finish_safe(out, SAFE_JOURNAL);
        cleanup(in);
        return 0;
    }
    cycles[HND_C_RECORDS] = cyc(p) - t0;

    /* B9: mailbox (untrusted) */
    mbx_rc = rot_mailbox_read(p, &req);
    have_req = mbx_rc == ROT_MBX_OK;

    /* B10: a trial in progress is judged before anything else */
    if (j.trial_state == TRIAL_RUNNING) {
        rot_trial_result tr;
        const rot_mbx_t *rep = have_req && req.type == MBX_HEALTH_REPORT ? &req : NULL;

        rc = rot_trial_resolve(&ctx, &j, rep, in->reset_cause, &tr);
        if (rc == ROT_TRIAL_COUNTER) {
            finish_safe(out, SAFE_COUNTER);
            cleanup(in);
            return 0;
        }
        if (rc != ROT_TRIAL_OK) {
            finish_safe(out, SAFE_JOURNAL);
            cleanup(in);
            return 0;
        }
        ev = tr.committed ? EV_COMMIT : EV_ROLLBACK;
        ev_reason = tr.reason;
        out->hnd.flags |= HND_F_NEW_RECEIPT;
        jlog(p, "{\"ev\":\"trial\",\"committed\":%d,\"reason\":%d,\"svn\":%llu,\"floor\":%llu}",
             tr.committed, tr.reason, (unsigned long long)tr.svn, (unsigned long long)tr.floor_after);
        have_req = 0; /* a report belongs to the trial; anything else waited behind it */
    } else if (have_req && req.type == MBX_HEALTH_REPORT) {
        have_req = 0; /* stale report, nothing is on trial */
    }

    /* B11: install */
    if (have_req && req.type == MBX_INSTALL_REQ) {
        rot_install_result ir;

        t0 = cyc(p);
        rc = rot_install_run(&ctx, &j, &req, in->install_attempts, &ir);
        cycles[HND_C_INSTALL] = cyc(p) - t0;
        if (rc == ROT_INST_COUNTER) {
            finish_safe(out, SAFE_COUNTER);
            cleanup(in);
            return 0;
        }
        if (rc != ROT_INST_OK) {
            finish_safe(out, SAFE_JOURNAL);
            cleanup(in);
            return 0;
        }
        if (ir.refused) {
            ev = EV_REFUSED;
            ev_reason = ir.reason;
            out->hnd.flags |= HND_F_NEW_RECEIPT;
        } else {
            ev = EV_TRIAL_START;
        }
        jlog(p, "{\"ev\":\"install\",\"refused\":%d,\"reason\":%d,\"trial\":%d}",
             ir.refused, ir.reason, ir.trial_started);
        have_req = 0;
    }

    /* B13: choose the image to run */
    {
        int order[2];
        t0 = cyc(p);
        if (j.trial_state == TRIAL_RUNNING) {
            order[0] = j.trial_slot;
            order[1] = 1 - j.trial_slot;
        } else {
            order[0] = j.active;
            order[1] = 1 - j.active;
        }
        for (int i = 0; i < 2 && chosen < 0; i++) {
            int s = order[i];
            if (!slot_usable(&j, s)) {
                continue;
            }
            rc = rot_slot_verify(&ctx, s, &info);
            if (rc == 0) {
                chosen = s;
            } else if (rc == ROT_SLOT_COUNTER) {
                finish_safe(out, SAFE_COUNTER);
                cleanup(in);
                return 0;
            } else {
                if (out->image_reason == 0) {
                    out->image_reason = rc; /* the first refusal is the informative one */
                }
                jlog(p, "{\"ev\":\"slot_refused\",\"slot\":%d,\"reason\":%d}", s, rc);
            }
        }
        cycles[HND_C_VERIFY] = cyc(p) - t0;
    }
    if (chosen < 0) {
        out->hnd.device_id = keys.device_id;
        if (mbx_rc != ROT_MBX_EMPTY) {
            rot_mailbox_erase(p);
        }
        finish_safe(out, SAFE_NO_VALID_IMAGE);
        cleanup(in);
        return 0;
    }

    /* B12: attestation for the image that will run */
    if (have_req && req.type == MBX_ATTEST_REQ) {
        atr2_t a;
        uint8_t body[ATR2_BODY_BYTES];

        t0 = cyc(p);
        memset(&a, 0, sizeof a);
        if (rot_rng_bytes(j.nonce, sizeof j.nonce) != 0) {
            finish_safe(out, SAFE_INTERNAL);
            cleanup(in);
            return 0;
        }
        j.nonce_state = NONCE_OUTSTANDING;
        if (rot_journal_commit(p, keys.journal_key, &j) != ROT_JNL_OK) {
            finish_safe(out, SAFE_JOURNAL);
            cleanup(in);
            return 0;
        }
        a.device_id = keys.device_id;
        a.svn = info.svn;
        a.floor = ctx.floor;
        memcpy(a.verifier_nonce, req.payload, 32);
        memcpy(a.rot_nonce, j.nonce, 32);
        memcpy(a.image_digest, info.digest, 32);
        a.active_slot = (uint8_t)chosen;
        a.trial_state = trial_flag(&j);
        a.reset_cause = in->reset_cause;
        a.flags = (uint8_t)(in->sim_puf ? ATR2_FLAG_SIM_PUF : 0);
        a.journal_seq = j.seq;
        a.last_receipt_seq = j.receipt_seq;
        a.bits_corrected = (uint16_t)st.bits_corrected;
        a.worst_block = (uint8_t)st.worst_block;
        memcpy(a.last_receipt_digest, j.last_receipt_digest, 32);
        memcpy(a.version, info.apm.version, 16);
        atr2_serialize(body, &a);
        if (atr2_sign(body, keys.sk_dsa, out->hnd.atr2) != 0) {
            finish_safe(out, SAFE_INTERNAL);
            cleanup(in);
            return 0;
        }
        out->hnd.atr2_len = ATR2_TOTAL_BYTES;
        out->hnd.flags |= HND_F_ATTEST;
        rot_flash_put(p, ROT_DATA_SECTOR_OFF(ROT_SECTOR_ATR2), out->hnd.atr2, ATR2_TOTAL_BYTES);
        cycles[HND_C_ATTEST] = cyc(p) - t0;
        ev = EV_ATTEST;
    }

    /* B14: public report */
    out->hnd.device_id = keys.device_id;
    out->hnd.svn = info.svn;
    out->hnd.floor = ctx.floor;
    out->hnd.active_slot = (uint8_t)chosen;
    out->hnd.trial_slot = j.trial_slot;
    out->hnd.trial_state = j.trial_state;
    out->hnd.reset_cause = in->reset_cause;
    out->hnd.slot_status[0] = j.status[0];
    out->hnd.slot_status[1] = j.status[1];
    out->hnd.worst_block = (uint8_t)st.worst_block;
    out->hnd.refresh_count = in->refresh_count;
    out->hnd.bits_corrected = (uint16_t)st.bits_corrected;
    out->hnd.die_temp_x10 = in->die_temp_x10;
    out->hnd.journal_seq = j.seq;
    out->hnd.receipt_seq = j.receipt_seq;
    memcpy(out->hnd.version_str, info.apm.version, 16);
    out->hnd.last_event = (uint8_t)ev;
    out->hnd.last_reason = (uint8_t)ev_reason;
    memcpy(out->hnd.build_id, in->build_id, 20);
    memcpy(out->hnd.pk_dsa, keys.pk_dsa, ROT_DSA_PK);
    memcpy(out->hnd.pk_kem, keys.pk_kem, ROT_KEM_PK);
    if (in->sim_puf) {
        out->hnd.flags |= HND_F_SIM_PUF;
    }
    if (j.trial_state == TRIAL_RUNNING && chosen == j.trial_slot) {
        out->hnd.flags |= HND_F_TRIAL;
    }
    cycles[HND_C_TOTAL] = cyc(p) - tstart;
    memcpy(out->hnd.cycles, cycles, sizeof cycles);
    rot_handoff_seal(&out->hnd);

    /* B15: the mailbox goes last, after all state is durable */
    if (mbx_rc != ROT_MBX_EMPTY) {
        rot_mailbox_erase(p);
    }

    out->action = BOOT_CHAIN;
    out->chain_slot = chosen;
    out->chain_off = ROT_SLOT_OFF(chosen) + ROT_APP_BIN_OFFSET;
    out->chain_len = (info.apm.app_bin_len + 3u) & ~3u;
    out->trial = (j.trial_state == TRIAL_RUNNING && chosen == j.trial_slot);
    out->trial_deadline_ms = info.apm.trial_deadline_ms;

    jlog(p, "{\"ev\":\"chain\",\"slot\":%d,\"svn\":%llu,\"floor\":%llu,\"bits\":%u,\"worst\":%u,\"trial\":%d}",
         chosen, (unsigned long long)info.svn, (unsigned long long)ctx.floor,
         st.bits_corrected, st.worst_block, out->trial);
    cleanup(in);
    return 0;
}
