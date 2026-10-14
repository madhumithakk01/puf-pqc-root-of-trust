/*
 * Fault tests for the RoT boot state machine: offline tampering of slots and
 * records, a key that does not reconstruct, and power cuts injected at many
 * points of an install and of a trial commit. The invariants after every
 * cut: the device boots only a verified image at or above the floor, the
 * floor never decreases, and the next update still works.
 */

#include "rot_fixture.h"

#include "rot/rot_counter.h"
#include "rot/rot_crc32.h"
#include "rot/rot_flash.h"
#include "rot/rot_helper.h"
#include "rot/rot_receipts.h"
#include "rot/rot_trial.h"
#include "rot/rot_util.h"

#include "attest/attest2.h"
#include "dlv/dlv.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

static void check(const char *name, int ok)
{
    printf("  %s %s\n", ok ? "ok  " : "FAIL", name);
    if (!ok) failures++;
}

#define IMG_CAP 65536
#define BPM_OK  720
#define SPO2_OK 975

static fx_t F;
static uint8_t imgs[6][IMG_CAP];
static size_t img_len[6];
static uint8_t pkg[IMG_CAP * 2];

static void nonce_of(uint8_t n[32], int tag)
{
    for (int i = 0; i < 32; i++) n[i] = (uint8_t)(tag * 29 + i);
}

static void build_images(void)
{
    for (int s = 1; s <= 5; s++) {
        char ver[16];
        snprintf(ver, sizeof ver, "1.%d.0", s - 1);
        img_len[s] = fx_image(&F, imgs[s], IMG_CAP, (uint64_t)s, ver, BPM_OK, SPO2_OK, 5000 + (size_t)s * 500, F.vendor_sk);
    }
}

static void health_ok(uint64_t svn)
{
    fx_mbx_health(&F, svn, BPM_OK, SPO2_OK, 0x15, 1, 100);
}

/* attest, package svn `s`, stage, request; does not boot the install */
static int prepare_install(int s, int nonce_tag)
{
    uint8_t vn[32], rn[32];
    char ver[16];
    size_t n;
    snprintf(ver, sizeof ver, "1.%d.0", s - 1);
    nonce_of(vn, nonce_tag);
    if (fx_attest(&F, vn, rn) != 0) return -1;
    n = fx_package(&F, pkg, sizeof pkg, imgs[s], img_len[s], F.device_id, rn, (uint64_t)s, ver,
                   F.dev_pk_kem, F.vendor_sk);
    if (n == 0) return -2;
    fx_stage_and_request(&F, pkg, n);
    return 0;
}

/* Full update cycle that must succeed: returns 0 when svn `s` is committed. */
static int full_update(int s, int nonce_tag)
{
    uint64_t floor = 0;
    if (prepare_install(s, nonce_tag) != 0) return -1;
    if (fx_boot(&F) != 0 || !F.out.trial) return -2;
    health_ok((uint64_t)s);
    if (fx_boot(&F) != 0) return -3;
    if (fx_floor(&F, &floor) != 0 || floor != (uint64_t)s) return -4;
    return F.out.hnd.svn == (uint64_t)s ? 0 : -5;
}

static void fresh_device(uint32_t puf_id)
{
    fx_free(&F);
    fx_init(&F, puf_id);
    build_images();
    fx_enroll(&F);
}

/* ------------------------------------------------------------------ */

static void test_offline_tamper(void)
{
    rot_journal_t j;
    static uint8_t S[ROT_FLASH_TOTAL];

    fresh_device(777);
    fx_put_slot(&F, 0, imgs[1], img_len[1]);
    full_update(2, 1);
    full_update(3, 2);   /* slot B = svn 2 was active, now slot A = svn 3 active; floor 3 */
    fx_save(&F, S);
    check("start: svn 3 active in slot A, floor 3", fx_boot(&F) == 0 && F.out.hnd.svn == 3 && F.out.chain_slot == 0);

    /* A7: one byte changed in the active slot */
    F.fm.mem[ROT_SLOT_OFF(0) + 5000] ^= 0x01;
    check("A7 flipped byte in the active image: SAFE, nothing unverified runs",
          fx_boot(&F) == BOOT_SAFE && F.out.safe_reason == SAFE_NO_VALID_IMAGE);
    check("A7: the refusal names the bad signature", F.out.image_reason == RCP_REASON_IMG_BAD_SIGNATURE);
    fx_restore(&F, S);
    check("A7: restoring the byte boots again", fx_boot(&F) == 0 && F.out.hnd.svn == 3);

    /* A8: old signed image written over the active slot */
    fx_put_slot(&F, 0, imgs[1], img_len[1]);
    check("A8 genuine old image in the active slot: SAFE",
          fx_boot(&F) == BOOT_SAFE && F.out.safe_reason == SAFE_NO_VALID_IMAGE);
    check("A8: refused as below the floor", F.out.image_reason == RCP_REASON_IMG_BELOW_FLOOR);
    fx_restore(&F, S);

    /* other slot: GOOD, above floor -> fallback; REJECTED -> never */
    fresh_device(778);
    fx_put_slot(&F, 0, imgs[1], img_len[1]);
    fx_put_slot(&F, 1, imgs[1], img_len[1]);
    memset(&j, 0, sizeof j);
    j.active = 0;
    j.status[0] = SLOT_GOOD;
    j.status[1] = SLOT_GOOD;
    fx_set_journal(&F, &j);
    check("two good slots, active boots", fx_boot(&F) == 0 && F.out.chain_slot == 0);
    F.fm.mem[ROT_SLOT_OFF(0) + 4500] ^= 0x10;
    check("tampered active slot falls back to the other verified slot",
          fx_boot(&F) == 0 && F.out.chain_slot == 1 && F.out.hnd.svn == 1);
    j.status[1] = SLOT_REJECTED;
    fx_set_journal(&F, &j);
    check("a REJECTED slot is never booted", fx_boot(&F) == BOOT_SAFE && F.out.safe_reason == SAFE_NO_VALID_IMAGE);
    memset(F.fm.mem + ROT_SLOT_OFF(0), 0x00, 8192);
    check("unsigned garbage in a slot is refused", fx_boot(&F) == BOOT_SAFE);
}

static void test_record_tamper(void)
{
    static uint8_t S[ROT_FLASH_TOTAL];
    uint32_t a = ROT_DATA_SECTOR_OFF(ROT_SECTOR_ANC1);

    fresh_device(901);
    fx_put_slot(&F, 0, imgs[1], img_len[1]);
    full_update(2, 3);
    fx_save(&F, S);
    check("baseline boots", fx_boot(&F) == 0);

    F.fm.mem[a + 8 + 40] ^= 1;
    check("anchor public key altered: SAFE(ANCHOR)", fx_boot(&F) == BOOT_SAFE && F.out.safe_reason == SAFE_ANCHOR);
    fx_restore(&F, S);
    memset(F.fm.mem + a, 0xFF, ROT_FLASH_SECTOR);
    check("anchor erased: SAFE(ANCHOR), the device does not trust an empty anchor",
          fx_boot(&F) == BOOT_SAFE && F.out.safe_reason == SAFE_ANCHOR);
    fx_restore(&F, S);

    {
        /* the newest counter page: whichever sector has the higher seq */
        uint32_t ca = ROT_DATA_SECTOR_OFF(ROT_SECTOR_RBC1_A), cb = ROT_DATA_SECTOR_OFF(ROT_SECTOR_RBC1_B);
        uint32_t cur = (F.fm.mem[ca + 4] >= F.fm.mem[cb + 4]) ? ca : cb;
        F.fm.mem[cur + 8] ^= 0x04;
        check("counter value altered: SAFE(COUNTER)", fx_boot(&F) == BOOT_SAFE && F.out.safe_reason == SAFE_COUNTER);
        fx_restore(&F, S);
        F.fm.mem[cur + 20] ^= 0x01;
        check("counter tag altered: SAFE(COUNTER)", fx_boot(&F) == BOOT_SAFE && F.out.safe_reason == SAFE_COUNTER);
        fx_restore(&F, S);
        memset(F.fm.mem + ca, 0xFF, ROT_FLASH_SECTOR);
        memset(F.fm.mem + cb, 0xFF, ROT_FLASH_SECTOR);
        check("both counter pages erased: SAFE(COUNTER)", fx_boot(&F) == BOOT_SAFE && F.out.safe_reason == SAFE_COUNTER);
        fx_restore(&F, S);
    }

    {
        uint32_t ja = ROT_DATA_SECTOR_OFF(ROT_SECTOR_JNL1_A), jb = ROT_DATA_SECTOR_OFF(ROT_SECTOR_JNL1_B);
        F.fm.mem[ja + 9] ^= 1;
        F.fm.mem[jb + 9] ^= 1;
        check("both journal pages altered: SAFE(JOURNAL)", fx_boot(&F) == BOOT_SAFE && F.out.safe_reason == SAFE_JOURNAL);
        fx_restore(&F, S);
        memset(F.fm.mem + ja, 0xFF, ROT_FLASH_SECTOR);
        memset(F.fm.mem + jb, 0xFF, ROT_FLASH_SECTOR);
        check("both journal pages erased: SAFE(JOURNAL)", fx_boot(&F) == BOOT_SAFE && F.out.safe_reason == SAFE_JOURNAL);
        fx_restore(&F, S);
    }

    {
        uint32_t h = ROT_DATA_SECTOR_OFF(ROT_SECTOR_HLP1);
        F.fm.mem[h + 128 + 100] ^= 1; /* inside the pair bitmap */
        check("helper data damaged (CRC fails): SAFE(HELPER)", fx_boot(&F) == BOOT_SAFE && F.out.safe_reason == SAFE_HELPER);
        fx_restore(&F, S);

        /* an attacker fixes the CRC after changing the pair bitmap or the fuzzy helper */
        F.fm.mem[h + 2176 + 10] ^= 0x55;
        rot_put32(F.fm.mem + h + 2656, rot_crc32(0, F.fm.mem + h, 2656));
        check("helper changed with a fixed CRC: key does not reconstruct, one refresh is requested",
              fx_boot_wrong_chip(&F, F.puf_id, 0) == BOOT_REFRESH);
        check("after the retry the device stops: SAFE(PUF_MISMATCH)",
              fx_boot_wrong_chip(&F, F.puf_id, 1) == BOOT_SAFE && F.out.safe_reason == SAFE_PUF_MISMATCH);
        fx_restore(&F, S);
        memset(F.fm.mem + h, 0xFF, ROT_FLASH_SECTOR);
        check("helper erased looks like an unenrolled device (enrollment would be a factory act)",
              fx_boot(&F) == BOOT_ENROLL);
        fx_restore(&F, S);
    }

    check("flash cloned onto a different chip: key does not reconstruct",
          fx_boot_wrong_chip(&F, 31337, 0) == BOOT_REFRESH
          && fx_boot_wrong_chip(&F, 31337, 1) == BOOT_SAFE && F.out.safe_reason == SAFE_PUF_MISMATCH);
    check("the cloned flash never exposes the device identity", F.out.hnd.device_id == 0
          && rot_all_byte(F.out.hnd.pk_dsa, ROT_DSA_PK, 0));

    /* L3: restoring an older snapshot of the data region is accepted (documented limit) */
    {
        static uint8_t old[ROT_FLASH_TOTAL];
        fresh_device(902);
        fx_put_slot(&F, 0, imgs[1], img_len[1]);
        full_update(2, 4);
        fx_save(&F, old);
        full_update(3, 5);
        memcpy(F.fm.mem + ROT_REGION_DATA_OFF, old + ROT_REGION_DATA_OFF, ROT_REGION_DATA_SIZE);
        {
            uint64_t floor = 0;
            fx_floor(&F, &floor);
            check("L3: an old data-region snapshot is accepted by the device (floor 2 again)", floor == 2);
        }
        {
            uint8_t vn[32], rn[32];
            nonce_of(vn, 77);
            check("L3: ...and the attestation reports the lower floor for the vendor to flag",
                  fx_attest(&F, vn, rn) == 0 && F.out.hnd.floor <= 2);
        }
    }
}

/* ------------------------------------------------------------------ */

/* Reboot after a power cut until the device settles; returns last action. */
static int settle(void)
{
    int act = -1;
    F.reset_cause = RC_POR;
    for (int i = 0; i < 5; i++) {
        act = fx_boot(&F);
        if (act == 0 || act == BOOT_SAFE) break;
    }
    return act;
}

typedef struct {
    int points, bad, recovered_trial, recovered_plain;
} sweep_t;

static void sweep_install(sweep_t *sw, uint64_t base_floor, int next_svn, uint64_t step)
{
    static uint8_t S1[ROT_FLASH_TOTAL];
    uint64_t total;

    fx_save(&F, S1);
    F.fm.spent = 0;
    fx_boot(&F);
    total = F.fm.spent;
    printf("       install boot costs %llu flash units; sampling every %llu\n",
           (unsigned long long)total, (unsigned long long)step);

    for (uint64_t cut = 0; cut <= total; cut += step) {
        uint64_t floor = 0;
        rot_journal_t j;
        int act, ok = 1;

        fx_restore(&F, S1);
        flash_model_arm_cut(&F.fm, (int64_t)cut);
        F.reset_cause = RC_POR;
        fx_boot(&F);
        flash_model_power_on(&F.fm);
        act = settle();
        sw->points++;

        if (act != 0) { ok = 0; }
        if (ok && (fx_floor(&F, &floor) != 0 || floor != base_floor)) ok = 0;
        if (ok && F.out.hnd.svn < floor) ok = 0;
        if (ok && fx_journal(&F, &j) != 0) ok = 0;
        if (ok && j.trial_state == TRIAL_RUNNING) {
            /* the install reached its trial: the new image must verify and commit */
            health_ok((uint64_t)next_svn);
            if (fx_boot(&F) != 0 || F.out.hnd.svn != (uint64_t)next_svn || F.out.hnd.floor != (uint64_t)next_svn) ok = 0;
            sw->recovered_trial++;
        } else if (ok) {
            /* the install did not complete: the device is still on the old image and a new update works */
            if (F.out.hnd.svn != base_floor) ok = 0;
            if (ok && full_update(next_svn, 90 + (int)(cut & 31)) != 0) ok = 0;
            sw->recovered_plain++;
        }
        if (!ok) {
            sw->bad++;
            printf("       cut at %llu: act=%d floor=%llu svn=%llu\n", (unsigned long long)cut, act,
                   (unsigned long long)floor, (unsigned long long)F.out.hnd.svn);
        }
    }
    fx_restore(&F, S1);
}

static void test_power_cut_install(void)
{
    sweep_t sw = { 0 };

    fresh_device(1001);
    fx_put_slot(&F, 0, imgs[1], img_len[1]);
    full_update(2, 6);              /* active slot B, svn 2, floor 2 */
    prepare_install(3, 7);          /* nonce outstanding, package staged, request queued */
    sweep_install(&sw, 2, 3, 53);
    check("install power cuts: every sampled point recovers to a verified image with floor intact", sw.bad == 0);
    check("install power cuts: both outcomes occur (completed trial and aborted install)",
          sw.recovered_trial > 0 && sw.recovered_plain > 0);
    printf("       %d cut points: %d reached the trial, %d aborted before it\n",
           sw.points, sw.recovered_trial, sw.recovered_plain);
}

static void test_power_cut_commit(void)
{
    static uint8_t S2[ROT_FLASH_TOTAL];
    uint64_t total;
    int bad = 0, points = 0;

    fresh_device(1002);
    fx_put_slot(&F, 0, imgs[1], img_len[1]);
    full_update(2, 8);
    prepare_install(3, 9);
    fx_boot(&F);                    /* trial of svn 3 running in slot A */
    health_ok(3);
    fx_save(&F, S2);
    F.fm.spent = 0;
    fx_boot(&F);
    total = F.fm.spent;
    printf("       commit boot costs %llu flash units\n", (unsigned long long)total);

    for (uint64_t cut = 0; cut <= total; cut += 11) {
        uint64_t floor = 0;
        rot_journal_t j;
        int ok = 1;

        fx_restore(&F, S2);
        flash_model_arm_cut(&F.fm, (int64_t)cut);
        F.reset_cause = RC_POR;
        fx_boot(&F);
        flash_model_power_on(&F.fm);
        if (settle() != 0) ok = 0;
        points++;

        /* the report is still in the mailbox until the very end, so the decision is re-taken and lands on the same result */
        if (ok && (fx_floor(&F, &floor) != 0 || floor != 3)) ok = 0;
        if (ok && (fx_journal(&F, &j) != 0 || j.active != 0 || j.status[0] != SLOT_GOOD
                   || j.trial_state != TRIAL_NONE)) ok = 0;
        if (ok && F.out.hnd.svn != 3) ok = 0;
        if (ok) {
            /* every receipt in the ring verifies, and they chain */
            uint8_t objs[8][RCP_TOTAL_BYTES];
            uint8_t zero[32] = { 0 };
            rcp_t r;
            uint32_t n = j.receipt_seq;
            int chain_ok = n >= 2;
            for (uint32_t s = 1; s <= n && chain_ok; s++) {
                chain_ok = fx_receipt(&F, s, objs[s - 1], &r) == 0;
            }
            if (chain_ok && rcp_verify_chain(&objs[0][0], n, F.dev_pk_dsa, zero) != 0) chain_ok = 0;
            if (!chain_ok) ok = 0;
        }
        if (!ok) {
            bad++;
            printf("       cut at %llu failed\n", (unsigned long long)cut);
        }
    }
    check("commit power cuts: every sampled point ends committed at svn 3 with a valid receipt chain", bad == 0);
    printf("       %d cut points\n", points);
}

static void test_trial_timeout(void)
{
    rcp_t r;
    rot_journal_t j;
    uint8_t obj[RCP_TOTAL_BYTES];
    static uint8_t S3[ROT_FLASH_TOTAL];

    fresh_device(1003);
    fx_put_slot(&F, 0, imgs[1], img_len[1]);
    full_update(2, 10);
    prepare_install(3, 11);
    fx_boot(&F);
    fx_save(&F, S3);

    F.reset_cause = RC_WATCHDOG;
    fx_boot(&F);
    fx_journal(&F, &j);
    check("watchdog expiry without a report rolls back with TIMEOUT",
          fx_receipt(&F, j.receipt_seq, obj, &r) == 0 && r.outcome == RCP_ROLLED_BACK
          && r.reason == RCP_REASON_HEALTH_TIMEOUT && F.out.hnd.svn == 2 && F.out.hnd.floor == 2);
    fx_restore(&F, S3);
    F.reset_cause = RC_POR;
    fx_boot(&F);
    fx_journal(&F, &j);
    check("power loss during the trial rolls back with POWER_LOSS",
          fx_receipt(&F, j.receipt_seq, obj, &r) == 0 && r.outcome == RCP_ROLLED_BACK
          && r.reason == RCP_REASON_HEALTH_POWER_LOSS);
    health_ok(9);
    check("a stale HEALTH_REPORT with no trial is ignored and erased", fx_boot(&F) == 0
          && rot_all_byte(F.fm.mem + ROT_DATA_SECTOR_OFF(ROT_SECTOR_MBX1), 64, 0xFF) && F.out.hnd.floor == 2);
}

int main(void)
{
    fx_init(&F, 5);
    build_images();

    test_offline_tamper();
    test_record_tamper();
    test_trial_timeout();
    test_power_cut_install();
    test_power_cut_commit();

    fx_free(&F);
    if (failures) {
        printf("test_rot_faults: FAIL (%d)\n", failures);
        return 1;
    }
    printf("test_rot_faults: PASS\n");
    return 0;
}
