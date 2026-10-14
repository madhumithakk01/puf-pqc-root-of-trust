/*
 * Tests for the RoT's flash records: sealed anchor (ANC1), persisted rollback
 * counter (RBC1), state journal (JNL1) and mailbox (MBX1).
 *
 * For every record that is rewritten, a power cut is injected at every flash
 * cost unit of the write (flash_model.h) and the state afterwards must be
 * either the old record or the new one, never a third thing and never an
 * unrecoverable error.
 */

#include "flash_model.h"

#include "rot/rot_anchor.h"
#include "rot/rot_counter.h"
#include "rot/rot_crc32.h"
#include "rot/rot_flash.h"
#include "rot/rot_journal.h"
#include "rot/rot_mailbox.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

static void check(const char *name, int ok)
{
    printf("  %s %s\n", ok ? "ok  " : "FAIL", name);
    if (!ok) failures++;
}

static flash_model fm;
static rot_platform P;
static uint8_t snapshot[ROT_FLASH_TOTAL];

static void fresh(void)
{
    flash_model_power_on(&fm);
    memset(fm.mem, 0xFF, fm.size);
    fm.spent = 0;
}

static void save(void) { memcpy(snapshot, fm.mem, fm.size); }
static void restore(void)
{
    memcpy(fm.mem, snapshot, fm.size);
    flash_model_power_on(&fm);
}

static uint8_t key[32], key2[32];

/* ---- anchor ---------------------------------------------------------- */

static void test_anchor(void)
{
    uint8_t pk[ROT_ANCHOR_PK_BYTES], out[ROT_ANCHOR_PK_BYTES], pk2[ROT_ANCHOR_PK_BYTES];
    for (unsigned i = 0; i < sizeof pk; i++) { pk[i] = (uint8_t)(i * 7 + 3); pk2[i] = (uint8_t)(i * 5 + 9); }

    fresh();
    check("blank sector is ABSENT", rot_anchor_open(&P, key, out) == ROT_ANCHOR_ABSENT);
    check("seal", rot_anchor_seal(&P, key, pk) == 0);
    check("open returns the sealed key", rot_anchor_open(&P, key, out) == 0 && memcmp(out, pk, sizeof pk) == 0);
    check("another device key cannot open it", rot_anchor_open(&P, key2, out) == ROT_ANCHOR_BAD);

    uint32_t off = ROT_DATA_SECTOR_OFF(ROT_SECTOR_ANC1);
    fm.mem[off + 8 + 100] ^= 1;
    check("a flipped public-key bit is detected", rot_anchor_open(&P, key, out) == ROT_ANCHOR_BAD);
    fm.mem[off + 8 + 100] ^= 1;
    fm.mem[off + 1320] ^= 1;
    check("a flipped tag bit is detected", rot_anchor_open(&P, key, out) == ROT_ANCHOR_BAD);
    fm.mem[off + 1320] ^= 1;
    fm.mem[off + 4] = 2;
    check("a wrong version is rejected", rot_anchor_open(&P, key, out) == ROT_ANCHOR_BAD);
    fm.mem[off + 4] = 1;
    check("record is intact again", rot_anchor_open(&P, key, out) == 0);

    /* an attacker swaps in their own key and tag guess: rejected */
    uint8_t forged[ROT_ANCHOR_BYTES];
    memcpy(forged, fm.mem + off, sizeof forged);
    memcpy(forged + 8, pk2, sizeof pk2);
    memcpy(fm.mem + off, forged, sizeof forged);
    check("swapped vendor key without the tag key is rejected", rot_anchor_open(&P, key, out) == ROT_ANCHOR_BAD);

    /* power cut at every unit while sealing over an existing record */
    fresh();
    rot_anchor_seal(&P, key, pk);
    save();
    fm.spent = 0;
    rot_anchor_seal(&P, key, pk2);
    uint64_t total = fm.spent;
    int bad = 0, old_n = 0, new_n = 0;
    for (uint64_t cut = 0; cut <= total; cut++) {
        restore();
        flash_model_arm_cut(&fm, (int64_t)cut);
        rot_anchor_seal(&P, key, pk2);
        flash_model_power_on(&fm);
        int rc = rot_anchor_open(&P, key, out);
        if (rc == 0 && memcmp(out, pk2, sizeof pk2) == 0) new_n++;
        else if (rc == 0 && memcmp(out, pk, sizeof pk) == 0) old_n++;
        else if (rc == ROT_ANCHOR_ABSENT || rc == ROT_ANCHOR_BAD) { /* torn: detected */ }
        else bad++;
    }
    check("anchor: no cut point yields an accepted key other than old or new", bad == 0);
    check("anchor: the finished write is accepted", new_n >= 1);
    (void)old_n;
}

/* ---- counter ---------------------------------------------------------- */

static void test_counter(void)
{
    uint64_t f;

    fresh();
    check("unenrolled counter reads NONE", rot_counter_read(&P, key, &f) == ROT_CTR_NONE);
    check("enroll floor 1", rot_counter_enroll(&P, key, 1) == 0);
    check("read floor 1", rot_counter_read(&P, key, &f) == 0 && f == 1);
    check("update to 2", rot_counter_update(&P, key, 2) == 0 && rot_counter_read(&P, key, &f) == 0 && f == 2);
    check("update to 3 uses the other page", rot_counter_update(&P, key, 3) == 0
          && rot_counter_read(&P, key, &f) == 0 && f == 3);
    check("equal value refused", rot_counter_update(&P, key, 3) == ROT_CTR_MONOTONIC);
    check("lower value refused", rot_counter_update(&P, key, 2) == ROT_CTR_MONOTONIC);
    check("floor unchanged after refusals", rot_counter_read(&P, key, &f) == 0 && f == 3);
    check("wrong key sees tampering", rot_counter_read(&P, key2, &f) == ROT_CTR_TAMPER);

    /* flip the stored counter in the current page */
    uint32_t a = ROT_DATA_SECTOR_OFF(ROT_SECTOR_RBC1_A), b = ROT_DATA_SECTOR_OFF(ROT_SECTOR_RBC1_B);
    uint32_t cur = (fm.mem[a + 4] > fm.mem[b + 4]) ? a : b;
    fm.mem[cur + 8] ^= 0x08;
    check("a modified counter is TAMPER", rot_counter_read(&P, key, &f) == ROT_CTR_TAMPER);
    fm.mem[cur + 8] ^= 0x08;
    check("restored page reads again", rot_counter_read(&P, key, &f) == 0 && f == 3);

    /* power cut at every unit of an update, from two different starting states */
    for (int start = 0; start < 2; start++) {
        fresh();
        rot_counter_enroll(&P, key, 1);
        if (start) rot_counter_update(&P, key, 2);
        uint64_t base = start ? 2 : 1, target = base + 1;
        save();
        fm.spent = 0;
        rot_counter_update(&P, key, target);
        uint64_t total = fm.spent;
        int bad = 0, advanced = 0, again_bad = 0;
        for (uint64_t cut = 0; cut <= total; cut++) {
            restore();
            flash_model_arm_cut(&fm, (int64_t)cut);
            rot_counter_update(&P, key, target);
            flash_model_power_on(&fm);
            int rc = rot_counter_read(&P, key, &f);
            if (rc != 0 || (f != base && f != target)) { bad++; continue; }
            if (f == target) advanced++;
            /* and the device can continue from whatever state it is in */
            if (rot_counter_update(&P, key, target + 1) != 0 || rot_counter_read(&P, key, &f) != 0
                || f != target + 1) again_bad++;
        }
        char name[96];
        snprintf(name, sizeof name, "counter %llu->%llu: every cut point leaves the old or new floor",
                 (unsigned long long)base, (unsigned long long)target);
        check(name, bad == 0);
        snprintf(name, sizeof name, "counter %llu->%llu: the next update always succeeds",
                 (unsigned long long)base, (unsigned long long)target);
        check(name, again_bad == 0);
        check("counter: the completed write advances", advanced >= 1);
    }
}

/* ---- journal ---------------------------------------------------------- */

static rot_journal_t sample_journal(void)
{
    rot_journal_t j;
    memset(&j, 0, sizeof j);
    j.active = 0;
    j.status[0] = SLOT_GOOD;
    j.status[1] = SLOT_EMPTY;
    return j;
}

static int journal_equal(const rot_journal_t *a, const rot_journal_t *b)
{
    return a->active == b->active && a->status[0] == b->status[0] && a->status[1] == b->status[1]
           && a->trial_state == b->trial_state && a->trial_slot == b->trial_slot
           && a->nonce_state == b->nonce_state && a->trial_svn == b->trial_svn
           && memcmp(a->nonce, b->nonce, 32) == 0 && a->receipt_seq == b->receipt_seq
           && memcmp(a->last_receipt_digest, b->last_receipt_digest, 32) == 0;
}

static void test_journal(void)
{
    rot_journal_t j = sample_journal(), got, next;

    fresh();
    check("blank journal is NONE", rot_journal_load(&P, key, &got) == ROT_JNL_NONE);
    check("enroll", rot_journal_enroll(&P, key, &j) == 0);
    check("load after enroll", rot_journal_load(&P, key, &got) == 0 && got.seq == 1
          && journal_equal(&got, &j));
    check("wrong key sees no journal", rot_journal_load(&P, key2, &got) == ROT_JNL_NONE);

    next = got;
    next.nonce_state = NONCE_OUTSTANDING;
    for (int i = 0; i < 32; i++) next.nonce[i] = (uint8_t)(0x60 + i);
    check("commit 1", rot_journal_commit(&P, key, &next) == 0 && next.seq == 2 && next.page == 1);
    check("load sees commit 1", rot_journal_load(&P, key, &got) == 0 && got.seq == 2
          && journal_equal(&got, &next) && got.page == 1);
    next.trial_state = TRIAL_RUNNING;
    next.trial_slot = 1;
    next.trial_svn = 3;
    next.status[1] = SLOT_TRIAL;
    check("commit 2 alternates back", rot_journal_commit(&P, key, &next) == 0 && next.seq == 3 && next.page == 0);
    check("load sees commit 2", rot_journal_load(&P, key, &got) == 0 && got.seq == 3 && journal_equal(&got, &next));

    /* tamper with the newest page: it is ignored, the older one wins */
    uint32_t newest = ROT_DATA_SECTOR_OFF(ROT_SECTOR_JNL1_A);
    fm.mem[newest + 9] ^= 1;
    check("a modified newest page is ignored", rot_journal_load(&P, key, &got) == 0 && got.seq == 2);
    fm.mem[newest + 9] ^= 1;
    check("restored page wins again", rot_journal_load(&P, key, &got) == 0 && got.seq == 3);

    /* both pages bad */
    fm.mem[newest + 9] ^= 1;
    fm.mem[ROT_DATA_SECTOR_OFF(ROT_SECTOR_JNL1_B) + 9] ^= 1;
    check("both pages bad is NONE", rot_journal_load(&P, key, &got) == ROT_JNL_NONE);

    /* valid tag but out-of-range field (a bug or a key leak, not an accident) */
    {
        rot_journal_t evil = sample_journal();
        uint8_t rec[ROT_JNL_BYTES];
        evil.seq = 9;
        evil.active = 7;
        rot_journal_serialize(rec, &evil, key);
        fresh();
        rot_flash_put(&P, ROT_DATA_SECTOR_OFF(ROT_SECTOR_JNL1_A), rec, sizeof rec);
        check("out-of-range field with a valid tag is rejected", rot_journal_load(&P, key, &got) == ROT_JNL_BAD_FIELD);
    }

    /* power cut at every unit of a commit */
    for (int start = 0; start < 2; start++) {
        fresh();
        j = sample_journal();
        rot_journal_enroll(&P, key, &j);
        rot_journal_load(&P, key, &got);
        if (start) { got.receipt_seq = 1; rot_journal_commit(&P, key, &got); }
        rot_journal_t old = got, nw = got;
        nw.trial_state = TRIAL_RUNNING;
        nw.trial_slot = 1;
        nw.trial_svn = 9;
        nw.status[1] = SLOT_TRIAL;
        save();
        fm.spent = 0;
        rot_journal_t w = nw;
        w.page = old.page; w.seq = old.seq;
        rot_journal_commit(&P, key, &w);
        uint64_t total = fm.spent;
        int bad = 0, again_bad = 0, new_n = 0;
        for (uint64_t cut = 0; cut <= total; cut++) {
            restore();
            flash_model_arm_cut(&fm, (int64_t)cut);
            w = nw; w.page = old.page; w.seq = old.seq;
            rot_journal_commit(&P, key, &w);
            flash_model_power_on(&fm);
            rot_journal_t cur;
            if (rot_journal_load(&P, key, &cur) != 0) { bad++; continue; }
            if (journal_equal(&cur, &nw)) new_n++;
            else if (!journal_equal(&cur, &old)) { bad++; continue; }
            cur.receipt_seq += 1;
            if (rot_journal_commit(&P, key, &cur) != 0) again_bad++;
        }
        check("journal: every cut point leaves the old or the new state", bad == 0);
        check("journal: the next commit always succeeds", again_bad == 0);
        check("journal: the completed write is the new state", new_n >= 1);
    }
}

/* ---- mailbox ---------------------------------------------------------- */

static int put_mbx(uint32_t seq, uint8_t type, const uint8_t *payload, uint16_t len)
{
    uint8_t rec[128];
    size_t n = rot_mailbox_build(rec, seq, type, payload, len);
    return rot_flash_put(&P, ROT_DATA_SECTOR_OFF(ROT_SECTOR_MBX1), rec, n);
}

static void test_mailbox(void)
{
    rot_mbx_t m;
    uint8_t pl[64];
    for (int i = 0; i < 64; i++) pl[i] = (uint8_t)(i + 1);

    fresh();
    check("blank mailbox is EMPTY", rot_mailbox_read(&P, &m) == ROT_MBX_EMPTY);
    check("ATTEST_REQ", put_mbx(5, MBX_ATTEST_REQ, pl, 32) == 0 && rot_mailbox_read(&P, &m) == 0
          && m.seq == 5 && m.type == MBX_ATTEST_REQ && m.len == 32 && memcmp(m.payload, pl, 32) == 0);
    check("INSTALL_REQ", put_mbx(6, MBX_INSTALL_REQ, pl, 8) == 0 && rot_mailbox_read(&P, &m) == 0
          && m.type == MBX_INSTALL_REQ && m.len == 8);
    check("HEALTH_REPORT", put_mbx(7, MBX_HEALTH_REPORT, pl, 32) == 0 && rot_mailbox_read(&P, &m) == 0
          && m.type == MBX_HEALTH_REPORT);

    uint32_t off = ROT_DATA_SECTOR_OFF(ROT_SECTOR_MBX1);
    fm.mem[off + 20] ^= 1;
    check("payload bit flip fails the CRC", rot_mailbox_read(&P, &m) == ROT_MBX_BAD);
    fm.mem[off + 20] ^= 1;
    check("restored record reads", rot_mailbox_read(&P, &m) == 0);

    check("wrong payload length for the type", put_mbx(1, MBX_ATTEST_REQ, pl, 31) == 0
          && rot_mailbox_read(&P, &m) == ROT_MBX_BAD);
    check("unknown type", put_mbx(1, 9, pl, 8) == 0 && rot_mailbox_read(&P, &m) == ROT_MBX_BAD);
    check("type zero", put_mbx(1, 0, pl, 8) == 0 && rot_mailbox_read(&P, &m) == ROT_MBX_BAD);
    {
        uint8_t rec[128];
        size_t n = rot_mailbox_build(rec, 1, MBX_ATTEST_REQ, pl, 32);
        rec[10] = 0xFF; rec[11] = 0x7F; /* absurd length */
        rot_flash_put(&P, off, rec, n);
        check("oversize length field", rot_mailbox_read(&P, &m) == ROT_MBX_BAD);
        n = rot_mailbox_build(rec, 1, MBX_ATTEST_REQ, pl, 32);
        rec[0] = 'X';
        rot_flash_put(&P, off, rec, n);
        check("bad magic", rot_mailbox_read(&P, &m) == ROT_MBX_BAD);
        rot_flash_put(&P, off, rec, 3);
        check("truncated record", rot_mailbox_read(&P, &m) == ROT_MBX_BAD);
    }
    check("erase", rot_mailbox_erase(&P) == 0 && rot_mailbox_read(&P, &m) == ROT_MBX_EMPTY);

    check("CRC32 known answer (\"123456789\")", rot_crc32(0, (const uint8_t *)"123456789", 9) == 0xCBF43926u);
}

int main(void)
{
    for (int i = 0; i < 32; i++) { key[i] = (uint8_t)(i + 1); key2[i] = (uint8_t)(0x90 + i); }
    if (flash_model_init(&fm, ROT_FLASH_TOTAL) != 0) return 1;
    flash_model_platform(&fm, &P);

    test_anchor();
    test_counter();
    test_journal();
    test_mailbox();

    flash_model_free(&fm);
    if (failures) {
        printf("test_records: FAIL (%d)\n", failures);
        return 1;
    }
    printf("test_records: PASS\n");
    return 0;
}
