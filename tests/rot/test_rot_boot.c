#define _GNU_SOURCE
/*
 * End-to-end tests of the RoT boot state machine on the host platform:
 * enrollment, verified boot, attestation, the install pipeline with every
 * refusal, trial commit and rollback, offline tampering, record tampering,
 * and power cuts during install and commit.
 */

#include "rot_fixture.h"

#include "rot/rot_counter.h"
#include "rot/rot_crc32.h"
#include "rot/rot_flash.h"
#include "rot/rot_receipts.h"
#include "rot/rot_trial.h"
#include "rot/rot_util.h"

#include "attest/attest2.h"
#include "dlv/dlv.h"
#include "fips202.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(uint8_t *, uint8_t *, const uint8_t *);

static int failures = 0;

static void check(const char *name, int ok)
{
    printf("  %s %s\n", ok ? "ok  " : "FAIL", name);
    if (!ok) failures++;
}

#define IMG_CAP   (64 * 1024)
#define BPM_OK    720
#define SPO2_OK   975

static fx_t F;
static uint8_t v1[IMG_CAP], v2[IMG_CAP], v3[IMG_CAP];
static size_t v1_len, v2_len, v3_len;
static uint8_t pkg[IMG_CAP * 2];
static uint8_t zero32[32];

static void make_images(void)
{
    v1_len = fx_image(&F, v1, sizeof v1, 1, "1.0.0", BPM_OK, APM_SPO2_NONE, 6000, F.vendor_sk);
    v2_len = fx_image(&F, v2, sizeof v2, 2, "1.1.0", BPM_OK, SPO2_OK, 7000, F.vendor_sk);
    v3_len = fx_image(&F, v3, sizeof v3, 3, "1.2.0", BPM_OK, SPO2_OK, 7200, F.vendor_sk);
}

static void nonce_of(uint8_t n[32], int tag)
{
    for (int i = 0; i < 32; i++) n[i] = (uint8_t)(tag * 29 + i);
}

static uint64_t slot_hash_first(int slot)
{
    uint8_t d[8];
    shake256(d, 8, F.fm.mem + ROT_SLOT_OFF(slot), ROT_REGION_APP_A_SIZE);
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)d[i] << (8 * i);
    return v;
}

static int last_receipt(rcp_t *r)
{
    rot_journal_t j;
    uint8_t obj[RCP_TOTAL_BYTES];
    if (fx_journal(&F, &j) != 0) return -1;
    return fx_receipt(&F, j.receipt_seq, obj, r);
}

/* Attest, build a package for `image`, stage it, request the install, boot. */
static int do_install(const uint8_t *image, size_t image_len, uint64_t svn, const char *ver,
                      uint32_t device_id, const uint8_t *kem_pk, const uint8_t *sign_sk,
                      int nonce_tag, uint8_t *nonce_used)
{
    uint8_t vn[32], rn[32];
    size_t n;
    nonce_of(vn, nonce_tag);
    if (fx_attest(&F, vn, rn) != 0) return -10;
    if (nonce_used) memcpy(nonce_used, rn, 32);
    n = fx_package(&F, pkg, sizeof pkg, image, image_len, device_id, rn, svn, ver, kem_pk, sign_sk);
    if (n == 0) return -11;
    fx_stage_and_request(&F, pkg, n);
    return fx_boot(&F);
}

static int do_install_ok(const uint8_t *image, size_t len, uint64_t svn, const char *ver)
{
    return do_install(image, len, svn, ver, F.device_id, F.dev_pk_kem, F.vendor_sk, 5, NULL);
}

static void settle_health(uint64_t svn, uint16_t bpm, int sensor_ok)
{
    fx_mbx_health(&F, svn, bpm, SPO2_OK, 0x15, (uint8_t)sensor_ok, 100);
}

/* ------------------------------------------------------------------ */

static void test_enroll_and_boot(void)
{
    rot_journal_t j;
    uint64_t floor = 0;

    check("unenrolled device asks for enrollment", fx_boot(&F) == BOOT_ENROLL);
    check("enrollment succeeds", fx_enroll(&F) == 0);
    check("ENR1 proof of possession verifies", rot_enr1_verify(F.enr1, sizeof F.enr1) == 0);
    {
        uint8_t t[ROT_ENR1_BYTES];
        memcpy(t, F.enr1, sizeof t);
        t[100] ^= 1;
        check("a modified ENR1 is rejected", rot_enr1_verify(t, sizeof t) != 0);
    }
    check("journal and floor after enrollment", fx_journal(&F, &j) == 0 && j.active == 0
          && j.status[0] == SLOT_GOOD && j.status[1] == SLOT_EMPTY && fx_floor(&F, &floor) == 0 && floor == 1);

    check("enrolled but no image: SAFE(NO_VALID_IMAGE)",
          fx_boot(&F) == BOOT_SAFE && F.out.safe_reason == SAFE_NO_VALID_IMAGE);

    fx_put_slot(&F, 0, v1, v1_len);
    check("v1.0 in slot A boots", fx_boot(&F) == 0 && F.out.chain_slot == 0);
    check("chain target is the binary 4 KB into the slot",
          F.out.chain_off == ROT_REGION_APP_A_OFF + 0x1000 && F.out.chain_len == 6000);
    check("report: identity, floor, svn", F.out.hnd.device_id == F.device_id && F.out.hnd.floor == 1
          && F.out.hnd.svn == 1 && strcmp(F.out.hnd.version_str, "1.0.0") == 0);
    check("report CRC valid and public keys match enrollment", rot_handoff_valid(&F.out.hnd)
          && memcmp(F.out.hnd.pk_dsa, F.dev_pk_dsa, ROT_DSA_PK) == 0
          && memcmp(F.out.hnd.pk_kem, F.dev_pk_kem, ROT_KEM_PK) == 0);
    check("not a trial, no attestation", !(F.out.hnd.flags & (HND_F_TRIAL | HND_F_ATTEST)) && !F.out.trial);

    unsigned max_bits = 0, max_worst = 0;
    int same_id = 1;
    for (int i = 0; i < 30; i++) {
        if (fx_boot(&F) != 0 || F.out.hnd.device_id != F.device_id) same_id = 0;
        if (F.out.hnd.bits_corrected > max_bits) max_bits = F.out.hnd.bits_corrected;
        if (F.out.hnd.worst_block > max_worst) max_worst = F.out.hnd.worst_block;
    }
    check("30 noisy boots: identity never changes", same_id);
    printf("       bits corrected max %u of 3840, worst block %u of 7\n", max_bits, max_worst);
    check("the decoder really corrected errors (noise is present)", max_bits > 20);
    check("margin: worst block within capacity", max_worst <= 7);
}

static void test_attest(void)
{
    uint8_t vn[32], r1[32], r2[32];
    atr2_t a;
    rot_journal_t j;

    nonce_of(vn, 1);
    check("attest returns a verified ATR2", fx_attest(&F, vn, r1) == 0);
    check("ATR2 content", atr2_parse(F.out.hnd.atr2, &a) == 0 && a.device_id == F.device_id
          && a.svn == 1 && a.floor == 1 && a.active_slot == 0 && a.trial_state == 0
          && memcmp(a.verifier_nonce, vn, 32) == 0 && memcmp(a.image_digest, zero32, 32) != 0);
    check("RoT nonce is fresh and recorded in the journal", memcmp(r1, zero32, 32) != 0
          && fx_journal(&F, &j) == 0 && j.nonce_state == NONCE_OUTSTANDING && memcmp(j.nonce, r1, 32) == 0);
    check("ATR2 is also stored in the data region",
          memcmp(F.fm.mem + ROT_DATA_SECTOR_OFF(ROT_SECTOR_ATR2), F.out.hnd.atr2, ATR2_TOTAL_BYTES) == 0);
    check("mailbox is erased after the boot",
          rot_all_byte(F.fm.mem + ROT_DATA_SECTOR_OFF(ROT_SECTOR_MBX1), 64, 0xFF));

    nonce_of(vn, 2);
    check("a second attestation gives another RoT nonce", fx_attest(&F, vn, r2) == 0 && memcmp(r1, r2, 32) != 0);
    {
        uint8_t t[ATR2_TOTAL_BYTES];
        memcpy(t, F.out.hnd.atr2, sizeof t);
        t[16] ^= 1;
        check("tampering with the report breaks the signature",
              atr2_verify(t, sizeof t, F.dev_pk_dsa) != 0);
    }
}

static void test_update_flow(void)
{
    rot_journal_t j;
    uint64_t floor;
    rcp_t r;
    uint8_t n[32];

    /* U1-U16: v1.0 -> v1.1 */
    check("v1.1 installs into slot B and starts a trial",
          do_install_ok(v2, v2_len, 2, "1.1.0") == 0 && F.out.trial && F.out.chain_slot == 1
          && (F.out.hnd.flags & HND_F_TRIAL) && F.out.trial_deadline_ms == 15000);
    check("journal: trial RUNNING, floor not yet advanced",
          fx_journal(&F, &j) == 0 && j.trial_state == TRIAL_RUNNING && j.trial_slot == 1
          && j.status[1] == SLOT_TRIAL && j.trial_svn == 2 && j.nonce_state == NONCE_NONE
          && fx_floor(&F, &floor) == 0 && floor == 1);
    check("the nonce was consumed and the active slot is untouched", j.active == 0);

    settle_health(2, BPM_OK, 1);
    check("good health evidence commits v1.1", fx_boot(&F) == 0 && F.out.hnd.floor == 2
          && F.out.hnd.svn == 2 && F.out.chain_slot == 1 && !F.out.trial);
    check("journal: slot B active and GOOD, trial cleared",
          fx_journal(&F, &j) == 0 && j.active == 1 && j.status[1] == SLOT_GOOD && j.trial_state == TRIAL_NONE
          && fx_floor(&F, &floor) == 0 && floor == 2);
    check("COMMITTED receipt verifies", last_receipt(&r) == 0 && r.outcome == RCP_COMMITTED && r.reason == 0
          && r.from_svn == 1 && r.to_svn == 2 && r.floor_before == 1 && r.floor_after == 2);
    check("mailbox erased after the commit boot",
          rot_all_byte(F.fm.mem + ROT_DATA_SECTOR_OFF(ROT_SECTOR_MBX1), 64, 0xFF));

    /* v1.2: BPM doubles, health fails */
    check("v1.2 installs into slot A and starts a trial",
          do_install_ok(v3, v3_len, 3, "1.2.0") == 0 && F.out.trial && F.out.chain_slot == 0);
    settle_health(3, 1440, 1);
    check("doubled BPM rolls back to v1.1", fx_boot(&F) == 0 && F.out.chain_slot == 1 && F.out.hnd.svn == 2
          && F.out.hnd.floor == 2 && !F.out.trial);
    check("ROLLED_BACK receipt names the BPM failure", last_receipt(&r) == 0 && r.outcome == RCP_ROLLED_BACK
          && r.reason == RCP_REASON_HEALTH_FAIL_BPM && r.to_svn == 3 && r.floor_after == 2);
    check("slot A is REJECTED, floor stays 2", fx_journal(&F, &j) == 0 && j.status[0] == SLOT_REJECTED
          && j.active == 1 && fx_floor(&F, &floor) == 0 && floor == 2);

    /* receipt chain over the three receipts so far (seq 1 commit, 2 rollback) */
    {
        uint8_t objs[2][RCP_TOTAL_BYTES];
        check("receipts 1 and 2 form a valid chain",
              fx_receipt(&F, 1, objs[0], &r) == 0 && fx_receipt(&F, 2, objs[1], &r) == 0
              && rcp_verify_chain(&objs[0][0], 2, F.dev_pk_dsa, zero32) == 0);
    }

    /* other health failures, each from a fresh trial of v1.2 */
    struct { const char *name; uint8_t part; uint8_t ok; uint16_t live; uint16_t bpm; uint64_t svn; int reason; } cases[] = {
        { "wrong sensor part id", 0x11, 1, 100, BPM_OK, 3, RCP_REASON_HEALTH_FAIL_SENSOR },
        { "sensor not ok",        0x15, 0, 100, BPM_OK, 3, RCP_REASON_HEALTH_FAIL_SENSOR },
        { "too few live samples", 0x15, 1, 10,  BPM_OK, 3, RCP_REASON_HEALTH_FAIL_SENSOR },
        { "report for another svn", 0x15, 1, 100, BPM_OK, 9, RCP_REASON_HEALTH_SVN_MISMATCH },
        { "BPM just outside tolerance", 0x15, 1, 100, BPM_OK + 31, 3, RCP_REASON_HEALTH_FAIL_BPM },
    };
    for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        char nm[96];
        snprintf(nm, sizeof nm, "trial fails: %s", cases[i].name);
        do_install(v3, v3_len, 3, "1.2.0", F.device_id, F.dev_pk_kem, F.vendor_sk, 10 + (int)i, n);
        fx_mbx_health(&F, cases[i].svn, cases[i].bpm, SPO2_OK, cases[i].part, cases[i].ok, cases[i].live);
        fx_boot(&F);
        check(nm, last_receipt(&r) == 0 && r.outcome == RCP_ROLLED_BACK && r.reason == cases[i].reason
              && F.out.chain_slot == 1 && F.out.hnd.floor == 2);
    }
    {
        do_install(v3, v3_len, 3, "1.2.0", F.device_id, F.dev_pk_kem, F.vendor_sk, 30, n);
        fx_mbx_health(&F, 3, BPM_OK + 30, SPO2_OK + 20, 0x15, 1, 100);
        fx_boot(&F);
        check("trial passes exactly at both tolerances (commit to svn 3)",
              last_receipt(&r) == 0 && r.outcome == RCP_COMMITTED && F.out.hnd.floor == 3);
    }
}

static void test_refusals(void)
{
    /* state on entry: v1.2 committed in slot A (floor 3); slot B holds v1.1 */
    rot_journal_t j;
    rcp_t r;
    uint64_t floor, hash_a, hash_b;
    uint8_t n[32];
    size_t pl;

    fx_floor(&F, &floor);
    check("entry state: floor 3, slot A active", floor == 3 && (fx_journal(&F, &j), j.active == 0));
    {
        /* a new image that would be svn 4 for the refusal cases */
        static uint8_t v4[IMG_CAP];
        size_t v4_len = fx_image(&F, v4, sizeof v4, 4, "1.3.0", BPM_OK, SPO2_OK, 7100, F.vendor_sk);
        hash_a = slot_hash_first(0);
        hash_b = slot_hash_first(1);

        /* A1: one byte flipped in transit */
        {
            uint8_t vn[32], rn[32];
            nonce_of(vn, 40);
            fx_attest(&F, vn, rn);
            pl = fx_package(&F, pkg, sizeof pkg, v4, v4_len, F.device_id, rn, 4, "1.3.0", F.dev_pk_kem, F.vendor_sk);
            pkg[DLV_PREFIX_BYTES + 500] ^= 0x01;
            fx_stage_and_request(&F, pkg, pl);
            fx_boot(&F);
            check("A1 tampered package: REFUSED, digest",
                  last_receipt(&r) == 0 && r.outcome == RCP_REFUSED && r.reason == RCP_REASON_PKG_AUTH_FAILED);
            check("A1: nothing erased or written, nonce still outstanding",
                  slot_hash_first(1) == hash_b && fx_journal(&F, &j) == 0 && j.nonce_state == NONCE_OUTSTANDING
                  && F.out.chain_slot == 0);

            /* A2: forged vendor, current nonce */
            pl = fx_package(&F, pkg, sizeof pkg, v4, v4_len, F.device_id, rn, 4, "1.3.0", F.dev_pk_kem, F.other_sk);
            fx_stage_and_request(&F, pkg, pl);
            fx_boot(&F);
            check("A2 forged vendor: REFUSED, unknown signer",
                  last_receipt(&r) == 0 && r.outcome == RCP_REFUSED && r.reason == RCP_REASON_PKG_UNKNOWN_SIGNER);

            /* A3: genuine vendor, downgrade to svn 1 (below floor 3) */
            pl = fx_package(&F, pkg, sizeof pkg, v1, v1_len, F.device_id, rn, 1, "1.0.0", F.dev_pk_kem, F.vendor_sk);
            fx_stage_and_request(&F, pkg, pl);
            fx_boot(&F);
            check("A3 downgrade: REFUSED, SVN below floor",
                  last_receipt(&r) == 0 && r.outcome == RCP_REFUSED && r.reason == RCP_REASON_PKG_BELOW_FLOOR
                  && r.to_svn == 1 && r.floor_before == 3);
            check("A3: refused before decapsulation (nonce kept, slots untouched)",
                  fx_journal(&F, &j) == 0 && j.nonce_state == NONCE_OUTSTANDING
                  && slot_hash_first(0) == hash_a && slot_hash_first(1) == hash_b);

            /* A5: package for another device */
            pl = fx_package(&F, pkg, sizeof pkg, v4, v4_len, F.device_id + 1, rn, 4, "1.3.0", F.dev_pk_kem, F.vendor_sk);
            fx_stage_and_request(&F, pkg, pl);
            fx_boot(&F);
            check("A5 other device id: REFUSED, not for this device",
                  last_receipt(&r) == 0 && r.outcome == RCP_REFUSED && r.reason == RCP_REASON_PKG_WRONG_DEVICE);

            /* A5b: right device id, encrypted to another device's KEM key */
            {
                static uint8_t other_pk[ROT_KEM_PK], other_sk[ROT_KEM_SK];
                uint8_t seed[64];
                for (int i = 0; i < 64; i++) seed[i] = (uint8_t)(0xA0 + i);
                PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(other_pk, other_sk, seed);
                pl = fx_package(&F, pkg, sizeof pkg, v4, v4_len, F.device_id, rn, 4, "1.3.0", other_pk, F.vendor_sk);
                fx_stage_and_request(&F, pkg, pl);
                fx_boot(&F);
                check("A5b encrypted to another KEM key: REFUSED, MAC failed",
                      last_receipt(&r) == 0 && r.outcome == RCP_REFUSED && r.reason == RCP_REASON_PKG_MAC_FAILED);
                check("A5b: nonce is not consumed by a failed MAC",
                      fx_journal(&F, &j) == 0 && j.nonce_state == NONCE_OUTSTANDING && slot_hash_first(1) == hash_b);
            }

            /* inner image signed by someone else: passes U7-U13, fails U15 */
            {
                static uint8_t bad[IMG_CAP];
                size_t bl = fx_image(&F, bad, sizeof bad, 4, "1.3.0", BPM_OK, SPO2_OK, 7100, F.other_sk);
                pl = fx_package(&F, pkg, sizeof pkg, bad, bl, F.device_id, rn, 4, "1.3.0", F.dev_pk_kem, F.vendor_sk);
                fx_stage_and_request(&F, pkg, pl);
                fx_boot(&F);
                check("inner image with a foreign signature: REFUSED, bad signature",
                      last_receipt(&r) == 0 && r.outcome == RCP_REFUSED && r.reason == RCP_REASON_IMG_BAD_SIGNATURE);
                check("the failed target slot is wiped; the nonce is spent; the device keeps running",
                      rot_all_byte(F.fm.mem + ROT_SLOT_OFF(1), 4096, 0xFF) && fx_journal(&F, &j) == 0
                      && j.nonce_state == NONCE_NONE && j.status[1] == SLOT_EMPTY && F.out.chain_slot == 0);
            }
        }

        /* inner svn differs from the manifest svn */
        {
            uint8_t vn[32], rn[32];
            nonce_of(vn, 41);
            fx_attest(&F, vn, rn);
            pl = fx_package(&F, pkg, sizeof pkg, v4, v4_len, F.device_id, rn, 5, "1.3.0", F.dev_pk_kem, F.vendor_sk);
            fx_stage_and_request(&F, pkg, pl);
            fx_boot(&F);
            check("DLV svn 5 around an svn 4 image: REFUSED, svn mismatch",
                  last_receipt(&r) == 0 && r.outcome == RCP_REFUSED && r.reason == RCP_REASON_IMG_SVN_MISMATCH);
        }

        /* A4: replay of a genuine package after it was used */
        {
            uint8_t used_pkg[IMG_CAP * 2];
            size_t used_len;
            uint8_t vn[32], rn[32];
            nonce_of(vn, 42);
            fx_attest(&F, vn, rn);
            used_len = fx_package(&F, used_pkg, sizeof used_pkg, v4, v4_len, F.device_id, rn, 4, "1.3.0", F.dev_pk_kem, F.vendor_sk);
            fx_stage_and_request(&F, used_pkg, used_len);
            fx_boot(&F);
            check("genuine svn 4 package starts a trial", F.out.trial && F.out.chain_slot == 1);
            settle_health(4, BPM_OK, 1);
            fx_boot(&F);
            check("svn 4 committed, floor 4", F.out.hnd.floor == 4 && F.out.chain_slot == 1);
            fx_stage_and_request(&F, used_pkg, used_len);
            fx_boot(&F);
            check("A4 replay of the captured package: REFUSED, stale nonce",
                  last_receipt(&r) == 0 && r.outcome == RCP_REFUSED && r.reason == RCP_REASON_PKG_STALE_NONCE);
            check("A4: running image and floor unchanged", F.out.hnd.svn == 4 && F.out.hnd.floor == 4);
        }

        /* malformed mailbox claims */
        fx_mbx_install(&F, 10, 0);
        fx_boot(&F);
        check("install claim shorter than a manifest: REFUSED, malformed",
              last_receipt(&r) == 0 && r.outcome == RCP_REFUSED && r.reason == RCP_REASON_PKG_MALFORMED);
        fx_mbx_install(&F, 0xFFFFFFF0u, 0);
        fx_boot(&F);
        check("install claim larger than staging: REFUSED, malformed, no read outside staging",
              last_receipt(&r) == 0 && r.reason == RCP_REASON_PKG_MALFORMED);
        memset(F.fm.mem + ROT_REGION_STAGING_OFF, 0x5A, 4096);
        fx_mbx_install(&F, 4096, 0x12345678u);
        fx_boot(&F);
        check("install with a wrong CRC: REFUSED, malformed",
              last_receipt(&r) == 0 && r.reason == RCP_REASON_PKG_MALFORMED);
        {
            uint8_t rnd[4096];
            for (int i = 0; i < 4096; i++) rnd[i] = (uint8_t)(i * 2654435761u >> 11);
            memcpy(F.fm.mem + ROT_REGION_STAGING_OFF, rnd, 4096);
            fx_mbx_install(&F, 4096, rot_crc32(0, rnd, 4096));
            fx_boot(&F);
            check("random bytes with a valid CRC: REFUSED, malformed",
                  last_receipt(&r) == 0 && r.reason == RCP_REASON_PKG_MALFORMED && F.out.hnd.floor == 4);
        }
        (void)n;
    }

    /* A6: ciphertext only */
    {
        uint8_t vn[32], rn[32];
        static uint8_t v5[IMG_CAP];
        size_t l5 = fx_image(&F, v5, sizeof v5, 5, "1.4.0", BPM_OK, SPO2_OK, 7000, F.vendor_sk);
        nonce_of(vn, 43);
        fx_attest(&F, vn, rn);
        pl = fx_package(&F, pkg, sizeof pkg, v5, l5, F.device_id, rn, 5, "1.4.0", F.dev_pk_kem, F.vendor_sk);
        const uint8_t *ct = pkg + DLV_PREFIX_BYTES + 8 + 768 + 24 + 8;
        size_t ct_len = pl - DLV_PREFIX_BYTES - 8 - 768 - 24 - 8 - 32;
        unsigned hist[256] = { 0 };
        double h = 0;
        for (size_t i = 0; i < ct_len; i++) hist[ct[i]]++;
        for (int i = 0; i < 256; i++) {
            if (hist[i]) {
                double p = (double)hist[i] / (double)ct_len;
                h -= p * log2(p);
            }
        }
        printf("       ciphertext entropy %.3f bits/byte over %zu bytes\n", h, ct_len);
        check("A6 ciphertext entropy above 7.9 bits per byte", h > 7.9);
        check("A6 no plaintext version string or SBI1 magic in the package",
              memmem(pkg, pl, "1.4.0\0", 6) == NULL ? 1 : (memmem(pkg + DLV_PREFIX_BYTES, pl - DLV_PREFIX_BYTES, "1.4.0", 5) == NULL)
              && memmem(pkg + DLV_PREFIX_BYTES, pl - DLV_PREFIX_BYTES, "SBI1", 4) == NULL
              && memmem(pkg + DLV_PREFIX_BYTES, pl - DLV_PREFIX_BYTES, "APM1", 4) == NULL);
    }
}

int main(void)
{
    fx_init(&F, 4242);
    make_images();
    check("test images built", v1_len && v2_len && v3_len);

    test_enroll_and_boot();
    test_attest();
    test_update_flow();
    test_refusals();

    fx_free(&F);
    if (failures) {
        printf("test_rot_boot: FAIL (%d)\n", failures);
        return 1;
    }
    printf("test_rot_boot: PASS\n");
    return 0;
}
