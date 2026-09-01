/*
 * Tests for the rollback counter.
 *
 * KATs (page bytes and tags) were produced independently in Python over the
 * same layout and MAC. The integration case drives the real key path:
 * simulated PUF -> fuzzy extractor -> KDF("rollback-auth-key") -> counter.
 */

#include "rollback/rollback.h"
#include "kdf/kdf.h"
#include "puf/puf_sim.h"
#include "fuzzy/fuzzy_extractor.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

static void to_hex(char *dst, const uint8_t *b, size_t n)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        dst[2 * i]     = d[b[i] >> 4];
        dst[2 * i + 1] = d[b[i] & 0x0f];
    }
    dst[2 * n] = '\0';
}

static void expect_hex(const char *name, const uint8_t *got, size_t n,
                       const char *want)
{
    char buf[2 * 64 + 1];
    to_hex(buf, got, n);
    if (strcmp(buf, want) != 0) {
        printf("  FAIL %s\n    want %s\n    got  %s\n", name, want, buf);
        failures++;
    } else {
        printf("  ok   %s\n", name);
    }
}

static void check(const char *name, int ok)
{
    if (ok) {
        printf("  ok   %s\n", name);
    } else {
        printf("  FAIL %s\n", name);
        failures++;
    }
}

int main(void)
{
    uint8_t key[32];
    for (int i = 0; i < 32; i++) {
        key[i] = (uint8_t)i;
    }
    rollback_store s;
    uint64_t c;

    /* 1. Enrolment KAT. */
    check("enroll ok", rollback_enroll(&s, key, 0) == ROLLBACK_OK);
    expect_hex("enrolled page 0", s.page[0], 64,
               "52424331010000000000000000000000ef1b64dbbb2b19b9008f1ac917c2358ffb812ea70c8b09da677de4108cdf4e5b00000000000000000000000000000000");
    check("read enrolled counter == 0",
          rollback_read(&s, key, &c) == ROLLBACK_OK && c == 0);

    /* 2. Update and read. */
    check("update 0 -> 5", rollback_update(&s, key, 5, 0) == ROLLBACK_OK);
    check("read == 5", rollback_read(&s, key, &c) == ROLLBACK_OK && c == 5);
    expect_hex("page 1 after update", s.page[1], 64,
               "524243310200000005000000000000002b2b80d2c3005ec85dd38ca9636f28d436a2ea157caa608607afde9199765b0200000000000000000000000000000000");

    /* 3. Monotonicity. */
    check("update 5 -> 5 refused", rollback_update(&s, key, 5, 0) == ROLLBACK_ERR_MONOTONIC);
    check("update 5 -> 3 refused", rollback_update(&s, key, 3, 0) == ROLLBACK_ERR_MONOTONIC);
    check("update 5 -> 6 ok", rollback_update(&s, key, 6, 0) == ROLLBACK_OK);
    check("read == 6", rollback_read(&s, key, &c) == ROLLBACK_OK && c == 6);

    /* 4. Tamper with cnt on the newest page -> rejected, falls back. */
    {
        rollback_store t;
        rollback_enroll(&t, key, 0);
        rollback_update(&t, key, 5, 0);            /* page1 newest, cnt=5 */
        t.page[1][8] ^= 0x01;                      /* flip a bit of cnt */
        check("read ignores tampered page (falls back to 0)",
              rollback_read(&t, key, &c) == ROLLBACK_OK && c == 0);
        unsigned bad = 0;
        check("verify reports tamper on page 1",
              rollback_verify(&t, key, &c, &bad) == ROLLBACK_ERR_TAMPER &&
              bad == 0x2 && c == 0);
    }

    /* 5. Tamper with the tag -> same. */
    {
        rollback_store t;
        rollback_enroll(&t, key, 0);
        rollback_update(&t, key, 5, 0);
        t.page[1][16] ^= 0x80;                     /* flip a bit of tag */
        check("tag tamper rejected, falls back",
              rollback_read(&t, key, &c) == ROLLBACK_OK && c == 0);
    }

    /* 6. Both pages corrupted -> no valid page (boot must refuse). */
    {
        rollback_store t;
        rollback_enroll(&t, key, 0);
        rollback_update(&t, key, 5, 0);
        t.page[0][20] ^= 0x01;
        t.page[1][20] ^= 0x01;
        unsigned bad = 0;
        check("read -> NO_VALID_PAGE", rollback_read(&t, key, &c) == ROLLBACK_ERR_NO_VALID_PAGE);
        check("verify -> TAMPER, both pages flagged",
              rollback_verify(&t, key, &c, &bad) == ROLLBACK_ERR_TAMPER && bad == 0x3);
    }

    /* 7. Forgery without the key. */
    {
        rollback_store t;
        rollback_enroll(&t, key, 0);
        rollback_update(&t, key, 5, 0);            /* page1 valid, cnt=5 */
        /* attacker overwrites page0 with cnt=999, tag under a wrong key */
        uint8_t wrong[32];
        memset(wrong, 0xAA, sizeof wrong);
        rollback_store forge;
        rollback_enroll(&forge, wrong, 999);      /* borrow marshal via a wrong-key enroll */
        /* bump its seq to 3 so it would "win" if accepted */
        forge.page[0][4] = 3;
        {
            /* recompute the wrong-key tag over the edited record */
            uint8_t msg[15 + 16];
            memcpy(msg, "rollback/v1/tag", 15);
            memcpy(msg + 15, forge.page[0], 16);
            rot_kdf_derive(wrong, 32, msg, sizeof msg, forge.page[0] + 16, 32);
        }
        memcpy(t.page[0], forge.page[0], 64);
        check("forged page rejected; real key still reads 5",
              rollback_read(&t, key, &c) == ROLLBACK_OK && c == 5);
    }

    /* 8. Power loss mid-update: never bricked; always the old or the new
     *    counter, authentic. The authenticated record is bytes [0:48); a write
     *    cut before that durably keeps the old value, at/after it the new one. */
    {
        static const size_t faults[] = { 1, 4, 8, 16, 20, 32, 40, 47, 48, 56, 63 };
        int all_ok = 1;
        for (size_t i = 0; i < sizeof faults / sizeof faults[0]; i++) {
            rollback_store t;
            rollback_enroll(&t, key, 0);
            rollback_update(&t, key, 5, 0);        /* good state: cnt=5 */
            int rc = rollback_update(&t, key, 9, faults[i]);
            uint64_t rc_cnt = 123;
            int rr = rollback_read(&t, key, &rc_cnt);
            uint64_t want = faults[i] < 48 ? 5u : 9u;
            if (rc != ROLLBACK_ERR_WRITE_INTERRUPTED ||
                rr != ROLLBACK_OK || rc_cnt != want) {
                printf("       fault@%zu: rc=%d read=%d cnt=%llu want=%llu\n",
                       faults[i], rc, rr, (unsigned long long)rc_cnt,
                       (unsigned long long)want);
                all_ok = 0;
            }
        }
        check("interrupted update: never bricked, always old-or-new counter", all_ok);
    }

    /* 9. Recovery proceeds after a torn write. */
    {
        rollback_store t;
        rollback_enroll(&t, key, 0);
        rollback_update(&t, key, 5, 0);
        rollback_update(&t, key, 9, 20);           /* interrupted */
        check("post-fault: retry 9 completes",
              rollback_update(&t, key, 9, 0) == ROLLBACK_OK);
        check("post-fault: read == 9", rollback_read(&t, key, &c) == ROLLBACK_OK && c == 9);
        check("post-fault: update 9 -> 10", rollback_update(&t, key, 10, 0) == ROLLBACK_OK);
        check("post-fault: read == 10", rollback_read(&t, key, &c) == ROLLBACK_OK && c == 10);
    }

    /* 10. A/B alternation over a run of updates. */
    {
        rollback_store t;
        rollback_enroll(&t, key, 0);
        int ok = 1;
        for (uint64_t v = 1; v <= 8; v++) {
            if (rollback_update(&t, key, v, 0) != ROLLBACK_OK) ok = 0;
            uint64_t rv;
            if (rollback_read(&t, key, &rv) != ROLLBACK_OK || rv != v) ok = 0;
        }
        check("8 sequential updates all read back", ok);
    }

    /* 11. Re-enrol under a different key invalidates the old one. */
    {
        rollback_store t;
        rollback_enroll(&t, key, 0);
        rollback_update(&t, key, 5, 0);
        uint8_t key2[32];
        memset(key2, 0x11, sizeof key2);
        rollback_enroll(&t, key2, 0);
        check("old key can no longer read", rollback_read(&t, key, &c) == ROLLBACK_ERR_NO_VALID_PAGE);
        check("new key reads 0", rollback_read(&t, key2, &c) == ROLLBACK_OK && c == 0);
    }

    /* 12. Integration: simulated PUF -> fuzzy extractor -> KDF -> counter key. */
    {
        const fuzzy_params fp = { .blocks = 128, .rep = 15 };
        const size_t nb = fuzzy_response_bytes(fp); /* 240 */
        uint8_t w[FUZZY_MAX_RESPONSE_BYTES], helper[FUZZY_MAX_RESPONSE_BYTES];
        uint8_t rnd[16], R[32], rbkey[32];
        for (int i = 0; i < 16; i++) rnd[i] = (uint8_t)i;

        puf_sim_response(3, w, nb);
        fuzzy_gen(fp, w, nb, rnd, sizeof rnd, helper, nb, R, sizeof R);
        rot_kdf_derive(R, 32, (const uint8_t *)"rollback-auth-key", 17, rbkey, 32);
        expect_hex("KDF(fuzzy key, \"rollback-auth-key\")", rbkey, 32,
                   "f0c3586bf65b911952c1c33e70ee623e9f678fb4dba1c3804a46fa63c229263b");

        rollback_store t;
        rollback_enroll(&t, rbkey, 0);
        expect_hex("enrolled tag under the derived key", t.page[0] + 16, 32,
                   "ccb332ebbb04624e8bb5dff387ee2168457bd08999a87a54fde702d7d752ef56");
        rollback_update(&t, rbkey, 7, 0);

        /* reboot: reconstruct the key from a noisy PUF read */
        uint8_t wn[FUZZY_MAX_RESPONSE_BYTES], R2[32], rbkey2[32];
        uint8_t seed[4] = { 1, 0, 0, 0 };
        puf_sim_response_noisy(3, 30000u /* 3% */, seed, sizeof seed, wn, nb);
        check("fuzzy_rep ok", fuzzy_rep(fp, wn, nb, helper, nb, R2, sizeof R2) == 0);
        rot_kdf_derive(R2, 32, (const uint8_t *)"rollback-auth-key", 17, rbkey2, 32);
        check("key reconstructed from noisy PUF matches", memcmp(rbkey, rbkey2, 32) == 0);
        check("counter authenticates under the reconstructed key",
              rollback_read(&t, rbkey2, &c) == ROLLBACK_OK && c == 7);
    }

    if (failures) {
        printf("test_rollback: FAIL (%d)\n", failures);
        return 1;
    }
    printf("test_rollback: PASS\n");
    return 0;
}
