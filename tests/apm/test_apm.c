/*
 * Tests for the APM1 app manifest: field offsets against the documented
 * layout, a round trip, and one case per refusal status including the order
 * in which they are reported.
 */

#include "apm/apm.h"

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

#define BIN_LEN 100u
#define TOTAL   (APM_BYTES + BIN_LEN)

static apm_t sample(void)
{
    apm_t m;
    memset(&m, 0, sizeof m);
    m.flags = APM_FLAG_HAS_SPO2;
    memcpy(m.version, "1.1.0", 5);
    m.svn = 2;
    m.app_bin_len = BIN_LEN;
    m.golden_bpm_x10 = 720;
    m.tol_bpm_x10 = 30;
    m.golden_spo2_x10 = 975;
    m.tol_spo2_x10 = 20;
    m.min_live_samples = 50;
    m.trial_deadline_ms = 15000;
    for (int i = 0; i < 32; i++) m.golden_digest[i] = (uint8_t)(0xA0 + i);
    for (int i = 0; i < 20; i++) m.build_id[i] = (uint8_t)(0x10 + i);
    return m;
}

/* A complete body: manifest followed by BIN_LEN bytes of "binary". */
static void make_body(uint8_t *body, const apm_t *m)
{
    apm_build(body, m);
    memset(body + APM_BYTES, 0x5A, m->app_bin_len);
}

static apm_status parse(const uint8_t *body, uint64_t svn)
{
    return apm_parse(body, TOTAL, svn, NULL);
}

int main(void)
{
    uint8_t *body = malloc(TOTAL);
    uint8_t *t = malloc(TOTAL);
    apm_t m = sample(), got;

    make_body(body, &m);

    check("magic at 0", memcmp(body, "APM1", 4) == 0);
    check("apm_version at 4", body[4] == 1 && body[5] == 0);
    check("flags at 6", body[6] == 1 && body[7] == 0);
    check("version string at 8", memcmp(body + 8, "1.1.0\0\0\0", 8) == 0);
    check("svn at 24", body[24] == 2 && body[25] == 0);
    check("app_bin_offset at 32 is 4072", body[32] == 0xE8 && body[33] == 0x0F);
    check("app_bin_len at 36", body[36] == BIN_LEN);
    check("golden_bpm_x10 at 40 (720)", body[40] == 0xD0 && body[41] == 0x02);
    check("trial_deadline_ms at 50 (15000)", body[50] == 0x98 && body[51] == 0x3A);
    check("golden digest at 56", body[56] == 0xA0 && body[87] == 0xBF);
    check("build id at 88", body[88] == 0x10 && body[107] == 0x23);
    check("zero fill from 108", body[108] == 0 && body[APM_BYTES - 1] == 0);

    check("valid manifest accepted", apm_parse(body, TOTAL, 2, &got) == APM_OK);
    check("round trip: fields", got.svn == 2 && got.app_bin_len == BIN_LEN
          && got.golden_bpm_x10 == 720 && got.tol_spo2_x10 == 20
          && got.min_live_samples == 50 && got.trial_deadline_ms == 15000);
    check("round trip: arrays", memcmp(got.golden_digest, m.golden_digest, 32) == 0
          && memcmp(got.build_id, m.build_id, 20) == 0
          && memcmp(got.version, m.version, APM_VERSION_STR_LEN) == 0);

    check("body shorter than manifest", apm_parse(body, APM_BYTES - 1, 2, NULL) == APM_E_SHORT);

    memcpy(t, body, TOTAL); t[0] = 'X';
    check("bad magic", parse(t, 2) == APM_E_MAGIC);

    memcpy(t, body, TOTAL); t[4] = 2;
    check("bad apm_version", parse(t, 2) == APM_E_VERSION);

    memcpy(t, body, TOTAL); t[32] ^= 1;
    check("bad app_bin_offset", parse(t, 2) == APM_E_OFFSET);

    memcpy(t, body, TOTAL); t[36] = BIN_LEN + 1;
    check("app_bin_len too long", parse(t, 2) == APM_E_LENGTH);
    memcpy(t, body, TOTAL); t[36] = BIN_LEN - 1;
    check("app_bin_len too short", parse(t, 2) == APM_E_LENGTH);
    memcpy(t, body, TOTAL); t[36] = t[37] = t[38] = t[39] = 0;
    check("app_bin_len zero", apm_parse(t, APM_BYTES, 2, NULL) == APM_E_LENGTH);

    check("svn differs from SBI1 fw_version", parse(body, 3) == APM_E_SVN);

    memcpy(t, body, TOTAL); t[7] = 0x80;
    check("unknown flag bit", parse(t, 2) == APM_E_FIELDS);
    memcpy(t, body, TOTAL); t[50] = t[51] = 0;
    check("zero deadline", parse(t, 2) == APM_E_FIELDS);
    memcpy(t, body, TOTAL); t[50] = 0x99; t[51] = 0x3A;
    check("deadline above 15000", parse(t, 2) == APM_E_FIELDS);
    memcpy(t, body, TOTAL); t[52] = 1;
    check("reserved nonzero", parse(t, 2) == APM_E_FIELDS);
    memcpy(t, body, TOTAL); t[APM_BYTES - 1] = 1;
    check("padding nonzero", parse(t, 2) == APM_E_FIELDS);
    memcpy(t, body, TOTAL); t[6] = 0;
    check("SpO2 value without HAS_SPO2", parse(t, 2) == APM_E_FIELDS);

    apm_t nosp = sample();
    nosp.flags = 0; nosp.golden_spo2_x10 = APM_SPO2_NONE; nosp.tol_spo2_x10 = 0;
    make_body(t, &nosp);
    check("no-SpO2 manifest accepted", parse(t, 2) == APM_OK);
    nosp.golden_spo2_x10 = 975;
    make_body(t, &nosp);
    check("HAS_SPO2 clear but value set", parse(t, 2) == APM_E_FIELDS);

    /* Order: magic, then offset, length, svn, fields. */
    memcpy(t, body, TOTAL); t[0] = 'X'; t[32] ^= 1; t[36]++; t[52] = 1;
    check("order: magic first", parse(t, 3) == APM_E_MAGIC);
    memcpy(t, body, TOTAL); t[32] ^= 1; t[36]++; t[52] = 1;
    check("order: offset before length", parse(t, 3) == APM_E_OFFSET);
    memcpy(t, body, TOTAL); t[36]++; t[52] = 1;
    check("order: length before svn", parse(t, 3) == APM_E_LENGTH);
    memcpy(t, body, TOTAL); t[52] = 1;
    check("order: svn before fields", parse(t, 3) == APM_E_SVN);

    free(body);
    free(t);
    if (failures) {
        printf("test_apm: FAIL (%d)\n", failures);
        return 1;
    }
    printf("test_apm: PASS\n");
    return 0;
}
