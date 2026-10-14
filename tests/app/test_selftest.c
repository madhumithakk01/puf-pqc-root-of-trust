/*
 * Health self-test: the HEV1 it produces is judged by the RoT's own rule
 * against a manifest built from the v1.1 result. v1.1 passes; the v1.2
 * regression fails on the rate; a missing, wrong or silent sensor fails on
 * the sensor check, with no finger needed.
 */

#include "fake_i2c.h"

#include "health/selftest.h"
#include "rot/rot_hev.h"
#include "rot/rot_receipt.h"
#include "rot/rot_trial.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

static void check(const char *name, int ok)
{
    printf("  %s %s\n", ok ? "ok  " : "FAIL", name);
    if (!ok) failures++;
}

typedef struct {
    fake_t bus;
    uint32_t now;
    int stream;          /* push 100 sps while time passes */
} env_t;

static uint32_t now_ms(void *c) { return ((env_t *)c)->now; }

static void delay_ms(void *c, unsigned ms)
{
    env_t *e = c;
    for (unsigned i = 0; i < ms; i++) {
        e->now++;
        if (e->stream && e->now % 10 == 0) push(&e->bus, 90000 + e->now, 100000 + e->now);
    }
}

static int bus_write(void *c, uint8_t a, uint8_t r, const uint8_t *d, size_t n)
{
    return fk_write(&((env_t *)c)->bus, a, r, d, n);
}

static int bus_read(void *c, uint8_t a, uint8_t r, uint8_t *d, size_t n)
{
    return fk_read(&((env_t *)c)->bus, a, r, d, n);
}

static void bus_delay(void *c, unsigned ms)
{
    delay_ms(c, ms);
}

static rot_hev_t run(env_t *e, dsp_variant v, uint64_t svn, int with_sensor, selftest_result *res)
{
    static max30102 dev;
    max30102_bus bus = { e, bus_write, bus_read, bus_delay };
    selftest_env env = { with_sensor ? &dev : NULL, &bus, v, svn, e, now_ms, delay_ms, NULL };
    uint8_t hev[32];
    rot_hev_t h;

    e->now = 0;
    selftest_run(&env, res, hev);
    rot_hev_parse(hev, &h);
    return h;
}

static apm_t manifest_from(const rot_hev_t *golden)
{
    apm_t m;
    memset(&m, 0, sizeof m);
    m.flags = APM_FLAG_HAS_SPO2;
    m.golden_bpm_x10 = golden->golden_bpm_x10;
    m.tol_bpm_x10 = 30;
    m.golden_spo2_x10 = golden->golden_spo2_x10;
    m.tol_spo2_x10 = 20;
    m.min_live_samples = 50;
    m.trial_deadline_ms = 15000;
    return m;
}

int main(void)
{
    static env_t e;
    selftest_result r;
    rot_hev_t good, h;
    apm_t apm;

    fake_reset(&e.bus);
    e.stream = 1;
    good = run(&e, DSP_V11, 2, 1, &r);
    printf("       v1.1 self-test: %u.%u bpm, SpO2 %u.%u, %u live samples, %u ms\n",
           good.golden_bpm_x10 / 10, good.golden_bpm_x10 % 10, good.golden_spo2_x10 / 10,
           good.golden_spo2_x10 % 10, good.live_samples, good.selftest_ms);
    check("HEV1 carries the svn and the sensor facts", good.svn == 2 && good.part_id == 0x15
          && good.sensor_ok == 1 && good.live_samples >= 90 && good.live_samples <= 110);
    check("the 1 s probe takes about a second", good.selftest_ms >= 1000 && good.selftest_ms < 1100);
    check("the app verdict is positive", good.verdict == 1);

    apm = manifest_from(&good);
    check("RoT judge: v1.1 passes its own manifest", rot_trial_judge(&good, 2, &apm) == 0);
    check("RoT judge: a report for another svn is refused", rot_trial_judge(&good, 3, &apm) == RCP_REASON_HEALTH_SVN_MISMATCH);

    fake_reset(&e.bus);
    h = run(&e, DSP_V12, 3, 1, &r);
    printf("       v1.2 self-test: %u.%u bpm\n", h.golden_bpm_x10 / 10, h.golden_bpm_x10 % 10);
    check("RoT judge: v1.2 fails on the rate", rot_trial_judge(&h, 3, &apm) == 0 ? 0 : 1);
    {
        rot_hev_t same_svn = h;
        same_svn.svn = 2;
        check("RoT judge: v1.2 evidence is rejected as FAIL_BPM", rot_trial_judge(&same_svn, 2, &apm) == RCP_REASON_HEALTH_FAIL_BPM);
    }

    fake_reset(&e.bus);
    h = run(&e, DSP_V11, 2, 0, &r);
    check("no sensor attached: sensor_ok 0, part id 0", h.sensor_ok == 0 && h.part_id == 0);
    check("RoT judge: no sensor fails the sensor check", rot_trial_judge(&h, 2, &apm) == RCP_REASON_HEALTH_FAIL_SENSOR);

    fake_reset(&e.bus);
    e.bus.regs[MAX30102_REG_PART_ID] = 0x11;
    h = run(&e, DSP_V11, 2, 1, &r);
    check("wrong part: its id is reported, sensor not ok", h.part_id == 0x11 && h.sensor_ok == 0);
    check("RoT judge: wrong part fails the sensor check", rot_trial_judge(&h, 2, &apm) == RCP_REASON_HEALTH_FAIL_SENSOR);

    fake_reset(&e.bus);
    e.stream = 1;
    e.bus.fail_first = 1;
    h = run(&e, DSP_V11, 2, 1, &r);
    check("one failed probe attempt is retried and the sensor then passes", h.sensor_ok == 1 && h.live_samples > 0);

    fake_reset(&e.bus);
    e.stream = 1;
    e.bus.fail_first = 1000;
    h = run(&e, DSP_V11, 2, 1, &r);
    check("a sensor that never initialises still fails after the retries", h.sensor_ok == 0 && h.live_samples == 0);
    check("RoT judge: that update is rolled back on the sensor check", rot_trial_judge(&h, 2, &apm) == RCP_REASON_HEALTH_FAIL_SENSOR);

    fake_reset(&e.bus);
    e.stream = 0;
    h = run(&e, DSP_V11, 2, 1, &r);
    check("sensor present but silent: no live samples", h.part_id == 0x15 && h.live_samples == 0 && h.sensor_ok == 0);
    check("RoT judge: a silent sensor fails the sensor check", rot_trial_judge(&h, 2, &apm) == RCP_REASON_HEALTH_FAIL_SENSOR);

    {
        uint8_t a[32], b[32];
        selftest_env env;
        max30102_bus bus = { &e, bus_write, bus_read, bus_delay };
        selftest_result r2;
        memset(&env, 0, sizeof env);
        env.bus = &bus; env.variant = DSP_V10; env.svn = 1; env.ctx = &e; env.now_ms = now_ms; env.delay_ms = delay_ms;
        e.now = 0; selftest_run(&env, &r2, a);
        e.now = 0; selftest_run(&env, &r2, b);
        check("without a sensor the golden result is repeatable", memcmp(a, b, 32) == 0);
    }

    if (failures) {
        printf("test_selftest: FAIL (%d)\n", failures);
        return 1;
    }
    printf("test_selftest: PASS\n");
    return 0;
}
