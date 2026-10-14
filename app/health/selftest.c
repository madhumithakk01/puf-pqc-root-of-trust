#include "health/selftest.h"

#include "golden/golden_trace.h"
#include "rot/rot_hev.h"

#include <string.h>

#define LIVE_WINDOW_MS 1000u
#define POLL_MS        10u
#define PROBE_TRIES    3u
#define PROBE_GAP_MS   300u

void selftest_run(const selftest_env *env, selftest_result *res, uint8_t hev1[32])
{
    dsp_t d;
    rot_hev_t h;
    uint32_t t0 = env->now_ms(env->ctx);

    memset(res, 0, sizeof *res);

    /* 1. golden trace through the DSP */
    dsp_init(&d, env->variant);
    for (unsigned i = 0; i < GOLDEN_SAMPLES; i++) {
        dsp_push(&d, golden_red[i], golden_ir[i]);
    }
    dsp_result(&d, &res->golden);

    /* 2. sensor probe. A single failed attempt can be a bus glitch, so the probe is tried a few times;
       the sensor must still initialise and deliver samples for the verdict to pass. */
    int probe = MAX30102_ERR_BUS;
    for (unsigned try_n = 0; env->dev && env->bus && try_n < PROBE_TRIES; try_n++) {
        if (try_n) {
            env->delay_ms(env->ctx, PROBE_GAP_MS);
            if (env->bus_recover) env->bus_recover(env->ctx);
        }
        probe = max30102_init(env->dev, env->bus);
        if (probe == MAX30102_OK) break;
    }
    if (env->dev && env->bus && probe == MAX30102_OK) {
        uint32_t red[32], ir[32], start = env->now_ms(env->ctx);
        uint32_t live = 0;
        int n;

        res->part_id = env->dev->part_id;
        while (env->now_ms(env->ctx) - start < LIVE_WINDOW_MS) {
            n = max30102_read_fifo(env->dev, red, ir, 32);
            if (n < 0) {
                break;
            }
            live += (uint32_t)n;
            env->delay_ms(env->ctx, POLL_MS);
        }
        res->live_samples = (uint16_t)(live > 0xFFFFu ? 0xFFFFu : live);
        res->sensor_ok = res->live_samples > 0;
    } else if (env->dev && env->bus) {
        uint8_t id = 0;
        /* the part may answer even though configuration failed; report what it says */
        if (max30102_read_part_id(env->dev, &id) == 0) {
            res->part_id = id;
        }
    }

    res->elapsed_ms = (uint16_t)(env->now_ms(env->ctx) - t0);
    res->verdict = (res->golden.bpm_x10 != 0 && res->sensor_ok) ? 1 : 0;

    memset(&h, 0, sizeof h);
    h.svn = env->svn;
    h.golden_bpm_x10 = res->golden.bpm_x10;
    h.golden_spo2_x10 = res->golden.spo2_x10;
    h.beats = res->golden.beats;
    h.mean_rr_ms = res->golden.mean_rr_ms;
    h.part_id = res->part_id;
    h.sensor_ok = res->sensor_ok;
    h.live_samples = res->live_samples;
    h.selftest_ms = res->elapsed_ms;
    h.verdict = res->verdict;
    rot_hev_build(hev1, &h);
}
