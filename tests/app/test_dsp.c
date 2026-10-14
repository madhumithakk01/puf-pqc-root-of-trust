/*
 * DSP tests: the golden trace gives the expected rate on v1.0 and v1.1 and
 * a doubled rate on the v1.2 regression, and synthetic traces exercise
 * alerts, quality, flat input and a drifting baseline.
 */

#include "dsp/dsp.h"
#include "golden/golden_trace.h"

#include <math.h>
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

static dsp_out run_golden(dsp_variant v)
{
    dsp_t d;
    dsp_out o;
    dsp_init(&d, v);
    for (unsigned i = 0; i < GOLDEN_SAMPLES; i++) dsp_push(&d, golden_red[i], golden_ir[i]);
    dsp_result(&d, &o);
    return o;
}

static unsigned absd(unsigned a, unsigned b) { return a > b ? a - b : b - a; }

static double pulse(double phase)
{
    return exp(-pow((phase - 0.20) / 0.07, 2)) + 0.35 * exp(-pow((phase - 0.52) / 0.10, 2));
}

/* synthetic trace: bpm, spo2, perfusion, noise sigma, wander amplitude */
static dsp_out run_synth(dsp_variant v, double bpm, double spo2, double pi, double noise,
                         double wander, unsigned seconds, double jitter)
{
    dsp_t d;
    dsp_out o;
    double period = 100.0 * 60.0 / bpm;
    double dc_ir = 100000, dc_red = 90000;
    double r = (110.0 - spo2) / 25.0;
    double a_ir = dc_ir * pi, a_red = dc_red * pi * r;
    unsigned n_samples = 100 * seconds;
    double next_beat = 0, phase_start = 0;
    unsigned s = 12345;

    dsp_init(&d, v);
    for (unsigned n = 0; n < n_samples; n++) {
        double p, g1, g2, ir, red;
        if ((double)n >= next_beat) {
            phase_start = next_beat;
            s = s * 1103515245u + 12345u;
            next_beat += period * (1.0 + jitter * (((double)((s >> 16) & 0x7FFF) / 32767.0) - 0.5));
        }
        p = pulse(((double)n - phase_start) / period);
        s = s * 1103515245u + 12345u;
        g1 = ((double)((s >> 16) & 0x7FFF) / 32767.0 - 0.5) * 2.0 * noise;
        s = s * 1103515245u + 12345u;
        g2 = ((double)((s >> 16) & 0x7FFF) / 32767.0 - 0.5) * 2.0 * noise;
        ir = dc_ir + wander * sin(2 * 3.14159265358979323846 * 0.2 * n / 100.0) - a_ir * p + g1;
        red = dc_red + 0.9 * wander * sin(2 * 3.14159265358979323846 * 0.2 * n / 100.0) - a_red * p + g2;
        dsp_push(&d, (uint32_t)red, (uint32_t)ir);
    }
    dsp_result(&d, &o);
    return o;
}

int main(void)
{
    dsp_out o10 = run_golden(DSP_V10), o11 = run_golden(DSP_V11), o12 = run_golden(DSP_V12);

    printf("       golden beats: v1.0 %u, v1.2 %u\n", o10.beats, o12.beats);
    printf("       golden: v1.0 %u.%u bpm | v1.1 %u.%u bpm, SpO2 %u.%u, quality %u | v1.2 %u.%u bpm\n",
           o10.bpm_x10 / 10, o10.bpm_x10 % 10, o11.bpm_x10 / 10, o11.bpm_x10 % 10,
           o11.spo2_x10 / 10, o11.spo2_x10 % 10, o11.quality, o12.bpm_x10 / 10, o12.bpm_x10 % 10);

    check("v1.0 golden rate within 3 bpm of 72", absd(o10.bpm_x10, 720) <= 30);
    /* 72 bpm for 10 s is 12 beats; detection starts after the 2 s warm-up and the
       first peak only starts the interval, so 8 to 10 intervals are counted */
    check("v1.0 counts 8 to 10 beat intervals in 10 s", o10.beats >= 8 && o10.beats <= 10);
    check("v1.0 mean RR about 833 ms", absd(o10.mean_rr_ms, 833) <= 30);
    check("v1.0 reports no SpO2, no alerts, no quality", o10.spo2_x10 == DSP_SPO2_NONE && o10.alerts == 0 && o10.quality == 0);
    check("v1.1 golden rate matches v1.0", absd(o11.bpm_x10, o10.bpm_x10) <= 5);
    check("v1.1 golden SpO2 within 2 % of 97.5", absd(o11.spo2_x10, 975) <= 20);
    check("v1.1 resting trace raises no alert", o11.alerts == 0);
    check("v1.1 quality is high on the clean trace", o11.quality >= 60);
    check("v1.2 reports about twice the rate (the regression)", absd(o12.bpm_x10, 2 * o10.bpm_x10) <= 60);
    check("v1.2 is far outside the 3 bpm tolerance", absd(o12.bpm_x10, 720) > 300);
    check("v1.2 still sees the SpO2 correctly", absd(o12.spo2_x10, 975) <= 20);

    {
        dsp_out a = run_golden(DSP_V11), b = run_golden(DSP_V11);
        check("deterministic: the same samples give identical results", memcmp(&a, &b, sizeof a) == 0);
    }

    for (int bpm = 50; bpm <= 120; bpm += 10) {
        dsp_out o = run_synth(DSP_V11, bpm, 97, 0.015, 25, 300, 20, 0.0);
        char nm[64];
        snprintf(nm, sizeof nm, "synthetic %d bpm within 3 bpm", bpm);
        check(nm, absd(o.bpm_x10, (unsigned)bpm * 10) <= 30);
    }
    {
        dsp_out o = run_synth(DSP_V11, 44, 97, 0.015, 25, 300, 20, 0.0);
        check("44 bpm raises the low-rate alert", (o.alerts & DSP_ALERT_HR_LOW) && !(o.alerts & DSP_ALERT_HR_HIGH));
    }
    {
        dsp_out o = run_synth(DSP_V11, 135, 97, 0.015, 25, 300, 20, 0.0);
        check("135 bpm raises the high-rate alert", (o.alerts & DSP_ALERT_HR_HIGH) != 0);
    }
    {
        dsp_out o = run_synth(DSP_V11, 72, 88, 0.015, 25, 300, 20, 0.0);
        check("SpO2 88 % is reported near 88 and raises the alert", absd(o.spo2_x10, 880) <= 30
              && (o.alerts & DSP_ALERT_SPO2_LOW));
    }
    {
        dsp_out o = run_synth(DSP_V11, 72, 97, 0.015, 25, 300, 20, 0.0);
        dsp_out noisy = run_synth(DSP_V11, 72, 97, 0.004, 400, 300, 20, 0.35);
        printf("       quality clean %u, poor %u\n", o.quality, noisy.quality);
        check("signal quality drops with noise, low perfusion and irregular beats", noisy.quality + 15 < o.quality);
    }
    {
        /* the 1 s mean passes about 60 % of a 0.2 Hz drift, so a drift of half the
           pulse amplitude is the design limit */
        dsp_out o = run_synth(DSP_V10, 72, 97, 0.015, 25, 750, 20, 0.0);
        check("baseline drift of half the pulse amplitude does not disturb the rate",
              absd(o.bpm_x10, 720) <= 30);
    }
    {
        dsp_t d;
        dsp_out o;
        dsp_init(&d, DSP_V11);
        for (int i = 0; i < 1500; i++) dsp_push(&d, 100000, 100000);
        dsp_result(&d, &o);
        check("a flat signal gives no heart rate and no beats", o.bpm_x10 == 0 && o.beats == 0);
    }
    {
        dsp_t d;
        dsp_out o;
        dsp_init(&d, DSP_V11);
        for (int i = 0; i < 150; i++) dsp_push(&d, 90000, 100000);
        dsp_result(&d, &o);
        check("too little data gives no SpO2", o.spo2_x10 == DSP_SPO2_NONE);
    }

    if (failures) {
        printf("test_dsp: FAIL (%d)\n", failures);
        return 1;
    }
    printf("test_dsp: PASS\n");
    return 0;
}
