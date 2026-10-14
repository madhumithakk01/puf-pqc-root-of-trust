#include "dsp/dsp.h"

#include <string.h>

static uint32_t isqrt32(uint64_t v)
{
    uint64_t r = 0, bit = 1ull << 62;
    while (bit > v) bit >>= 2;
    while (bit) {
        if (v >= r + bit) {
            v -= r + bit;
            r = (r >> 1) + bit;
        } else {
            r >>= 1;
        }
        bit >>= 2;
    }
    return (uint32_t)r;
}

void dsp_init(dsp_t *d, dsp_variant v)
{
    memset(d, 0, sizeof *d);
    d->variant = v;
}

static uint32_t median_rr(const dsp_t *d)
{
    uint32_t a[DSP_RR_HISTORY];
    unsigned n = d->rr_count;

    for (unsigned i = 0; i < n; i++) a[i] = d->rr[i];
    for (unsigned i = 1; i < n; i++) {
        uint32_t k = a[i];
        unsigned j = i;
        while (j > 0 && a[j - 1] > k) {
            a[j] = a[j - 1];
            j--;
        }
        a[j] = k;
    }
    return n ? a[n / 2] : 0;
}

/* One value at the detector's rate. */
static void detect(dsp_t *d, int32_t s)
{
    uint32_t refractory = d->variant == DSP_V12 ? DSP_REFRACTORY_MS * DSP_RATE_HZ / 2000u
                                                : DSP_REFRACTORY_MS * DSP_RATE_HZ / 1000u;
    int32_t thr;

    /* decaying amplitude estimate */
    if (s > d->peak_est) {
        d->peak_est = s;
    } else {
        d->peak_est -= d->peak_est / 512;
    }
    thr = d->peak_est / 2;

    /* local maximum at the previous sample */
    if (d->det_idx >= 2 && d->n > DSP_WARMUP && d->prev1 > d->prev2 && d->prev1 >= s && d->prev1 > thr
        && thr > 0) {
        uint32_t at = d->det_idx - 1;
        if (!d->have_peak || at - d->last_peak >= refractory) {
            if (d->have_peak) {
                uint32_t rr = at - d->last_peak;
                /* 0.3 s to 2.0 s at the real rate; v1.2 counts in decimated samples */
                uint32_t lo = refractory, hi = (d->variant == DSP_V12 ? 100u : 200u);
                if (rr >= lo && rr <= hi) {
                    d->rr[d->rr_head] = rr;
                    d->rr_head = (d->rr_head + 1) % DSP_RR_HISTORY;
                    if (d->rr_count < DSP_RR_HISTORY) d->rr_count++;
                    d->beats++;
                }
            }
            d->last_peak = at;
            d->have_peak = 1;
        }
    }
    d->prev2 = d->prev1;
    d->prev1 = s;
    d->det_idx++;
}

void dsp_push(dsp_t *d, uint32_t red, uint32_t ir)
{
    uint32_t slot = d->n % DSP_DC_WINDOW;
    uint32_t count = d->n < DSP_DC_WINDOW ? d->n + 1 : DSP_DC_WINDOW;
    int32_t x, s;

    /* DC removal: 1 s moving mean, then invert (a beat is a dip in the raw signal) */
    d->dc_sum += ir;
    if (d->n >= DSP_DC_WINDOW) d->dc_sum -= d->dc_ring[slot];
    d->dc_ring[slot] = ir;
    x = (int32_t)(d->dc_sum / count) - (int32_t)ir;

    /* 4-tap moving average */
    d->sm[3] = d->sm[2];
    d->sm[2] = d->sm[1];
    d->sm[1] = d->sm[0];
    d->sm[0] = x;
    s = (d->sm[0] + d->sm[1] + d->sm[2] + d->sm[3]) / 4;

    if (d->variant == DSP_V12) {
        /* 2:1 decimating smoother: one detector value per two samples */
        if (d->dec_phase == 0) {
            d->dec_hold = s;
            d->dec_phase = 1;
        } else {
            d->dec_phase = 0;
            detect(d, (d->dec_hold + s) / 2);
        }
    } else {
        detect(d, s);
    }

    if (d->variant != DSP_V10) {
        uint32_t i = d->n % DSP_AC_WINDOW;
        uint32_t dc_ir = (uint32_t)(d->dc_sum / count);
        uint32_t dc_red;

        d->red_dc_sum += red;
        if (d->n >= DSP_DC_WINDOW) d->red_dc_sum -= d->red_dc_ring[slot];
        d->red_dc_ring[slot] = red;
        dc_red = (uint32_t)(d->red_dc_sum / count);

        d->red_hp[i] = (int32_t)red - (int32_t)dc_red;
        d->ir_hp[i] = (int32_t)ir - (int32_t)dc_ir;
        if (d->ac_fill < DSP_AC_WINDOW) d->ac_fill++;
    }
    d->n++;
}

/* RMS of a DC-removed window. */
static uint32_t window_rms(const int32_t *hp, uint32_t n)
{
    uint64_t sq = 0;
    for (uint32_t i = 0; i < n; i++) sq += (uint64_t)((int64_t)hp[i] * hp[i]);
    return isqrt32(sq / n);
}

void dsp_result(const dsp_t *d, dsp_out *o)
{
    uint32_t rr = median_rr(d);

    memset(o, 0, sizeof *o);
    o->spo2_x10 = DSP_SPO2_NONE;
    o->beats = d->beats;

    if (d->rr_count >= 3 && rr) {
        /* 100 Hz is a constant here, on purpose: see the v1.2 note in dsp.h */
        o->bpm_x10 = (uint16_t)((60u * DSP_RATE_HZ * 10u + rr / 2u) / rr);
        o->mean_rr_ms = (uint16_t)(rr * 1000u / DSP_RATE_HZ);
    }

    if (d->variant == DSP_V10) {
        return;
    }

    if (o->bpm_x10) {
        if (o->bpm_x10 < 500u) o->alerts |= DSP_ALERT_HR_LOW;
        if (o->bpm_x10 > 1200u) o->alerts |= DSP_ALERT_HR_HIGH;
    }

    if (d->ac_fill >= DSP_AC_WINDOW) {
        uint32_t count = d->n < DSP_DC_WINDOW ? d->n : DSP_DC_WINDOW;
        uint32_t dc_i = (uint32_t)(d->dc_sum / count);
        uint32_t dc_r = (uint32_t)(d->red_dc_sum / count);
        uint32_t ac_r = window_rms(d->red_hp, DSP_AC_WINDOW);
        uint32_t ac_i = window_rms(d->ir_hp, DSP_AC_WINDOW);

        if (dc_r && dc_i && ac_i) {
            /* R = (AC_red / DC_red) / (AC_ir / DC_ir), scaled by 1000 */
            uint64_t r1000 = ((uint64_t)ac_r * dc_i * 1000u) / ((uint64_t)dc_r * ac_i);
            int64_t s10 = 1100 - (int64_t)(250u * r1000) / 1000;
            if (s10 < 0) s10 = 0;
            if (s10 > 1000) s10 = 1000;
            o->spo2_x10 = (uint16_t)s10;
            if (s10 < 920) o->alerts |= DSP_ALERT_SPO2_LOW;
        }

        /* quality: perfusion index and RR regularity */
        {
            /* perfusion index in 0.01 %, from the RMS (peak to peak is about 3 x RMS) */
            uint32_t pi_x100 = dc_i ? (uint32_t)(((uint64_t)ac_i * 3u * 10000u) / dc_i) : 0;
            uint32_t score_pi = pi_x100 / 2u > 100u ? 100u : pi_x100 / 2u;
            uint32_t score_rr = 0;

            if (d->rr_count >= 3 && rr) {
                uint64_t sum = 0, sq = 0;
                uint32_t mean, sd, cv_x10;
                for (unsigned i = 0; i < d->rr_count; i++) sum += d->rr[i];
                mean = (uint32_t)(sum / d->rr_count);
                for (unsigned i = 0; i < d->rr_count; i++) {
                    int64_t e = (int64_t)d->rr[i] - mean;
                    sq += (uint64_t)(e * e);
                }
                sd = isqrt32(sq / d->rr_count);
                cv_x10 = mean ? (sd * 1000u) / mean : 1000u; /* cv in 0.1 % */
                score_rr = cv_x10 >= 200u ? 0u : 100u - cv_x10 / 2u;
            }
            o->quality = (uint8_t)((score_pi + score_rr) / 2u);
        }
    }
}
