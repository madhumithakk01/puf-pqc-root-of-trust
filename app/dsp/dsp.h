#ifndef APP_DSP_H
#define APP_DSP_H

#include <stdint.h>

/*
 * Pulse-oximeter signal processing, integer arithmetic only (the target has
 * no FPU) and fully deterministic, so the board and the host produce the
 * same result on the same samples.
 *
 * Input is raw 18-bit ADC samples at 100 Hz, red and IR. A heartbeat shows
 * as a dip in the raw reflectance, so the signal is inverted after DC
 * removal.
 *
 *   v1.0  DC removal (1 s moving mean), 4-tap smoothing, adaptive-threshold
 *         peak detection with a 300 ms refractory period, heart rate from
 *         the median of the last five RR intervals.
 *   v1.1  adds SpO2 by ratio of ratios, SpO2 = 110 - 25 R (uncalibrated,
 *         demonstration only), alerts and a 0-100 signal quality.
 *   v1.2  v1.1 plus a 2:1 decimating smoother that halves the sample rate
 *         of the detector but leaves the 100 Hz constant in the RR to BPM
 *         conversion: a deliberate regression that reports twice the rate.
 */

#define DSP_RATE_HZ        100u
#define DSP_DC_WINDOW      100u
#define DSP_RR_HISTORY     5u
#define DSP_AC_WINDOW      400u
#define DSP_WARMUP         200u
#define DSP_REFRACTORY_MS  300u

#define DSP_SPO2_NONE      0xFFFFu

#define DSP_ALERT_HR_LOW   0x01u
#define DSP_ALERT_HR_HIGH  0x02u
#define DSP_ALERT_SPO2_LOW 0x04u

typedef enum { DSP_V10 = 0, DSP_V11 = 1, DSP_V12 = 2 } dsp_variant;

typedef struct {
    dsp_variant variant;
    uint32_t n;                         /* samples pushed */

    uint32_t dc_ring[DSP_DC_WINDOW];
    uint64_t dc_sum;

    int32_t  sm[4];                     /* smoothing taps */
    int32_t  prev1, prev2;              /* last two smoothed values */
    int32_t  peak_est;
    uint32_t det_idx;                   /* detector sample index */
    uint32_t last_peak;
    int      have_peak;
    int32_t  dec_hold;                  /* v1.2 decimator state */
    int      dec_phase;

    uint32_t rr[DSP_RR_HISTORY];
    unsigned rr_count;
    unsigned rr_head;
    uint16_t beats;

    /* SpO2: DC-removed samples of the last 4 s, and a 1 s mean for red */
    int32_t  red_hp[DSP_AC_WINDOW];
    int32_t  ir_hp[DSP_AC_WINDOW];
    uint32_t red_dc_ring[DSP_DC_WINDOW];
    uint64_t red_dc_sum;
    uint32_t ac_fill;
} dsp_t;

typedef struct {
    uint16_t bpm_x10;      /* 0 until enough beats */
    uint16_t spo2_x10;     /* DSP_SPO2_NONE for v1.0 or until enough data */
    uint16_t beats;
    uint16_t mean_rr_ms;
    uint8_t  quality;      /* 0-100; 0 for v1.0 */
    uint8_t  alerts;       /* DSP_ALERT_*; 0 for v1.0 */
} dsp_out;

void dsp_init(dsp_t *d, dsp_variant v);
void dsp_push(dsp_t *d, uint32_t red, uint32_t ir);
void dsp_result(const dsp_t *d, dsp_out *o);

#endif
