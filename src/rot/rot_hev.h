#ifndef ROT_HEV_H
#define ROT_HEV_H

#include <stdint.h>

/*
 * Health evidence (HEV1), written by the application's pre-network
 * self-test and judged by the RoT.
 *
 * HEV1 (32 bytes, written by the application):
 *    0  4  "HEV1"
 *    4  8  svn
 *   12  2  golden_bpm_x10 (BPM the app computed from the embedded trace)
 *   14  2  golden_spo2_x10 (0xFFFF if unsupported)
 *   16  2  beats detected
 *   18  2  mean RR ms
 *   20  1  sensor PART_ID
 *   21  1  sensor_ok
 *   22  2  live samples in 1 s
 *   24  2  self-test ms
 *   26  1  app verdict (informational, never trusted)
 *   27  5  reserved
 */

#define HEV1_BYTES 32u
#define HEV1_PART_ID_MAX30102 0x15u

typedef struct {
    uint64_t svn;
    uint16_t golden_bpm_x10;
    uint16_t golden_spo2_x10;
    uint16_t beats;
    uint16_t mean_rr_ms;
    uint8_t  part_id;
    uint8_t  sensor_ok;
    uint16_t live_samples;
    uint16_t selftest_ms;
    uint8_t  verdict;
} rot_hev_t;

/* 0, or -1 on bad magic. */
int rot_hev_parse(const uint8_t b[HEV1_BYTES], rot_hev_t *h);
void rot_hev_build(uint8_t b[HEV1_BYTES], const rot_hev_t *h);

#endif
