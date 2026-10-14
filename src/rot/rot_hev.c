#include "rot/rot_hev.h"

#include "rot/rot_util.h"

#include <string.h>

void rot_hev_build(uint8_t b[HEV1_BYTES], const rot_hev_t *h)
{
    memset(b, 0, HEV1_BYTES);
    memcpy(b, "HEV1", 4);
    rot_put64(b + 4, h->svn);
    rot_put16(b + 12, h->golden_bpm_x10);
    rot_put16(b + 14, h->golden_spo2_x10);
    rot_put16(b + 16, h->beats);
    rot_put16(b + 18, h->mean_rr_ms);
    b[20] = h->part_id;
    b[21] = h->sensor_ok;
    rot_put16(b + 22, h->live_samples);
    rot_put16(b + 24, h->selftest_ms);
    b[26] = h->verdict;
}

int rot_hev_parse(const uint8_t b[HEV1_BYTES], rot_hev_t *h)
{
    if (memcmp(b, "HEV1", 4) != 0) {
        return -1;
    }
    h->svn = rot_get64(b + 4);
    h->golden_bpm_x10 = rot_get16(b + 12);
    h->golden_spo2_x10 = rot_get16(b + 14);
    h->beats = rot_get16(b + 16);
    h->mean_rr_ms = rot_get16(b + 18);
    h->part_id = b[20];
    h->sensor_ok = b[21];
    h->live_samples = rot_get16(b + 22);
    h->selftest_ms = rot_get16(b + 24);
    h->verdict = b[26];
    return 0;
}
