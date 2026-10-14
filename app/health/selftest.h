#ifndef APP_SELFTEST_H
#define APP_SELFTEST_H

#include <stdint.h>

#include "dsp/dsp.h"
#include "sensor/max30102.h"

/*
 * Trial-boot self-test. Runs before the network starts:
 *
 *   1. the DSP over the embedded golden trace -> rate, SpO2, beats;
 *   2. a probe of the sensor: PART_ID and the number of samples that arrive
 *      in one second.
 *
 * The result is packed into HEV1 for the RoT. The app's own verdict is
 * informational; the RoT decides from the numbers.
 */

typedef struct {
    max30102 *dev;                         /* NULL when no sensor is attached */
    const max30102_bus *bus;               /* used to initialise `dev` */
    dsp_variant variant;
    uint64_t svn;                          /* the version this image believes it is */
    void *ctx;
    uint32_t (*now_ms)(void *ctx);
    void (*delay_ms)(void *ctx, unsigned ms);
} selftest_env;

typedef struct {
    dsp_out  golden;
    uint8_t  part_id;
    uint8_t  sensor_ok;
    uint16_t live_samples;
    uint16_t elapsed_ms;
    uint8_t  verdict;
} selftest_result;

/* Run the self-test; fills `res` and the 32-byte HEV1. */
void selftest_run(const selftest_env *env, selftest_result *res, uint8_t hev1[32]);

#endif
