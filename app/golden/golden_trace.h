#ifndef APP_GOLDEN_TRACE_H
#define APP_GOLDEN_TRACE_H

#include <stdint.h>

/* Embedded resting trace used by the health self-test: 10 s at 100 Hz. */
#define GOLDEN_SAMPLES 1000u

extern const uint32_t golden_red[GOLDEN_SAMPLES];
extern const uint32_t golden_ir[GOLDEN_SAMPLES];

#endif
