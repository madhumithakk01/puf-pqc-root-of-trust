/* The on-target self-test passes on the host, and each check can fail. */

#include "rot/rot_rng.h"
#include "rot/rot_selftest.h"

#include <stdint.h>
#include <stdio.h>

static void raw(void *c, uint8_t *b, size_t n)
{
    (void)c;
    for (size_t i = 0; i < n; i++) b[i] = (uint8_t)(i * 3 + 1);
}

static uint64_t ticks;
static uint64_t counter(void) { return ticks += 1000; }

int main(void)
{
    uint64_t cyc[5];
    uint32_t r;
    int ok;

    rot_rng_init(raw, NULL);
    r = rot_selftest_run(counter, cyc);
    printf("  %s all known answers hold on this platform\n", r == 0 ? "ok  " : "FAIL");
    ok = r == 0 && cyc[0] == 1000 && cyc[4] == 1000;
    printf("  %s per-step counter laps are reported\n", ok ? "ok  " : "FAIL");
    printf("test_selftest_kat: %s\n", (r == 0 && ok) ? "PASS" : "FAIL");
    return (r == 0 && ok) ? 0 : 1;
}
