/*
 * The freshness rule: which POWMAN reset causes allow the SRAM to be read as
 * a PUF, and which force a refresh.
 */

#include "rot/rot_reset.h"
#include "rot/rot_handoff.h"

#include <stdint.h>
#include <stdio.h>

static int failures = 0;

static void check(const char *name, int ok)
{
    printf("  %s %s\n", ok ? "ok  " : "FAIL", name);
    if (!ok) failures++;
}

int main(void)
{
    rot_reset_verdict v;
    const uint32_t marker_wd = rot_reset_marker(RC_WATCHDOG);

    check("marker carries the original cause", (marker_wd & 0xFF) == RC_WATCHDOG
          && (marker_wd & RST_MARKER_MASK) == RST_MARKER);

    v = rot_reset_classify(RST_HAD_POR, 0);
    check("power-on reset is fresh", v.fresh && v.cause == RC_POR);
    v = rot_reset_classify(RST_HAD_POR, 0xDEADBEEF);
    check("power-on reset is fresh whatever the scratch register holds", v.fresh && v.cause == RC_POR);
    v = rot_reset_classify(RST_HAD_RUN_LOW, 0);
    check("RUN pin low is fresh", v.fresh && v.cause == RC_RUN);

    v = rot_reset_classify(RST_HAD_SWCORE_PD, marker_wd);
    check("our own power-down with its marker is fresh and remembers the cause",
          v.fresh && v.cause == RC_PSTATE && v.original == RC_WATCHDOG);
    v = rot_reset_classify(RST_HAD_SWCORE_PD, 0);
    check("a switched-core power-down without the marker is stale", !v.fresh && v.cause == RC_OTHER);
    v = rot_reset_classify(RST_HAD_SWCORE_PD, 0x52465000);
    check("a near-miss marker is stale", !v.fresh);

    for (int b = 22; b <= 24; b++) {
        v = rot_reset_classify(1u << b, 0);
        char nm[64];
        snprintf(nm, sizeof nm, "watchdog reset (bit %d) is stale", b);
        check(nm, !v.fresh && v.cause == RC_WATCHDOG);
    }
    v = rot_reset_classify(RST_HAD_WDT_PSM, 0);
    check("watchdog PSM reset is stale", !v.fresh && v.cause == RC_WATCHDOG);
    v = rot_reset_classify(RST_HAD_DP_RESET_REQ, 0);
    check("debugger reset is stale", !v.fresh && v.cause == RC_DEBUG);
    v = rot_reset_classify(RST_HAD_RESCUE, 0);
    check("rescue reset is stale", !v.fresh && v.cause == RC_DEBUG);
    v = rot_reset_classify(RST_HAD_HZD_SYS_RESET, 0);
    check("RISC-V debug system reset is stale", !v.fresh && v.cause == RC_DEBUG);
    v = rot_reset_classify(RST_HAD_BOR, 0);
    check("brown-out is stale", !v.fresh && v.cause == RC_BROWNOUT);
    v = rot_reset_classify(RST_HAD_GLITCH, 0);
    check("glitch detection is stale", !v.fresh && v.cause == RC_BROWNOUT);
    v = rot_reset_classify(0, marker_wd);
    check("no cause bit at all is stale", !v.fresh && v.cause == RC_OTHER);

    /* a stale cause beats a fresh one when both are reported */
    v = rot_reset_classify(RST_HAD_POR | RST_HAD_BOR, 0);
    check("POR together with brown-out is treated as stale", !v.fresh);
    v = rot_reset_classify(RST_HAD_POR | RST_HAD_WDT_POWMAN, 0);
    check("POR together with a watchdog bit is treated as stale", !v.fresh && v.cause == RC_WATCHDOG);
    v = rot_reset_classify(RST_HAD_RUN_LOW | RST_HAD_DP_RESET_REQ, 0);
    check("RUN low together with a debugger reset is treated as stale", !v.fresh);
    v = rot_reset_classify(RST_HAD_SWCORE_PD | RST_HAD_WDT_SWCORE, marker_wd);
    check("our marker does not excuse a watchdog bit", !v.fresh);

    if (failures) {
        printf("test_reset: FAIL (%d)\n", failures);
        return 1;
    }
    printf("test_reset: PASS\n");
    return 0;
}
