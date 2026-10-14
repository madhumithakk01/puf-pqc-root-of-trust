#include "rot/rot_reset.h"

#include "rot/rot_handoff.h"   /* RC_* */

uint32_t rot_reset_marker(uint8_t original_cause)
{
    return RST_MARKER | original_cause;
}

rot_reset_verdict rot_reset_classify(uint32_t bits, uint32_t scratch0)
{
    rot_reset_verdict v = { RC_UNKNOWN, 0, RC_UNKNOWN };
    int marked = (scratch0 & RST_MARKER_MASK) == RST_MARKER;

    if (bits & RST_WATCHDOG_MASK) {
        v.cause = RC_WATCHDOG;
    } else if (bits & RST_DEBUG_MASK) {
        v.cause = RC_DEBUG;
    } else if (bits & (RST_HAD_BOR | RST_HAD_GLITCH)) {
        v.cause = RC_BROWNOUT;
    } else if (bits & RST_HAD_POR) {
        v.cause = RC_POR;
        v.fresh = 1;
    } else if (bits & RST_HAD_RUN_LOW) {
        v.cause = RC_RUN;
        v.fresh = 1;
    } else if (bits & RST_HAD_SWCORE_PD) {
        if (marked) {
            v.cause = RC_PSTATE;
            v.fresh = 1;
            v.original = (uint8_t)(scratch0 & 0xFFu);
        } else {
            v.cause = RC_OTHER;   /* a power-down we did not request */
        }
    } else {
        v.cause = RC_OTHER;
    }
    return v;
}
