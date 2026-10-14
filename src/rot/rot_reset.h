#ifndef ROT_RESET_H
#define ROT_RESET_H

#include <stdint.h>

/*
 * Freshness rule for the SRAM PUF.
 *
 * The key window is only a usable PUF response when the SRAM powered up from
 * scratch. The RP2350 reports why it last reset in POWMAN_CHIP_RESET; this
 * module turns those bits into a verdict:
 *
 *   fresh   power-on reset, RUN pin low, or a power-down of the switched core
 *           that the RoT itself asked for (its marker is in a POWMAN scratch
 *           register)
 *   stale   everything else: watchdog resets, debugger and rescue resets,
 *           brown-out and glitch detection (the SRAM may be only partly
 *           discharged), a switched-core power-down nobody asked for, and
 *           a register with no bit set at all
 *
 * A stale boot never reads the window: the RoT refreshes the SRAM first.
 */

#define RST_HAD_POR              (1u << 16)
#define RST_HAD_BOR              (1u << 17)
#define RST_HAD_RUN_LOW          (1u << 18)
#define RST_HAD_DP_RESET_REQ     (1u << 19)
#define RST_HAD_RESCUE           (1u << 21)
#define RST_HAD_WDT_POWMAN_ASYNC (1u << 22)
#define RST_HAD_WDT_POWMAN       (1u << 23)
#define RST_HAD_WDT_SWCORE       (1u << 24)
#define RST_HAD_SWCORE_PD        (1u << 25)
#define RST_HAD_GLITCH           (1u << 26)
#define RST_HAD_HZD_SYS_RESET    (1u << 27)
#define RST_HAD_WDT_PSM          (1u << 28)

#define RST_WATCHDOG_MASK (RST_HAD_WDT_POWMAN_ASYNC | RST_HAD_WDT_POWMAN | RST_HAD_WDT_SWCORE | RST_HAD_WDT_PSM)
#define RST_DEBUG_MASK    (RST_HAD_DP_RESET_REQ | RST_HAD_RESCUE | RST_HAD_HZD_SYS_RESET)

/* POWMAN scratch 0: high 24 bits are the marker, low 8 bits the original cause. */
#define RST_MARKER_MASK  0xFFFFFF00u
#define RST_MARKER       0x52465300u  /* "RFS" */

typedef struct {
    uint8_t cause;   /* RC_* of this reset (RC_PSTATE when it is our own refresh) */
    uint8_t fresh;   /* 1 if the SRAM can be read as a PUF */
    uint8_t original; /* RC_* of the reset that made us refresh, when this boot is the refresh */
} rot_reset_verdict;

/* `scratch0` is the POWMAN scratch register as left by the previous run. */
rot_reset_verdict rot_reset_classify(uint32_t chip_reset_bits, uint32_t scratch0);

/* Value to store in scratch 0 before asking for a refresh. */
uint32_t rot_reset_marker(uint8_t original_cause);

#endif
