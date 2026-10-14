#ifndef RP2350_PLATFORM_H
#define RP2350_PLATFORM_H

#include <stddef.h>
#include <stdint.h>

#include "rot/rot_platform.h"

/*
 * RP2350 implementation of the portable RoT platform interface, plus the
 * board-only pieces: SRAM refresh through a Pstate, POWMAN scratch use,
 * cycle counters, TRNG, die temperature, PMP, and the final wipe and chain.
 */

/* SRAM map, see the implementation guide */
#define PUF_ZONE_BASE      0x20068000u
#define PUF_ZONE_SIZE      0x00014000u    /* 20 blocks of 4 KB */
#define PUF_BLOCK_SIZE     0x1000u
#define PUF_KEY_BLOCK      8u             /* default key window: block 8 = 0x20070000 */
#define PUF_KEY_WINDOW     (PUF_ZONE_BASE + PUF_KEY_BLOCK * PUF_BLOCK_SIZE)
#define HANDOFF_BASE       0x2007C000u
#define HANDOFF_SIZE       0x00004000u
#define WIPE_END           HANDOFF_BASE   /* R1-R3 end here; R4 holds the handoff */

#define FINAL_STACK_TOP    0x20081C00u    /* final-phase stack: SCRATCH_Y bank, 3 KB */
#define FINAL_PARAMS       0x20081000u
#define ROM_STACK_BASE     0x20081C00u    /* RISC-V boot ROM emulation stack, 1 KB */
#define ROM_STACK_SIZE     0x400u
#define CHAIN_WORKAREA     0x20080000u    /* SCRATCH_X, 3,264 bytes needed */
#define CHAIN_WORKAREA_SZ  0xCC0u

/* POWMAN scratch registers owned by the RoT */
enum {
    SCR_MARKER = 0,     /* refresh marker + original cause */
    SCR_REFRESHES = 1,  /* refresh attempts in this boot sequence */
    SCR_ENROLL = 2,     /* enrollment progress */
    SCR_CHARZ = 3,      /* characterization pattern id */
    SCR_INSTALL = 4,    /* install attempts: (mailbox seq & 0xFFFF) << 16 | attempts */
    SCR_PUF_RETRY = 5,  /* a key mismatch already triggered one refresh */
};

#define REFRESH_MAX_ATTEMPTS 3u
#define DEFAULT_T_OFF_MS     1000u   /* 100 ms did not wake on the board; 1 s refreshes cleanly */

void rp2350_platform_init(rot_platform *p);

/* Arm the RoT-phase watchdog (fed by the platform wdt_feed op). */
void rp2350_wdt_arm(uint32_t ms);

uint32_t rp2350_chip_reset_bits(void);
uint32_t rp2350_scratch_get(unsigned idx);
void rp2350_scratch_set(unsigned idx, uint32_t v);

/*
 * Power the SRAM off for `t_off_ms` and reboot into the RoT. Does not return
 * on success; returns a negative pico error code if the request was refused.
 */
int rp2350_refresh(uint32_t t_off_ms);

/* Stop the cycle counter inhibit and read 64-bit mcycle / minstret. */
void rp2350_counters_enable(void);
uint64_t rp2350_mcycle(void);
uint64_t rp2350_minstret(void);

/* Die temperature in tenths of a degree C. */
int rp2350_die_temp_x10(void);

/* Raw TRNG bytes, no conditioning. */
void rp2350_trng_raw(uint8_t *buf, size_t n);

/* Lock a PMP region that denies writes to the OTP register block until the next reset. */
int rp2350_pmp_lock_otp(void);

/*
 * Final phase: stack to the SCRATCH_Y bank, wipe R1-R3, optionally arm the
 * watchdog, chain the image at flash offset `app_off`. Does not return.
 */
typedef struct {
    uint32_t region_base;   /* XIP address of the application binary */
    uint32_t region_size;
    uint32_t watchdog_ms;   /* 0: no trial */
    uint32_t pmp_lock;
} final_params;

void __attribute__((noreturn)) rp2350_final_chain(const final_params *fp);

#endif
