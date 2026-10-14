#include "rp2350_platform.h"

#include <stdio.h>
#include <string.h>

#include "hardware/adc.h"
#include "hardware/flash.h"
#include "hardware/irq.h"
#include "hardware/resets.h"
#include "hardware/structs/powman.h"
#include "hardware/structs/trng.h"
#include "hardware/sync.h"
#include "hardware/watchdog.h"
#include "pico/aon_timer.h"
#include "pico/bootrom.h"
#include "pico/low_power.h"
#include "pico/stdlib.h"

#include "rot/rot_flash_map.h"

/* ------------------------------------------------------------------ */
/* POWMAN scratch and reset cause                                     */

uint32_t rp2350_chip_reset_bits(void)
{
    return powman_hw->chip_reset;
}

uint32_t rp2350_scratch_get(unsigned idx)
{
    return powman_hw->scratch[idx];
}

void rp2350_scratch_set(unsigned idx, uint32_t v)
{
    powman_hw->scratch[idx] = v;
}

/* ------------------------------------------------------------------ */
/* SRAM refresh                                                       */

int rp2350_refresh(uint32_t t_off_ms)
{
    pstate_bitset_t none = pstate_bitset_none();   /* nothing stays powered: all SRAM off */

    if (!aon_timer_is_running()) {
        struct timespec ts = { 0, 0 };
        aon_timer_start(&ts);
    }
    return low_power_pstate_for_ms(t_off_ms, &none, NULL);
}

/* ------------------------------------------------------------------ */
/* counters, temperature, TRNG                                        */

#if defined(__riscv)

void rp2350_counters_enable(void)
{
    __asm volatile("csrw 0x320, zero");   /* mcountinhibit: run mcycle and minstret */
}

uint64_t rp2350_mcycle(void)
{
    uint32_t hi, lo, hi2;
    do {
        __asm volatile("csrr %0, mcycleh" : "=r"(hi));
        __asm volatile("csrr %0, mcycle" : "=r"(lo));
        __asm volatile("csrr %0, mcycleh" : "=r"(hi2));
    } while (hi != hi2);
    return ((uint64_t)hi << 32) | lo;
}

uint64_t rp2350_minstret(void)
{
    uint32_t hi, lo, hi2;
    do {
        __asm volatile("csrr %0, minstreth" : "=r"(hi));
        __asm volatile("csrr %0, minstret" : "=r"(lo));
        __asm volatile("csrr %0, minstreth" : "=r"(hi2));
    } while (hi != hi2);
    return ((uint64_t)hi << 32) | lo;
}

#else /* Arm fallback: the DWT cycle counter */

#define DWT_CTRL   (*(volatile uint32_t *)0xE0001000u)
#define DWT_CYCCNT (*(volatile uint32_t *)0xE0001004u)
#define DEMCR      (*(volatile uint32_t *)0xE000EDFCu)

void rp2350_counters_enable(void)
{
    DEMCR |= 1u << 24;
    DWT_CTRL |= 1u;
}

uint64_t rp2350_mcycle(void)
{
    return DWT_CYCCNT;
}

uint64_t rp2350_minstret(void)
{
    return 0;
}

#endif

int rp2350_die_temp_x10(void)
{
    uint32_t sum = 0;

    adc_init();
    adc_set_temp_sensor_enabled(true);
    adc_select_input(ADC_TEMPERATURE_CHANNEL_NUM);
    for (int i = 0; i < 16; i++) {
        sum += adc_read();
    }
    adc_set_temp_sensor_enabled(false);
    {
        /* 3.3 V reference, 12 bit; T = 27 - (V - 0.706) / 0.001721 */
        int32_t mv = (int32_t)((sum / 16u) * 3300u / 4096u);
        return 270 - ((mv - 706) * 10000) / 1721;
    }
}

void rp2350_trng_raw(uint8_t *buf, size_t n)
{
    while (n) {
        uint32_t w[count_of(trng_hw->ehr_data)];
        size_t take;

        /* raw ROSC samples, as pico_rand takes them; the RoT conditions them itself */
        trng_hw->sample_cnt1 = 0;
        trng_hw->trng_debug_control = (uint32_t)-1;
        trng_hw->rnd_source_enable = (uint32_t)-1;
        trng_hw->rng_icr = (uint32_t)-1;
        while (trng_hw->trng_busy) {
            tight_loop_contents();
        }
        for (unsigned i = 0; i < count_of(w); i++) {
            w[i] = trng_hw->ehr_data[i];
        }
        take = n < sizeof w ? n : sizeof w;
        memcpy(buf, w, take);
        buf += take;
        n -= take;
    }
}

/* ------------------------------------------------------------------ */
/* PMP                                                                */

int rp2350_pmp_lock_otp(void)
{
#if defined(__riscv)
    /* NAPOT region 0x40120000 + 64 KB, locked, read-only: no writes to the OTP register block */
    uint32_t addr = (0x40120000u | 0x7FFFu) >> 2;
    uint32_t cfg = 0x80u | 0x18u | 0x01u;   /* L | A=NAPOT | R */
    __asm volatile("csrw pmpaddr0, %0" ::"r"(addr));
    __asm volatile("csrw pmpcfg0, %0" ::"r"(cfg));
    return 0;
#else
    return -1;
#endif
}

/* ------------------------------------------------------------------ */
/* flash                                                              */

static int wdt_armed;

static int fl_read(void *ctx, uint32_t off, uint8_t *buf, size_t n)
{
    (void)ctx;
    memcpy(buf, (const void *)(XIP_BASE + off), n);
    return 0;
}

static int fl_erase(void *ctx, uint32_t off, size_t len)
{
    uint32_t irq;
    (void)ctx;
    if ((off & (FLASH_SECTOR_SIZE - 1)) || (len & (FLASH_SECTOR_SIZE - 1))) return ROT_E_RANGE;
    irq = save_and_disable_interrupts();
    flash_range_erase(off, len);
    restore_interrupts(irq);
    return 0;
}

static int fl_write(void *ctx, uint32_t off, const uint8_t *buf, size_t n)
{
    uint32_t irq;
    (void)ctx;
    if ((off & (FLASH_PAGE_SIZE - 1)) || (n & (FLASH_PAGE_SIZE - 1))) return ROT_E_RANGE;
    irq = save_and_disable_interrupts();
    flash_range_program(off, buf, n);
    restore_interrupts(irq);
    return 0;
}

static const uint8_t *fl_xip(void *ctx, uint32_t off)
{
    (void)ctx;
    return (const uint8_t *)(XIP_BASE + off);
}

static void pl_log(void *ctx, const char *line)
{
    (void)ctx;
    puts(line);
}

static void pl_trng(void *ctx, uint8_t *buf, size_t n)
{
    (void)ctx;
    rp2350_trng_raw(buf, n);
}

static uint64_t pl_cycles(void *ctx)
{
    (void)ctx;
    return rp2350_mcycle();
}

static void pl_wdt(void *ctx)
{
    (void)ctx;
    if (wdt_armed) {
        watchdog_update();
    }
}

void rp2350_wdt_arm(uint32_t ms)
{
    watchdog_enable(ms, true);
    wdt_armed = 1;
}

void rp2350_platform_init(rot_platform *p)
{
    rp2350_counters_enable();
#if defined(__riscv)
    {
        /*
         * ROM functions that run under Arm emulation on RISC-V need a stack of
         * their own. Keep it in the SCRATCH_Y bank, out of the RoT's own stack.
         */
        static bootrom_stack_t st;
        st.base = (uint32_t *)ROM_STACK_BASE;
        st.size = ROM_STACK_SIZE;
        rom_set_bootrom_stack(&st);
    }
#endif
    memset(p, 0, sizeof *p);
    p->ctx = NULL;
    p->flash_read = fl_read;
    p->flash_erase = fl_erase;
    p->flash_write = fl_write;
    p->flash_xip = fl_xip;
    p->log = pl_log;
    p->trng_raw = pl_trng;
    p->cycles = pl_cycles;
    p->wdt_feed = pl_wdt;
}

/* ------------------------------------------------------------------ */
/* final phase                                                        */

void __attribute__((noreturn, noinline, used)) rot_final_stage(void)
{
    const final_params *fp = (const final_params *)FINAL_PARAMS;
    volatile uint32_t *p;
    uint32_t base = fp->region_base, size = fp->region_size;

    /* wipe R1 (program RAM), R2 (RoT stack) and R3 (PUF zone); R4 holds the handoff */
    for (p = (volatile uint32_t *)SRAM_BASE; p < (volatile uint32_t *)WIPE_END; p++) {
        *p = 0;
    }
    rom_chain_image((uint8_t *)CHAIN_WORKAREA, CHAIN_WORKAREA_SZ, base, size);

    /* a chain that returns has failed: restart the sequence */
    watchdog_reboot(0, 0, 0);
    for (;;) {
        __asm volatile("wfi");
    }
}

void __attribute__((noreturn)) rp2350_final_chain(const final_params *fp)
{
    final_params *dst = (final_params *)FINAL_PARAMS;

    *dst = *fp;
    /* the boot ROM translates flash in 4 KB units; a region of any other length is not entered */
    dst->region_size = (fp->region_size + 4095u) & ~4095u;
    if (fp->watchdog_ms) {
        watchdog_enable(fp->watchdog_ms, true);
    } else if (wdt_armed) {
        watchdog_disable();   /* the RoT-phase guard is not the application's */
    }
#if defined(__riscv)
    if (fp->pmp_lock) {
        rp2350_pmp_lock_otp();
    }
    __asm volatile("csrci mstatus, 8");           /* no more interrupts */
    /* the application's start-up expects every external interrupt disabled and clear */
    for (uint n = 0; n < NUM_IRQS; n++) {
        irq_set_enabled(n, false);
        irq_clear(n);
    }
    reset_block_mask(RESETS_RESET_USBCTRL_BITS);  /* the application starts USB afresh */
    __asm volatile("mv sp, %0\n\tj rot_final_stage" ::"r"(FINAL_STACK_TOP) : "memory");
#else
    __asm volatile("cpsid i");
    reset_block_mask(RESETS_RESET_USBCTRL_BITS);
    __asm volatile("mov sp, %0\n\tb rot_final_stage" ::"r"(FINAL_STACK_TOP) : "memory");
#endif
    for (;;) {
    }
}
