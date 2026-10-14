/* Test application for spike_chain: reports where it runs and what survived the chain. */

#include <stdio.h>

#include "hardware/watchdog.h"
#include "hardware/structs/powman.h"
#include "hardware/structs/watchdog.h"
#include "pico/stdlib.h"

#define PATTERN 0xA55A1234u
#define HANDOFF 0x2007C000u

int main(void)
{
    const volatile uint32_t *h = (const volatile uint32_t *)HANDOFF;
    unsigned ok = 0;
    void *pc = (void *)main;

    /* Survives the watchdog reset; spike_chain prints it on the next boot. */
    powman_hw->scratch[3] = 0xC0DE0001u;
    powman_hw->scratch[2] = (uint32_t)pc;
    stdio_init_all();
    powman_hw->scratch[3] = 0xC0DE0002u;
    sleep_ms(2000);
    for (unsigned i = 0; i < 4096; i++) ok += h[i] == PATTERN + i;
    powman_hw->scratch[4] = ok;
    powman_hw->scratch[5] = (watchdog_hw->ctrl & WATCHDOG_CTRL_ENABLE_BITS) ? 1u : 0u;
    powman_hw->scratch[3] = 0xC0DE0003u;
    printf("U1 main at %p (linked at 0x10000000: runs from slot B only if translation worked)\n", pc);
    printf("U2 handoff pattern intact: %u/4096 words\n", ok);
    printf("U6 watchdog enabled: %s\n", (watchdog_hw->ctrl & WATCHDOG_CTRL_ENABLE_BITS) ? "yes" : "no");
    for (;;) sleep_ms(1000);
}
