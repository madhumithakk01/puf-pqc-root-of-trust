/* Test application for spike_chain: reports where it runs and what survived the chain. */

#include <stdio.h>

#include "hardware/watchdog.h"
#include "hardware/structs/watchdog.h"
#include "pico/stdlib.h"

#define PATTERN 0xA55A1234u
#define HANDOFF 0x2007C000u

int main(void)
{
    const volatile uint32_t *h = (const volatile uint32_t *)HANDOFF;
    unsigned ok = 0;
    void *pc = (void *)main;

    stdio_init_all();
    sleep_ms(2000);
    for (unsigned i = 0; i < 4096; i++) ok += h[i] == PATTERN + i;
    printf("U1 main at %p (linked at 0x10000000: runs from slot B only if translation worked)\n", pc);
    printf("U2 handoff pattern intact: %u/4096 words\n", ok);
    printf("U6 watchdog enabled: %s\n", (watchdog_hw->ctrl & WATCHDOG_CTRL_ENABLE_BITS) ? "yes" : "no");
    for (;;) sleep_ms(1000);
}
