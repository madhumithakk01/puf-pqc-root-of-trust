/*
 * Chain spike (open items U1, U2, U6). An offset-0 image fills the handoff
 * region with a pattern, arms the watchdog for 8 s and chains a test
 * application placed 4 KB into app_b. The test application (spike_chain_app)
 * prints its program counter, checks the pattern and reports whether the
 * watchdog is still enabled.
 */

#include <stdio.h>

#include "hardware/watchdog.h"
#include "pico/bootrom.h"
#include "pico/stdlib.h"

#include "platform/rp2350/rp2350_platform.h"
#include "rot/rot_flash_map.h"

#define PATTERN 0xA55A1234u

int main(void)
{
    static bootrom_stack_t st;
    volatile uint32_t *h = (volatile uint32_t *)HANDOFF_BASE;

    stdio_init_all();
    sleep_ms(2000);
    printf("spike_chain: filling the handoff region and chaining app_b + 4 KB\n");
    for (unsigned i = 0; i < HANDOFF_SIZE / 4; i++) h[i] = PATTERN + i;

    st.base = (uint32_t *)ROM_STACK_BASE;
    st.size = ROM_STACK_SIZE;
    rom_set_bootrom_stack(&st);
    watchdog_enable(8000, true);
    stdio_flush();
    sleep_ms(50);
    {
        int rc = rom_chain_image((uint8_t *)CHAIN_WORKAREA, CHAIN_WORKAREA_SZ,
                                 XIP_BASE + ROT_REGION_APP_B_OFF + ROT_APP_BIN_OFFSET, 64 * 1024);
        printf("chain returned %d\n", rc);
    }
    for (;;) sleep_ms(1000);
}
