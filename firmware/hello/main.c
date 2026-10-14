/* Banner over USB each second and a blink of the CYW43-driven LED. */

#include <stdio.h>

#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"

#if defined(__riscv)
#define ARCH "RISC-V (Hazard3)"
#else
#define ARCH "Arm (Cortex-M33)"
#endif

int main(void)
{
    stdio_init_all();
    if (cyw43_arch_init()) {
        printf("cyw43 init failed\n");
        return 1;
    }
    for (unsigned n = 0;; n++) {
        cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, n & 1);
        printf("hello from the RP2350 on %s, tick %u, t=%llu us\n", ARCH, n,
               (unsigned long long)time_us_64());
        sleep_ms(1000);
    }
}
