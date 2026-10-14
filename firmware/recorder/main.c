/*
 * Recorder: streams raw MAX30102 samples over USB as "red,ir" CSV lines at
 * 100 Hz, for recording the golden trace (tools/sensor/record.py).
 */

#include <stdio.h>

#include "hardware/gpio.h"
#include "hardware/i2c.h"
#include "pico/stdlib.h"

#include "sensor/max30102.h"

#define BUS i2c0

static int bus_write(void *c, uint8_t a, uint8_t r, const uint8_t *d, size_t n)
{
    uint8_t buf[16];
    (void)c;
    if (n + 1 > sizeof buf) return -1;
    buf[0] = r;
    for (size_t i = 0; i < n; i++) buf[1 + i] = d[i];
    return i2c_write_blocking(BUS, a, buf, n + 1, false) == (int)(n + 1) ? 0 : -1;
}

static int bus_read(void *c, uint8_t a, uint8_t r, uint8_t *d, size_t n)
{
    (void)c;
    if (i2c_write_blocking(BUS, a, &r, 1, true) != 1) return -1;
    return i2c_read_blocking(BUS, a, d, n, false) == (int)n ? 0 : -1;
}

static void bus_delay(void *c, unsigned ms) { (void)c; sleep_ms(ms); }

int main(void)
{
    max30102 dev;
    max30102_bus bus = { NULL, bus_write, bus_read, bus_delay };
    uint32_t red[32], ir[32];

    stdio_init_all();
    sleep_ms(2000);
    i2c_init(BUS, 400 * 1000);
    gpio_set_function(4, GPIO_FUNC_I2C);
    gpio_set_function(5, GPIO_FUNC_I2C);
    gpio_pull_up(4);
    gpio_pull_up(5);
    printf("# recorder: red,ir at 100 Hz\n");
    while (max30102_init(&dev, &bus) != MAX30102_OK) {
        printf("# sensor init failed, retrying\n");
        sleep_ms(1000);
    }
    printf("red,ir\n");
    for (;;) {
        int n = max30102_read_fifo(&dev, red, ir, 32);
        for (int i = 0; i < n; i++) printf("%lu,%lu\n", (unsigned long)red[i], (unsigned long)ir[i]);
        sleep_ms(10);
    }
}
