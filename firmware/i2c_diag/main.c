/*
 * I2C wiring diagnostic. Reports the idle level of every GPIO that can carry
 * I2C0 or I2C1 with the internal pull-up on and then with a pull-down on, then
 * scans each I2C-capable pin pair in both orientations. A line that floats
 * low with the pull-up enabled is shorted or held by the sensor board.
 */

#include <stdio.h>

#include "hardware/gpio.h"
#include "hardware/i2c.h"
#include "pico/stdlib.h"

static void levels(void)
{
    printf("release test (drive low, release, no pulls; level at 2/20/200 us): ");
    for (int p = 2; p <= 9; p++) {
        int r[3];
        static const unsigned us[3] = { 2, 18, 180 };
        gpio_init(p);
        gpio_disable_pulls(p);
        gpio_put(p, 0);
        gpio_set_dir(p, GPIO_OUT);
        sleep_us(500);
        gpio_set_dir(p, GPIO_IN);
        for (int i = 0; i < 3; i++) {
            sleep_us(us[i]);
            r[i] = gpio_get(p);
        }
        printf("GP%d=%d%d%d ", p, r[0], r[1], r[2]);
    }
    printf("\n");
}

static unsigned scan(i2c_inst_t *bus, int sda, int scl, int *first)
{
    unsigned found = 0;
    i2c_init(bus, 100 * 1000);
    gpio_set_function(sda, GPIO_FUNC_I2C);
    gpio_set_function(scl, GPIO_FUNC_I2C);
    gpio_pull_up(sda);
    gpio_pull_up(scl);
    for (int a = 0x08; a < 0x78; a++) {
        uint8_t b;
        if (i2c_read_timeout_us(bus, a, &b, 1, false, 2000) >= 0) {
            if (!found) *first = a;
            found++;
        }
    }
    i2c_deinit(bus);
    gpio_init(sda);
    gpio_init(scl);
    return found;
}

int main(void)
{
    stdio_init_all();
    sleep_ms(2500);
    for (;;) {
        int first = 0;
        levels();
        /* I2C0 pairs: SDA on GP0/4/8, SCL on GP1/5/9. I2C1: SDA on GP2/6, SCL on GP3/7. */
        static const struct { int bus, sda, scl; } pairs[] = {
            { 0, 4, 5 }, { 0, 8, 9 }, { 1, 2, 3 }, { 1, 6, 7 },
        };
        for (unsigned i = 0; i < sizeof pairs / sizeof pairs[0]; i++) {
            i2c_inst_t *b = pairs[i].bus ? i2c1 : i2c0;
            unsigned n = scan(b, pairs[i].sda, pairs[i].scl, &first);
            printf("i2c%d SDA=GP%d SCL=GP%d: %u found", pairs[i].bus, pairs[i].sda, pairs[i].scl, n);
            if (n) printf(" (first 0x%02x)", first);
            printf("\n");
        }
        printf("--\n");
        sleep_ms(2000);
    }
}
