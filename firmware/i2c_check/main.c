/*
 * Sensor bring-up: scan I2C0 (GP4 SDA, GP5 SCL) at 400 kHz, read the MAX30102
 * PART_ID 100 times, initialise it through the application driver and read
 * the die temperature. A pass is: only 0x57 answers, PART_ID is 0x15 100
 * times out of 100, and init succeeds.
 */

#include <stdio.h>

#include "hardware/gpio.h"
#include "hardware/i2c.h"
#include "pico/stdlib.h"

#include "sensor/max30102.h"

#define SDA_PIN 4
#define SCL_PIN 5
#define BUS i2c0

static int bus_write(void *ctx, uint8_t addr, uint8_t reg, const uint8_t *d, size_t n)
{
    uint8_t buf[16];
    (void)ctx;
    if (n + 1 > sizeof buf) return -1;
    buf[0] = reg;
    for (size_t i = 0; i < n; i++) buf[1 + i] = d[i];
    return i2c_write_blocking(BUS, addr, buf, n + 1, false) == (int)(n + 1) ? 0 : -1;
}

static int bus_read(void *ctx, uint8_t addr, uint8_t reg, uint8_t *d, size_t n)
{
    (void)ctx;
    if (i2c_write_blocking(BUS, addr, &reg, 1, true) != 1) return -1;
    return i2c_read_blocking(BUS, addr, d, n, false) == (int)n ? 0 : -1;
}

static void bus_delay(void *ctx, unsigned ms)
{
    (void)ctx;
    sleep_ms(ms);
}

int main(void)
{
    stdio_init_all();
    sleep_ms(2000);

    i2c_init(BUS, 400 * 1000);
    gpio_set_function(SDA_PIN, GPIO_FUNC_I2C);
    gpio_set_function(SCL_PIN, GPIO_FUNC_I2C);
    gpio_pull_up(SDA_PIN);
    gpio_pull_up(SCL_PIN);

    for (;;) {
        unsigned found = 0, good = 0;
        uint8_t id = 0;
        max30102 dev;
        max30102_bus bus = { NULL, bus_write, bus_read, bus_delay };
        int t = 0, rc;

        printf("scan:");
        for (int a = 0x08; a < 0x78; a++) {
            uint8_t b;
            if (i2c_read_blocking(BUS, a, &b, 1, false) >= 0) {
                printf(" 0x%02x", a);
                found++;
            }
        }
        printf(" (%u found)\n", found);

        for (int i = 0; i < 100; i++) {
            if (bus_read(NULL, MAX30102_ADDR, MAX30102_REG_PART_ID, &id, 1) == 0 && id == MAX30102_PART_ID) good++;
        }
        printf("PART_ID 0x15: %u/100\n", good);

        rc = max30102_init(&dev, &bus);
        printf("init rc=%d part=0x%02x rev=0x%02x\n", rc, dev.part_id, dev.rev_id);
        if (rc == 0 && max30102_read_temp(&dev, &t) == 0) {
            printf("die temperature %d.%d C\n", t / 10, t % 10);
        }
        printf("RESULT %s\n", (found == 1 && good == 100 && rc == 0) ? "PASS" : "FAIL");
        sleep_ms(3000);
    }
}
