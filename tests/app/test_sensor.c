/*
 * MAX30102 driver tests against a fake I2C bus that models the register
 * file, the reset bit and the 32-entry FIFO.
 */

#include "sensor/max30102.h"
#include "fake_i2c.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

static void check(const char *name, int ok)
{
    printf("  %s %s\n", ok ? "ok  " : "FAIL", name);
    if (!ok) failures++;
}

int main(void)
{
    static fake_t f;
    max30102 dev;
    max30102_bus bus = { &f, fk_write, fk_read, fk_delay };
    uint32_t red[40], ir[40];

    fake_reset(&f);
    check("init succeeds on a genuine part", max30102_init(&dev, &bus) == 0);
    check("part id and revision recorded", dev.part_id == 0x15 && dev.rev_id == 0x03);
    check("FIFO config: no averaging, rollover on", f.regs[MAX30102_REG_FIFO_CFG] == 0x10);
    check("SpO2 config: 4096 nA, 100 sps, 411 us", f.regs[MAX30102_REG_SPO2_CFG] == 0x33);
    check("LED currents about 7 mA", f.regs[MAX30102_REG_LED1_PA] == 0x24 && f.regs[MAX30102_REG_LED2_PA] == 0x24);
    check("mode is SpO2 (red + IR)", f.regs[MAX30102_REG_MODE] == 0x03);
    check("FIFO pointers cleared", f.wr == 0 && f.rd == 0 && f.ovf == 0);
    check("the device address 0x57 is the only one used", !f.bad_addr_seen);

    {
        uint8_t id = 0;
        check("read_part_id", max30102_read_part_id(&dev, &id) == 0 && id == 0x15);
    }

    check("empty FIFO reads zero samples", max30102_read_fifo(&dev, red, ir, 40) == 0);
    push(&f, 0x12345, 0x3FFFF);
    push(&f, 0x00001, 0x2A5A5);
    push(&f, 0x3FFFF, 0x00000);
    check("three samples read", max30102_read_fifo(&dev, red, ir, 40) == 3);
    check("18-bit values, red before IR", red[0] == 0x12345 && ir[0] == 0x3FFFF && red[1] == 1
          && ir[1] == 0x2A5A5 && red[2] == 0x3FFFF && ir[2] == 0);
    check("FIFO is empty again", max30102_read_fifo(&dev, red, ir, 40) == 0);

    for (int i = 0; i < 20; i++) push(&f, (uint32_t)(1000 + i), (uint32_t)(2000 + i));
    check("max limits the burst", max30102_read_fifo(&dev, red, ir, 12) == 12 && red[11] == 1011);
    check("the rest follows in order", max30102_read_fifo(&dev, red, ir, 40) == 8 && red[0] == 1012
          && ir[7] == 2019);

    for (int i = 0; i < 35; i++) push(&f, (uint32_t)i, (uint32_t)i);
    check("overflow: 32 samples, oldest first, the three lost ones are gone",
          max30102_read_fifo(&dev, red, ir, 40) == 32 && red[0] == 3 && red[31] == 34 && ir[0] == 3);
    check("overflow flag cleared", f.ovf == 0 && max30102_read_fifo(&dev, red, ir, 40) == 0);

    {
        int t = 0;
        f.regs[MAX30102_REG_TEMP_INT] = 29;
        f.regs[MAX30102_REG_TEMP_FRAC] = 0x08;
        check("temperature 29.5 C", max30102_read_temp(&dev, &t) == 0 && t == 295);
        check("temperature conversion was triggered", f.regs[MAX30102_REG_TEMP_CFG] == 1);
    }

    fake_reset(&f);
    f.regs[MAX30102_REG_PART_ID] = 0x11;
    check("wrong PART_ID is refused", max30102_init(&dev, &bus) == MAX30102_ERR_PART);

    fake_reset(&f);
    f.reset_sticks = 1;
    check("a reset bit that never clears is reported", max30102_init(&dev, &bus) == MAX30102_ERR_RESET);
    check("the driver waited between polls", f.delays >= 20);

    fake_reset(&f);
    f.fail_writes = 3;
    check("a bus error during configuration is reported", max30102_init(&dev, &bus) == MAX30102_ERR_BUS);

    if (failures) {
        printf("test_sensor: FAIL (%d)\n", failures);
        return 1;
    }
    printf("test_sensor: PASS\n");
    return 0;
}
