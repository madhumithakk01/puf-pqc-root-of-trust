#include "sensor/max30102.h"

#include <string.h>

static int wr(max30102 *d, uint8_t reg, uint8_t v)
{
    return d->bus.write_reg(d->bus.ctx, MAX30102_ADDR, reg, &v, 1) == 0 ? 0 : MAX30102_ERR_BUS;
}

static int rd(max30102 *d, uint8_t reg, uint8_t *buf, size_t n)
{
    return d->bus.read_reg(d->bus.ctx, MAX30102_ADDR, reg, buf, n) == 0 ? 0 : MAX30102_ERR_BUS;
}

int max30102_read_part_id(max30102 *d, uint8_t *id)
{
    return rd(d, MAX30102_REG_PART_ID, id, 1);
}

int max30102_init(max30102 *d, const max30102_bus *bus)
{
    uint8_t v = 0;
    int rc;

    memset(d, 0, sizeof *d);
    d->bus = *bus;

    rc = wr(d, MAX30102_REG_MODE, 0x40); /* reset */
    if (rc) return rc;
    for (int i = 0; ; i++) {
        if (i == 20) return MAX30102_ERR_RESET;
        if (d->bus.delay_ms) d->bus.delay_ms(d->bus.ctx, 2);
        rc = rd(d, MAX30102_REG_MODE, &v, 1);
        if (rc) return rc;
        if (!(v & 0x40)) break;
    }

    rc = rd(d, MAX30102_REG_PART_ID, &d->part_id, 1);
    if (rc) return rc;
    if (d->part_id != MAX30102_PART_ID) return MAX30102_ERR_PART;
    rc = rd(d, MAX30102_REG_REV_ID, &d->rev_id, 1);
    if (rc) return rc;

    if ((rc = wr(d, MAX30102_REG_FIFO_CFG, 0x10))) return rc;  /* no averaging, rollover on */
    if ((rc = wr(d, MAX30102_REG_SPO2_CFG, 0x33))) return rc;  /* 4096 nA, 100 sps, 411 us */
    if ((rc = wr(d, MAX30102_REG_LED1_PA, 0x24))) return rc;   /* red ~7.2 mA */
    if ((rc = wr(d, MAX30102_REG_LED2_PA, 0x24))) return rc;   /* IR ~7.2 mA */
    if ((rc = wr(d, MAX30102_REG_FIFO_WR, 0))) return rc;
    if ((rc = wr(d, MAX30102_REG_FIFO_OVF, 0))) return rc;
    if ((rc = wr(d, MAX30102_REG_FIFO_RD, 0))) return rc;
    return wr(d, MAX30102_REG_MODE, 0x03);                     /* SpO2: red + IR */
}

int max30102_read_fifo(max30102 *d, uint32_t *red, uint32_t *ir, size_t max)
{
    uint8_t p[3];
    uint8_t buf[6 * 8];
    unsigned avail;
    size_t done = 0;
    int rc;

    rc = rd(d, MAX30102_REG_FIFO_WR, p, 3); /* WR, OVF, RD are consecutive */
    if (rc) return rc;
    avail = (unsigned)(p[0] - p[2]) & 31u;
    if (p[1] != 0) {
        /*
         * Overflow: the FIFO holds 32 samples and the oldest is at the write
         * pointer. Move the read pointer there so they come out in order.
         */
        uint8_t wp = p[0] & 31u;
        if ((rc = wr(d, MAX30102_REG_FIFO_RD, wp))) return rc;
        if ((rc = wr(d, MAX30102_REG_FIFO_OVF, 0))) return rc;
        avail = 32;
    }
    if (avail > max) avail = (unsigned)max;

    while (done < avail) {
        size_t n = avail - done > 8 ? 8 : avail - done;
        rc = rd(d, MAX30102_REG_FIFO_DATA, buf, n * 6);
        if (rc) return rc;
        for (size_t i = 0; i < n; i++) {
            const uint8_t *s = buf + 6 * i;
            red[done + i] = (((uint32_t)s[0] << 16) | ((uint32_t)s[1] << 8) | s[2]) & 0x3FFFFu;
            ir[done + i] = (((uint32_t)s[3] << 16) | ((uint32_t)s[4] << 8) | s[5]) & 0x3FFFFu;
        }
        done += n;
    }
    return (int)done;
}

int max30102_read_temp(max30102 *d, int *t_x10)
{
    uint8_t cfg = 1, ti = 0, tf = 0;
    int rc;

    rc = d->bus.write_reg(d->bus.ctx, MAX30102_ADDR, MAX30102_REG_TEMP_CFG, &cfg, 1);
    if (rc) return MAX30102_ERR_BUS;
    if (d->bus.delay_ms) d->bus.delay_ms(d->bus.ctx, 30);
    if ((rc = rd(d, MAX30102_REG_TEMP_INT, &ti, 1))) return rc;
    if ((rc = rd(d, MAX30102_REG_TEMP_FRAC, &tf, 1))) return rc;
    /* integer part is signed; fraction is 0.0625 C per count (low nibble) */
    *t_x10 = (int)(int8_t)ti * 10 + ((int)(tf & 0x0F) * 625) / 1000;
    return 0;
}
