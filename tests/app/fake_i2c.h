#ifndef TESTS_FAKE_I2C_H
#define TESTS_FAKE_I2C_H

/*
 * Fake MAX30102 on an I2C bus: register file, reset bit, 32-entry FIFO.
 * Shared by the driver tests and the self-test.
 */

#include "sensor/max30102.h"

#include <stdint.h>
#include <string.h>

typedef struct {
    uint8_t regs[256];
    uint8_t fifo[32][6];
    uint8_t wr, rd, ovf;
    int fail_writes;       /* fail every write after this many (0 = never) */
    int writes;
    int reset_sticks;      /* the reset bit never clears */
    int bad_addr_seen;
    unsigned delays;
} fake_t;

static inline void fake_reset(fake_t *f)
{
    memset(f, 0, sizeof *f);
    f->regs[MAX30102_REG_PART_ID] = MAX30102_PART_ID;
    f->regs[MAX30102_REG_REV_ID] = 0x03;
}

static inline int fk_write(void *ctx, uint8_t addr, uint8_t reg, const uint8_t *d, size_t n)
{
    fake_t *f = ctx;
    if (addr != MAX30102_ADDR) { f->bad_addr_seen = 1; return -1; }
    if (f->fail_writes && ++f->writes > f->fail_writes) return -1;
    for (size_t i = 0; i < n; i++) {
        uint8_t r = (uint8_t)(reg + i);
        if (r == MAX30102_REG_MODE && (d[i] & 0x40) && !f->reset_sticks) {
            uint8_t part = f->regs[MAX30102_REG_PART_ID];
            memset(f->regs, 0, sizeof f->regs);
            f->regs[MAX30102_REG_PART_ID] = part;
            f->regs[MAX30102_REG_REV_ID] = 0x03;
            f->wr = f->rd = f->ovf = 0;
            continue;
        }
        if (r == MAX30102_REG_FIFO_WR) { f->wr = d[i] & 31; continue; }
        if (r == MAX30102_REG_FIFO_OVF) { f->ovf = d[i]; continue; }
        if (r == MAX30102_REG_FIFO_RD) { f->rd = d[i] & 31; continue; }
        f->regs[r] = d[i];
    }
    return 0;
}

static inline int fk_read(void *ctx, uint8_t addr, uint8_t reg, uint8_t *d, size_t n)
{
    fake_t *f = ctx;
    if (addr != MAX30102_ADDR) { f->bad_addr_seen = 1; return -1; }
    for (size_t i = 0; i < n; i++) {
        uint8_t r = reg;
        if (reg != MAX30102_REG_FIFO_DATA) r = (uint8_t)(reg + i);
        if (r == MAX30102_REG_FIFO_WR) d[i] = f->wr;
        else if (r == MAX30102_REG_FIFO_OVF) d[i] = f->ovf;
        else if (r == MAX30102_REG_FIFO_RD) d[i] = f->rd;
        else if (r == MAX30102_REG_FIFO_DATA) {
            /* six bytes per sample, popped after the sixth */
            static unsigned phase;
            d[i] = f->fifo[f->rd][phase % 6];
            if (++phase % 6 == 0) f->rd = (f->rd + 1) & 31;
        } else d[i] = f->regs[r];
    }
    return 0;
}

static inline void fk_delay(void *ctx, unsigned ms)
{
    ((fake_t *)ctx)->delays += ms;
}

static inline void push(fake_t *f, uint32_t red, uint32_t ir)
{
    uint8_t *s = f->fifo[f->wr];
    s[0] = (uint8_t)(red >> 16); s[1] = (uint8_t)(red >> 8); s[2] = (uint8_t)red;
    s[3] = (uint8_t)(ir >> 16);  s[4] = (uint8_t)(ir >> 8);  s[5] = (uint8_t)ir;
    f->wr = (f->wr + 1) & 31;
    if (f->wr == f->rd) f->ovf = 1;
}

#endif
