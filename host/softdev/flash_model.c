#include "flash_model.h"

#include "rot/rot_flash_map.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int flash_model_init(flash_model *f, size_t size)
{
    f->mem = malloc(size);
    if (!f->mem) {
        return -1;
    }
    memset(f->mem, 0xFF, size);
    f->size = size;
    f->budget = -1;
    f->dead = 0;
    f->spent = 0;
    f->erases = 0;
    return 0;
}

void flash_model_free(flash_model *f)
{
    free(f->mem);
    f->mem = NULL;
}

void flash_model_arm_cut(flash_model *f, int64_t units)
{
    f->budget = units;
    f->dead = 0;
}

void flash_model_disarm(flash_model *f)
{
    f->budget = -1;
}

void flash_model_power_on(flash_model *f)
{
    f->dead = 0;
    f->budget = -1;
}

/* Units this operation may still use; -1 if unlimited. */
static int64_t allowance(const flash_model *f, int64_t want)
{
    if (f->budget < 0) {
        return want;
    }
    return f->budget < want ? f->budget : want;
}

static void spend(flash_model *f, int64_t units)
{
    f->spent += (uint64_t)units;
    if (f->budget >= 0) {
        f->budget -= units;
    }
}

static int fm_read(void *ctx, uint32_t off, uint8_t *buf, size_t n)
{
    flash_model *f = ctx;
    if ((uint64_t)off + n > f->size) {
        return ROT_E_RANGE;
    }
    memcpy(buf, f->mem + off, n);
    return 0;
}

static int fm_erase(void *ctx, uint32_t off, size_t len)
{
    flash_model *f = ctx;
    if (f->dead) {
        return ROT_E_FLASH;
    }
    if ((off % ROT_FLASH_SECTOR) || (len % ROT_FLASH_SECTOR) || (uint64_t)off + len > f->size) {
        return ROT_E_RANGE;
    }
    for (size_t s = 0; s < len; s += ROT_FLASH_SECTOR) {
        int64_t units = ROT_FLASH_SECTOR / 256;
        int64_t ok = allowance(f, units);
        memset(f->mem + off + s, 0xFF, (size_t)ok * 256);
        spend(f, ok);
        if (ok < units) {
            f->dead = 1;
            return ROT_E_FLASH;
        }
        f->erases++;
    }
    return 0;
}

static int fm_write(void *ctx, uint32_t off, const uint8_t *buf, size_t n)
{
    flash_model *f = ctx;
    if (f->dead) {
        return ROT_E_FLASH;
    }
    if ((uint64_t)off + n > f->size) {
        return ROT_E_RANGE;
    }
    int64_t ok = allowance(f, (int64_t)n);
    for (int64_t i = 0; i < ok; i++) {
        f->mem[off + (size_t)i] &= buf[i];
    }
    spend(f, ok);
    if ((size_t)ok < n) {
        f->dead = 1;
        return ROT_E_FLASH;
    }
    return 0;
}

static uint64_t tstate = 0x243F6A8885A308D3ull;

static void fm_trng(void *ctx, uint8_t *buf, size_t n)
{
    (void)ctx;
    for (size_t i = 0; i < n; i++) {
        tstate ^= tstate << 13;
        tstate ^= tstate >> 7;
        tstate ^= tstate << 17;
        buf[i] = (uint8_t)(tstate >> 24);
    }
}

static uint64_t fm_cycles(void *ctx)
{
    return ((flash_model *)ctx)->spent;
}

static const uint8_t *fm_xip(void *ctx, uint32_t off)
{
    flash_model *f = ctx;
    return off < f->size ? f->mem + off : NULL;
}

static void fm_wdt(void *ctx)
{
    (void)ctx;
}

void flash_model_platform(flash_model *f, rot_platform *p)
{
    p->ctx = f;
    p->flash_read = fm_read;
    p->flash_erase = fm_erase;
    p->flash_write = fm_write;
    p->flash_xip = fm_xip;
    p->log = NULL;
    p->trng_raw = fm_trng;
    p->cycles = fm_cycles;
    p->wdt_feed = fm_wdt;
}

int flash_model_load(flash_model *f, const char *path)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        return -1;
    }
    size_t n = fread(f->mem, 1, f->size, fp);
    fclose(fp);
    return n == f->size ? 0 : -1;
}

int flash_model_save(const flash_model *f, const char *path)
{
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        return -1;
    }
    size_t n = fwrite(f->mem, 1, f->size, fp);
    fclose(fp);
    return n == f->size ? 0 : -1;
}
