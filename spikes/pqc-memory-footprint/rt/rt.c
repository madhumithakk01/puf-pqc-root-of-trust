/*
 * Minimal freestanding runtime for the footprint spike: libc shims the PQClean
 * reference C needs, a UART for reporting, a deterministic randombytes, and the
 * stack painting helpers.
 *
 * This file is linked into every spike image. Its own footprint is measured by
 * the `baseline` image and subtracted out in the results.
 */

#include "rt/rt.h"

#include "fips202.h"
#include "randombytes.h"

#include <stdlib.h>

/* --- libc shims (-nostdlib; the compiler and PQClean still emit these) --- */

void *memcpy(void *dst, const void *src, size_t n)
{
    uint8_t *d = dst;
    const uint8_t *s = src;
    while (n--) {
        *d++ = *s++;
    }
    return dst;
}

void *memset(void *dst, int c, size_t n)
{
    uint8_t *d = dst;
    while (n--) {
        *d++ = (uint8_t)c;
    }
    return dst;
}

int memcmp(const void *a, const void *b, size_t n)
{
    const uint8_t *x = a, *y = b;
    for (size_t i = 0; i < n; i++) {
        if (x[i] != y[i]) {
            return (int)x[i] - (int)y[i];
        }
    }
    return 0;
}

void *memmove(void *dst, const void *src, size_t n)
{
    uint8_t *d = dst;
    const uint8_t *s = src;
    if (d < s) {
        while (n--) {
            *d++ = *s++;
        }
    } else {
        d += n;
        s += n;
        while (n--) {
            *--d = *--s;
        }
    }
    return dst;
}

/* --- UART --- */

#define UART0_BASE    0x10000000u
#define UART_THR      0u
#define UART_LSR      5u
#define UART_LSR_THRE 0x20u

static volatile uint8_t *const uart = (volatile uint8_t *)UART0_BASE;

static void uart_putc(char c)
{
    while ((uart[UART_LSR] & UART_LSR_THRE) == 0u) {
    }
    uart[UART_THR] = (uint8_t)c;
}

void uart_puts(const char *s)
{
    for (; *s != '\0'; ++s) {
        if (*s == '\n') {
            uart_putc('\r');
        }
        uart_putc(*s);
    }
}

void uart_putu(uint32_t v)
{
    char buf[10];
    int i = 0;
    if (v == 0) {
        uart_putc('0');
        return;
    }
    while (v > 0) {
        buf[i++] = (char)('0' + (v % 10));
        v /= 10;
    }
    while (i > 0) {
        uart_putc(buf[--i]);
    }
}

void uart_puthex(uint32_t v)
{
    static const char d[] = "0123456789abcdef";
    uart_puts("0x");
    for (int s = 28; s >= 0; s -= 4) {
        uart_putc(d[(v >> s) & 0xf]);
    }
}

/* --- exit --- */

#define SYSCON_TEST 0x100000u

void spike_finish(int code)
{
    volatile uint32_t *t = (volatile uint32_t *)SYSCON_TEST;
    *t = (code == 0) ? 0x5555u : (((uint32_t)code << 16) | 0x3333u);
    for (;;) {
    }
}

void exit(int code)
{
    spike_finish(code);
    for (;;) {
    }
}

/* --- heap ---
 *
 * PQClean's reference fips202 heap-allocates every Keccak context
 * (PQC_SHAKEINCCTX_BYTES = 208, PQC_SHAKECTX_BYTES = 200). Scheme code uses
 * them strictly nested, so a LIFO bump allocator is exact and its peak is the
 * heap high-water mark. rt_heap_hwm() reports that; the results treat it as
 * part of RAM alongside stack and static data. A production embedded port
 * would make these static/stack instead (this spike does not modify the
 * reference C).
 */

#define HEAP_ARENA_BYTES 8192

static uint8_t heap_arena[HEAP_ARENA_BYTES] __attribute__((aligned(16)));
static size_t heap_top = 0;
static size_t heap_hwm = 0;

void *malloc(size_t n)
{
    size_t aligned = (n + 15u) & ~(size_t)15u;
    if (heap_top + aligned + 16u > HEAP_ARENA_BYTES) {
        return NULL;
    }
    /* store the block size in the 16 bytes preceding the returned pointer */
    size_t *hdr = (size_t *)(heap_arena + heap_top);
    *hdr = aligned;
    void *p = heap_arena + heap_top + 16u;
    heap_top += aligned + 16u;
    if (heap_top > heap_hwm) {
        heap_hwm = heap_top;
    }
    return p;
}

void free(void *p)
{
    if (p == NULL) {
        return;
    }
    uint8_t *block = (uint8_t *)p - 16u;
    size_t *hdr = (size_t *)block;
    size_t total = *hdr + 16u;
    /* LIFO fast path; out-of-order frees just leak until the arena unwinds */
    if (block + total == heap_arena + heap_top) {
        heap_top -= total;
    }
}

uint32_t rt_heap_hwm(void)
{
    return (uint32_t)heap_hwm;
}

/* --- deterministic randombytes: a fixed-seed SHAKE256 stream --- */

static shake256incctx drbg;
static int drbg_ready = 0;

int randombytes(uint8_t *output, size_t n)
{
    if (!drbg_ready) {
        static const uint8_t seed[32] = {
            's', 'p', 'i', 'k', 'e', '-', 'p', 'q', 'c', '-', 'f', 'o', 'o', 't',
            'p', 'r', 'i', 'n', 't', '-', 'd', 'r', 'b', 'g', '-', 'v', '1', 0,
            0, 0, 0, 0
        };
        shake256_inc_init(&drbg);
        shake256_inc_absorb(&drbg, seed, sizeof seed);
        shake256_inc_finalize(&drbg);
        drbg_ready = 1;
    }
    shake256_inc_squeeze(output, n, &drbg);
    return 0;
}

/* --- stack painting --- */

#define PAINT 0x5a5a5a5au

extern uint32_t _stack_limit;
extern uint32_t _stack_top;

void stack_paint_below(uintptr_t sp)
{
    uint32_t *p   = (uint32_t *)&_stack_limit;
    uint32_t *end = (uint32_t *)(sp & ~(uintptr_t)3);
    while (p < end) {
        *p++ = PAINT;
    }
}

uint32_t stack_used_below(uintptr_t sp)
{
    const uint32_t *base = (const uint32_t *)&_stack_limit;
    const uint32_t *top  = (const uint32_t *)(sp & ~(uintptr_t)3);

    /* first word from the bottom that is no longer the sentinel; require two in
     * a row so a lone coincidental 0x5a5a5a5a written by the callee is ignored */
    for (const uint32_t *p = base; p + 1 < top; p++) {
        if (p[0] != PAINT && p[1] != PAINT) {
            return (uint32_t)(sp - (uintptr_t)p);
        }
    }
    return 0;
}
