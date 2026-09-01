/*
 * Freestanding runtime for the integrated boot image: libc shims the vendored
 * reference C needs, a UART, an exit path, and a LIFO heap arena for PQClean's
 * fips202 Keccak contexts.
 */

#include "rt/rt.h"

#include <stdlib.h>

/* --- mem* --- */

void *memcpy(void *dst, const void *src, size_t n)
{
    uint8_t *d = dst;
    const uint8_t *s = src;
    while (n--) {
        *d++ = *s++;
    }
    return dst;
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

/* --- UART (NS16550A on QEMU virt) --- */

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
    for (; *s; ++s) {
        if (*s == '\n') {
            uart_putc('\r');
        }
        uart_putc(*s);
    }
}

void uart_putu(uint32_t v)
{
    char b[10];
    int i = 0;
    if (v == 0) {
        uart_putc('0');
        return;
    }
    while (v) {
        b[i++] = (char)('0' + v % 10);
        v /= 10;
    }
    while (i) {
        uart_putc(b[--i]);
    }
}

/* --- exit --- */

#define SYSCON_TEST 0x100000u

void rt_exit(int code)
{
    volatile uint32_t *t = (volatile uint32_t *)SYSCON_TEST;
    *t = (code == 0) ? 0x5555u : (((uint32_t)code << 16) | 0x3333u);
    for (;;) {
    }
}

void exit(int code)
{
    rt_exit(code);
    for (;;) {
    }
}

/* --- heap: LIFO arena for fips202 Keccak contexts --- */

#define HEAP_ARENA_BYTES 32768

static uint8_t heap_arena[HEAP_ARENA_BYTES] __attribute__((aligned(16)));
static size_t heap_top = 0;
static size_t heap_hwm = 0;

void *malloc(size_t n)
{
    size_t need = ((n + 15u) & ~(size_t)15u) + 16u;
    if (heap_top + need > HEAP_ARENA_BYTES) {
        return NULL;
    }
    size_t *hdr = (size_t *)(heap_arena + heap_top);
    *hdr = need;
    void *p = heap_arena + heap_top + 16u;
    heap_top += need;
    if (heap_top > heap_hwm) {
        heap_hwm = heap_top;
    }
    return p;
}

void free(void *p)
{
    if (!p) {
        return;
    }
    uint8_t *block = (uint8_t *)p - 16u;
    size_t total = *(size_t *)block;
    if (block + total == heap_arena + heap_top) {
        heap_top -= total;
    }
}

uint32_t rt_heap_hwm(void)
{
    return (uint32_t)heap_hwm;
}
