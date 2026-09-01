#ifndef ROT_INTEGRATION_RT_H
#define ROT_INTEGRATION_RT_H

#include <stddef.h>
#include <stdint.h>

void *memcpy(void *dst, const void *src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);

void uart_puts(const char *s);
void uart_putu(uint32_t v);

/* exit QEMU: 0 pass, nonzero fail(code) */
void rt_exit(int code);

/* retired-instruction counter (M-mode rdinstret) -- deterministic in QEMU for
 * deterministic code, unlike rdcycle which tracks host time */
static inline uint32_t rt_instret(void)
{
    uint32_t c;
    __asm__ volatile("rdinstret %0" : "=r"(c));
    return c;
}

uint32_t rt_heap_hwm(void);

#endif /* ROT_INTEGRATION_RT_H */
