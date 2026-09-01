#ifndef SPIKE_RT_H
#define SPIKE_RT_H

#include <stddef.h>
#include <stdint.h>

/* Freestanding libc shims (defined in rt.c). */
void *memcpy(void *dst, const void *src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);

/* UART (NS16550A on QEMU 'virt'). */
void uart_puts(const char *s);
void uart_putu(uint32_t v);       /* unsigned decimal */
void uart_puthex(uint32_t v);

/* Exit QEMU via the SiFive test finisher: 0 -> pass, nonzero -> fail(code). */
void spike_finish(int code);

/* Stack painting / high-water measurement.
 *
 * paint_below(sp) fills [_stack_limit, sp) with a sentinel word.
 * used_below(sp) returns sp minus the lowest address that no longer holds the
 * sentinel, i.e. the number of stack bytes consumed beneath sp.
 */
void     stack_paint_below(uintptr_t sp);
uint32_t stack_used_below(uintptr_t sp);

/* Heap high-water mark (PQClean fips202 allocates Keccak state). */
uint32_t rt_heap_hwm(void);

static inline uintptr_t read_sp(void)
{
    uintptr_t s;
    __asm__ volatile("mv %0, sp" : "=r"(s));
    return s;
}

#endif /* SPIKE_RT_H */
