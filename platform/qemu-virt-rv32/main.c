/*
 * Minimal boot image for the QEMU 'virt' RV32 machine: write a banner to the
 * NS16550A UART, then signal a clean exit through the SiFive test finisher so
 * the run has a deterministic exit code for CI.
 */

#include <stdint.h>

/* NS16550A UART on QEMU 'virt', byte-wide registers, no address shift. */
#define UART0_BASE      0x10000000u
#define UART_THR        0u
#define UART_LSR        5u
#define UART_LSR_THRE   0x20u

/* SiFive test finisher on QEMU 'virt'. */
#define SYSCON_TEST     0x100000u
#define TEST_PASS       0x5555u

static volatile uint8_t *const uart = (volatile uint8_t *)UART0_BASE;
static volatile uint32_t *const test = (volatile uint32_t *)SYSCON_TEST;

static void uart_putc(char c)
{
    while ((uart[UART_LSR] & UART_LSR_THRE) == 0u) {
    }
    uart[UART_THR] = (uint8_t)c;
}

static void uart_puts(const char *s)
{
    for (; *s != '\0'; ++s) {
        if (*s == '\n') {
            uart_putc('\r');
        }
        uart_putc(*s);
    }
}

int main(void)
{
    uart_puts("puf-pqc-root-of-trust: RV32 boot OK\n");
    *test = TEST_PASS;
    for (;;) {
    }
    return 0;
}
