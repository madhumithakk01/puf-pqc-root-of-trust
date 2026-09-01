/*
 * Reset entry for the QEMU 'virt' RV32 machine.
 *
 * QEMU (-bios none -kernel <elf>) loads the image at the RAM base (0x80000000)
 * and jumps there. _start must therefore be the first byte of .text.init, which
 * the linker script places at ORIGIN(RAM). Single hart; no trap handling needed
 * for the scaffold.
 */

    .section .text.init, "ax", @progbits
    .global _start
_start:
    /* Set up the stack. */
    la      sp, _stack_top

    /* Zero .bss. */
    la      t0, _bss_start
    la      t1, _bss_end
1:
    bgeu    t0, t1, 2f
    sw      zero, 0(t0)
    addi    t0, t0, 4
    j       1b
2:
    call    main

    /* main() returning is not expected; park the hart. */
3:
    wfi
    j       3b
