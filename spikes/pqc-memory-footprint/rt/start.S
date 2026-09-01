/*
 * Reset entry for the footprint spike. QEMU (-bios none -kernel <elf>) loads
 * the image at the RAM base and jumps there, so _start must be first in
 * .text.init. Single hart, no trap handling.
 */

    .section .text.init, "ax", @progbits
    .global _start
_start:
    la      sp, _stack_top

    /* zero .bss */
    la      t0, _bss_start
    la      t1, _bss_end
1:
    bgeu    t0, t1, 2f
    sw      zero, 0(t0)
    addi    t0, t0, 4
    j       1b
2:
    call    main
3:
    wfi
    j       3b
