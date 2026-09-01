/*
 * RV32 link script for the footprint spike, QEMU 'virt', run in place from the
 * RAM base. Same target as platform/qemu-virt-rv32 but with a large, explicitly
 * bounded stack region so the harness can paint it and locate the high-water
 * mark.
 */

OUTPUT_ARCH("riscv")
OUTPUT_FORMAT("elf32-littleriscv")
ENTRY(_start)

MEMORY
{
    RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 16M
}

STACK_SIZE = 1M;

SECTIONS
{
    . = ORIGIN(RAM);

    .text : {
        KEEP(*(.text.init))
        *(.text .text.*)
    } > RAM

    .rodata : {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    } > RAM

    .data : {
        *(.data .data.*)
        *(.sdata .sdata.*)
    } > RAM

    .bss (NOLOAD) : {
        . = ALIGN(16);
        _bss_start = .;
        *(.sbss .sbss.*)
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        _bss_end = .;
    } > RAM

    . = ALIGN(16);
    _stack_limit = .;
    . = . + STACK_SIZE;
    _stack_top = .;

    /DISCARD/ : {
        *(.comment)
        *(.note .note.*)
        *(.eh_frame)
    }
}
