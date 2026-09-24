/* Temporary sail-riscv host link layout (RV32IMC).
 * RAM matches sail default MainMemory base 0x80000000.
 * Not the ESP32-C3 HOT_REGION / firmware contract.
 */

OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY
{
    RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 1M
}

SECTIONS
{
    .text : ALIGN(4) {
        KEEP(*(.text._start))
        *(.text)
        *(.text.*)
        *(xdp)
        *(xdp1)
        *(.xdp)
        *(.xdp.*)
    } > RAM

    .rodata : ALIGN(4) {
        *(.rodata)
        *(.rodata.*)
        *(.srodata)
        *(.srodata.*)
        *(license)
    } > RAM

    .maps : ALIGN(4) {
        *(.maps)
        *(maps)
    } > RAM

    .data : ALIGN(4) {
        *(.data)
        *(.data.*)
        *(.sdata)
        *(.sdata.*)
        KEEP(*(.tohost))
    } > RAM

    .bss : ALIGN(4) {
        *(.bss)
        *(.bss.*)
        *(.sbss)
        *(.sbss.*)
        *(COMMON)
        . = ALIGN(16);
        _stack_bottom = .;
        . = . + 0x4000;
        _stack_top = .;
    } > RAM

    /DISCARD/ : {
        *(.eh_frame)
        *(.comment)
        *(.note*)
        *(.riscv.attributes)
        *(.relaxdp)
    }
}
