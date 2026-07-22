/* Auto-generated from firmware/mem_map.toml — do not edit by hand.
 * helper_dispatcher @ 0x40380000, HOT_REGION @ 0x40381000 len 0x1000
 */

helper_dispatcher = 0x40380000;

/*
 * ORIGIN/LENGTH must match firmware HOT_REGION placeholder
 * (`mem_map.toml` / `.iram1.hotload_area`).
 */
MEMORY
{
    HOT_REGION (rwx) : ORIGIN = 0x40381000, LENGTH = 0x1000
}

/*
 * Firmware jalr's HOT_REGION base — not a CRT. Define `_start` at `.xdp`
 * so LLD has an entry symbol and e_entry matches the load address.
 */
ENTRY(_start)

SECTIONS
{
    .xdp : ALIGN(4) {
        _start = .;
        *(xdp)
        *(.xdp)
        *(.xdp.*)
    } > HOT_REGION

    .text : ALIGN(4) {
        *(.text)
        *(.text.*)
    } > HOT_REGION

    .rodata : ALIGN(4) {
        *(.rodata)
        *(.rodata.*)
        *(.srodata)
        *(.srodata.*)
        *(license)
    } > HOT_REGION

    .maps : ALIGN(4) {
        *(.maps)
    } > HOT_REGION

    .data : ALIGN(4) {
        *(.data)
        *(.data.*)
        *(.sdata)
        *(.sdata.*)
    } > HOT_REGION

    .bss : ALIGN(4) {
        *(.bss)
        *(.bss.*)
        *(.sbss)
        *(.sbss.*)
        *(COMMON)
    } > HOT_REGION

    /DISCARD/ : {
        *(.eh_frame)
        *(.comment)
        *(.note*)
        *(.riscv.attributes)
        *(.relaxdp)
    }
}
