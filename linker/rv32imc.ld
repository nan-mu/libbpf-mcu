/* RV32IMC ILP32 slot layout. */
helper_dispatcher = @HELPER@;
MEMORY { HOT_REGION (rwx) : ORIGIN = @BASE@, LENGTH = @LENGTH@ }
ENTRY(_start)
SECTIONS
{
    .xdp : ALIGN(4) { _start = .; *(xdp) *(xdp1) *(.xdp) *(.xdp.*) } > HOT_REGION
    .text : ALIGN(4) { *(.text) *(.text.*) } > HOT_REGION
    .rodata : ALIGN(4) { *(.rodata) *(.rodata.*) *(.srodata) *(.srodata.*) *(license) } > HOT_REGION
    .maps : ALIGN(4) { *(.maps) *(maps) } > HOT_REGION
    .data : ALIGN(4) { *(.data) *(.data.*) *(.sdata) *(.sdata.*) } > HOT_REGION
    .bss : ALIGN(4) { *(.bss) *(.bss.*) *(.sbss) *(.sbss.*) *(COMMON) } > HOT_REGION
    /DISCARD/ : { *(.eh_frame) *(.comment) *(.note*) *(.riscv.attributes) *(.relaxdp) }
}
