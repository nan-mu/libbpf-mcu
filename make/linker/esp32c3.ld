/* payload.ld - ESP32-C3 AOT 热加载专属链接器脚本 */

helper_dispatcher = 0x403A0000;

/*
 * 【警告】这里的 ORIGIN 必须与主固件中分配的 aot_payload_buffer 地址严格一致！
 * 当前：HOT_REGION @ 0x403A1000，长度 4K-512。
 */
MEMORY
{
    HOT_REGION (rwx) : ORIGIN = 0x403A1000, LENGTH = 4K - 512
}

SECTIONS
{
    /* SEC("xdp") → 节名 "xdp"（无点号）；兼容 .xdp / .xdp.* */
    .xdp : ALIGN(4) {
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

    /* SEC(".maps") map 描述符占位；固件侧另有绝对地址语义 */
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
