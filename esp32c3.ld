/* payload.ld - ESP32-C3 AOT 热加载专属链接器脚本 */

helper_dispatcher = 0x403A0000;

/* 
 * 【警告】这里的 ORIGIN 必须与你 ESP-IDF 主固件中分配的 aot_payload_buffer 地址严格一致！
 * 假设你的主固件分配到了 0x40381100 (SRAM 1 区域)，预留大小为 4KB (4096 Bytes)。
 */
MEMORY
{
    /* 统一的热加载区域 */
    HOT_REGION (rwx) : ORIGIN = 0x403A1000, LENGTH = 4K - 512
}

SECTIONS
{
    /* 1. 代码段 (.xdp) - 放在最前面，单片机强转指针跳转的入口 */
    .xdp : ALIGN(4) {
        *(.xdp)
        *(.xdp.*)
    } > HOT_REGION

    /* 2. 代码段 (.text) - 可能存在的其他函数 */
    .text : ALIGN(4) {
        *(.text)
        *(.text.*)
    } > HOT_REGION

    /* 3. 只读数据段 (.rodata) - 存放你的长字符串常量等 */
    .rodata : ALIGN(4) {
        *(.rodata)
        *(.rodata.*)
        *(.srodata)
        *(.srodata.*)
        *(license)  /* license 字符串也是只读的 */
    } > HOT_REGION

    /* 4. 已初始化数据段 (.data) - 带有初始值的全局/静态变量 */
    .data : ALIGN(4) {
        *(.data)
        *(.data.*)
        *(.sdata)
        *(.sdata.*)
    } > HOT_REGION

    /* 5. 未初始化数据段 (.bss) - 提取 bin 时会被剥离，单片机依赖 Footer 的大小来进行 memset 清零 */
    .bss : ALIGN(4) {
        *(.bss)
        *(.bss.*)
        *(.sbss)
        *(.sbss.*)
        *(COMMON)
    } > HOT_REGION

    /* 6. 垃圾桶 - 丢弃所有对裸机执行无用的编译器元数据，防止干扰文件结构 */
    /DISCARD/ : {
        *(.eh_frame)
        *(.comment)
        *(.note*)
        *(.riscv.attributes)
    }
}