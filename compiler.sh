#!/bin/bash
set -e # 遇到错误立即停止

CLANG=/opt/homebrew/opt/llvm/bin/clang
OBJCOPY=/opt/homebrew/opt/llvm/bin/llvm-objcopy
SIZE=/opt/homebrew/opt/llvm/bin/llvm-size
INPUT_FILE="$1"
filename="${INPUT_FILE##*/}"
TARGET=target/${filename%.c}

# 1. 使用 Clang 编译 C 文件为 ELF 目标文件
# -target riscv32 -march=rv32imc: 指定 ESP32-C3 的指令集
# -nostdlib -ffreestanding: 禁用标准库，生成纯裸机代码
# -O2: 开启优化
echo "[1/5] 正在编译 payload.c -> payload.elf..."

# 先编译成目标文件
$CLANG --target=riscv32 -march=rv32imc -O2 \
      -I inclued \
      -I inclued/bpf \
      -I inclued/linux \
      -O2 \
      -nostdlib -ffreestanding -fno-builtin \
      -c $INPUT_FILE -o $TARGET/payload.o

# 生成汇编代码
echo "[2/5] 生成汇编代码 -> payload.s..."
$CLANG --target=riscv32 -march=rv32imc -O2 \
      -I inclued \
      -I inclued/bpf \
      -I inclued/linux \
      -nostdlib -ffreestanding -fno-builtin \
      -S $INPUT_FILE -o $TARGET/payload.s

echo "      汇编代码已保存到: $TARGET/payload.s"

# 使用 RISC-V 工具链的链接器
echo "[3/5] 链接 payload.o -> payload.elf..."
RISCV_LD=""
if [ -x "$(which riscv32-unknown-elf-ld 2>/dev/null)" ]; then
    RISCV_LD="riscv32-unknown-elf-ld"
elif [ -x "$(which riscv64-unknown-elf-ld 2>/dev/null)" ]; then
    RISCV_LD="riscv64-unknown-elf-ld -m elf32lriscv"
elif [ -x "$(which riscv64-elf-ld 2>/dev/null)" ]; then
    RISCV_LD="riscv64-elf-ld -m elf32lriscv"
fi

if [ -z "$RISCV_LD" ]; then
    echo "[错误] 未找到 RISC-V 链接器"
    echo "请安装 RISC-V 工具链（选择其中一个）:"
    echo "  方案1（推荐）: brew install riscv64-elf-gcc"
    echo "  方案2: brew tap riscv-software-src/riscv && brew install riscv-tools"
    exit 1
fi

$RISCV_LD -T esp32c3.ld --no-warn-rwx-segments $TARGET/payload.o -o $TARGET/payload.elf

# 2. 从 ELF 中提取出纯净的裸二进制数据 (.text + .rodata + .data)
echo "[4/5] payload.elf -> payload.bin..."
$OBJCOPY -O binary $TARGET/payload.elf $TARGET/payload.bin

# 3. 提取我们需要的重要尺寸数据
# 获取 .bin 的实际文件大小 (Bytes)
echo "[5/5] 提取尺寸信息并验证..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    BIN_SIZE=$(stat -f%z "$TARGET/payload.bin")
else
    BIN_SIZE=$(stat -c%s "$TARGET/payload.bin")
fi

# 使用 llvm-size 提取 .bss 段的大小
# llvm-size 默认输出第二行第三列就是 bss 的十进制大小
BSS_SIZE=$($SIZE $TARGET/payload.elf | awk 'NR==2 {print $3}')

echo "      -> Bin 大小: $BIN_SIZE Bytes"
echo "      -> BSS 大小: $BSS_SIZE Bytes"

# 可选的安全检查：验证总大小是否超过了我们承诺的 4KB (4096)
TOTAL_SIZE=$((BIN_SIZE + BSS_SIZE))
if [ "$TOTAL_SIZE" -gt 4096 ]; then
    echo "[错误] 内存溢出！总大小 $TOTAL_SIZE 字节超过了 4KB 限制。"
    exit 1
fi

echo "✓ 编译成功！总大小: $TOTAL_SIZE Bytes"
