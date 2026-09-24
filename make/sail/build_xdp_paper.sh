#!/usr/bin/env bash
# Temporary: build tests/xdp/xdp_paper.c as a sail-riscv-loadable RV32 ELF.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CLANG="${CLANG:-/opt/homebrew/opt/llvm/bin/clang}"
OUT_DIR="${OUT_DIR:-$ROOT/../build/xdp_paper}"
OUT_ELF="${OUT_ELF:-$OUT_DIR/sail-rv32.elf}"

mkdir -p "$OUT_DIR"
"$CLANG" -c \
  --target=riscv32-unknown-none-elf -march=rv32imc -mabi=ilp32 \
  -O2 -mcmodel=medany -mno-relax \
  -nostdlib -ffreestanding -fno-builtin -fno-exceptions \
  -fno-asynchronous-unwind-tables \
  -I "$ROOT/include" -include vmlinux.h \
  "$ROOT/tests/xdp/xdp_paper.c" -o "$OUT_DIR/sail-xdp_paper.o"

"$CLANG" -c \
  --target=riscv32-unknown-none-elf -march=rv32imc -mabi=ilp32 \
  -O2 -mcmodel=medany -mno-relax \
  -nostdlib -ffreestanding -fno-builtin -fno-exceptions \
  -fno-asynchronous-unwind-tables \
  "$ROOT/make/sail/runtime.c" -o "$OUT_DIR/sail-runtime.o"

"$CLANG" \
  --target=riscv32-unknown-none-elf -march=rv32imc -mabi=ilp32 \
  -nostdlib -ffreestanding -fuse-ld=lld -mno-relax \
  -Wl,-T,"$ROOT/make/linker/sail-rv32.ld" \
  -Wl,--build-id=none -Wl,--no-pie \
  "$OUT_DIR/sail-xdp_paper.o" "$OUT_DIR/sail-runtime.o" \
  -o "$OUT_ELF"

echo "$OUT_ELF"
