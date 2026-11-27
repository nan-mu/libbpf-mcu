#!/usr/bin/env bash
# Link a standalone C source and runtime for the Sail RV32 simulator.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CLANG="${CLANG:-/opt/homebrew/opt/llvm/bin/clang}"
SOURCE="${1:?Usage: build.sh path/to/sail-fixture.c}"
OUT_DIR="${OUT_DIR:-$ROOT/build/sail}"
OUT_ELF="${OUT_ELF:-$OUT_DIR/sail-rv32.elf}"

mkdir -p "$OUT_DIR"
"$CLANG" -c \
  --target=riscv32-unknown-none-elf -march=rv32imc -mabi=ilp32 \
  -O2 -mcmodel=medany -mno-relax \
  -nostdlib -ffreestanding -fno-builtin -fno-exceptions \
  -fno-asynchronous-unwind-tables \
  -I "$ROOT/include" -include vmlinux.h \
  "$SOURCE" -o "$OUT_DIR/sail-program.o"

"$CLANG" -c \
  --target=riscv32-unknown-none-elf -march=rv32imc -mabi=ilp32 \
  -O2 -mcmodel=medany -mno-relax \
  -nostdlib -ffreestanding -fno-builtin -fno-exceptions \
  -fno-asynchronous-unwind-tables \
  "$ROOT/linker/sail/runtime.c" -o "$OUT_DIR/sail-runtime.o"

"$CLANG" \
  --target=riscv32-unknown-none-elf -march=rv32imc -mabi=ilp32 \
  -nostdlib -ffreestanding -fuse-ld=lld -mno-relax \
  -Wl,-T,"$ROOT/linker/sail/sail-rv32.ld" \
  -Wl,--build-id=none -Wl,--no-pie \
  "$OUT_DIR/sail-program.o" "$OUT_DIR/sail-runtime.o" \
  -o "$OUT_ELF"

echo "$OUT_ELF"
