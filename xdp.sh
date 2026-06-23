#!/usr/bin/env bash
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLANG="${CLANG:-clang}"
LIBBPF="$ROOT/libbpf"
VMLINUX="$LIBBPF/.github/actions/build-selftests/vmlinux.h"
SHIM="$ROOT/libbpf-mcu/.bpf-shim"

mkdir -p "$SHIM/bpf" "$SHIM/linux"
ln -sf "$LIBBPF/src/bpf_helpers.h" "$SHIM/bpf/bpf_helpers.h"

cat > "$SHIM/linux/types.h" <<'EOF'
#ifndef __LINUX_TYPES_H
#define __LINUX_TYPES_H
#endif
EOF

cat > "$SHIM/linux/bpf.h" <<'EOF'
#ifndef __LINUX_BPF_H__
#define __LINUX_BPF_H__
#include <linux/types.h>
#include <linux/bpf_common.h>
#endif
EOF

SRC="$1"
OUT="${2:-${SRC%.c}.o}"

exec "$CLANG" \
  -g -O2 --target=bpf \
  -Wall -Wno-missing-declarations -fno-stack-protector \
  -I"$SHIM" \
  -I"$LIBBPF/src" \
  -I"$LIBBPF/include/uapi" \
  --include "$VMLINUX" \
  -c "$SRC" -o "$OUT"