#!/bin/sh
# C -> eBPF -> RV32IM -> Compact ELF V0, in one command.
#
# FIRMWARE must be a linked firmware ELF carrying `.xpost.mem`; it supplies the
# slot address, slot capacity and helper address. The exit status is the number
# of programs that failed to produce an accepted container. A program too large
# for the slot is reported as a failure with its size, never truncated.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
CLANG="${CLANG:-clang}"
OBJDUMP="${OBJDUMP:-llvm-objdump}"
FIRMWARE="${FIRMWARE:?set FIRMWARE to a linked firmware ELF with .xpost.mem}"
NAMES="${NAMES:-div2 xdp_drop case_mark just_drop just_tx firewall bitswap bsort}"
HOST_TARGET="${HOST_TARGET:-aarch64-apple-darwin}"

PREVAIL="${PREVAIL:-$ROOT/prevail/bin/prevail}"
if [ ! -x "$PREVAIL" ]; then
  MAIN=$(dirname "$(git -C "$ROOT" rev-parse --path-format=absolute --git-common-dir)")
  PREVAIL="$MAIN/prevail/bin/prevail"
fi
if [ ! -x "$PREVAIL" ]; then
  echo "PREVAIL is not executable; set PREVAIL to a built prevail binary" >&2
  exit 3
fi
export PREVAIL

TOOLS="$ROOT/tools/target/$HOST_TARGET/release/xpost-mcu-elf"
CARGO_TARGET_DIR="$ROOT/tools/target" cargo build --quiet \
  --manifest-path "$ROOT/tools/Cargo.toml" --release --target "$HOST_TARGET" \
  --bin xpost-mcu-elf

OUT="$ROOT/build/jit-elf"
mkdir -p "$OUT"
printf 'program\tprevail\telf\timage_bytes\tcontainer_bytes\tdetail\n' > "$OUT/report.tsv"
fail=0
for name in $NAMES; do
  src="$ROOT/tests/xdp/$name.c"
  obj="$OUT/$name.bpf.o"
  "$CLANG" --target=bpf -O2 -g -Wall -Wno-missing-declarations -fno-stack-protector \
    -I "$ROOT/include-bpf" -include vmlinux.h -c "$src" -o "$obj"
  python3 "$ROOT/make/obj_report.py" --obj "$obj" --src "$src" \
    --out "$OUT/$name.bpf.toml" --objdump "$OBJDUMP" --btf \
    >"$OUT/$name.report.out" 2>&1 || true

  set +e
  python3 "$ROOT/make/prevail_gate.py" --obj "$obj" --stamp "$OUT/$name.prevail.ok" \
    >"$OUT/$name.prevail.out" 2>&1
  prev=$?
  set -e
  if [ "$prev" -eq 0 ]; then prevail=pass; else prevail=fail; fi

  set +e
  "$TOOLS" pack-jit --firmware "$FIRMWARE" --obj "$obj" \
    --bpf-toml "$OUT/$name.bpf.toml" --name "$name" \
    -o "$OUT/$name.elf" >"$OUT/$name.pack.out" 2>"$OUT/$name.pack.err"
  code=$?
  set -e
  if [ "$code" -eq 0 ]; then
    elf=pass
    image=$(sed -n 's/.*image_len=\([0-9]*\).*/\1/p' "$OUT/$name.pack.err")
    container=$(wc -c <"$OUT/$name.elf" | tr -d ' ')
    detail=$(cat "$OUT/$name.pack.err")
  else
    elf=fail
    image=-
    container=-
    detail=$(cat "$OUT/$name.pack.err")
    fail=$((fail + 1))
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$name" "$prevail" "$elf" "$image" "$container" "$detail" >> "$OUT/report.tsv"
done
cat "$OUT/report.tsv"
exit "$fail"