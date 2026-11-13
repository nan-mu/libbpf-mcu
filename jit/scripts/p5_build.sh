#!/bin/sh
# P5 build: three exec_bench firmwares (+ diag cross-check variants), and one
# container per workload per arm (AOT copy, JIT pack-jit, rBPF pack --map-index).
#
# Inputs are the canonical libbpf-mcu objects in /Volumes/SSD/bs/build/<p>/bpf.o,
# the same objects the AOT containers were compiled from. The xdp bytecode was
# verified byte-identical to the worktree tests/xdp sources.
#
# Nothing here writes to the xpost repo outside target/: cargo runs --locked and
# a sha256 guard proves the tracked files are unchanged afterwards.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
XPOST=/Volumes/SSD/bs/xpost
BUILD=/Volumes/SSD/bs/build
OUT="$ROOT/build/p5"
TOOLS="$ROOT/tools/target/aarch64-apple-darwin/release/xpost-mcu-elf"
WORKLOADS="incr square bitswap fib buf memcpy fletcher32 bsort"

mkdir -p "$OUT/fw" "$OUT/aot" "$OUT/jit" "$OUT/rbpf" "$OUT/logs"

GUARD="$OUT/logs/tracked-guard.txt"
guard_files() {
  sha256sum \
    "$XPOST/profiles.toml" \
    "$XPOST/Cargo.lock" \
    "$XPOST/examples/exec_bench/Cargo.lock" \
    "$XPOST/examples/exec_bench_hal/Cargo.lock" \
    "$XPOST/xpost-test/config/default.toml" \
    "$XPOST/xpost-test/config/exec_bench.toml" 2>/dev/null
}
guard_files > "$GUARD.before"

CARGO_TARGET_DIR="$ROOT/tools/target" cargo build --quiet \
  --manifest-path "$ROOT/tools/Cargo.toml" --release --target aarch64-apple-darwin \
  --bin xpost-mcu-elf

build_fw() {
  # build_fw <example-dir> <artifact-name> <out-name> [features...]
  dir=$1; art=$2; out=$3; shift 3
  if [ "$#" -gt 0 ]; then
    feat=$1; shift
    (cd "$dir" && cargo build --locked --release --features "$feat") \
      >"$OUT/logs/build-$out.log" 2>&1
  else
    (cd "$dir" && cargo build --locked --release) \
      >"$OUT/logs/build-$out.log" 2>&1
  fi
  cp "$dir/target/riscv32imc-unknown-none-elf/release/$art" "$OUT/fw/$out"
  echo "built $out"
}

EB="$XPOST/examples/exec_bench"
EH="$XPOST/examples/exec_bench_hal"
build_fw "$EB" exec_bench exec_bench_aot
build_fw "$EB" exec_bench exec_bench_rbpf interp
build_fw "$EB" exec_bench exec_bench_aot_diag diag
build_fw "$EB" exec_bench exec_bench_rbpf_diag interp,diag
build_fw "$EH" exec_bench_hal exec_bench_hal
build_fw "$EH" exec_bench_hal exec_bench_hal_diag diag

# All variants must share one memory map, or the containers would not be
# interchangeable between the plain and diag firmware of the same arm.
for v in exec_bench_aot exec_bench_rbpf exec_bench_aot_diag exec_bench_rbpf_diag; do
  "$TOOLS" mem-map "$OUT/fw/$v" > "$OUT/logs/memmap-$v.json"
done
cmp "$OUT/logs/memmap-exec_bench_aot.json" "$OUT/logs/memmap-exec_bench_rbpf.json"
cmp "$OUT/logs/memmap-exec_bench_aot.json" "$OUT/logs/memmap-exec_bench_aot_diag.json"
cmp "$OUT/logs/memmap-exec_bench_aot.json" "$OUT/logs/memmap-exec_bench_rbpf_diag.json"

printf 'workload\tarm\tstatus\timage_bytes\tcontainer_bytes\tdetail\n' > "$OUT/containers.tsv"
for p in $WORKLOADS; do
  obj="$BUILD/$p/bpf.o"
  toml="$BUILD/$p/bpf.toml"

  cp "$BUILD/$p/$p.elf" "$OUT/aot/$p.elf"
  aot_img=$(wc -c <"$BUILD/$p/esp32c3.bin" | tr -d ' ')
  aot_cont=$(wc -c <"$OUT/aot/$p.elf" | tr -d ' ')
  printf '%s\taot\tpass\t%s\t%s\tcanonical libbpf-mcu container\n' \
    "$p" "$aot_img" "$aot_cont" >> "$OUT/containers.tsv"

  if "$TOOLS" pack-jit --firmware "$OUT/fw/exec_bench_aot" --obj "$obj" \
      --bpf-toml "$toml" --name "$p" -o "$OUT/jit/$p.elf" \
      >"$OUT/jit/$p.pack.out" 2>"$OUT/jit/$p.pack.err"; then
    img=$(sed -n 's/.*image_len=\([0-9]*\).*/\1/p' "$OUT/jit/$p.pack.err")
    cont=$(wc -c <"$OUT/jit/$p.elf" | tr -d ' ')
    printf '%s\tjit\tpass\t%s\t%s\t%s\n' "$p" "$img" "$cont" \
      "$(cat "$OUT/jit/$p.pack.err")" >> "$OUT/containers.tsv"
  else
    printf '%s\tjit\tFAIL\t-\t-\t%s\n' "$p" \
      "$(tr '\n' ' ' <"$OUT/jit/$p.pack.err")" >> "$OUT/containers.tsv"
  fi

  llvm-objcopy -O binary --only-section=xdp "$obj" "$OUT/rbpf/$p.xdp.bin"
  # Plain pack, the interp_exec_bench.py reference command. `--map-index --obj`
  # fails closed on these objects: every workload declares the carrier map but
  # none references it (zero helper calls), so there are no map relocations to
  # rewrite and the tool refuses the unreferenced declaration.
  if "$TOOLS" pack --image "$OUT/rbpf/$p.xdp.bin" --bpf-toml "$toml" \
      --name "$p" \
      --slot-address 0x40380200 --helper-address 0x40380000 --machine 1 \
      -o "$OUT/rbpf/$p.elf" >"$OUT/rbpf/$p.pack.out" 2>"$OUT/rbpf/$p.pack.err"; then
    img=$(wc -c <"$OUT/rbpf/$p.xdp.bin" | tr -d ' ')
    cont=$(wc -c <"$OUT/rbpf/$p.elf" | tr -d ' ')
    printf '%s\trbpf\tpass\t%s\t%s\tbytecode image\n' "$p" "$img" "$cont" >> "$OUT/containers.tsv"
  else
    printf '%s\trbpf\tFAIL\t-\t-\t%s\n' "$p" \
      "$(tr '\n' ' ' <"$OUT/rbpf/$p.pack.err")" >> "$OUT/containers.tsv"
  fi
done
cat "$OUT/containers.tsv"

guard_files > "$GUARD.after"
if cmp -s "$GUARD.before" "$GUARD.after"; then
  echo "tracked-file guard: unchanged"
else
  echo "tracked-file guard: CHANGED" >&2
  diff "$GUARD.before" "$GUARD.after" >&2 || true
  exit 4
fi