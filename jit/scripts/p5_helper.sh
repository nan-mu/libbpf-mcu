#!/bin/sh
# P5 helper-cost supplement: helper_loop on exec_bench, three XDP arms.
#
# helper_loop does n bounded ARRAY lookups + increments per flight. Its object
# declares only `counters`; the exec_bench carrier also needs `workload`, so the
# metadata merges both maps. The AOT image keeps its linked counters address;
# pack-jit binds counters from the relocation; pack --map-index writes the
# metadata index into the lddw (this object HAS a map relocation, unlike the
# eight pure-compute workloads).
#
# HAL has no helper_loop opcode (run_hal knows ops 0..7): that arm is NOT
# MEASURED for this probe by design.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
BUILD=/Volumes/SSD/bs/build
OUT="$ROOT/build/p5/helper"
TOOLS="$ROOT/tools/target/aarch64-apple-darwin/release/xpost-mcu-elf"
mkdir -p "$OUT"

/usr/bin/python3 - "$BUILD" "$OUT" <<'EOF'
import sys
build, out = sys.argv[1], sys.argv[2]
hl = open(f"{build}/helper_loop/bpf.toml").read()
incr = open(f"{build}/incr/bpf.toml").read()
start = incr.index("[maps.workload]")
end = incr.index("[CORE]")
merged = hl.rstrip() + "\n\n" + incr[start:end].rstrip() + "\n"
open(f"{out}/helper_loop.merged.toml", "w").write(merged)
print("merged maps: counters + workload")
EOF

llvm-objcopy -O binary --only-section=xdp "$BUILD/helper_loop/bpf.o" "$OUT/helper_loop.xdp.bin"

"$TOOLS" pack-jit --firmware "$ROOT/build/p5/fw/exec_bench_aot" \
  --obj "$BUILD/helper_loop/bpf.o" --bpf-toml "$OUT/helper_loop.merged.toml" \
  --name helper_loop -o "$OUT/jit_helper_loop.elf" 2>"$OUT/jit.pack.err"
cat "$OUT/jit.pack.err"

"$TOOLS" pack --image "$BUILD/helper_loop/esp32c3.bin" \
  --bpf-toml "$OUT/helper_loop.merged.toml" --name helper_loop \
  --slot-address 0x40380200 --helper-address 0x40380000 --machine 1 \
  -o "$OUT/aot_helper_loop.elf" 2>"$OUT/aot.pack.err"
cat "$OUT/aot.pack.err"

"$TOOLS" pack --image "$OUT/helper_loop.xdp.bin" \
  --bpf-toml "$OUT/helper_loop.merged.toml" --map-index --obj "$BUILD/helper_loop/bpf.o" \
  --name helper_loop --slot-address 0x40380200 --helper-address 0x40380000 --machine 1 \
  -o "$OUT/rbpf_helper_loop.elf" 2>"$OUT/rbpf.pack.err"
cat "$OUT/rbpf.pack.err"

wc -c "$OUT"/*.elf