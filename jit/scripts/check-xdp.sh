#!/bin/sh
# Compile tests/xdp C to eBPF, run PREVAIL, then compare the JIT image with
# the eBPF reference. The exit status is the number of JIT failures.
# unsupported and inconclusive are recorded and neither is a pass.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
CLANG="${CLANG:-clang}"
PREVAIL="${PREVAIL:-$ROOT/prevail/bin/prevail}"
if [ ! -x "$PREVAIL" ]; then
  # A worktree has an empty submodule dir; the main checkout has the built one.
  MAIN=$(dirname "$(git -C "$ROOT" rev-parse --path-format=absolute --git-common-dir)")
  PREVAIL="$MAIN/prevail/bin/prevail"
fi
if [ ! -x "$PREVAIL" ]; then
  echo "PREVAIL is not executable; set PREVAIL to a built prevail binary" >&2
  exit 3
fi
export PREVAIL
OUT="$ROOT/build/jit-check"
mkdir -p "$OUT"
printf 'program\tprevail\tjit\tline\n' > "$OUT/report.tsv"
fail=0
for name in div2 xdp_drop case_mark just_drop just_tx firewall bitswap bsort; do
  src="$ROOT/tests/xdp/$name.c"
  obj="$OUT/$name.bpf.o"
  "$CLANG" --target=bpf -O2 -g -Wall -Wno-missing-declarations -fno-stack-protector \
    -I "$ROOT/include-bpf" -include vmlinux.h -c "$src" -o "$obj"
  set +e
  python3 "$ROOT/make/prevail_gate.py" --obj "$obj" --stamp "$OUT/$name.prevail.ok" \
    >"$OUT/$name.prevail.out" 2>&1
  prev=$?
  set -e
  if [ "$prev" -eq 0 ]; then
    prevail=pass
  else
    prevail=fail
  fi
  packet=00000000000000000000000008004500002c00000000401100007f0000017f000001
  if [ "$name" = div2 ]; then
    packet=0800000002000000
  elif [ "$name" = case_mark ]; then
    packet=112233445566aabbccddeeff0800450000000000000000110000c00002017f0000010400040000080000000000000000000000000000000000000000
  elif [ "$name" = bitswap ]; then
    packet=0000000001000000785634120000000000000000000000000000000000000000
  elif [ "$name" = bsort ]; then
    packet=0000000004000000040000000100000003000000020000000000000000000000
  fi
  set +e
  cargo run --quiet --release --manifest-path "$ROOT/jit/Cargo.toml" -- \
    check "$obj" --packet "$packet" >"$OUT/$name.check" 2>"$OUT/$name.check.err"
  code=$?
  set -e
  line=$(cat "$OUT/$name.check")
  case $code in
    0) jit=pass ;;
    2) jit=unsupported ;;
    *) jit=fail; fail=$((fail + 1)) ;;
  esac
  if grep -q 'status=inconclusive' "$OUT/$name.check"; then
    jit=inconclusive
  fi
  printf '%s\t%s\t%s\t%s\n' "$name" "$prevail" "$jit" "$line" >> "$OUT/report.tsv"
done
cat "$OUT/report.tsv"
exit "$fail"
