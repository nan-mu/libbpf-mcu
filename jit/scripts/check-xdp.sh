#!/bin/sh
# Compile the selected C fixtures to eBPF, run PREVAIL, then compare the JIT
# image with the eBPF reference. Required EXB2 cases also check known output.
# unsupported and inconclusive are recorded and neither is a pass.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
if [ -z "${CLANG:-}" ] && [ -x /opt/homebrew/opt/llvm/bin/clang ]; then
  CLANG=/opt/homebrew/opt/llvm/bin/clang
fi
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
FIXTURES="$ROOT/tests/fixtures/exb2"
cargo_check() {
  cargo run --quiet --release --manifest-path "$ROOT/jit/Cargo.toml" -- check "$@"
}
while IFS= read -r source <&3; do
  src="$ROOT/$source"
  name=$(basename "$src" .c)
  obj="$OUT/$name.bpf.o"
  "$CLANG" --target=bpf -O2 -g -Wall -Wno-missing-declarations -fno-stack-protector \
    -I "$ROOT/include-bpf" -include vmlinux.h -c "$src" -o "$obj"
  set +e
  python3 "$ROOT/make/prevail_gate.py" --obj "$obj" \
    >"$OUT/$name.prevail.out" 2>&1
  prev=$?
  set -e
  if [ "$prev" -eq 0 ]; then
    prevail=pass
  else
    prevail=fail
    fail=$((fail + 1))
  fi
  packet=00000000000000000000000008004500002c00000000401100007f0000017f000001
  if [ "$name" = div2 ]; then
    packet=0800000002000000
  elif [ "$name" = case_mark ]; then
    packet=112233445566aabbccddeeff0800450000000000000000110000c00002017f0000010400040000080000000000000000000000000000000000000000
  elif [ "$name" = bitswap ]; then
    packet=0000000001000000785634120000000000000000000000000000000000000000
  fi
  required=no
  set -- "$obj" --packet "$packet"
  case "$name" in
    bsort|noop|copy)
      required=yes
      set -- "$obj" --packet-file "$FIXTURES/$name.input.bin" \
        --expect-packet-file "$FIXTURES/$name.expected.bin" --expect-return 2 ;;
  esac
  set +e
  cargo_check "$@" >"$OUT/$name.check" 2>"$OUT/$name.check.err"
  code=$?
  set -e
  line=$(cat "$OUT/$name.check")
  case $code in
    0) jit=pass ;;
    2) jit=unsupported ;;
    *) jit=fail ;;
  esac
  if grep -q 'status=inconclusive' "$OUT/$name.check"; then
    jit=inconclusive
  fi
  if [ "$jit" = fail ] || { [ "$required" = yes ] && [ "$jit" != pass ]; }; then
    fail=$((fail + 1))
  fi
  printf '%s\t%s\t%s\t%s\n' "$name" "$prevail" "$jit" "$line" >> "$OUT/report.tsv"
  if [ "$name" = bsort ]; then
    short="$OUT/bsort.short.bin"
    dd if="$FIXTURES/bsort.input.bin" of="$short" bs=1 count=8 2>/dev/null
    if cargo_check "$obj" --packet-file "$short" \
         --expect-packet-file "$short" --expect-return 0 >"$OUT/bsort.short.check"; then
      jit=pass
    else
      jit=fail
      fail=$((fail + 1))
    fi
    printf '%s\t%s\t%s\t%s\n' bsort/short "$prevail" "$jit" "$(cat "$OUT/bsort.short.check")" >> "$OUT/report.tsv"
  fi
done 3< "$ROOT/jit/scripts/xdp-sources.txt"
cat "$OUT/report.tsv"
exit "$fail"
