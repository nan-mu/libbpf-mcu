# libbpf-mcu

Freestanding C compat layer: compile libbpf-style XDP C to MCU AOT objects for
ESP32-C3 / RV32IMC (phase 1). This is not a Linux XDP runtime on the MCU.

## Build

```bash
pixi run build --firmware <firmware.elf>
pixi run build --firmware <firmware.elf> -c just_drop
pixi run clean
```

- `--firmware` is a linked firmware ELF that carries `.xpost.mem` (XPM1). Addresses
  are read as-is and used for slot linking and XDP ELF metadata. libbpf-mcu
  does not choose what to flash.
- Omit target → build `bpf` then `esp32c3` for every `tests/**/*.c` except
  `tests/unused/`.
- `-c <stem>` → only matching `tests/**/<stem>.c` (also excludes `unused/`).

Artifacts land in `--build-dir` (default `../build`, outside the repo):

| Path | Role |
|------|------|
| `<p>/bpf/<p>_bpf.o` | Raw Clang eBPF ELF. AOT and JIT must not rewrite it. |
| `<p>/bpf/report.toml` | BPF report and map definitions. No `aot_addr`. |
| `<p>/bpf/prevail.ok` | PREVAIL stamp for that BPF object. Absent when the gate did not run. |
| `<p>/rv32/<p>_rv32.o` | C to RV32 AOT relocatable object. Not produced by compiling `bpf.o`. |
| `<p>/rv32/<p>_rv32.debug.elf` | AOT linked debug ELF. |
| `<p>/rv32/<p>_rv32.bin` | AOT raw image. |
| `<p>/rv32/<p>_rv32.elf` | AOT XPOST Compact ELF V0 container. |
| `<p>/jit/<p>_jit.bin` | Host JIT RV32IM raw image. There is no `<p>_jit.o`. |
| `<p>/jit/<p>_jit.elf` | JIT XPOST Compact ELF V0 container. |
| `<p>/bpf-xpost/<p>_bpf-xpost.elf` | rBPF XPOST Compact ELF V0 container. Not a raw BPF ELF. |

Do not choose an engine from the `.elf` suffix. Read `role` and `format` in the mode `report.toml`. `--image-name` does not change these file names. `--output` is rejected. Old names are a copy from `artifacts export-legacy` into a different directory. See `docs/artifacts.md`.

Ninja files, depfiles, the linker script, and `.stage` are internal. Do not commit a build directory.

## Pipeline

Python (`make/cli.py` / `make/build.py`) only plans the route: resolve inputs, ensure
the host tool, read XPM1, write one ninja graph. Ninja executes:

1. `cargo build` → `tools/target/<host>/release/xpost-mcu-elf` (restat; rebuild when
   `tools/` or `xpost-elf` inputs change)
2. clang compiles `<p>/bpf/<p>_bpf.o`. When the build includes ESP32-C3 or JIT, ninja runs PREVAIL on that object and writes `<p>/bpf/prevail.ok` before the later edge.
3. clang link / bin / report
4. `xpost-mcu-elf pack` (direct binary call, never `cargo run`) + stamp `elf_size_kb`

`prevail/` is a git submodule. The binary is `prevail/bin/prevail`. `build bpf`
emits only the bpf edges and does not run PREVAIL.

Encode/decode uses `xpost-elf` only. Maps that cannot enter XDP ELF V0 are
omitted silently from metadata.

## Headers

- `include/` — MCU freestanding (`esp32c3` ninja)
- `include-bpf/` — host BPF (`bpf` ninja)

## JIT

`jit/` is a separate host tool. `pixi run build` does not run it, and it is not
the freestanding C-to-RV32IMC path above.

It compiles eBPF bytecode to RV32IM on the Mac. RV32IMC can run the encoding.
The compiler emits no RVC, F, D, or A. Register pairing follows the Jitterbug
RV32 JIT. `compile` leaves helper calls and map `lddw`s as relocations.
`check` links those against `helper_dispatcher` and a VMR address, then
compares the image with the eBPF reference interpreter. An omitted section
selects `xdp` or `xdp1`, not the empty `.text` Clang emits. Half and word
memory operations are byte loads and stores, because eBPF allows an
unaligned address. BPF-to-BPF calls,
ALU64 div/mod, atomics, and tail calls are rejected. A helper call uses the
firmware ilp32 shape: id in `a0`, R1..R5 lows in `a1`..`a5`, return
zero-extended from `a0`. The program entry still takes `ctx` in `a0` and
returns R0 in `a0`/`a1`.

```bash
cargo test --manifest-path jit/Cargo.toml
cargo run --release --manifest-path jit/Cargo.toml -- compile <bpf.o-or-raw> -o out.rv32
cargo run --release --manifest-path jit/Cargo.toml -- check <bpf.o>
jit/scripts/check-xdp.sh
```

`--repeat N` times only the compile call. `ns_min`, `ns_med`, and `ns_max` are
those samples.

## Local publication

Development builds never publish to GitHub. Validate a development tree with
`pixi run python make/layout.py verify --build-dir ../build`. Input artifacts
must resolve within the program directory and match their SHA-256; RV32 report
changes stale the rBPF container through `map_index_basis`.

After merge, a user can run:

```bash
pixi run publish-artifacts --firmware /path/to/firmware.elf --tag v0.1.0
```

Formal publication and `--dry-run` require clean `main`; `--package-only` allows
local verification on a development branch and never calls GitHub. Repeat
`--program STEM` to select programs; every selected program must produce four
modes. `--out` must be a new directory outside this repository. The script
retains an isolated diagnostic work directory, validates a staged and extracted
archive, and uploads only its tar.gz and external SHA256SUMS through local `gh`.
Internal SHA256SUMS covers all official files except itself. Firmware is not
packaged; its hash and toolchain remain in the reports.

A user must confirm the explicit tag and commit before GitHub creates a missing
tag. Existing tags/releases are rejected. The script never pushes tags or
merges PRs. CI tests code and the build protocol only; it never publishes formal
assets. Agents implementing this tool must test upload with mocks, not create a
Release. See `docs/artifacts.md` for parameters and package structure.

## Scope

Phase 1 proves RV32IMC only. Architecture-agnostic remains a design goal until a
second arch exists. Verifier safety does not automatically transfer to the MCU
binary; linker layout and ABI are separate proof burden.
