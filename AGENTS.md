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

Artifacts land in `../build/<stem>/`:

| File | Role |
|------|------|
| `bpf.o` | Host BPF object |
| `bpf.toml` | BPF report / map metadata (`aot_addr` merged after MCU link) |
| `<stem>.elf` | **XDP ELF** V0 (aka `xdp.elf`; cold-region image, flash separately from firmware) |
| `esp32c3.toml` | MCU report; includes `elf_size_kb` (XDP ELF bytes / 1024) |

Intermediate: `esp32c3.o`, `esp32c3.elf`, `esp32c3.bin`. Do not embed `.bin` into
firmware. `layout.toml` is not a compile input. Do not confuse `esp32c3.elf`
(AOT debug ELF) with XDP ELF (`<stem>.elf` / `xdp.elf`).

## Pipeline

Python (`make/cli.py` / `make/build.py`) only plans the route: resolve inputs, ensure
the host tool, read XPM1, write one ninja graph. Ninja executes:

1. `cargo build` → `tools/target/<host>/release/xpost-mcu-elf` (restat; rebuild when
   `tools/` or `xpost-elf` inputs change)
2. clang compiles `bpf.o`. When the build includes ESP32-C3, ninja runs PREVAIL on
   that `bpf.o` and writes `prevail.ok` before the ESP32-C3 cc edge.
3. clang link / bin / report
4. `xpost-mcu-elf pack` (direct binary call, never `cargo run`) + stamp `elf_size_kb`

`prevail/` is a git submodule. The binary is `prevail/bin/prevail`. `build bpf`
emits only the bpf edges and does not run PREVAIL.

Encode/decode uses `xpost-elf` only. Maps that cannot enter XDP ELF V0 are
omitted silently from metadata.

## Headers

- `include/` — MCU freestanding (`esp32c3` ninja)
- `include-bpf/` — host BPF (`bpf` ninja)

## Scope

Phase 1 proves RV32IMC only. Architecture-agnostic remains a design goal until a
second arch exists. Verifier safety does not automatically transfer to the MCU
binary; linker layout and ABI are separate proof burden.
