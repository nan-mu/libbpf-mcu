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
  are read as-is and used for slot linking and Compact ELF metadata. libbpf-mcu
  does not choose what to flash.
- Omit target → build `bpf` then `esp32c3` for every `tests/**/*.c` except
  `tests/failed/`.
- `-c <stem>` → only `tests/**/<stem>.c`.

Artifacts land in `../build/<stem>/`:

| File | Role |
|------|------|
| `bpf.o` | Host BPF object |
| `bpf.toml` | BPF report / map metadata (`aot_addr` merged after MCU link) |
| `<stem>.elf` | Compact ELF V0 (flash separately from firmware) |
| `esp32c3.toml` | MCU report; includes `elf_size_kb` (Compact ELF bytes / 1024) |

Intermediate: `esp32c3.o`, `esp32c3.elf`, `esp32c3.bin`. Do not embed `.bin` into
firmware. `layout.toml` is not a compile input.

## ELF path

All ELF section encode/decode goes through Rust `tools/` (`xpost-mcu-elf`), which
depends on `../xpost/xpost-elf` (and `xpost-build` only for `bpf.toml` → metadata).
Python orchestrates ninja; it does not implement Compact ELF / XPM1 codecs.

## Headers

- `include/` — MCU freestanding (`esp32c3` ninja)
- `include-bpf/` — host BPF (`bpf` ninja)

## Scope

Phase 1 proves RV32IMC only. Architecture-agnostic remains a design goal until a
second arch exists. Verifier safety does not automatically transfer to the MCU
binary; linker layout and ABI are separate proof burden.
