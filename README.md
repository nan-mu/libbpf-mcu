# libbpf-mcu

libbpf-mcu builds libbpf-style C/eBPF XDP programs for the XPOST microcontroller runtime. It provides freestanding C headers, host build tools, PREVAIL verification, and artifact reports for ESP32-C3. Programs can run as native code compiled from C, native code generated from eBPF on the host, or eBPF bytecode packaged for the rBPF interpreter.

The supported MCU target is ESP32-C3 with RV32IMC, the ILP32 ABI, and no FPU. A second architecture is a project goal. The MCU runtime and helper interface come from XPOST. This repository does not provide a Linux XDP runtime.

## Build modes

| Artifact mode | Input and processing | Result |
| --- | --- | --- |
| `bpf` | Clang compiles C with the BPF headers. | Original eBPF relocatable ELF with sections, BTF and relocations. |
| `llvm-aot` | Clang independently compiles C using the MCU headers, then LLD links at firmware addresses. | RV32IMC in a Compact ELF V0 container. |
| `jit` | The host JIT compiles eBPF and links helpers and map references. | RV32IM in a Compact ELF V0 container. |
| `ebpf` | The packer extracts eBPF and rewrites map references to indices. | Compact ELF V0 for rBPF execution. |

## Prerequisites

Run commands from this repository's root. The Pixi manifest and lock file target macOS on Apple Silicon (`osx-arm64`). Other host platforms need their own environment setup. Pixi installs Python `>=3.14.6,<3.15` and the declared Python dependency. Install the native tools separately.

- Install Pixi, Ninja, Cargo, and Rust. Install `7zz` or `7z` for packaging. `tools/Cargo.toml` uses Rust edition 2024, and `jit/Cargo.toml` uses edition 2021. Use a toolchain that supports these editions and their dependencies. These manifests declare no `rust-version`, and the repository does not pin a Rust toolchain.
- Install LLVM with the BPF and RISC-V backends, LLD, `llvm-objcopy`, and `llvm-objdump`. Apple Clang does not supply the required BPF backend. The build prefers Homebrew LLVM for Clang and has no enforced LLVM minimum version. `--objcopy` and `--objdump` override those tools.
- Initialize the PREVAIL submodule and build it manually. Backend builds require `prevail/bin/prevail`. PREVAIL's own [build instructions](prevail/README.md#building) describe its C++23 compiler and native dependencies.
- Place the XPOST workspace beside this checkout. `tools/Cargo.toml` resolves `xpost-elf` at `../xpost/xpost-elf` relative to this repository. That crate owns Compact ELF V0 and XPM1 encoding and decoding.
- Supply an already linked firmware ELF with a `.xpost.mem` XPM1 record for AOT, JIT, and rBPF builds. XPM1 provides the helper dispatcher, code slot, and map table addresses and lengths.

For example, initialize and build PREVAIL after installing its native dependencies:

```bash
	git submodule update --init --recursive
	cmake -S prevail -B prevail/build -DCMAKE_BUILD_TYPE=Release
	cmake --build prevail/build
	pixi install
```

On macOS, use the Homebrew compiler and include/library configuration described in PREVAIL's build instructions if CMake selects Apple Clang.

## Build programs

Build a raw eBPF object without firmware or a PREVAIL run:

```bash
	pixi run build bpf -c firewall
```

Build BPF and AOT with addresses from your linked firmware:

```bash
	pixi run build --firmware /path/to/firmware.elf -c firewall
```

Build host JIT code or an rBPF container explicitly:

```bash
	pixi run build jit --firmware /path/to/firmware.elf -c firewall
	pixi run build esp32c3 --engine rbpf --firmware /path/to/firmware.elf -c firewall
```

Omitting the target selects AOT and builds its required raw BPF object. Omitting `-c` selects all `tests/**/*.c` except files under `tests/unused/`. `-c STEM` selects one unique source stem. Use `--inputs "path/to/a.c path/to/b.c"` for explicit sources, without `-c`.

`--build-dir /path/to/build` chooses the output root. The default is `build/` in the checkout. `--force` rebuilds the selected graph. `--image-name NAME` names a container internally and `--slot-symbol SYMBOL` selects a firmware slot. `--no-compact-elf` suppresses the AOT container while keeping the debug files.

Select and verify a program through its `index.toml`. Open `<mode>/report.toml` to read the full C source, the instruction bytes and assembly, and the generation commands. XPOST handles firmware, flashing and device execution. For exact member names, report regeneration and legacy export, see the [program artifact reference](docs/artifacts.md).

## Local verification and packaging

```sh
pixi run test
pixi run python make/layout.py verify --build-dir build
pixi run package
```

`pixi run clean` removes the default build root. The package task builds the versioned `release/programs.toml` configuration and verifies one 7z per program offline in `packages/`. The checked-in configuration includes the 17 raw BPF programs. Deployment requires maintainer-confirmed firmware for each selected mode. To publish verified archives locally as a GitHub Release, follow the [publication procedure](docs/artifacts.md#publish-program-artifacts).

## License

Repository code is licensed under [MIT](LICENSE). Headers in `include/bpf/` and `include-bpf/bpf/` retain their SPDX licenses, currently `LGPL-2.1 OR BSD-2-Clause`. The PREVAIL submodule and its bundled dependencies retain their own notices, including [LICENSE.txt](prevail/LICENSE.txt) and [LICENSE-Apache-2.0.txt](prevail/LICENSE-Apache-2.0.txt).
