# libbpf-mcu

libbpf-mcu builds libbpf-style C/eBPF XDP programs for the XPOST microcontroller runtime. It provides freestanding C headers, host build tools, PREVAIL verification, and artifact reports for RV32IMC. Programs can run as native code compiled from C, native code generated from eBPF on the host, or eBPF bytecode packaged for the rBPF interpreter.

The native compilation target is `rv32imc`, using the ILP32 ABI without an FPU. Firmware deployments use the ESP32-C3 machine profile defined by XPOST Compact ELF V0. The MCU runtime and helper interface come from XPOST. This repository does not provide a Linux XDP runtime.

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
- Install LLVM with the BPF and RISC-V backends, LLD, `llvm-objcopy`, and `llvm-objdump`. Apple Clang does not supply the required BPF backend. The build prefers Homebrew LLVM for Clang and has no enforced LLVM minimum version. Set `LIBBPF_MCU_OBJCOPY` or `LIBBPF_MCU_OBJDUMP` to select another LLVM executable.
- Initialize the PREVAIL submodule and build it manually. Every build requires the verifier. The default is `prevail/bin/prevail`; set `PREVAIL` to select a built executable. PREVAIL's own [build instructions](prevail/README.md#building) describe its C++23 compiler and native dependencies.
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

Build and verify all default programs, or select one by source stem:

```bash
pixi run build
pixi run build -c firewall
```

Build BPF and AOT with addresses from your linked firmware:

```bash
pixi run build rv32imc --firmware /path/to/firmware.elf -c firewall
```

Build host JIT code or an rBPF container explicitly:

```bash
pixi run build jit --firmware /path/to/firmware.elf -c firewall
pixi run build rv32imc --engine rbpf --firmware /path/to/firmware.elf -c firewall
```

The project defines three Pixi tasks. Use `-h` or `--help` on any task.

| Task | Arguments |
| --- | --- |
| `build [bpf\|rv32imc\|jit]` | With no target, build BPF by default. Supplying `--firmware` selects `rv32imc` when the target is omitted. Select `jit` explicitly for host JIT. |
| `test` | Runs the Python and Rust suites, including PREVAIL negatives and toolchain integration. |
| `clean` | Removes the default `build/` directory. |

| Build option | Meaning |
| --- | --- |
| `-c STEM`, `--crate STEM` | Select a unique C source stem under `tests/`, including `tests/diagnostics/`. The default build excludes diagnostics and `tests/unused/`. |
| `--inputs FILE [FILE ...]` | Select C sources by path, mutually exclusive with `-c`. Quote each path containing spaces once. |
| `--build-dir DIR` | Choose the whole output root (default `build/`). |
| `--force` | Rerun the selected build graph, including verification. |
| `--firmware ELF` | Required for `rv32imc` and `jit`. The linked firmware supplies the XPM1 slot, its capacity, and the helper address. |
| `--engine aot\|rbpf` | Select native LLVM AOT or interpreted eBPF for `rv32imc`. |
| `--slot-symbol SYMBOL` | For a deployment, use this firmware symbol's address and size as the slot. |
| `--image-name NAME` | Set the internal deployment image name. Archive filenames follow the program stem. |

Each successful program has a machine-readable `index.toml`, a single human-readable `report.md`, and its original C file. Its `objects/` directory holds relocatable objects. Its `containers/` directory holds the selected firmware-bound deployments. The report groups built modes by architecture (eBPF and RV32IMC), with the source, machine descriptions, instruction bytes, disassembly, and build steps. See the [program artifact reference](docs/artifacts.md).

The default build includes the seven EXB2 compute benchmarks and five networking programs. See the [benchmark contracts and source history](docs/benchmarks.md).

## Verification and Release archives

```sh
pixi run test
pixi run python make/layout.py verify --build-dir build
```

On an authorized Release, the agent runs `pixi run build` in a fresh worktree at the pinned commit and uses every program directory from that successful build. It creates one `<program>.7z` per directory, verifies the extracted files against the build, and uploads the complete set to the GitHub Release. A failed build stops publication. New default programs are included automatically. See the [publication procedure](docs/artifacts.md#publish-program-artifacts).

## License

Repository code is licensed under [MIT](LICENSE). Headers in `include/bpf/` and `include-bpf/bpf/` retain their SPDX licenses, currently `LGPL-2.1 OR BSD-2-Clause`. The PREVAIL submodule and its bundled dependencies retain their own notices, including [LICENSE.txt](prevail/LICENSE.txt) and [LICENSE-Apache-2.0.txt](prevail/LICENSE-Apache-2.0.txt).
