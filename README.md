# libbpf-mcu

libbpf-mcu builds libbpf-style C/eBPF XDP programs for the XPOST microcontroller runtime. It provides freestanding C headers, host build tools, PREVAIL verification, and artifact reports for ESP32-C3. Programs can run as native code compiled from C, native code generated from eBPF on the host, or eBPF bytecode packaged for the rBPF interpreter.

The supported MCU target is ESP32-C3 with RV32IMC, the ILP32 ABI, and no FPU. A second architecture is a project goal. The MCU runtime and helper interface come from XPOST. This repository does not provide a Linux XDP runtime.

## Build modes

| Mode in reports | Input and processing | Result |
| --- | --- | --- |
| `bpf` | Clang compiles C with the BPF headers. | Raw eBPF relocatable ELF with sections, BTF, and relocations. |
| `rv32` | Clang independently compiles the same C with the MCU headers, then LLD links against firmware addresses. | RV32IMC AOT object, linked debug ELF, raw image, and Compact ELF V0 container. |
| `jit` | The host JIT compiles eBPF from the raw BPF object and links helpers and map references. | RV32IM machine code and a Compact ELF V0 container. RV32IMC devices can execute this code. |
| `bpf-xpost` | The packer extracts eBPF and rewrites map references to indices for the rBPF loader. | eBPF image and a Compact ELF V0 container for interpretation. This is a packaging mode, not another compiler. |

AOT takes C as its compilation input. Its BPF object is the input to the PREVAIL gate. The JIT runs on the host and emits no compressed or floating-point instructions. The raw BPF object remains unchanged by all downstream modes.

## Prerequisites

Run commands from this repository's root. The Pixi manifest and lock file target macOS on Apple Silicon (`osx-arm64`). Other host platforms need their own environment setup. Pixi installs Python `>=3.14.6,<3.15` and the declared Python dependency. Install the native tools separately.

- Install Pixi, Ninja, Cargo, and Rust. `tools/Cargo.toml` uses Rust edition 2024, and `jit/Cargo.toml` uses edition 2021. Use a toolchain that supports these editions and their dependencies. These manifests declare no `rust-version`, and the repository does not pin a Rust toolchain.
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

Omitting the target selects `bpf` followed by `esp32c3`. Omitting `-c` selects all `tests/**/*.c` except files under `tests/unused/`. `-c STEM` selects one unique source stem. Use `--inputs "path/to/a.c path/to/b.c"` for explicit sources, without `-c`.

`--build-dir /path/to/build` selects the output root. The default is `../build`, outside the repository. `--force` rebuilds the graph. `--release` omits section contents from object reports. It does not select a different optimization level. `--image-name NAME` sets the container's internal name. `--slot-symbol SYMBOL` replaces the firmware slot address and length with that symbol's address and size for ESP32-C3 builds. JIT rejects `--slot-symbol`, `--engine rbpf`, and `--no-compact-elf`. `--no-compact-elf` suppresses the AOT container. `--output` is rejected because names are defined by the artifact protocol.

Python resolves inputs, prepares the host tool, reads XPM1, and writes a Ninja graph. Ninja runs Clang, PREVAIL, linking, reporting, and packing. `include-bpf/` supplies the BPF headers. `include/` supplies the freestanding MCU headers. Backend builds gate the raw BPF object with PREVAIL before publishing their reports. An rBPF build also produces the RV32 report used to establish map metadata.

## Artifact layout

The complete layout below shows all four modes for program `<p>`. A build contains only the modes and optional artifacts it produced.

```text
<build-root>/
├── index.toml
└── <p>/
    ├── manifest.toml
    ├── bpf/
    │   ├── <p>_bpf.o
    │   ├── report.toml
    │   └── prevail.ok
    ├── rv32/
    │   ├── <p>_rv32.o
    │   ├── <p>_rv32.debug.elf
    │   ├── <p>_rv32.bin
    │   ├── <p>_rv32.elf
    │   └── report.toml
    ├── jit/
    │   ├── <p>_jit.bin
    │   ├── <p>_jit.elf
    │   └── report.toml
    └── bpf-xpost/
        ├── <p>_bpf-xpost.bin
        ├── <p>_bpf-xpost.elf
        └── report.toml
```

`prevail.ok` exists only after the gate runs. JIT does not emit a relocatable `.o`. The RV32 `.debug.elf` is a linked ELF for inspection. The mode's other `.elf` is an XPOST Compact ELF V0 container. Select artifacts by their report `role` and `format`, not by the `.elf` suffix.

`index.toml` hashes program manifests. Each manifest hashes its mode reports, and each report hashes its declared artifacts and inputs. See the [artifact protocol and release matrix](docs/artifacts.md) for field ownership, fingerprints, invalidation, and legacy exports. Ninja files, depfiles, linker scripts, and staging directories are internal build files.

## XPOST integration

XPOST consumes a selected artifact root, program, and profile. Resolve its engine to the corresponding mode directory:

| XPOST engine | libbpf-mcu mode | Container |
| --- | --- | --- |
| `Aot` | `rv32` | `<p>/rv32/<p>_rv32.elf` |
| `Jit` | `jit` | `<p>/jit/<p>_jit.elf` |
| `Rbpf` | `bpf-xpost` | `<p>/bpf-xpost/<p>_bpf-xpost.elf` |

Each profile must select its own root and program, especially when the same source has multiple slot or image-name variants. In a release archive, use the selected `sets/<id>` directory as the artifact root. The existing v1 index, manifest, and report fields remain the consumer contract.

libbpf-mcu produces code, containers, and reports. XPOST builds and flashes firmware, loads containers, manages runtime caches, and runs device experiments. A firmware ELF is a build input here. A raw `.bin` is an inspection artifact, not a firmware flashing instruction.

## Local verification

Run the local test suite and validate an existing artifact tree:

```bash
	pixi run test
	pixi run python make/layout.py verify --build-dir ../build
```

The suite includes Python build/protocol tests and Rust JIT tests. Some tests require the native tools, PREVAIL, and the sibling XPOST workspace. `pixi run clean` removes the default build output.

Compilation, PREVAIL acceptance, artifact integrity, and device execution establish different facts. PREVAIL checks the eBPF input. It does not prove that the independently compiled MCU binary preserves those properties. Artifact verification checks the recorded files and hash links. ABI correctness, link layout, and behavior on a device require separate evidence. These instructions make no claim that a particular build or device experiment has passed.

## Local release publication

Define independent build sets in a TOML plan. Each set selects one program, requested modes, firmware, and backend options. The [release matrix reference](docs/artifacts.md#release-plans-and-matrix) includes two `case_mark` variants and explains generated dependencies.

```bash
	pixi run publish-artifacts --plan /path/to/release-plan.toml --tag v0.1.0
```

Formal publication requires clean local `main`, an explicit unused tag, and authenticated local `gh`. After building and validating the package, the script requires you to type the tag and full source commit. It then creates the tag reference through `gh api` and uploads with `gh release create --verify-tag`. Existing tags and Releases are rejected.

`--package-only` builds and checks a local package on a development branch without GitHub calls. `--dry-run` requires clean `main` and checks the GitHub destination, then packages without publication. These two options are mutually exclusive. `--draft` creates a draft when uploading. `--out DIRECTORY` selects a new directory outside the repository. Publication runs locally. No hosted workflow participates.

The archive retains independent `sets/<id>` artifact roots and an outer `release-index.toml`. Only the archive and its external `SHA256SUMS` are uploaded. Firmware is excluded, while reports retain its hash and XPM1 addresses. See the [package and publication reference](docs/artifacts.md#package-and-publication) for validation and failure behavior.

## License

Repository code is licensed under [MIT](LICENSE). Headers in `include/bpf/` and `include-bpf/bpf/` retain their SPDX licenses, currently `LGPL-2.1 OR BSD-2-Clause`. The PREVAIL submodule and its bundled dependencies retain their own notices, including [LICENSE.txt](prevail/LICENSE.txt) and [LICENSE-Apache-2.0.txt](prevail/LICENSE-Apache-2.0.txt).
