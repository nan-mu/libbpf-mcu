# libbpf-mcu

Build XDP programs for XPOST on ESP32-C3. LLVM AOT compiles C independently for RV32IMC with the ILP32 ABI and no FPU. The host JIT translates eBPF to RV32IM. The rBPF image contains eBPF with map indices.

## Host tools

Install Cargo and Rust, Ninja, LLVM with the BPF and RISC-V backends, and LLD. The build prefers Homebrew LLVM on macOS. Set `LIBBPF_MCU_CLANG`, `LIBBPF_MCU_LLD`, `LIBBPF_MCU_OBJDUMP` or `LIBBPF_MCU_NINJA` to select specific executables. Install `7zz` or `7z` for local release archives.

Initialize the pinned PREVAIL submodule and build it using its [build instructions](prevail/README.md#building). The default verifier is `prevail/bin/prevail`. Set `PREVAIL` to use an existing executable. Cargo fetches XPOST dependencies at the revision pinned in `Cargo.lock`.

```sh
cargo run --locked -p mcu -- doctor
cargo run --locked -p mcu -- build
cargo run --locked -p mcu -- build -c firewall --bpf-only
cargo run --locked -p mcu -- build -c just_tx --modes llvm-aot,jit
```

A default build produces the three portable modes for all 12 programs under `experiments/`. Use `-c STEM` for a selected program or `--inputs FILE ...` for explicit C sources. `--force` rebuilds the selected programs. `--build-dir DIR` selects the output root and defaults to `build/` inside the checkout. See [output directory ownership](docs/artifacts.md#build-and-clean) before reusing a directory.

From another working directory, pass `--manifest-path /path/to/libbpf-mcu/Cargo.toml` to `cargo run`. Ninja runs from the checkout root. Relative `--build-dir` and `--inputs` paths resolve from the invocation directory.

Inspect the generated graph and the verified program index with these commands.

```sh
ninja -f build/build.ninja -t commands firewall
ninja -f build/build.ninja -t graph firewall
cargo run --locked -p mcu-object -- verify --build-dir build
```

See the [artifact and release reference](docs/artifacts.md), [architecture map](docs/architecture.md), and [benchmark protocols](docs/benchmarks.md).

## Tests

```sh
cargo test --locked --workspace --exclude xpost-jit-oracle
```

See the [test guide](tests/README.md) for the real toolchain tests, full matrix, native reference comparisons and Oracle.

## License

Repository code is licensed under [MIT](LICENSE). SDK headers retain their SPDX licenses. The PREVAIL submodule and its dependencies retain their own notices.
