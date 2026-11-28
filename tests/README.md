# Toolchain tests

Production programs live under `experiments/`. This directory contains explicit diagnostics, negative programs and stable packet and object fixtures.

| Layer | Entry point | Scope |
| --- | --- | --- |
| L0–L1 | `cargo test --locked --workspace --exclude xpost-jit-oracle` | Rust unit tests, binary contracts, JIT arithmetic and ABI checks |
| L2 | `cargo test --locked -p mcu --test pipeline level2_ -- --ignored --nocapture` | Real Ninja incrementality, verifier substitution and failure cases |
| L3 | `cargo test --locked -p mcu --test pipeline level3_ -- --ignored --nocapture` | Real LLVM, PREVAIL and Ninja for three programs and rejected inputs |
| L4 | `cargo test --locked -p mcu --test pipeline level4_ -- --ignored --nocapture` | Clean-checkout release matrix, archive verification, two-layout direct-link comparisons |

Use `cargo test --locked -p mcu-jit --test xdp -- --ignored --nocapture` to compile fixture C sources with Clang, run PREVAIL, and check JIT results against expected return values, packets and map writes. Run the [independent JIT Oracle](../jit/oracle/README.md) with `cargo test --locked -p xpost-jit-oracle --test differential`. The Oracle writes per-case results and distinguishes unsupported and inconclusive outcomes from passes.

Set `PREVAIL` to an executable if it is outside the checkout or the main checkout associated with a linked worktree. Set `LIBBPF_MCU_CLANG` to select an LLVM Clang with the BPF and RISC-V backends. The tools prefer Homebrew LLVM on macOS.

For an optional Sail diagnostic, use an existing build root and link a C program to the HTIF runtime with the command below. Pass the resulting ELF to your RV32 Sail simulator. The stack estimator is available through `cargo run --locked -p mcu-dev-tools -- stack-budget --help`.

```sh
cargo run --locked -p mcu-dev-tools -- sail-image \
  --source experiments/just_tx/just_tx.c --entry just_tx --work-dir build/intermediates/sail
```
