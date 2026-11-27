# Toolchain tests

Production programs live under `experiments/`. This directory contains explicit diagnostics, negative programs and stable packet and object fixtures.

| Layer | Entry point | Scope |
| --- | --- | --- |
| L0 | `./mcu test --level 0` | Rust unit tests for library and binary logic |
| L1 | `./mcu test --level 1` | Binary and public library contracts, JIT arithmetic and ABI checks |
| L2 | `./mcu test --level 2` | Real Ninja incrementality, verifier substitution, interruption and failure cases |
| L3 | `./mcu test --level 3` | Real LLVM, PREVAIL and Ninja for three programs and rejected inputs |
| L4 | `./mcu test --level 4` | Clean-checkout release matrix, archive verification, two-layout direct-link comparisons |

Use `./mcu test --all` for all layers. Run the [independent JIT Oracle](../jit/oracle/README.md) with `cargo test --locked -p xpost-jit-oracle --test differential`. The Oracle writes per-case results and distinguishes unsupported and inconclusive outcomes from passes.

`jit/scripts/check-xdp.sh` runs the JIT fixture checks with PREVAIL. For optional Sail diagnostics, `linker/sail/build.sh source.c` links a selected C fixture for the simulator. `cargo run --locked -p mcu-dev-tools -- stack-budget --help` documents the stack estimate CLI.
