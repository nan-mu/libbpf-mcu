# Artifact terminology

| Term | Meaning |
| --- | --- |
| `bpf` | Original Clang eBPF object, shared by PREVAIL, JIT and interpreter packaging. |
| `llvm-aot` | Deployment mode generated from C as RV32IMC. The legacy export argument is `rv32`. |
| `ebpf` | Deployment mode carrying eBPF rewritten for the rBPF interpreter. The legacy export argument is `bpf-xpost`. |
| `jit` | Deployment mode generated on the host from eBPF as RV32IM. |
| Program index | Version 2 `index.toml` at each program root. |
| Report | Human-readable `report.toml` with source, disassembly and generation steps. |
| Release configuration | Versioned `release/programs.toml` with per-program mode and firmware selections. |
| Program archive | One verified `<program>.7z` per program, uploaded as one Release attachment. |

The v1 manifest, set layout and aggregate Release archive describe historical builds. Use the program index for current artifact selection.
