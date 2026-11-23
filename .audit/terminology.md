# Artifact terminology

| Term | Meaning |
| --- | --- |
| `bpf` | Original Clang eBPF object, shared by PREVAIL, JIT and interpreter packaging. |
| `llvm-aot` | Deployment mode generated from C as RV32IMC. |
| `ebpf` | Deployment mode carrying eBPF rewritten for the rBPF interpreter. |
| `jit` | Deployment mode generated on the host from eBPF as RV32IM. |
| Program index | Version 3 `index.toml` at each program root. |
| Report | One `report.md` per program with source and a machine description, disassembly and generation steps for each built mode. |
| Release scope | All program directories produced by one successful default `pixi run build` in a fresh worktree at the release commit. |
| Program archive | One verified `<program>.7z` per program, uploaded as one Release attachment. |

The v1 manifest, set layout and aggregate Release archive describe historical builds. Use the program index for current artifact selection.
