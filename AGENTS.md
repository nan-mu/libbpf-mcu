# Repository invariants

- Keep the supported target explicit. ESP32-C3 uses RV32IMC, ILP32 and no FPU. A second architecture is a project goal.
- Keep `include-bpf/` for Clang BPF and `include/` for independently compiled freestanding AOT C. Host JIT compiles eBPF to RV32IM. The `ebpf` deployment rewrites map references to rBPF indices.
- Preserve the original `<p>/bpf/<p>_bpf.o`. Use `xpost-elf` for Compact ELF V0 and XPM1. Resolve firmware addresses from the supplied linked ELF. XPOST owns flashing, runtime caches and device experiments.
- Keep the v2 per-program index as the machine contract. Validate relative paths, file sizes, hashes and container contents. Build and legacy export derive semantics from objects, firmware, linked ELF and private build inputs. Treat `report.toml` as human-readable output.
- Keep `build/` as the default output root. `--build-dir` selects the full root and `pixi run clean` removes the default root. Keep Ninja files, depfiles, linker scripts, stamps and staging files out of program archives.

Run `pixi run test` for implementation changes. Verify generated artifacts with `pixi run python make/layout.py verify --build-dir DIR`. Check docs against the CLI and wire format, then run `git diff --check`. Keep verification local. Compilation, PREVAIL acceptance, byte integrity and device execution are separate evidence.

For packaging or an explicit request to publish the current `main`, read the [artifact and publication instructions](docs/artifacts.md#publish-program-artifacts). Use mock `gh` for publication tests. A PR implementation request permits local packaging and PR delivery.
