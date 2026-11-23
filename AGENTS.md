# Repository invariants

- Name the RISC-V build target `rv32imc`. The supported MCU is ESP32-C3, with the ILP32 ABI and no FPU.
- Keep `include-bpf/` for Clang BPF and `include/` for independently compiled freestanding AOT C. Host JIT compiles eBPF to RV32IM. The `ebpf` deployment rewrites map references to rBPF indices.
- Preserve the original `<p>/objects/<p>_bpf.o`. Use `xpost-elf` for Compact ELF V0 and XPM1. Resolve firmware addresses from the supplied linked ELF. XPOST owns flashing, runtime caches and device experiments.
- Keep the v3 per-program index as the machine contract. Validate relative paths, file sizes, hashes and container contents. Builds derive semantics from objects, firmware, linked ELF and private build inputs. Expose program files only after PREVAIL accepts the original object. Keep one human-readable `report.md` at the program root.
- Keep `build/` as the default output root. `--build-dir` selects the full root and `pixi run clean` removes the default root. Keep Ninja files, depfiles, linker scripts, stamps and staging files out of program archives.

Run `pixi run test` for implementation changes. Verify generated artifacts with `pixi run python make/layout.py verify --build-dir DIR`. Check docs against the CLI and wire format, then run `git diff --check`. Keep verification local. Compilation, PREVAIL acceptance, byte integrity and device execution are separate evidence.

An explicit request to publish the current `main` authorizes a GitHub Release. Use a fresh worktree at that commit, run `pixi run build` without arguments and archive every program from the successful build as its own `.7z`. Verify the entire batch before uploading it. A build or PR review can exercise those steps locally. Follow the [publication instructions](docs/artifacts.md#publish-program-artifacts) for tagging, upload and retry.
