# Repository invariants

- Keep the supported target explicit: ESP32-C3, RV32IMC, ILP32, no FPU. A second architecture is a goal, not implemented support.
- Keep `include-bpf/` for Clang BPF and `include/` for freestanding C-to-MCU compilation. AOT compiles C independently. Host JIT compiles eBPF to RV32IM. `bpf-xpost` packages eBPF for rBPF and rewrites map references to indices.
- Preserve the raw `<p>/bpf/<p>_bpf.o`. AOT addresses belong in the RV32 report. JIT has no relocatable `.o`. Use report `role` and `format` to distinguish linked debug ELF from Compact ELF V0 containers.
- Use `xpost-elf` for Compact ELF V0 and XPM1 encoding and decoding. Firmware addresses come from the supplied linked ELF. Flashing, runtime caches, and device experiments belong to XPOST.
- Preserve the v1 index, manifest, and report schemas and their relative paths. Validate index-to-manifest, manifest-to-report, artifact, and input hashes. Inputs must resolve within the program directory. A changed RV32 report invalidates rBPF through `map_index_basis`.
- Keep primary source identity in `[source]`, not `[[dependency]]`. Include its bytes in `input_set_id`. Serialize build options and hash their canonical ordered representation with the configuration. See [the field ownership reference](docs/artifacts.md#field-ownership).
- Keep release sets independent under `sets/<id>`. Put `release-index.toml` outside those unchanged artifact roots. Requested modes and generated dependencies are separate lists.
- Keep build outputs outside the checkout by default. Ninja files, depfiles, linker scripts, stamps, and staging directories are internal. Legacy exports are copies into another directory.

Run `pixi run test` locally for relevant implementation changes. Validate generated artifacts with `pixi run python make/layout.py verify --build-dir ../build`. Check documentation changes against the actual CLI, manifests, and protocol, then run `git diff --check`. Do not add CI or hooks for this workflow. Compilation, PREVAIL acceptance, hash verification, and device execution are separate evidence. Do not report unrun checks as passed.

Publication is a local manual action through `pixi run publish-artifacts --plan PLAN --tag TAG`. Formal publication requires clean `main` and explicit tag/commit confirmation. Agents test tag creation, upload, and Release behavior with mocks only. Do not create a Release while implementing or testing the publisher. See [the artifact reference](docs/artifacts.md) for the release matrix and packaging contract.
