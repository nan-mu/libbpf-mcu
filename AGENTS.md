# Repository invariants

- Target `rv32imc` on ESP32-C3 with ILP32 and no FPU. Host JIT emits RV32IM.
- Compile the same standalone experiment C with the BPF SDK in `include-bpf/` and the MCU SDK in `include/`. Preserve `<p>/objects/<p>_bpf.o` byte for byte after PREVAIL acceptance.
- Keep portable image v1, program index v3 and Compact ELF V0. Use `xpost-elf` for XPM1 and Compact ELF. Resolve firmware addresses from the supplied linked ELF. XPOST owns device deployment.
- Keep stable Ninja intermediates under the selected build root and one `report.md` per program. Keep private intermediates out of archives. Validate relative paths, lengths, hashes and image contents.
- Use the [architecture map](docs/architecture.md) for tool ownership.

Run `cargo test --locked --workspace --exclude xpost-jit-oracle` for implementation changes. For changes to the build, release or generated code, run the applicable [real toolchain and Oracle tests](tests/README.md). Verify generated artifacts with `cargo run --locked -p mcu-object -- verify --build-dir DIR`. Check docs against the actual CLI and formats. Run `git diff --check`. Record compilation, PREVAIL acceptance, byte integrity, independent semantics and device execution separately.

An explicit publication request authorizes a GitHub Release from clean `main`. Build the complete matrix in a fresh worktree, then archive and verify it locally. Follow the [publication procedure](docs/artifacts.md#publish-program-artifacts) for tags, upload and retry.
