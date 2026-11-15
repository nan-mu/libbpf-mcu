# Artifact reports

Reference for the files under `--build-dir`. The default directory is `../build`, outside this repository. Paths below are relative to that directory. `<p>` is the C source stem.

A file is consumable only when `index.toml`, `<p>/manifest.toml`, and the mode `report.toml` agree on hashes, and every `[[artifact]]` hash matches the file next to that report. Moving or renaming the build directory does not change those relative paths.

## Modes

| Path | Format |
| --- | --- |
| `<p>/bpf/<p>_bpf.o` | `elf-bpf-relocatable` |
| `<p>/bpf/report.toml` | BPF report, including `[maps]` |
| `<p>/bpf/prevail.ok` | Gate stamp. Present only after PREVAIL runs. |
| `<p>/rv32/<p>_rv32.o` | `elf-riscv-relocatable` |
| `<p>/rv32/<p>_rv32.debug.elf` | `elf-riscv-linked` |
| `<p>/rv32/<p>_rv32.bin` | `raw-rv32-image` |
| `<p>/rv32/<p>_rv32.elf` | `xpost-compact-elf-v0` |
| `<p>/jit/<p>_jit.bin` | `raw-rv32-image` |
| `<p>/jit/<p>_jit.elf` | `xpost-compact-elf-v0` |
| `<p>/bpf-xpost/<p>_bpf-xpost.bin` | `raw-ebpf-image` |
| `<p>/bpf-xpost/<p>_bpf-xpost.elf` | `xpost-compact-elf-v0` |

`bpf-xpost` is the rBPF container packed from the raw BPF object. It is not a fourth compiler, and it is not the raw BPF ELF. JIT does not emit `<p>_jit.o`.

The suffix `.elf` is not an engine. `role` is `bpf_object`, `aot_object`, `debug_elf`, `image`, or `xpost_container`.

Ninja files, depfiles, the generated linker script, and `.stage` are internal. They are not `[[artifact]]` entries.

## index.toml

`schema` is `libbpf-mcu.artifacts.v1`. Each `[[program]]` has `name`, `manifest`, and `manifest_sha256`. `manifest` is relative to the build root. Programs are sorted by name. A program is listed only when at least one mode is still consumable. A failed mode does not remove the other modes.

## manifest.toml

`schema` is `libbpf-mcu.program.v1`. `[source]` has `repo`, `commit`, `dirty`, `path`, and `sha256`. Each consumable `[[mode]]` has `name` (`bpf`, `rv32`, `jit`, or `bpf-xpost`), `report`, and `report_sha256`. `report` is relative to the manifest.

`[[stale]]` and `[[failed]]` are not consumable. A mode becomes stale when its `source_id` no longer matches the source being published, or when it names a BPF object whose bytes changed. The same source file hash is not a build configuration. `configuration_id` is separate.

Two C files with the same stem are still an error. The build does not overwrite one with the other.

## report.toml

`schema` is `libbpf-mcu.report.v1`. Top-level fields are `program`, `mode`, and `status` (`success`, `failed`, or `unsupported`). Only `success` plus matching hashes is consumable. The report lists hashes of other files and does not contain its own hash. The manifest stores that hash.

`[source]` matches the manifest source fields.

`[build]` has `source_id`, `input_set_id`, `configuration_id`, `argv`, `diagnostic_argv`, `cflags`, `ldflags`, `opt`, `target`, `isa`, `abi`, and `endian`. `source_id` is the repository, commit, source path, and source bytes. `input_set_id` adds every dependency the mode actually read, including headers, plus input artifacts and the firmware hash when the mode has one. `configuration_id` adds the toolchain versions and the flags. `diagnostic_argv` is not part of `configuration_id`. Absolute paths in it are rewritten to `$REPO`, `$HOME`, `$BUILD`, or `$PATH`. A clock is not stored in the report.

`[[dependency]]` has `path`, `role`, and `sha256`. Paths inside this repository stay repository-relative. A file outside it is `external/<hash>/<name>`.

`[toolchain]` lists only tools that ran. BPF records Clang. RV32 records Clang, and the packer when a container is built. JIT records rustc, the JIT package, the packer, and PREVAIL. Unused tools are omitted.

`[[input_artifact]]` has `role`, `path`, and `sha256`. JIT and rBPF use role `bpf_object`. RV32 uses role `gate_bpf` for the BPF object that PREVAIL checked. That object is not the AOT compile input. The AOT compile input is the C source.

`[firmware]` exists only for modes that read a firmware ELF. It has the ELF `sha256` and the XPM1 addresses. The raw BPF report has no firmware table.

`[verification]` has `status` (`not_run`, `accepted`, `rejected`, or `unsupported`), `input_sha256`, `verifier`, `verifier_id`, and `options`. A BPF-only build leaves `not_run`. `prevail.ok` binds the BPF bytes and the verifier id. A stamp for different bytes is `rejected`.

`[[artifact]]` has `role`, `path`, `format`, `sha256`, `size_bytes`, and `primary`. `path` is relative to the report file.

Map and BTF tables stay in the report as `[maps.<name>]` and `[CORE]`. AOT addresses are `aot_addr` on the RV32 report only. JIT map VMRs, relocations, image length, and timing stay under `[jit]`. The rBPF report records `[rbpf]` with `map_index` and the address-report hash used for that pack.

## Publish and failure

A mode is published by writing the report to a temporary file, checking the artifact hashes, then replacing `report.toml` and updating the manifest and index under one lock. If that sequence stops, a consumer that checks hashes does not treat an older `success` report as the new result.

A failed mode drops its own consumable entry and deletes that mode's image and container files. It does not delete another mode, and it does not delete `<p>_bpf.o` unless the BPF mode itself failed. PREVAIL rejection leaves no RV32 or rBPF success container.

A successful build is not a device run.

## Old paths

`artifacts export-legacy` copies one mode into a different directory. It does not write back into the canonical tree, and it refuses a second mode in the same output directory.

```bash
python make/cli.py artifacts export-legacy \
  --build-dir ../build \
  --out /tmp/legacy-rv32 \
  --mode rv32
```

`--mode` is `rv32`, `jit`, or `bpf-xpost`. The copy uses the old names `<p>/bpf.o`, `<p>/bpf.toml`, and `<p>/<p>.elf`. RV32 also copies `esp32c3.o`, `esp32c3.elf`, and `esp32c3.bin`. The legacy `bpf.toml` for RV32 is the only place that still merges `aot_addr` into the BPF map tables, and that merge stays in the copy.

These paths are not the published tree:

| Path | Why it stays |
| --- | --- |
| `jit/oracle/build/<name>.bpf.o` | The oracle compiles its own objects. |
| `build/jit-check/<name>.bpf.o` | `jit/scripts/check-xdp.sh` compiles into that private directory. |
| `make/sail/` outputs | The sail script writes its own directory. |

Do not point a consumer at whichever `.elf` was written last in the build root. Use one mode directory, or one legacy export of one mode.
