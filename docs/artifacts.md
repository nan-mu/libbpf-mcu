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

## Local release command

Development builds and `artifacts export-legacy` do not contact GitHub. Validate consumable modes in an existing tree with:

```bash
pixi run python make/layout.py verify --build-dir ../build
```

This checks the index-to-manifest and manifest-to-report hashes, output hashes and sizes, and every input artifact hash. Input paths resolve within the program directory, including through symlinks. Legal sibling references include `../bpf/<p>_bpf.o` and `../rv32/report.toml`. RV32 report changes invalidate rBPF's `map_index_basis`; the manifest records that mode as stale and `load_mode()` rejects it. Other valid modes remain available. A development tree may contain only some modes; release validation additionally requires all four modes and no stale or failed modes.

After merging the PR, run publication manually from clean `main`:

```bash
pixi run publish-artifacts --firmware /path/to/firmware.elf --tag v0.1.0
```

The script checks local main identity, tracked and untracked changes, local and remote tag absence, Release absence, `gh auth status`, firmware XPM1, PREVAIL, and build tools. A tag is required and is never inferred. The script refuses an existing Tag or Release. It pins GitHub operations to the repository in `origin`, regardless of `GH_REPO`. It does not execute `git tag` or push a tag. After building and validating, it asks you to type the requested tag and full source commit, showing the destination repository. Only after this confirmation does `gh api` atomically create the missing tag at that commit; a concurrent tag creation aborts publication. `gh release create --verify-tag` then creates the Release and uploads both assets. Default publication creates a non-draft Release.

| Option | Behavior |
| --- | --- |
| `--program STEM` | Select one program. Repeat for several. Default selects all tests outside `unused`. |
| `--out DIRECTORY` | New output directory outside the repository. Default is the system temporary directory under `libbpf-mcu-publications/<tag>`. Existing directories are rejected. |
| `--dry-run` | Require clean main and check GitHub availability; build and verify the package without uploading or creating a tag. |
| `--package-only` | Build and verify locally, including on a development branch. Does not call `gh` or create a Release. Mutually exclusive with dry-run. |
| `--draft` | Create a draft Release when uploading. |

For local acceptance before merge:

```bash
pixi run publish-artifacts --firmware /path/to/firmware.elf \
  --tag local-firewall --program firewall --package-only --out /tmp/new-firewall-package
```

The script creates an isolated build directory, invokes the existing build CLI for BPF, AOT, JIT, and rBPF, then validates every expected mode. rBPF retains the AOT container and publishes against its final RV32 report. An unsupported or failed mode stops publication with the program and mode name. No mode is silently omitted. The diagnostic work directory and `commands.log` remain available after success or failure; remove them yourself when no longer needed.

The script copies only index, manifests, reports, and declared official artifacts into a separate staging tree:

```text
libbpf-mcu-artifacts/
├── index.toml
├── <program>/
│   ├── manifest.toml
│   ├── bpf/
│   ├── rv32/
│   ├── jit/
│   └── bpf-xpost/
└── SHA256SUMS
```

The internal `SHA256SUMS` covers every official file except itself. The output directory contains `libbpf-mcu-artifacts-<tag>.tar.gz` and a separate `SHA256SUMS` covering the archive. After extraction, run `sha256sum -c SHA256SUMS` from the extracted root, or use `shasum -a 256 -c SHA256SUMS` on macOS. The script extracts its own archive and repeats protocol and checksum validation before upload. Firmware, Ninja graphs, depfiles, PREVAIL stamps, linker scripts, caches, and `.stage` files are excluded. Reports retain firmware hashes, source identities, flags, and tool versions.

Release notes include the source commit, firmware hash, and toolchain. Only the archive and its external checksum file are uploaded. Upload errors return a failure; the script does not retry by overwriting an existing Release. A failure after confirmed tag creation can leave a tag or partially uploaded Release requiring manual inspection.

CI runs Python protocol, path, hash, publisher-fixture, and Ninja incremental tests plus syntax, formatting, and static checks. CI does not build or upload formal Release assets. The complete local suite remains `pixi run python make/cli.py test`; its Rust parity tests also require the sibling xpost workspace. Formal publication is always a local manual action.

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
