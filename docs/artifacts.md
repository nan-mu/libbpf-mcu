# Artifact protocol and release matrix

This reference describes canonical build artifacts and the local release publisher. Paths are relative to `--build-dir`, which defaults to `../build` outside the repository. `<p>` is the unique C source stem.

## Modes and formats

| Mode | Artifact path | Role | Format |
| --- | --- | --- | --- |
| `bpf` | `<p>/bpf/<p>_bpf.o` | `bpf_object` | `elf-bpf-relocatable` |
| `rv32` | `<p>/rv32/<p>_rv32.o` | `aot_object` | `elf-riscv-relocatable` |
| `rv32` | `<p>/rv32/<p>_rv32.debug.elf` | `debug_elf` | `elf-riscv-linked` |
| `rv32` | `<p>/rv32/<p>_rv32.bin` | `image` | `raw-rv32-image` |
| `rv32` | `<p>/rv32/<p>_rv32.elf` | `xpost_container` | `xpost-compact-elf-v0` |
| `jit` | `<p>/jit/<p>_jit.bin` | `image` | `raw-rv32-image` |
| `jit` | `<p>/jit/<p>_jit.elf` | `xpost_container` | `xpost-compact-elf-v0` |
| `bpf-xpost` | `<p>/bpf-xpost/<p>_bpf-xpost.bin` | `image` | `raw-ebpf-image` |
| `bpf-xpost` | `<p>/bpf-xpost/<p>_bpf-xpost.elf` | `xpost_container` | `xpost-compact-elf-v0` |

Every produced mode has `<p>/<mode>/report.toml`. The program has `<p>/manifest.toml`, and the build root has `index.toml`. `<p>/bpf/prevail.ok` exists only after PREVAIL runs. It is an internal gate stamp, not an official artifact.

The BPF object is the original Clang ELF. AOT independently compiles C to RV32IMC. Its BPF input establishes the verification gate, not the AOT compiler input. Host JIT translates eBPF to RV32IM and emits no relocatable `.o`. `bpf-xpost` packages eBPF for the rBPF interpreter and rewrites map references to indices. It is not another compiler.

The `.elf` suffix does not identify an engine. The RV32 debug ELF and the Compact ELF V0 containers have different roles and formats. Containers are primary artifacts. The BPF object is primary in `bpf`. If `--no-compact-elf` suppresses an AOT container, its raw image becomes primary instead. Release plans always produce backend containers.

Ninja graphs, depfiles, linker scripts, gate stamps, and staging files are internal. They do not appear in `[[artifact]]`.

## Field ownership

The writer owns the meaning of each field. A consumer validates the v1 hash links and chooses a mode, role, and format. Release matrix metadata adds an outer selection layer. XPOST consumers do not need new fields in the existing artifact schemas.

| Location and fields | Owner | Meaning and validation |
| --- | --- | --- |
| `index.schema` | Layout publisher | `libbpf-mcu.artifacts.v1`. |
| `index.program[].name`, `.manifest`, `.manifest_sha256` | Layout publisher | Program name, build-root-relative manifest path, and SHA-256 of its bytes. Entries are sorted by name and include programs with consumable modes. |
| `manifest.schema`, `.program` | Layout publisher | `libbpf-mcu.program.v1` and the source stem identifying the program. |
| `manifest.source` | Source probe | Same source record as a report. Establishes which program source the manifest represents. |
| `manifest.mode[].name`, `.report`, `.report_sha256` | Layout publisher | Consumable mode name, manifest-relative report path, and SHA-256 of its bytes. |
| `manifest.stale[]`, `manifest.failed[]` | Layout publisher | Nonconsumable modes with `name`, manifest-relative `report`, and `reason`. Other valid modes remain available. |
| `report.schema` | Layout publisher | `libbpf-mcu.report.v1`. |
| `report.program`, `.mode`, `.status` | Mode publisher | Source stem, one of `bpf`, `rv32`, `jit`, or `bpf-xpost`, and `success`, `failed`, or `unsupported`. Only validated `success` is consumable. |
| `source.repo`, `.commit`, `.dirty`, `.path`, `.sha256` | Source probe | Repository URL, source commit, working-tree state, source path, and primary C file hash. `dirty` is provenance, not part of `source_id`. |
| `build.source_id` | Layout publisher | SHA-256 of canonical JSON containing `repo`, `commit`, `path`, and `sha256` from `[source]`. |
| `build.input_set_id` | Layout publisher | Fingerprint of primary source, dependencies, input artifacts, and firmware hash when present. Details below. |
| `build.configuration_id` | Layout publisher | Fingerprint of logical arguments, flags, target properties, ordered options, and toolchain. It is separate from the source and input fingerprints. |
| `build.argv` | Mode publisher | Logical argument vector for identity. It uses protocol mode names and is not necessarily a command to paste into the CLI. |
| `build.diagnostic_argv` | Mode publisher | Diagnostic invocation with absolute paths redacted to `$REPO`, `$HOME`, `$BUILD`, or `$PATH`. Excluded from configuration identity. |
| `build.cflags`, `.ldflags`, `.opt`, `.target`, `.isa`, `.abi`, `.endian` | Mode publisher | Effective flag descriptions, optimization, target, instruction set, ABI, and byte order. Used in configuration identity. |
| `build.options` | Mode publisher | Serialized option strings in canonical key order. Includes options that affect packaging and firmware linking. Used in configuration identity. |
| `dependency[].path`, `.role`, `.sha256` | Dependency collector | Nonprimary file inputs, such as headers and linker files. Repository-relative paths stay relative. External files use `external/<first-16-hash-digits>/<name>`. |
| `input_artifact[].role`, `.path`, `.sha256` | Mode publisher | Declared artifacts consumed by the mode. Paths are relative to the report and must resolve within the program directory, including through symlinks. |
| `artifact[].role`, `.path`, `.format`, `.sha256`, `.size_bytes`, `.primary` | Mode publisher | Output purpose, report-relative path, format, content hash, byte count, and primary-output marker. Role and format come from the table above. |
| `toolchain` | Mode publisher | Recorded compiler, verifier, Rust, JIT-package, or packer identities for the mode. Keys are serialized in sorted order. |
| `firmware.sha256` | Firmware probe | Hash of the linked firmware ELF. The ELF is not packaged. Raw BPF reports have no firmware table. |
| `firmware.helper_addr`, `.slot_addr`, `.slot_len`, `.table_addr`, `.table_len`, `.slot_symbol` | XPM1 probe and optional slot override | Firmware helper, code slot, and map table addresses and lengths. The optional symbol replaces the slot address and length and records that choice. Values are strings. |
| `verification.status`, `.input_sha256`, `.verifier`, `.verifier_id`, `.options` | PREVAIL gate | `not_run`, `accepted`, `rejected`, or `unsupported`, plus the checked BPF hash and verifier identity/options. BPF-only builds record `not_run`. |
| `maps`, `CORE`, `xdp`, `text` and section measurements | Object/BTF reporter | Object layout, map definitions, BTF-derived metadata, and optional section contents. `--release` omits section contents. `aot_addr` belongs in the RV32 report only. |
| `jit` | Host JIT | Map VMRs, relocations, image length, and compile timing. These describe host compilation, not device performance. |
| `rbpf.map_index`, `.addr_report`, `.addr_sha256` | rBPF packer | Map-index rewriting and the RV32 address report used to derive the metadata. Its bytes are also bound by the `map_index_basis` input artifact. |

A report never stores its own hash. The manifest owns the report hash, and the index owns the manifest hash. Artifacts and input artifacts own their content hashes in the report. This chain allows a whole artifact root to move without rewriting relative links.

### Fingerprints and options

Canonical JSON uses sorted object keys, compact separators, and ASCII escaping. SHA-256 hashes its UTF-8 bytes. These rules preserve the current v1 identifiers.

`source_id` hashes exactly the four source fields listed above. The primary source is deliberately absent from `[[dependency]]`. It remains in the input fingerprint as a `{path, sha256}` row.

`input_set_id` hashes a list of `{path, sha256}` rows. Rows come from dependencies, the primary source, and input artifacts. Firmware contributes a row with path `firmware`. The list is sorted by `(path, sha256)`. Dependency and input roles are descriptions, not keys in this hash. Thus the primary source still changes the fingerprint even when a depfile also names it.

`configuration_id` hashes an object containing `abi`, `argv`, `cflags`, `endian`, `isa`, `ldflags`, `opt`, `options`, `target`, and `toolchain`. It does not incorporate `source_id` or `input_set_id`. Consumers retain all three identities to distinguish source, input, and configuration changes.

The serialized `[build.options]` table exposes the exact strings that contribute to configuration identity. To reproduce the fingerprint from a parsed report, convert the table to a list of `[key, value]` pairs sorted by key. Hash that list as `options` alongside the other configuration fields. Hashing the TOML table as a JSON object would produce a different identifier.

| Mode | Option keys and values |
| --- | --- |
| `bpf` | `release` is `"0"` or `"1"`. |
| Backend modes | `container`, `engine`, `helper`, `image_name`, `release`, `slot`, `slot_len`, `slot_symbol`, `table`, `table_len`, in that order. `container` and `release` use `"0"` or `"1"`. Unset names and symbols are `""`. Addresses and lengths use their recorded strings. |

Backend `engine` is `aot`, `jit`, or `rbpf` according to the route. A generated RV32 report from an rBPF build can therefore record `engine = "rbpf"`. This does not change its `rv32` mode or machine-code artifact formats.

BPF records Clang. RV32 records Clang and PREVAIL, and records Rust and the packer when it emits a container. JIT records Rust, the JIT package, the packer, and PREVAIL. rBPF records Rust, the packer, and PREVAIL. Toolchain identities are reported values, not enforced minimum versions.

### Input relationships

| Mode | Input artifact role | Input |
| --- | --- | --- |
| `rv32` | `gate_bpf` | `../bpf/<p>_bpf.o`, accepted by PREVAIL. |
| `jit` | `bpf_object` | `../bpf/<p>_bpf.o`, compiled by the host JIT. |
| `bpf-xpost` | `bpf_object` | `../bpf/<p>_bpf.o`, extracted and patched for interpretation. |
| `bpf-xpost` | `map_index_basis` | `../rv32/report.toml`, the map metadata basis. |

Changing the RV32 report invalidates rBPF through `map_index_basis`, even if the BPF object is unchanged. A changed source identity or input artifact hash makes an older mode stale. Duplicate source stems are errors.

## Publication within a build root

A mode publisher prepares a report, checks its output hashes, replaces `report.toml`, and updates the manifest and index under a lock. Consumers must verify the hash chain rather than trusting an older `success` report after an interrupted build.

A failed mode loses its consumable entry and its image/container outputs. Other modes remain available. A downstream failure does not delete the raw BPF object. PREVAIL rejection leaves no successful RV32 or rBPF container.

Validate an existing root with:

```bash
	pixi run python make/layout.py verify --build-dir ../build
```

Validation checks index-to-manifest and manifest-to-report hashes, artifact hashes and sizes, and input artifact hashes and path containment. A development root can contain a subset of modes. A release set must contain exactly its generated mode closure, with no stale or failed modes.

XPOST resolves `Aot` to `rv32`, `Jit` to `jit`, and `Rbpf` to `bpf-xpost`. Each profile selects its own artifact root and program. In an archive that root is `sets/<id>`. Firmware compilation/flashing, runtime cache management, and device experiments are XPOST responsibilities.

## Release plans and matrix

The publisher accepts `--plan PATH --tag TAG`. It reads a TOML plan with schema `libbpf-mcu.release-plan.v1` and one or more `[[build]]` entries. Firmware paths are relative to the plan file, not the current directory.

This example defines independent normal-slot and idle-slot variants of `case_mark`, plus a firmware-free BPF set:

```toml
	schema = "libbpf-mcu.release-plan.v1"

	[[build]]
	id = "case-mark"
	program = "case_mark"
	modes = ["rv32", "jit", "bpf-xpost"]
	firmware = "firmware.elf"
	image_name = "case_mark"
	release = true

	[[build]]
	id = "case-mark-idle"
	program = "case_mark"
	modes = ["rv32", "bpf-xpost"]
	firmware = "firmware.elf"
	image_name = "case_mark_idle"
	slot_symbol = "xdp_slot_idle"
	release = true

	[[build]]
	id = "firewall-bpf"
	program = "firewall"
	modes = ["bpf"]
```

`firmware.elf` and `xdp_slot_idle` are example inputs to replace with an actual linked firmware and slot symbol. This plan is a configuration example, not execution evidence.

| Plan field | Requirement |
| --- | --- |
| `id` | Required. Matches `[A-Za-z0-9][A-Za-z0-9_-]*`. Unique without regard to case. Determines the independent output root. |
| `program` | Required. One unique source stem in the default tests, excluding `unused`. |
| `modes` | Required nonempty list of distinct `bpf`, `rv32`, `jit`, or `bpf-xpost` values. Order is retained as the requested list. |
| `firmware` | Required for any backend mode. Linked firmware ELF with XPM1. Relative to the plan file. |
| `image_name` | Optional backend option. Matches `[A-Za-z0-9_]{1,31}`. Defaults to the program name in the container. Does not rename files. |
| `slot_symbol` | Optional backend option. Matches `[A-Za-z_][A-Za-z0-9_]*`. Overrides the XPM1 slot address and length. Rejected if `jit` is requested. |
| `release` | Optional backend boolean, default `false`. Omits object section contents from reports. |

Unknown plan keys are errors. A BPF-only set rejects firmware, image-name, slot-symbol, and enabled release options. A single set cannot combine JIT with a slot override. Use another set for the slot variant. The plan exposes no `--no-compact-elf` equivalent.

Every set has its own build root and program manifest. Sets sharing a source stem do not overwrite each other's configurations. The generated closure always includes `bpf`, and `bpf-xpost` also requires `rv32`. Generated modes are ordered `bpf`, `rv32`, `jit`, `bpf-xpost`.

| Set | Requested modes | Produced modes | Archive artifact root |
| --- | --- | --- | --- |
| `case-mark` | `rv32`, `jit`, `bpf-xpost` | `bpf`, `rv32`, `jit`, `bpf-xpost` | `sets/case-mark` |
| `case-mark-idle` | `rv32`, `bpf-xpost` | `bpf`, `rv32`, `bpf-xpost` | `sets/case-mark-idle` |
| `firewall-bpf` | `bpf` | `bpf` | `sets/firewall-bpf` |

The publisher builds BPF first, then requested AOT, then rBPF when needed, then JIT. It validates the final RV32 report as the rBPF basis. A failed or unsupported mode aborts packaging with a program/mode diagnostic. Requested modes are never silently omitted.

## Package and publication

Create a local package with a new output directory outside the repository:

```bash
	pixi run publish-artifacts --plan /path/to/release-plan.toml \
	  --tag local-matrix --package-only --out /tmp/new-matrix-package
```

Formal publication uses the same plan interface:

```bash
	pixi run publish-artifacts --plan /path/to/release-plan.toml --tag v0.1.0
```

| Publisher option | Behavior |
| --- | --- |
| `--plan PATH` | Required TOML release plan. Validated before any set build starts. |
| `--tag TAG` | Required explicit unused tag. Never inferred. |
| `--out DIRECTORY` | New directory outside the repository. Default is `<system-temp>/libbpf-mcu-publications/<tag>`. Existing paths are rejected. |
| `--dry-run` | Requires clean local `main` and GitHub checks. Builds and validates without creating a tag or uploading. |
| `--package-only` | Allows development branches and local changes. Builds and validates without calling GitHub. Mutually exclusive with `--dry-run`. |
| `--draft` | Adds `--draft` to the Release creation command. The default upload creates a non-draft Release. |

Formal publication and dry runs require clean local `main` at HEAD, including no untracked changes. The publisher derives the GitHub repository from `origin`, checks `gh` authentication, and rejects an existing local tag, remote tag, or Release. `GH_REPO` does not redirect publication.

The publisher retains an isolated diagnostic directory with build outputs and `commands.log`. It copies only official files into a staging tree, validates each set, checks container metadata against firmware and requested names, creates the archive, extracts it, and repeats validation. Firmware, Ninja files, depfiles, stamps, linker scripts, caches, and staging files are excluded.

The package preserves each canonical artifact root unchanged:

```text
libbpf-mcu-artifacts/
├── release-index.toml
├── sets/
│   ├── case-mark/
│   │   ├── index.toml
│   │   └── case_mark/
│   │       ├── manifest.toml
│   │       ├── bpf/
│   │       ├── rv32/
│   │       ├── jit/
│   │       └── bpf-xpost/
│   ├── case-mark-idle/
│   │   ├── index.toml
│   │   └── case_mark/
│   │       ├── manifest.toml
│   │       ├── bpf/
│   │       ├── rv32/
│   │       └── bpf-xpost/
│   └── firewall-bpf/
│       ├── index.toml
│       └── firewall/
│           ├── manifest.toml
│           └── bpf/
└── SHA256SUMS
```

`release-index.toml` is outside all per-set roots. Its schema is `libbpf-mcu.release-index.v1`. Each `[[set]]` has `id`, `program`, `root`, `requested_modes`, and `produced_modes`. Backend sets also have `firmware_sha256`. Rows follow plan order. `root` is `sets/<id>`. Firmware hashes also remain in the mode reports. The outer index does not replace the v1 index/manifest/report hash chain inside each set.

The internal `SHA256SUMS` covers the release index and every official per-set file except the checksum file itself. The output directory contains `libbpf-mcu-artifacts-<tag>.tar.gz` and a separate `SHA256SUMS` for that archive. Check the extracted tree with `sha256sum -c SHA256SUMS`, or `shasum -a 256 -c SHA256SUMS` on macOS.

After validation, formal publication asks you to type the explicit tag and full source commit, with the destination repository shown. The script rechecks source state, plan hash, firmware hashes, and destination. It atomically creates the missing `refs/tags/<tag>` through `gh api`, then runs `gh release create --verify-tag` with the archive and external checksum file. It does not run `git tag`, push tags, or merge changes. Notes record source commit, branch state, plan hash, and requested/produced sets and firmware hashes.

Upload failures return failure. A failure after tag creation can leave a tag or a partial Release for manual inspection. The script does not overwrite an existing Release. Publication runs through local `gh`; no hosted workflow is used. Agents test publication behavior with mocks rather than creating Releases.

Compilation, PREVAIL acceptance, protocol integrity, and device behavior are distinct evidence. Package validation does not imply device execution or that eBPF verification proves the independently compiled MCU binary safe.

## Legacy export

`artifacts export-legacy` copies one verified mode into a different directory. It refuses a second mode in that directory and never writes back into the canonical root.

```bash
	pixi run python make/cli.py artifacts export-legacy \
	  --build-dir ../build --out /tmp/legacy-rv32 --mode rv32
```

The mode is `rv32`, `jit`, or `bpf-xpost`. Each export copies `<p>/bpf.o`, `<p>/bpf.toml`, and `<p>/<p>.elf`. RV32 also copies `esp32c3.o`, `esp32c3.elf`, and `esp32c3.bin`. Only the legacy RV32 `bpf.toml` merges `aot_addr` into BPF map tables. That merge stays in the copy.

The oracle's `jit/oracle/build/<name>.bpf.o`, `build/jit-check/<name>.bpf.o`, and `make/sail/` outputs are private tooling outputs, not canonical artifacts. Consumers select one explicit mode directory or one explicit legacy export.
