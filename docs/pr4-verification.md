# PR #4 local verification

This revision was checked locally on 2026-11-18 from the development tree based on `26077194182fedf9e588eab771dd2f44411067ba`. The package smoke used real LLVM, PREVAIL, Ninja, Rust host tools, and the current XPOST resolver. Its firmware inputs were generated ELF fixtures with valid XPM1 records and a sized `xdp_slot_idle` symbol. They were not flashed to hardware. The development package records the source tree as dirty; it is not a formal release.

## Local test entry point

```bash
pixi run test
```

The command passed 84 Python unittest cases, the standalone PREVAIL rejection checks, 51 Rust JIT tests, and two Rust host-tool tests. Parameterized publisher methods exercise additional cases within those counts. The entry point runs:

- BTF layout, PREVAIL selection and negative programs, and reentrancy/model checks.
- XPOST ELF, XPM1, and Compact ELF parity tests.
- Real JIT/AOT/rBPF build checks.
- 19 artifact layout tests, 15 publisher test methods, and five Ninja incremental tests.
- `cargo test --manifest-path jit/Cargo.toml` and `cargo test --manifest-path tools/Cargo.toml`.

Publisher fixtures cover invalid plans and options, case-insensitive set collisions, missing firmware, failed firmware inspection, BPF-only sets, backend subsets, isolated repeated programs, stale modes, missing artifacts and inputs, hash/size/primary mismatches, incorrect input roles and targets, invalid manifest/report hashes, symlinks, incorrect firmware addresses, incorrect options, and incorrect embedded names. Publication calls are mocked: dirty/non-main source trees, existing local/remote tags and Releases, missing tools, authentication failure, each matrix build call failing, rejected verification, declined confirmation, tag creation races, firmware mutation, upload failure, dry-run, and package-only behavior are tested. No real tag or Release was created.

The local quality checks passed:

```bash
pixi run python -m compileall -q make scripts
uvx ruff==0.14.5 check --select E9,F63,F7,F82 make scripts
uvx ruff==0.14.5 format --check scripts/publish_artifacts.py scripts/test_publish_artifacts.py
git diff --check
```

Ruff is invoked as a local development tool; the publisher gains no runtime dependency. No remote test job or hook framework is part of this delivery.

## Real multi-firmware matrix

The smoke plan contained three isolated sets:

| Set ID | Program | Requested modes | Produced modes | Container name | Slot |
| --- | --- | --- | --- | --- | --- |
| `firewall` | `firewall` | `bpf`, `rv32`, `jit`, `bpf-xpost` | All four | `firewall` | `0x40380200` |
| `case-mark` | `case_mark` | `rv32` | `bpf`, `rv32` | `case_mark` | `0x40390200` |
| `case-mark-idle` | `case_mark` | `rv32` | `bpf`, `rv32` | `case_mark_idle` | `0x40391200` |

The idle set selected `slot_symbol = "xdp_slot_idle"` and `image_name = "case_mark_idle"`. Both case variants retained the same source identity and firmware hash, with different configuration/input identities and independently hashed containers. Their canonical filenames remain `case_mark/rv32/case_mark_rv32.elf` under different roots.

| Firmware input | SHA-256 | Helper | Default slot / length | Table / length |
| --- | --- | --- | --- | --- |
| Firewall fixture | `be7b8414bffe1308ae7a6faab8fba4cbbbc31e83c73193405adfe5e6e8e858ec` | `0x40380000` | `0x40380200 / 0xe00` | `0x310000 / 0x10000` |
| Case fixture | `e02064e663d251f558f48ae17ce7806a72149480df18261b927cb770b7c7426c` | `0x40390000` | `0x40390200 / 0xe00` | `0x320000 / 0x10000` |

All backend reports matched their set's firmware hash and effective XPM1/symbol addresses. The packer's Rust decoder validated the embedded name, slot, helper, and machine. The AOT container remained declared and consumable after rBPF packing.

The final command was:

```bash
pixi run publish-artifacts --plan <smoke-root>/release-plan.toml \
  --tag pr4-matrix-final --package-only --out <smoke-root>/final-package
```

Its build and validation output was:

```text
[2/5] Build firewall/bpf-xpost
[2/5] Build firewall/jit
[2/5] Build case-mark/rv32
[2/5] Build case-mark-idle/rv32
[3/5] Validate sets and dependencies
[4/5] Stage, checksum, archive, extract, and validate again
verified archive: .../libbpf-mcu-artifacts-pr4-matrix-final.tar.gz
[5/5] Local validation complete; upload disabled
```

The rBPF route generated the BPF and AOT prerequisites. There was no separate redundant AOT or BPF invocation for the four-mode set.

## Archive and consumer evidence

```text
libbpf-mcu-artifacts/
├── release-index.toml
├── sets/
│   ├── firewall/index.toml + firewall/{manifest.toml,bpf/,rv32/,jit/,bpf-xpost/}
│   ├── case-mark/index.toml + case_mark/{manifest.toml,bpf/,rv32/}
│   └── case-mark-idle/index.toml + case_mark/{manifest.toml,bpf/,rv32/}
└── SHA256SUMS
```

The final archive SHA-256 is `8de53d3687dd4ad6cc2bd23821ebb346fab80b3dc53a2c6253b6ee5c1cb9a459`.

Independent extraction verified the external checksum for the archive and all 34 internal official files. Each set passed `layout.verify_tree()` and `load_mode()` from its extracted root. The exact official-file allowlist excluded firmware, Ninja files, depfiles, stages, caches, diagnostics, and host binaries.

A separate temporary Rust runner called the existing `xpost_artifact::resolve_flash_image()` against the extracted roots, using fresh caches and each set's expected firmware hash:

```text
resolved firewall Aot
resolved firewall Jit
resolved firewall Rbpf
resolved case-mark Aot          profile=case_mark
resolved case-mark-idle Aot     profile=case_mark_idle
```

The producer mappings remain `Aot -> rv32`, `Jit -> jit`, and `Rbpf -> bpf-xpost`. The consumer crate was read and used without modification. Its ordinary resolution does not need the outer release index or the new readable build options.

Retained local evidence:

- Smoke inputs, package, independent extraction, resolver runner, and fresh caches: `/private/var/folders/sx/y9r434kd5g7gld19gj1wz1kc0000gn/T/pr4-matrix-smoke-tv9sd0p6`.
- Publisher diagnostics and original independent build roots: `/var/folders/sx/y9r434kd5g7gld19gj1wz1kc0000gn/T/libbpf-mcu-publish-13o5p1di`.
- Logs: `/tmp/pr4-local-tests-final.log`, `/tmp/pr4-matrix-final.log`, and `/tmp/pr4-matrix-verify.log`.

These temporary paths are local evidence, not packaged inputs or public download URLs.

## Incremental build regression

A fresh default-target `just_drop` build used an external directory and the same valid firewall fixture:

```text
First command:     ten Ninja steps, including BPF, PREVAIL, RV32 link/pack/publish
Identical command: ninja: no work to do.
Firmware ident byte changed, XPM1 unchanged:
[1/1] publish rv32 just_drop
```

The final RV32 report matched the changed firmware SHA-256. No PREVAIL, BPF/RV32 compilation, link, or pack step repeated on the firmware-only change. Logs are retained under the smoke root as `first.log`, `second.log`, and `firmware.log`.

The layout/incremental regressions also verify BPF changes, every input artifact, allowed cross-mode references, traversal/absolute/symlink rejection, RV32 report changes making `bpf-xpost` stale, refusal by `load_mode()`, and preservation of unrelated successful modes through the manifest and index.

## Scope and provenance

The three v1 schema identifiers and the index-to-manifest-to-report-to-artifact hash chain remain intact. The primary source is recorded once per report and remains in `input_set_id`; serialized `[build.options]` reproduces the options used in `configuration_id`. No Compact ELF, XPM1, firmware ABI, or map/VMR semantics changed.

The workflow file introduced earlier in PR #4 was deleted. All evidence here is local. No device execution, PR merge, tag push, real Release, or binary upload was performed. Six pre-existing untracked files under `artifacts/` were preserved and excluded from the commit; they prevent claiming a completely clean working tree even when tracked files are clean.
