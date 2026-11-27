# ADR 0001: One Rust workspace, distinct compiler and development tools

Status: accepted, implementation pending
Date: 2026-11-28

## Context

libbpf-mcu combines Python build steps, existing Rust ELF helpers and a separate JIT project. The user wants a directly auditable Ninja graph, individually testable transformations, and an end-to-end build entry without manual installation. Moving the scripts verbatim to Rust would preserve the old boundaries and hidden command chains.

## Decision

Use one Cargo workspace and lockfile, with four executable targets (working names): the specialized build system `mcu`, compiler `mcu-jit`, object processor `mcu-object`, and developer tool `tools` with a `release` subcommand. Normal users use the build system (`build`, `clean`, `test`, `doctor`); no separate configure command, public bootstrap stage or tool-dispatch subcommand. The thin repository launcher resolves/builds local executables; no installation of project tools is required. Build regenerates the Ninja graph and immediately runs Ninja. Cargo and Ninja manage incremental work.

Ninja directly invokes LLVM, PREVAIL and the two internal compilation executables; command capture or dynamic argument plumbing must not hide a second build pipeline. JIT remains independent. Object processing groups ELF, BPF/BTF, image/container, disassembly preparation and report generation. Report aggregates actual outputs and execution evidence; disassembly is its interface and llvm-objdump runs as a Ninja node. Ordinary program indexes and integrity checks are not Release-only functionality. The developer executable orchestrates release preparation, verification and version management outside the normal build graph.

Executable boundaries are not library boundaries. Extract genuinely shared semantics and data contracts into independent Rust library crates with a single authoritative implementation. Consumers may depend on those libraries; no dependency on executable entry points or cycle, no generic dumping ground for unrelated helpers. Independently test feature contracts and algorithms, real Ninja scheduling, real-toolchain smoke builds and full release matrices.

## Consequences

More explicit file contracts and graph edges are needed; algorithms can be exercised without the whole build. Existing program archive, portable-image and Compact ELF wire contracts stay in force. Binding remains a separate reusable operation on published bytes, and independent direct linking remains a test reference, not a second production compiler. Normal builds never depend on the developer executable. Names and exact crate boundaries are not frozen.

Source: libbpf-mcu OpenSpec design conversation, 2026-11-25 through 2026-11-28: user approved the four-program architecture, direct Ninja invocation, removal of configure and the source snapshot generator; final confirmation requires independent shared Rust libraries.
