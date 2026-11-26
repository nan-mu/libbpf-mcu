# Program artifacts and local releases

The `rv32imc` build target uses the ILP32 ABI and no FPU. The current XPOST machine profile supports ESP32-C3. The Rust host tool uses `xpost-elf` for XPM1 and Compact ELF V0. Its Rust dependencies on XPOST are pinned in `tools/Cargo.toml` and `tools/Cargo.lock` to the main commit that merged the dynamic host encoder. The local verifier checks the V0 field bounds, layout and payload digest. XPOST owns installation and device storage limits.

## Program layout

`--build-dir` selects the whole build root and defaults to `build/` in the checkout. Each program has its own directory and `index.toml`. A program archive starts at that directory. `<p>` is the C source stem.

The default build produces this archive layout for each program.

```text
<p>/
├── index.toml
├── <p>.c
├── report.md
├── objects/
│   ├── <p>_bpf.o
│   └── <p>_rv32.o
└── images/
    ├── llvm-aot.bin
    ├── llvm-aot.json
    ├── jit.bin
    ├── jit.json
    ├── ebpf.bin
    └── ebpf.json
```

The v3 program index records the program identity, source snapshot, original BPF object and one `[[mode]]` per deployment. Each portable row contains `image` and `layout` member records with a canonical relative path, byte length and SHA-256. `fixup_sites` lists the required fixup offsets in order. The `llvm-aot` row also records `object`, the RV32IMC relocatable reference. The original BPF and RV32 objects support audit and independent reference builds.

| Mode | Role | Format |
| --- | --- | --- |
| `llvm-aot` | `native_image` | `rv32imc-le` |
| `jit` | `native_image` | `rv32im-le` |
| `ebpf` | `interpreter_image` | `rbpf-map-index-le` |

An explicit build with `--firmware ELF` still produces a `xpost_container` row with `format = "xpost-compact-elf-v0"` and the `elf` member under `containers/`. `layout.py verify` can check either representation. The release verifier requires portable rows in all three modes for all 12 programs.

The top-level C snapshot incorporates quoted program headers resolved relative to the including file, including for sources selected outside the repository. It preserves comments, conditional branches for host, eBPF and RV32 compilation, and references to the target SDK. Conventional header guards also apply to recursive includes. Each `#pragma once` sets a guard for its header when the preprocessor reaches the directive. Ordinary headers can expand repeatedly under different macro definitions. Recompile the snapshot with the corresponding SDK headers and build flags. The report embeds these same source bytes, and the index hashes them.

PREVAIL checks the original Clang object before the build exposes any program files, including in BPF-only builds. A rejected program requires investigation. In a deployment, the firmware supplies the slot address and capacity. The packer checks the final image size after map rewriting or native linking. Intermediate binaries, linked debug ELFs, linker scripts, dependency fingerprints and failure diagnostics belong to the build root’s private `.ninja/` directory.

## Reading the report

Each program contains one `report.md`. Source appears once. The eBPF chapter groups the original object and the rewritten interpreter payload. The `RV32IMC` chapter groups LLVM AOT and host JIT. Only built modes appear. Each subsection includes a fixed description of its ISA and execution model, instruction bytes, disassembly, and the actual generation steps. BPF addresses are byte offsets in executable sections. The rBPF listing shows the map-indexed payload. Portable native listings use zero-relative addresses and end before map placeholders. Explicit firmware-bound listings use linked RV32 addresses. Build commands may include the build host’s absolute paths.

Run `pixi run python make/layout.py reports --build-dir build` to regenerate reports from a completed local build. Verification of the indexed machine files is independent of Markdown rendering. The archive includes the report from the same build.

## Portable image layout

No-argument `pixi run build` and `prepare-release` produce the release matrix without firmware or a target layout. The programs are `firewall`, `just_drop`, `just_tx`, `noop`, `prime`, `log2`, `copy`, `fletcher32`, `bsort`, `strcmp`, `case_swap` and `case_mark`. XPOST supplies HAL.

Each layout is a UTF-8 JSON object with `schema = "libbpf-mcu.portable-image.v1"` and the `program` and `mode` from the index.

- `base` and `entry_offset` are zero in v1. `alignment` is the required slot alignment in bytes. The native payload is a flat little-endian byte sequence beginning at the entry. `regions` enumerates its ordered nonempty spans. Each has a `name`, `kind` (`code`, `data`, `maps` or `zero`), `offset`, `size` and `alignment`. Gaps are zero-filled, as are map placeholders and zero-fill regions. Native code starts on a halfword boundary for AOT and a word boundary for JIT.
- `maps` are sorted by symbol `name`. Their `offset` is relative to the target slot, and the VMR is `slot + offset`. `placeholder_bytes` bounds the reserved range. `map_type`, `len`, `key_layout` and `value_layout` follow Compact ELF V0. The layout arrays contain bit widths. The implicit ARRAY key has `key_layout = null`. rBPF uses the AOT map ordering and offsets. Its bytecode carries map indices and has no native fixups or map placeholder bytes in the bytecode span.
- Each `fixups` item has a byte `offset`, `kind`, symbolic `target` and signed `addend`. v1 accepts addend zero. Records are strictly ordered and nonoverlapping. AOT retains the result of linking at zero with `-mno-relax` and `--no-relax --emit-relocs`. Intra-image branch and jump displacements remain constant under translation. Unsupported allocatable ELF relocations fail generation. The JIT serializes the output of the existing RV32IM compiler with its map references resolved to zero-relative offsets. Helper sites retain their canonical unresolved encodings.

| Fixup | Width | Canonical value at base zero | Bound value |
| --- | ---: | --- | --- |
| AOT `hi20` | 4 | Map offset | High 20 bits of map VMR after adding `0x800` |
| AOT `lo12-i` / `lo12-s` | 4 | Map offset | Low 12 VMR bits in the I/S immediate |
| AOT `call-pcrel` | 8 | `-offset` | `helper - (slot + offset)` in AUIPC/JALR |
| JIT `call-abs` | 8 | 0 | Absolute helper split across LUI/JALR |
| JIT `map-lddw` | 16 | Map offset | Absolute map VMR in the low LUI/ADDI pair and zero in the high pair |

The split uses the rounded high 20 bits and signed low 12 bits. The PC-relative helper displacement must fit signed 32 bits. Verification checks canonical encoding at every fixup, the indexed site list, and the AOT reference object's relocation inventory or JIT's reserved instruction sequences. A fixed-address image with a rewritten base field fails the canonical encoding check. The ledger and index bind all file bytes to SHA-256. For provenance, obtain the ledger from the trusted release.

## Bind a release image

Build the host encoder once from this producer revision using `cargo build --release --locked --manifest-path tools/Cargo.toml`. Use the resulting executable with `--encoder` or put it on PATH as `xpost-mcu-elf`. Supply the actual slot and helper addresses and the slot capacity from the selected firmware layout.

```sh
pixi run bind-release --program-dir "$unpacked" --mode llvm-aot \
  --slot-address 0x40380200 --slot-length 0xe00 --helper-address 0x40380000 \
  --encoder "$encoder" --output "$output"
```

The binder only opens the index and the selected `image` and `layout` members. It checks the address ranges, alignment, helper disjointness, slot capacity and map VMRs. The encoder wraps the bound payload with `xpost-elf` Compact ELF V0. Completed output is written atomically outside the program directory after the encoded bytes and metadata are checked. For rBPF the binder copies the bytecode and binds its map descriptors to the slot. XPOST owns the subsequent firmware read, deployment integration and device validation.

For an independent reference, `pixi run direct-link-reference --program-dir "$unpacked" --mode llvm-aot --firmware "$firmware" --output "$reference"` links the archived RV32 object using LLD. `--mode jit` compiles and links the archived BPF object with the host JIT. This separate CLI accepts `--slot-symbol`. The comparison script in `make/compare_release.py` runs the binding CLI with only the indexed binding members, and compares those bytes and metadata with direct links at both layouts.

## Publish program artifacts

An explicit request to publish the current `nan-mu/libbpf-mcu` `main` authorizes the agent to build, tag, upload and publish the GitHub Release. The required release matrix is the 12 programs above with all three modes, for 36 deployment inputs. Keep the v3 program index and the [portable members](#program-layout).

1. **Pin the build.** Confirm the destination and authenticated account with `gh repo view nan-mu/libbpf-mcu --json nameWithOwner` and `gh auth status --hostname github.com`. Fetch `main`, record its full SHA, and create a fresh detached worktree at that SHA with an empty `build/`. Initialize PREVAIL at the pinned revision or select a verified binary built from that revision with `PREVAIL`.
2. **Build, archive and verify the batch locally.** In that worktree run the following with `$archives` set to a new absolute directory outside the checkout. The prepare command runs the no-argument release build and checks PREVAIL. It verifies the 12×3 matrix, extracts and validates each archive, and compares the extracted files with the build. Any failed check stops preparation before tagging or uploading.

   ```sh
   pixi run prepare-release --archive-dir "$archives"
   pixi run python make/layout.py verify --build-dir build
   pixi run verify-release --archive-dir "$archives" --unpack-dir "$unpacked_batch"
   ```

   `$unpacked_batch` must be a new directory. Keep the 12 verified `<program>.7z` files, and `release.json` for retries. The ledger names each asset and records its archive digest, program paths, member digests and lengths, mode records, build commit and toolchain. Use `verify-release` again before resuming any upload. Add `--build-dir build` to also compare to the build tree. Each asset name equals its archive filename.
3. **Create or resume a draft.** Hold a lock for this repository on the publishing machine through draft discovery, upload and publication. Recheck the remote `main` SHA, the clean worktree and the ledger's commit. Look up tags and Releases for the commit and reuse the matching draft when unambiguous. Run `tag=$(pixi run next-release-tag --commit "$sha")` to resolve the current `v0.1` series. A new allocation increments the maximum decimal patch in that series, starting at `v0.1.0` when the series is empty. Save the pinned SHA and allocated tag alongside the verified batch. On retry, pass `--allocated "$tag"`. If another commit has claimed that ref, the command refreshes the remote tag list and returns the next numeric patch. Verify the tag's resolved commit before creating a draft.

   Create the tag ref if it is absent and the draft if it does not already exist.

   ```sh
   gh api -X POST repos/nan-mu/libbpf-mcu/git/refs -f ref="refs/tags/$tag" -f sha="$sha"
   gh release create "$tag" -R nan-mu/libbpf-mcu --verify-tag --draft --generate-notes
   ```

4. **Upload and publish.** Read the draft's numeric `release_id` and list all of its assets using `gh api --paginate --slurp "repos/nan-mu/libbpf-mcu/releases/$release_id/assets"`. Compare against `release.json`. Upload only missing files, using the API's separate filename and request body.

   ```sh
   gh api --hostname github.com -X POST \
     "https://uploads.github.com/repos/nan-mu/libbpf-mcu/releases/$release_id/assets" \
     -H 'Content-Type: application/x-7z-compressed' --input "$archive" -f "name=$asset"
   ```

   On retry, check the original local bytes against the ledger and reuse matching uploads. An extra asset, an unexpected upload state or a digest conflict stops publication. After uploading, list all assets again. Publish only if the sets match, every asset is `uploaded` with digest `sha256:<local SHA-256>`, and the tag and remote `main` still resolve to the pinned commit. Run `gh release edit "$tag" -R nan-mu/libbpf-mcu --draft=false`, read back the Release and assets by numeric Release ID, and return the Release URL, tag, commit and verified asset names and digests. For an already public Release, verify the existing tag and assets and return its URL. [GitHub Release API](https://docs.github.com/en/rest/releases/releases) · [GitHub asset API](https://docs.github.com/en/rest/releases/assets) · [GitHub CLI request options](https://cli.github.com/manual/gh_api) · [GitHub CLI upload arguments](https://cli.github.com/manual/gh_release_upload)
