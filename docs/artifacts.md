# Program artifacts and local releases

The `rv32imc` build target uses the ILP32 ABI and no FPU. The current XPOST machine profile supports ESP32-C3. The Rust host tool uses `xpost-elf` for XPM1 and Compact ELF V0. The workspace pins its Rust dependencies on XPOST in `Cargo.lock`. The local verifier checks the V0 field bounds, layout and payload digest. XPOST owns installation and device storage limits.

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

The v3 program index records the program identity, standalone source, original BPF object and one `[[mode]]` per deployment. Each portable row contains `image` and `layout` member records with a canonical relative path, byte length and SHA-256. `fixup_sites` lists the required fixup offsets in order. The `llvm-aot` row also records `object`, the RV32IMC relocatable reference. The original BPF and RV32 objects support audit and independent reference builds.

| Mode | Role | Format |
| --- | --- | --- |
| `llvm-aot` | `native_image` | `rv32imc-le` |
| `jit` | `native_image` | `rv32im-le` |
| `ebpf` | `interpreter_image` | `rbpf-map-index-le` |

The C file preserves the exact bytes compiled by both target SDKs. PREVAIL checks the original Clang object before publication. Stable build intermediates and Ninja metadata live outside program directories.

## Reading the report

Each program has one `report.md` with the source once and listings for the built modes. The eBPF listing uses section byte offsets. The native listings show RV32IMC AOT and RV32IM JIT instructions at their zero-relative link addresses. The build recipes come from the current Ninja graph.

## Portable image layout

`cargo run --locked -p mcu -- build` produces the release matrix without firmware or a target layout. The programs are `firewall`, `just_drop`, `just_tx`, `noop`, `prime`, `log2`, `copy`, `fletcher32`, `bsort`, `strcmp`, `case_swap` and `case_mark`. XPOST supplies HAL.

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

Use the indexed image and layout from an unpacked program directory. Supply the slot and helper addresses and slot capacity, or use `--firmware ELF` to read its XPM1 record.

```sh
cargo run --locked -p mcu-object -- bind --program-dir "$unpacked" --mode llvm-aot \
  --slot-address 0x40380200 --slot-length 0xe00 --helper-address 0x40380000 \
  --output "$output"
```

The binder checks the range, alignment, helper disjointness, map addresses and slot capacity and writes a Compact ELF V0 container. For rBPF it carries the same bytecode and binds the map descriptors to the slot. XPOST owns deployment and device validation.

Use `cargo run --locked -p mcu-dev-tools -- reference --program-dir "$unpacked" --mode llvm-aot --firmware "$firmware" --work-dir "$build/intermediates/reference" --output "$reference"` to generate an independent direct link. Select `--mode jit` to compile and link the original eBPF with the host JIT.

## Build and clean

Use a new or empty output directory for the first `cargo run --locked -p mcu -- build`. The default is `build/` in the checkout. The build writes a `.mcu-build` marker tied to the checkout and directory, so subsequent builds and retries may reuse it even if the first run stopped before writing `build.ninja`. Choose a fresh directory or move an older unmanaged build aside before rebuilding.

`cargo run --locked -p mcu -- clean --build-dir DIR` removes the whole owned output tree, including private intermediates. Keep personal files and Cargo caches outside that tree. Build and clean reject unrelated nonempty directories, direct symlinks, Git metadata, checkout content and configured Cargo target directories. Clean also refuses a tree containing a nested Git directory or a tagged cache. An absent or empty unowned directory requires no cleanup.

## Publish program artifacts

An explicit request to publish the current `nan-mu/libbpf-mcu` `main` authorizes the agent to build, tag, upload and publish the GitHub Release. The required release matrix is the 12 programs above with all three modes, for 36 deployment inputs. Keep the v3 program index and the [portable members](#program-layout).

1. **Pin the build.** Confirm the destination and authenticated account with `gh repo view nan-mu/libbpf-mcu --json nameWithOwner` and `gh auth status --hostname github.com`. Fetch `main`, record its full SHA, and create a fresh detached worktree at that SHA with an empty `build/`. Initialize PREVAIL at the pinned revision or select a verified binary built from that revision with `PREVAIL`.
2. **Build, archive and verify the batch locally.** In that worktree run the following with `$archives` set to a new absolute directory outside the checkout. Build the no-argument release matrix first. Release preparation verifies the 12×3 matrix, extracts and validates each archive, and compares the extracted files with the build. Any failed check stops preparation before tagging or uploading.

   ```sh
   cargo run --locked -p mcu -- build
   cargo run --locked -p mcu-object -- verify --build-dir build
   cargo run --locked -p mcu-dev-tools -- release prepare --archive-dir "$archives"
   cargo run --locked -p mcu-dev-tools -- release verify --archive-dir "$archives" --unpack-dir "$unpacked_batch"
   ```

   `$unpacked_batch` must be a new directory. Keep the 12 verified `<program>.7z` files and `release.json` for retries. The ledger records each archive's digest, program paths, member digests and lengths, and mode records. Preparation checks that the indexed C sources match the clean checkout. In ledger v2, `archive_preparation` records the checkout commit, current graph digest, paths and digests of tools named by that graph, and preparation host-tool versions. Those values are observed during archive preparation. The ledger makes no attestation about the checkout, SDK headers, graph or tools used to produce historical build outputs. The fresh pinned build in step 1 establishes that procedure for formal publication. `tools release verify` verifies archive contents and accepts v1 and v2 ledgers. Add `--build-dir build` to also compare to the build tree.
3. **Create or resume a draft.** Hold a lock for this repository on the publishing machine through draft discovery, upload and publication. Recheck the remote `main` SHA, the clean pinned worktree and the checkout commit observed during preparation. Look up tags and Releases for the commit and reuse the matching draft when unambiguous. Run `tag=$(cargo run --locked -p mcu-dev-tools -- release next-tag --commit "$sha")` to resolve the current `v0.1` series. A new allocation increments the maximum decimal patch in that series, starting at `v0.1.0` when the series is empty. Save the pinned SHA and allocated tag alongside the verified batch. On retry, pass `--allocated "$tag"`. If another commit has claimed that ref, the command refreshes the remote tag list and returns the next numeric patch. Verify the tag's resolved commit before creating a draft.

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
