# Program artifacts and local releases

The `rv32imc` build target uses the ILP32 ABI and no FPU. The current XPOST machine profile supports ESP32-C3. The Rust host tool uses the sibling XPOST workspace's `xpost-elf` crate for XPM1 and Compact ELF V0. The local verifier checks the same wire format and payload digest. The 8192-byte container ceiling and 256-entry map limit mirror XPOST revision `94bfe6d8`. The device builder uses the same map limit and checks the configured image cell capacity. [XPOST encoder](https://github.com/nan-mu/xpost/blob/94bfe6d8dc7747b7565ba6e3be20e9083ea893e8/xpost-elf/src/encode.rs#L8-L17) · [Device image and map builder](https://github.com/nan-mu/xpost/blob/94bfe6d8dc7747b7565ba6e3be20e9083ea893e8/src/xdp/image/builder.rs#L209-L266) · [Device storage default](https://github.com/nan-mu/xpost/blob/94bfe6d8dc7747b7565ba6e3be20e9083ea893e8/src/xdp/table/storage.rs#L17-L21)

## Program layout

`--build-dir` selects the whole build root and defaults to `build/` in the checkout. Each program has its own directory and `index.toml`. A program archive starts at that directory. `<p>` is the C source stem.

A full `just_tx` program with all three deployments has these eight files:

```text
just_tx/
├── index.toml
├── just_tx.c
├── report.md
├── objects/
│   ├── just_tx_bpf.o
│   └── just_tx_rv32.o
└── containers/
    ├── just_tx-vm-aot.elf
    ├── just_tx-vm-ebpf.elf
    └── just_tx-vm-jit.elf
```

A fresh `pixi run build` builds three deployments for each release program. The native object carries the LLVM AOT relocations. The original BPF object carries the relocations and instructions used to regenerate the JIT fixups and the interpreter's map bindings.

The machine contract is `libbpf-mcu.program-index.v3`. It records the program, source snapshot, original BPF ELF and one `[[mode]]` per deployment. Each deployment records its container. LLVM AOT also records the native relocatable object. Each referenced file has a canonical relative path, byte length and SHA-256. Use `pixi run python make/layout.py verify --build-dir DIR` on a build root or an extracted program directory to check the indexed bytes and ELF format.

The top-level C snapshot incorporates quoted program headers resolved relative to the including file, including for sources selected outside the repository. It preserves comments, conditional branches for host, eBPF and RV32 compilation, and references to the target SDK. Conventional header guards also apply to recursive includes. Each `#pragma once` sets a guard for its header when the preprocessor reaches the directive. Ordinary headers can expand repeatedly under different macro definitions. Recompile the snapshot with the corresponding SDK headers and build flags. The report embeds these same source bytes, and the index hashes them.

PREVAIL checks the original Clang object before the build exposes any program files, including in BPF-only builds. A rejected program requires investigation. In a deployment, the firmware supplies the slot address and capacity. The packer checks the final image size after map rewriting or native linking. Intermediate binaries, linked debug ELFs, linker scripts, dependency fingerprints and failure diagnostics belong to the build root’s private `.ninja/` directory.

## Reading the report

Each program contains one `report.md`. Source appears once. The eBPF chapter groups the original object and the rewritten interpreter payload. The `RV32IMC` chapter groups LLVM AOT and host JIT. Only built modes appear. Each subsection includes a fixed description of its ISA and execution model, instruction bytes, disassembly, and the actual generation steps. BPF addresses are byte offsets in executable sections. The rBPF listing shows the rewritten bytes in the deployed image. LLVM AOT uses linked RV32IMC addresses and checks the listing against the payload. Host JIT shows RV32IM instructions through the end of code, before map storage. Build commands may include the build host’s absolute paths.

Run `pixi run python make/layout.py reports --build-dir build` to regenerate reports from a completed local build. Verification of the indexed machine files is independent of Markdown rendering. The archive includes the report from the same build.

## Release firmware

The default build uses [XPOST `b5a44072ed57657c7482758412cccf1fd93df6fa`](https://github.com/nan-mu/xpost/tree/b5a44072ed57657c7482758412cccf1fd93df6fa). Place a Git checkout containing that commit at `../xpost` or set `LIBBPF_MCU_XPOST`. The build takes the source tree from that commit, including `profiles.toml`, each carrier's `Cargo.lock` and the `xpost-elf` crate. It uses the XPOST nightly toolchain with `rust-src` and builds the firmware with locked Cargo dependencies. Linked firmware ELFs and their source snapshot stay under the build root's private `.ninja/` directory.

```sh
git -C ../xpost fetch origin b5a44072ed57657c7482758412cccf1fd93df6fa
rustup toolchain install nightly --component rust-src --target riscv32imc-unknown-none-elf
```

| Required programs | Native carrier for LLVM AOT and JIT | Interpreter carrier for rBPF |
| --- | --- | --- |
| `firewall` | `firewall-cag` | `firewall-cag` with `xpost/interp` |
| `just_drop`, `just_tx` | `just-drop-cag`, `just-tx-cag` (same `just_xdp` build) | Same profiles with `xpost/interp` |
| `noop`, `prime`, `log2`, `copy`, `fletcher32`, `bsort`, `strcmp` | `exec-bench-aot` | `exec-bench-rbpf` |
| `case_swap`, `case_mark` | `case-cag` with `xpost/perf-aggregate` | `case-cag` with `xpost/perf-aggregate,xpost/interp` |

The pinned case ingress references the aggregate timer unconditionally. Its carrier builds enable that feature. The release gate compares XPM1 with the linked slot and helper symbols and checks both the payload size in SRAM and the Compact ELF size in the cold cell. The report and release ledger record the XPOST revision, firmware build command, compiler, firmware SHA-256 and target layout. HAL remains an XPOST firmware condition.

### Prepare a native image for a different slot

Use the producer revision that built the archive. Extract a program directory, select the mode by its v3 index, and supply the consumer's linked firmware:

```sh
pixi run retarget --program-dir "$unpacked" --mode llvm-aot \
  --firmware "$firmware" --slot-symbol xdp_slot_idle --output "$output"
```

Use `--mode jit` to regenerate the JIT relocation records from the indexed BPF object and link the image at the new slot. AOT relinks the indexed RV32IMC object. The tool reads the helper address from XPM1 and uses the primary slot when `--slot-symbol` is omitted. It verifies the archive's indexed bytes, runs PREVAIL on the original object, and writes the resulting Compact ELF outside the program directory. XPOST handles installation and slot switching.

## Publish program artifacts

An explicit request to publish the current `nan-mu/libbpf-mcu` `main` authorizes the agent to build, tag, upload and publish the GitHub Release. The required release matrix is the 12 programs above with all three modes, for 36 deployments. Keep the v3 program index and the eight members shown under [Program layout](#program-layout).

1. **Pin the build.** Confirm the destination and authenticated account with `gh repo view nan-mu/libbpf-mcu --json nameWithOwner` and `gh auth status --hostname github.com`. Fetch `main`, record its full SHA, and create a fresh detached worktree at that SHA with an empty `build/`. Initialize PREVAIL at the pinned revision or select a verified binary built from that revision with `PREVAIL`. Set up the pinned [release firmware](#release-firmware).
2. **Build, archive and verify the batch locally.** In that worktree run the following with `$archives` set to a new absolute directory outside the checkout. The prepare command runs the same build as `pixi run build` without arguments. It runs PREVAIL, checks the required matrix, archives each program, validates every archive listing, extracts it into a separate empty directory, verifies the canonical v3 roles, lengths, hashes and Compact ELFs, and compares the eight extracted files against the build. It verifies rBPF map bindings and regenerates each native container from the archived objects at its actual linked target. A failed check stops this step before any tag or upload.

   ```sh
   pixi run prepare-release --archive-dir "$archives"
   pixi run python make/layout.py verify --build-dir build
   pixi run verify-release --archive-dir "$archives" --unpack-dir "$unpacked_batch"
   ```

   `$unpacked_batch` must be a new directory. Keep `build/`, the 12 verified `<program>.7z` files, and `release.json` for retries. The ledger names each asset and records its archive digest, program paths, deployment digests, image sizes and firmware bindings. Use `verify-release` again before resuming any upload. Each asset name equals its archive filename.
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
