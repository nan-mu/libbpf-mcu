# Program artifacts and local releases

The `rv32imc` build target uses the ILP32 ABI and no FPU. The current XPOST machine profile supports ESP32-C3. The Rust host tool uses `xpost-elf` for XPM1 and Compact ELF V0. Its Rust dependencies on XPOST are pinned in `tools/Cargo.toml` and `tools/Cargo.lock` to the main commit that merged the dynamic host encoder. The local verifier checks the V0 field bounds, layout and payload digest. XPOST owns installation and device storage limits.

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

Supply a directory of linked ESP32-C3 XPOST firmware ELFs. The release build looks up each required file by the names below. Set `LIBBPF_MCU_FIRMWARE_DIR` for `pixi run build` without arguments, or pass `--firmware-dir DIR` to `build` or `prepare-release`.

| Required programs | Native for LLVM AOT and JIT | Interpreter for rBPF |
| --- | --- | --- |
| `firewall` | `firewall-native.elf` | `firewall-interp.elf` |
| `just_drop`, `just_tx` | `just_xdp-native.elf` | `just_xdp-interp.elf` |
| `noop`, `prime`, `log2`, `copy`, `fletcher32`, `bsort`, `strcmp` | `exec_bench-native.elf` | `exec_bench-interp.elf` |
| `case_swap`, `case_mark` | `case_xdp-native.elf` | `case_xdp-interp.elf` |

Supply firmware with the matching engine. The build reads XPM1 and cross-checks `xdp_slot` and `helper_dispatcher` in the ELF symbol table. It checks payload size against the linked SRAM slot. The complete ELF is checked against the V0 wire layout. It records the selected filename, resolved input path, SHA-256 and target layout. Keep the supplied ELFs available when verifying or retrying a batch.

A missing ELF reports the affected programs, modes and filename. If a mode fails a capacity check, its build log and diagnostic identify the failed deployment. The release remains incomplete until every required mode passes.

### Prepare a native image for a different slot

Use the producer revision that built the archive. Extract a program directory, select the mode by its v3 index, and supply the consumer's linked firmware:

```sh
pixi run retarget --program-dir "$unpacked" --mode llvm-aot \
  --firmware "$firmware" --slot-symbol xdp_slot_idle --output "$output"
```

Use `--mode jit` to regenerate the JIT relocation records from the indexed BPF object and link the image at the new slot. AOT relinks the indexed RV32IMC object. The tool reads the helper address from XPM1 and uses the primary slot when `--slot-symbol` is omitted. It verifies the archive's indexed bytes, runs PREVAIL on the original object, and writes the resulting Compact ELF outside the program directory. XPOST handles installation and slot switching.

## Publish program artifacts

An explicit request to publish the current `nan-mu/libbpf-mcu` `main` authorizes the agent to build, tag, upload and publish the GitHub Release. The required release matrix is the 12 programs above with all three modes, for 36 deployments. Keep the v3 program index and the eight members shown under [Program layout](#program-layout).

1. **Pin the build.** Confirm the destination and authenticated account with `gh repo view nan-mu/libbpf-mcu --json nameWithOwner` and `gh auth status --hostname github.com`. Fetch `main`, record its full SHA, and create a fresh detached worktree at that SHA with an empty `build/`. Initialize PREVAIL at the pinned revision or select a verified binary built from that revision with `PREVAIL`. Supply the linked [release firmware](#release-firmware).
2. **Build, archive and verify the batch locally.** In that worktree run the following with `$archives` set to a new absolute directory outside the checkout. Set `$firmware_dir` to the linked ELF directory. The prepare command runs the same release build as `pixi run build` with `LIBBPF_MCU_FIRMWARE_DIR`. It runs PREVAIL, checks the required matrix, archives each program, validates every archive listing, extracts it into a separate empty directory, verifies the canonical v3 roles, lengths, hashes and Compact ELFs, and compares the eight extracted files against the build. It verifies rBPF map bindings and regenerates each native container from the archived objects at its actual linked target. A failed check stops this step before any tag or upload.

   ```sh
   pixi run prepare-release --firmware-dir "$firmware_dir" --archive-dir "$archives"
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
