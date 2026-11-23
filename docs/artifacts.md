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

A fresh `pixi run build` currently builds and verifies raw BPF for every default source. The complete `just_tx` program in that build consists of `index.toml`, `just_tx.c`, `report.md` and `objects/just_tx_bpf.o`. The native object accompanies the LLVM AOT deployment. JIT produces linked instructions directly, and the rBPF deployment uses rewritten bytecode from the original eBPF object.

The machine contract is `libbpf-mcu.program-index.v3`. It records the program, source snapshot, original BPF ELF and one `[[mode]]` per deployment. Each deployment records its container. LLVM AOT also records the native relocatable object. Each referenced file has a canonical relative path, byte length and SHA-256. Use `pixi run python make/layout.py verify --build-dir DIR` on a build root or an extracted program directory to check the indexed bytes and ELF format.

The top-level C snapshot incorporates quoted program headers resolved relative to the including file, including for sources selected outside the repository. It preserves comments, conditional branches for host, eBPF and RV32 compilation, and references to the target SDK. Conventional header guards also apply to recursive includes. Each `#pragma once` sets a guard for its header when the preprocessor reaches the directive. Ordinary headers can expand repeatedly under different macro definitions. Recompile the snapshot with the corresponding SDK headers and build flags. The report embeds these same source bytes, and the index hashes them.

PREVAIL checks the original Clang object before the build exposes any program files, including in BPF-only builds. A rejected program requires investigation. In a deployment, the firmware supplies the slot address and capacity. The packer checks the final image size after map rewriting or native linking. Intermediate binaries, linked debug ELFs, linker scripts, dependency fingerprints and failure diagnostics belong to the build root’s private `.ninja/` directory.

## Reading the report

Each program contains one `report.md`. Source appears once. The eBPF chapter groups the original object and the rewritten interpreter payload. The `RV32IMC` chapter groups LLVM AOT and host JIT. Only built modes appear. Each subsection includes a fixed description of its ISA and execution model, instruction bytes, disassembly, and the actual generation steps. BPF addresses are byte offsets in executable sections. The rBPF listing shows the rewritten bytes in the deployed image. LLVM AOT uses linked RV32IMC addresses and checks the listing against the payload. Host JIT shows RV32IM instructions through the end of code, before map storage. Build commands may include the build host’s absolute paths.

Run `pixi run python make/layout.py reports --build-dir build` to regenerate reports from a completed local build. Verification of the indexed machine files is independent of Markdown rendering. The archive includes the report from the same build.

## Publish program artifacts

An explicit request to publish the current `nan-mu/libbpf-mcu` `main` authorizes the agent to build, tag, upload and publish the GitHub Release. The default build determines both the program set and the members of each archive. Adding a source to the default build automatically includes its verified result in the next release.

1. **Pin and build.** Confirm the destination and authenticated account with `gh repo view nan-mu/libbpf-mcu --json nameWithOwner` and `gh auth status --hostname github.com`. Fetch `main`, record its full SHA, and create a fresh detached worktree at that SHA with an empty `build/`. Initialize and build the PREVAIL submodule at the revision pinned by this commit, or point `PREVAIL` to a verifier built from that same revision. See the [build prerequisites](../README.md#prerequisites). From that worktree run **`pixi run build` without arguments**. Wait for its exit status. A nonzero status (including a PREVAIL rejection) ends the entire release attempt before tagging or uploading. Individual programs may still have completed locally.
2. **Discover the outputs.** Run `pixi run python make/layout.py verify --build-dir build` and enumerate every `build/<program>/index.toml` from this run. Each archive contains `index.toml`, `report.md`, `source.path`, `bpf.path`, every `mode[].elf.path`, and each supplied `mode[].object.path`. Check that these are exactly the regular files under the program root, with no symlinks. The archive starts inside that root. The build root’s private `.ninja/` stays outside the program directories.
3. **Create and check every archive locally.** Create a fresh staging directory outside the checkout. For each program use 7-Zip to create `<program>.7z` from its directory. Extract each archive into its own empty directory, verify the extracted index, and compare the full relative file set and all file bytes (including the report and index) with the build output. A failure here stops the release. Record each stem, local archive path, asset name and file SHA-256 together with the pinned commit. Retain the verified originals for retries.

   For example, in `build/just_tx/`, with `$archive` set to the absolute staging path ending in `just_tx.7z` and `$unpacked` to an empty directory:

   ```sh
   7zz a -t7z -- "$archive" .
   7zz x -o"$unpacked" -- "$archive"
   ```

   `7z` accepts the same commands. From the checkout root, `pixi run python make/layout.py verify --build-dir "$unpacked"` verifies the extracted machine files.

   Compute the asset name from the program stem in its index. Stems containing only ASCII letters, digits, underscores and hyphens and starting with a letter or digit keep their local filename. For other stems, use `program-` followed by the lowercase SHA-256 of the UTF-8 stem, then `.7z`. Check the entire batch for duplicate stems, local filenames or asset names. Compare filenames and asset names case-insensitively and stop before creating a tag if they collide.

   ```sh
   asset=$(pixi run python -c '
   import hashlib, re, sys
   stem = sys.argv[1]
   if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", stem):
       stem = "program-" + hashlib.sha256(stem.encode("utf-8")).hexdigest()
   print(stem + ".7z")
   ' "$program")
   ```

   The stem `probe#1` keeps the local file `probe#1.7z`. The computed asset name uses the digest form, which avoids GitHub filename normalization. The SHA-256 in the upload ledger is computed over the 7z bytes.
4. **Create or resume a draft.** Hold a lock for this repository on the publishing machine through draft discovery, upload and publication. Recheck the remote `main` SHA and the clean worktree. Look up the tags and Releases that already reference this commit, peeling annotated tags. Reuse the matching tag and draft when unambiguous. For a fresh tag, choose the next numeric patch among `v0.1.N`, starting at `v0.1.0`. Create the tag at the pinned SHA. If another writer claims that name first, read the ref and recompute the next available version when it belongs to another commit. Verify the tag target before creating a draft.

   ```sh
   gh api -X POST repos/nan-mu/libbpf-mcu/git/refs -f ref="refs/tags/$tag" -f sha="$sha"
   gh release create "$tag" -R nan-mu/libbpf-mcu --verify-tag --draft --generate-notes
   ```

5. **Upload and publish.** Read the draft's numeric `release_id` and list all of its assets using `gh api --paginate --slurp "repos/nan-mu/libbpf-mcu/releases/$release_id/assets"`. Compare against the verified upload ledger. Upload only missing files, using the API's separate filename and request body. This passes paths containing `#` literally. The CLI's `gh release upload` treats `#` as an asset label separator.

   ```sh
   gh api --hostname github.com -X POST \
     "https://uploads.github.com/repos/nan-mu/libbpf-mcu/releases/$release_id/assets" \
     -H 'Content-Type: application/x-7z-compressed' --input "$archive" -f "name=$asset"
   ```

   On retry, check the original local bytes against the ledger and reuse matching uploads. An extra asset, an unexpected upload state or a digest conflict stops publication. After uploading, list all assets again. Publish only if the sets match, every asset is `uploaded` with digest `sha256:<local SHA-256>`, and the tag and remote `main` still resolve to the pinned commit. Run `gh release edit "$tag" -R nan-mu/libbpf-mcu --draft=false`, read back the Release and assets by numeric Release ID, and return the Release URL, tag, commit and verified asset names and digests. For an already public Release, verify the existing tag and assets and return its URL. [GitHub Release API](https://docs.github.com/en/rest/releases/releases) · [GitHub asset API](https://docs.github.com/en/rest/releases/assets) · [GitHub CLI request options](https://cli.github.com/manual/gh_api) · [GitHub CLI upload arguments](https://cli.github.com/manual/gh_release_upload)
