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

PREVAIL checks the original Clang object before the build exposes any program files, including in BPF-only builds. A rejected program requires investigation. In a deployment, the firmware supplies the slot address and capacity. The packer checks the final image size after map rewriting or native linking. Intermediate binaries, linked debug ELFs, linker scripts, dependency fingerprints and failure diagnostics belong to the build root’s private `.ninja/` directory.

## Reading the report

Each program contains one `report.md`. Source appears once. The eBPF chapter groups the original object and the rewritten interpreter payload. The `RV32IMC` chapter groups LLVM AOT and host JIT. Only built modes appear. Each subsection includes a fixed description of its ISA and execution model, instruction bytes, disassembly, and the actual generation steps. BPF addresses are byte offsets in executable sections. The rBPF listing shows the rewritten bytes in the deployed image. LLVM AOT uses linked RV32IMC addresses and checks the listing against the payload. Host JIT shows RV32IM instructions through the end of code, before map storage. Build commands may include the build host’s absolute paths.

Run `pixi run python make/layout.py reports --build-dir build` to regenerate reports from a completed local build. Verification of the indexed machine files is independent of Markdown rendering. The archive includes the report from the same build.

## Publish program artifacts

An explicit request to publish the current `nan-mu/libbpf-mcu` `main` authorizes the agent to build, tag, upload and publish the GitHub Release. The default build determines both the program set and the members of each archive. Adding a source to the default build automatically includes its verified result in the next release.

1. **Pin and build.** Confirm the destination and authenticated account with `gh repo view nan-mu/libbpf-mcu --json nameWithOwner` and `gh auth status --hostname github.com`. Fetch `main`, record its full SHA, and create a fresh detached worktree at that SHA with an empty `build/`. Initialize and build the PREVAIL submodule at the revision pinned by this commit, or point `PREVAIL` to a verifier built from that same revision. See the [build prerequisites](../README.md#prerequisites). From that worktree run **`pixi run build` without arguments**. Wait for its exit status. A nonzero status (including a PREVAIL rejection) ends the entire release attempt before tagging or uploading. Individual programs may still have completed locally.
2. **Discover the outputs.** Run `pixi run python make/layout.py verify --build-dir build` and enumerate every `build/<program>/index.toml` from this run. Each archive contains `index.toml`, `report.md`, `source.path`, `bpf.path`, every `mode[].elf.path`, and each supplied `mode[].object.path`. Check that these are exactly the regular files under the program root, with no symlinks. The archive starts inside that root. The build root’s private `.ninja/` stays outside the program directories.
3. **Create and check every archive locally.** Create a fresh staging directory outside the checkout. For each program use 7-Zip to create `<program>.7z` from its directory. Extract each archive into its own empty directory, verify the extracted index, and compare the full relative file set and all file bytes (including the report and index) with the build output. A failure here stops the release. Retain the originals and their SHA-256 values together with the pinned SHA and archive names for retries.

   For example, in `build/just_tx/`, with `$archive` set to the absolute staging path ending in `just_tx.7z` and `$unpacked` to an empty directory:

   ```sh
   7zz a -t7z -- "$archive" .
   7zz x -o"$unpacked" -- "$archive"
   ```

   `7z` accepts the same commands. From the checkout root, `pixi run python make/layout.py verify --build-dir "$unpacked"` verifies the extracted machine files.
4. **Create or resume a draft.** Recheck the remote `main` SHA and the clean worktree. Look up the tags and Releases that already reference this commit, peeling annotated tags. Reuse the matching tag and draft when unambiguous. For a fresh tag, choose the next numeric patch among `v0.1.N`, starting at `v0.1.0`. Create the tag at the pinned SHA. If another writer claims that name first, read the ref and recompute the next available version when it belongs to another commit. Verify the tag target before creating a draft.

   ```sh
   gh api -X POST repos/nan-mu/libbpf-mcu/git/refs -f ref="refs/tags/$tag" -f sha="$sha"
   gh release create "$tag" -R nan-mu/libbpf-mcu --verify-tag --draft --generate-notes
   ```

5. **Upload and publish.** Upload each verified archive to the draft with `gh release upload "$tag" "$archive" -R nan-mu/libbpf-mcu`. List every asset using `gh api --paginate --slurp "repos/nan-mu/libbpf-mcu/releases/$release_id/assets"`. On retry, compare against the original local archive bytes and upload only missing files. If a name, state or digest conflicts, leave the draft for inspection. Publish only after the full set matches, every asset has state `uploaded` and digest `sha256:<local SHA-256>`, and the tag and remote `main` still resolve to the pinned commit. Use `gh release edit "$tag" -R nan-mu/libbpf-mcu --draft=false`, read back the Release and assets by numeric Release ID, and return the Release URL, tag, commit and verified asset names and digests. For an already public matching Release, verify the existing tag and assets and return its URL. [GitHub Release API](https://docs.github.com/en/rest/releases/releases) · [GitHub asset digests](https://docs.github.com/en/rest/releases/assets) · [GitHub CLI release commands](https://cli.github.com/manual/gh_release)
