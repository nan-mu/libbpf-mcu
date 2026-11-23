# Program artifacts and local releases

The supported MCU is ESP32-C3 with RV32IMC, ILP32, and no FPU. The Rust host tool uses the sibling XPOST workspace's `xpost-elf` crate for XPM1 and Compact ELF V0. The local verifier checks the same wire format and payload digest.

## Program layout

`--build-dir` selects the whole build root and defaults to `build/` in the checkout. Each program has its own directory and `index.toml`. A program archive starts at that directory. `<p>` is the C source stem.

| Mode | Machine members relative to program root | Human report |
| --- | --- | --- |
| All | `index.toml`, `src/<p>.c` | |
| Raw BPF | `bpf/<p>_bpf.o` | `bpf/report.toml` |
| `llvm-aot` | `llvm-aot/<p>-vm-aot.elf` | `llvm-aot/report.toml` |
| `ebpf` | `ebpf/<p>-vm-ebpf.elf` | `ebpf/report.toml` |
| `jit` | `jit/<p>-vm-jit.elf` | `jit/report.toml` |

The `libbpf-mcu.program-index.v2` index records the program, source snapshot, original Clang object, and one `[[mode]]` table per available deployment. The `source` and `bpf` tables identify each member by role. Each deployment has `role = "xpost_container"` and `format = "xpost-compact-elf-v0"`. The source, object and ELF records give canonical relative paths, byte counts and SHA-256 of complete files.

`pixi run python make/layout.py verify --build-dir DIR` verifies an extracted program root or enumerates program indexes one level below a build root. It checks path containment, sizes, complete file hashes, the BPF ELF type, and Compact ELF V0 metadata and payload digest. A BPF-only index omits `[[mode]]`. Machine verification works with the reports absent.

The raw BPF object retains sections, BTF and relocations. PREVAIL checks this object before any deployment build. AOT independently compiles C with `include/`, links using the firmware slot and helper dispatcher, and packs the resulting image. Host JIT uses the raw object and links RV32IM instructions before packaging. The `ebpf` mode extracts the XDP section and rewrites map references to their indices in Compact ELF order. Its private RV32 link supplies the map addresses for the selected interpreter firmware, including when the same program's AOT container targets another firmware.

The build root's `.ninja/` holds the graph, host tool, linker scripts, depfile state, fingerprints and failure diagnostics. Successful modes retain their receipts across invocations. Changed source, headers, object, verifier, firmware or linked map-address basis invalidates the corresponding outputs before the index advertises them again. The build lock serializes writes within the root. Compilations, PREVAIL acceptance, artifact verification and device execution establish separate evidence.

The native object, linked debug ELF and flat image remain in the local `llvm-aot/` directory. `--no-compact-elf` produces those files and a report for inspection. The index exposes deployable containers. JIT keeps its local `jit.bin` and emits no relocatable object.

## Human reports

Each report starts with `[source]`. Its `path` identifies the original file relative to the checkout and `text` contains the UTF-8 source snapshot. `[assembly].listing` shows each instruction's bytes and operands with a section-relative byte offset for eBPF or a linked address for RV32. The raw BPF listing uses its executable ELF sections. The interpreter listing uses rewritten bytes from the container. AOT uses symbols from the linked ELF after checking the code sections against the container payload. The JIT listing stops at the end of the linked instructions.

The `[[generation]]` entries record the executed arguments and in-process calls. Absolute paths in these arguments describe the actual build host. The report can be regenerated from the successful local build receipts and artifacts.

```sh
pixi run python make/layout.py reports --build-dir build
```

## Legacy export

The exporter accepts `rv32`, `jit` or `bpf-xpost` and reserves each output directory for one mode. It reconstructs legacy files from the original BPF object, linked ELF, deployment container and available build data. Historical v1 roots use their index and manifest for program identity and mode selection. When a required object or linked ELF is missing, rebuild the program from source.

```sh
pixi run python make/cli.py artifacts export-legacy --build-dir build --mode rv32 --out /tmp/libbpf-rv32
```

| Export mode | Files inside each program directory |
| --- | --- |
| `rv32` | `bpf.o`, `bpf.toml` with linked `aot_addr`, `esp32c3.o`, `esp32c3.elf`, `esp32c3.bin`, `<p>.elf` if packaged |
| `jit` | `bpf.o`, `bpf.toml`, `jit.bin`, `jit.toml` with code extent and map bindings, `<p>.elf`, `prevail.ok` if present |
| `bpf-xpost` | `bpf.o`, `bpf.toml`, `<p>.bin`, `<p>.elf` |

## Offline packaging

`release/programs.toml` lists the 17 formal sources under `tests/xdp/`. Each row always includes raw BPF. Add deployment modes after the maintainer confirms the linked firmware and its SHA-256 for each mode. An empty `modes` array requires no firmware. A single program can specify a different ELF, `image_name` or `slot_symbol` per mode. The firmware and source paths are relative to the checkout root.

```toml
schema = "libbpf-mcu.release-plan.v2"

[[program]]
name = "just_tx"
source = "tests/xdp/just_tx.c"
modes = ["jit"]

[program.firmware.jit]
path = "firmware/just_tx-jit.elf"
sha256 = "<64 lowercase hex digits>"
```

Install `7zz` or `7z` and run the package task. The default output directory is `build/packages/`. A developer can pass `--plan` with a test configuration and choose a separate `--out` directory. The command accepts development worktrees and uses no GitHub credentials. Provision the build tools and dependency caches before running on a disconnected host.

```sh
pixi run package --out /path/to/fresh-archive-directory
```

The command builds the requested modes, checks the available index against the selection, archives each program as `<p>.7z`, and verifies it after extraction. Exact archive paths follow the program layout above. The package task reports commit, working-tree status, absolute archive paths, names and SHA-256 on stdout as JSON. Build and archiver logs go to stderr. A missing mode, missing or modified firmware, conflicting archive name, or build failure aborts packaging. Preserve the verified 7z files and the task's JSON output for publication retries.

## Publish program artifacts

A maintainer's explicit request to publish the current `nan-mu/libbpf-mcu` `main` authorizes the agent to create the tag, upload the verified archives and make the Release public. Use a local authenticated `gh` session. Acquire a same-host lock for this repository before starting and hold it through final readback. An atomically created directory such as `~/.local/state/libbpf-mcu/publish.lock` works across checkouts. On interruption, confirm the previous agent has stopped before releasing its lock.

1. **Pin the commit.** Confirm `gh auth status --hostname github.com` and use `gh repo view nan-mu/libbpf-mcu --json nameWithOwner` to confirm the destination. Confirm local `main` is clean and compare its full HEAD SHA to `git ls-remote https://github.com/nan-mu/libbpf-mcu.git refs/heads/main`. Keep the verified SHA, exact archive list and original files together. For a fresh build, run `pixi run package` with the versioned plan at that SHA. Before allocating a tag, recheck HEAD, remote `main`, cleanliness, the package receipt's commit and the file names and digests. For a retry, look for the assigned tag and matching draft first and use the recorded files.
2. **Allocate the tag and draft.** Read the remote tags with `git ls-remote --tags https://github.com/nan-mu/libbpf-mcu.git` and match `^v0\.1\.(0|[1-9][0-9]*)$`. Choose the largest numeric patch plus one, or `v0.1.0` if none exist. Find prior tags for the pinned SHA by resolving each candidate to its commit, peeling annotated tags when needed. Read drafts and public Releases via `gh api --paginate --slurp repos/nan-mu/libbpf-mcu/releases`, matching `tag_name`. A single matching tag can be reused. Resolve ambiguity before allocating another tag. Create a missing tag with the POST below. If creation races with another publisher, read the resulting ref before proceeding. A ref for the pinned commit can be reused. A tag already assigned to this attempt that points elsewhere requires stopping and reporting the difference. If a concurrent publish took an unassigned candidate for another commit, refresh the tag and Release lists before selecting the next version. Read the exact remote ref and confirm its commit before creating or reusing a draft.

   ```sh
   gh api --hostname github.com -X POST repos/nan-mu/libbpf-mcu/git/refs \
     -f ref="refs/tags/$tag" -f sha="$sha"
   gh api --hostname github.com "repos/nan-mu/libbpf-mcu/git/ref/tags/$tag"
   gh release create "$tag" -R nan-mu/libbpf-mcu --verify-tag --draft --generate-notes
   ```

3. **Upload and verify.** Find the draft's numeric Release ID in the REST response. List every asset by Release ID, flatten the paginated arrays, and compare names, upload states and digests to the package receipt and original local files. Reuse an asset only if its name is expected, its state is `uploaded` and its digest is exactly `sha256:<local SHA-256>`. Upload each missing archive using the command below. Stop on an unexpected name, duplicate name, wrong digest or non-uploaded asset. After an upload error, re-read the assets before retrying. Never use `--clobber`.

   ```sh
   gh api --hostname github.com --paginate --slurp \
     "repos/nan-mu/libbpf-mcu/releases/$release_id/assets"
   gh release upload "$tag" "$archive" -R nan-mu/libbpf-mcu
   ```

4. **Publish and read back.** Immediately before changing draft status, re-read the tag, the Release and all its asset pages. Check the pinned SHA, exact set of asset names, `uploaded` states and matching SHA-256 digests. Once these checks pass, run the edit command. Read the Release again by its numeric ID and verify `draft=false`. Return its `html_url`, tag, commit SHA and attachment names and digests.

   ```sh
   gh release edit "$tag" -R nan-mu/libbpf-mcu --draft=false
   gh api --hostname github.com "repos/nan-mu/libbpf-mcu/releases/$release_id"
   ```

A retry with a correct tag and no draft creates the missing draft. A draft carrying only verified assets resumes with the missing files from the original local set. If the same Release is already public, verify its tag and entire asset set and return the existing link. If any release input or remote asset differs, preserve the draft and report the difference. [GitHub Release API](https://docs.github.com/en/rest/releases/releases) · [GitHub asset digests](https://docs.github.com/en/rest/releases/assets) · [GitHub CLI release commands](https://cli.github.com/manual/gh_release)
