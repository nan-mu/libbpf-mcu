# PR #4 local verification

Verified on 2026-11-18 in the working tree based on `30d8f071d8d6744b88cd73999694ba635b1fda9a`. Builds used LLVM, the installed PREVAIL executable, and the existing Rust host tools. The firmware fixture was a local ELF carrying XPM1, not a device-run result.

## Automated checks

`pixi run python make/cli.py test` passed all 74 tests across ten test files. This includes actual PREVAIL rejection cases, Compact ELF parity, JIT build checks, 17 layout tests, five Ninja incremental tests, and seven publisher test methods with parameterized failure cases.

Publisher fixtures cover dirty/non-main source trees, existing tags, authentication/tool failures, failure at each of the four build calls, invalid artifact hashes, missing firmware, existing output, declined confirmation, tag creation races, firmware mutation, wrong dependency targets, symlinks, and missing inputs. Upload failures return failure. Dry-run never writes a GitHub tag or Release; package-only never calls `gh`. Successful upload command construction is tested with mocks, including a repository pinned from `origin`, the exact commit, and `--verify-tag`.

The following checks also passed locally:

```bash
pixi run python -m compileall -q make scripts/publish_artifacts.py scripts/test_publish_artifacts.py
uvx ruff==0.14.5 check --select E9,F63,F7,F82 make scripts/publish_artifacts.py scripts/test_publish_artifacts.py
uvx ruff==0.14.5 format --check scripts/publish_artifacts.py scripts/test_publish_artifacts.py
git diff --check
```

## Default build and incrementality

A new external build directory was used for:

```bash
pixi run build --firmware <fixture.elf> -c just_drop --build-dir <new-directory>
```

The target was omitted, exercising default BPF plus ESP32-C3 directory initialization.

```text
First build:
[1/10] TOOL xpost-mcu-elf
[2/10] clang ... --target=bpf ... just_drop_bpf.o
[3/10] publish bpf just_drop
[4/10] PREVAIL .../bpf/prevail.ok
[5/10] clang ... --target=riscv32-unknown-none-elf ... just_drop_rv32.o
[6/10] link .../just_drop_rv32.debug.elf
[7/10] bin .../just_drop_rv32.bin
[8/10] report .../rv32/.stage/body.toml
[9/10] pack .../just_drop_rv32.elf
[10/10] publish rv32 just_drop

Identical second command:
ninja: no work to do.

Firmware ELF ident byte changed, XPM1 unchanged:
[1/1] publish rv32 just_drop
```

The firmware SHA-256 in the new RV32 report matched the changed file. No compile, PREVAIL, link, or pack edge ran on the firmware-only change.

## Dependency invalidation

A real firewall build initially loaded all four modes. After changing the firmware outside XPM1 and targeting only the RV32 report publish edge:

```text
[1/1] publish rv32 firewall
mode: ['bpf', 'rv32', 'jit']
stale: [{'name': 'bpf-xpost', 'report': 'bpf-xpost/report.toml',
         'reason': 'input hash mismatch: ../rv32/report.toml'}]
Consumer refusal: bpf-xpost is not a consumable mode of firewall
```

The index still listed firewall, and BPF, RV32, and JIT loaded successfully. Automated tests also exercise changed BPF bytes, missing inputs, hash mismatches, absolute paths, parent traversal, external symlinks, and valid cross-mode references through the manifest, index, and consumer interface.

## Real local package

```bash
pixi run publish-artifacts --firmware <fixture.elf> \
  --tag pr4-final-firewall --program firewall --package-only \
  --out /tmp/libbpf-pr4-final-firewall
```

All four existing build routes completed. The script validated the build tree, staged official files, generated checksums and the archive, extracted it, and validated the extracted tree. An independent extraction and `shasum -a 256 -c SHA256SUMS` also passed for the archive and all 15 official files. `layout.verify_tree()` accepted BPF, RV32, JIT, and bpf-xpost after extraction. No firmware, `.ninja`, `.stage`, depfiles, or PREVAIL stamp was packaged.

Archive SHA-256 for this local working-tree acceptance run:

```text
3e25590c21d8dd2c5a7e8405d816e4a4546b8af6b4475c0c4f0221165c5de2c7  libbpf-mcu-artifacts-pr4-final-firewall.tar.gz
```

## Limits

No GitHub tag, Release, or asset upload was performed. GitHub mutation and upload behavior were tested with mocks. Formal publication from clean merged main remains a user action. The real four-mode package acceptance selected firewall; a full default release campaign across all programs was not run. Unsupported programs fail the whole campaign with the failing program and mode.

The new CI workflow runs code and protocol checks only. Its checks were reproduced locally; hosted GitHub Actions status must be read from the PR after push. No device or network smoke test was run for this task.
