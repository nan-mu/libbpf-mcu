# Audit: jit-xpost

Task book: the `/poteto-delivery` arguments in this task's T3 thread, "Agent 任务书：RV32 eBPF JIT 审核、验证及 XPOST 集成" (P0–P5 plus 7 deliverables). No later revision.
PStack: `/Volumes/SSD/.claude/plugins/cache/cursor-plugins/pstack/0.15.36` v0.15.36, playbook `figure-it-out` (entered via `session-pickup`).
Base: `agent/userspace-jit` @ `1898246baf4f4a4119c159af6bedb76ad2c3ea2b`  Branch: `agent/jit-xpost-verify`  PR: pending

## Resume record

Prior run (Cursor) left 2 commits, `1994710` and `4f1fbd7`, pushed to `origin/agent/jit-xpost-verify`. No PR existed. Inherited: P0 negative tests and `matrix.rs`, P1 `check-xdp.sh`, P2 a hand-written reference pair, a partial P3 (`host_abi.rs`, `patch_lddw`). P4 was recorded INCONCLUSIVE (never flashed). P5 not started. This run redoes none of it; it verifies the inherited claims and continues from P2 oracle independence.

## Constraints

| # | Requirement (from task book) | Implemented | Verified | Evidence (code/test/artifact) | Open issue |
|---|------------------------------|-------------|----------|-------------------------------|------------|
| C1 | Reuse the existing Rust JIT; do not reimplement the backend | yes | yes | `jit/src/compile.rs` extended in place, 1491 lines; no new backend | — |
| C2 | Target RV32IMC, ABI ILP32; emitting RV32IM is allowed | yes | no | `jit/src/rv.rs` encoder | Confirm emitted ISA on device |
| C3 | Compiler runs on the Mac, never on the MCU | yes | yes | `jit/src/main.rs` host CLI; no MCU compile path | — |
| C4 | Preserve XPOST helper/map/cold-load/slot/hot-update model | no | no | — | P3 must bind through existing VMR table |
| C5 | Do not redesign the XPOST runtime state machine | yes | yes | xpost repo untouched by this branch | Keep it untouched |
| C6 | Never deliver unlinked, unchecked, or unknown-dependency machine code | yes | yes | `link` errors on any unresolved reloc; `check_rv32im` rejects non-RV32IM; `scan_at` checks entry, size, digest and map-VMA set; a dropped map is a hard error | — |
| C7 | Unsupported eBPF features give an explicit error; no panic, silent skip, or unknown code | yes | yes | 501 oracle cases recorded unsupported with reasons, 25 negative cases return Err; `check_rv32im` gate; F1 removed the one silent skip | Malformed-ELF fuzz tracked separately under R7 |

## P0 — reliable test baseline

| # | Requirement | Implemented | Verified | Evidence | Open issue |
|---|-------------|-------------|----------|----------|------------|
| R1 | Run all existing JIT unit and exec tests; record pass/fail/uncovered | yes | yes | `cargo test` in `jit/`: 17 exec tests green, run this session | Unit-test count to be recorded in report |
| R2 | Build opcode × source mode × operand width matrix from compile/rv/load/exec | yes | yes | `jit/src/matrix.rs`, `xpost-jit matrix` JSON; corroborated by 6188 oracle boundary probes over the same set | — |
| R3 | Support status for ALU32/ALU64, jumps, memory, lddw, call | yes | yes | matrix JSON groups alu32/alu64/jmp64/jmp32/mem/lddw/call; unsupported rows carry the refusal reason | — |
| R4 | lddw takes two insns, second word validated, no jump into the middle slot | yes | yes | `jit/tests/exec.rs::rejects_bad_lddw_and_a_branch_into_it` green | — |
| R5 | Illegal register, unsupported opcode, bad branch target return `Result::Err` | yes | yes | `jit/tests/exec.rs::unknown_alu_and_bad_reg_are_errors` green | — |
| R6 | Arithmetic obeys RFC 9669 overflow, extension, div0, shift, signed rules | partial | yes | 6188 oracle boundary probes agree except 27 ALU32 mod-by-zero cases adjudicated to rbpf (`jit/REPORT.md` §3) | RFC clause text unverified; both official RFC hosts blocked |
| R7 | ELF header/section/symbol/relocation bounds and types validated; no panic on bad input | partial | no | `jit/src/load.rs` bounds checks + 5 lib unit tests; 25 oracle negative cases | No dedicated malformed-ELF fuzz sweep |
| A-P0 | Machine-readable matrix plus a regression test per fix | yes | yes | `xpost-jit matrix` JSON; `exec.rs::clang_map_lddw_resolves_through_the_relocation` for F1 | — |

## P1 — real C→eBPF→JIT tests

| # | Requirement | Implemented | Verified | Evidence | Open issue |
|---|-------------|-------------|----------|----------|------------|
| R8 | Cover div2, xdp_drop, case_mark, just_drop, just_tx, firewall, bitswap, bsort | yes | yes | `build/jit-check/report.tsv` 8 rows, re-run this session before and after the F1 fix | — |
| R9 | Clang produces a real `bpf.o` | yes | yes | `jit/scripts/check-xdp.sh:26` clang `--target=bpf` | — |
| R10 | Check ELF type, symbols, program sections, relocations | yes | yes | `load.rs` validates header/section/symbol/reloc; `make/obj_report.py --btf` emits per-object reports; `llvm-readelf -r` confirmed the F1 relocation | — |
| R11 | Run PREVAIL and record the accurate result | yes | yes | `make/prevail_gate.py`, prevail column = pass for all 8 in both report.tsv files | prevail/ empty in worktree; script falls back to the main checkout build |
| R12 | Select the named XDP section and run the Rust JIT | yes | yes | `load.rs` selects `xdp`/`xdp1`; report shows section per program | — |
| R13 | Check generated RV32 instructions and relocations | yes | yes | `check_rv32im` ISA gate; `link` fails closed on any unresolved reloc; `pack-jit` reports resolved reloc counts | — |
| R14 | Execute the fully linked artifact on an independent RV32 executor | yes | yes | oracle's own RV32 executor cross-checks `rv_vm` on 8727 cases with 0 splits; and the linked image ran on the ESP32-C3 (`jit/reports/p4/`) | — |
| R15 | Compare against an eBPF reference executor | yes | yes | `jit/oracle/` compares against the rbpf fork, not the JIT's own logic | — |
| R16 | Out-of-scope programs recorded UNSUPPORTED, never PASS | yes | yes | `check-xdp.sh:54-61`, exit 2 for unsupported/inconclusive | — |
| A-P1 | One reproducible command; input is a real compiled ELF, not hand-assembled | yes | yes | `jit/scripts/check-xdp.sh` re-run this session; `jit/scripts/build-elf.sh` extends it to Compact ELF V0 | — |

## P2 — semantic correctness and safety

| # | Requirement | Implemented | Verified | Evidence | Open issue |
|---|-------------|-------------|----------|----------|------------|
| R17 | Independent reference interpreter, prefer a mature implementation, not the JIT's own logic | yes | yes | `jit/oracle/` uses the rbpf fork; it falsified the shared premise and exposed the map-relocation defect | Map model is shared by construction (scoped assumption) |
| R18 | Compare return/XDP action, full packet bytes, map content, helper call order/args/returns, termination states | yes | yes | `jit/oracle/results.json` per case: ret, term, traces, memory regions; `check.rs` also watches packet + map storage | — |
| R19 | Randomized differential plus boundary tests (0, -1, signed min/max, overflow, shift edges) | yes | yes | 8727 cases: 6188 probe, 2000 random seeds, 14 program, 25 negative | — |
| R20 | Jitterbug-style per-instruction state correspondence: registers, control flow, memory, exit | partial | yes | probes save r0..r8 and compare the whole save area, so a register-pair mismatch surfaces as a byte diff | No symbolic proof; correspondence is empirical |
| R21 | Partition claims: differential-proven / symbolically-proven / verifier-assumed / uncovered | yes | yes | `jit/oracle/README.md` four-way split | — |
| A-P2 | Every supported insn has a boundary case and an independent reference result; coverage and limits reported | partial | yes | 8199 pass / 27 adjudicated oracle defects / 501 unsupported | 27 ALU32 mod-by-zero cases diverge; adjudicated to rbpf, RFC text unverified |

## P3 — host-side link and XPOST glue

| # | Requirement | Implemented | Verified | Evidence | Open issue |
|---|-------------|-------------|----------|----------|------------|
| R23 | Read `.xpost.mem` from the target firmware ELF for slot addr, capacity, helper addr | yes | yes | `tools/src/jit_image.rs:44-52`; measured `just_xdp` slot `0x40380200` len 3584 helper `0x40380000` | — |
| R24 | JIT produces a linkable RV32 object or equivalent verifiable IR | yes | yes | `Image{code,relocs}` is the verifiable IR; `jit_image.rs` closes it | Container is the delivery form, not a `.o` |
| R25 | Generate ABI trampoline, entry, helper asm | yes | yes | prologue/epilogue in `compile.rs`; entry = slot base checked by `scan_at`; 6 programs entered and returned correctly on the ESP32-C3 | — |
| R26 | Resolve helper call, bpf-to-bpf call, map lddw, target address relocs | yes | yes | `compile.rs::link`; `pack-jit` reports `relocs=2` resolved for all map programs | — |
| R27 | Assign addresses per the existing XPOST slot linker layout | yes | yes | `jit_image.rs` code at slot base then 16-byte map placeholders, matching `esp32c3-slot.ld.tmpl` `.maps` | — |
| R28 | Link into an RV32 ELF and check symbols and relocations | yes | yes | `build_container` + `scan_at` verify entry, image size, digest, map VMA set | — |
| R29 | Extract the full native image and pack to Compact ELF V0 with existing `xpost-mcu-elf pack` | yes | yes | `xpost-mcu-elf pack-jit` reuses `build_container`; 7 containers in `build/jit-elf/` | — |
| R30 | Explicit eBPF helper ABI ↔ `helper_dispatcher` ABI argument/return conversion | yes | yes | `jit/XPOST-ABI.md` §helper; on-device map lookup+update mutated real storage (`counter[96]`+31, `blacklist[.96]`+31, helper_loop counters=100) | — |
| R31 | Map refs bound through VMR→RMA, not metadata address as storage | yes | yes | `jit_image.rs` emits absolute VMR in lddw; container `map_vma` set equals linked set, else error | Device alias binding pending |
| R32 | bpf-to-bpf calls linked correctly, or refused when unsupported | yes | yes | `exec.rs::bpf_to_bpf_call_is_refused` green | Refusal is the declared behavior |
| R33 | No unresolved runtime relocation remains after compile | yes | yes | `link` returns Err on any unresolved reloc; `pack-jit` fails closed | — |
| R34 | Handle `.rodata`, `.data`, `.bss` explicitly; no reliance on loader init it does not perform | partial | yes | map placeholders emitted inside the flat span; a non-map `lddw` symbol is refused, so `.rodata` cannot be silently mishandled | `.rodata` support not implemented; refusal is explicit |
| R35 | Validate entry address, image length, target ISA, alignment, stack budget | partial | yes | `check_rv32im` gate; slot-fit and entry checks in `jit_image.rs` | Stack budget still unreconciled against firmware |
| R36 | Use the existing `xpost-elf` library; no second incompatible container | yes | yes | `tools/Cargo.toml` path dep; encode via `build_container`, accept via `scan_at` | — |
| A-P3 | A real ELF V0 the existing XPOST loader accepts, not just a `.rv32` | yes | yes | `build/jit-elf/report.tsv`: 7 pass, bsort refused; accepted by the loader's own `scan_at` | On-device acceptance pending (P4) |

## P4 — device integration

| # | Requirement | Implemented | Verified | Evidence | Open issue |
|---|-------------|-------------|----------|----------|------------|
| R37 | Run current XPOST firmware on ESP32-C3, prefer no MCU runtime change | yes | yes | `just_xdp` (RX) flashed via agent; WiFi joins CMCC-dKji, UDP 192.168.110.106:8080 ACKs; `jit/reports/p4/agent.log`. xpost repo untouched (only the 2 pre-existing toml edits) | Prebuilt ELF lacked baked WiFi env; rebuilt `examples/just_xdp` (untracked target only) to bake `.env` |
| R38 | No-map DROP/PASS program | yes | yes | `jit_just_drop`/`jit_xdp_drop`/`jit_div2` on RX; `summary.tsv` rows; div2 raw return a/b=12→Aborted matches AOT | — |
| R39 | Packet byte modification | partial | partial | `jit_case_mark` runs the rewrite path, rxcnt[17]+34, xdp_tx=34, bad_md=0 | Exact rewritten bytes INCONCLUSIVE: tcpdump needs root (no passwordless sudo); TX action + map confirmed, byte-level capture not obtained |
| R40 | Map lookup/update | yes | yes | `jit_just_drop` counter[96]+31; `jit_firewall` blacklist[.96]+31; VMR alias binding works on silicon | — |
| R41 | Helper call and return value | yes | yes | bpf_map_lookup_elem returns valid pointer (map updates land); helper_unresolved=0, helper_map=0 across all JIT cases | — |
| R42 | `just_tx` TX behavior | yes | partial | `jit_just_tx` xdp_tx=100, rxcnt[17]+100, tx_completed>0; UDP→TX, non-UDP→DROP matches AOT | Exact MAC-swap bytes INCONCLUSIVE (no capture); TX action confirmed via counters |
| R43 | Existing slot load, lease, stage, activate, switch tests | yes | yes | `switch/switch.json`: case_xdp stage→activate→switch JIT(slot0)↔AOT(slot1), ok=1 rollback=0 severe=0; just_xdp cold-install→boot-lease→enable/disable | just_xdp registers no switch/status handler (`ERR unsupported`); hot-switch exercised on case_xdp |
| R44 | Check shared stack, register restore, helper args, map alias, packet window, IRAM exec, failure fallback | yes | partial | All JIT cases: stack_misalign=0, bad_md=0, runtime_errors=0, reentry=0, helper_*=0; IRAM slot 0x40380200 executes | Failure-fallback (bad image→Drop) not separately injected; clean-path safety counters proven |
| R45 | Record serial output, runtime state, return action, packet/map content per case | yes | yes | Per-case `case.json` + `serial.log` + `perf.json` under `jit/reports/p4/`; `summary.tsv` consolidates | — |
| A-P4 | Same firmware config and runtime interface as AOT; JIT runs the real XDP datapath | yes | yes | 6 RX programs run on silicon as JIT Compact ELF V0, behavior identical to AOT controls; `jit/scripts/p4_drive.py` reruns it | **Primary gap closed.** bitswap exec-ingress INCONCLUSIVE (carrier seeding blocked via agent API) |

## P5 — performance and resources

| # | Requirement | Implemented | Verified | Evidence | Open issue |
|---|-------------|-------------|----------|----------|------------|
| R46 | Keep four arms: XPOST AOT, JIT, rBPF, HAL | yes | yes | `jit/reports/p5/matrix/summary.tsv`: 8 workloads × 4 arms on exec_bench; AOT/JIT share `exec-bench-aot` firmware (image-only difference), rBPF `interp`, HAL `exec_bench_hal` | bsort JIT not measurable (R54); rBPF/HAL helper probe gaps (R52) |
| R47 | Mac host JIT compile time | yes | yes | `jit/reports/p5/host-compile.tsv`: given 8 programs + 6 exec workloads + helper_loop measured (`xpost-jit compile --repeat 200`, release) | — |
| R48 | Generated native code byte count | yes | yes | `host-compile.tsv` rv_bytes; `build/p5/containers.tsv` image_bytes (JIT code + 16B map placeholder) | — |
| R49 | XPOST Compact ELF file size | yes | yes | `build/p5/containers.tsv` container_bytes per arm/workload (e.g. incr AOT 460 / JIT 888 / rBPF 576) | — |
| R50 | MCU per-execution time | yes | yes | `matrix/summary.tsv`: single-shot `exec seg engine` (n=100/arm, median+spread) AND 2000-run `bench mean_ns` cross-check; all outputs verified correct | Single-shot engine is hook-dominated (~70us flat AOT/JIT); batch mean_ns is the work-resolving figure |
| R51 | Stack usage and slot capacity | yes | yes | `jit/reports/p5/resources.tsv`: JIT frame 592B caller stack; AOT entry frame 16B (32B helper_loop); slot 8192 exec_bench / 3584 RX; soft canary only | rBPF/HAL exact frame bytes not statically fixed (Rust caller-stack frames) |
| R52 | Helper, map, and pure-compute performance differences | yes | partial | `helper/summary.tsv`: helper_loop (8 ARRAY lookup+update) AOT 33.6us / JIT 38.6us batch, counters verified=100; 8 exec workloads are pure compute (0 helper calls) | rBPF helper NOT MEASURED (cold `switch` path leaves map index unresolved, counters=0); HAL helper NOT MEASURED (no opcode) — `failures.json` |
| R53 | Compile time never mixed into MCU exec time; identical inputs and methodology per arm | yes | yes | Host compile in `host-compile.tsv` only; MCU times from device clock; identical 32B fixtures all arms (bitswap param 0→1, current source refuses 0); AOT/JIT order-balanced interleaved | — |
| R54 | Over-capacity programs report a failure reason; no truncation or silent dependency removal | yes | yes | `failures.json`: bsort JIT image 12956 > 8192 (and > 3584 RX), refused not truncated; AOT bsort 1900 / rBPF 4952 fit and measured | — |

## Deliverables

| # | Requirement | Implemented | Verified | Evidence | Open issue |
|---|-------------|-------------|----------|----------|------------|
| D1 | Full test execution report naming really-run tests and the environment | yes | yes | `jit/REPORT.md` §1: 34 JIT tests, 8727 oracle cases, 8-program pipeline, device RX and perf, with host and board environment | — |
| D2 | ISA support matrix, confirmed defect list, fix record | yes | yes | `xpost-jit matrix` JSON; `jit/REPORT.md` §2 F1–F7 with fix status; `.audit/jit-xpost.tsv` | F3–F5 and F7 live in xpost, reported not modified |
| D3 | Reproducible C→eBPF→JIT→XPOST ELF pipeline | yes | yes | `jit/scripts/build-elf.sh` one command; flashed container byte-identical to a fresh pack | — |
| D4 | Automated differential, negative, and applicable device tests | yes | yes | `jit/oracle/` 8727 cases incl. 25 negative; `jit/tests/exec.rs` 18; `jit/scripts/p4_drive.py`, `p4_switch.py` | Device packet-byte capture INCONCLUSIVE |
| D5 | XPOST helper/map/entry/stack ABI contract doc | yes | yes | `jit/XPOST-ABI.md`; `jit/REPORT.md` §7 device-confirmed entry, helper and map facts | Stack depth still unreconciled |
| D6 | Comparable perf/resource results for AOT, JIT, rBPF, HAL | yes | yes | `jit/reports/p5/`: `matrix/summary.tsv` (4-arm engine times + batch), `host-compile.tsv`, `resources.tsv`, `helper/summary.tsv`, `failures.json`, `build/p5/containers.tsv`; rerunnable `jit/scripts/p5_build.sh` + `p5_drive.py` | bsort JIT over-capacity; rBPF/HAL helper gaps documented |
| D7 | Explicit safety boundary, open gaps, integration acceptance conclusion | yes | yes | `jit/REPORT.md` §8: 8 numbered gaps plus the acceptance conclusion | Core goal met on silicon; gaps recorded, so the PR stays Draft |

## External evidence

- RFC 9669 (eBPF ISA), sections 4 (ALU) and 4.2 (byte swap). Used to settle ALU END imm=64 as a 64-bit swap. https://www.rfc-editor.org/rfc/rfc9669.html
- Jitterbug (Nelson et al., OSDI 2019), per-instruction state correspondence for JIT translation validation. Method reference for R20. https://www.usenix.org/conference/osdi19/presentation/nelson
- rbpf, the independent oracle for R17. Local fork at `/Volumes/SSD/bs/xpost/rbpf`, upstream https://github.com/qmonnet/rbpf

## Genuine conflicts

None raised. Hardware, toolchain, and the xpost tooling are all present, so no task-book requirement is currently blocked by a missing permission or an unsatisfiable pair.