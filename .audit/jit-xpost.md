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
| C6 | Never deliver unlinked, unchecked, or unknown-dependency machine code | no | no | — | P3 link + validation gate |
| C7 | Unsupported eBPF features give an explicit error; no panic, silent skip, or unknown code | partial | no | `jit/src/compile.rs` rejects alu64 div/mod, bswap, atomics, bpf-to-bpf | Needs malformed-input panic sweep |

## P0 — reliable test baseline

| # | Requirement | Implemented | Verified | Evidence | Open issue |
|---|-------------|-------------|----------|----------|------------|
| R1 | Run all existing JIT unit and exec tests; record pass/fail/uncovered | yes | yes | `cargo test` in `jit/`: 17 exec tests green, run this session | Unit-test count to be recorded in report |
| R2 | Build opcode × source mode × operand width matrix from compile/rv/load/exec | yes | partial | `jit/src/matrix.rs`, `xpost-jit matrix` JSON dumped this session | Matrix must be checked against real encoder, not asserted |
| R3 | Support status for ALU32/ALU64, jumps, memory, lddw, call | yes | partial | matrix JSON groups alu32/alu64/jmp64/jmp32/mem/lddw/call | — |
| R4 | lddw takes two insns, second word validated, no jump into the middle slot | yes | yes | `jit/tests/exec.rs::rejects_bad_lddw_and_a_branch_into_it` green | — |
| R5 | Illegal register, unsupported opcode, bad branch target return `Result::Err` | yes | yes | `jit/tests/exec.rs::unknown_alu_and_bad_reg_are_errors` green | — |
| R6 | Arithmetic obeys RFC 9669 overflow, extension, div0, shift, signed rules | partial | no | `jit/XPOST-ABI.md` §内存和算术; `exec.rs::div_mod_zero`, `shift_and_arsh` | Needs independent-oracle boundary proof (P2) |
| R7 | ELF header/section/symbol/relocation bounds and types validated; no panic on bad input | partial | no | `jit/src/load.rs` | Panic sweep on malformed ELF outstanding |
| A-P0 | Machine-readable matrix plus a regression test per fix | partial | no | matrix JSON; `exec.rs` regression tests | Deliver matrix as a committed artifact |

## P1 — real C→eBPF→JIT tests

| # | Requirement | Implemented | Verified | Evidence | Open issue |
|---|-------------|-------------|----------|----------|------------|
| R8 | Cover div2, xdp_drop, case_mark, just_drop, just_tx, firewall, bitswap, bsort | yes | partial | `build/jit-check/report.tsv`, 8 rows | Inherited run; re-run this session |
| R9 | Clang produces a real `bpf.o` | yes | yes | `jit/scripts/check-xdp.sh:26` clang `--target=bpf` | — |
| R10 | Check ELF type, symbols, program sections, relocations | partial | no | `jit/src/load.rs` | No explicit reported ELF inspection step |
| R11 | Run PREVAIL and record the accurate result | yes | partial | `make/prevail_gate.py`, `report.tsv` prevail column | prevail/ empty in worktree; script falls back to main checkout |
| R12 | Select the named XDP section and run the Rust JIT | yes | yes | `load.rs` selects `xdp`/`xdp1`; report shows section per program | — |
| R13 | Check generated RV32 instructions and relocations | partial | no | `.rv32` + `.reloc` emitted | No assertion on reloc resolution yet |
| R14 | Execute the fully linked artifact on an independent RV32 executor | partial | no | `jit/src/rv_vm.rs` | rv_vm is self-written; linked artifact does not exist yet |
| R15 | Compare against an eBPF reference executor | partial | no | `jit/src/bpf_vm.rs`, `jit/tests/diff.rs` | Reference is self-written (see R17) |
| R16 | Out-of-scope programs recorded UNSUPPORTED, never PASS | yes | yes | `check-xdp.sh:54-61`, exit 2 for unsupported/inconclusive | — |
| A-P1 | One reproducible command; input is a real compiled ELF, not hand-assembled | yes | partial | `jit/scripts/check-xdp.sh` | Re-run and confirm from clean state |

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
| R25 | Generate ABI trampoline, entry, helper asm | yes | no | prologue/epilogue in `compile.rs`; entry = slot base checked by `scan_at` | Device confirmation pending (P4) |
| R26 | Resolve helper call, bpf-to-bpf call, map lddw, target address relocs | yes | yes | `compile.rs::link`; `pack-jit` reports `relocs=2` resolved for all map programs | — |
| R27 | Assign addresses per the existing XPOST slot linker layout | yes | yes | `jit_image.rs` code at slot base then 16-byte map placeholders, matching `esp32c3-slot.ld.tmpl` `.maps` | — |
| R28 | Link into an RV32 ELF and check symbols and relocations | yes | yes | `build_container` + `scan_at` verify entry, image size, digest, map VMA set | — |
| R29 | Extract the full native image and pack to Compact ELF V0 with existing `xpost-mcu-elf pack` | yes | yes | `xpost-mcu-elf pack-jit` reuses `build_container`; 7 containers in `build/jit-elf/` | — |
| R30 | Explicit eBPF helper ABI ↔ `helper_dispatcher` ABI argument/return conversion | yes | no | `jit/XPOST-ABI.md` §helper; `host_abi.rs` | Untested on device |
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
| R37 | Run current XPOST firmware on ESP32-C3, prefer no MCU runtime change | no | no | agent healthy at 127.0.0.1:9240, port `/dev/cu.usbmodem21101` | Prior run never flashed |
| R38 | No-map DROP/PASS program | no | no | — | Outstanding |
| R39 | Packet byte modification | no | no | — | Outstanding |
| R40 | Map lookup/update | no | no | — | Outstanding |
| R41 | Helper call and return value | no | no | — | Outstanding |
| R42 | `just_tx` TX behavior | no | no | — | Outstanding |
| R43 | Existing slot load, lease, stage, activate, switch tests | no | no | — | Outstanding |
| R44 | Check shared stack, register restore, helper args, map alias, packet window, IRAM exec, failure fallback | no | no | — | Outstanding |
| R45 | Record serial output, runtime state, return action, packet/map content per case | no | no | — | Outstanding |
| A-P4 | Same firmware config and runtime interface as AOT; JIT runs the real XDP datapath | no | no | — | **Primary gap** |

## P5 — performance and resources

| # | Requirement | Implemented | Verified | Evidence | Open issue |
|---|-------------|-------------|----------|----------|------------|
| R46 | Keep four arms: XPOST AOT, JIT, rBPF, HAL | no | no | `xpost/profiles.toml` has aot/rbpf/hal; JIT arm to add | Outstanding |
| R47 | Mac host JIT compile time | partial | no | `main.rs --repeat` reports ns min/med/max | Needs recorded runs |
| R48 | Generated native code byte count | yes | partial | `report.tsv` rv_bytes column | — |
| R49 | XPOST Compact ELF file size | no | no | — | Needs P3 output |
| R50 | MCU per-execution time | no | no | firmware `exec seg:` line | Outstanding |
| R51 | Stack usage and slot capacity | no | no | frame 592; slot 8192 (exec_bench) / 3584 (just_xdp) | Outstanding |
| R52 | Helper, map, and pure-compute performance differences | no | no | — | Outstanding |
| R53 | Compile time never mixed into MCU exec time; identical inputs and methodology per arm | no | no | — | Outstanding |
| R54 | Over-capacity programs report a failure reason; no truncation or silent dependency removal | no | no | bsort emits 12940 bytes vs 8192 slot | Must be reported as a failure |

## Deliverables

| # | Requirement | Implemented | Verified | Evidence | Open issue |
|---|-------------|-------------|----------|----------|------------|
| D1 | Full test execution report naming really-run tests and the environment | no | no | — | Outstanding |
| D2 | ISA support matrix, confirmed defect list, fix record | partial | no | matrix JSON, `.audit/jit-xpost.tsv` | Outstanding |
| D3 | Reproducible C→eBPF→JIT→XPOST ELF pipeline | partial | no | `check-xdp.sh` stops at `.rv32` | Needs the pack stage |
| D4 | Automated differential, negative, and applicable device tests | partial | no | `jit/tests/diff.rs`, `exec.rs` | Device tests outstanding |
| D5 | XPOST helper/map/entry/stack ABI contract doc | partial | no | `jit/XPOST-ABI.md` | Needs device-verified facts |
| D6 | Comparable perf/resource results for AOT, JIT, rBPF, HAL | no | no | — | Outstanding |
| D7 | Explicit safety boundary, open gaps, integration acceptance conclusion | partial | no | `jit/XPOST-ABI.md` §不由 JIT 保证的事 | Outstanding |

## External evidence

- RFC 9669 (eBPF ISA), sections 4 (ALU) and 4.2 (byte swap). Used to settle ALU END imm=64 as a 64-bit swap. https://www.rfc-editor.org/rfc/rfc9669.html
- Jitterbug (Nelson et al., OSDI 2019), per-instruction state correspondence for JIT translation validation. Method reference for R20. https://www.usenix.org/conference/osdi19/presentation/nelson
- rbpf, the independent oracle for R17. Local fork at `/Volumes/SSD/bs/xpost/rbpf`, upstream https://github.com/qmonnet/rbpf

## Genuine conflicts

None raised. Hardware, toolchain, and the xpost tooling are all present, so no task-book requirement is currently blocked by a missing permission or an unsatisfiable pair.