# RV32 eBPF JIT: audit, verification, and XPOST integration

Task book: P0–P5 plus seven deliverables. Baseline `1898246`. Branch `agent/jit-xpost-verify`.

**Result.** A Clang-built eBPF ELF compiles on macOS to RV32IM, links at the firmware's
execution slot, packs through the existing `xpost-elf` library into Compact ELF V0, and
**executes on the ESP32-C3 XPOST RX path**. Six RX programs behaved identically to their
AOT controls with every safety counter at zero. The audit also found and fixed a defect
that made every map lookup miss.

Read section 8 before relying on this. Several properties are explicitly not proven.

## 1. What actually ran, and where

Environment: macOS, Darwin 25.6, arm64. Clang `/opt/homebrew/opt/llvm/bin/clang`.
Board: ESP32-C3 over `/dev/cu.usbmodem21101`, xpost-agent on `127.0.0.1:9240`.
RX stimulus: UDP from this Mac (`192.168.110.96`) to the board (`192.168.110.106:8080`).

| Suite | Command | Result |
|---|---|---|
| JIT unit + integration | `cargo test --release` in `jit/` | 34 pass (5 lib, 11 diff, 18 exec), 0 fail |
| C→eBPF→JIT check | `jit/scripts/check-xdp.sh` | 8 programs, PREVAIL pass, 8 JIT pass |
| Independent oracle | `cargo test --manifest-path jit/oracle/Cargo.toml --release` | 8727 cases: 8199 pass, 27 adjudicated divergences, 501 unsupported, 0 inconclusive |
| C→eBPF→JIT→ELF V0 | `jit/scripts/build-elf.sh` | 7 containers accepted, `bsort` refused over capacity |
| Device RX (P4) | `jit/scripts/p4_drive.py` | 6 programs × AOT control + JIT, all OBSERVED, safety counters clean |
| Device hot-switch | `jit/scripts/p4_switch.py` | 2 switches, `ok=1 rollback=0 severe=0` |
| Device perf (P5) | `jit/scripts/p5_drive.py matrix` | 80 matrix records, 0 errors, every output byte-correct |

The oracle suite is **red by design**: 27 cases diverge and are attributed, not hidden.
See section 3.

## 2. The defect that mattered

**Map references were silently dropped.** Clang leaves `src_reg` at 0 on a map `lddw`
and names the map only in the ELF relocation. `compile.rs` tested `src_reg` alone, so it
emitted the constant 0. The helper received map 0, found no descriptor, and every lookup
missed. A blocklist program blocked nothing.

Evidence: `xdp_drop.bpf.o` instruction 14 is `18 01 ...` (`dst=1, src=0`) with
`R_BPF_64_64 → blocklist` at offset `0x70`.

**Why the old test missed it.** `bpf_vm.rs` was written in the same change as the JIT and
had the same branch. Both engines computed map 0, both missed, and the differential test
passed. This is the shared-premise failure the task book warned about, and it is the
reason an independent oracle was necessary rather than optional.

Fix: the relocation is the identity. `compile.rs` and `bpf_vm.rs` both changed.
Regression: `jit/tests/exec.rs::clang_map_lddw_resolves_through_the_relocation`.
Observable effect: map programs went from `relocs=1` to `relocs=2`.

### Confirmed defect list

| # | Defect | Where | Status |
|---|---|---|---|
| F1 | Map `lddw` identity taken from `src_reg`, not the relocation | `jit/src/compile.rs`, `bpf_vm.rs` | **Fixed**, regression test added |
| F2 | ALU32 mod-by-zero high half | rbpf, not the JIT | Adjudicated to rbpf, see §3 |
| F3 | rbpf JMP64 immediate zero-extends while its own JSGT sign-extends | `rbpf/src/interpreter.rs:324` | Reported, xpost not modified |
| F4 | rbpf has no SDIV/SMOD (never reads `insn.off`) | `rbpf/src/interpreter.rs` | Reported |
| F5 | rbpf `NEG64` panics on `i64::MIN` under overflow checks | `rbpf/src/interpreter.rs:573` | Reported |
| F6 | Oracle key pointer was a host address, unreadable by the map model | `jit/oracle/src/run.rs` | Fixed in the harness |
| F7 | rBPF map index never resolved on the cold-boot path | `xpost/src/xdp/mod.rs:492` vs `swap.rs:173` | Reported, xpost not modified |

F7 is an XPOST integration gap, not a JIT defect: `switch` copies cold image bytes raw and
never calls `apply_map_addresses`, which lives only in the hot-swap `stage` path. An
interpreter image booting cold therefore gets null map pointers. AOT and JIT are unaffected
because they carry absolute addresses.

## 3. Semantic verification and the one open divergence

The oracle is the `rbpf` fork at `/Volumes/SSD/bs/xpost/rbpf`, a genuinely separate
implementation. It compares return value, termination status, the full packet window,
map storage, and the ordered helper trace `(id, arg1..arg5) → ret`.

Coverage: 6188 boundary probes, 2000 seeded random programs, 14 real-program cases,
25 negative cases. Boundary values include `0`, `-1`, `i32::MIN/MAX`, `i64::MIN/MAX`,
overflow edges, and shift counts `0,1,31,32,33,63,64,65`.

**27 divergences, all one question.** ALU32 `mod` with a zero divisor: the JIT keeps the
low 32 bits and clears the high half; rbpf keeps all 64 bits.

Adjudicated to rbpf, on measured evidence: `alu32/mod/x/0xffffffffffffffff/0x1` **passes**
— rbpf zero-extends the ALU32 result with a non-zero divisor even when the destination's
high half is set. It only preserves 64 bits on the zero-divisor path, which contradicts
its own behavior elsewhere. `jit/oracle/examples/modzero.rs` confirms it: inserting
`mov32 dst,dst` after each ALU32 MOD/DIV makes all 15 random cases agree.

**Limit, stated plainly.** The RFC 9669 clause text is **unverified**. Network policy
blocks both `rfc-editor.org` and `datatracker.ietf.org`. The adjudication rests on the
ALU32 zero-extension invariant and rbpf's internal inconsistency, not on a reading of the
spec. Impact is narrow: it needs a zero divisor *and* a non-zero destination high half.
No program in `tests/xdp` reaches it.

### Four-way split of claims

- **Proven by differential test against an independent oracle:** register mapping,
  ALU32/ALU64 arithmetic over the supported set, conditional and unconditional jumps,
  byte/half/word/double memory access including unaligned, `lddw`, helper argument and
  return marshalling, program exit, and map reference binding.
- **Proven by symbolic argument:** nothing. No symbolic proof was attempted.
- **Assumed from the eBPF verifier:** `R1..R5` unreadable after a helper call, `R0`
  assigned before exit, `lddw` words paired. The JIT does not re-check these. An illegal
  program that reads `R1` after a call gets garbage, not an error.
- **Not covered:** atomics, tail calls, ALU64 div/mod, ALU64 bswap, BPF-to-BPF calls
  (all refused with an explicit error); `.rodata`/`.data`/`.bss` (refused); map semantics
  themselves, because both oracle sides call the same host `dispatch` by construction;
  HASH maps on the host, which are modelled as arrays.

## 4. Reproducible pipeline

```sh
# Host: C -> eBPF -> PREVAIL -> RV32IM -> Compact ELF V0
CLANG=/opt/homebrew/opt/llvm/bin/clang \
OBJDUMP=/opt/homebrew/opt/llvm/bin/llvm-objdump \
FIRMWARE=<firmware.elf> sh jit/scripts/build-elf.sh

# Independent differential oracle
cargo test --manifest-path jit/oracle/Cargo.toml --release

# Device RX
python3 jit/scripts/p4_drive.py run jit_just_drop just_drop --packets 30
```

`pack-jit` reads the firmware's `.xpost.mem`, links at the slot base, places map
placeholders inside the flat image, and encodes with `xpost_elf::build_container`. It then
accepts the result with `xpost_elf::scan_at` — **the same parser the firmware loader runs**.
Entry, image size, digest, and the map-VMA set are all checked. A referenced map that the
metadata builder would drop is a hard error, not a silent miss.

The device does no relocation and parses no sections, so every address is closed on the
host. `check_rv32im` rejects RVC halfwords, F/D/A opcodes, and RV64-only widths.

**Byte-level reproducibility verified:** the container flashed to the board as
`jit_xdp_drop` is byte-identical to a fresh `pack-jit` run from the Clang object.

## 5. Device integration (P4)

Firmware `just_xdp` (`just-drop-cag` / `just-tx-cag`), **no MCU runtime changes**. A passed
datagram is ACKed, a dropped one is not, which makes the action observable from the Mac.

| Program | JIT observation | AOT control |
|---|---|---|
| `just_drop` | 30 sent, 0 ACKs, `counter[96]` +31 | +30, same behavior |
| `xdp_drop` (seeded) | 30 sent, 0 ACKs, `xdp_drop`=30 | identical |
| `xdp_drop` (empty map) | 20 sent, 19 ACKs | passes, as expected |
| `firewall` (seeded) | 0 ACKs, `blacklist[.96]` +31 | +31 |
| `firewall` (empty) | 20 sent, 16 ACKs | passes |
| `case_mark` | `rxcnt[17]` +34, `xdp_tx`=34, `bad_md`=0 | +33, `xdp_tx`=33 |
| `just_tx` | `xdp_tx`=100, UDP→TX, non-UDP→DROP | `xdp_tx`=95, same |
| `div2` | return 12 → Aborted, `xdp_aborted`=22 | identical distribution |

Both branches of every map conditional were exercised, with the map seeded and empty.
Every JIT case: `runtime_errors`, `bad_md`, `stack_misalign`, `reentry`, `helper_unresolved`,
`helper_map`, `pool_drop_misalign` all **zero**.

Hot-update: on `case_xdp`, staged AOT into slot 1, activated 0→1, staged JIT into slot 0,
activated 1→0. Both switches `ok=1 rollback=0 severe=0`. The JIT image participates in the
existing lease/stage/activate model unchanged.

Perf totals include background traffic from the shared WiFi network. Stimulus was isolated
by the per-source map key (e.g. `counter[96]` equals the packet count exactly) and by ACK
behavior, not by raw perf totals.

## 6. Performance and resources (P5)

**Host compile time is never mixed into MCU execution time.** Host numbers are
`xpost-jit compile --repeat 200`, release, on the Mac. MCU numbers come from the device clock.

MCU per-execution, firmware's own 2000-run batch mean (µs), `exec_bench`, identical inputs:

| workload | AOT | JIT | JIT/AOT | rBPF | HAL |
|---|---|---|---|---|---|
| incr | 5.36 | 6.01 | 1.12 | 44.0 | 1.16 |
| square | 5.36 | 6.01 | 1.12 | 44.1 | 1.14 |
| bitswap | 5.65 | 7.20 | 1.27 | 80.3 | 1.28 |
| fib | 6.66 | 8.59 | 1.29 | 178.8 | 2.39 |
| buf | 6.51 | 10.75 | 1.65 | 201.2 | 2.39 |
| memcpy | 5.55 | 7.12 | 1.28 | 78.2 | 1.62 |
| fletcher32 | 6.35 | 9.12 | 1.44 | 155.7 | 2.16 |
| bsort | 7.61 | **over capacity** | — | 534.4 | 5.24 |

AOT and JIT share the **identical firmware** and differ only in the cold-table container,
measured in two order-balanced interleaved passes.

**What limits the number.** The single-shot `exec seg engine` median is flat at ~70 µs
across workloads whose work differs 20×, because it brackets `invoke` including perf hooks
that cost more than a small program. The batch mean divides the 1 µs clock quantization by
2000 and amortizes interrupts, so it resolves actual engine work. Repeatability: AOT incr
5363 ns in a probe, 5362 ns in the matrix. Noise floor is the 1 µs systimer plus embassy
and USB-serial interrupts; WiFi is not initialized in `exec_bench`. CPU 160 MHz, IRAM-resident.

Resources:

| program | compile ns_med | JIT code bytes | AOT container | JIT container | rBPF container |
|---|---|---|---|---|---|
| incr | 791 | 536 | 460 | 888 | 576 |
| bitswap | 1000 | 1252 | 628 | 1604 | 880 |
| fletcher32 | 5667 | 5052 | 1428 | 5408 | 3556 |
| bsort | 6979 | 12940 | 2236 | **refused** | 5288 |
| case_mark | 2333 | 2528 | — | 2872 (RX slot) | — |
| just_tx | 1270 | 1752 | — | 2092 (RX slot) | — |

JIT code is larger because it emits RV32IM without compression; AOT is RV32IMC.
Stack: JIT frame 592 bytes from the caller stack, no stack switch. AOT entry frame 16 bytes
(32 for `helper_loop`). Slot capacity 8192 (`exec_bench`) / 3584 (`just_xdp` RX).

Helper/map cost, measured with `helper_loop` (8 ARRAY lookup+update per flight):
AOT 33.6 µs, JIT 38.6 µs batch. The counters map reached exactly 100 after 100 flights on
both arms, proving the helpers mutated real storage. That implies ~3.5 µs per lookup+update
on AOT. The 8 exec workloads are pure compute (zero helper calls).

**Over capacity, reported not truncated.** `bsort` JIT image is 12956 bytes, exceeding both
the 8192-byte exec slot and the 3584-byte RX slot. `pack-jit` refuses with the size in the
message. AOT `bsort` (1900-byte image) and rBPF `bsort` (4952-byte bytecode) both fit and
were measured.

## 7. ABI contract

`jit/XPOST-ABI.md` is the contract. Summary of what the device run confirmed:

- Entry: firmware `jalr` to the slot base, `a0 = xdp_md*`, return read from `a0` as `i32`.
  `sp` must be 16-byte aligned. `s0..s11` saved and restored by the firmware.
- `xdp_md`: 24 bytes, `data@0`, `data_end@4`, `data_meta@8`, `ingress_ifindex@0xc`,
  `rx_queue_index@0x10`, `egress_ifindex@0x14`. The program may shrink `data_end` but must
  not move `data`.
- Helper: `helper_dispatcher(idx, a1..a5) -> usize`, ilp32. `a0` is the helper id, `a1..a5`
  are the low 32 bits of BPF `R1..R5`, return in `a0` zero-extended into `R0`.
- Map: the `lddw` carries the absolute VMR address. The firmware binds it to real storage
  through its VMR table at lease. The placeholder bytes in the image are never read.

## 8. Safety boundary and open gaps

**Do not read "tests pass" as "the JIT is correct."** What is established is section 3's
first bullet, on the inputs tested. Specifically not established:

1. **Exact packet bytes on the device.** `case_mark` and `just_tx` ran the rewrite path and
   returned TX with `bad_md`=0, but byte-level capture needs root tcpdump and there is no
   passwordless sudo. TX action and map effects are confirmed; the rewritten bytes are
   **INCONCLUSIVE** on silicon. Host oracle compares them fully.
2. **RFC 9669 clause text unverified** for the ALU32 mod-by-zero case (§3).
3. **Stack budget not reconciled.** The 592-byte frame is measured against the tool's
   default budget, not against a measured firmware reservation. No stack-budget receipt
   exists. `stack_misalign`=0 on every run is not a depth proof.
4. **`.rodata`/`.data`/`.bss` unsupported.** A non-map `lddw` symbol is refused explicitly.
   No test program needs them.
5. **rBPF helper cost NOT MEASURED** because of F7, an XPOST cold-boot gap. HAL has no
   `helper_loop` twin by design.
6. **Failure fallback not injected.** Clean-path safety counters are zero, but a deliberately
   corrupt image was not run to observe the Drop path.
7. **Map semantics shared by construction** in the oracle; HASH modelled as ARRAY on the host.
8. **Verifier assumptions** are not re-checked by the JIT (§3, third bullet).

**Integration acceptance.** The core goal is met and verified on silicon: a JIT-produced
Compact ELF V0, built from a real Clang object on macOS, executes on the XPOST RX path
through the existing loader, helper, map, slot, and hot-update model, with no MCU runtime
change, matching AOT behavior. The gaps above are recorded rather than closed, so this
stays a Draft until they are resolved or explicitly accepted.

## 9. Evidence

- `.audit/jit-xpost.md` — requirement checklist, one row per task-book item.
- `.audit/jit-xpost.tsv` — decision trail.
- `jit/reports/p4/` — per-case JSON, serial logs, perf, `summary.tsv`, switch and lifecycle.
- `jit/reports/p5/` — 80 matrix records, `host-compile.tsv`, `resources.tsv`, `failures.json`.
- `jit/oracle/` — the independent oracle; `results.json` is regenerable and not committed.
- `build/jit-elf/report.tsv` — container build results including the `bsort` refusal.