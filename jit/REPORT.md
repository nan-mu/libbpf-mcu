# RV32 eBPF JIT

Host path only. A Clang eBPF object compiles to RV32IM, links with addresses from the firmware ELF's `.xpost.mem` (XPM1), and packs as Compact ELF V0. Device RX runs, hot switch, and performance numbers are not part of this PR.

## 1. What this tree checks

| Suite | Command |
|---|---|
| JIT tests | `cargo test --manifest-path jit/Cargo.toml` |
| C to eBPF to JIT | `jit/scripts/check-xdp.sh` |
| Independent oracle | `cargo test --manifest-path jit/oracle/Cargo.toml --release` |
| Pack | `pixi run build jit -c <stem> --firmware <firmware.elf>` |

Device RX, hot-switch, and the perf matrix are not commands in this tree. `pixi run build jit` does not talk to a board.

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

A program relocation that does not resolve to a name is a load error. `compile` does not
see an empty map for that `lddw`, so the immediates are not emitted as a constant.

### Confirmed defect list

| # | Defect | Where | Status |
|---|---|---|---|
| F1 | Map `lddw` identity taken from `src_reg`, not the relocation | `jit/src/compile.rs`, `bpf_vm.rs` | **Fixed**, regression test added |
| F2 | ALU32 mod-by-zero high half | rbpf, not the JIT | Adjudicated to rbpf, see §3 |
| F3 | rbpf JMP64 immediate zero-extends while its own JSGT sign-extends | `rbpf/src/interpreter.rs:324` | Reported, xpost not modified |
| F4 | rbpf has no SDIV/SMOD (never reads `insn.off`) | `rbpf/src/interpreter.rs` | Reported |
| F5 | rbpf `NEG64` panics on `i64::MIN` under overflow checks | `rbpf/src/interpreter.rs:573` | Reported |
| F6 | Oracle key pointer was a host address, unreadable by the map model | `jit/oracle/src/run.rs` | Fixed in the harness |

## 3. Semantic verification and the one open divergence

The oracle is a separate rbpf interpreter. It compares return value, termination status, the full packet window,
map storage, and the ordered helper trace `(id, arg1..arg5) → ret`.

Coverage, counted from `results.json`: 6688 boundary probes (6176 pass, 12 fail, 500
unsupported), 2000 seeded random programs, 14 real-program cases, 25 negative cases.
Boundary values include `0`, `-1`, `i32::MIN/MAX`, `i64::MIN/MAX`, overflow edges, and
shift counts `0,1,31,32,33,63,64,65`.

The oracle also runs its **own** RV32 executor alongside the library's on every case and
requires identical returns and memory. `executor_split` is recorded on 8702 cases and is
null on every one, so the two executors never disagreed.

**111 engine-vs-engine disagreements, in four groups.** 27 are one question, ALU32 `mod`
with a zero divisor: the JIT keeps the low 32 bits and clears the high half, rbpf keeps all
64 bits. The other 84 sit in the `unsupported` bucket but are real disagreements with
differing returns and memory: 44 rbpf JMP64-immediate cases and 40 SDIV/SMOD cases. They
are attributed to rbpf, not to the JIT. A further 368 unsupported cases are JIT refusals
and 48 are both engines refusing.

**The JIT is right on all four, and the spec says so.** The IETF BPF WG source for
RFC 9669 (`ietf-wg-bpf/ebpf-docs`, `rst/instruction-set.rst`) states verbatim:

> If execution would result in modulo by zero, for ``ALU64`` the value of the destination
> register is unchanged whereas for ``ALU`` the upper 32 bits of the destination register
> are zeroed.

That is exactly the JIT's behavior. The same document defines `imm` as a **signed** integer
immediate, which confirms F3 against rbpf's zero-extending `JGT_IMM`, and defines SDIV/SMOD
with `offset` 1, which confirms F4.

Corroborating measurement: `alu32/mod/x/0xffffffffffffffff/0x1` **passes** — rbpf
zero-extends with a non-zero divisor even when the destination's high half is set, so it
contradicts itself on the zero-divisor path. `jit/oracle/examples/modzero.rs` inserts
`mov32 dst,dst` after each ALU32 MOD/DIV and all 15 random cases then agree.

**Evidence limit.** This is the RFC's own body text read from the WG repository at HEAD,
not the published RFC page. `rfc-editor.org` and `datatracker.ietf.org` are both blocked by
network policy. The clause is unambiguous, so the adjudication is spec-confirmed rather
than inferred.

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
pixi run build jit -c firewall --firmware <firmware.elf>

# Independent differential oracle
cargo test --manifest-path jit/oracle/Cargo.toml --release
```

Device RX, hot-switch, and the perf matrix are not commands in this tree. Their scripts and report files were removed. `pixi run build jit` does not talk to a board.

`pack-jit` reads the firmware's `.xpost.mem` (XPM1), links at the slot base, places map
placeholders inside the flat image, and encodes with `xpost_elf::build_container`. It then
accepts the result with `xpost_elf::scan_at` — **the same parser the firmware loader runs**.
Entry, image size, digest, and the map-VMA set are all checked. A referenced map that the
metadata builder would drop is a hard error, not a silent miss.

The device does no relocation and parses no sections, so every address is closed on the
host. `check_rv32im` rejects RVC halfwords, F/D/A opcodes, and RV64-only widths.

## 5. Device RX and hot switch

Device RX runs and hot switch are not part of this PR.

## 6. Performance

Performance numbers are not part of this PR.

## 7. ABI contract

`jit/XPOST-ABI.md` is the contract. It is not proof the firmware executed a JIT image.

- Entry: firmware `jalr` to the slot base, `a0 = xdp_md*`, return read from `a0` as `i32`.
  `sp` must be 16-byte aligned. `s0..s11` saved and restored by the firmware.
- `xdp_md`: 24 bytes, `data@0`, `data_end@4`, `data_meta@8`, `ingress_ifindex@0xc`,
  `rx_queue_index@0x10`, `egress_ifindex@0x14`. The program may shrink `data_end` but must
  not move `data`.
- Helper: `helper_dispatcher(idx, a1..a5) -> usize`, ilp32. `a0` is the helper id, `a1..a5`
  are the low 32 bits of BPF `R1..R5`, return in `a0` zero-extended into `R0`.
- Map: the `lddw` carries the absolute VMR address. The firmware binds it to real storage
  through its VMR table at lease. The placeholder bytes in the image are never read.

## 8. Limits

**Do not read "tests pass" as "the JIT is correct."** What a host differential run establishes
is section 3's first bullet, on the inputs that run exercised.

- The 592-byte frame is the tool's stack adjust, not a measured firmware reservation.
- `.rodata`, `.data`, and `.bss` are refused. A non-map `lddw` symbol is an error.
- Map semantics in the oracle are shared by construction. HASH maps are modelled as arrays
  on the host. The oracle rewrites ctx loads on its own side, recorded per case as `ctx_patches`.
- Verifier assumptions are not re-checked by the JIT (section 3).

Device execution is not part of this PR.

## 9. Where to look

- `jit/XPOST-ABI.md` — RV32IM entry, helper convention, and map VMR.
- `jit/oracle/` — the independent oracle. `results.json` is regenerated by the test command
  and is not committed.
- `jit/tests/exec.rs` — map `lddw` regression.
