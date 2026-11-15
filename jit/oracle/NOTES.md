# Findings, and changes needed outside this crate

Everything here is a report. No file outside `jit/oracle/` was modified.

## F1. Map addresses are silently dropped. This is a JIT defect.

**Status: fixed in `jit/src/compile.rs` and `jit/src/bpf_vm.rs` by the parent,
and confirmed by this oracle.** All fourteen program-level cases now pass,
including the three stack-keyed map programs that F6 below was hiding. The
analysis below is kept as the record of what was wrong.

**Severity: high.** A blocklist program never blocks anything.

`jit/src/compile.rs:400`, in `emit_lddw`:

```rust
if insn.src == 0 {
    emit_imm(&mut ctx.code, live.lo, insn.imm);
    emit_imm(&mut ctx.code, live.hi, next.imm);
} else {
    // ... emits RelocKind::Lddw and consults ctx.symbols
}
```

The branch decides "is this a map load?" from `src_reg` alone. `ctx.symbols` is
consulted only in the `else` arm.

Clang does not set `src_reg` for a map reference. It emits `src_reg = 0` and
carries the map identity in an ELF relocation. Measured on
`jit/oracle/build/xdp_drop.bpf.o`:

```
14: 18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00   r1 = 0x0 ll
RELOCATION RECORDS FOR [xdp]:
0000000000000070 R_BPF_64_64   blocklist
```

Byte 1 is `0x01`, so `dst = 1`, `src = 0`. Offset `0x70` is 112, which is pc 14.
`load_bpf` correctly returns `symbols = {112: "blocklist"}`. `compile` then takes
the `src == 0` arm and emits the constant 0, with no relocation.

Consequence chain, all observed:

- `compile` reports 1 relocation (the helper `Call`), not 2.
- `link` has nothing to patch, so `R1 = 0` at the call.
- The helper receives `map = 0`. `dispatch` reads address 0, finds no `MAP1`
  magic, and returns a miss.
- Every map lookup misses, unconditionally.

**The existing differential test cannot see this.** `jit/src/bpf_vm.rs:42` has
the identical branch:

```rust
let value = if insn.src == 0 {
    (insn.imm as u32 as u64) | ((next.imm as u32 as u64) << 32)
} else {
    let name = symbols.get(&(pc as u64 * 8)) ...
};
```

Both sides compute `R1 = 0`, both miss, both agree. Running the shipped checker
on the packet whose key is map index 3:

```
$ cargo run --manifest-path jit/Cargo.toml -- check \
    jit/oracle/build/firewall.bpf.o --packet ...030000007f000001
status=pass section=xdp bpf_insns=23 rv_bytes=660 relocs=1 r0=0x2 detail=r0 0x2
```

`r0=0x2` is `XDP_PASS`. rbpf returns `0x1`, `XDP_DROP`, and writes the counter in
map storage. The program is a firewall that passes everything.

This is the premise failure the task book predicted: two implementations written
from one reading agree with each other and are both wrong.

**Suggested fix, not applied.** Decide "is this a pseudo load?" from the
presence of a relocation at that pc, not from `src_reg`:

```rust
let symbol = ctx.symbols.get(&(pc as u64 * 8)).cloned();
if insn.src == 0 && symbol.is_none() {
    // plain 64-bit constant
} else {
    // fixed four-word shape + RelocKind::Lddw carrying `symbol`
}
```

`bpf_vm.rs:42` needs the same change, or the reference keeps agreeing with the
bug. `link` already rejects address 0, so once the relocation exists the
fail-closed path covers a missing map.

Seven program-level cases fail on this. Five have matching return values and
differing helper traces (`map = 0` vs `map = 0x3000`); two also differ in the
returned action and in map storage. The trace comparison is what exposes the
five that the return value alone would hide.

## F2. ALU32 mod-by-zero: unresolved disagreement. 27 cases.

**Status: still open, and now fully attributed.** 12 boundary probes and 15
random seeds. The parent is adjudicating it against RFC 9669. Nothing on either
side was changed to make these pass.

The 15 random failures are the *same* question, not a memory bug. Evidence, all
rerunnable with
`cargo run --manifest-path jit/oracle/Cargo.toml --release --example modzero`:

- Every differing scratch word has an identical low 32 bits. Only the high 32
  differ. The same holds for the return value where it differs.
- Inserting `mov32 dst, dst` after every ALU32 MOD/DIV forces the JIT's rule
  (keep low 32, clear high 32) onto rbpf. For a nonzero divisor both engines
  already zero-extend, so the insertion is a no-op there. After the insertion
  all 15 cases pass: return value and all 128 scratch bytes identical.
- The example asserts that every jump still lands on the same instruction after
  the offset remap, so a broken remap cannot produce a trivial pass by exiting
  early. That guard caught a real bug in the guard itself during development
  (it compared `off`, which is legitimately rewritten for a jump target that is
  itself a jump).

`seed1235` shows the propagation clearly: pc 36 is `mod32 r3, r4` with `r4 == 0`,
and pc 38 is `mul64 r3, -2045049925`. The high-bit difference from the mod
survives the multiply, so the saved `r3` differs while its low 32 matches.

Exact instruction: `mod32 r0, r1`, opcode `0x9f`, `off = 0`.

| `r0` before | `r1` | JIT after | rbpf after |
| --- | --- | --- | --- |
| `0xffffffffffffffff` | `0` | `0x00000000ffffffff` | `0xffffffffffffffff` |
| `0x8000000000000000` | `0` | `0x0000000000000000` | `0x8000000000000000` |
| `0x7fffffffffffffff` | `0` | `0x00000000ffffffff` | `0x7fffffffffffffff` |
| `0xffffffff80000000` | `0` | `0x0000000080000000` | `0xffffffff80000000` |

Same for the immediate form (`0x94`, `imm = 0`) and for a divisor whose low 32
bits are zero (`0x8000000000000000`).

- JIT rule: keep the low 32 bits, clear the high 32.
- rbpf rule: leave all 64 bits unchanged. `interpreter.rs:526`,
  `MOD32_REG if reg[_src] as u32 == 0 => ()`.

All 27 failures differ **only** in the high 32 bits; verified programmatically.
12 are boundary probes, 15 are random seeds. `seed428` is the clearest: the
return value matches, and the only differing word is saved `r8`, whose instruction
21 is `mod32 r8, 0`. Reproduce with
`cargo run --manifest-path jit/oracle/Cargo.toml --example fuzzcase -- 428`.

**I could not adjudicate this, and I am not guessing.** Two things worth knowing:

- `jit/XPOST-ABI.md` states both "mod leaves the destination unchanged" and
  "32 位模 0 保留低 32 位并清高 32 位". Those describe different behaviors. The
  implementation does the latter.
- The uBPF conformance vectors bundled with rbpf do not settle it.
  `test_vm_mod_by_zero_imm` uses `mov32 r0, 1` and
  `test_vm_mod_by_zero_reg_long` leaves `r0` at 0, so both destinations already
  have zero upper halves. Neither distinguishes the two rules.

Adjudication needs RFC 9669 §4.1 and the kernel's `___bpf_prog_run` ALU32_MOD
path. I had neither text locally. Until then this stays a failure, not a pass
and not a declared oracle gap.

Note the blast radius is narrow: it needs a zero divisor **and** a nonzero upper
half in the destination. No `tests/xdp` program reaches it.

## F3. Three rbpf defects. Outside this crate, in the xpost tree.

These are oracle limitations, recorded as unsupported with rbpf's own text. They
are not JIT defects, and the JIT is on the correct side of the first one.

1. **JMP64 immediates are zero-extended.** `interpreter.rs:324`:
   `macro_rules! unsigned_u64 { ($imm:expr) => { ($imm as u32) as u64 } }`, used by
   `JEQ/JGT/JGE/JLT/JLE/JNE_IMM`. But `JSGT_IMM` at `:604` uses `insn.imm as i64`
   and every `ALU64_IMM` uses `insn.imm as u64` — both sign-extend the same i32
   field. `JSET_IMM` also sign-extends, and it has zero failures, which matches
   the diagnosis exactly. 44 cases. Fix: sign-extend for the 64-bit unsigned
   comparisons, i.e. `insn.imm as i64 as u64`.
2. **No SDIV/SMOD.** The ALU block never reads `insn.off`, so `off = 1` executes
   as unsigned. 40 cases.
3. **`NEG64` panics on `i64::MIN` under overflow checks.**
   `interpreter.rs:573`: `reg[_dst] = -(reg[_dst] as i64) as u64`. `NEG32` at
   `:524` correctly uses `wrapping_neg()`. 22 cases. Fix: `wrapping_neg()`.

## F4. The dependency path in the task brief does not resolve

The brief says `path = "../../xpost/rbpf"` resolves from `jit/oracle/`. It does
not. From `<worktree>/jit/oracle`, `../..` is `<worktree>`, and the symlink is one
level above that. Verified:

```
<worktree>/xpost                       -> No such file or directory
<worktree>/../xpost/rbpf               -> exists
```

The manifest uses `../../../xpost/rbpf`.

## F5. Two harness bugs I found and fixed in my own crate

Recorded so the coverage numbers are read correctly.

- The random generator built conditional jumps from an ALU class, so
  `CLASS_ALU | JMP_JEQ | SRC_X` decoded as `sub32`. The random suite had no jumps
  at all until this was fixed.
- `Rng::new` used `seed | 1`, which folded every even seed into the odd one above
  it. Seeds 1..2000 produced only 1000 distinct programs. Replaced with a
  splitmix64 finalizer. Failures rose from 27 to 34 because coverage doubled, not
  because the JIT changed.

## F6. rbpf's BPF stack was not u32-addressable. Harness defect, fixed.

Three program cases (`just_drop`, `just_tx`, `case_mark`) failed with matching
map VMRs and mismatched key pointers:

```
jit_trace = [{"id":1,"args":[12288,196524,4130,14,8],"ret":32776}]
rbpf_trace= [{"id":1,"args":[12288,44441724,4130,14,8],"ret":0}]
```

`args[0] = 0x3000` agreed. `args[1]` is the key: the JIT's `196524 = 0x2ffb0 - 4`
is a model offset, rbpf's `44441724` is a macOS heap address. `dispatch` indexes
a flat `Vec<u8>` by u32, so it could not read rbpf's key and every stack-keyed
lookup returned a miss. The JIT was right; the harness could not compare.

The old bridge truncated any out-of-window argument with `a[k] as u32`, which is
the silent guess that hid this.

**Fix.** The fork's `mcu` ABI takes the stack from the caller, so the harness
allocates it and knows its window by construction. `bridge_call` relocates
in-window arguments to `MODEL_FP - 512 + (arg - stack_host)` and copies the stack
bytes into the model before `dispatch`. Each relocation is recorded per case in
`results.json` under `stack_patches`. An address argument of a map helper that
is wider than 32 bits and falls in no known window now makes the case
inconclusive with blame `oracle-harness`, never a truncated guess.

`MODEL_FP = 0x2ffb0` is derived from the JIT's frame
(`sp = 0x30000`, `align16(9*4 + 10*4 + 512) = 592`, `fp = sp - 592 + 512`) and
verified at run time by `jit_frame_pointer`, so a prologue change fails loudly.

Result: all three cases pass, with identical traces on both sides. The stack
window is now a compared region too.

Two regressions were introduced and fixed while doing this, both recorded here
because they are properties of the `mcu` path the next engineer must know:

- Under `mcu`, `register_allowed_memory` is inert. Permission comes only from
  `McuEnv::check_access`. Forgetting to register the flat world made every
  packet access fault (9 new failures). `install` now registers the world it
  owns.
- `bridge_call` holds the thread-local `RefCell` borrow. Calling a helper that
  borrows it again panics with "RefCell already borrowed". The stack sync is an
  inner function taking `&mut Bridge`.

## F7. The probe/random memory comparison is correct. Not a harness defect.

The suspicion was that `memory jit 4096..4224 rbpf 0..128 differs` meant the
packet window was being compared for pure-ALU probes. It does not.

- For probes, `DATA = 0x1000` is the **scratch** base, not the packet. The JIT
  watch `4096..4224` and the rbpf watch `0..128` are the same 128-byte scratch
  region in two address spaces. `check_probe` passes `r1 = DATA` to the JIT and
  the scratch buffer as `mbuff` to rbpf, so `r9 = r1` is the scratch base on
  both sides.
- Both buffers are zero-initialized (`vec![0u8; FLAT_LEN]` and
  `vec![0u8; scratch_len.max(64)]`). Nothing is uninitialized or aliased.
- The probes are not memory-free: the tail stores `r0` and `r1` (and the random
  tail stores `r0..r8`) into that region. A difference there is a register
  difference, which is exactly what the region is for.
- The differing bytes are confined to the 8-byte register save slots. After the
  fix the detail names them, e.g.
  `differs in 4 bytes [+0x44 00/0e +0x45 00/0b +0x46 00/1c +0x47 00/2c]`, which
  is the high half of saved `r8`. A mis-mapped region would differ wholesale,
  not in one register's high half.
- `seed141` differs only in the return value with identical memory: a forward
  jump landed on `exit` and skipped the stores, so the scratch stayed zero on
  both sides. That is the generator's intended behavior, not an artifact.

The cause of all 15 random failures is F2's ALU32 mod/div-by-zero high-bit rule,
proven by the `modzero` experiment. No JIT memory bug was found. The only
harness change here is the diff detail, which now names the differing offsets
and both byte values instead of an opaque range.

## Suggested follow-ups outside this crate

- F1 is applied. Keep the regression case in `jit/tests/` that asserts a map
  lookup **hits**, not just that the two engines agree. Agreement was the
  property that hid F1, and F6 hid the stack-keyed half of it.
- Adjudicate F2 against RFC 9669 §4.1 and the kernel's `___bpf_prog_run`
  ALU32_MOD path, then fix the losing side. All 27 failures should clear
  together; `modzero` is the check that they do.
- Consider reporting F3 upstream to qmonnet/rbpf.
