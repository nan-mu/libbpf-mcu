# Independent differential oracle for xpost-jit

This crate tests the eBPF-to-RV32IM JIT against **rbpf**, an interpreter that
shares no code and no reading of RFC 9669 with the JIT. It replaces the weak
evidence of `jit/tests/diff.rs`, which compares the JIT against
`jit/src/bpf_vm.rs` — a reference written in the same change, from the same
reading of the spec.

The oracle is a local fork of qmonnet/rbpf v0.4.1 at
`/Volumes/SSD/bs/xpost/rbpf`, reached from this manifest as
`../../../xpost/rbpf`. It is a **fork**, not upstream: it carries an MCU ABI and
a tightened memory-window check. Its interpreter's arithmetic and jump paths
are upstream's.

## Run

```sh
cargo test --manifest-path jit/oracle/Cargo.toml --release -- --nocapture
```

`build.rs` compiles the eight `tests/xdp/*.c` programs with clang
(`/opt/homebrew/opt/llvm/bin/clang`, override with `CLANG`). The test writes
`jit/oracle/results.json` and exits non-zero if any case fails.

Rerunnable levers:

```sh
python3 -I jit/oracle/summarize.py jit/oracle/results.json
python3 -I jit/oracle/query.py jit/oracle/results.json just_drop 3 pass
cargo run --manifest-path jit/oracle/Cargo.toml --release --example dump -- firewall
cargo run --manifest-path jit/oracle/Cargo.toml --release --example fuzzcase -- 428
cargo run --manifest-path jit/oracle/Cargo.toml --release --example modzero
```

`summarize.py` groups every case by status and blame. `query.py` prints one
case's traces, ctx patches and stack patches. `dump` prints the linked RV32
image and both helper traces. `fuzzcase` reproduces one random seed and shows
which scratch words differ. `modzero` attributes random failures to the open
ALU32 mod/div-by-zero question (see `NOTES.md` F2).

## Current result

Measured on this host, 8727 cases, `--release`:

| status | count |
| --- | --- |
| pass | 8199 |
| fail | 27 |
| inconclusive | 0 |
| unsupported | 501 |

The suite is **red**, and it should be. All 27 failures are one unresolved
semantic disagreement: ALU32 mod/div by zero and the destination's high 32
bits. 12 are boundary probes, 15 are random seeds. `modzero` proves the 15
random ones are the same question, not a memory bug. See `NOTES.md` F2.

The default test profile enables overflow checks, which makes rbpf's `NEG64`
panic on `i64::MIN`. Those 22 cases are unsupported there and pass under
`--release`: 8177 pass / 27 fail / 0 inconclusive / 523 unsupported. The fail
count is 27 either way.

## What is compared

For every case, five observables:

1. return value / XDP action,
2. the full packet bytes,
3. map descriptor and storage bytes,
4. the ordered helper trace `(id, arg1..arg5)` and return,
5. termination status (exit, fault, refused, panic).

A case where both engines fault is **inconclusive**, never a pass. That line is
copied from `jit/src/check.rs` and kept.

## How the two engines share memory

The JIT addresses a flat buffer with 32-bit offsets, which is what the firmware
does. rbpf addresses a buffer of the same shape with real 64-bit host pointers.
Helper arguments are normalized back to offsets before the traces are compared,
so the traces are directly comparable.

**The map model is shared by construction.** The rbpf helpers call
`xpost_jit::dispatch`, the same function the RV32 interpreter calls. Map
semantics are therefore identical on both sides and are *not* under test. This
isolates the translation. It also means a bug inside `dispatch` is invisible
here.

The map model is the one from `jit/src/check.rs`: every map is an ARRAY of 256
eight-byte values, whatever the object's `.maps` section declares. A HASH program
such as `firewall` meets array semantics on both sides.

### The ctx adaptation, and why it is unavoidable

Clang emits `w1 = *(u32 *)(r1 + 0)` for `ctx->data`, then uses that
zero-extended u32 as an address. On the ESP32-C3 and in the JIT's flat model an
address fits in 32 bits. On this host it cannot: **macOS arm64 refuses every
fixed mapping below 4 GiB**. Measured with `mmap(MAP_FIXED)` at `0x10000`,
`0x10000000`, `0x80000000` and `0xf0000000`, all `ENOMEM`, both inside and
outside the tool sandbox. So no real packet buffer has an address the program
could reach through a u32.

The Linux verifier resolves the same mismatch by rewriting the ctx access into
a pointer-sized load. `src/ctx.rs` does that, and nothing else, **on the rbpf
side only**. The JIT always runs the untouched Clang bytes.

A must-taint analysis finds the loads whose base is provably the ctx pointer on
every path. This matters: `firewall` reads `*(u32 *)(r1 + 0)` twice, once from
the ctx and once from a map value after a helper call. Matching on the register
number alone would patch the wrong instruction. `bsort` reads `ctx->data_end`
again at pc 13, so a "first three instructions" heuristic would also be wrong.

Every patch is recorded per case in `results.json` under `ctx_patches`. The
rbpf-side ctx is 48 bytes of u64 fields; offsets are doubled, and only the three
pointer fields are widened.

### The stack adaptation

The BPF stack has the same problem as the ctx, and it is not optional. A program
that builds a map key on the stack passes `r10 - k` to the helper. The JIT's
`r10` is a model offset (`0x2ffb0`), so `dispatch` reads the key from the flat
buffer. rbpf's `r10` is a real host heap address, which `dispatch` cannot index
with a u32. Before this adaptation every stack-keyed lookup silently missed.

The fork's `mcu` ABI takes the stack from the caller
(`EbpfVmMbuff::execute_program_mcu`), so the harness owns the buffer and its
window is known by construction rather than inferred from an allocator address.
`bridge_call` relocates each argument that falls in that window to
`MODEL_FP - 512 + (arg - stack_host)`, and copies the stack bytes into the model
before `dispatch` runs, so both engines read the same key. Every relocation is
recorded per case under `stack_patches` as `{call, arg, host, model}`.

An argument that is wider than 32 bits, is an address argument of a map helper,
and falls in no known window is a harness error, not a guess. The case becomes
**inconclusive** with blame `oracle-harness` and the offending value in the
detail. Scalars are still truncated to 32 bits, which is what the JIT's helper
ABI does.

`MODEL_FP` is verified, not assumed: `jit_frame_pointer` runs
`mov64 r1, r10; call 6` through the JIT and compares the reported frame pointer
against the constant. A prologue change fails loudly instead of misaligning the
two stacks.

The stack window `[MODEL_FP-512, MODEL_FP)` is also a compared region, so a
wrong JIT stack offset is now observable. The JIT's saved registers and scratch
words live above `MODEL_FP`, outside it.

Under `mcu`, `register_allowed_memory` and `register_helper` are inert;
permission comes from `McuEnv::check_access` and helpers from
`McuEnv::call_helper`. The harness registers the flat world and the ctx buffer
as the allowed windows. `execute_inner` is shared with the host path, so the
arithmetic and jump semantics under test are unchanged.

### The helper trace on the JIT side

`xpost_jit::run_rv` hardwires helper interception to `host_abi::dispatch` and
exposes no hook, so it cannot report a trace. `src/rv.rs` is an oracle-local
RV32IM executor that records one. **Every case runs both executors** and requires
the same return value and the same final memory. A divergence is recorded as
`executor_split` and makes the case inconclusive. There were zero splits across
all 8727 cases, which is what licenses using the tracing executor's trace.

## Four-way split of claims

### Proven by differential test against an independent interpreter

- ALU32 and ALU64 `add, sub, mul, div, or, and, lsh, rsh, neg, mod, xor, mov,
  arsh` over `0, 1, -1, 0x80000000, 0x7fffffff, i64::MIN, i64::MAX,
  0xffffffff80000000`, register and immediate forms, with the full 64-bit
  destination compared so ALU32 zero-extension is checked.
- Shift counts `0, 1, 31, 32, 33, 63, 64, 65` for `lsh, rsh, arsh`, both widths
  and both source forms.
- All eleven conditional jumps, `jmp64` and `jmp32`, register form, over the same
  value set. Immediate form is proven for non-negative immediates and for the
  signed comparisons; see the rbpf gap below.
- `le`/`be` at 16, 32 and 64 bits in the ALU32 class.
- Byte, half, word and double-word loads and stores at offsets `0,1,2,3,4,7,8,15`,
  including unaligned addresses.
- 1964 seeded random programs over the supported set, with forward conditional
  jumps, comparing the return value and all nine saved registers.
- All fourteen program-level cases on real Clang ELF, including `div2`,
  `bitswap`, `bsort`, `firewall` and the three stack-keyed map programs, on the
  `check-xdp.sh` packets and the extra inputs.
- 24 negative cases: the JIT returns `Err` and does not panic on ALU64 div/mod,
  ALU64 bswap, atomics, tail calls, BPF-to-BPF calls, `jmp32` control flow,
  `ld_abs`/`ld_ind`, unknown opcodes, truncated and malformed `lddw`, empty
  input, and out-of-range registers.

### Proven by symbolic argument, not by execution

- The ctx adaptation preserves semantics: it changes only the width and offset
  of loads whose base is provably the ctx pointer, which is the kernel's own
  rewrite. The patch list is in `results.json` for audit.
- The tracing executor is faithful *for these cases*, because it agreed with
  `run_rv` on the return value and the whole memory every time. This is an
  empirical agreement over 8727 cases, not a proof about all inputs.
- rbpf's `JGT_IMM` zero-extends the same i32 field that its own `JSGT_IMM` and
  every `ALU64_IMM` sign-extend. Both cannot be right; the ISA defines `imm` as
  signed. This pins the blame without needing a third implementation.

### Assumed from the eBPF verifier, not checked here

- `R1..R5` are unreadable after a helper call.
- `R0` is assigned before `exit`.
- The two words of an `lddw` are paired.
- `r10` is never written. The JIT accepts a write to `r10`; it documents that it
  assumes verifier-checked input, so this is recorded as an observation
  (`negative/observe/write-r10`), not a defect.
- Program termination. The generated random programs only jump forward, so they
  terminate by construction; real program termination is the verifier's job.

### Not covered

- **Map semantics.** Shared by construction, as above. A `dispatch` bug is
  invisible to this crate.
- **HASH maps.** Every map is modeled as an ARRAY.
- **The firmware.** Nothing here runs on an ESP32-C3. The RV32 image is executed
  by an interpreter, not by silicon, and the Compact ELF V0 container, slot
  capacity, linker script and `helper_dispatcher` address are not exercised.
- **`host_abi::HELPER = 0x4038_0000`.** The RV32 interpreter forwards *any*
  helper address to the host model, so a wrong address cannot show up here.
- **ALU64 div/mod and ALU64 bswap.** The JIT rejects them; 416 cases are
  recorded unsupported.
- **SDIV/SMOD.** rbpf has no signed div/mod, so these 40 cases have no
  independent oracle.
- **The 27 ALU32 mod/div-by-zero cases.** Unresolved; see `NOTES.md` F2. The
  `modzero` example attributes every random failure to this one rule.
- **Stack depth.** The JIT fixes the BPF stack at 512 bytes and does not read the
  verifier's `stack_depth`.

## Known rbpf gaps

Each is declared in `run::oracle_gap` from code evidence, never inferred from a
disagreement, and the disagreement is still recorded in full.

| gap | cases | evidence |
| --- | --- | --- |
| JMP64 immediates zero-extended | 44 | `interpreter.rs:324` `unsigned_u64!` vs `:604` `JSGT_IMM` |
| no SDIV/SMOD | 40 | the ALU block never reads `insn.off` |
| `NEG64` panics on `i64::MIN` | 22 | `interpreter.rs:573` `-(reg as i64)`; `NEG32` at `:524` uses `wrapping_neg` |

The `NEG64` panic only fires under overflow checks, which the default test
profile enables and `--release` does not. It is caught and recorded, never
allowed to abort the suite. The 22 cases are unsupported in the default profile
and pass under `--release`; no other case changes status between the two.
