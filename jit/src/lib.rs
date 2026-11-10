//! Userspace eBPF → RV32IM compiler.
//!
//! The host process runs on the Mac. It does not execute the RV32 image.
//! Output is a flat instruction stream plus relocations. Nothing is linked:
//! helper calls and non-immediate `lddw`s keep a fixed instruction shape and a
//! side record.
//!
//! Register pairing follows Jitterbug's RV32 JIT (Linux `bpf_jit_comp32`):
//! each BPF register is a `(hi, lo)` pair. RV32IMC can execute this encoding.
//! The compiler emits RV32IM only: no RVC, no F/D, and no A.
//!
//! Assumptions, each with a gap:
//! - BPF stack is fixed at 512 bytes. The verifier's real `stack_depth` is not
//!   an input yet.
//! - ALU32 results zero-extend into the high half (`verifier_zext` is off).
//! - Program entry matches the Linux RV32 prologue: `a0` is `lo(R1)`, `hi(R1)`
//!   is cleared. Exit returns `R0` in `a0`/`a1`. That is not the firmware
//!   ilp32 helper ABI.
//! - A call is `lui t1, 0; jalr ra, t1, 0` (8 bytes). The linker patches those
//!   two words with an absolute address. `R5` is stored at `0(sp)` as in
//!   Jitterbug, because `R1`–`R4` already occupy `a0`–`a7`.
//! - An unlinked `lddw` is four words: `lui`/`addi` for `lo`, then `hi`.
//! - ALU64 `div`/`mod`, atomics, and tail calls are rejected.
//! - RV32M `div` is not eBPF's div-by-zero. ALU32 div/mod branch around a zero
//!   divisor: div becomes 0, mod leaves the destination unchanged.

#![forbid(unsafe_code)]

mod bpf;
mod compile;
mod load;
mod rv;

pub mod isa {
    pub use crate::bpf::*;
}

pub use bpf::{decode_insns, Insn};
pub use compile::{compile, Image, JitError, Reloc, RelocKind};
pub use load::{load_bpf, LoadError, Source};
pub use rv::disassemble;
