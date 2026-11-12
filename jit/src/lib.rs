//! Userspace eBPF → RV32IM compiler.
//!
//! The host process runs on the Mac. It does not execute the RV32 image.
//! Output is a flat instruction stream plus relocations. `link` patches helper
//! calls and map `lddw`s. A call or `lddw` left unpatched is not executable.
//! BPF-to-BPF calls are rejected.
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
//! - A helper call moves the low 32 bits of R1..R5 into `a1`..`a5`, puts the
//!   helper id in `a0`, then `lui t1; jalr ra, t1`. `link` fills in
//!   `helper_dispatcher`. The return in `a0` is zero-extended into R0.
//! - An unlinked `lddw` is four words: `lui`/`addi` for `lo`, then `hi`.
//! - ALU64 `div`/`mod`, atomics, and tail calls are rejected.
//! - RV32M `div` is not eBPF's div-by-zero. ALU32 div/mod branch around a zero
//!   divisor: div becomes 0, mod leaves the destination unchanged.

#![forbid(unsafe_code)]

mod bpf;
mod bpf_vm;
mod check;
mod compile;
mod host_abi;
mod load;
mod matrix;
mod rv;
mod rv_vm;

pub mod isa {
    pub use crate::bpf::*;
}

pub use bpf::{decode_insns, Insn};
pub use bpf_vm::execute;
pub use check::{check_packet, compare, Report};
pub use compile::{compile, frame_bytes, link, Image, JitError, LinkIn, Reloc, RelocKind};
pub use host_abi::{dispatch, write_map, HELPER, KIND_ARRAY, KIND_HASH, MAP_MAGIC};
pub use load::{load_bpf, LoadError, Source};
pub use matrix::json as support_json;
pub use rv::disassemble;
pub use rv_vm::{run as run_rv, Stop};
