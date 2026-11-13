//! Host adaptation of the `xdp_md` pointer loads, for the rbpf side only.
//!
//! Clang emits `w1 = *(u32 *)(r1 + 0)` for `ctx->data`. The program then uses
//! that zero-extended u32 as an address. On the ESP32-C3 and in the JIT's flat
//! host model an address fits in 32 bits, so this works. On a 64-bit host it
//! cannot: macOS arm64 refuses every mapping below 4 GiB (measured, see
//! README), so no real packet buffer has an address the program could reach
//! through a u32.
//!
//! The Linux verifier resolves the same mismatch by rewriting the ctx access
//! into a pointer-sized load. This module does that, and nothing else. The JIT
//! side always runs the untouched Clang bytes.
//!
//! A must-taint analysis finds the loads whose base is provably the ctx
//! pointer on every path. `firewall` reads `*(u32 *)(r1 + 0)` twice, once from
//! the ctx and once from a map value after a helper call, so matching on the
//! register number alone would patch the wrong instruction.

use xpost_jit::isa::*;
use xpost_jit::Insn;

#[derive(Clone, Copy, Debug)]
pub struct Patch {
    pub pc: usize,
    pub old_off: i16,
    pub new_off: i16,
    pub widened: bool,
}

pub struct Adapted {
    pub insns: Vec<Insn>,
    pub patched: Vec<Patch>,
}

type Taint = [bool; 11];

const TOP: Taint = [true; 11];

fn entry() -> Taint {
    let mut t = [false; 11];
    t[1] = true;
    t
}

fn is_lddw(i: Insn) -> bool {
    i.class() == CLASS_LD && i.size() == SIZE_DW && i.mode() == MODE_IMM
}

/// Successors, plus the register the instruction writes, if any.
fn succs(insns: &[Insn], pc: usize) -> Vec<usize> {
    let i = insns[pc];
    let next = if is_lddw(i) { pc + 2 } else { pc + 1 };
    match i.class() {
        CLASS_JMP | CLASS_JMP32 => match i.op() {
            JMP_EXIT => vec![],
            JMP_JA => vec![(next as i32 + i.off as i32) as usize],
            JMP_CALL => vec![next],
            _ => vec![next, (next as i32 + i.off as i32) as usize],
        },
        _ => vec![next],
    }
}

fn transfer(t: &Taint, i: Insn) -> Taint {
    let mut out = *t;
    match i.class() {
        CLASS_ALU | CLASS_ALU64 => {
            out[i.dst as usize] = i.op() == ALU_MOV && i.src_is_reg() && t[i.src as usize];
        }
        CLASS_LDX | CLASS_LD => out[i.dst as usize] = false,
        CLASS_JMP | CLASS_JMP32 => {
            if i.op() == JMP_CALL {
                for r in 0..=5 {
                    out[r] = false;
                }
            }
        }
        _ => {}
    }
    out
}

pub fn adapt(insns: &[Insn]) -> Result<Adapted, String> {
    let n = insns.len();
    let mut wide = vec![false; n];
    let mut pc = 0;
    while pc < n {
        if is_lddw(insns[pc]) {
            if pc + 1 >= n {
                return Err(format!("lddw at {pc} is truncated"));
            }
            wide[pc + 1] = true;
            pc += 2;
        } else {
            pc += 1;
        }
    }

    let mut reachable = vec![false; n];
    let mut stack = vec![0usize];
    while let Some(pc) = stack.pop() {
        if pc >= n || reachable[pc] || wide[pc] {
            continue;
        }
        reachable[pc] = true;
        for s in succs(insns, pc) {
            if s >= n {
                return Err(format!("jump at {pc} leaves the program"));
            }
            stack.push(s);
        }
    }

    let mut state = vec![TOP; n];
    state[0] = entry();
    loop {
        let mut changed = false;
        for pc in 0..n {
            if !reachable[pc] || wide[pc] {
                continue;
            }
            let out = transfer(&state[pc], insns[pc]);
            for s in succs(insns, pc) {
                for r in 0..11 {
                    if state[s][r] && !out[r] {
                        state[s][r] = false;
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }

    let mut out = insns.to_vec();
    let mut patched = Vec::new();
    for pc in 0..n {
        if !reachable[pc] || wide[pc] {
            continue;
        }
        let i = insns[pc];
        let base_is_ctx = match i.class() {
            CLASS_LDX => state[pc][i.src as usize],
            CLASS_ST | CLASS_STX => state[pc][i.dst as usize],
            _ => false,
        };
        if !base_is_ctx {
            continue;
        }
        if i.class() != CLASS_LDX || i.mode() != MODE_MEM {
            return Err(format!("insn {pc} writes or oddly reads the ctx"));
        }
        let widened = match (i.size(), i.off) {
            (SIZE_W, 0) | (SIZE_W, 4) | (SIZE_W, 8) => true,
            (SIZE_W, 12) | (SIZE_W, 16) | (SIZE_W, 20) => false,
            _ => {
                return Err(format!(
                    "insn {pc} reads ctx off {} at size {:#x}",
                    i.off,
                    i.size()
                ))
            }
        };
        let new_off = i.off * 2;
        out[pc] = Insn {
            code: if widened {
                CLASS_LDX | SIZE_DW | MODE_MEM
            } else {
                i.code
            },
            off: new_off,
            ..i
        };
        patched.push(Patch {
            pc,
            old_off: i.off,
            new_off,
            widened,
        });
    }
    if patched.is_empty() {
        return Err("no ctx access found; the program does not match the XDP shape".into());
    }
    Ok(Adapted {
        insns: out,
        patched,
    })
}
