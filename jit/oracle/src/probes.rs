//! Instruction-level boundary probes.
//!
//! These are instruction probes, not program-level tests, so they are built
//! directly as eBPF words. Every probe saves the scratch base in `r9`, computes
//! into `r0`/`r1`, then stores both so a clobbered register is observable even
//! when the return value happens to match.

use xpost_jit::isa::*;
use xpost_jit::Insn;

pub struct Probe {
    pub name: String,
    pub insns: Vec<Insn>,
}

pub const SCRATCH: usize = 128;

/// Values that straddle the 32-bit and 64-bit signed/unsigned edges.
pub const WIDE: &[u64] = &[
    0,
    1,
    u64::MAX,
    0x8000_0000,
    0x7fff_ffff,
    i64::MIN as u64,
    i64::MAX as u64,
    0xffff_ffff_8000_0000,
];

/// Immediates are sign-extended i32, so a 64-bit edge cannot be an immediate.
pub const NARROW: &[i32] = &[0, 1, -1, i32::MIN, i32::MAX, 2, -2];

pub const SHIFTS: &[i32] = &[0, 1, 31, 32, 33, 63, 64, 65];

fn insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
    Insn {
        code,
        dst,
        src,
        off,
        imm,
    }
}

fn mov64(dst: u8, src: u8) -> Insn {
    insn(CLASS_ALU64 | ALU_MOV | SRC_X, dst, src, 0, 0)
}

fn lddw(dst: u8, v: u64) -> [Insn; 2] {
    [
        insn(CLASS_LD | SIZE_DW | MODE_IMM, dst, 0, 0, v as u32 as i32),
        insn(0, 0, 0, 0, (v >> 32) as u32 as i32),
    ]
}

fn stxdw(dst: u8, src: u8, off: i16) -> Insn {
    insn(CLASS_STX | SIZE_DW | MODE_MEM, dst, src, off, 0)
}

fn exit() -> Insn {
    insn(CLASS_JMP | JMP_EXIT, 0, 0, 0, 0)
}

fn head(a: u64, b: u64) -> Vec<Insn> {
    let mut v = vec![mov64(9, 1)];
    v.extend(lddw(0, a));
    v.extend(lddw(1, b));
    v
}

fn tail() -> Vec<Insn> {
    vec![stxdw(9, 0, 0), stxdw(9, 1, 8), exit()]
}

const BINARY: &[(&str, u8)] = &[
    ("add", ALU_ADD),
    ("sub", ALU_SUB),
    ("mul", ALU_MUL),
    ("div", ALU_DIV),
    ("or", ALU_OR),
    ("and", ALU_AND),
    ("lsh", ALU_LSH),
    ("rsh", ALU_RSH),
    ("mod", ALU_MOD),
    ("xor", ALU_XOR),
    ("mov", ALU_MOV),
    ("arsh", ALU_ARSH),
];

const CONDS: &[(&str, u8)] = &[
    ("jeq", JMP_JEQ),
    ("jgt", JMP_JGT),
    ("jge", JMP_JGE),
    ("jset", JMP_JSET),
    ("jne", JMP_JNE),
    ("jsgt", JMP_JSGT),
    ("jsge", JMP_JSGE),
    ("jlt", JMP_JLT),
    ("jle", JMP_JLE),
    ("jslt", JMP_JSLT),
    ("jsle", JMP_JSLE),
];

pub fn alu() -> Vec<Probe> {
    let mut out = Vec::new();
    for (wname, class) in [("alu32", CLASS_ALU), ("alu64", CLASS_ALU64)] {
        for (opname, op) in BINARY {
            for a in WIDE {
                for b in WIDE {
                    let mut ins = head(*a, *b);
                    ins.push(insn(class | op | SRC_X, 0, 1, 0, 0));
                    ins.extend(tail());
                    out.push(Probe {
                        name: format!("{wname}/{opname}/x/{a:#x}/{b:#x}"),
                        insns: ins,
                    });
                }
                for b in NARROW {
                    let mut ins = head(*a, *b as u64);
                    ins.push(insn(class | op | SRC_K, 0, 0, 0, *b));
                    ins.extend(tail());
                    out.push(Probe {
                        name: format!("{wname}/{opname}/k/{a:#x}/{b}"),
                        insns: ins,
                    });
                }
            }
        }
        for a in WIDE {
            let mut ins = head(*a, 0);
            ins.push(insn(class | ALU_NEG, 0, 0, 0, 0));
            ins.extend(tail());
            out.push(Probe {
                name: format!("{wname}/neg/{a:#x}"),
                insns: ins,
            });
        }
        for (ename, src) in [("le", SRC_K), ("be", SRC_X)] {
            for bits in [16i32, 32, 64] {
                for a in WIDE {
                    let mut ins = head(*a, 0);
                    ins.push(insn(class | ALU_END | src, 0, 0, 0, bits));
                    ins.extend(tail());
                    out.push(Probe {
                        name: format!("{wname}/{ename}{bits}/{a:#x}"),
                        insns: ins,
                    });
                }
            }
        }
        for (sname, op) in [("sdiv", ALU_DIV), ("smod", ALU_MOD)] {
            for a in WIDE {
                for b in WIDE {
                    let mut ins = head(*a, *b);
                    ins.push(insn(class | op | SRC_X, 0, 1, 1, 0));
                    ins.extend(tail());
                    out.push(Probe {
                        name: format!("{wname}/{sname}/x/{a:#x}/{b:#x}"),
                        insns: ins,
                    });
                }
            }
        }
    }
    out
}

pub fn shifts() -> Vec<Probe> {
    let mut out = Vec::new();
    for (wname, class) in [("alu32", CLASS_ALU), ("alu64", CLASS_ALU64)] {
        for (opname, op) in [("lsh", ALU_LSH), ("rsh", ALU_RSH), ("arsh", ALU_ARSH)] {
            for count in SHIFTS {
                for a in WIDE {
                    let mut ins = head(*a, *count as u64);
                    ins.push(insn(class | op | SRC_X, 0, 1, 0, 0));
                    ins.extend(tail());
                    out.push(Probe {
                        name: format!("{wname}/{opname}/x/count{count}/{a:#x}"),
                        insns: ins,
                    });
                    let mut ins = head(*a, 0);
                    ins.push(insn(class | op | SRC_K, 0, 0, 0, *count));
                    ins.extend(tail());
                    out.push(Probe {
                        name: format!("{wname}/{opname}/k/count{count}/{a:#x}"),
                        insns: ins,
                    });
                }
            }
        }
    }
    out
}

pub fn jumps() -> Vec<Probe> {
    let mut out = Vec::new();
    for (wname, class) in [("jmp64", CLASS_JMP), ("jmp32", CLASS_JMP32)] {
        for (opname, op) in CONDS {
            for a in WIDE {
                for b in WIDE {
                    out.push(cond_probe(wname, class, opname, *op, SRC_X, *a, *b, 0));
                }
                for b in NARROW {
                    out.push(cond_probe(
                        wname, class, opname, *op, SRC_K, *a, *b as u64, *b,
                    ));
                }
            }
        }
    }
    out
}

fn cond_probe(
    wname: &str,
    class: u8,
    opname: &str,
    op: u8,
    src: u8,
    a: u64,
    b: u64,
    imm: i32,
) -> Probe {
    let mut ins = head(a, b);
    ins.push(insn(CLASS_ALU64 | ALU_MOV | SRC_K, 2, 0, 0, 0));
    let at = ins.len();
    ins.push(insn(class | op | src, 0, 1, 1, imm));
    ins.push(insn(CLASS_JMP | JMP_JA, 0, 0, 1, 0));
    ins.push(insn(CLASS_ALU64 | ALU_MOV | SRC_K, 2, 0, 0, 1));
    let _ = at;
    ins.push(stxdw(9, 2, 0));
    ins.push(stxdw(9, 0, 8));
    ins.push(stxdw(9, 1, 16));
    ins.push(mov64(0, 2));
    ins.push(exit());
    let s = if src == SRC_X { "x" } else { "k" };
    Probe {
        name: format!("{wname}/{opname}/{s}/{a:#x}/{b:#x}"),
        insns: ins,
    }
}

/// Load and store widths against the scratch base, which needs no ctx.
pub fn memory() -> Vec<Probe> {
    let mut out = Vec::new();
    for (sname, size) in [("b", SIZE_B), ("h", SIZE_H), ("w", SIZE_W), ("dw", SIZE_DW)] {
        for off in [0i16, 1, 2, 3, 4, 7, 8, 15] {
            let mut ins = vec![mov64(9, 1)];
            ins.extend(lddw(0, 0x0123_4567_89ab_cdef));
            ins.push(stxdw(9, 0, 64));
            ins.push(insn(CLASS_STX | size | MODE_MEM, 9, 0, off, 0));
            ins.push(insn(CLASS_LDX | size | MODE_MEM, 2, 9, off, 0));
            ins.push(stxdw(9, 2, 72));
            ins.push(mov64(0, 2));
            ins.push(exit());
            out.push(Probe {
                name: format!("mem/{sname}/off{off}"),
                insns: ins,
            });
        }
    }
    out
}

pub fn all() -> Vec<Probe> {
    let mut v = alu();
    v.extend(shifts());
    v.extend(jumps());
    v.extend(memory());
    v
}
