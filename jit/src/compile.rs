//! Jitterbug-style RV32 lowering. Calls and non-constant `lddw`s are not linked.

use std::collections::HashMap;
use std::fmt;

use crate::bpf::*;
use crate::rv::*;

const BPF_STACK: i32 = 512;
const SAVED: i32 = 9;
const SCRATCH_WORDS: i32 = 10;
const MAX_TAIL_CALLS: i32 = 33;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelocKind {
    /// Helper call. Patch 8 bytes: `lui t1, hi; jalr ra, t1, lo`.
    Call,
    /// BPF-to-BPF call (`src == BPF_PSEUDO_CALL`). Same 8-byte shape, not resolved.
    Func,
    /// Map / subprog / other pseudo `lddw`. Patch 16 bytes: `lui`+`addi` for
    /// `lo`, then the same pair for `hi`.
    Lddw,
}

impl RelocKind {
    fn as_str(self) -> &'static str {
        match self {
            RelocKind::Call => "call",
            RelocKind::Func => "func",
            RelocKind::Lddw => "lddw",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reloc {
    pub kind: RelocKind,
    pub rv_off: u32,
    pub bpf_pc: u32,
    pub src_reg: u8,
    pub imm: i32,
    pub symbol: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Image {
    pub code: Vec<u32>,
    pub relocs: Vec<Reloc>,
}

impl Image {
    pub fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.code.len() * 4);
        for word in &self.code {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out
    }

    pub fn reloc_text(&self) -> String {
        let mut out = String::from(
            "# unlinked\n\
             # call/func at rv_off: 8 bytes, lui t1,hi ; jalr ra,t1,lo (absolute address)\n\
             # lddw at rv_off: 16 bytes, lui/addi lo then lui/addi hi\n\
             # kind rv_off bpf_pc src imm symbol\n",
        );
        for r in &self.relocs {
            let sym = r.symbol.as_deref().unwrap_or("-");
            out.push_str(&format!(
                "{} {:#x} {} {} {} {}\n",
                r.kind.as_str(),
                r.rv_off,
                r.bpf_pc,
                r.src_reg,
                r.imm,
                sym
            ));
        }
        out
    }
}

#[derive(Debug)]
pub enum JitError {
    Empty,
    BadReg {
        pc: usize,
        reg: u8,
    },
    TruncatedLddw {
        pc: usize,
    },
    BadTarget {
        pc: usize,
        target: i32,
    },
    /// Second word of `lddw` is not the reserved zero word from RFC 9669.
    BadLddw {
        pc: usize,
    },
    /// A branch lands on the second word of an `lddw`.
    LddwMiddle {
        pc: usize,
        target: usize,
    },
    Unresolved {
        what: &'static str,
        detail: String,
    },
    Unsupported {
        pc: usize,
        code: u8,
        what: &'static str,
    },
}

impl fmt::Display for JitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JitError::Empty => write!(f, "eBPF program is empty"),
            JitError::BadReg { pc, reg } => {
                write!(f, "bpf pc {pc}: register {reg} is out of range")
            }
            JitError::TruncatedLddw { pc } => {
                write!(f, "bpf pc {pc}: lddw is missing its second word")
            }
            JitError::BadTarget { pc, target } => {
                write!(
                    f,
                    "bpf pc {pc}: branch target {target} is outside the program"
                )
            }
            JitError::BadLddw { pc } => {
                write!(f, "bpf pc {pc}: lddw second word is not reserved-zero")
            }
            JitError::LddwMiddle { pc, target } => {
                write!(
                    f,
                    "bpf pc {pc}: branch target {target} is the second word of lddw"
                )
            }
            JitError::Unresolved { what, detail } => {
                write!(f, "unresolved {what}: {detail}")
            }
            JitError::Unsupported { pc, code, what } => {
                write!(f, "bpf pc {pc}: unsupported {what} (opcode {code:#x})")
            }
        }
    }
}

impl std::error::Error for JitError {}

#[derive(Clone, Copy)]
struct Slot {
    hi: i16,
    lo: i16,
}

#[derive(Clone, Copy)]
struct Live {
    hi: u8,
    lo: u8,
}

const TMP1: Live = Live { hi: T3, lo: T2 };
const TMP2: Live = Live { hi: T5, lo: T4 };

struct Fixup {
    at: usize,
    target_pc: usize,
    rd: u8,
}

struct Ctx<'a> {
    code: Vec<u32>,
    fixups: Vec<Fixup>,
    relocs: Vec<Reloc>,
    symbols: &'a HashMap<u64, String>,
    /// True when this eBPF slot is the second word of an `lddw`.
    wide_hi: Vec<bool>,
}

pub fn frame_bytes() -> u32 {
    stack_adjust() as u32
}

pub fn compile(insns: &[Insn], symbols: &HashMap<u64, String>) -> Result<Image, JitError> {
    if insns.is_empty() {
        return Err(JitError::Empty);
    }
    let wide_hi = wide_high_slots(insns)?;
    let mut ctx = Ctx {
        code: Vec::with_capacity(insns.len() * 8),
        fixups: Vec::new(),
        relocs: Vec::new(),
        symbols,
        wide_hi,
    };
    emit_prologue(&mut ctx.code);
    let mut rv_at = vec![0usize; insns.len() + 1];
    let mut pc = 0;
    while pc < insns.len() {
        rv_at[pc] = ctx.code.len();
        let step = emit_insn(&mut ctx, insns, pc)?;
        if step == 2 {
            rv_at[pc + 1] = ctx.code.len();
        }
        pc += step;
    }
    rv_at[insns.len()] = ctx.code.len();
    emit_epilogue(&mut ctx.code);
    for f in &ctx.fixups {
        let dest = rv_at[f.target_pc];
        let byte_off = (dest as i32 - f.at as i32) * 4;
        let (hi, lo) = split_pc_rel(byte_off);
        ctx.code[f.at] = auipc(T1, hi);
        ctx.code[f.at + 1] = jalr(f.rd, T1, lo);
    }
    Ok(Image {
        code: ctx.code,
        relocs: ctx.relocs,
    })
}

fn stack_adjust() -> i32 {
    let raw = SAVED * 4 + SCRATCH_WORDS * 4 + BPF_STACK;
    (raw + 15) & !15
}

fn stack_off(k: i32) -> i16 {
    (-4 - 4 * SAVED - 4 * k) as i16
}

fn bpf_slot(reg: u8) -> Slot {
    match reg {
        0 => Slot {
            hi: S2 as i16,
            lo: S1 as i16,
        },
        1 => Slot {
            hi: A1 as i16,
            lo: A0 as i16,
        },
        2 => Slot {
            hi: A3 as i16,
            lo: A2 as i16,
        },
        3 => Slot {
            hi: A5 as i16,
            lo: A4 as i16,
        },
        4 => Slot {
            hi: A7 as i16,
            lo: A6 as i16,
        },
        5 => Slot {
            hi: S4 as i16,
            lo: S3 as i16,
        },
        6 => Slot {
            hi: stack_off(0),
            lo: stack_off(1),
        },
        7 => Slot {
            hi: stack_off(2),
            lo: stack_off(3),
        },
        8 => Slot {
            hi: stack_off(4),
            lo: stack_off(5),
        },
        9 => Slot {
            hi: stack_off(6),
            lo: stack_off(7),
        },
        REG_FP => Slot {
            hi: S6 as i16,
            lo: S5 as i16,
        },
        _ => unreachable!("register checked before bpf_slot"),
    }
}

fn check_reg(pc: usize, reg: u8) -> Result<(), JitError> {
    if reg > REG_FP {
        Err(JitError::BadReg { pc, reg })
    } else {
        Ok(())
    }
}

fn is_lddw(insn: Insn) -> bool {
    insn.class() == CLASS_LD && insn.size() == SIZE_DW && insn.mode() == MODE_IMM
}

/// RFC 9669 wide encoding: the second word keeps opcode, regs, and offset at zero.
fn check_lddw_second(pc: usize, next: Insn) -> Result<(), JitError> {
    if next.code == 0 && next.dst == 0 && next.src == 0 && next.off == 0 {
        Ok(())
    } else {
        Err(JitError::BadLddw { pc })
    }
}

fn wide_high_slots(insns: &[Insn]) -> Result<Vec<bool>, JitError> {
    let mut hi = vec![false; insns.len()];
    let mut pc = 0;
    while pc < insns.len() {
        if is_lddw(insns[pc]) {
            let next = insns.get(pc + 1).copied().ok_or(JitError::TruncatedLddw { pc })?;
            check_lddw_second(pc, next)?;
            hi[pc + 1] = true;
            pc += 2;
        } else {
            pc += 1;
        }
    }
    Ok(hi)
}

fn known_alu(op: u8) -> bool {
    matches!(
        op,
        ALU_ADD
            | ALU_SUB
            | ALU_MUL
            | ALU_DIV
            | ALU_OR
            | ALU_AND
            | ALU_LSH
            | ALU_RSH
            | ALU_NEG
            | ALU_MOD
            | ALU_XOR
            | ALU_MOV
            | ALU_ARSH
            | ALU_END
    )
}

fn emit_prologue(code: &mut Vec<u32>) {
    let adj = stack_adjust();
    code.push(addi(T6, ZERO, MAX_TAIL_CALLS));
    code.push(addi(SP, SP, -adj));
    for (i, r) in [RA, FP, S1, S2, S3, S4, S5, S6, S7].into_iter().enumerate() {
        code.push(sw(r, adj - 4 * (i as i32 + 1), SP));
    }
    code.push(addi(FP, SP, adj));
    // BPF fp is the high end of the 512-byte BPF stack. hi(R1) is cleared
    // because the host passes a 32-bit pointer in a0.
    code.push(addi(S5, SP, BPF_STACK));
    code.push(addi(S6, ZERO, 0));
    code.push(addi(A0, A0, 0));
    code.push(addi(A1, ZERO, 0));
}

fn emit_epilogue(code: &mut Vec<u32>) {
    let adj = stack_adjust();
    // R0 is (s2, s1). Copy it out before restoring s1/s2.
    code.push(addi(A0, S1, 0));
    code.push(addi(A1, S2, 0));
    for (i, r) in [RA, FP, S1, S2, S3, S4, S5, S6, S7].into_iter().enumerate() {
        code.push(lw(r, adj - 4 * (i as i32 + 1), SP));
    }
    code.push(addi(SP, SP, adj));
    code.push(jalr(ZERO, RA, 0));
}

fn emit_insn(ctx: &mut Ctx<'_>, insns: &[Insn], pc: usize) -> Result<usize, JitError> {
    let insn = insns[pc];
    let class = insn.class();
    match class {
        CLASS_ALU | CLASS_ALU64 => emit_alu(ctx, insn, pc, class == CLASS_ALU64),
        CLASS_JMP | CLASS_JMP32 => emit_jmp(ctx, insns, insn, pc, class == CLASS_JMP),
        CLASS_LD if insn.size() == SIZE_DW && insn.mode() == MODE_IMM => emit_lddw(ctx, insns, pc),
        CLASS_LDX if insn.mode() == MODE_MEM => emit_mem(ctx, insn, pc, false),
        CLASS_ST | CLASS_STX if insn.code == NOSPEC => Ok(1),
        CLASS_ST | CLASS_STX if insn.mode() == MODE_MEM => emit_mem(ctx, insn, pc, true),
        CLASS_ST | CLASS_STX if insn.mode() == MODE_ATOMIC => Err(JitError::Unsupported {
            pc,
            code: insn.code,
            what: "atomic (RV32IMC has no A)",
        }),
        _ => Err(JitError::Unsupported {
            pc,
            code: insn.code,
            what: "opcode",
        }),
    }
}

fn emit_lddw(ctx: &mut Ctx<'_>, insns: &[Insn], pc: usize) -> Result<usize, JitError> {
    let insn = insns[pc];
    check_reg(pc, insn.dst)?;
    let next = insns.get(pc + 1).copied().ok_or(JitError::TruncatedLddw { pc })?;
    check_lddw_second(pc, next)?;
    let dst = bpf_slot(insn.dst);
    let live = get64(&mut ctx.code, dst, TMP1);
    let symbol = ctx.symbols.get(&(pc as u64 * 8)).cloned();
    // Clang leaves src_reg at 0 and names the map only in the ELF relocation,
    // so the relocation is the identity. Testing src_reg alone turned every
    // map load into the constant 0 and each lookup then missed.
    if insn.src == 0 && symbol.is_none() {
        emit_imm(&mut ctx.code, live.lo, insn.imm);
        emit_imm(&mut ctx.code, live.hi, next.imm);
    } else {
        // Fixed four-word shape so a later link can patch the constant
        // without inserting instructions.
        let at = ctx.code.len();
        emit_imm64_fixed(&mut ctx.code, live, 0, 0);
        ctx.relocs.push(Reloc {
            kind: RelocKind::Lddw,
            rv_off: (at * 4) as u32,
            bpf_pc: pc as u32,
            src_reg: insn.src,
            imm: insn.imm,
            symbol,
        });
    }
    put64(&mut ctx.code, dst, live);
    Ok(2)
}

fn emit_imm64_fixed(code: &mut Vec<u32>, rd: Live, lo: i32, hi: i32) {
    let (hi0, lo0) = split_pc_rel(lo);
    code.push(lui(rd.lo, hi0));
    code.push(addi(rd.lo, rd.lo, lo0));
    let (hi1, lo1) = split_pc_rel(hi);
    code.push(lui(rd.hi, hi1));
    code.push(addi(rd.hi, rd.hi, lo1));
}

fn emit_alu(ctx: &mut Ctx<'_>, insn: Insn, pc: usize, is64: bool) -> Result<usize, JitError> {
    let op = insn.op();
    if op == ALU_END {
        if is64 {
            return Err(JitError::Unsupported {
                pc,
                code: insn.code,
                what: "alu64 bswap",
            });
        }
        check_reg(pc, insn.dst)?;
        emit_end(
            &mut ctx.code,
            bpf_slot(insn.dst),
            insn.imm,
            insn.src_is_reg(),
            pc,
        )?;
        return Ok(1);
    }
    check_reg(pc, insn.dst)?;
    if insn.src_is_reg() {
        check_reg(pc, insn.src)?;
    }
    if !known_alu(op) {
        return Err(JitError::Unsupported {
            pc,
            code: insn.code,
            what: "alu op",
        });
    }
    if is64 && matches!(op, ALU_DIV | ALU_MOD) {
        return Err(JitError::Unsupported {
            pc,
            code: insn.code,
            what: "alu64 div/mod",
        });
    }
    let dst = bpf_slot(insn.dst);
    if op == ALU_MOV && insn.src_is_reg() && insn.off != 0 {
        emit_movsx(&mut ctx.code, dst, bpf_slot(insn.src), insn.off, is64, pc)?;
        return Ok(1);
    }
    if !is64 && op == ALU_MOV && insn.src_is_reg() && insn.imm == 1 && insn.off == 0 {
        emit_zext(&mut ctx.code, dst);
        return Ok(1);
    }
    if insn.src_is_reg()
        || matches!(op, ALU_NEG)
        || (!is64 && matches!(op, ALU_MUL | ALU_DIV | ALU_MOD))
    {
        if !insn.src_is_reg() && !matches!(op, ALU_NEG) {
            // ALU32 mul/div/mod immediate: materialize, then the register form.
            emit_imm32(&mut ctx.code, TMP2, insn.imm);
            let rd_lo = get32(&mut ctx.code, dst, TMP1.lo);
            emit_alu32_reg(&mut ctx.code, rd_lo, TMP2.lo, op, insn.off == 1);
            put32(&mut ctx.code, dst, rd_lo);
            return Ok(1);
        }
        if is64 {
            let src_slot = if insn.src_is_reg() {
                bpf_slot(insn.src)
            } else {
                dst
            };
            let rd = get64(&mut ctx.code, dst, TMP1);
            let rs = if insn.src_is_reg() {
                get64(&mut ctx.code, src_slot, TMP2)
            } else {
                rd
            };
            let same = insn.src_is_reg() && insn.dst == insn.src && dst.hi >= 0;
            emit_alu64_reg(&mut ctx.code, rd, rs, op, same);
            put64(&mut ctx.code, dst, rd);
        } else {
            let rd_lo = get32(&mut ctx.code, dst, TMP1.lo);
            let rs_lo = if matches!(op, ALU_NEG) {
                rd_lo
            } else {
                get32(&mut ctx.code, bpf_slot(insn.src), TMP2.lo)
            };
            emit_alu32_reg(&mut ctx.code, rd_lo, rs_lo, op, insn.off == 1);
            put32(&mut ctx.code, dst, rd_lo);
        }
        return Ok(1);
    }

    // Immediate form. ALU64 add/sub/mul/shift-by-reg-style immediates for
    // add/sub/mul go through a materialized register, matching Jitterbug.
    if is64
        && matches!(
            op,
            ALU_ADD | ALU_SUB | ALU_MUL | ALU_LSH | ALU_RSH | ALU_ARSH
        )
        && op != ALU_MOV
    {
        if matches!(op, ALU_LSH | ALU_RSH | ALU_ARSH) {
            let rd = get64(&mut ctx.code, dst, TMP1);
            emit_shift64_imm(&mut ctx.code, rd, insn.imm, op);
            put64(&mut ctx.code, dst, rd);
        } else {
            emit_imm32(&mut ctx.code, TMP2, insn.imm);
            let rd = get64(&mut ctx.code, dst, TMP1);
            emit_alu64_reg(&mut ctx.code, rd, TMP2, op, false);
            put64(&mut ctx.code, dst, rd);
        }
        return Ok(1);
    }
    if is64 {
        let rd = get64(&mut ctx.code, dst, TMP1);
        emit_alu64_imm(&mut ctx.code, rd, insn.imm, op, pc)?;
        put64(&mut ctx.code, dst, rd);
    } else {
        let rd_lo = get32(&mut ctx.code, dst, TMP1.lo);
        emit_alu32_imm(&mut ctx.code, rd_lo, insn.imm, op, pc)?;
        put32(&mut ctx.code, dst, rd_lo);
    }
    Ok(1)
}

fn emit_movsx(
    code: &mut Vec<u32>,
    dst: Slot,
    src: Slot,
    off: i16,
    is64: bool,
    pc: usize,
) -> Result<(), JitError> {
    let rd = get64(code, dst, TMP1);
    let rs = get64(code, src, TMP2);
    match off {
        8 => {
            code.push(slli(rd.lo, rs.lo, 24));
            code.push(srai(rd.lo, rd.lo, 24));
        }
        16 => {
            code.push(slli(rd.lo, rs.lo, 16));
            code.push(srai(rd.lo, rd.lo, 16));
        }
        32 if is64 => code.push(addi(rd.lo, rs.lo, 0)),
        _ => {
            return Err(JitError::Unsupported {
                pc,
                code: if is64 { 0xbf } else { 0xbc },
                what: "movsx width",
            });
        }
    }
    if is64 {
        code.push(srai(rd.hi, rd.lo, 31));
        put64(code, dst, rd);
    } else {
        put32(code, dst, rd.lo);
    }
    Ok(())
}

fn emit_zext(code: &mut Vec<u32>, dst: Slot) {
    if dst.hi < 0 {
        code.push(sw(ZERO, i32::from(dst.hi), FP));
    } else {
        code.push(addi(dst.hi as u8, ZERO, 0));
    }
}

fn emit_alu64_reg(code: &mut Vec<u32>, rd: Live, rs: Live, op: u8, same_reg: bool) {
    match op {
        ALU_MOV => {
            code.push(addi(rd.lo, rs.lo, 0));
            code.push(addi(rd.hi, rs.hi, 0));
        }
        ALU_ADD if same_reg => {
            code.push(srli(T0, rd.lo, 31));
            code.push(slli(rd.hi, rd.hi, 1));
            code.push(or(rd.hi, T0, rd.hi));
            code.push(slli(rd.lo, rd.lo, 1));
        }
        ALU_ADD => {
            code.push(add(rd.lo, rd.lo, rs.lo));
            code.push(sltu(T0, rd.lo, rs.lo));
            code.push(add(rd.hi, rd.hi, rs.hi));
            code.push(add(rd.hi, rd.hi, T0));
        }
        ALU_SUB => {
            code.push(sub(T1, rd.hi, rs.hi));
            code.push(sltu(T0, rd.lo, rs.lo));
            code.push(sub(rd.hi, T1, T0));
            code.push(sub(rd.lo, rd.lo, rs.lo));
        }
        ALU_AND => {
            code.push(and(rd.lo, rd.lo, rs.lo));
            code.push(and(rd.hi, rd.hi, rs.hi));
        }
        ALU_OR => {
            code.push(or(rd.lo, rd.lo, rs.lo));
            code.push(or(rd.hi, rd.hi, rs.hi));
        }
        ALU_XOR => {
            code.push(xor(rd.lo, rd.lo, rs.lo));
            code.push(xor(rd.hi, rd.hi, rs.hi));
        }
        ALU_MUL => {
            code.push(mul(T0, rs.hi, rd.lo));
            code.push(mul(rd.hi, rd.hi, rs.lo));
            code.push(mulhu(T1, rd.lo, rs.lo));
            code.push(add(rd.hi, rd.hi, T0));
            code.push(mul(rd.lo, rd.lo, rs.lo));
            code.push(add(rd.hi, rd.hi, T1));
        }
        ALU_LSH => emit_lsh64_var(code, rd, rs),
        ALU_RSH => emit_rsh64_var(code, rd, rs),
        ALU_ARSH => emit_arsh64_var(code, rd, rs),
        ALU_NEG => {
            code.push(sub(rd.lo, ZERO, rd.lo));
            code.push(sltu(T0, ZERO, rd.lo));
            code.push(sub(rd.hi, ZERO, rd.hi));
            code.push(sub(rd.hi, rd.hi, T0));
        }
        _ => unreachable!("alu64 reg op filtered before emit"),
    }
}

fn emit_shift64_imm(code: &mut Vec<u32>, rd: Live, imm: i32, op: u8) {
    let sh = (imm as u32) & 63;
    match op {
        ALU_LSH => emit_lsh64_imm(code, rd, sh),
        ALU_RSH => emit_rsh64_imm(code, rd, sh),
        ALU_ARSH => emit_arsh64_imm(code, rd, sh),
        _ => unreachable!(),
    }
}

fn emit_lsh64_imm(code: &mut Vec<u32>, rd: Live, sh: u32) {
    if sh == 0 {
    } else if sh >= 32 {
        code.push(slli(rd.hi, rd.lo, sh - 32));
        code.push(addi(rd.lo, ZERO, 0));
    } else {
        code.push(srli(T0, rd.lo, 32 - sh));
        code.push(slli(rd.hi, rd.hi, sh));
        code.push(or(rd.hi, T0, rd.hi));
        code.push(slli(rd.lo, rd.lo, sh));
    }
}

fn emit_rsh64_imm(code: &mut Vec<u32>, rd: Live, sh: u32) {
    if sh == 0 {
    } else if sh >= 32 {
        code.push(srli(rd.lo, rd.hi, sh - 32));
        code.push(addi(rd.hi, ZERO, 0));
    } else {
        code.push(slli(T0, rd.hi, 32 - sh));
        code.push(srli(rd.lo, rd.lo, sh));
        code.push(or(rd.lo, T0, rd.lo));
        code.push(srli(rd.hi, rd.hi, sh));
    }
}

fn emit_arsh64_imm(code: &mut Vec<u32>, rd: Live, sh: u32) {
    if sh == 0 {
    } else if sh >= 32 {
        code.push(srai(rd.lo, rd.hi, sh - 32));
        code.push(srai(rd.hi, rd.hi, 31));
    } else {
        code.push(slli(T0, rd.hi, 32 - sh));
        code.push(srli(rd.lo, rd.lo, sh));
        code.push(or(rd.lo, T0, rd.lo));
        code.push(srai(rd.hi, rd.hi, sh));
    }
}

fn emit_lsh64_var(code: &mut Vec<u32>, rd: Live, rs: Live) {
    code.push(andi(T0, rs.lo, 63));
    code.push(addi(T1, T0, -32));
    let blt_at = code.len();
    code.push(0);
    code.push(sll(rd.hi, rd.lo, T1));
    code.push(addi(rd.lo, ZERO, 0));
    let jal_at = code.len();
    code.push(0);
    let slow = code.len();
    code.push(addi(T1, ZERO, 31));
    code.push(sub(T1, T1, T0));
    code.push(srli(T0, rd.lo, 1));
    code.push(srl(T0, T0, T1));
    code.push(andi(T1, rs.lo, 63));
    code.push(sll(rd.hi, rd.hi, T1));
    code.push(or(rd.hi, rd.hi, T0));
    code.push(sll(rd.lo, rd.lo, T1));
    let done = code.len();
    let blt_off = (slow as i32 - blt_at as i32) * 4;
    let jal_off = (done as i32 - jal_at as i32) * 4;
    code[blt_at] = blt(T1, ZERO, blt_off);
    code[jal_at] = jal(ZERO, jal_off);
}

fn emit_rsh64_var(code: &mut Vec<u32>, rd: Live, rs: Live) {
    code.push(andi(T0, rs.lo, 63));
    code.push(addi(T1, T0, -32));
    let blt_at = code.len();
    code.push(0);
    code.push(srl(rd.lo, rd.hi, T1));
    code.push(addi(rd.hi, ZERO, 0));
    let jal_at = code.len();
    code.push(0);
    let slow = code.len();
    code.push(addi(T1, ZERO, 31));
    code.push(sub(T1, T1, T0));
    code.push(slli(T0, rd.hi, 1));
    code.push(sll(T0, T0, T1));
    code.push(andi(T1, rs.lo, 63));
    code.push(srl(rd.lo, rd.lo, T1));
    code.push(or(rd.lo, rd.lo, T0));
    code.push(srl(rd.hi, rd.hi, T1));
    let done = code.len();
    code[blt_at] = blt(T1, ZERO, (slow as i32 - blt_at as i32) * 4);
    code[jal_at] = jal(ZERO, (done as i32 - jal_at as i32) * 4);
}

fn emit_arsh64_var(code: &mut Vec<u32>, rd: Live, rs: Live) {
    code.push(andi(T0, rs.lo, 63));
    code.push(addi(T1, T0, -32));
    let blt_at = code.len();
    code.push(0);
    code.push(sra(rd.lo, rd.hi, T1));
    code.push(srai(rd.hi, rd.hi, 31));
    let jal_at = code.len();
    code.push(0);
    let slow = code.len();
    code.push(addi(T1, ZERO, 31));
    code.push(sub(T1, T1, T0));
    code.push(slli(T0, rd.hi, 1));
    code.push(sll(T0, T0, T1));
    code.push(andi(T1, rs.lo, 63));
    code.push(srl(rd.lo, rd.lo, T1));
    code.push(or(rd.lo, rd.lo, T0));
    code.push(sra(rd.hi, rd.hi, T1));
    let done = code.len();
    code[blt_at] = blt(T1, ZERO, (slow as i32 - blt_at as i32) * 4);
    code[jal_at] = jal(ZERO, (done as i32 - jal_at as i32) * 4);
}

fn emit_alu64_imm(code: &mut Vec<u32>, rd: Live, imm: i32, op: u8, pc: usize) -> Result<(), JitError> {
    match op {
        ALU_MOV => emit_imm32(code, rd, imm),
        ALU_AND => {
            if fits_i12(imm) {
                code.push(andi(rd.lo, rd.lo, imm));
            } else {
                emit_imm(code, T0, imm);
                code.push(and(rd.lo, rd.lo, T0));
            }
            if imm >= 0 {
                code.push(addi(rd.hi, ZERO, 0));
            }
        }
        ALU_OR => {
            if fits_i12(imm) {
                code.push(ori(rd.lo, rd.lo, imm));
            } else {
                emit_imm(code, T0, imm);
                code.push(or(rd.lo, rd.lo, T0));
            }
            if imm < 0 {
                code.push(ori(rd.hi, rd.hi, -1));
            }
        }
        ALU_XOR => {
            if fits_i12(imm) {
                code.push(xori(rd.lo, rd.lo, imm));
            } else {
                emit_imm(code, T0, imm);
                code.push(xor(rd.lo, rd.lo, T0));
            }
            if imm < 0 {
                code.push(xori(rd.hi, rd.hi, -1));
            }
        }
        _ => {
            return Err(JitError::Unsupported {
                pc,
                code: op,
                what: "alu64 immediate",
            });
        }
    }
    Ok(())
}

fn emit_alu32_reg(code: &mut Vec<u32>, rd: u8, rs: u8, op: u8, signed: bool) {
    match op {
        ALU_MOV => code.push(addi(rd, rs, 0)),
        ALU_ADD => code.push(add(rd, rd, rs)),
        ALU_SUB => code.push(sub(rd, rd, rs)),
        ALU_AND => code.push(and(rd, rd, rs)),
        ALU_OR => code.push(or(rd, rd, rs)),
        ALU_XOR => code.push(xor(rd, rd, rs)),
        ALU_MUL => code.push(mul(rd, rd, rs)),
        ALU_DIV | ALU_MOD => emit_div32(code, rd, rs, signed, op == ALU_MOD),
        ALU_LSH => code.push(sll(rd, rd, rs)),
        ALU_RSH => code.push(srl(rd, rd, rs)),
        ALU_ARSH => code.push(sra(rd, rd, rs)),
        ALU_NEG => code.push(sub(rd, ZERO, rd)),
        _ => unreachable!("alu32 reg op filtered before emit"),
    }
}

fn emit_div32(code: &mut Vec<u32>, rd: u8, rs: u8, signed: bool, is_mod: bool) {
    // eBPF: div by zero yields 0; mod by zero leaves the destination.
    // RV32M div/rem do not.
    if is_mod {
        let beq_at = code.len();
        code.push(0);
        code.push(if signed {
            rem(rd, rd, rs)
        } else {
            remu(rd, rd, rs)
        });
        let done = code.len();
        code[beq_at] = beq(rs, ZERO, (done as i32 - beq_at as i32) * 4);
    } else {
        let beq_at = code.len();
        code.push(0);
        code.push(if signed {
            div(rd, rd, rs)
        } else {
            divu(rd, rd, rs)
        });
        let jal_at = code.len();
        code.push(0);
        let zero_at = code.len();
        code.push(addi(rd, ZERO, 0));
        let done = code.len();
        code[beq_at] = beq(rs, ZERO, (zero_at as i32 - beq_at as i32) * 4);
        code[jal_at] = jal(ZERO, (done as i32 - jal_at as i32) * 4);
    }
}

fn emit_alu32_imm(code: &mut Vec<u32>, rd: u8, imm: i32, op: u8, pc: usize) -> Result<(), JitError> {
    let sh = (imm as u32) & 31;
    match op {
        ALU_MOV => emit_imm(code, rd, imm),
        ALU_ADD => {
            if fits_i12(imm) {
                code.push(addi(rd, rd, imm));
            } else {
                emit_imm(code, T0, imm);
                code.push(add(rd, rd, T0));
            }
        }
        ALU_SUB => {
            if imm != i32::MIN && fits_i12(imm.wrapping_neg()) {
                code.push(addi(rd, rd, imm.wrapping_neg()));
            } else {
                emit_imm(code, T0, imm);
                code.push(sub(rd, rd, T0));
            }
        }
        ALU_AND => {
            if fits_i12(imm) {
                code.push(andi(rd, rd, imm));
            } else {
                emit_imm(code, T0, imm);
                code.push(and(rd, rd, T0));
            }
        }
        ALU_OR => {
            if fits_i12(imm) {
                code.push(ori(rd, rd, imm));
            } else {
                emit_imm(code, T0, imm);
                code.push(or(rd, rd, T0));
            }
        }
        ALU_XOR => {
            if fits_i12(imm) {
                code.push(xori(rd, rd, imm));
            } else {
                emit_imm(code, T0, imm);
                code.push(xor(rd, rd, T0));
            }
        }
        ALU_LSH => code.push(slli(rd, rd, sh)),
        ALU_RSH => code.push(srli(rd, rd, sh)),
        ALU_ARSH => code.push(srai(rd, rd, sh)),
        _ => {
            return Err(JitError::Unsupported {
                pc,
                code: op,
                what: "alu32 immediate",
            });
        }
    }
    Ok(())
}

fn emit_end(code: &mut Vec<u32>, dst: Slot, imm: i32, from_be: bool, pc: usize) -> Result<(), JitError> {
    let rd = get64(code, dst, TMP1);
    match (from_be, imm) {
        (false, 16) => {
            code.push(slli(rd.lo, rd.lo, 16));
            code.push(srli(rd.lo, rd.lo, 16));
            code.push(addi(rd.hi, ZERO, 0));
        }
        (false, 32) => code.push(addi(rd.hi, ZERO, 0)),
        // `{END, LE, ALU}` with 64 is the identity of the whole 64-bit value
        // on a little-endian host, not a truncation to 32 bits.
        (false, 64) => {}
        (true, 16) => {
            emit_rev16(code, rd.lo);
            code.push(addi(rd.hi, ZERO, 0));
        }
        (true, 32) => {
            emit_rev32(code, rd.lo);
            code.push(addi(rd.hi, ZERO, 0));
        }
        (true, 64) => {
            code.push(addi(T0, rd.lo, 0));
            code.push(addi(rd.lo, rd.hi, 0));
            code.push(addi(rd.hi, T0, 0));
            emit_rev32(code, rd.lo);
            emit_rev32(code, rd.hi);
        }
        _ => {
            return Err(JitError::Unsupported {
                pc,
                code: ALU_END,
                what: "bswap width",
            });
        }
    }
    put64(code, dst, rd);
    Ok(())
}

fn emit_rev16(code: &mut Vec<u32>, rd: u8) {
    code.push(slli(rd, rd, 16));
    code.push(slli(T1, rd, 8));
    code.push(srli(rd, rd, 8));
    code.push(add(T1, rd, T1));
    code.push(srli(rd, T1, 16));
}

fn emit_rev32(code: &mut Vec<u32>, rd: u8) {
    code.push(addi(T1, ZERO, 0));
    for _ in 0..3 {
        code.push(andi(T0, rd, 255));
        code.push(add(T1, T1, T0));
        code.push(slli(T1, T1, 8));
        code.push(srli(rd, rd, 8));
    }
    code.push(andi(T0, rd, 255));
    code.push(add(T1, T1, T0));
    code.push(addi(rd, T1, 0));
}

fn emit_jmp(
    ctx: &mut Ctx<'_>,
    insns: &[Insn],
    insn: Insn,
    pc: usize,
    is64: bool,
) -> Result<usize, JitError> {
    let op = insn.op();
    if !is64 && matches!(op, JMP_JA | JMP_CALL | JMP_EXIT) {
        return Err(JitError::Unsupported {
            pc,
            code: insn.code,
            what: "jmp32 control",
        });
    }
    match op {
        JMP_JA => {
            let target = branch_target(pc, insn.off, insns.len(), &ctx.wide_hi)?;
            ctx.emit_jump(ZERO, target);
        }
        JMP_EXIT => {
            if pc + 1 != insns.len() {
                ctx.emit_jump(ZERO, insns.len());
            }
        }
        JMP_CALL => emit_call(ctx, insn, pc)?,
        JMP_JEQ | JMP_JNE | JMP_JGT | JMP_JGE | JMP_JLT | JMP_JLE | JMP_JSGT | JMP_JSGE
        | JMP_JSLT | JMP_JSLE | JMP_JSET => {
            check_reg(pc, insn.dst)?;
            let target = branch_target(pc, insn.off, insns.len(), &ctx.wide_hi)?;
            let dst = bpf_slot(insn.dst);
            if is64 {
                let rs = if insn.src_is_reg() {
                    check_reg(pc, insn.src)?;
                    get64(&mut ctx.code, bpf_slot(insn.src), TMP2)
                } else {
                    emit_imm32(&mut ctx.code, TMP2, insn.imm);
                    TMP2
                };
                let rd = get64(&mut ctx.code, dst, TMP1);
                emit_bcc64(ctx, op, rd, rs, target, pc)?;
            } else {
                let rs = if insn.src_is_reg() {
                    check_reg(pc, insn.src)?;
                    get32(&mut ctx.code, bpf_slot(insn.src), TMP2.lo)
                } else {
                    emit_imm(&mut ctx.code, TMP2.lo, insn.imm);
                    TMP2.lo
                };
                let rd = get32(&mut ctx.code, dst, TMP1.lo);
                emit_bcc32(ctx, op, rd, rs, target, pc)?;
            }
        }
        _ => {
            return Err(JitError::Unsupported {
                pc,
                code: insn.code,
                what: if op == 0xf0 { "tail call" } else { "jump" },
            });
        }
    }
    Ok(1)
}

fn branch_target(pc: usize, off: i16, len: usize, wide_hi: &[bool]) -> Result<usize, JitError> {
    let target = pc as i32 + 1 + i32::from(off);
    if target < 0 || target > len as i32 {
        return Err(JitError::BadTarget { pc, target });
    }
    let target = target as usize;
    if target < wide_hi.len() && wide_hi[target] {
        return Err(JitError::LddwMiddle { pc, target });
    }
    Ok(target)
}

fn emit_call(ctx: &mut Ctx<'_>, insn: Insn, pc: usize) -> Result<(), JitError> {
    if insn.src == PSEUDO_CALL {
        return Err(JitError::Unsupported {
            pc,
            code: insn.code,
            what: "bpf-to-bpf call",
        });
    }
    if insn.src != 0 {
        return Err(JitError::Unsupported {
            pc,
            code: insn.code,
            what: "call src",
        });
    }
    let r5 = bpf_slot(5);
    let r0 = bpf_slot(0);
    // helper_dispatcher(idx, a1..a5) takes the low 32 bits of R1..R5.
    // Those lows currently sit in a0, a2, a4, a6, and s3. Copy them before a0
    // becomes the helper id. The address itself stays a relocation.
    ctx.code.push(addi(T0, A0, 0));
    ctx.code.push(addi(T2, A2, 0));
    ctx.code.push(addi(T3, A4, 0));
    ctx.code.push(addi(T4, A6, 0));
    ctx.code.push(addi(T5, r5.lo as u8, 0));
    emit_imm(&mut ctx.code, A0, insn.imm);
    ctx.code.push(addi(A1, T0, 0));
    ctx.code.push(addi(A2, T2, 0));
    ctx.code.push(addi(A3, T3, 0));
    ctx.code.push(addi(A4, T4, 0));
    ctx.code.push(addi(A5, T5, 0));
    ctx.code.push(addi(S7, T6, 0));
    let at = ctx.code.len();
    ctx.code.push(lui(T1, 0));
    ctx.code.push(jalr(RA, T1, 0));
    ctx.relocs.push(Reloc {
        kind: RelocKind::Call,
        rv_off: (at * 4) as u32,
        bpf_pc: pc as u32,
        src_reg: insn.src,
        imm: insn.imm,
        symbol: ctx.symbols.get(&(pc as u64 * 8)).cloned(),
    });
    ctx.code.push(addi(T6, S7, 0));
    ctx.code.push(addi(r0.lo as u8, A0, 0));
    ctx.code.push(addi(r0.hi as u8, ZERO, 0));
    Ok(())
}

impl Ctx<'_> {
    fn emit_jump(&mut self, rd: u8, target_pc: usize) {
        let at = self.code.len();
        self.code.push(auipc(T1, 0));
        self.code.push(jalr(rd, T1, 0));
        self.fixups.push(Fixup { at, target_pc, rd });
    }
}

fn emit_bcc32(
    ctx: &mut Ctx<'_>,
    op: u8,
    a: u8,
    b: u8,
    target: usize,
    pc: usize,
) -> Result<(), JitError> {
    if op == JMP_JSET {
        ctx.code.push(and(T0, a, b));
        ctx.code.push(beq(T0, ZERO, 12));
    } else {
        ctx.code.push(invert32(op, a, b, 12, pc)?);
    }
    ctx.emit_jump(ZERO, target);
    Ok(())
}

fn invert32(op: u8, a: u8, b: u8, off: i32, pc: usize) -> Result<u32, JitError> {
    Ok(match op {
        JMP_JEQ => bne(a, b, off),
        JMP_JNE => beq(a, b, off),
        JMP_JGT => bleu(a, b, off),
        JMP_JLE => bgtu(a, b, off),
        JMP_JLT => bgeu(a, b, off),
        JMP_JGE => bltu(a, b, off),
        JMP_JSGT => ble(a, b, off),
        JMP_JSLE => bgt(a, b, off),
        JMP_JSLT => bge(a, b, off),
        JMP_JSGE => blt(a, b, off),
        _ => {
            return Err(JitError::Unsupported {
                pc,
                code: op,
                what: "condition",
            });
        }
    })
}

fn emit_bcc64(
    ctx: &mut Ctx<'_>,
    op: u8,
    a: Live,
    b: Live,
    target: usize,
    pc: usize,
) -> Result<(), JitError> {
    match op {
        JMP_JEQ => {
            ctx.code.push(bne(a.hi, b.hi, 16));
            ctx.code.push(bne(a.lo, b.lo, 12));
        }
        JMP_JNE => {
            ctx.code.push(bne(a.hi, b.hi, 8));
            ctx.code.push(beq(a.lo, b.lo, 12));
        }
        JMP_JGT => {
            ctx.code.push(bgtu(a.hi, b.hi, 12));
            ctx.code.push(bltu(a.hi, b.hi, 16));
            ctx.code.push(bleu(a.lo, b.lo, 12));
        }
        JMP_JLT => {
            ctx.code.push(bltu(a.hi, b.hi, 12));
            ctx.code.push(bgtu(a.hi, b.hi, 16));
            ctx.code.push(bgeu(a.lo, b.lo, 12));
        }
        JMP_JGE => {
            ctx.code.push(bgtu(a.hi, b.hi, 12));
            ctx.code.push(bltu(a.hi, b.hi, 16));
            ctx.code.push(bltu(a.lo, b.lo, 12));
        }
        JMP_JLE => {
            ctx.code.push(bltu(a.hi, b.hi, 12));
            ctx.code.push(bgtu(a.hi, b.hi, 16));
            ctx.code.push(bgtu(a.lo, b.lo, 12));
        }
        JMP_JSGT => {
            ctx.code.push(bgt(a.hi, b.hi, 12));
            ctx.code.push(blt(a.hi, b.hi, 16));
            ctx.code.push(bleu(a.lo, b.lo, 12));
        }
        JMP_JSLT => {
            ctx.code.push(blt(a.hi, b.hi, 12));
            ctx.code.push(bgt(a.hi, b.hi, 16));
            ctx.code.push(bgeu(a.lo, b.lo, 12));
        }
        JMP_JSGE => {
            ctx.code.push(bgt(a.hi, b.hi, 12));
            ctx.code.push(blt(a.hi, b.hi, 16));
            ctx.code.push(bltu(a.lo, b.lo, 12));
        }
        JMP_JSLE => {
            ctx.code.push(blt(a.hi, b.hi, 12));
            ctx.code.push(bgt(a.hi, b.hi, 16));
            ctx.code.push(bgtu(a.lo, b.lo, 12));
        }
        JMP_JSET => {
            ctx.code.push(and(T0, a.hi, b.hi));
            ctx.code.push(bne(T0, ZERO, 12));
            ctx.code.push(and(T0, a.lo, b.lo));
            ctx.code.push(beq(T0, ZERO, 12));
        }
        _ => {
            return Err(JitError::Unsupported {
                pc,
                code: op,
                what: "condition",
            });
        }
    }
    ctx.emit_jump(ZERO, target);
    Ok(())
}

fn emit_mem(ctx: &mut Ctx<'_>, insn: Insn, pc: usize, store: bool) -> Result<usize, JitError> {
    check_reg(pc, insn.dst)?;
    let size = insn.size();
    if !matches!(size, SIZE_B | SIZE_H | SIZE_W | SIZE_DW) {
        return Err(JitError::Unsupported {
            pc,
            code: insn.code,
            what: "mem size",
        });
    }
    if store && insn.class() == CLASS_ST {
        emit_imm32(&mut ctx.code, TMP2, insn.imm);
        let base = get64(&mut ctx.code, bpf_slot(insn.dst), TMP1);
        emit_store(&mut ctx.code, base, TMP2, insn.off, size);
    } else if store {
        check_reg(pc, insn.src)?;
        let base = get64(&mut ctx.code, bpf_slot(insn.dst), TMP1);
        let val = get64(&mut ctx.code, bpf_slot(insn.src), TMP2);
        emit_store(&mut ctx.code, base, val, insn.off, size);
    } else {
        check_reg(pc, insn.src)?;
        let dst = bpf_slot(insn.dst);
        let rd = get64(&mut ctx.code, dst, TMP1);
        let base = get64(&mut ctx.code, bpf_slot(insn.src), TMP2);
        emit_imm(&mut ctx.code, T0, i32::from(insn.off));
        ctx.code.push(add(T0, T0, base.lo));
        match size {
            SIZE_B => {
                ctx.code.push(lbu(rd.lo, 0, T0));
                ctx.code.push(addi(rd.hi, ZERO, 0));
            }
            // eBPF allows an unaligned address. A half or word `lhu`/`lw` is
            // not defined there: packet fields often sit at 2-mod-4.
            SIZE_H => {
                emit_load_le(&mut ctx.code, rd.lo, T0, 2, 0);
                ctx.code.push(addi(rd.hi, ZERO, 0));
            }
            SIZE_W => {
                emit_load_le(&mut ctx.code, rd.lo, T0, 4, 0);
                ctx.code.push(addi(rd.hi, ZERO, 0));
            }
            SIZE_DW => {
                emit_load_le(&mut ctx.code, rd.lo, T0, 4, 0);
                emit_load_le(&mut ctx.code, rd.hi, T0, 4, 4);
            }
            _ => unreachable!(),
        }
        put64(&mut ctx.code, dst, rd);
    }
    Ok(1)
}

fn emit_store(code: &mut Vec<u32>, base: Live, val: Live, off: i16, size: u8) {
    emit_imm(code, T0, i32::from(off));
    code.push(add(T0, T0, base.lo));
    match size {
        SIZE_B => code.push(sb(val.lo, 0, T0)),
        SIZE_H => emit_store_le(code, T0, val.lo, 2, 0),
        SIZE_W => emit_store_le(code, T0, val.lo, 4, 0),
        SIZE_DW => {
            emit_store_le(code, T0, val.lo, 4, 0);
            emit_store_le(code, T0, val.hi, 4, 4);
        }
        _ => unreachable!(),
    }
}

fn emit_load_le(code: &mut Vec<u32>, dst: u8, addr: u8, n: u8, disp: i32) {
    code.push(addi(dst, ZERO, 0));
    for i in 0..n {
        code.push(lbu(T1, disp + i32::from(i), addr));
        if i != 0 {
            code.push(slli(T1, T1, u32::from(i) * 8));
        }
        code.push(or(dst, dst, T1));
    }
}

fn emit_store_le(code: &mut Vec<u32>, addr: u8, src: u8, n: u8, disp: i32) {
    for i in 0..n {
        if i == 0 {
            code.push(andi(T1, src, 0xff));
        } else {
            code.push(srli(T1, src, u32::from(i) * 8));
            code.push(andi(T1, T1, 0xff));
        }
        code.push(sb(T1, disp + i32::from(i), addr));
    }
}

fn emit_imm32(code: &mut Vec<u32>, rd: Live, imm: i32) {
    emit_imm(code, rd.lo, imm);
    if imm >= 0 {
        code.push(addi(rd.hi, ZERO, 0));
    } else {
        code.push(addi(rd.hi, ZERO, -1));
    }
}

fn get64(code: &mut Vec<u32>, slot: Slot, tmp: Live) -> Live {
    if slot.hi < 0 {
        code.push(lw(tmp.hi, i32::from(slot.hi), FP));
        code.push(lw(tmp.lo, i32::from(slot.lo), FP));
        tmp
    } else {
        Live {
            hi: slot.hi as u8,
            lo: slot.lo as u8,
        }
    }
}

fn put64(code: &mut Vec<u32>, dst: Slot, src: Live) {
    if dst.hi < 0 {
        code.push(sw(src.hi, i32::from(dst.hi), FP));
        code.push(sw(src.lo, i32::from(dst.lo), FP));
    }
}

fn get32(code: &mut Vec<u32>, slot: Slot, tmp_lo: u8) -> u8 {
    if slot.lo < 0 {
        code.push(lw(tmp_lo, i32::from(slot.lo), FP));
        tmp_lo
    } else {
        slot.lo as u8
    }
}

fn put32(code: &mut Vec<u32>, dst: Slot, src_lo: u8) {
    if dst.lo < 0 {
        code.push(sw(src_lo, i32::from(dst.lo), FP));
        code.push(sw(ZERO, i32::from(dst.hi), FP));
    } else {
        code.push(addi(dst.hi as u8, ZERO, 0));
    }
}

/// Addresses that close every relocation. A zero address is refused.
pub struct LinkIn<'a> {
    pub helper: u32,
    /// ELF symbol name to the map's VMR address. Not the value storage.
    pub maps: &'a HashMap<String, u32>,
}

pub fn link(image: &Image, input: &LinkIn<'_>) -> Result<Vec<u32>, JitError> {
    if image.relocs.is_empty() {
        return Ok(image.code.clone());
    }
    if input.helper == 0 {
        return Err(JitError::Unresolved {
            what: "helper",
            detail: "address is 0".into(),
        });
    }
    let mut code = image.code.clone();
    for reloc in &image.relocs {
        match reloc.kind {
            RelocKind::Func => {
                return Err(JitError::Unresolved {
                    what: "bpf-to-bpf call",
                    detail: format!("bpf pc {}", reloc.bpf_pc),
                });
            }
            RelocKind::Call => patch_call(&mut code, reloc.rv_off, input.helper)?,
            RelocKind::Lddw => {
                let name = reloc.symbol.as_deref().ok_or_else(|| JitError::Unresolved {
                    what: "lddw",
                    detail: format!("bpf pc {} has no symbol", reloc.bpf_pc),
                })?;
                let addr = input.maps.get(name).copied().ok_or_else(|| JitError::Unresolved {
                    what: "map",
                    detail: name.to_string(),
                })?;
                if addr == 0 {
                    return Err(JitError::Unresolved {
                        what: "map",
                        detail: format!("{name} address is 0"),
                    });
                }
                patch_lddw(&mut code, reloc.rv_off, addr)?;
            }
        }
    }
    Ok(code)
}

fn abs_pair(rd: u8, addr: u32) -> [u32; 2] {
    let (hi, lo) = split_pc_rel(addr as i32);
    [lui(rd, hi), addi(rd, rd, lo)]
}

fn patch_call(code: &mut [u32], rv_off: u32, helper: u32) -> Result<(), JitError> {
    let at = word_at(code, rv_off, 2)?;
    if code[at + 1] != jalr(RA, T1, 0) {
        return Err(JitError::Unresolved {
            what: "call",
            detail: format!("offset {rv_off:#x} is not an unlinked jalr"),
        });
    }
    let (hi, lo) = split_pc_rel(helper as i32);
    code[at] = lui(T1, hi);
    code[at + 1] = jalr(RA, T1, lo);
    Ok(())
}

fn patch_lddw(code: &mut [u32], rv_off: u32, addr: u32) -> Result<(), JitError> {
    let at = word_at(code, rv_off, 4)?;
    // The unlinked sequence is lui/addi for the low half, then the same pair
    // for the high half, each addi reading the register its lui wrote.
    let shape = [
        ((code[at] & 0x7f) as u8, ((code[at] >> 7) & 31) as u8),
        ((code[at + 1] & 0x7f) as u8, ((code[at + 1] >> 7) & 31) as u8),
        ((code[at + 2] & 0x7f) as u8, ((code[at + 2] >> 7) & 31) as u8),
        ((code[at + 3] & 0x7f) as u8, ((code[at + 3] >> 7) & 31) as u8),
    ];
    let addi_rs1 = |word: u32| ((word >> 15) & 31) as u8;
    let ok = shape[0].0 == 0x37
        && shape[1].0 == 0x13
        && shape[1].1 == addi_rs1(code[at + 1])
        && shape[2].0 == 0x37
        && shape[3].0 == 0x13
        && shape[3].1 == addi_rs1(code[at + 3])
        && shape[1].1 == shape[0].1
        && shape[3].1 == shape[2].1
        && shape[0].1 != 0
        && shape[2].1 != 0;
    if !ok {
        return Err(JitError::Unresolved {
            what: "lddw",
            detail: format!("offset {rv_off:#x} is not the unlinked four-word pair"),
        });
    }
    let lo = abs_pair(shape[0].1, addr);
    let hi = abs_pair(shape[2].1, 0);
    code[at] = lo[0];
    code[at + 1] = lo[1];
    code[at + 2] = hi[0];
    code[at + 3] = hi[1];
    Ok(())
}

fn word_at(code: &[u32], rv_off: u32, n: usize) -> Result<usize, JitError> {
    if rv_off % 4 != 0 {
        return Err(JitError::Unresolved {
            what: "reloc",
            detail: format!("offset {rv_off:#x} is not aligned"),
        });
    }
    let at = (rv_off / 4) as usize;
    if at.checked_add(n).map(|end| end > code.len()).unwrap_or(true) {
        return Err(JitError::Unresolved {
            what: "reloc",
            detail: format!("offset {rv_off:#x} is past the image"),
        });
    }
    Ok(at)
}
