//! Execute the JIT output on a tiny RV32 interpreter and compare with eBPF.
//!
//! The interpreter decodes instruction bits itself. Encoder pins live in
//! `rv.rs`. A branch test fails if those two disagree.

use std::collections::HashMap;

use xpost_jit::isa::*;
use xpost_jit::{compile, disassemble, Insn};

const SENTINEL: u32 = 0xffff_fff0;
const MEM: usize = 0x4_0000;
const SP: u32 = 0x3_0000;

fn i(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
    Insn {
        code,
        dst,
        src,
        off,
        imm,
    }
}

fn run(insns: &[Insn], a0: u32) -> Result<(u32, u32), String> {
    let image = compile(insns, &HashMap::new()).map_err(|e| e.to_string())?;
    exec(&image.code, a0).map_err(|e| format!("{e}\n{}", disassemble(&image.code)))
}

fn exec(code: &[u32], a0: u32) -> Result<(u32, u32), String> {
    let mut x = [0u32; 32];
    x[1] = SENTINEL;
    x[2] = SP;
    x[10] = a0;
    let mut mem = vec![0u8; MEM];
    let mut pc: i32 = 0;
    for _ in 0..200_000 {
        if pc < 0 || pc as usize / 4 >= code.len() || (pc as u32) & 3 != 0 {
            return Err(format!("pc {pc:#x} left the image"));
        }
        let inst = code[pc as usize / 4];
        let next = step(&mut x, &mut mem, pc, inst)?;
        if next == SENTINEL as i32 {
            return Ok((x[10], x[11]));
        }
        pc = next;
    }
    Err("step limit".into())
}

fn step(x: &mut [u32; 32], mem: &mut [u8], pc: i32, inst: u32) -> Result<i32, String> {
    let op = inst & 0x7f;
    let rd = ((inst >> 7) & 31) as usize;
    let f3 = (inst >> 12) & 7;
    let rs1 = ((inst >> 15) & 31) as usize;
    let rs2 = ((inst >> 20) & 31) as usize;
    let f7 = inst >> 25;
    let i_imm = ((inst as i32) >> 20) as u32;
    let mut next = pc + 4;
    match op {
        0x13 => {
            let sh = rs2 as u32;
            let v = match f3 {
                0 => x[rs1].wrapping_add(i_imm),
                1 if f7 == 0 => x[rs1] << sh,
                4 => x[rs1] ^ i_imm,
                5 if f7 == 0 => x[rs1] >> sh,
                5 if f7 == 0x20 => ((x[rs1] as i32) >> sh) as u32,
                6 => x[rs1] | i_imm,
                7 => x[rs1] & i_imm,
                _ => return Err(format!("op-imm {inst:#x}")),
            };
            write(x, rd, v);
        }
        0x33 => {
            let a = x[rs1];
            let b = x[rs2];
            let v = match (f7, f3) {
                (0, 0) => a.wrapping_add(b),
                (0x20, 0) => a.wrapping_sub(b),
                (0, 1) => a << (b & 31),
                (0, 3) => u32::from(a < b),
                (0, 4) => a ^ b,
                (0, 5) => a >> (b & 31),
                (0x20, 5) => ((a as i32) >> (b & 31)) as u32,
                (0, 6) => a | b,
                (0, 7) => a & b,
                (1, 0) => a.wrapping_mul(b),
                (1, 3) => ((u64::from(a) * u64::from(b)) >> 32) as u32,
                (1, 4) => signed_div(a, b),
                (1, 5) => {
                    if b == 0 {
                        u32::MAX
                    } else {
                        a / b
                    }
                }
                (1, 6) => {
                    if b == 0 {
                        a
                    } else {
                        (a as i32).wrapping_rem(b as i32) as u32
                    }
                }
                (1, 7) => {
                    if b == 0 {
                        a
                    } else {
                        a % b
                    }
                }
                _ => return Err(format!("op {inst:#x}")),
            };
            write(x, rd, v);
        }
        0x37 => write(x, rd, inst & !0xfff),
        0x17 => write(x, rd, (pc as u32).wrapping_add(inst & !0xfff)),
        0x6f => {
            let off = j_off(inst);
            if rd != 0 {
                write(x, rd, (pc as u32).wrapping_add(4));
            }
            next = pc.wrapping_add(off);
        }
        0x67 => {
            let target = x[rs1].wrapping_add(i_imm) & !1;
            if rd != 0 {
                write(x, rd, (pc as u32).wrapping_add(4));
            }
            if target == SENTINEL {
                return Ok(SENTINEL as i32);
            }
            next = target as i32;
        }
        0x63 => {
            let a = x[rs1];
            let b = x[rs2];
            let take = match f3 {
                0 => a == b,
                1 => a != b,
                4 => (a as i32) < (b as i32),
                5 => (a as i32) >= (b as i32),
                6 => a < b,
                7 => a >= b,
                _ => return Err(format!("branch {inst:#x}")),
            };
            if take {
                next = pc.wrapping_add(b_off(inst));
            }
        }
        0x03 => {
            let addr = x[rs1].wrapping_add(i_imm);
            let v = match f3 {
                0 => i32::from(load(mem, addr, 1)?[0] as i8) as u32,
                1 => i32::from(u16::from_le_bytes(load(mem, addr, 2)?.try_into().unwrap()) as i16)
                    as u32,
                2 => u32::from_le_bytes(load(mem, addr, 4)?.try_into().unwrap()),
                4 => u32::from(load(mem, addr, 1)?[0]),
                5 => u32::from(u16::from_le_bytes(load(mem, addr, 2)?.try_into().unwrap())),
                _ => return Err(format!("load {inst:#x}")),
            };
            write(x, rd, v);
        }
        0x23 => {
            let imm = s_off(inst) as u32;
            let addr = x[rs1].wrapping_add(imm);
            let v = x[rs2];
            match f3 {
                0 => store(mem, addr, &v.to_le_bytes()[..1])?,
                1 => store(mem, addr, &v.to_le_bytes()[..2])?,
                2 => store(mem, addr, &v.to_le_bytes())?,
                _ => return Err(format!("store {inst:#x}")),
            }
        }
        _ => return Err(format!("opcode {inst:#x}")),
    }
    x[0] = 0;
    Ok(next)
}

fn signed_div(a: u32, b: u32) -> u32 {
    if b == 0 {
        return u32::MAX;
    }
    if a == 0x8000_0000 && b == 0xffff_ffff {
        return a;
    }
    (a as i32).wrapping_div(b as i32) as u32
}

fn write(x: &mut [u32; 32], rd: usize, v: u32) {
    if rd != 0 {
        x[rd] = v;
    }
}

fn load(mem: &[u8], addr: u32, n: usize) -> Result<&[u8], String> {
    let a = addr as usize;
    if a + n > mem.len() {
        return Err(format!("load {addr:#x} len {n}"));
    }
    if a % n != 0 {
        return Err(format!("misaligned load {addr:#x}"));
    }
    Ok(&mem[a..a + n])
}

fn store(mem: &mut [u8], addr: u32, bytes: &[u8]) -> Result<(), String> {
    let a = addr as usize;
    if a + bytes.len() > mem.len() {
        return Err(format!("store {addr:#x}"));
    }
    if a % bytes.len() != 0 {
        return Err(format!("misaligned store {addr:#x}"));
    }
    mem[a..a + bytes.len()].copy_from_slice(bytes);
    Ok(())
}

fn b_off(inst: u32) -> i32 {
    let b12 = (inst >> 31) & 1;
    let b11 = (inst >> 7) & 1;
    let b10_5 = (inst >> 25) & 0x3f;
    let b4_1 = (inst >> 8) & 0xf;
    let imm = (b12 << 12) | (b11 << 11) | (b10_5 << 5) | (b4_1 << 1);
    ((imm << 19) as i32) >> 19
}

fn j_off(inst: u32) -> i32 {
    let b20 = (inst >> 31) & 1;
    let b10_1 = (inst >> 21) & 0x3ff;
    let b11 = (inst >> 20) & 1;
    let b19_12 = (inst >> 12) & 0xff;
    let imm = (b20 << 20) | (b19_12 << 12) | (b11 << 11) | (b10_1 << 1);
    ((imm << 11) as i32) >> 11
}

fn s_off(inst: u32) -> i32 {
    let hi = (inst >> 25) & 0x7f;
    let lo = (inst >> 7) & 0x1f;
    let imm = (hi << 5) | lo;
    ((imm << 20) as i32) >> 20
}

fn alu64(op: u8, src: u8) -> u8 {
    CLASS_ALU64 | op | src
}
fn alu32(op: u8, src: u8) -> u8 {
    CLASS_ALU | op | src
}
fn jmp64(op: u8, src: u8) -> u8 {
    CLASS_JMP | op | src
}

#[test]
fn mov_exit() {
    let p = [
        i(alu64(ALU_MOV, SRC_K), 0, 0, 0, 42),
        i(jmp64(JMP_EXIT, 0), 0, 0, 0, 0),
    ];
    assert_eq!(run(&p, 0).unwrap(), (42, 0));
}

#[test]
fn add64_carry() {
    let p = [
        i(CLASS_LD | SIZE_DW | MODE_IMM, 0, 0, 0, -1),
        i(0, 0, 0, 0, 0),
        i(alu64(ALU_ADD, SRC_K), 0, 0, 0, 2),
        i(jmp64(JMP_EXIT, 0), 0, 0, 0, 0),
    ];
    assert_eq!(run(&p, 0).unwrap(), (1, 1));
}

#[test]
fn bpf_stack_slot() {
    let p = [
        i(CLASS_ST | MODE_MEM | SIZE_W, REG_FP, 0, -4, 0x1234_5678),
        i(CLASS_LDX | MODE_MEM | SIZE_W, 0, REG_FP, -4, 0),
        i(jmp64(JMP_EXIT, 0), 0, 0, 0, 0),
    ];
    assert_eq!(run(&p, 0).unwrap(), (0x1234_5678, 0));
}

#[test]
fn stacked_register() {
    let p = [
        i(alu64(ALU_MOV, SRC_K), 6, 0, 0, 0x99),
        i(alu64(ALU_MOV, SRC_X), 0, 6, 0, 0),
        i(jmp64(JMP_EXIT, 0), 0, 0, 0, 0),
    ];
    assert_eq!(run(&p, 0).unwrap(), (0x99, 0));
}

#[test]
fn backward_loop() {
    let p = [
        i(alu64(ALU_MOV, SRC_K), 0, 0, 0, 0),
        i(alu64(ALU_MOV, SRC_K), 1, 0, 0, 4),
        i(alu64(ALU_ADD, SRC_K), 0, 0, 0, 1),
        i(alu64(ALU_SUB, SRC_K), 1, 0, 0, 1),
        i(jmp64(JMP_JNE, SRC_K), 1, 0, -3, 0),
        i(jmp64(JMP_EXIT, 0), 0, 0, 0, 0),
    ];
    assert_eq!(run(&p, 0).unwrap(), (4, 0));
}

#[test]
fn jeq_skips() {
    let p = [
        i(alu64(ALU_MOV, SRC_K), 0, 0, 0, 1),
        i(jmp64(JMP_JEQ, SRC_K), 0, 0, 1, 1),
        i(alu64(ALU_MOV, SRC_K), 0, 0, 0, 9),
        i(jmp64(JMP_EXIT, 0), 0, 0, 0, 0),
    ];
    assert_eq!(run(&p, 0).unwrap(), (1, 0));
}

#[test]
fn signed_less() {
    let p = [
        i(alu64(ALU_MOV, SRC_K), 0, 0, 0, -1),
        i(jmp64(JMP_JSLT, SRC_K), 0, 0, 1, 0),
        i(alu64(ALU_MOV, SRC_K), 0, 0, 0, 5),
        i(jmp64(JMP_EXIT, 0), 0, 0, 0, 0),
    ];
    assert_eq!(run(&p, 0).unwrap(), (0xffff_ffff, 0xffff_ffff));
}

#[test]
fn div_mod_zero() {
    let div0 = [
        i(alu32(ALU_MOV, SRC_K), 0, 0, 0, 7),
        i(alu32(ALU_DIV, SRC_K), 0, 0, 0, 0),
        i(jmp64(JMP_EXIT, 0), 0, 0, 0, 0),
    ];
    assert_eq!(run(&div0, 0).unwrap(), (0, 0));
    let div = [
        i(alu32(ALU_MOV, SRC_K), 0, 0, 0, 7),
        i(alu32(ALU_DIV, SRC_K), 0, 0, 0, 2),
        i(jmp64(JMP_EXIT, 0), 0, 0, 0, 0),
    ];
    assert_eq!(run(&div, 0).unwrap(), (3, 0));
    let mod0 = [
        i(alu32(ALU_MOV, SRC_K), 0, 0, 0, 7),
        i(alu32(ALU_MOD, SRC_K), 0, 0, 0, 0),
        i(jmp64(JMP_EXIT, 0), 0, 0, 0, 0),
    ];
    assert_eq!(run(&mod0, 0).unwrap(), (7, 0));
}

#[test]
fn bswap32() {
    let p = [
        i(alu64(ALU_MOV, SRC_K), 0, 0, 0, 0x1234_5678),
        i(CLASS_ALU | ALU_END | SRC_X, 0, 0, 0, 32),
        i(jmp64(JMP_EXIT, 0), 0, 0, 0, 0),
    ];
    assert_eq!(run(&p, 0).unwrap(), (0x7856_3412, 0));
}

#[test]
fn mul64() {
    let p = [
        i(alu64(ALU_MOV, SRC_K), 0, 0, 0, 6),
        i(alu64(ALU_MOV, SRC_K), 1, 0, 0, 7),
        i(alu64(ALU_MUL, SRC_X), 0, 1, 0, 0),
        i(jmp64(JMP_EXIT, 0), 0, 0, 0, 0),
    ];
    assert_eq!(run(&p, 0).unwrap(), (42, 0));
}

#[test]
fn shift_and_arsh() {
    let lsh = [
        i(CLASS_LD | SIZE_DW | MODE_IMM, 0, 0, 0, 1),
        i(0, 0, 0, 0, 0),
        i(alu64(ALU_MOV, SRC_K), 2, 0, 0, 40),
        i(alu64(ALU_LSH, SRC_X), 0, 2, 0, 0),
        i(jmp64(JMP_EXIT, 0), 0, 0, 0, 0),
    ];
    assert_eq!(run(&lsh, 0).unwrap(), (0, 0x100));
    let arsh = [
        i(CLASS_LD | SIZE_DW | MODE_IMM, 0, 0, 0, 0),
        i(0, 0, 0, 0, i32::MIN),
        i(alu64(ALU_ARSH, SRC_K), 0, 0, 0, 1),
        i(jmp64(JMP_EXIT, 0), 0, 0, 0, 0),
    ];
    assert_eq!(run(&arsh, 0).unwrap(), (0, 0xc000_0000));
}

#[test]
fn alu32_clears_high() {
    let p = [
        i(alu64(ALU_MOV, SRC_K), 0, 0, 0, -1),
        i(alu32(ALU_MOV, SRC_K), 0, 0, 0, -1),
        i(jmp64(JMP_EXIT, 0), 0, 0, 0, 0),
    ];
    assert_eq!(run(&p, 0).unwrap(), (0xffff_ffff, 0));
}

#[test]
fn call_and_lddw_stay_unlinked() {
    let p = [
        i(CLASS_LD | SIZE_DW | MODE_IMM, 1, PSEUDO_MAP_FD, 0, 0),
        i(0, 0, 0, 0, 0),
        i(jmp64(JMP_CALL, 0), 0, 0, 0, 1),
        i(jmp64(JMP_EXIT, 0), 0, 0, 0, 0),
    ];
    let mut syms = HashMap::new();
    syms.insert(0, "map_counter".into());
    let image = compile(&p, &syms).unwrap();
    let call_at = image.relocs[1].rv_off as usize / 4;
    assert_eq!(image.code[call_at], 0x0000_0337, "lui t1, 0");
    assert_eq!(image.code[call_at + 1], 0x0003_00e7, "jalr ra, t1, 0");
    assert_eq!(image.relocs.len(), 2);
    assert_eq!(image.relocs[0].kind, xpost_jit::RelocKind::Lddw);
    assert_eq!(image.relocs[0].symbol.as_deref(), Some("map_counter"));
    assert_eq!(image.relocs[1].kind, xpost_jit::RelocKind::Call);
    assert_eq!(image.relocs[1].imm, 1);
    let text = image.reloc_text();
    assert!(text.contains("lddw"));
    assert!(text.contains("map_counter"));
}

#[test]
fn rejects_alu64_div() {
    let p = [
        i(alu64(ALU_DIV, SRC_X), 0, 1, 0, 0),
        i(jmp64(JMP_EXIT, 0), 0, 0, 0, 0),
    ];
    let err = compile(&p, &HashMap::new()).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("alu64 div"), "{msg}");
}
