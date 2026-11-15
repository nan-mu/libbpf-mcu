//! RV32IM interpreter for linked JIT output.
//!
//! It decodes instruction bits. A helper address outside this memory is
//! intercepted and passed to [`crate::host_abi::dispatch`], which is also
//! what the eBPF reference calls.

use crate::host_abi;

const SENTINEL: u32 = 0xffff_fff0;
const STEPS: usize = 1_000_000;

pub struct Stop {
    pub a0: u32,
    pub a1: u32,
    pub mem: Vec<u8>,
}

pub fn run(
    code: &[u32],
    a0: u32,
    mut mem: Vec<u8>,
    helper_at: Option<u32>,
) -> Result<Stop, String> {
    let mut x = [0u32; 32];
    x[1] = SENTINEL;
    x[2] = 0x3_0000;
    x[10] = a0;
    let mut pc: i32 = 0;
    for _ in 0..STEPS {
        if pc < 0 || (pc as u32) & 3 != 0 || (pc as usize) / 4 >= code.len() {
            return Err(format!("pc {pc:#x} left the image"));
        }
        let inst = code[pc as usize / 4];
        let next = step(&mut x, &mut mem, pc, inst, helper_at)?;
        if next == SENTINEL as i32 {
            return Ok(Stop {
                a0: x[10],
                a1: x[11],
                mem,
            });
        }
        pc = next;
    }
    Err("step limit".into())
}

fn step(
    x: &mut [u32; 32],
    mem: &mut [u8],
    pc: i32,
    inst: u32,
    helper_at: Option<u32>,
) -> Result<i32, String> {
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
            if Some(target) == helper_at {
                let args = [x[10], x[11], x[12], x[13], x[14], x[15]];
                let ret = host_abi::dispatch(mem, args);
                x[10] = ret;
                return Ok(x[1] as i32);
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
                1 => {
                    let b = load(mem, addr, 2)?;
                    i32::from(u16::from_le_bytes([b[0], b[1]]) as i16) as u32
                }
                2 => {
                    let b = load(mem, addr, 4)?;
                    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
                }
                4 => u32::from(load(mem, addr, 1)?[0]),
                5 => {
                    let b = load(mem, addr, 2)?;
                    u32::from(u16::from_le_bytes([b[0], b[1]]))
                }
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
    let end = a.checked_add(n).ok_or_else(|| format!("load {addr:#x}"))?;
    if end > mem.len() {
        return Err(format!("load {addr:#x} len {n}"));
    }
    if a % n != 0 {
        return Err(format!("misaligned load {addr:#x}"));
    }
    Ok(&mem[a..end])
}

fn store(mem: &mut [u8], addr: u32, bytes: &[u8]) -> Result<(), String> {
    let a = addr as usize;
    let end = a
        .checked_add(bytes.len())
        .ok_or_else(|| format!("store {addr:#x}"))?;
    if end > mem.len() {
        return Err(format!("store {addr:#x}"));
    }
    if a % bytes.len() != 0 {
        return Err(format!("misaligned store {addr:#x}"));
    }
    mem[a..end].copy_from_slice(bytes);
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
