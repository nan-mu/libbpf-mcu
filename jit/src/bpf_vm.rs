//! eBPF reference interpreter.
//!
//! Arithmetic follows RFC 9669. This file does not call the RV32 lowering.
//! Signed division overflow, the most negative value divided by -1, uses
//! wrapping two's-complement division. RFC 9669's table does not name that case.
//! Shift counts are masked with 31 or 63 (RFC 9669, section 4).

use std::collections::HashMap;

use crate::bpf::*;
use crate::host_abi;

pub const FRAME: u64 = 0x2_0000;
const STEPS: usize = 1_000_000;

pub fn execute(
    insns: &[Insn],
    symbols: &HashMap<u64, String>,
    maps: &HashMap<String, u32>,
    mem: &mut [u8],
    r1: u64,
) -> Result<u64, String> {
    let wide = wide_slots(insns)?;
    let mut reg = [0u64; 11];
    reg[1] = r1;
    reg[10] = FRAME;
    let mut pc = 0usize;
    for _ in 0..STEPS {
        if pc == insns.len() {
            return Ok(reg[0]);
        }
        if pc > insns.len() || wide[pc] {
            return Err(format!("bpf pc {pc} is not an instruction"));
        }
        let insn = insns[pc];
        let class = insn.class();
        if class == CLASS_LD && insn.size() == SIZE_DW && insn.mode() == MODE_IMM {
            let next = *insns.get(pc + 1).ok_or_else(|| format!("bpf pc {pc}: truncated lddw"))?;
            if next.code != 0 || next.dst != 0 || next.src != 0 || next.off != 0 {
                return Err(format!("bpf pc {pc}: bad lddw"));
            }
            let value = if insn.src == 0 {
                (insn.imm as u32 as u64) | ((next.imm as u32 as u64) << 32)
            } else {
                let name = symbols
                    .get(&(pc as u64 * 8))
                    .ok_or_else(|| format!("bpf pc {pc}: lddw has no symbol"))?;
                let addr = maps
                    .get(name)
                    .ok_or_else(|| format!("bpf pc {pc}: map {name}"))?;
                u64::from(*addr)
            };
            write_reg(&mut reg, insn.dst, value)?;
            pc += 2;
            continue;
        }
        if insn.code == NOSPEC {
            pc += 1;
            continue;
        }
        match class {
            CLASS_ALU | CLASS_ALU64 => {
                let is64 = class == CLASS_ALU64;
                let dst = read_reg(&reg, insn.dst)?;
                let src = alu_src(&reg, insn, is64)?;
                let value = if insn.op() == ALU_END {
                    endian(dst, insn.imm, insn.src_is_reg(), is64)?
                } else if insn.op() == ALU_MOV && insn.src_is_reg() && insn.off != 0 {
                    movsx(src, insn.off, is64)?
                } else if !is64
                    && insn.op() == ALU_MOV
                    && insn.src_is_reg()
                    && insn.imm == 1
                    && insn.off == 0
                {
                    dst & 0xffff_ffff
                } else {
                    alu(insn.op(), insn.off, dst, src, is64)?
                };
                write_reg(&mut reg, insn.dst, value)?;
                pc += 1;
            }
            CLASS_JMP | CLASS_JMP32 => {
                if insn.op() == JMP_CALL {
                    if class != CLASS_JMP || insn.src != 0 {
                        return Err(format!("bpf pc {pc}: unsupported call"));
                    }
                    let args = [
                        insn.imm as u32,
                        reg[1] as u32,
                        reg[2] as u32,
                        reg[3] as u32,
                        reg[4] as u32,
                        reg[5] as u32,
                    ];
                    reg[0] = u64::from(host_abi::dispatch(mem, args));
                    pc += 1;
                    continue;
                }
                match jump(&reg, insn, pc, insns.len(), class == CLASS_JMP)? {
                    None => return Ok(reg[0]),
                    Some(next) => {
                        if next < insns.len() && wide[next] {
                            return Err(format!("bpf pc {pc}: branch into lddw"));
                        }
                        pc = next;
                    }
                }
            }
            CLASS_LDX if insn.mode() == MODE_MEM => {
                let addr = read_reg(&reg, insn.src)?.wrapping_add(insn.off as i64 as u64);
                write_reg(&mut reg, insn.dst, load_mem(mem, addr, insn.size())?)?;
                pc += 1;
            }
            CLASS_ST | CLASS_STX if insn.mode() == MODE_MEM => {
                let addr = read_reg(&reg, insn.dst)?.wrapping_add(insn.off as i64 as u64);
                let value = if class == CLASS_ST {
                    insn.imm as i64 as u64
                } else {
                    read_reg(&reg, insn.src)?
                };
                store_mem(mem, addr, value, insn.size())?;
                pc += 1;
            }
            CLASS_ST | CLASS_STX if insn.mode() == MODE_ATOMIC => {
                return Err(format!("bpf pc {pc}: atomic"));
            }
            _ => return Err(format!("bpf pc {pc}: unsupported opcode {:#x}", insn.code)),
        }
    }
    Err("bpf step limit".into())
}

fn wide_slots(insns: &[Insn]) -> Result<Vec<bool>, String> {
    let mut wide = vec![false; insns.len()];
    let mut pc = 0;
    while pc < insns.len() {
        let insn = insns[pc];
        if insn.class() == CLASS_LD && insn.size() == SIZE_DW && insn.mode() == MODE_IMM {
            if pc + 1 >= insns.len() {
                return Err(format!("bpf pc {pc}: truncated lddw"));
            }
            wide[pc + 1] = true;
            pc += 2;
        } else {
            pc += 1;
        }
    }
    Ok(wide)
}

fn alu_src(reg: &[u64; 11], insn: Insn, is64: bool) -> Result<u64, String> {
    if insn.op() == ALU_NEG {
        return Ok(0);
    }
    if insn.src_is_reg() {
        return read_reg(reg, insn.src);
    }
    if is64 {
        Ok(insn.imm as i64 as u64)
    } else {
        Ok(insn.imm as u32 as u64)
    }
}

fn alu(op: u8, off: i16, dst: u64, src: u64, is64: bool) -> Result<u64, String> {
    let signed = off == 1;
    if !is64 {
        let d = dst as u32;
        let s = src as u32;
        let v = match op {
            ALU_ADD => d.wrapping_add(s),
            ALU_SUB => d.wrapping_sub(s),
            ALU_MUL => d.wrapping_mul(s),
            ALU_DIV if !signed => {
                if s == 0 {
                    0
                } else {
                    d / s
                }
            }
            ALU_DIV => sdiv32(d, s),
            ALU_OR => d | s,
            ALU_AND => d & s,
            ALU_LSH => d.wrapping_shl(s & 31),
            ALU_RSH => d.wrapping_shr(s & 31),
            ALU_NEG => d.wrapping_neg(),
            ALU_MOD if !signed => {
                if s == 0 {
                    d
                } else {
                    d % s
                }
            }
            ALU_MOD => smod32(d, s),
            ALU_XOR => d ^ s,
            ALU_MOV => s,
            ALU_ARSH => ((d as i32) >> (s & 31)) as u32,
            _ => return Err(format!("alu32 op {op:#x}")),
        };
        return Ok(u64::from(v));
    }
    match op {
        ALU_ADD => Ok(dst.wrapping_add(src)),
        ALU_SUB => Ok(dst.wrapping_sub(src)),
        ALU_MUL => Ok(dst.wrapping_mul(src)),
        ALU_DIV | ALU_MOD => Err("alu64 div/mod".into()),
        ALU_OR => Ok(dst | src),
        ALU_AND => Ok(dst & src),
        ALU_LSH => Ok(dst.wrapping_shl((src & 63) as u32)),
        ALU_RSH => Ok(dst.wrapping_shr((src & 63) as u32)),
        ALU_NEG => Ok(dst.wrapping_neg()),
        ALU_XOR => Ok(dst ^ src),
        ALU_MOV => Ok(src),
        ALU_ARSH => Ok(((dst as i64) >> (src & 63)) as u64),
        _ => Err(format!("alu64 op {op:#x}")),
    }
}

fn sdiv32(a: u32, b: u32) -> u32 {
    if b == 0 {
        return 0;
    }
    (a as i32).wrapping_div(b as i32) as u32
}

fn smod32(a: u32, b: u32) -> u32 {
    if b == 0 {
        return a;
    }
    (a as i32).wrapping_rem(b as i32) as u32
}

fn movsx(src: u64, off: i16, is64: bool) -> Result<u64, String> {
    let low = match off {
        8 => src as i8 as i32 as u32,
        16 => src as i16 as i32 as u32,
        32 if is64 => src as u32,
        _ => return Err(format!("movsx width {off}")),
    };
    if is64 {
        Ok(low as i32 as i64 as u64)
    } else {
        Ok(u64::from(low))
    }
}

fn endian(dst: u64, imm: i32, from_be: bool, is64: bool) -> Result<u64, String> {
    if is64 {
        return Err("alu64 bswap".into());
    }
    let v = dst as u32;
    match (from_be, imm) {
        (false, 16) => Ok(u64::from(v & 0xffff)),
        (false, 32) => Ok(u64::from(v)),
        // `{END, *, ALU}` with 64 acts on the whole 64-bit value (RFC 9669,
        // section 4.2). le64 on a little-endian host is the identity.
        (false, 64) => Ok(dst),
        (true, 16) => Ok(u64::from(v.swap_bytes() >> 16)),
        (true, 32) => Ok(u64::from(v.swap_bytes())),
        (true, 64) => Ok(dst.swap_bytes()),
        _ => Err(format!("bswap width {imm}")),
    }
}

fn jump(
    reg: &[u64; 11],
    insn: Insn,
    pc: usize,
    len: usize,
    is64: bool,
) -> Result<Option<usize>, String> {
    let op = insn.op();
    if !is64 && matches!(op, JMP_JA | JMP_CALL | JMP_EXIT) {
        return Err(format!("bpf pc {pc}: jmp32 control"));
    }
    match op {
        JMP_EXIT => Ok(None),
        JMP_JA => dest(pc, insn.off, len).map(Some),
        JMP_JEQ | JMP_JNE | JMP_JGT | JMP_JGE | JMP_JLT | JMP_JLE | JMP_JSGT | JMP_JSGE
        | JMP_JSLT | JMP_JSLE | JMP_JSET => {
            let dst = read_reg(reg, insn.dst)?;
            let src = if insn.src_is_reg() {
                read_reg(reg, insn.src)?
            } else if is64 {
                insn.imm as i64 as u64
            } else {
                insn.imm as u32 as u64
            };
            if take(op, dst, src, is64) {
                dest(pc, insn.off, len).map(Some)
            } else {
                Ok(Some(pc + 1))
            }
        }
        _ => Err(format!("bpf pc {pc}: jump {op:#x}")),
    }
}

fn dest(pc: usize, off: i16, len: usize) -> Result<usize, String> {
    let target = pc as i32 + 1 + i32::from(off);
    if target < 0 || target > len as i32 {
        return Err(format!("bpf pc {pc}: bad target {target}"));
    }
    Ok(target as usize)
}

fn take(op: u8, dst: u64, src: u64, is64: bool) -> bool {
    if is64 {
        return match op {
            JMP_JEQ => dst == src,
            JMP_JNE => dst != src,
            JMP_JGT => dst > src,
            JMP_JGE => dst >= src,
            JMP_JLT => dst < src,
            JMP_JLE => dst <= src,
            JMP_JSET => dst & src != 0,
            JMP_JSGT => (dst as i64) > (src as i64),
            JMP_JSGE => (dst as i64) >= (src as i64),
            JMP_JSLT => (dst as i64) < (src as i64),
            JMP_JSLE => (dst as i64) <= (src as i64),
            _ => false,
        };
    }
    let d = dst as u32;
    let s = src as u32;
    match op {
        JMP_JEQ => d == s,
        JMP_JNE => d != s,
        JMP_JGT => d > s,
        JMP_JGE => d >= s,
        JMP_JLT => d < s,
        JMP_JLE => d <= s,
        JMP_JSET => d & s != 0,
        JMP_JSGT => (d as i32) > (s as i32),
        JMP_JSGE => (d as i32) >= (s as i32),
        JMP_JSLT => (d as i32) < (s as i32),
        JMP_JSLE => (d as i32) <= (s as i32),
        _ => false,
    }
}

fn read_reg(reg: &[u64; 11], idx: u8) -> Result<u64, String> {
    reg.get(idx as usize)
        .copied()
        .ok_or_else(|| format!("register {idx}"))
}

fn write_reg(reg: &mut [u64; 11], idx: u8, value: u64) -> Result<(), String> {
    *reg.get_mut(idx as usize)
        .ok_or_else(|| format!("register {idx}"))? = value;
    Ok(())
}

fn load_mem(mem: &[u8], addr: u64, size: u8) -> Result<u64, String> {
    let n = size_bytes(size)?;
    let at = usize::try_from(addr).map_err(|_| format!("load {addr:#x}"))?;
    let bytes = mem
        .get(at..at.checked_add(n).ok_or_else(|| format!("load {addr:#x}"))?)
        .ok_or_else(|| format!("load {addr:#x}"))?;
    let mut buf = [0u8; 8];
    buf[..n].copy_from_slice(bytes);
    Ok(u64::from_le_bytes(buf))
}

fn store_mem(mem: &mut [u8], addr: u64, value: u64, size: u8) -> Result<(), String> {
    let n = size_bytes(size)?;
    let at = usize::try_from(addr).map_err(|_| format!("store {addr:#x}"))?;
    let end = at.checked_add(n).ok_or_else(|| format!("store {addr:#x}"))?;
    let slot = mem.get_mut(at..end).ok_or_else(|| format!("store {addr:#x}"))?;
    slot.copy_from_slice(&value.to_le_bytes()[..n]);
    Ok(())
}

fn size_bytes(size: u8) -> Result<usize, String> {
    match size {
        SIZE_B => Ok(1),
        SIZE_H => Ok(2),
        SIZE_W => Ok(4),
        SIZE_DW => Ok(8),
        _ => Err(format!("mem size {size:#x}")),
    }
}
