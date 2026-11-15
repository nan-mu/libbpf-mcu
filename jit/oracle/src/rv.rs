//! RV32IM executor that records the helper-call trace.
//!
//! `xpost_jit::run_rv` hardwires helper interception to `host_abi::dispatch`
//! and exposes no hook, so it cannot report which helpers ran with which
//! arguments. This executor records them. Every case runs both executors and
//! requires the same return value and the same final memory, so a divergence
//! between them is reported as a finding rather than silently trusted.
//!
//! Entry and exit follow the JIT's own convention: `a0` is `lo(R1)`, `sp` is
//! `0x3_0000`, `ra` is the sentinel, and a `jalr` to the sentinel ends the run.

pub const SENTINEL: u32 = 0xffff_fff0;
pub const STEPS: usize = 1_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    pub id: u32,
    pub args: [u32; 5],
    pub ret: u32,
}

pub struct Stop {
    pub a0: u32,
    pub a1: u32,
    pub mem: Vec<u8>,
    pub trace: Vec<Call>,
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
    let mut trace = Vec::new();
    let mut pc: i32 = 0;
    for _ in 0..STEPS {
        if pc < 0 || (pc as u32) & 3 != 0 || (pc as usize) / 4 >= code.len() {
            return Err(format!("pc {pc:#x} left the image"));
        }
        let inst = code[pc as usize / 4];
        let op = inst & 0x7f;
        let rd = ((inst >> 7) & 31) as usize;
        let f3 = (inst >> 12) & 7;
        let rs1 = ((inst >> 15) & 31) as usize;
        let rs2 = ((inst >> 20) & 31) as usize;
        let f7 = inst >> 25;
        let imm = ((inst as i32) >> 20) as u32;
        let mut next = pc + 4;
        match op {
            0x13 => {
                let sh = rs2 as u32;
                let a = x[rs1];
                let v = match f3 {
                    0 => a.wrapping_add(imm),
                    1 if f7 == 0 => a << sh,
                    2 => u32::from((a as i32) < (imm as i32)),
                    3 => u32::from(a < imm),
                    4 => a ^ imm,
                    5 if f7 == 0 => a >> sh,
                    5 if f7 == 0x20 => ((a as i32) >> sh) as u32,
                    6 => a | imm,
                    7 => a & imm,
                    _ => return Err(format!("op-imm {inst:#x}")),
                };
                put(&mut x, rd, v);
            }
            0x33 => {
                let a = x[rs1];
                let b = x[rs2];
                let v = match (f7, f3) {
                    (0, 0) => a.wrapping_add(b),
                    (0x20, 0) => a.wrapping_sub(b),
                    (0, 1) => a << (b & 31),
                    (0, 2) => u32::from((a as i32) < (b as i32)),
                    (0, 3) => u32::from(a < b),
                    (0, 4) => a ^ b,
                    (0, 5) => a >> (b & 31),
                    (0x20, 5) => ((a as i32) >> (b & 31)) as u32,
                    (0, 6) => a | b,
                    (0, 7) => a & b,
                    (1, 0) => a.wrapping_mul(b),
                    (1, 1) => (((a as i32 as i64) * (b as i32 as i64)) >> 32) as u32,
                    (1, 2) => (((a as i32 as i64) * (b as u64 as i64)) >> 32) as u32,
                    (1, 3) => ((u64::from(a) * u64::from(b)) >> 32) as u32,
                    (1, 4) => sdiv(a, b),
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
                put(&mut x, rd, v);
            }
            0x37 => put(&mut x, rd, inst & !0xfff),
            0x17 => put(&mut x, rd, (pc as u32).wrapping_add(inst & !0xfff)),
            0x6f => {
                if rd != 0 {
                    put(&mut x, rd, (pc as u32).wrapping_add(4));
                }
                next = pc.wrapping_add(j_off(inst));
            }
            0x67 => {
                let target = x[rs1].wrapping_add(imm) & !1;
                if rd != 0 {
                    put(&mut x, rd, (pc as u32).wrapping_add(4));
                }
                if target == SENTINEL {
                    return Ok(Stop {
                        a0: x[10],
                        a1: x[11],
                        mem,
                        trace,
                    });
                }
                if Some(target) == helper_at {
                    let args = [x[11], x[12], x[13], x[14], x[15]];
                    let r = xpost_jit::dispatch(
                        &mut mem,
                        [x[10], args[0], args[1], args[2], args[3], args[4]],
                    );
                    trace.push(Call {
                        id: x[10],
                        args,
                        ret: r,
                    });
                    x[10] = r;
                    next = x[1] as i32;
                } else {
                    next = target as i32;
                }
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
                let addr = x[rs1].wrapping_add(imm);
                let v = match f3 {
                    0 => i32::from(load(&mem, addr, 1)?[0] as i8) as u32,
                    1 => {
                        let b = load(&mem, addr, 2)?;
                        i32::from(u16::from_le_bytes([b[0], b[1]]) as i16) as u32
                    }
                    2 => {
                        let b = load(&mem, addr, 4)?;
                        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
                    }
                    4 => u32::from(load(&mem, addr, 1)?[0]),
                    5 => {
                        let b = load(&mem, addr, 2)?;
                        u32::from(u16::from_le_bytes([b[0], b[1]]))
                    }
                    _ => return Err(format!("load {inst:#x}")),
                };
                put(&mut x, rd, v);
            }
            0x23 => {
                let addr = x[rs1].wrapping_add(s_off(inst) as u32);
                let v = x[rs2];
                match f3 {
                    0 => store(&mut mem, addr, &v.to_le_bytes()[..1])?,
                    1 => store(&mut mem, addr, &v.to_le_bytes()[..2])?,
                    2 => store(&mut mem, addr, &v.to_le_bytes())?,
                    _ => return Err(format!("store {inst:#x}")),
                }
            }
            _ => return Err(format!("opcode {inst:#x}")),
        }
        x[0] = 0;
        pc = next;
    }
    Err("step limit".into())
}

fn sdiv(a: u32, b: u32) -> u32 {
    if b == 0 {
        return u32::MAX;
    }
    if a == 0x8000_0000 && b == 0xffff_ffff {
        return a;
    }
    (a as i32).wrapping_div(b as i32) as u32
}

fn put(x: &mut [u32; 32], rd: usize, v: u32) {
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
    let imm = (((inst >> 31) & 1) << 12)
        | (((inst >> 7) & 1) << 11)
        | (((inst >> 25) & 0x3f) << 5)
        | (((inst >> 8) & 0xf) << 1);
    ((imm << 19) as i32) >> 19
}

fn j_off(inst: u32) -> i32 {
    let imm = (((inst >> 31) & 1) << 20)
        | (((inst >> 21) & 0x3ff) << 1)
        | (((inst >> 20) & 1) << 11)
        | (((inst >> 12) & 0xff) << 12);
    ((imm << 11) as i32) >> 11
}

fn s_off(inst: u32) -> i32 {
    let imm = (((inst >> 25) & 0x7f) << 5) | ((inst >> 7) & 0x1f);
    ((imm << 20) as i32) >> 20
}
