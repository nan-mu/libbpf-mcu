//! RV32IM encoder. Immediates are byte offsets for branches and jumps.
//!
//! Branch and jump arguments are byte offsets from the instruction, matching
//! the RISC-V spec (the low bit is not stored). A few encodings are pinned in
//! unit tests so a later edit cannot swap the immediate fields silently.

pub const ZERO: u8 = 0;
pub const RA: u8 = 1;
pub const SP: u8 = 2;
pub const FP: u8 = 8;
pub const S1: u8 = 9;
pub const A0: u8 = 10;
pub const A1: u8 = 11;
pub const A2: u8 = 12;
pub const A3: u8 = 13;
pub const A4: u8 = 14;
pub const A5: u8 = 15;
pub const A6: u8 = 16;
pub const A7: u8 = 17;
pub const S2: u8 = 18;
pub const S3: u8 = 19;
pub const S4: u8 = 20;
pub const S5: u8 = 21;
pub const S6: u8 = 22;
pub const S7: u8 = 23;
pub const T0: u8 = 5;
pub const T1: u8 = 6;
pub const T2: u8 = 7;
pub const T3: u8 = 28;
pub const T4: u8 = 29;
pub const T5: u8 = 30;
pub const T6: u8 = 31;

const OP_IMM: u32 = 0x13;
const OP: u32 = 0x33;
const LUI: u32 = 0x37;
const AUIPC: u32 = 0x17;
const JAL: u32 = 0x6f;
const JALR: u32 = 0x67;
const BRANCH: u32 = 0x63;
const LOAD: u32 = 0x03;
const STORE: u32 = 0x23;

/// Reject anything the ESP32-C3 slot must not receive: RVC halfwords, the F/D
/// and A extensions, and RV64-only widths. The encoder emits RV32IM by
/// construction, so this is a gate on the artifact rather than on the encoder.
pub fn check_rv32im(code: &[u32]) -> Result<(), String> {
    for (i, &inst) in code.iter().enumerate() {
        let at = format!("word {i} ({:#x})", i * 4);
        if inst & 3 != 3 {
            return Err(format!("{at}: {inst:#010x} is not a 32-bit instruction"));
        }
        let funct3 = (inst >> 12) & 7;
        let funct7 = inst >> 25;
        match inst & 0x7f {
            LUI | AUIPC | JAL | JALR | BRANCH => {}
            LOAD if matches!(funct3, 0 | 1 | 2 | 4 | 5) => {}
            STORE if matches!(funct3, 0 | 1 | 2) => {}
            OP if matches!(funct7, 0 | 0x20 | 1) => {}
            OP_IMM => match funct3 {
                1 if funct7 != 0 => {
                    return Err(format!("{at}: slli shamt is not RV32 ({funct7:#x})"));
                }
                5 if !matches!(funct7, 0 | 0x20) => {
                    return Err(format!("{at}: shift funct7 is not RV32 ({funct7:#x})"));
                }
                _ => {}
            },
            0x0f => {}
            _ => {
                return Err(format!(
                    "{at}: opcode {:#04x} is outside RV32IM",
                    inst & 0x7f
                ));
            }
        }
    }
    Ok(())
}

pub fn fits_i12(imm: i32) -> bool {
    (-2048..2048).contains(&imm)
}

fn r_type(funct7: u32, rs2: u8, rs1: u8, funct3: u32, rd: u8) -> u32 {
    (funct7 << 25)
        | (u32::from(rs2) << 20)
        | (u32::from(rs1) << 15)
        | (funct3 << 12)
        | (u32::from(rd) << 7)
        | OP
}

fn i_type(imm: i32, rs1: u8, funct3: u32, rd: u8, opcode: u32) -> u32 {
    let imm = (imm as u32) & 0xfff;
    (imm << 20) | (u32::from(rs1) << 15) | (funct3 << 12) | (u32::from(rd) << 7) | opcode
}

fn s_type(imm: i32, rs2: u8, rs1: u8, funct3: u32) -> u32 {
    let imm = imm as u32;
    let hi = (imm >> 5) & 0x7f;
    let lo = imm & 0x1f;
    (hi << 25)
        | (u32::from(rs2) << 20)
        | (u32::from(rs1) << 15)
        | (funct3 << 12)
        | (lo << 7)
        | STORE
}

/// `imm[12:1]` packed from a byte offset. Bit 0 of the offset is dropped.
fn b_type(funct3: u32, rs1: u8, rs2: u8, byte_off: i32) -> u32 {
    debug_assert_eq!(byte_off & 1, 0, "branch offset {byte_off} is odd");
    let imm = byte_off as u32;
    let b12 = (imm >> 12) & 1;
    let b11 = (imm >> 11) & 1;
    let b10_5 = (imm >> 5) & 0x3f;
    let b4_1 = (imm >> 1) & 0xf;
    (b12 << 31)
        | (b10_5 << 25)
        | (u32::from(rs2) << 20)
        | (u32::from(rs1) << 15)
        | (funct3 << 12)
        | (b4_1 << 8)
        | (b11 << 7)
        | BRANCH
}

fn j_type(rd: u8, byte_off: i32) -> u32 {
    debug_assert_eq!(byte_off & 1, 0, "jal offset {byte_off} is odd");
    let imm = byte_off as u32;
    let b20 = (imm >> 20) & 1;
    let b10_1 = (imm >> 1) & 0x3ff;
    let b11 = (imm >> 11) & 1;
    let b19_12 = (imm >> 12) & 0xff;
    (b20 << 31) | (b10_1 << 21) | (b11 << 20) | (b19_12 << 12) | (u32::from(rd) << 7) | JAL
}

pub fn addi(rd: u8, rs1: u8, imm: i32) -> u32 {
    i_type(imm, rs1, 0, rd, OP_IMM)
}

pub fn andi(rd: u8, rs1: u8, imm: i32) -> u32 {
    i_type(imm, rs1, 7, rd, OP_IMM)
}

pub fn ori(rd: u8, rs1: u8, imm: i32) -> u32 {
    i_type(imm, rs1, 6, rd, OP_IMM)
}

pub fn xori(rd: u8, rs1: u8, imm: i32) -> u32 {
    i_type(imm, rs1, 4, rd, OP_IMM)
}

pub fn slli(rd: u8, rs1: u8, shamt: u32) -> u32 {
    debug_assert!(shamt < 32);
    i_type(shamt as i32, rs1, 1, rd, OP_IMM)
}

pub fn srli(rd: u8, rs1: u8, shamt: u32) -> u32 {
    debug_assert!(shamt < 32);
    i_type(shamt as i32, rs1, 5, rd, OP_IMM)
}

pub fn srai(rd: u8, rs1: u8, shamt: u32) -> u32 {
    debug_assert!(shamt < 32);
    i_type((0x20 << 5) | shamt as i32, rs1, 5, rd, OP_IMM)
}

pub fn add(rd: u8, rs1: u8, rs2: u8) -> u32 {
    r_type(0, rs2, rs1, 0, rd)
}

pub fn sub(rd: u8, rs1: u8, rs2: u8) -> u32 {
    r_type(0x20, rs2, rs1, 0, rd)
}

pub fn and(rd: u8, rs1: u8, rs2: u8) -> u32 {
    r_type(0, rs2, rs1, 7, rd)
}

pub fn or(rd: u8, rs1: u8, rs2: u8) -> u32 {
    r_type(0, rs2, rs1, 6, rd)
}

pub fn xor(rd: u8, rs1: u8, rs2: u8) -> u32 {
    r_type(0, rs2, rs1, 4, rd)
}

pub fn sll(rd: u8, rs1: u8, rs2: u8) -> u32 {
    r_type(0, rs2, rs1, 1, rd)
}

pub fn srl(rd: u8, rs1: u8, rs2: u8) -> u32 {
    r_type(0, rs2, rs1, 5, rd)
}

pub fn sra(rd: u8, rs1: u8, rs2: u8) -> u32 {
    r_type(0x20, rs2, rs1, 5, rd)
}

pub fn sltu(rd: u8, rs1: u8, rs2: u8) -> u32 {
    r_type(0, rs2, rs1, 3, rd)
}

pub fn mul(rd: u8, rs1: u8, rs2: u8) -> u32 {
    r_type(1, rs2, rs1, 0, rd)
}

pub fn mulhu(rd: u8, rs1: u8, rs2: u8) -> u32 {
    r_type(1, rs2, rs1, 3, rd)
}

pub fn divu(rd: u8, rs1: u8, rs2: u8) -> u32 {
    r_type(1, rs2, rs1, 5, rd)
}

pub fn div(rd: u8, rs1: u8, rs2: u8) -> u32 {
    r_type(1, rs2, rs1, 4, rd)
}

pub fn remu(rd: u8, rs1: u8, rs2: u8) -> u32 {
    r_type(1, rs2, rs1, 7, rd)
}

pub fn rem(rd: u8, rs1: u8, rs2: u8) -> u32 {
    r_type(1, rs2, rs1, 6, rd)
}

pub fn lui(rd: u8, imm20: i32) -> u32 {
    ((imm20 as u32) << 12) | (u32::from(rd) << 7) | LUI
}

pub fn auipc(rd: u8, imm20: i32) -> u32 {
    ((imm20 as u32) << 12) | (u32::from(rd) << 7) | AUIPC
}

pub fn jal(rd: u8, byte_off: i32) -> u32 {
    j_type(rd, byte_off)
}

pub fn jalr(rd: u8, rs1: u8, imm: i32) -> u32 {
    i_type(imm, rs1, 0, rd, JALR)
}

pub fn beq(rs1: u8, rs2: u8, byte_off: i32) -> u32 {
    b_type(0, rs1, rs2, byte_off)
}

pub fn bne(rs1: u8, rs2: u8, byte_off: i32) -> u32 {
    b_type(1, rs1, rs2, byte_off)
}

pub fn blt(rs1: u8, rs2: u8, byte_off: i32) -> u32 {
    b_type(4, rs1, rs2, byte_off)
}

pub fn bge(rs1: u8, rs2: u8, byte_off: i32) -> u32 {
    b_type(5, rs1, rs2, byte_off)
}

pub fn bltu(rs1: u8, rs2: u8, byte_off: i32) -> u32 {
    b_type(6, rs1, rs2, byte_off)
}

pub fn bgeu(rs1: u8, rs2: u8, byte_off: i32) -> u32 {
    b_type(7, rs1, rs2, byte_off)
}

pub fn bgtu(rs1: u8, rs2: u8, byte_off: i32) -> u32 {
    bltu(rs2, rs1, byte_off)
}

pub fn bleu(rs1: u8, rs2: u8, byte_off: i32) -> u32 {
    bgeu(rs2, rs1, byte_off)
}

pub fn bgt(rs1: u8, rs2: u8, byte_off: i32) -> u32 {
    blt(rs2, rs1, byte_off)
}

pub fn ble(rs1: u8, rs2: u8, byte_off: i32) -> u32 {
    bge(rs2, rs1, byte_off)
}

pub fn lw(rd: u8, imm: i32, rs1: u8) -> u32 {
    i_type(imm, rs1, 2, rd, LOAD)
}

pub fn lbu(rd: u8, imm: i32, rs1: u8) -> u32 {
    i_type(imm, rs1, 4, rd, LOAD)
}

pub fn sb(rs2: u8, imm: i32, rs1: u8) -> u32 {
    s_type(imm, rs2, rs1, 0)
}

pub fn sw(rs2: u8, imm: i32, rs1: u8) -> u32 {
    s_type(imm, rs2, rs1, 2)
}

/// Split a PC-relative byte offset into the `auipc` high part and the
/// sign-extended low 12 bits, so `auipc rd, hi; jalr .., rd, lo` lands on
/// `pc + byte_off` of the `auipc`.
pub fn split_pc_rel(byte_off: i32) -> (i32, i32) {
    let hi = byte_off.wrapping_add(1 << 11) >> 12;
    let lo = byte_off & 0xfff;
    let lo = if lo >= 0x800 { lo - 0x1000 } else { lo };
    (hi, lo)
}

pub fn emit_imm(code: &mut Vec<u32>, rd: u8, imm: i32) {
    let (hi, lo) = split_pc_rel(imm);
    if hi != 0 {
        code.push(lui(rd, hi));
        code.push(addi(rd, rd, lo));
    } else {
        code.push(addi(rd, ZERO, lo));
    }
}

const ABI: [&str; 32] = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "fp", "s1", "a0", "a1", "a2", "a3", "a4",
    "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
    "t5", "t6",
];

fn reg(i: u32) -> &'static str {
    ABI[(i & 31) as usize]
}

fn sext(val: u32, bits: u32) -> i32 {
    let shift = 32 - bits;
    ((val << shift) as i32) >> shift
}

pub fn disassemble(code: &[u32]) -> String {
    let mut out = String::new();
    for (i, inst) in code.iter().copied().enumerate() {
        out.push_str(&format!("{:04x}: {}\n", i * 4, mnemonic(inst)));
    }
    out
}

pub fn mnemonic(inst: u32) -> String {
    let op = inst & 0x7f;
    let rd = (inst >> 7) & 31;
    let funct3 = (inst >> 12) & 7;
    let rs1 = (inst >> 15) & 31;
    let rs2 = (inst >> 20) & 31;
    let funct7 = inst >> 25;
    let i_imm = sext(inst >> 20, 12);
    match op {
        OP_IMM => match funct3 {
            0 => format!("addi {}, {}, {}", reg(rd), reg(rs1), i_imm),
            1 => format!("slli {}, {}, {}", reg(rd), reg(rs1), rs2),
            4 => format!("xori {}, {}, {}", reg(rd), reg(rs1), i_imm),
            5 if funct7 == 0 => format!("srli {}, {}, {}", reg(rd), reg(rs1), rs2),
            5 => format!("srai {}, {}, {}", reg(rd), reg(rs1), rs2),
            6 => format!("ori {}, {}, {}", reg(rd), reg(rs1), i_imm),
            7 => format!("andi {}, {}, {}", reg(rd), reg(rs1), i_imm),
            _ => format!(".word {inst:#x}"),
        },
        OP => {
            let name = match (funct7, funct3) {
                (0, 0) => "add",
                (0x20, 0) => "sub",
                (0, 1) => "sll",
                (0, 3) => "sltu",
                (0, 4) => "xor",
                (0, 5) => "srl",
                (0x20, 5) => "sra",
                (0, 6) => "or",
                (0, 7) => "and",
                (1, 0) => "mul",
                (1, 3) => "mulhu",
                (1, 4) => "div",
                (1, 5) => "divu",
                (1, 6) => "rem",
                (1, 7) => "remu",
                _ => return format!(".word {inst:#x}"),
            };
            format!("{name} {}, {}, {}", reg(rd), reg(rs1), reg(rs2))
        }
        LUI => format!("lui {}, {}", reg(rd), sext(inst >> 12, 20)),
        AUIPC => format!("auipc {}, {}", reg(rd), sext(inst >> 12, 20)),
        JAL => format!("jal {}, {}", reg(rd), j_off(inst)),
        JALR => format!("jalr {}, {}, {}", reg(rd), reg(rs1), i_imm),
        BRANCH => {
            let name = match funct3 {
                0 => "beq",
                1 => "bne",
                4 => "blt",
                5 => "bge",
                6 => "bltu",
                7 => "bgeu",
                _ => return format!(".word {inst:#x}"),
            };
            format!("{name} {}, {}, {}", reg(rs1), reg(rs2), b_off(inst))
        }
        LOAD => {
            let name = match funct3 {
                0 => "lb",
                1 => "lh",
                2 => "lw",
                4 => "lbu",
                5 => "lhu",
                _ => return format!(".word {inst:#x}"),
            };
            format!("{name} {}, {}({})", reg(rd), i_imm, reg(rs1))
        }
        STORE => {
            let name = match funct3 {
                0 => "sb",
                1 => "sh",
                2 => "sw",
                _ => return format!(".word {inst:#x}"),
            };
            let imm = s_off(inst);
            format!("{name} {}, {}({})", reg(rs2), imm, reg(rs1))
        }
        _ => format!(".word {inst:#x}"),
    }
}

fn b_off(inst: u32) -> i32 {
    let b12 = (inst >> 31) & 1;
    let b11 = (inst >> 7) & 1;
    let b10_5 = (inst >> 25) & 0x3f;
    let b4_1 = (inst >> 8) & 0xf;
    let imm = (b12 << 12) | (b11 << 11) | (b10_5 << 5) | (b4_1 << 1);
    sext(imm, 13)
}

fn j_off(inst: u32) -> i32 {
    let b20 = (inst >> 31) & 1;
    let b10_1 = (inst >> 21) & 0x3ff;
    let b11 = (inst >> 20) & 1;
    let b19_12 = (inst >> 12) & 0xff;
    let imm = (b20 << 20) | (b19_12 << 12) | (b11 << 11) | (b10_1 << 1);
    sext(imm, 21)
}

fn s_off(inst: u32) -> i32 {
    let hi = (inst >> 25) & 0x7f;
    let lo = (inst >> 7) & 0x1f;
    sext((hi << 5) | lo, 12)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_encodings() {
        assert_eq!(addi(1, 0, -1), 0xfff0_0093);
        assert_eq!(addi(0, 0, 0), 0x0000_0013);
        assert_eq!(lui(2, 0x12345), 0x1234_5137);
        assert_eq!(auipc(1, 1), 0x0000_1097);
        assert_eq!(jal(0, 8), 0x0080_006f);
        assert_eq!(jal(0, 16), 0x0100_006f);
        assert_eq!(beq(0, 0, 8), 0x0000_0463);
        assert_eq!(jalr(0, RA, 0), 0x0000_8067);
    }

    #[test]
    fn branch_offset_roundtrip() {
        for off in [-4096, -8, 0, 8, 16, 2048, 4094] {
            let word = beq(A0, A1, off);
            assert_eq!(b_off(word), off, "{word:#x}");
        }
    }

    #[test]
    fn pc_rel_split_covers_sign() {
        for off in [-4096, -8, 0, 8, 2048, 4096, 5000] {
            let (hi, lo) = split_pc_rel(off);
            assert_eq!(hi.wrapping_shl(12).wrapping_add(lo), off);
            assert!((-2048..2048).contains(&lo));
        }
    }
}
