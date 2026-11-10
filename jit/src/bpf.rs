//! eBPF instruction words. Little-endian 8-byte encoding.

pub const CLASS_LD: u8 = 0x00;
pub const CLASS_LDX: u8 = 0x01;
pub const CLASS_ST: u8 = 0x02;
pub const CLASS_STX: u8 = 0x03;
pub const CLASS_ALU: u8 = 0x04;
pub const CLASS_JMP: u8 = 0x05;
pub const CLASS_JMP32: u8 = 0x06;
pub const CLASS_ALU64: u8 = 0x07;

pub const SRC_K: u8 = 0x00;
pub const SRC_X: u8 = 0x08;

pub const SIZE_W: u8 = 0x00;
pub const SIZE_H: u8 = 0x08;
pub const SIZE_B: u8 = 0x10;
pub const SIZE_DW: u8 = 0x18;

pub const MODE_IMM: u8 = 0x00;
pub const MODE_ABS: u8 = 0x20;
pub const MODE_IND: u8 = 0x40;
pub const MODE_MEM: u8 = 0x60;
pub const MODE_ATOMIC: u8 = 0xc0;

pub const ALU_ADD: u8 = 0x00;
pub const ALU_SUB: u8 = 0x10;
pub const ALU_MUL: u8 = 0x20;
pub const ALU_DIV: u8 = 0x30;
pub const ALU_OR: u8 = 0x40;
pub const ALU_AND: u8 = 0x50;
pub const ALU_LSH: u8 = 0x60;
pub const ALU_RSH: u8 = 0x70;
pub const ALU_NEG: u8 = 0x80;
pub const ALU_MOD: u8 = 0x90;
pub const ALU_XOR: u8 = 0xa0;
pub const ALU_MOV: u8 = 0xb0;
pub const ALU_ARSH: u8 = 0xc0;
pub const ALU_END: u8 = 0xd0;

pub const JMP_JA: u8 = 0x00;
pub const JMP_JEQ: u8 = 0x10;
pub const JMP_JGT: u8 = 0x20;
pub const JMP_JGE: u8 = 0x30;
pub const JMP_JSET: u8 = 0x40;
pub const JMP_JNE: u8 = 0x50;
pub const JMP_JSGT: u8 = 0x60;
pub const JMP_JSGE: u8 = 0x70;
pub const JMP_CALL: u8 = 0x80;
pub const JMP_EXIT: u8 = 0x90;
pub const JMP_JLT: u8 = 0xa0;
pub const JMP_JLE: u8 = 0xb0;
pub const JMP_JSLT: u8 = 0xc0;
pub const JMP_JSLE: u8 = 0xd0;

pub const REG_FP: u8 = 10;

/// `lddw` whose immediate is not a constant: map fd, map value, subprog, …
pub const PSEUDO_MAP_FD: u8 = 1;
pub const PSEUDO_CALL: u8 = 1;

pub const NOSPEC: u8 = CLASS_ST | MODE_ATOMIC;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    pub code: u8,
    pub dst: u8,
    pub src: u8,
    pub off: i16,
    pub imm: i32,
}

impl Insn {
    pub fn class(self) -> u8 {
        self.code & 0x07
    }

    pub fn op(self) -> u8 {
        self.code & 0xf0
    }

    pub fn src_is_reg(self) -> bool {
        self.code & SRC_X != 0
    }

    pub fn size(self) -> u8 {
        self.code & 0x18
    }

    pub fn mode(self) -> u8 {
        self.code & 0xe0
    }
}

pub fn decode_insns(bytes: &[u8]) -> Result<Vec<Insn>, String> {
    if bytes.len() % 8 != 0 {
        return Err(format!(
            "eBPF bytecode length {} is not a multiple of 8",
            bytes.len()
        ));
    }
    let mut out = Vec::with_capacity(bytes.len() / 8);
    for chunk in bytes.chunks_exact(8) {
        let regs = chunk[1];
        out.push(Insn {
            code: chunk[0],
            dst: regs & 0x0f,
            src: regs >> 4,
            off: i16::from_le_bytes([chunk[2], chunk[3]]),
            imm: i32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_one_word() {
        // mov64 r0, 1
        let mut raw = [0u8; 8];
        raw[0] = CLASS_ALU64 | ALU_MOV | SRC_K;
        raw[1] = 0;
        raw[4] = 1;
        let insns = decode_insns(&raw).unwrap();
        assert_eq!(insns[0].imm, 1);
        assert_eq!(insns[0].op(), ALU_MOV);
        assert!(!insns[0].src_is_reg());
    }
}
