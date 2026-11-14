//! Differential tests. Expected values come from the eBPF reference, not from
//! a previous run of the JIT.

use std::collections::HashMap;

use xpost_jit::isa::*;
use xpost_jit::{compare, support_json, write_map, Insn, KIND_ARRAY};

const MEM_BYTES: usize = 0x4_0000;

fn insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
    Insn { code, dst, src, off, imm }
}

fn words(dst: u8, value: u64) -> [Insn; 2] {
    [
        insn(CLASS_LD | SIZE_DW | MODE_IMM, dst, 0, 0, value as i32),
        insn(0, 0, 0, 0, (value >> 32) as i32),
    ]
}

fn exit() -> Insn {
    insn(CLASS_JMP | JMP_EXIT, 0, 0, 0, 0)
}

fn run(prog: &[Insn]) {
    let mem = vec![0u8; MEM_BYTES];
    let report = compare(prog, &HashMap::new(), &HashMap::new(), &mem, 0, &[]);
    assert_eq!(report.status, "pass", "{}", report.detail);
}

fn alu_reg(class: u8, op: u8, a: u64, b: u64) {
    let mut prog = Vec::new();
    prog.extend(words(0, a));
    prog.extend(words(1, b));
    prog.push(insn(class | op | SRC_X, 0, 1, 0, 0));
    prog.push(exit());
    run(&prog);
}

fn alu_imm(class: u8, op: u8, a: u64, imm: i32) {
    let mut prog = Vec::new();
    prog.extend(words(0, a));
    prog.push(insn(class | op | SRC_K, 0, 0, 0, imm));
    prog.push(exit());
    run(&prog);
}

const VALS: [u64; 12] = [
    0,
    1,
    2,
    7,
    40,
    31,
    32,
    63,
    64,
    0x7fff_ffff,
    0x8000_0000,
    u64::MAX,
];

#[test]
fn alu_register_boundaries() {
    let ops = [
        ALU_ADD, ALU_SUB, ALU_MUL, ALU_OR, ALU_AND, ALU_XOR, ALU_LSH, ALU_RSH, ALU_ARSH, ALU_MOV,
    ];
    for op in ops {
        for a in VALS {
            for b in VALS {
                alu_reg(CLASS_ALU64, op, a, b);
                alu_reg(CLASS_ALU, op, a, b);
            }
        }
    }
}

#[test]
fn alu_immediate_boundaries() {
    let ops = [
        ALU_ADD, ALU_SUB, ALU_OR, ALU_AND, ALU_XOR, ALU_LSH, ALU_RSH, ALU_ARSH, ALU_MOV,
    ];
    let imms = [0, 1, 2, -1, 7, 31, 32, 40, 63, i32::MAX, i32::MIN];
    for op in ops {
        for a in VALS {
            for imm in imms {
                alu_imm(CLASS_ALU64, op, a, imm);
                alu_imm(CLASS_ALU, op, a, imm);
            }
        }
    }
}

#[test]
fn div_mod_signed_and_zero() {
    let pairs = [
        (13u32, 3u32),
        (13, 0),
        (0, 3),
        (u32::MAX, 2),
        (7, 2),
        (1, 1),
    ];
    for (a, b) in pairs {
        alu_reg(CLASS_ALU, ALU_DIV, u64::from(a), u64::from(b));
        alu_reg(CLASS_ALU, ALU_MOD, u64::from(a), u64::from(b));
        alu_imm(CLASS_ALU, ALU_DIV, u64::from(a), b as i32);
        alu_imm(CLASS_ALU, ALU_MOD, u64::from(a), b as i32);
    }
    // Signed, offset 1. -13 % 3 == -1 under truncated division.
    let mut prog = Vec::new();
    prog.extend(words(0, -13i32 as u32 as u64));
    prog.push(insn(CLASS_ALU | ALU_MOD | SRC_K, 0, 0, 1, 3));
    prog.push(exit());
    run(&prog);
    let mut prog = Vec::new();
    prog.extend(words(0, u64::from(i32::MIN as u32)));
    prog.push(insn(CLASS_ALU | ALU_DIV | SRC_K, 0, 0, 1, -1));
    prog.push(exit());
    run(&prog);
}

#[test]
fn jumps_on_signs_and_zero() {
    let vals = [0i64, 1, -1, 2, i32::MAX as i64, i32::MIN as i64, i64::MAX, i64::MIN];
    let ops = [
        JMP_JEQ, JMP_JNE, JMP_JGT, JMP_JGE, JMP_JLT, JMP_JLE, JMP_JSGT, JMP_JSGE, JMP_JSLT,
        JMP_JSLE, JMP_JSET,
    ];
    for op in ops {
        for a in vals {
            for b in vals {
                let mut prog = Vec::new();
                prog.push(insn(CLASS_ALU64 | ALU_MOV | SRC_K, 2, 0, 0, 1));
                prog.extend(words(0, a as u64));
                prog.extend(words(1, b as u64));
                prog.push(insn(CLASS_JMP | op | SRC_X, 0, 1, 1, 0));
                prog.push(insn(CLASS_ALU64 | ALU_MOV | SRC_K, 2, 0, 0, 0));
                prog.push(insn(CLASS_ALU64 | ALU_MOV | SRC_X, 0, 2, 0, 0));
                prog.push(exit());
                run(&prog);
            }
        }
    }
}

#[test]
fn array_lookup_matches() {
    let mut mem = vec![0u8; MEM_BYTES];
    write_map(&mut mem, 0x3000, KIND_ARRAY, 4, 8, 4, 0x4000).unwrap();
    mem[0x4000] = 0x2a;
    let mut symbols = HashMap::new();
    symbols.insert(0u64, "counter".into());
    let mut maps = HashMap::new();
    maps.insert("counter".into(), 0x3000);
    // r1 = map, r2 = &key, key = 0, call lookup, return the pointer.
    let prog = [
        insn(CLASS_LD | SIZE_DW | MODE_IMM, 1, PSEUDO_MAP_FD, 0, 0),
        insn(0, 0, 0, 0, 0),
        insn(CLASS_ALU64 | ALU_MOV | SRC_X, 2, REG_FP, 0, 0),
        insn(CLASS_ALU64 | ALU_ADD | SRC_K, 2, 0, 0, -4),
        insn(CLASS_ST | MODE_MEM | SIZE_W, REG_FP, 0, -4, 0),
        insn(CLASS_JMP | JMP_CALL, 0, 0, 0, 1),
        exit(),
    ];
    let report = compare(&prog, &symbols, &maps, &mem, 0, &[]);
    assert_eq!(report.status, "pass", "{}", report.detail);
    assert_eq!(report.r0, Some(0x4000));
}

#[test]
fn unaligned_word_roundtrip() {
    let mem = vec![0u8; MEM_BYTES];
    let prog = [
        insn(CLASS_ALU64 | ALU_MOV | SRC_K, 0, 0, 0, 0x1234_5678),
        insn(CLASS_STX | MODE_MEM | SIZE_W, 1, 0, 2, 0),
        insn(CLASS_LDX | MODE_MEM | SIZE_W, 0, 1, 2, 0),
        exit(),
    ];
    let report = compare(&prog, &HashMap::new(), &HashMap::new(), &mem, 0x1000, &[0x1000..0x1008]);
    assert_eq!(report.status, "pass", "{}", report.detail);
    assert_eq!(report.r0, Some(0x1234_5678));
}

#[test]
fn frame_is_592_bytes() {
    assert_eq!(xpost_jit::frame_bytes(), 592);
}

#[test]
fn alu32_bswap_widths() {
    // Both endian selections, all three widths, including the 64-bit case
    // that acts on the whole register (RFC 9669, section 4.2).
    for imm in [16, 32, 64] {
        for src in [SRC_K, SRC_X] {
            let prog = [
                insn(CLASS_LD | SIZE_DW | MODE_IMM, 0, 0, 0, 0x1234_5678),
                insn(0, 0, 0, 0, 0x9abc_def0u32 as i32),
                insn(CLASS_ALU | ALU_END | src, 0, 0, 0, imm),
                exit(),
            ];
            run(&prog);
        }
    }
    // The 64-bit swap must not truncate. lddw takes the low word first, so
    // 0x1234_5678_9abc_def0 reverses to 0xf0de_bc9a_7856_3412.
    let prog = [
        insn(CLASS_LD | SIZE_DW | MODE_IMM, 0, 0, 0, 0x9abc_def0u32 as i32),
        insn(0, 0, 0, 0, 0x1234_5678),
        insn(CLASS_ALU | ALU_END | SRC_X, 0, 0, 0, 64),
        exit(),
    ];
    let repo = compare(
        &prog,
        &HashMap::new(),
        &HashMap::new(),
        &vec![0u8; MEM_BYTES],
        0,
        &[],
    );
    assert_eq!(repo.status, "pass", "{}", repo.detail);
    assert_eq!(repo.r0, Some(0xf0de_bc9a_7856_3412));
}

#[test]
fn link_rejects_a_zero_or_missing_address() {
    let mut symbols = HashMap::new();
    symbols.insert(0u64, "counter".into());
    let prog = [
        insn(CLASS_LD | SIZE_DW | MODE_IMM, 1, PSEUDO_MAP_FD, 0, 0),
        insn(0, 0, 0, 0, 0),
        insn(CLASS_JMP | JMP_CALL, 0, 0, 0, 1),
        exit(),
    ];
    let image = xpost_jit::compile(&prog, &symbols).unwrap();
    let mut maps = HashMap::new();
    maps.insert("counter".to_string(), 0x3000u32);
    let zero = xpost_jit::link(
        &image,
        &xpost_jit::LinkIn {
            helper: 0,
            maps: &maps,
        },
    );
    assert!(zero.is_err());
    let missing = xpost_jit::link(
        &image,
        &xpost_jit::LinkIn {
            helper: xpost_jit::HELPER,
            maps: &HashMap::new(),
        },
    );
    assert!(missing.is_err());
    maps.insert("counter".into(), 0);
    let zero_map = xpost_jit::link(
        &image,
        &xpost_jit::LinkIn {
            helper: xpost_jit::HELPER,
            maps: &maps,
        },
    );
    assert!(zero_map.is_err());
}

#[test]
fn map_hit_increments_storage() {
    // After a helper call R1..R5 are unreadable, so the value pointer must be
    // loaded into R1 before it is used again.
    let mut mem = vec![0u8; MEM_BYTES];
    write_map(&mut mem, 0x3000, KIND_ARRAY, 4, 8, 256, 0x8000).unwrap();
    mem[0x8000 + 3 * 8] = 0x2a;
    let mut symbols = HashMap::new();
    symbols.insert(0u64, "counter".into());
    let mut maps = HashMap::new();
    maps.insert("counter".into(), 0x3000);
    let prog = [
        insn(CLASS_LD | SIZE_DW | MODE_IMM, 1, PSEUDO_MAP_FD, 0, 0),
        insn(0, 0, 0, 0, 0),
        insn(CLASS_ST | MODE_MEM | SIZE_W, REG_FP, 0, -4, 3),
        insn(CLASS_ALU64 | ALU_MOV | SRC_X, 2, REG_FP, 0, 0),
        insn(CLASS_ALU64 | ALU_ADD | SRC_K, 2, 0, 0, -4),
        insn(CLASS_JMP | JMP_CALL, 0, 0, 0, 1),
        insn(CLASS_JMP | JMP_JEQ | SRC_K, 0, 0, 4, 0),
        insn(CLASS_LDX | MODE_MEM | SIZE_DW, 1, 0, 0, 0),
        insn(CLASS_ALU64 | ALU_ADD | SRC_K, 1, 0, 0, 1),
        insn(CLASS_STX | MODE_MEM | SIZE_DW, 0, 1, 0, 0),
        insn(CLASS_ALU64 | ALU_MOV | SRC_X, 0, 1, 0, 0),
        insn(CLASS_JMP | JMP_EXIT, 0, 0, 0, 0),
    ];
    let report = compare(&prog, &symbols, &maps, &mem, 0, &[0x8000..0x8008]);
    assert_eq!(report.status, "pass", "{}", report.detail);
    assert_eq!(report.r0, Some(0x2b));
}

#[test]
fn support_matrix_does_not_panic() {
    let text = support_json();
    assert!(!text.contains("\"compile\":\"panic\""));
    assert!(text.contains("\"op\":\"div\""));
    assert!(text.contains("unsupported:alu64 div/mod"));
    assert!(text.contains("unsupported:atomic"));
}
