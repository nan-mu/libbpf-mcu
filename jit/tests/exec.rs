//! Run the JIT image and check the register result.
//!
//! The RV32 interpreter lives in the library. These expected values are the
//! eBPF results, not a second copy of the lowering.

use std::collections::HashMap;

use xpost_jit::isa::*;
use xpost_jit::{compile, disassemble, Insn};
const MEM: usize = 0x4_0000;

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
    let stop = xpost_jit::run_rv(code, a0, vec![0; MEM], None)?;
    Ok((stop.a0, stop.a1))
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

#[test]
fn rejects_bad_lddw_and_a_branch_into_it() {
    let bad = [
        i(CLASS_LD | SIZE_DW | MODE_IMM, 0, 0, 0, 1),
        i(alu64(ALU_MOV, SRC_K), 0, 0, 0, 1),
        i(jmp64(JMP_EXIT, 0), 0, 0, 0, 0),
    ];
    let msg = compile(&bad, &HashMap::new()).unwrap_err().to_string();
    assert!(msg.contains("second word"), "{msg}");

    let into = [
        i(CLASS_LD | SIZE_DW | MODE_IMM, 1, 0, 0, 1),
        i(0, 0, 0, 0, 0),
        i(jmp64(JMP_JA, 0), 0, 0, -2, 0),
        i(jmp64(JMP_EXIT, 0), 0, 0, 0, 0),
    ];
    let msg = compile(&into, &HashMap::new()).unwrap_err().to_string();
    assert!(msg.contains("second word of lddw"), "{msg}");
}

#[test]
fn unknown_alu_and_bad_reg_are_errors() {
    let bad_op = [
        i(0xe7, 0, 0, 0, 1),
        i(jmp64(JMP_EXIT, 0), 0, 0, 0, 0),
    ];
    let caught = std::panic::catch_unwind(|| compile(&bad_op, &HashMap::new()));
    let err = caught.expect("compile panicked").unwrap_err();
    assert!(err.to_string().contains("unsupported"), "{err}");

    let bad_reg = [
        i(alu64(ALU_MOV, SRC_K), 15, 0, 0, 1),
        i(jmp64(JMP_EXIT, 0), 0, 0, 0, 0),
    ];
    let msg = compile(&bad_reg, &HashMap::new()).unwrap_err().to_string();
    assert!(msg.contains("register"), "{msg}");
}

#[test]
fn bpf_to_bpf_call_is_refused() {
    let p = [
        i(jmp64(JMP_CALL, SRC_X), 0, 1, 0, 1),
        i(jmp64(JMP_EXIT, 0), 0, 0, 0, 0),
    ];
    let msg = compile(&p, &HashMap::new()).unwrap_err().to_string();
    assert!(msg.contains("bpf-to-bpf"), "{msg}");
}
