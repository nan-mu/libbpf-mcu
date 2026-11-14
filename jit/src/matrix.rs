//! Compile-support matrix. A row records whether `compile` accepts the
//! opcode. It does not record whether the differential test has run.

use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::bpf::*;
use crate::compile::{self, JitError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub group: &'static str,
    pub op: String,
    pub src: &'static str,
    pub width: &'static str,
    pub compile: String,
}

pub fn rows() -> Vec<Row> {
    let mut out = Vec::new();
    for (group, class) in [("alu32", CLASS_ALU), ("alu64", CLASS_ALU64)] {
        for &(name, op) in ALU {
            for (src_name, src) in [("k", SRC_K), ("x", SRC_X)] {
                let code = class | op | src;
                let insn = Insn {
                    code,
                    dst: 0,
                    src: if src == SRC_X { 1 } else { 0 },
                    off: 0,
                    imm: if op == ALU_END { 32 } else { 1 },
                };
                out.push(Row {
                    group,
                    op: name.to_string(),
                    src: src_name,
                    width: if class == CLASS_ALU64 { "64" } else { "32" },
                    compile: classify(&[insn, exit()]),
                });
            }
        }
    }
    for (group, class) in [("jmp64", CLASS_JMP), ("jmp32", CLASS_JMP32)] {
        for &(name, op) in JMP {
            for (src_name, src) in [("k", SRC_K), ("x", SRC_X)] {
                if matches!(op, JMP_JA | JMP_CALL | JMP_EXIT) && src == SRC_X {
                    continue;
                }
                let code = class | op | src;
                let insn = Insn {
                    code,
                    dst: 0,
                    src: if src == SRC_X { 1 } else { 0 },
                    off: 0,
                    imm: if op == JMP_CALL { 1 } else { 0 },
                };
                let prog = if op == JMP_EXIT {
                    vec![insn]
                } else {
                    vec![insn, exit()]
                };
                out.push(Row {
                    group,
                    op: name.to_string(),
                    src: src_name,
                    width: if class == CLASS_JMP { "64" } else { "32" },
                    compile: classify(&prog),
                });
            }
        }
    }
    let lddw = [
        Insn {
            code: CLASS_LD | SIZE_DW | MODE_IMM,
            dst: 0,
            src: 0,
            off: 0,
            imm: 1,
        },
        Insn {
            code: 0,
            dst: 0,
            src: 0,
            off: 0,
            imm: 0,
        },
        exit(),
    ];
    out.push(Row {
        group: "ld",
        op: "lddw".into(),
        src: "k",
        width: "64",
        compile: classify(&lddw),
    });
    for (name, size) in [("b", SIZE_B), ("h", SIZE_H), ("w", SIZE_W), ("dw", SIZE_DW)] {
        let ldx = Insn {
            code: CLASS_LDX | size | MODE_MEM,
            dst: 0,
            src: 1,
            off: 0,
            imm: 0,
        };
        out.push(Row {
            group: "ldx",
            op: "mem".into(),
            src: "x",
            width: name,
            compile: classify(&[ldx, exit()]),
        });
        let stx = Insn {
            code: CLASS_STX | size | MODE_MEM,
            dst: 10,
            src: 0,
            off: -8,
            imm: 0,
        };
        out.push(Row {
            group: "stx",
            op: "mem".into(),
            src: "x",
            width: name,
            compile: classify(&[stx, exit()]),
        });
    }
    let atomic = Insn {
        code: CLASS_STX | SIZE_W | MODE_ATOMIC,
        dst: 10,
        src: 0,
        off: -4,
        imm: 0,
    };
    out.push(Row {
        group: "stx",
        op: "atomic".into(),
        src: "x",
        width: "w",
        compile: classify(&[atomic, exit()]),
    });
    out
}

pub fn json() -> String {
    let mut out = String::from("[\n");
    for (i, row) in rows().into_iter().enumerate() {
        if i != 0 {
            out.push_str(",\n");
        }
        out.push_str(&format!(
            "  {{\"group\":\"{}\",\"op\":\"{}\",\"src\":\"{}\",\"width\":\"{}\",\"compile\":\"{}\"}}",
            row.group,
            row.op,
            row.src,
            row.width,
            escape(&row.compile)
        ));
    }
    out.push_str("\n]\n");
    out
}

fn classify(insns: &[Insn]) -> String {
    let owned = insns.to_vec();
    let result = catch_unwind(AssertUnwindSafe(|| {
        compile::compile(&owned, &HashMap::new())
    }));
    match result {
        Ok(Ok(_)) => "ok".into(),
        Ok(Err(e)) => match e {
            JitError::Unsupported { what, .. } => format!("unsupported:{what}"),
            other => format!("error:{}", other),
        },
        Err(_) => "panic".into(),
    }
}

fn exit() -> Insn {
    Insn {
        code: CLASS_JMP | JMP_EXIT,
        dst: 0,
        src: 0,
        off: 0,
        imm: 0,
    }
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

const ALU: &[(&str, u8)] = &[
    ("add", ALU_ADD),
    ("sub", ALU_SUB),
    ("mul", ALU_MUL),
    ("div", ALU_DIV),
    ("or", ALU_OR),
    ("and", ALU_AND),
    ("lsh", ALU_LSH),
    ("rsh", ALU_RSH),
    ("neg", ALU_NEG),
    ("mod", ALU_MOD),
    ("xor", ALU_XOR),
    ("mov", ALU_MOV),
    ("arsh", ALU_ARSH),
    ("end", ALU_END),
];

const JMP: &[(&str, u8)] = &[
    ("ja", JMP_JA),
    ("jeq", JMP_JEQ),
    ("jgt", JMP_JGT),
    ("jge", JMP_JGE),
    ("jset", JMP_JSET),
    ("jne", JMP_JNE),
    ("jsgt", JMP_JSGT),
    ("jsge", JMP_JSGE),
    ("call", JMP_CALL),
    ("exit", JMP_EXIT),
    ("jlt", JMP_JLT),
    ("jle", JMP_JLE),
    ("jslt", JMP_JSLT),
    ("jsle", JMP_JSLE),
];
