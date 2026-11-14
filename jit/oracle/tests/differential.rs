//! One entry point runs every suite and writes `results.json`.
//!
//! Run with `cargo test --manifest-path jit/oracle/Cargo.toml -- --nocapture`.

use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use xpost_jit::isa::*;
use xpost_jit::Insn;
use xpost_jit_oracle::report::{self, J};
use xpost_jit_oracle::run::{self, Status};
use xpost_jit_oracle::{fuzz, probes, unhex};

const DEFAULT_PACKET: &str = "00000000000000000000000008004500002c00000000401100007f0000017f000001";

const PROGRAMS: &[(&str, &str)] = &[
    ("div2", "0800000002000000"),
    ("xdp_drop", DEFAULT_PACKET),
    (
        "case_mark",
        "112233445566aabbccddeeff0800450000000000000000110000c00002017f00000104000400000800000000000000000000000000000000000000000000",
    ),
    ("just_drop", DEFAULT_PACKET),
    ("just_tx", DEFAULT_PACKET),
    ("firewall", DEFAULT_PACKET),
    (
        "bitswap",
        "0000000001000000785634120000000000000000000000000000000000000000",
    ),
    (
        "bsort",
        "0000000004000000040000000100000003000000020000000000000000000000",
    ),
];

/// Extra inputs that reach paths the check-xdp.sh packets do not: a map hit,
/// a zero divisor, and a truncated header.
const EXTRA: &[(&str, &str, &str)] = &[
    ("div2", "zero-divisor", "0800000000000000"),
    ("div2", "short", "0800"),
    (
        "firewall",
        "map-index-3",
        "00000000000000000000000008004500002c0000000040110000030000007f000001",
    ),
    (
        "xdp_drop",
        "map-index-3",
        "00000000000000000000000008004500002c0000000040110000030000007f000001",
    ),
    ("xdp_drop", "short", "0000"),
    ("bsort", "empty", "0000000000000000"),
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn program_suite(cases: &mut Vec<J>) {
    for (name, packet_hex) in PROGRAMS {
        run_program(cases, name, "check-xdp", packet_hex);
    }
    for (name, label, packet_hex) in EXTRA {
        run_program(cases, name, label, packet_hex);
    }
}

fn run_program(cases: &mut Vec<J>, name: &str, label: &str, packet_hex: &str) {
    let obj = root().join("build").join(format!("{name}.bpf.o"));
    let packet = unhex(packet_hex);
    let src = match xpost_jit::load_bpf(&obj, None) {
        Ok(s) => s,
        Err(e) => {
            cases.push(J::Obj(vec![
                ("suite", J::str("program")),
                ("name", J::str(format!("{name}/{label}"))),
                ("input", J::str(packet_hex)),
                ("status", J::str("unsupported")),
                ("detail", J::str(format!("load_bpf: {e}"))),
            ]));
            return;
        }
    };
    let outcome = run::check_program(&src.insns, &src.symbols, &packet);
    let watch = run::program_watch(&packet, &src.symbols);
    let pairs: Vec<_> = watch.iter().map(|w| (w.clone(), w.clone())).collect();
    cases.push(report::case(
        "program",
        &format!("{name}/{label}"),
        packet_hex,
        &outcome,
        &pairs,
    ));
}

fn probe_suite(cases: &mut Vec<J>) {
    let pairs = vec![(
        run::DATA as usize..run::DATA as usize + probes::SCRATCH,
        0..probes::SCRATCH,
    )];
    for p in probes::all() {
        let outcome = run::check_probe(&p.insns, probes::SCRATCH);
        cases.push(report::case("probe", &p.name, "boundary", &outcome, &pairs));
    }
}

fn fuzz_suite(cases: &mut Vec<J>) {
    let pairs = vec![(
        run::DATA as usize..run::DATA as usize + probes::SCRATCH,
        0..probes::SCRATCH,
    )];
    for seed in 1..=2000u64 {
        let insns = fuzz::program(seed, 16);
        let outcome = run::check_probe(&insns, probes::SCRATCH);
        cases.push(report::case(
            "random",
            &format!("seed{seed}"),
            &format!("seed={seed} ops=16"),
            &outcome,
            &pairs,
        ));
    }
}

fn ins(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
    Insn {
        code,
        dst,
        src,
        off,
        imm,
    }
}

fn exit() -> Insn {
    ins(CLASS_JMP | JMP_EXIT, 0, 0, 0, 0)
}

/// A negative case passes when the JIT returns `Err` and does not panic.
fn negative_suite(cases: &mut Vec<J>) {
    let mut reject: Vec<(String, Vec<Insn>)> = Vec::new();
    for (label, code) in [
        ("alu64-div-imm", CLASS_ALU64 | ALU_DIV | SRC_K),
        ("alu64-div-reg", CLASS_ALU64 | ALU_DIV | SRC_X),
        ("alu64-mod-imm", CLASS_ALU64 | ALU_MOD | SRC_K),
        ("alu64-mod-reg", CLASS_ALU64 | ALU_MOD | SRC_X),
        ("alu64-be64", CLASS_ALU64 | ALU_END | SRC_X),
        ("jmp32-ja", CLASS_JMP32 | JMP_JA),
        ("jmp32-call", CLASS_JMP32 | JMP_CALL),
        ("jmp32-exit", CLASS_JMP32 | JMP_EXIT),
        ("atomic-w", CLASS_STX | SIZE_W | MODE_ATOMIC),
        ("atomic-dw", CLASS_STX | SIZE_DW | MODE_ATOMIC),
        ("tail-call", CLASS_JMP | JMP_CALL),
        ("bpf-to-bpf", CLASS_JMP | JMP_CALL),
        ("ld-abs", CLASS_LD | SIZE_W | MODE_ABS),
        ("ld-ind", CLASS_LD | SIZE_W | MODE_IND),
        ("bad-opcode", 0xff),
    ] {
        let mut i = ins(code, 0, 1, 0, 1);
        if label == "alu64-be64" || label == "alu32-be64" {
            i.imm = 64;
        }
        if label == "tail-call" {
            i.src = 1;
            i.imm = 0;
        }
        if label == "bpf-to-bpf" {
            i.imm = 1;
        }
        reject.push((label.to_string(), vec![i, exit()]));
    }
    reject.push((
        "truncated-lddw".into(),
        vec![ins(CLASS_LD | SIZE_DW | MODE_IMM, 0, 0, 0, 1)],
    ));
    reject.push((
        "lddw-bad-second".into(),
        vec![
            ins(CLASS_LD | SIZE_DW | MODE_IMM, 0, 0, 0, 1),
            ins(0x07, 0, 0, 0, 0),
            exit(),
        ],
    ));
    reject.push(("empty".into(), vec![]));
    reject.push((
        "bad-dst-reg".into(),
        vec![ins(CLASS_ALU64 | ALU_MOV | SRC_K, 11, 0, 0, 1), exit()],
    ));
    reject.push((
        "bad-src-reg".into(),
        vec![ins(CLASS_ALU64 | ALU_ADD | SRC_X, 0, 12, 0, 0), exit()],
    ));
    // The eBPF spec forbids writing r10, but the JIT documents that it assumes
    // verifier-checked input and does not repeat verifier checks. Record what
    // it does rather than asserting a requirement it disclaims.
    let observe: Vec<(String, Vec<Insn>)> = vec![(
        "write-r10".into(),
        vec![ins(CLASS_ALU64 | ALU_MOV | SRC_K, 10, 0, 0, 1), exit()],
    )];
    for (label, prog) in observe {
        let empty = HashMap::new();
        let result = catch_unwind(AssertUnwindSafe(|| xpost_jit::compile(&prog, &empty)));
        let detail = match result {
            Err(_) => "compile panicked".to_string(),
            Ok(Ok(_)) => "compile accepted a write to r10; verifier-domain input, outside the JIT's stated contract".to_string(),
            Ok(Err(e)) => format!("compile rejected: {e}"),
        };
        cases.push(J::Obj(vec![
            ("suite", J::str("negative")),
            ("name", J::str(format!("observe/{label}"))),
            ("input", J::str("spec-invalid, verifier-domain")),
            ("status", J::str("unsupported")),
            ("blame", J::str("verifier-domain")),
            ("detail", J::str(detail)),
        ]));
    }

    for (label, prog) in reject {
        let empty = HashMap::new();
        let result = catch_unwind(AssertUnwindSafe(|| xpost_jit::compile(&prog, &empty)));
        let (status, detail) = match result {
            Err(_) => ("fail", "compile panicked".to_string()),
            Ok(Ok(_)) => (
                "fail",
                "compile accepted an input it must reject".to_string(),
            ),
            Ok(Err(e)) => ("pass", format!("compile rejected: {e}")),
        };
        cases.push(J::Obj(vec![
            ("suite", J::str("negative")),
            ("name", J::str(&label)),
            ("input", J::str("hand-built reject probe")),
            ("status", J::str(status)),
            ("detail", J::str(detail)),
        ]));
    }

    for (label, bytes) in [
        ("odd-length", vec![0x07u8, 0x00, 0x00]),
        ("empty-raw", vec![]),
        ("not-elf", vec![0x7f, b'E', b'L', b'F', 0x02]),
        ("truncated-elf", vec![0x7f, b'E', b'L', b'F']),
    ] {
        let dir = std::env::temp_dir().join(format!("xpost-oracle-neg-{label}"));
        std::fs::write(&dir, &bytes).unwrap();
        // An empty raw file decodes to zero instructions, which `compile`
        // rejects. The observable that matters is the whole pipeline.
        let result = catch_unwind(AssertUnwindSafe(|| {
            let src = xpost_jit::load_bpf(&dir, None)?;
            xpost_jit::compile(&src.insns, &src.symbols)
                .map(|_| ())
                .map_err(|e| xpost_jit::LoadError(e.to_string()))
        }));
        let _ = std::fs::remove_file(&dir);
        let (status, detail) = match result {
            Err(_) => ("fail", "the load/compile pipeline panicked".to_string()),
            Ok(Ok(_)) => ("fail", "the pipeline accepted malformed input".to_string()),
            Ok(Err(e)) => ("pass", format!("pipeline rejected: {e}")),
        };
        cases.push(J::Obj(vec![
            ("suite", J::str("negative")),
            ("name", J::str(format!("load/{label}"))),
            ("input", J::str("malformed file")),
            ("status", J::str(status)),
            ("detail", J::str(detail)),
        ]));
    }
}

#[test]
fn differential() {
    let mut cases = Vec::new();
    program_suite(&mut cases);
    probe_suite(&mut cases);
    fuzz_suite(&mut cases);
    negative_suite(&mut cases);

    let summary = report::summary(&cases);
    let doc = J::Obj(vec![
        (
            "oracle",
            J::str("rbpf v0.4.1 local fork at ../../../xpost/rbpf"),
        ),
        ("summary", summary),
        ("cases", J::Arr(cases.clone())),
    ]);
    let path = root().join("results.json");
    std::fs::write(&path, doc.to_json()).unwrap();

    println!("results: {}", path.display());
    if let J::Obj(fields) = &doc {
        for (k, v) in fields {
            if *k == "summary" {
                println!("summary: {}", v.to_json().trim());
            }
        }
    }
    let mut failures = 0;
    for c in &cases {
        if report::status_of(c) == Status::Fail {
            failures += 1;
            if failures <= 40 {
                println!("FAIL {}", c.to_json().trim());
            }
        }
    }
    let splits: Vec<_> = cases
        .iter()
        .filter(|c| {
            if let J::Obj(f) = c {
                return f
                    .iter()
                    .any(|(k, v)| *k == "executor_split" && !matches!(v, J::Null));
            }
            false
        })
        .collect();
    for s in splits.iter().take(10) {
        println!("EXECUTOR SPLIT {}", s.to_json().trim());
    }
    assert_eq!(
        failures, 0,
        "{failures} differential failures; see results.json"
    );
    assert!(splits.is_empty(), "{} rv32 executor splits", splits.len());
}
