//! One entry point runs every suite and writes `results.json`.
//!
//! Run with `cargo test --manifest-path jit/oracle/Cargo.toml -- --nocapture`.

use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use xpost_jit::isa::*;
use xpost_jit::{packet_world, ExpectedArrayValue, ExpectedPacket, Insn};
use xpost_jit_oracle::report::{self, J};
use xpost_jit_oracle::run::{self, Status};
use xpost_jit_oracle::{fuzz, hex, probes, unhex};

const DEFAULT_PACKET: &str = "00000000000000000000000008004500002c00000000401100007f0000017f000001";

const PROGRAMS: &[(&str, &str)] = &[
    ("div2", "0800000002000000"),
    ("xdp_drop", DEFAULT_PACKET),
    ("just_drop", DEFAULT_PACKET),
    ("firewall", DEFAULT_PACKET),
    (
        "bitswap",
        "0000000001000000785634120000000000000000000000000000000000000000",
    ),
];

const NETWORK: &[(&str, &str, usize)] = &[
    (
        "case_mark",
        "112233445566aabbccddeeff0800450000000000000000110000c00002017f00000104000400000800000000000000000000000000000000000000000000",
        82,
    ),
    ("just_tx", DEFAULT_PACKET, 74),
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
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn exb2_packets(cases: &mut Vec<J>) {
    let fixtures = root().join("../../tests/fixtures/exb2");
    for name in ["bsort", "noop", "copy"] {
        let input = std::fs::read(fixtures.join(format!("{name}.input.bin"))).unwrap();
        let expected = std::fs::read(fixtures.join(format!("{name}.expected.bin"))).unwrap();
        assert_eq!(input.len(), 8258);
        for (label, packet, expected, action) in [
            ("full", input.as_slice(), expected.as_slice(), 2),
            ("short", &input[..8], &input[..8], 0),
        ] {
            run_program(
                cases,
                name,
                label,
                packet,
                Some(ExpectedPacket {
                    r0: action,
                    bytes: expected,
                    array: None,
                }),
            );
        }
    }
}

fn exb2_kernel_answers(cases: &mut Vec<J>) {
    // Known one-round answers from the protocol and small inputs. The two
    // executors must both match the full expected packet, including digest.
    let caseset: &[(&str, u32, u32, &[u8], u32, u32)] = &[
        ("prime", 1, 10, &[], 4, 7),
        ("log2", 2, 3, &[1, 0, 0, 0, 8, 0, 0, 0, 64, 0, 0, 0], 9, 136),
        ("fletcher32", 4, 3, &[1, 0, 2], 0x0004_0003, 0),
        ("strcmp", 6, 2, b"ab\0ac\0", u32::MAX, 2),
    ];
    fn field(packet: &mut [u8], at: usize, value: u32) {
        packet[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    for &(name, task, n, input, lo, hi) in caseset {
        let mut packet = vec![0u8; 8258];
        packet[0..8].copy_from_slice(b"EXB2\x02\x00\x40\x00");
        field(&mut packet, 8, task);
        field(&mut packet, 12, n);
        field(&mut packet, 16, 1);
        field(&mut packet, 28, input.len() as u32);
        field(&mut packet, 36, u32::MAX);
        packet[64..64 + input.len()].copy_from_slice(input);
        let mut expected = packet.clone();
        for (at, value) in [
            (36, 0),
            (40, 1),
            (44, lo),
            (48, hi),
            (
                52,
                (0x811c_9dc5u32.rotate_left(5) ^ lo).wrapping_add(hi ^ 0x9e37_79b9),
            ),
        ] {
            field(&mut expected, at, value);
        }
        run_program(
            cases,
            name,
            "known-answer",
            &packet,
            Some(ExpectedPacket {
                r0: 2,
                bytes: &expected,
                array: None,
            }),
        );
    }
}

fn network_packets(cases: &mut Vec<J>) {
    let fixtures = root().join("../../tests/fixtures/network");
    for &(name, short, len) in NETWORK {
        let input = std::fs::read(fixtures.join(format!("{name}.input.bin"))).unwrap();
        let expected = std::fs::read(fixtures.join(format!("{name}.expected.bin"))).unwrap();
        let short = unhex(short);
        assert_eq!(input.len(), len);
        for (label, packet, bytes, r0, count) in [
            ("full", input.as_slice(), expected.as_slice(), 3, 1),
            ("short", short.as_slice(), short.as_slice(), 2, 0),
        ] {
            let array = (name == "just_tx").then_some(ExpectedArrayValue {
                name: "rxcnt",
                key: 17,
                value: count,
            });
            run_program(
                cases,
                name,
                label,
                packet,
                Some(ExpectedPacket { r0, bytes, array }),
            );
        }
    }
}

fn program_suite(cases: &mut Vec<J>) {
    for (name, packet_hex) in PROGRAMS {
        run_program(cases, name, "check-xdp", &unhex(packet_hex), None);
    }
    for (name, label, packet_hex) in EXTRA {
        run_program(cases, name, label, &unhex(packet_hex), None);
    }
    exb2_packets(cases);
    exb2_kernel_answers(cases);
    network_packets(cases);
}

fn run_program(
    cases: &mut Vec<J>,
    name: &str,
    label: &str,
    packet: &[u8],
    expected: Option<ExpectedPacket<'_>>,
) {
    let obj = root().join("build").join(format!("{name}.bpf.o"));
    let name = format!("{name}/{label}");
    let packet_hex = hex(packet);
    let src = match xpost_jit::load_bpf(&obj, None) {
        Ok(s) => s,
        Err(e) => {
            cases.push(J::Obj(vec![
                ("suite", J::str("program")),
                ("name", J::str(name)),
                ("input", J::str(packet_hex)),
                (
                    "status",
                    J::str(if expected.is_some() {
                        "fail"
                    } else {
                        "unsupported"
                    }),
                ),
                ("detail", J::str(format!("load_bpf: {e}"))),
            ]));
            return;
        }
    };
    let mut outcome = run::check_program(&src.insns, &src.symbols, packet);
    let layout = packet_world(packet, &src.symbols).ok();
    let watch = layout
        .as_ref()
        .map_or(&[][..], |world| world.watch.as_slice());
    let pairs: Vec<_> = watch.iter().map(|w| (w.clone(), w.clone())).collect();
    let expectation = expected.map(|expected| {
        let no_maps = HashMap::new();
        let maps = layout.as_ref().map_or(&no_maps, |world| &world.maps);
        let observe = |side: &run::Side| {
            let data = run::DATA as usize;
            expected.observe(
                side.r0,
                side.mem.as_deref(),
                data..data + packet.len(),
                maps,
            )
        };
        let jit = observe(&outcome.jit);
        let oracle = observe(&outcome.oracle);
        let mut detail = format!(
            "expected r0={} bytes={} jit_r0={:?} jit_bytes={} rbpf_r0={:?} rbpf_bytes={}",
            expected.r0,
            expected.bytes.len(),
            jit.r0,
            jit.bytes_match,
            oracle.r0,
            oracle.bytes_match,
        );
        let array = expected.array.as_ref().map_or(J::Null, |array| {
            detail.push_str(&format!(
                " {}[{}] expected={} jit={:?} rbpf={:?}",
                array.name, array.key, array.value, jit.array_value, oracle.array_value,
            ));
            J::Obj(vec![
                ("map", J::str(array.name)),
                ("key", J::Num(i64::from(array.key))),
                ("expected", J::Num(i64::from(array.value))),
                (
                    "jit",
                    jit.array_value.map_or(J::Null, |v| J::Num(i64::from(v))),
                ),
                (
                    "oracle",
                    oracle.array_value.map_or(J::Null, |v| J::Num(i64::from(v))),
                ),
            ])
        });
        if outcome.status != Status::Pass || !expected.matches(&jit) || !expected.matches(&oracle) {
            outcome.status = Status::Fail;
            outcome.blame = "open";
            outcome.diffs.push(detail.clone());
        }
        outcome.detail = format!("{}; {detail}", outcome.detail);
        J::Obj(vec![
            ("return", J::Num(expected.r0 as i64)),
            ("size_bytes", J::Num(expected.bytes.len() as i64)),
            ("jit_bytes_match", J::Bool(jit.bytes_match)),
            ("oracle_bytes_match", J::Bool(oracle.bytes_match)),
            ("array", array),
        ])
    });
    let mut case = report::case("program", &name, &packet_hex, &outcome, &pairs);
    if let (Some(expectation), J::Obj(fields)) = (expectation, &mut case) {
        fields.push(("expectation", expectation));
    }
    cases.push(case);
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
