//! Host-side eBPF → RV32IM compiler.
//!
//! `mcu-jit diagnostic compile <in> -o <out.rv32> [--section name] [--repeat n] [--disasm]`
//!
//! `<in>` is raw eBPF words or an ELF (`bpf.o`). `-` reads stdin.
//! The machine code is not linked. Relocations go to `<out>` with the
//! extension replaced by `.reloc`.
//!
//! `--repeat` times only `compile`, not file IO. The reported numbers are the
//! min, median, and max of those calls.

use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use xpost_jit::{compile, disassemble, load_bpf};

pub fn run(mut args: impl Iterator<Item = String>) -> Result<u8, String> {
    let cmd = args.next().ok_or_else(usage)?;
    if cmd == "matrix" {
        print!("{}", xpost_jit::support_json());
        return Ok(0);
    }
    if cmd == "check" {
        return check_cmd(args);
    }
    if cmd != "compile" {
        return Err(usage());
    }
    let mut input: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut section: Option<String> = None;
    let mut repeat: u32 = 1;
    let mut disasm = false;
    let mut rest = args.peekable();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "-o" => {
                output = Some(PathBuf::from(
                    rest.next()
                        .ok_or_else(|| "missing value for -o".to_string())?,
                ));
            }
            "--section" => {
                section = Some(
                    rest.next()
                        .ok_or_else(|| "missing value for --section".to_string())?,
                );
            }
            "--repeat" => {
                let v = rest
                    .next()
                    .ok_or_else(|| "missing value for --repeat".to_string())?;
                repeat = v
                    .parse()
                    .map_err(|_| format!("--repeat {v} is not a u32"))?;
                if repeat == 0 {
                    return Err("--repeat must be >= 1".into());
                }
            }
            "--disasm" => disasm = true,
            "-h" | "--help" => return Err(usage()),
            other if other.starts_with('-') => return Err(format!("unknown flag {other}")),
            other => {
                if input.is_some() {
                    return Err(format!("unexpected argument {other}"));
                }
                input = Some(PathBuf::from(other));
            }
        }
    }
    let input = input.ok_or_else(|| "missing input path".to_string())?;
    let output = output.ok_or_else(|| "missing -o".to_string())?;
    let src = load_bpf(&input, section.as_deref()).map_err(|e| e.to_string())?;
    let mut samples = Vec::with_capacity(repeat as usize);
    let mut image = None;
    for _ in 0..repeat {
        let start = Instant::now();
        let compiled = compile(&src.insns, &src.symbols).map_err(|e| e.to_string())?;
        samples.push(start.elapsed().as_nanos());
        image = Some(compiled);
    }
    let image = image.unwrap();
    samples.sort_unstable();
    let min = samples[0];
    let max = samples[samples.len() - 1];
    let mid = samples.len() / 2;
    let med = if samples.len() % 2 == 0 {
        samples[mid - 1].saturating_add(samples[mid]) / 2
    } else {
        samples[mid]
    };
    eprintln!(
        "section={} bpf_insns={} rv_insns={} bytes={} relocs={} repeat={} ns_min={} ns_med={} ns_max={}",
        src.section,
        src.insns.len(),
        image.code.len(),
        image.code.len() * 4,
        image.relocs.len(),
        repeat,
        min,
        med,
        max
    );
    if disasm {
        print!("{}", disassemble(&image.code, 0));
    }
    fs::write(&output, image.bytes()).map_err(|e| format!("write {}: {e}", output.display()))?;
    let reloc = output.with_extension("reloc");
    fs::write(&reloc, image.reloc_text()).map_err(|e| format!("write {}: {e}", reloc.display()))?;
    Ok(0)
}

fn check_cmd(args: impl Iterator<Item = String>) -> Result<u8, String> {
    let mut input: Option<PathBuf> = None;
    let mut section: Option<String> = None;
    let mut packet = vec![0u8; 64];
    let mut expected_packet = None;
    let mut expect_unchanged = false;
    let mut expected_return = None;
    let mut expected_array = None;
    let mut rest = args.peekable();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--section" => {
                section = Some(
                    rest.next()
                        .ok_or_else(|| "missing value for --section".to_string())?,
                );
            }
            "--packet" => {
                let hex = rest
                    .next()
                    .ok_or_else(|| "missing value for --packet".to_string())?;
                packet = parse_hex(&hex)?;
            }
            "--packet-file" | "--expect-packet-file" => {
                let path = rest
                    .next()
                    .ok_or_else(|| format!("missing value for {arg}"))?;
                let bytes = std::fs::read(&path).map_err(|e| format!("read {path}: {e}"))?;
                if arg == "--packet-file" {
                    packet = bytes;
                } else {
                    expected_packet = Some(bytes);
                }
            }
            "--expect-return" => {
                let value = rest.next().ok_or("missing value for --expect-return")?;
                expected_return = Some(
                    value
                        .parse()
                        .map_err(|_| format!("invalid return value {value}"))?,
                );
            }
            "--expect-unchanged" => expect_unchanged = true,
            "--expect-array-u32" => {
                let name = rest.next().ok_or("missing ARRAY name")?;
                let key = rest.next().ok_or("missing ARRAY key")?;
                let value = rest.next().ok_or("missing ARRAY value")?;
                expected_array = Some((
                    name,
                    key.parse()
                        .map_err(|_| format!("invalid ARRAY key {key}"))?,
                    value
                        .parse()
                        .map_err(|_| format!("invalid ARRAY value {value}"))?,
                ));
            }
            other if other.starts_with('-') => return Err(format!("unknown flag {other}")),
            other => {
                if input.is_some() {
                    return Err(format!("unexpected argument {other}"));
                }
                input = Some(PathBuf::from(other));
            }
        }
    }
    if expect_unchanged && expected_packet.is_some() {
        return Err("use either --expect-packet-file or --expect-unchanged".into());
    }
    let expected_bytes = if expect_unchanged {
        Some(packet.as_slice())
    } else {
        expected_packet.as_deref()
    };
    let expected = match (expected_bytes, expected_return) {
        (None, None) if expected_array.is_none() => None,
        (Some(bytes), Some(r0)) => Some(xpost_jit::ExpectedPacket {
            r0,
            bytes,
            array: expected_array.as_ref().map(|(name, key, value)| {
                xpost_jit::ExpectedArrayValue {
                    name,
                    key: *key,
                    value: *value,
                }
            }),
        }),
        _ => {
            return Err(
                "pair --expect-return with --expect-packet-file or --expect-unchanged".into(),
            );
        }
    };
    let input = input.ok_or_else(|| "missing input path".to_string())?;
    let src = load_bpf(&input, section.as_deref()).map_err(|e| e.to_string())?;
    let report = xpost_jit::check_packet_with_expected(&src.insns, &src.symbols, &packet, expected);
    println!(
        "status={} section={} bpf_insns={} rv_bytes={} relocs={} r0={} detail={}",
        report.status,
        src.section,
        src.insns.len(),
        report.rv_bytes,
        report.relocs,
        report
            .r0
            .map(|v| format!("{v:#x}"))
            .unwrap_or_else(|| "-".into()),
        report.detail
    );
    match report.status {
        "pass" => Ok(0),
        "unsupported" | "inconclusive" => Ok(2),
        _ => Ok(1),
    }
}

fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    let text: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if !text.len().is_multiple_of(2) {
        return Err("packet hex has an odd length".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn usage() -> String {
    "usage: mcu-jit diagnostic compile <in> -o <out.rv32> [--section name] [--repeat n] [--disasm]\n       mcu-jit diagnostic check <bpf.o> [--section name] [--packet hex | --packet-file path]\n                      [--expect-return value (--expect-packet-file path | --expect-unchanged)\n                       [--expect-array-u32 name key value]]\n       mcu-jit diagnostic matrix".into()
}
