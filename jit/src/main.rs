//! Host-side eBPF → RV32IM compiler.
//!
//! `xpost-jit compile <in> -o <out.rv32> [--section name] [--repeat n] [--disasm]`
//!
//! `<in>` is raw eBPF words or an ELF (`bpf.o`). `-` reads stdin.
//! The machine code is not linked. Relocations go to `<out>` with the
//! extension replaced by `.reloc`.
//!
//! `--repeat` times only `compile`, not file IO. The reported numbers are the
//! min, median, and max of those calls.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use xpost_jit::{compile, disassemble, load_bpf};

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("xpost-jit: {e}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<u8, String> {
    let mut args = env::args().skip(1);
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
    let mut rest = args.peekable();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--section" => {
                section = Some(rest.next().ok_or_else(|| "missing value for --section".to_string())?);
            }
            "--packet" => {
                let hex = rest.next().ok_or_else(|| "missing value for --packet".to_string())?;
                packet = parse_hex(&hex)?;
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
    let input = input.ok_or_else(|| "missing input path".to_string())?;
    let src = load_bpf(&input, section.as_deref()).map_err(|e| e.to_string())?;
    let report = xpost_jit::check_packet(&src.insns, &src.symbols, &packet);
    println!(
        "status={} section={} bpf_insns={} rv_bytes={} relocs={} r0={} detail={}",
        report.status,
        src.section,
        src.insns.len(),
        report.rv_bytes,
        report.relocs,
        report.r0.map(|v| format!("{v:#x}")).unwrap_or_else(|| "-".into()),
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
    if text.len() % 2 != 0 {
        return Err("packet hex has an odd length".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn usage() -> String {
    "usage: xpost-jit compile <in> -o <out.rv32> [--section name] [--repeat n] [--disasm]\n       xpost-jit check <bpf.o> [--section name] [--packet hex]\n       xpost-jit matrix".into()
}
