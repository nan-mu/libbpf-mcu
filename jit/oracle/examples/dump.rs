//! Dump the linked RV32 image and the helper trace for one program.
//!
//! `cargo run --manifest-path jit/oracle/Cargo.toml --example dump -- xdp_drop`

use std::collections::HashMap;
use std::path::PathBuf;

use xpost_jit_oracle::run;

fn main() {
    let name = std::env::args().nth(1).unwrap_or_else(|| "xdp_drop".into());
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let obj = root.join("build").join(format!("{name}.bpf.o"));
    let src = xpost_jit::load_bpf(&obj, None).unwrap();
    println!("section {} insns {}", src.section, src.insns.len());
    let mut syms: Vec<_> = src.symbols.iter().collect();
    syms.sort();
    for (off, n) in syms {
        println!("reloc byte {off} (pc {}) -> {n}", off / 8);
    }
    for (pc, i) in src.insns.iter().enumerate() {
        println!("  bpf {pc:3} code={:#04x} dst={} src={} off={} imm={}", i.code, i.dst, i.src, i.off, i.imm);
    }

    let packet = xpost_jit_oracle::unhex(
        "00000000000000000000000008004500002c0000000040110000030000007f000001",
    );
    let image = xpost_jit::compile(&src.insns, &src.symbols).unwrap();
    println!("relocs: {}", image.relocs.len());
    for r in &image.relocs {
        println!("  {:?} rv_off={} bpf_pc={} symbol={:?}", r.kind, r.rv_off, r.bpf_pc, r.symbol);
    }
    let mut maps = HashMap::new();
    for n in src.symbols.values() {
        maps.entry(n.clone()).or_insert(0x3000u32);
    }
    println!("maps: {maps:?}");
    let code = xpost_jit::link(&image, &xpost_jit::LinkIn { helper: xpost_jit::HELPER, maps: &maps }).unwrap();
    println!("--- linked RV32 ({} words) ---", code.len());
    for (i, line) in xpost_jit::disassemble(&code, 0).lines().enumerate() {
        println!("{i:4} {line}");
    }
    let o = run::check_program(&src.insns, &src.symbols, &packet);
    println!("status {:?} detail {}", o.status, o.detail);
    println!("jit trace {:?}", o.jit.trace);
    println!("rbpf trace {:?}", o.oracle.trace);
}
