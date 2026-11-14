//! Reproduce one random case and show exactly which bytes differ.
//!
//! `cargo run --manifest-path jit/oracle/Cargo.toml --example fuzzcase -- 428`

use xpost_jit::isa::*;
use xpost_jit_oracle::{fuzz, probes, run};

fn main() {
    let seed: u64 = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "428".into())
        .parse()
        .unwrap();
    let insns = fuzz::program(seed, 16);
    println!("seed {seed}, {} insns", insns.len());
    for (pc, i) in insns.iter().enumerate() {
        let note = if (i.class() == CLASS_ALU || i.class() == CLASS_ALU64)
            && (i.op() == ALU_MOD || i.op() == ALU_DIV)
        {
            " <-- div/mod"
        } else {
            ""
        };
        println!(
            "  {pc:3} code={:#04x} dst={} src={} off={} imm={}{}",
            i.code, i.dst, i.src, i.off, i.imm, note
        );
    }
    let o = run::check_probe(&insns, probes::SCRATCH);
    println!("status {:?} blame {} detail {}", o.status, o.blame, o.detail);
    println!("jit r0 {:?} rbpf r0 {:?}", o.jit.r0, o.oracle.r0);
    if let (Some(j), Some(r)) = (&o.jit.mem, &o.oracle.mem) {
        for k in (0..probes::SCRATCH).step_by(8) {
            let jv = u64::from_le_bytes(j[run::DATA as usize + k..run::DATA as usize + k + 8].try_into().unwrap());
            let rv = u64::from_le_bytes(r[k..k + 8].try_into().unwrap());
            if jv != rv {
                println!(
                    "  scratch+{k:3} (r{}): jit {:#018x} rbpf {:#018x}  low32 equal {}",
                    k / 8,
                    jv,
                    rv,
                    (jv as u32) == (rv as u32)
                );
            }
        }
    }
}
