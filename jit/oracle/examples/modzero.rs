//! Attribute a random failure to the ALU32 mod/div-by-zero high-bit question.
//!
//! `cargo run --manifest-path jit/oracle/Cargo.toml --release --example modzero`
//!
//! The experiment inserts `mov32 dst, dst` after every ALU32 MOD/DIV. For a
//! nonzero divisor both engines already zero-extend, so the insertion is a
//! no-op there. For a zero divisor it forces the JIT's rule (keep low 32, clear
//! high 32) onto rbpf. If a failing case becomes identical after the insertion,
//! the whole difference flowed through that rule and nothing else.
//!
//! This changes no verdict in the suite. It is a diagnostic for the open
//! ALU32 question, not a fix for either engine.

use xpost_jit::isa::*;
use xpost_jit::Insn;
use xpost_jit_oracle::{fuzz, probes, run};

fn is_lddw(i: Insn) -> bool {
    i.class() == CLASS_LD && i.size() == SIZE_DW && i.mode() == MODE_IMM
}

fn force_zero_extend(insns: &[Insn]) -> Vec<Insn> {
    let mut wide = vec![false; insns.len()];
    let mut pc = 0;
    while pc < insns.len() {
        if is_lddw(insns[pc]) {
            wide[pc + 1] = true;
            pc += 2;
        } else {
            pc += 1;
        }
    }
    let mut out: Vec<Insn> = Vec::new();
    let mut map = vec![0usize; insns.len() + 1];
    for pc in 0..insns.len() {
        map[pc] = out.len();
        out.push(insns[pc]);
        let i = insns[pc];
        if !wide[pc] && i.class() == CLASS_ALU && matches!(i.op(), ALU_MOD | ALU_DIV) {
            out.push(Insn {
                code: CLASS_ALU | ALU_MOV | SRC_X,
                dst: i.dst,
                src: i.dst,
                off: 0,
                imm: 0,
            });
        }
    }
    map[insns.len()] = out.len();
    for pc in 0..insns.len() {
        let i = insns[pc];
        let jumps = matches!(i.class(), CLASS_JMP | CLASS_JMP32)
            && !matches!(i.op(), JMP_EXIT | JMP_CALL);
        if !jumps {
            continue;
        }
        let target = (pc as i32 + 1 + i.off as i32) as usize;
        let at = map[pc];
        out[at].off = (map[target] as i32 - at as i32 - 1) as i16;
    }
    out
}

fn high32_only(o: &run::Outcome) -> bool {
    let (j, r) = match (&o.jit.mem, &o.oracle.mem) {
        (Some(j), Some(r)) => (j, r),
        _ => return false,
    };
    let lo = run::DATA as usize;
    (0..probes::SCRATCH).step_by(8).all(|k| {
        let jv = u64::from_le_bytes(j[lo + k..lo + k + 8].try_into().unwrap());
        let rv = u64::from_le_bytes(r[k..k + 8].try_into().unwrap());
        jv as u32 == rv as u32
    }) && o.jit.r0.map(|v| v as u32) == o.oracle.r0.map(|v| v as u32)
}

/// A broken offset remap could make the transformed program exit early and
/// leave both memories zero, which would pass for the wrong reason. Require
/// every jump to land on the same instruction it landed on before.
fn remap_preserves_targets(orig: &[Insn], out: &[Insn]) -> bool {
    let mut wide = vec![false; orig.len()];
    let mut pc = 0;
    while pc < orig.len() {
        if is_lddw(orig[pc]) {
            wide[pc + 1] = true;
            pc += 2;
        } else {
            pc += 1;
        }
    }
    let mut map = vec![0usize; orig.len() + 1];
    let mut n = 0;
    for pc in 0..orig.len() {
        map[pc] = n;
        n += 1;
        if !wide[pc]
            && orig[pc].class() == CLASS_ALU
            && matches!(orig[pc].op(), ALU_MOD | ALU_DIV)
        {
            n += 1;
        }
    }
    if n != out.len() {
        return false;
    }
    for pc in 0..orig.len() {
        let i = orig[pc];
        let jumps =
            matches!(i.class(), CLASS_JMP | CLASS_JMP32) && !matches!(i.op(), JMP_EXIT | JMP_CALL);
        if !jumps {
            continue;
        }
        let target = (pc as i32 + 1 + i.off as i32) as usize;
        let at = map[pc];
        let landed = (at as i32 + 1 + out[at].off as i32) as usize;
        // The target may itself be a jump, whose off is legitimately rewritten.
        let same = |a: Insn, b: Insn| (a.code, a.dst, a.src, a.imm) == (b.code, b.dst, b.src, b.imm);
        if landed != map[target] || !same(out[landed], orig[target]) {
            return false;
        }
    }
    true
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let seeds: Vec<u64> = if args.is_empty() {
        (1..=2000).collect()
    } else {
        args.iter().map(|s| s.parse().unwrap()).collect()
    };
    let mut failing = 0;
    let mut explained = 0;
    let mut unexplained = Vec::new();
    for seed in seeds {
        let insns = fuzz::program(seed, 16);
        let base = run::check_probe(&insns, probes::SCRATCH);
        if base.status != run::Status::Fail {
            continue;
        }
        failing += 1;
        let transformed = force_zero_extend(&insns);
        if !remap_preserves_targets(&insns, &transformed) {
            println!("seed{seed:<5} BAD REMAP: jump targets changed, result discarded");
            unexplained.push(seed);
            continue;
        }
        let forced = run::check_probe(&transformed, probes::SCRATCH);
        let ok = forced.status == run::Status::Pass;
        let low = high32_only(&base);
        println!(
            "seed{seed:<5} baseline={:?} high32_only={low} forced_zero_extend={:?} {}",
            base.status,
            forced.status,
            if ok { "EXPLAINED" } else { "NOT EXPLAINED" }
        );
        if ok {
            explained += 1;
        } else {
            unexplained.push(seed);
            println!("    residual: {}", forced.detail);
        }
    }
    println!("\n{failing} failing seeds, {explained} explained by the ALU32 mod/div-by-zero rule");
    if !unexplained.is_empty() {
        println!("not explained: {unexplained:?}");
    }
}