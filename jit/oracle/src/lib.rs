//! Differential test of `xpost-jit` against the independent `rbpf` interpreter.
//!
//! The eBPF oracle is rbpf, a fork of qmonnet/rbpf v0.4.1 that lives outside
//! this repository. It shares no code and no reading of RFC 9669 with the JIT
//! or with `jit/src/bpf_vm.rs`.

pub mod ctx;
pub mod fuzz;
pub mod probes;
pub mod report;
pub mod run;
pub mod rv;

pub use run::{check_probe, check_program, Outcome, Status};

pub fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
