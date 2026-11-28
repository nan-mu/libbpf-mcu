use std::env;
use std::path::PathBuf;
use std::process::Command;

// The Oracle retains its own fixed set of BPF inputs.
const SOURCES: &[&str] = &[
    "tests/unused/div2.c",
    "tests/diagnostics/xdp_drop.c",
    "experiments/case/case_mark.c",
    "experiments/just_drop/just_drop.c",
    "experiments/just_tx/just_tx.c",
    "experiments/firewall/firewall.c",
    "tests/unused/bitswap.c",
    "experiments/exec_bench/bsort.c",
    "experiments/exec_bench/noop.c",
    "experiments/exec_bench/copy.c",
    "experiments/exec_bench/prime.c",
    "experiments/exec_bench/log2.c",
    "experiments/exec_bench/fletcher32.c",
    "experiments/exec_bench/strcmp.c",
];

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let root = manifest.join("../..").canonicalize().unwrap();
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());

    let clang = env::var("CLANG").unwrap_or_else(|_| {
        let brew = "/opt/homebrew/opt/llvm/bin/clang";
        if PathBuf::from(brew).exists() {
            brew.to_string()
        } else {
            "clang".to_string()
        }
    });

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CLANG");
    println!(
        "cargo:rerun-if-changed={}",
        root.join("include-bpf").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        root.join("tests/unused/exec_common.h").display()
    );
    for path in SOURCES {
        let src = root.join(path);
        let name = src.file_stem().unwrap().to_str().unwrap();
        let obj = out.join(format!("{name}.bpf.o"));
        println!("cargo:rerun-if-changed={}", src.display());
        let status = Command::new(&clang)
            .args([
                "--target=bpf",
                "-O2",
                "-g",
                "-Wall",
                "-Wno-missing-declarations",
                "-fno-stack-protector",
                "-I",
            ])
            .arg(root.join("include-bpf"))
            .args(["-include", "vmlinux.h", "-c"])
            .arg(&src)
            .arg("-o")
            .arg(&obj)
            .status()
            .unwrap_or_else(|e| panic!("spawn {clang}: {e}"));
        assert!(status.success(), "clang failed on {}", src.display());
    }
}
