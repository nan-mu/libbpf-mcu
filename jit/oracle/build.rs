use std::env;
use std::path::PathBuf;
use std::process::Command;

const PROGRAMS: &[&str] = &[
    "div2",
    "xdp_drop",
    "case_mark",
    "just_drop",
    "just_tx",
    "firewall",
    "bitswap",
    "bsort",
];

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let root = manifest.join("../..").canonicalize().unwrap();
    let out = manifest.join("build");
    std::fs::create_dir_all(&out).unwrap();

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
    for name in PROGRAMS {
        let src = root.join("tests/xdp").join(format!("{name}.c"));
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
    println!(
        "cargo:rerun-if-changed={}",
        root.join("include-bpf/vmlinux.h").display()
    );
}
