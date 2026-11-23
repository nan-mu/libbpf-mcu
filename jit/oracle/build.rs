use std::env;
use std::path::PathBuf;
use std::process::Command;

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
    let sources = root.join("jit/scripts/xdp-sources.txt");
    println!("cargo:rerun-if-changed={}", sources.display());
    for path in ["tests/xdp", "tests/unused/exec_common.h", "include-bpf"] {
        println!("cargo:rerun-if-changed={}", root.join(path).display());
    }
    for path in std::fs::read_to_string(sources).unwrap().lines() {
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
