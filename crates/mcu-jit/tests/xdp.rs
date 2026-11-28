use std::{
    env, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

const PACKET: &str = "00000000000000000000000008004500002c00000000401100007f0000017f000001";

fn check(command: &mut Command, required: bool) {
    let output = command.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("{command:?}\n{stdout}");
    let status = output.status.code();
    assert!(
        (status == Some(0) && stdout.contains("status=pass"))
            || (!required
                && status == Some(2)
                && (stdout.contains("status=unsupported")
                    || stdout.contains("status=inconclusive"))),
        "{command:?}: {}\n{stdout}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn test_verifier(root: &Path) -> PathBuf {
    if let Some(path) = env::var_os("PREVAIL").filter(|value| !value.is_empty()) {
        return PathBuf::from(path);
    }
    let relative = Path::new("prevail/bin/prevail");
    let executable = |path: &Path| {
        path.metadata()
            .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
    };
    let local = root.join(relative);
    if executable(&local) {
        return local;
    }
    // A linked worktree can have an empty submodule while the main checkout
    // has the verifier already built.
    if let Ok(output) = Command::new("git")
        .current_dir(root)
        .args(["rev-parse", "--path-format=absolute", "--git-common-dir"])
        .output()
        && output.status.success()
        && let Ok(common_dir) = std::str::from_utf8(&output.stdout)
        && let Some(main) = Path::new(common_dir.trim_end_matches('\n')).parent()
    {
        let fallback = main.join(relative);
        if executable(&fallback) {
            return fallback;
        }
    }
    panic!("cannot find PREVAIL; set PREVAIL to a built verifier executable");
}

#[test]
#[ignore = "requires Clang with BPF support and real PREVAIL"]
fn verified_c_programs_match_xdp_packet_expectations() {
    // Known-answer fixtures compare the full response, with a separate map
    // assertion for just_tx. Truncation must preserve the packet. Other inputs
    // compare eBPF and JIT observations and retain unsupported as a distinct result.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let scratch = tempfile::tempdir().unwrap();
    let clang = env::var_os("LIBBPF_MCU_CLANG")
        .or_else(|| env::var_os("CLANG"))
        .map(PathBuf::from)
        .unwrap_or_else(mcu_project::preferred_clang);
    let verifier = test_verifier(&root);
    println!(
        "Clang: {}\nPREVAIL: {}",
        clang.display(),
        verifier.display()
    );
    let mut sources = mcu_project::program_sources(&root).unwrap();
    sources.extend(
        [
            "tests/unused/div2.c",
            "tests/unused/bitswap.c",
            "tests/diagnostics/xdp_drop.c",
        ]
        .map(|path| root.join(path)),
    );
    for source in sources {
        let name = source.file_stem().unwrap().to_str().unwrap();
        let object = scratch.path().join(format!("{name}.bpf.o"));
        let compile = Command::new(&clang)
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
            .arg(&source)
            .arg("-o")
            .arg(&object)
            .output()
            .unwrap();
        assert!(
            compile.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&compile.stderr)
        );
        mcu_bpf::verify(&verifier, &object).unwrap_or_else(|error| panic!("{name}: {error:#}"));
        let diagnostic = || {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_mcu-jit"));
            cmd.args(["diagnostic", "check"]).arg(&object);
            cmd
        };
        match name {
            "bsort" | "noop" | "copy" | "case_mark" | "just_tx" => {
                let network = matches!(name, "case_mark" | "just_tx");
                let fixtures = root.join(if network {
                    "tests/fixtures/network"
                } else {
                    "tests/fixtures/exb2"
                });
                let input = fixtures.join(format!("{name}.input.bin"));
                let mut full = diagnostic();
                full.arg("--packet-file")
                    .arg(&input)
                    .arg("--expect-packet-file")
                    .arg(fixtures.join(format!("{name}.expected.bin")))
                    .args(["--expect-return", if network { "3" } else { "2" }]);
                if name == "just_tx" {
                    full.args(["--expect-array-u32", "rxcnt", "17", "1"]);
                }
                check(&mut full, true);

                let mut short = diagnostic();
                match name {
                    "bsort" => {
                        let short_packet = scratch.path().join("short.bin");
                        fs::write(&short_packet, &fs::read(input).unwrap()[..8]).unwrap();
                        short.arg("--packet-file").arg(short_packet).args([
                            "--expect-unchanged",
                            "--expect-return",
                            "0",
                        ]);
                    }
                    "case_mark" => {
                        short.args(["--packet", "112233445566aabbccddeeff0800450000000000000000110000c00002017f00000104000400000800000000000000000000000000000000000000000000",
                            "--expect-unchanged", "--expect-return", "2"]);
                    }
                    "just_tx" => {
                        short.args([
                            "--packet",
                            PACKET,
                            "--expect-unchanged",
                            "--expect-return",
                            "2",
                            "--expect-array-u32",
                            "rxcnt",
                            "17",
                            "0",
                        ]);
                    }
                    _ => continue,
                }
                check(&mut short, true);
            }
            _ => {
                let packet = match name {
                    "div2" => "0800000002000000",
                    "bitswap" => "0000000001000000785634120000000000000000000000000000000000000000",
                    _ => PACKET,
                };
                check(diagnostic().args(["--packet", packet]), false);
            }
        }
    }
}
