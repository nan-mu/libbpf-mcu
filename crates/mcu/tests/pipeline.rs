use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn build(root: &Path, dir: &Path, extra: &[&str]) -> Command {
    let mut cmd = Command::new(root.join("mcu"));
    cmd.current_dir(dir.parent().unwrap())
        .arg("build")
        .args(extra)
        .arg("--build-dir")
        .arg(dir);
    cmd
}

fn success(cmd: &mut Command) -> String {
    let Output {
        status,
        stdout,
        stderr,
    } = cmd.output().unwrap();
    assert!(
        status.success(),
        "{cmd:?}: {status}\n{}\n{}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    String::from_utf8(stdout).unwrap()
}

fn mock(dir: &Path, script: &str) -> PathBuf {
    let path = dir.join("fake verifier");
    fs::write(&path, script).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[test]
#[ignore = "L2 requires Ninja and Clang"]
fn level2_incremental_gate_repairs_corruption_and_refuses_old_graph() {
    let root = root();
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("build with spaces");
    let checker = mock(
        tmp.path(),
        "#!/bin/sh\nif [ \"$1\" = -l ]; then echo '# section=xdp function=firewall'; else echo 'PASS: xdp/firewall'; fi\n",
    );
    let build = || {
        let mut cmd = build(&root, &dir, &["-c", "firewall"]);
        cmd.env("PREVAIL", &checker);
        cmd
    };
    let first = success(&mut build());
    assert!(first.contains("BPF COMPILE") && first.contains("BPF VERIFY"));
    let raw = dir.join("intermediates/firewall/firewall_bpf.o");
    let formal = dir.join("firewall");
    let bpf = formal.join("objects/firewall_bpf.o");
    let listing = dir.join("intermediates/firewall/report/jit.txt");
    let index = formal.join("index.toml");
    let original = fs::read(&raw).unwrap();
    assert_eq!(fs::read(&bpf).unwrap(), original);
    let unchanged = fs::metadata(&raw).unwrap().modified().unwrap();
    assert!(success(&mut build()).contains("no work to do"));
    fs::remove_file(&listing).unwrap();
    let report = success(&mut build());
    assert!(
        report.contains("DISASSEMBLE") && report.contains("REPORT") && report.contains("INDEX")
    );
    assert!(!report.contains("BPF COMPILE") && !report.contains("JIT IMAGE"));
    let jit = formal.join("images/jit.bin");
    let original_jit = fs::read(&jit).unwrap();
    fs::write(&jit, b"corrupt").unwrap();
    let repaired = success(&mut build());
    assert!(repaired.contains("JIT IMAGE") && !repaired.contains("BPF COMPILE"));
    assert_eq!(fs::read(&jit).unwrap(), original_jit);
    mock(
        tmp.path(),
        "#!/bin/sh\nif [ \"$1\" = -l ]; then echo '# section=xdp function=firewall'; else echo 'PASS: xdp/firewall'; fi\n# updated checker\n",
    );
    let reverified = success(&mut build());
    assert!(reverified.contains("BPF VERIFY") && !reverified.contains("BPF COMPILE"));
    assert_eq!(fs::metadata(&raw).unwrap().modified().unwrap(), unchanged);
    fs::remove_file(&raw).unwrap();
    let rebuilt = success(&mut build());
    assert!(rebuilt.contains("BPF COMPILE") && rebuilt.contains("BPF VERIFY"));
    let preserved = fs::read(dir.join("build.ninja")).unwrap();
    let source = root.join("experiments/firewall/firewall.c");
    let dup = tmp.path().join("firewall.c");
    fs::copy(&source, &dup).unwrap();
    let sentinel = tmp.path().join("ninja-started");
    let ninja = tmp.path().join("fake ninja");
    fs::write(&ninja, "#!/bin/sh\ntouch \"$NINJA_SENTINEL\"\n").unwrap();
    fs::set_permissions(&ninja, fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(root.join("mcu"))
        .args(["build", "--inputs"])
        .arg(source)
        .arg(dup)
        .arg("--build-dir")
        .arg(&dir)
        .env("PREVAIL", &checker)
        .env("LIBBPF_MCU_NINJA", ninja)
        .env("NINJA_SENTINEL", &sentinel)
        .output()
        .unwrap();
    assert!(
        !output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains("duplicate program")
    );
    assert_eq!(fs::read(dir.join("build.ninja")).unwrap(), preserved);
    assert!(!sentinel.exists());
    mock(
        tmp.path(),
        "#!/bin/sh\nif [ \"$1\" = -l ]; then echo '# section=xdp function=firewall'; fi\n",
    );
    let rejected = build().output().unwrap();
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stdout).contains("did not report PASS")
            || String::from_utf8_lossy(&rejected.stderr).contains("did not report PASS")
    );
    assert!(!bpf.exists() && !index.exists() && !jit.exists());
    assert_eq!(fs::read(raw).unwrap(), original);
}

#[test]
#[ignore = "L3 requires real LLVM, PREVAIL and Ninja"]
fn level3_real_portable_smoke_and_rejection() {
    let root = root();
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("smoke");
    success(&mut build(
        &root,
        &dir,
        &["-c", "just_drop", "-c", "firewall", "-c", "copy"],
    ));
    let indexes = mcu_index::verify_tree(&dir).unwrap();
    assert_eq!(indexes.len(), 3);
    for index in indexes {
        assert_eq!(index.mode.len(), 3);
    }
    for fixture in ["xdp_oob_packet", "xdp_null_map_deref", "xdp_uninit_key"] {
        let source = root.join("tests/unused").join(format!("{fixture}.c"));
        let output = build(
            &root,
            &dir,
            &["--bpf-only", "--inputs", source.to_str().unwrap()],
        )
        .output()
        .unwrap();
        assert!(!output.status.success(), "{fixture} must fail verification");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("PREVAIL"),
            "{fixture}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(!dir.join(fixture).join("index.toml").exists());
        assert!(
            !dir.join(fixture)
                .join(format!("objects/{fixture}_bpf.o"))
                .exists()
        );
        assert!(
            dir.join("intermediates")
                .join(fixture)
                .join(format!("{fixture}_bpf.o"))
                .is_file()
        );
    }
    let c = tmp.path().join("illegal_header.c");
    fs::write(tmp.path().join("private.h"), "#define ACTION XDP_DROP\n").unwrap();
    fs::write(&c, "#include <bpf/bpf_helpers.h>\n#include \"private.h\"\nSEC(\"xdp\") int entry(struct xdp_md *ctx) { (void)ctx; return ACTION; }\nchar LICENSE[] SEC(\"license\") = \"GPL\";\n").unwrap();
    let output = build(
        &root,
        &dir,
        &["--bpf-only", "--inputs", c.to_str().unwrap()],
    )
    .output()
    .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("undeclared dependency"));
    assert!(
        !dir.join("illegal_header/objects/illegal_header_bpf.o")
            .exists()
    );
    assert_eq!(mcu_index::verify_tree(&dir).unwrap().len(), 3);
}

fn cargo(root: &Path, package: &str) -> Command {
    let mut cmd = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    cmd.current_dir(root)
        .args(["run", "--quiet", "--locked", "-p", package, "--"]);
    cmd
}

fn image_bytes(root: &Path, relative: &str) -> Vec<u8> {
    fs::read(root.join(relative)).unwrap()
}

#[test]
#[ignore = "L4 requires the full toolchain and a clean checkout"]
fn level4_archives_and_reference_links() {
    use mcu_image::Mode;
    use mcu_index::{Index, image_paths};

    let root = root();
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path();
    let built = base.join("build");
    let sys_temp = base.join("release temp");
    fs::create_dir(&sys_temp).unwrap();
    let archives = base.join("archives");
    let unpacked = base.join("unpacked");
    success(&mut build(&root, &built, &[]));
    let programs = mcu::program_sources(&root).unwrap();
    for source in &programs {
        let name = mcu_image::program_name(source).unwrap();
        assert_eq!(
            fs::read(source).unwrap(),
            image_bytes(&built.join(name), &format!("{name}.c"))
        );
    }
    success(
        cargo(&root, "mcu-dev-tools")
            .env("TMPDIR", &sys_temp)
            .args(["release", "prepare", "--build-dir"])
            .arg(&built)
            .arg("--archive-dir")
            .arg(&archives),
    );
    success(
        cargo(&root, "mcu-dev-tools")
            .env("TMPDIR", &sys_temp)
            .args(["release", "verify", "--build-dir"])
            .arg(&built)
            .arg("--archive-dir")
            .arg(&archives)
            .arg("--unpack-dir")
            .arg(&unpacked),
    );
    assert!(fs::read_dir(&sys_temp).unwrap().next().is_none());
    let indexes = mcu_index::verify_tree(&unpacked).unwrap();
    assert_eq!(indexes.len(), 12);
    let minimal = base.join("unpacked-binding-input");
    fs::create_dir(&minimal).unwrap();
    fs::create_dir(minimal.join("images")).unwrap();
    let work = built.join("intermediates/direct-reference");
    let mut total = 0;
    for index in indexes {
        let program = unpacked.join(&index.program);
        fs::copy(program.join("index.toml"), minimal.join("index.toml")).unwrap();
        assert_eq!(index.mode.len(), 3);
        for mode in [Mode::Aot, Mode::Jit] {
            let (bin, json) = image_paths(mode);
            for path in [bin, json] {
                fs::copy(program.join(&path), minimal.join(path)).unwrap();
            }
            for (slot, helper) in [("0x40380200", "0x40380000"), ("0x40381000", "0x4037f000")] {
                let target = [
                    "--slot-address",
                    slot,
                    "--slot-length",
                    "0x5000",
                    "--helper-address",
                    helper,
                ];
                let bound = base.join("bound.elf");
                let reference = base.join("ref.elf");
                success(
                    cargo(&root, "mcu-object")
                        .args(["bind", "--program-dir"])
                        .arg(&minimal)
                        .args(["--mode", mode.name()])
                        .args(target)
                        .arg("--output")
                        .arg(&bound),
                );
                success(
                    cargo(&root, "mcu-dev-tools")
                        .args(["reference", "--program-dir"])
                        .arg(&program)
                        .args(["--mode", mode.name()])
                        .args(target)
                        .arg("--work-dir")
                        .arg(work.join(&index.program).join(slot))
                        .arg("--output")
                        .arg(&reference),
                );
                assert!(
                    fs::read(&bound).unwrap() == fs::read(&reference).unwrap(),
                    "reference differs for {} {mode} at {slot}/{helper}",
                    index.program
                );
                total += 1;
            }
        }
    }
    assert_eq!(total, 48);

    let firewall = unpacked.join("firewall");
    let (bin, json) = image_paths(Mode::Aot);
    fs::copy(firewall.join(&bin), minimal.join(&bin)).unwrap();
    fs::copy(firewall.join("index.toml"), minimal.join("index.toml")).unwrap();
    let mut index = Index::read(&minimal).unwrap();
    let mut layout = mcu_image::Layout::read(&firewall.join(&json)).unwrap();
    assert!(!layout.fixups.is_empty());
    layout.fixups.remove(0);
    fs::write(minimal.join(&json), serde_json::to_vec(&layout).unwrap()).unwrap();
    let row = index
        .mode
        .iter_mut()
        .find(|row| row.name == Mode::Aot)
        .unwrap();
    row.layout = Some(mcu_index::Member::new(&minimal, json).unwrap());
    index.write(&minimal).unwrap();
    let denied = base.join("must-not-deploy.elf");
    let rejected = cargo(&root, "mcu-object")
        .args(["bind", "--program-dir"])
        .arg(&minimal)
        .args([
            "--mode",
            "llvm-aot",
            "--slot-address",
            "0x40380200",
            "--slot-length",
            "4096",
            "--helper-address",
            "0x40380000",
            "--output",
        ])
        .arg(&denied)
        .output()
        .unwrap();
    assert!(!rejected.status.success() && !denied.exists());
}
