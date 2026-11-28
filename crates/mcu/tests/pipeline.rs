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

fn build(dir: &Path, extra: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mcu"));
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
    // The accepted object is an exact copy of the raw compiler output. Ninja
    // should repair just a damaged branch and skip execution on invalid input.
    let root = root();
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("build with spaces");
    let checker = mock(
        tmp.path(),
        "#!/bin/sh\nif [ \"$1\" = -l ]; then echo '# section=xdp function=firewall'; else echo 'PASS: xdp/firewall'; fi\n",
    );
    let build = || {
        let mut cmd = build(&dir, &["-c", "firewall"]);
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
    let report_path = formal.join("report.md");
    fs::write(&report_path, "forged nonempty report\n").unwrap();
    let repaired = success(&mut build());
    assert!(repaired.contains("REPORT") && !repaired.contains("JIT IMAGE"));
    let report = fs::read_to_string(&report_path).unwrap();
    assert!(report.contains("## RV32IM\n\n### jit"));
    assert!(report.contains("## RV32IMC\n\n### llvm-aot"));
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
    fs::write(&index, "not a program index").unwrap();
    fs::write(&jit, "untrusted cached image").unwrap();
    let repaired = success(&mut build());
    assert!(repaired.contains("BPF COMPILE") && repaired.contains("BPF VERIFY"));
    assert_eq!(fs::read(&jit).unwrap(), original_jit);
    let preserved = fs::read(dir.join("build.ninja")).unwrap();
    let source = root.join("experiments/firewall/firewall.c");
    let dup = tmp.path().join("firewall.c");
    fs::copy(&source, &dup).unwrap();
    let sentinel = tmp.path().join("ninja-started");
    let ninja = tmp.path().join("fake ninja");
    fs::write(&ninja, "#!/bin/sh\ntouch \"$NINJA_SENTINEL\"\n").unwrap();
    fs::set_permissions(&ninja, fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_mcu"))
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
    // Real PREVAIL must accept the normal matrix subset and refuse invalid BPF
    // while withdrawing every deployable output for the rejected program.
    let root = root();
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("smoke");
    success(&mut build(
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
        let output = build(&dir, &["--bpf-only", "--inputs", source.to_str().unwrap()])
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
    let output = build(&dir, &["--bpf-only", "--inputs", c.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("undeclared dependency"));
    assert!(
        !dir.join("illegal_header/objects/illegal_header_bpf.o")
            .exists()
    );
    // Replace a previously accepted real program with an ELF that PREVAIL
    // actually lists as two XDP entries.
    let source = tmp.path().join("just_drop.c");
    fs::write(&source, "#include <bpf/bpf_helpers.h>\nSEC(\"xdp\") int one(struct xdp_md *ctx) { (void)ctx; return XDP_DROP; }\nSEC(\"xdp1\") int two(struct xdp_md *ctx) { (void)ctx; return XDP_PASS; }\nchar LICENSE[] SEC(\"license\") = \"GPL\";\n").unwrap();
    let duplicate = build(&dir, &["--inputs", source.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&duplicate.stdout);
    assert!(
        !duplicate.status.success()
            && stdout.contains("expected one XDP entry")
            && stdout.contains("section=xdp function=one")
            && stdout.contains("section=xdp1 function=two"),
        "{stdout}"
    );
    assert!(!dir.join("just_drop/index.toml").exists());
    assert!(!dir.join("just_drop/objects/just_drop_bpf.o").exists());
    assert!(!dir.join("just_drop/images/jit.bin").exists());
    assert!(
        dir.join("intermediates/just_drop/just_drop_bpf.o")
            .is_file()
    );
    assert_eq!(mcu_index::verify_tree(&dir).unwrap().len(), 2);
}

fn built_binary(root: &Path, package: &str, name: &str) -> PathBuf {
    let mut cmd = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    cmd.current_dir(root).args([
        "build",
        "--quiet",
        "--locked",
        "-p",
        package,
        "--message-format=json",
    ]);
    success(&mut cmd)
        .lines()
        .find_map(|line| {
            let value: serde_json::Value = serde_json::from_str(line).ok()?;
            (value["target"]["name"] == name)
                .then(|| value["executable"].as_str().map(PathBuf::from))
                .flatten()
        })
        .unwrap_or_else(|| panic!("Cargo did not produce {name}"))
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
    let ninja = base.join("ninja observed after build");
    let original_ninja = b"#!/bin/sh\nexec \"$MCU_TEST_REAL_NINJA\" \"$@\"\n";
    fs::write(&ninja, original_ninja).unwrap();
    fs::set_permissions(&ninja, fs::Permissions::from_mode(0o755)).unwrap();
    success(build(&built, &[]).env("LIBBPF_MCU_NINJA", &ninja).env(
        "MCU_TEST_REAL_NINJA",
        std::env::var_os("LIBBPF_MCU_NINJA").unwrap_or_else(|| "ninja".into()),
    ));
    // The graph still names this Ninja path. Replacing its contents makes the
    // digest collected by prepare unsuitable as evidence of what built the images.
    let replacement = b"#!/bin/sh\nexit 97\n";
    fs::write(&ninja, replacement).unwrap();
    let tools = built_binary(&root, "mcu-dev-tools", "tools");
    let object = built_binary(&root, "mcu-object", "mcu-object");
    let programs = mcu::program_sources(&root).unwrap();
    for source in &programs {
        let name = mcu_image::program_name(source).unwrap();
        assert_eq!(
            fs::read(source).unwrap(),
            image_bytes(&built.join(name), &format!("{name}.c"))
        );
    }
    success(
        Command::new(&tools)
            .env("TMPDIR", &sys_temp)
            .args(["release", "prepare", "--build-dir"])
            .arg(&built)
            .arg("--archive-dir")
            .arg(&archives),
    );
    success(
        Command::new(&tools)
            .env("TMPDIR", &sys_temp)
            .args(["release", "verify", "--build-dir"])
            .arg(&built)
            .arg("--archive-dir")
            .arg(&archives)
            .arg("--unpack-dir")
            .arg(&unpacked),
    );
    let ledger: serde_json::Value =
        serde_json::from_slice(&fs::read(archives.join("release.json")).unwrap()).unwrap();
    assert_eq!(ledger["schema"], "libbpf-mcu.release.v2");
    assert!(ledger.get("commit").is_none() && ledger.get("toolchain").is_none());
    let observations = &ledger["archive_preparation"];
    assert_eq!(
        observations["graph_sha256"],
        mcu_image::sha256_hex(&fs::read(built.join("build.ninja")).unwrap())
    );
    assert_eq!(observations["checkout_commit"].as_str().unwrap().len(), 40);
    assert_eq!(
        observations["graph_tools"]["ninja"]["sha256"],
        mcu_image::sha256_hex(replacement)
    );
    assert_ne!(
        observations["graph_tools"]["ninja"]["sha256"],
        mcu_image::sha256_hex(original_ninja)
    );
    for name in [
        "clang", "lld", "objdump", "ninja", "prevail", "object", "jit",
    ] {
        let field = &observations["graph_tools"][name];
        assert_eq!(field["sha256"].as_str().unwrap().len(), 64);
        assert!(Path::new(field["path"].as_str().unwrap()).is_absolute());
    }
    let remaining = fs::read_dir(&sys_temp)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert!(
        remaining.is_empty(),
        "release left temporary paths {remaining:?}"
    );
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
                    Command::new(&object)
                        .args(["bind", "--program-dir"])
                        .arg(&minimal)
                        .args(["--mode", mode.name()])
                        .args(target)
                        .arg("--output")
                        .arg(&bound),
                );
                success(
                    Command::new(&tools)
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
    println!("Compared 48 complete bound containers against independent direct links");

    let firewall = unpacked.join("firewall");
    let mismatched = base.join("mismatched-aot");
    fs::create_dir(&mismatched).unwrap();
    let rejected = Command::new(&object)
        .arg("image-aot")
        .arg("--program")
        .arg("firewall")
        .arg("--input")
        .arg(firewall.join("objects/firewall_bpf.o"))
        .arg("--reference")
        .arg(built.join("just_drop/objects/just_drop_rv32.o"))
        .arg("--elf")
        .arg(built.join("intermediates/just_drop/just_drop_rv32.elf"))
        .arg("--output-dir")
        .arg(&mismatched)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("missing the BPF map"));
    assert!(fs::read_dir(&mismatched).unwrap().next().is_none());

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
    let rejected = Command::new(&object)
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

    // A consistent tamper of both site lists passes their cross-check.
    // The full archive verifier must still consult the independent RV32 object.
    let layout_path = image_paths(Mode::Aot).1;
    fs::copy(minimal.join(&layout_path), firewall.join(&layout_path)).unwrap();
    index
        .mode
        .iter_mut()
        .find(|row| row.name == Mode::Aot)
        .unwrap()
        .fixup_sites = Some(layout.sites());
    index.write(&firewall).unwrap();
    let rejected = Command::new(&object)
        .args(["verify", "--build-dir"])
        .arg(&firewall)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("reference object's relocation inventory"),
        "{}",
        String::from_utf8_lossy(&rejected.stderr)
    );
}
