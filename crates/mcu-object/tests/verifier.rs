use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

#[test]
fn a_success_exit_without_a_pass_withdraws_the_previously_published_object() {
    let dir = tempfile::tempdir().unwrap();
    let raw = dir.path().join("raw.o");
    let published = dir.path().join("accepted.o");
    let checker = dir.path().join("prevail");
    fs::write(&published, b"previously accepted").unwrap();
    fs::write(&raw, b"unverified").unwrap();
    fs::write(
        &checker,
        "#!/bin/sh\nif [ \"$1\" = -l ]; then echo '# section=xdp function=entry'; fi\n",
    )
    .unwrap();
    fs::set_permissions(&checker, fs::Permissions::from_mode(0o755)).unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_mcu-object"))
        .arg("bpf-verify")
        .arg("--checker")
        .arg(checker)
        .arg("--input")
        .arg(&raw)
        .arg("--output")
        .arg(&published)
        .status()
        .unwrap();
    assert!(!status.success());
    assert!(!published.exists());
    assert_eq!(fs::read(raw).unwrap(), b"unverified");
}
