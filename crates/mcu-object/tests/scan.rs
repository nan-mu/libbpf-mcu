use std::{fs, process::Command};
use xpost_elf::{ImageMetadataV0, build_container};

#[test]
fn scan_reports_verified_metadata_and_keeps_silent_default() {
    let metadata = ImageMetadataV0 {
        slot_address: 0x2000,
        helper_address: 0x1000,
        machine: 1,
        name: "test_image".try_into().unwrap(),
        maps: Default::default(),
    };
    let blob = build_container(b"image", &metadata, None).unwrap();
    let path = std::env::temp_dir().join(format!("xpost-scan-{}.elf", std::process::id()));
    fs::write(&path, blob.as_slice()).unwrap();
    let scan = |json: bool| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_mcu-object"));
        cmd.arg("scan").arg(&path);
        if json {
            cmd.arg("--json");
        }
        cmd.output().unwrap()
    };
    let plain = scan(false);
    assert!(plain.status.success());
    assert!(plain.stdout.is_empty());
    let output = scan(true);
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value,
        serde_json::json!({"name":"test_image", "slot_address":0x2000, "helper_address":0x1000, "machine":1})
    );
    fs::write(&path, b"invalid").unwrap();
    assert!(!scan(true).status.success());
    fs::remove_file(path).unwrap();
}
