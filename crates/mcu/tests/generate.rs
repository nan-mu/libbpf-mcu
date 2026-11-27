use std::{fs, path::PathBuf};

use mcu::{Generate, Mode, Tools};

#[test]
fn generate_describes_the_verification_gate_without_running_a_tool() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let build = root.join("build/generate test");
    let tools = Tools {
        clang: "/not an executable/clang".into(),
        lld: "/not an executable/ld.lld".into(),
        objdump: "/not an executable/llvm-objdump".into(),
        ninja: "/not an executable/ninja".into(),
        prevail: "/not an executable/prevail".into(),
        object: "/not an executable/mcu-object".into(),
        jit: "/not an executable/mcu-jit".into(),
    };
    let output = Generate {
        root: &root,
        build: &build,
        sources: &[root.join("tests/diagnostics/xdp_drop.c")],
        modes: &[] as &[Mode],
        tools: &tools,
    }
    .run()
    .unwrap();
    let graph = fs::read_to_string(output.graph).unwrap();
    assert!(graph.contains("BPF COMPILE"));
    assert!(graph.contains("BPF VERIFY"));
    assert!(graph.contains("intermediates/xdp_drop/xdp_drop_bpf.o"));
    assert!(graph.contains("objects/xdp_drop_bpf.o"));
    assert!(graph.contains("'/not an executable/clang'"));
    assert!(!graph.contains("llvm-aot.bin"));
    assert!(!build.join("xdp_drop/objects/xdp_drop_bpf.o").exists());
}
