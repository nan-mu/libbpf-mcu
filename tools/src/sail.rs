use std::{fs, path::Path, process::Command};

use anyhow::{Context, Result, ensure};

const TARGET: &[&str] = &[
    "--target=riscv32-unknown-none-elf",
    "-march=rv32imc",
    "-mabi=ilp32",
    "-mno-relax",
    "-nostdlib",
    "-ffreestanding",
];

fn run(command: &mut Command) -> Result<()> {
    let status = command
        .status()
        .with_context(|| format!("run {command:?}"))?;
    ensure!(status.success(), "{command:?} exited with {status}");
    Ok(())
}

pub fn link(
    root: &Path,
    source: &Path,
    entry: &str,
    work: &Path,
    output: Option<&Path>,
    clang: &Path,
) -> Result<()> {
    fs::create_dir_all(work)?;
    let runtime = root.join("linker/sail");
    let program_object = work.join("sail-program.o");
    let runtime_object = work.join("sail-runtime.o");
    for (input, object) in [
        (source, &program_object),
        (&runtime.join("runtime.c"), &runtime_object),
    ] {
        let mut compile = Command::new(clang);
        compile.args(TARGET).args([
            "-c",
            "-O2",
            "-mcmodel=medany",
            "-fno-builtin",
            "-fno-exceptions",
            "-fno-asynchronous-unwind-tables",
        ]);
        if input == source {
            compile
                .arg("-I")
                .arg(root.join("include"))
                .args(["-include", "vmlinux.h"]);
        }
        run(compile.arg(input).arg("-o").arg(object))?;
    }
    let default = work.join("sail-rv32.elf");
    let output = output.unwrap_or(&default);
    run(Command::new(clang)
        .args(TARGET)
        .args(["-fuse-ld=lld", "-Xlinker", "-T", "-Xlinker"])
        .arg(runtime.join("sail-rv32.ld"))
        .arg("-Xlinker")
        .arg(format!("--defsym=xdp_prog1={entry}"))
        .args(["-Wl,--build-id=none", "-Wl,--no-pie"])
        .arg(program_object)
        .arg(runtime_object)
        .arg("-o")
        .arg(output))?;
    println!("{}", output.display());
    Ok(())
}
