mod integrity;

use std::{
    collections::BTreeMap,
    env, fs,
    io::{self, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf, absolute},
    process::Command,
};

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use mcu::{Generate, Mode, Tools};
use mcu_image::program_name;

#[derive(Parser)]
#[command(about = "Build ESP32-C3 XDP program artifacts")]
struct Cli {
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Generate the Ninja graph and build the selected programs.
    Build {
        #[arg(short = 'c', long, conflicts_with = "inputs", value_name = "STEM")]
        program: Vec<String>,
        #[arg(long, num_args = 1.., value_name = "FILE")]
        inputs: Vec<PathBuf>,
        #[arg(long, value_delimiter = ',', conflicts_with = "bpf_only")]
        modes: Vec<Mode>,
        #[arg(long)]
        bpf_only: bool,
        #[arg(long)]
        build_dir: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Remove the selected build directory.
    Clean {
        #[arg(long)]
        build_dir: Option<PathBuf>,
    },
    /// Check the host compiler, linker, disassembler, verifier and Ninja.
    Doctor,
    /// Run the toolchain test suite.
    Test {
        #[arg(long, value_parser = clap::value_parser!(u8).range(0..=4), conflicts_with = "all")]
        level: Option<u8>,
        #[arg(long)]
        all: bool,
    },
}

fn root() -> Result<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?)
}

fn build_dir(root: &Path, selected: Option<PathBuf>) -> Result<PathBuf> {
    let path = absolute(selected.unwrap_or_else(|| root.join("build")))?;
    let mut resolved = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                resolved.pop();
            }
            _ => {
                resolved.push(component);
                if resolved.exists() {
                    resolved = resolved.canonicalize()?;
                }
            }
        }
    }
    ensure!(
        !root.starts_with(&resolved),
        "build directory would contain the checkout"
    );
    ensure!(
        !resolved.starts_with(root.join(".git")),
        "build directory would write to Git metadata"
    );
    Ok(resolved)
}

fn executable(name: &str, key: &str, preferred: &[&Path]) -> Result<PathBuf> {
    let resolve = |path: &Path| -> Option<PathBuf> {
        let meta = path.metadata().ok()?;
        (meta.is_file() && meta.permissions().mode() & 0o111 != 0)
            .then(|| absolute(path).ok())
            .flatten()
    };
    let search = |file: &Path| {
        env::var_os("PATH")
            .into_iter()
            .flat_map(|v| env::split_paths(&v).collect::<Vec<_>>())
            .find_map(|dir| resolve(&dir.join(file)))
    };
    if let Some(value) = env::var_os(key) {
        let path = Path::new(&value);
        return (if path.components().count() == 1 {
            search(path)
        } else {
            resolve(path)
        })
        .with_context(|| format!("{key} does not identify an executable: {}", path.display()));
    }
    preferred
        .iter()
        .find_map(|dir| resolve(&dir.join(name)))
        .or_else(|| search(Path::new(name)))
        .with_context(|| format!("cannot find {name}; set {key}"))
}

const LLVM: &[&str] = &["/opt/homebrew/opt/llvm/bin", "/usr/local/opt/llvm/bin"];

fn cargo(root: &Path) -> Command {
    let mut cmd = Command::new(env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    cmd.current_dir(root);
    cmd
}

fn built_tools(root: &Path) -> Result<BTreeMap<String, PathBuf>> {
    let output = cargo(root)
        .args([
            "build",
            "--quiet",
            "--locked",
            "-p",
            "mcu-object",
            "-p",
            "mcu-jit",
            "--message-format=json-render-diagnostics",
        ])
        .output()
        .context("run Cargo to prepare the build tools")?;
    io::stderr().write_all(&output.stderr)?;
    ensure!(
        output.status.success(),
        "Cargo tools build failed ({})",
        output.status
    );
    let mut result = BTreeMap::new();
    for line in String::from_utf8(output.stdout)?.lines() {
        let row: serde_json::Value = serde_json::from_str(line)?;
        if let (Some(name), Some(path)) =
            (row["target"]["name"].as_str(), row["executable"].as_str())
        {
            result.insert(name.to_owned(), absolute(path)?);
        }
    }
    Ok(result)
}

fn tools(root: &Path) -> Result<Tools> {
    let llvm = LLVM.iter().map(Path::new).collect::<Vec<_>>();
    let mut built = built_tools(root)?;
    Ok(Tools {
        clang: executable("clang", "LIBBPF_MCU_CLANG", &llvm)?,
        lld: executable("ld.lld", "LIBBPF_MCU_LLD", &llvm)?,
        objdump: executable("llvm-objdump", "LIBBPF_MCU_OBJDUMP", &llvm)?,
        ninja: executable("ninja", "LIBBPF_MCU_NINJA", &[])?,
        prevail: executable("prevail", "PREVAIL", &[&root.join("prevail/bin")])?,
        object: built
            .remove("mcu-object")
            .context("Cargo did not produce mcu-object")?,
        jit: built
            .remove("mcu-jit")
            .context("Cargo did not produce mcu-jit")?,
    })
}

fn sources(root: &Path, programs: Vec<String>, inputs: Vec<PathBuf>) -> Result<Vec<PathBuf>> {
    if !inputs.is_empty() {
        return inputs
            .into_iter()
            .map(|source| {
                let source = source
                    .canonicalize()
                    .with_context(|| format!("resolve {}", source.display()))?;
                ensure!(
                    source.is_file() && source.extension().is_some_and(|ext| ext == "c"),
                    "expected C source: {}",
                    source.display()
                );
                Ok(source)
            })
            .collect();
    }
    let mut discovered = BTreeMap::new();
    for path in mcu::program_sources(root)? {
        let name = program_name(&path)?.to_owned();
        ensure!(
            discovered.insert(name.clone(), path).is_none(),
            "duplicate program {name}"
        );
    }
    if programs.is_empty() {
        return Ok(discovered.into_values().collect());
    }
    programs
        .into_iter()
        .map(|name| {
            discovered
                .remove(&name)
                .with_context(|| format!("unknown or repeated program {name}"))
        })
        .collect()
}

fn verify_tool(tool: &Path, args: &[&str]) -> Result<String> {
    let result = Command::new(tool)
        .args(args)
        .output()
        .with_context(|| format!("run {}", tool.display()))?;
    ensure!(
        result.status.success(),
        "{} failed: {}",
        tool.display(),
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(String::from_utf8(result.stdout)?)
}

fn doctor(tools: Tools) -> Result<()> {
    let targets = verify_tool(&tools.clang, &["--print-targets"])?;
    for name in ["bpf", "riscv32"] {
        ensure!(
            targets
                .lines()
                .any(|line| line.split_whitespace().next() == Some(name)),
            "{} does not support {name}",
            tools.clang.display()
        );
    }
    for (tool, flag) in [
        (tools.lld, "--version"),
        (tools.objdump, "--version"),
        (tools.ninja, "--version"),
        (tools.prevail, "--help"),
        (tools.object, "--help"),
        (tools.jit, "--help"),
    ] {
        let report = verify_tool(&tool, &[flag])?;
        println!(
            "{} {}",
            tool.display(),
            report.lines().next().unwrap_or_default()
        );
    }
    Ok(())
}

fn main() -> Result<()> {
    let root = root()?;
    match Cli::parse().command {
        Action::Build {
            program,
            inputs,
            mut modes,
            bpf_only,
            build_dir: dir,
            force,
        } => {
            for key in [
                "CPATH",
                "C_INCLUDE_PATH",
                "CPLUS_INCLUDE_PATH",
                "OBJC_INCLUDE_PATH",
            ] {
                ensure!(
                    env::var_os(key).is_none_or(|v| v.is_empty()),
                    "unset {key}; only the target SDK may supply headers"
                );
            }
            let build = build_dir(&root, dir)?;
            let sources = sources(&root, program, inputs)?;
            let tools = tools(&root)?;
            if !bpf_only && modes.is_empty() {
                modes = Mode::ALL.to_vec();
            }
            modes.sort_unstable();
            modes.dedup();
            let _lock = mcu::lock_build(&build)?;
            integrity::check_dirs(&build, &sources)?;
            let before = integrity::snapshot(&root, &sources, &modes)?;
            let execute = Generate {
                root: &root,
                build: &build,
                sources: &sources,
                modes: &modes,
                tools: &tools,
            }
            .run()?;
            for source in &sources {
                integrity::preflight(&root, &build, source, &modes, &tools, force)?;
            }
            let execution = execute.run();
            let after = integrity::snapshot(&root, &sources, &modes);
            let mut invalid = Vec::new();
            for source in &sources {
                let unchanged = after.as_ref().is_ok_and(|after| {
                    let used = |path: &Path| {
                        path == source
                            || path.starts_with(root.join("include-bpf"))
                            || ((modes.contains(&Mode::Aot) || modes.contains(&Mode::Ebpf))
                                && path.starts_with(root.join("include")))
                    };
                    before
                        .iter()
                        .filter(|(path, _)| used(path))
                        .eq(after.iter().filter(|(path, _)| used(path)))
                });
                if let Err(error) =
                    integrity::postflight(&root, &build, source, &modes, &execute, unchanged)
                {
                    invalid.push(format!("{}: {error:#}", source.display()));
                }
            }
            if !invalid.is_empty() {
                eprintln!("{}", invalid.join("\n"));
            }
            execution?;
            after?;
            ensure!(
                invalid.is_empty(),
                "one or more program outputs failed validation"
            );
        }
        Action::Clean { build_dir: dir } => {
            let build = build_dir(&root, dir)?;
            let _lock = mcu::lock_build(&build)?;
            if build.exists() {
                let graph = fs::read_to_string(build.join("build.ninja")).unwrap_or_default();
                ensure!(
                    graph.starts_with("# Generated by mcu.") || build == root.join("build"),
                    "selected directory has no generated build.ninja: {}",
                    build.display()
                );
                fs::remove_dir_all(build)?;
            }
        }
        Action::Doctor => doctor(tools(&root)?)?,
        Action::Test { level, all } => {
            let levels = if all {
                0..=4
            } else {
                level.unwrap_or(0)..=level.unwrap_or(1)
            };
            for level in levels {
                let mut command = cargo(&root);
                command.args(["test", "--locked"]);
                match level {
                    0 => {
                        command.args([
                            "--workspace",
                            "--exclude",
                            "xpost-jit-oracle",
                            "--lib",
                            "--bins",
                        ]);
                    }
                    1 => {
                        command.args(["--workspace", "--exclude", "xpost-jit-oracle", "--tests"]);
                    }
                    2..=4 => {
                        command
                            .args(["-p", "mcu", "--test", "pipeline", "--"])
                            .arg(format!("level{level}_"))
                            .args(["--ignored", "--nocapture"]);
                    }
                    _ => unreachable!(),
                }
                println!("L{level} {command:?}");
                ensure!(command.status()?.success(), "L{level} tests failed");
            }
        }
    }
    Ok(())
}
