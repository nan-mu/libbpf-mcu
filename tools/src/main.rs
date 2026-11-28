mod diagnostics;
mod reference;
mod release;
mod sail;

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use mcu_image::{Mode, TargetLayout, elf_target, write_atomic};

#[derive(Parser)]
#[command(about = "Development tools for the ESP32-C3 build")]
struct Cli {
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    Release {
        #[command(subcommand)]
        command: ReleaseAction,
    },
    /// Link a native reference from archived compiler inputs.
    Reference {
        #[arg(long)]
        program_dir: PathBuf,
        #[arg(long)]
        mode: Mode,
        #[arg(long)]
        work_dir: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, env = "LIBBPF_MCU_LLD", default_value = "ld.lld")]
        lld: PathBuf,
        #[arg(long, conflicts_with_all = ["slot_address", "slot_length", "helper_address"])]
        firmware: Option<PathBuf>,
        #[arg(long, required_unless_present = "firmware", value_parser = number)]
        slot_address: Option<u32>,
        #[arg(long, required_unless_present = "firmware", value_parser = number)]
        slot_length: Option<u32>,
        #[arg(long, required_unless_present = "firmware", value_parser = number)]
        helper_address: Option<u32>,
    },
    /// Link a C program and the HTIF runtime for the Sail RV32 simulator.
    SailImage {
        #[arg(long)]
        source: PathBuf,
        #[arg(long, default_value = "xdp_prog1")]
        entry: String,
        #[arg(long)]
        work_dir: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long, env = "LIBBPF_MCU_CLANG", default_value = "clang")]
        clang: PathBuf,
    },
    #[command(flatten)]
    Diagnostic(diagnostics::Action),
}

#[derive(Subcommand)]
enum ReleaseAction {
    /// Archive and validate the already built release matrix.
    Prepare {
        #[arg(long)]
        build_dir: Option<PathBuf>,
        #[arg(long)]
        archive_dir: PathBuf,
    },
    /// Unpack and verify a release ledger and all its archives.
    Verify {
        #[arg(long)]
        build_dir: Option<PathBuf>,
        #[arg(long)]
        archive_dir: PathBuf,
        #[arg(long)]
        unpack_dir: PathBuf,
    },
    /// Determine the next patch tag or reuse a previous allocation.
    NextTag {
        #[arg(long)]
        commit: String,
        #[arg(long, default_value = "origin")]
        remote: String,
        #[arg(long)]
        allocated: Option<String>,
    },
}

fn number(value: &str) -> Result<u32, std::num::ParseIntError> {
    if let Some(hex) = value.strip_prefix("0x") {
        u32::from_str_radix(hex, 16)
    } else {
        value.parse()
    }
}

fn absolute_output(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok(parent
        .canonicalize()?
        .join(path.file_name().context("expected output path")?))
}

fn main() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .canonicalize()?;
    match Cli::parse().command {
        Action::SailImage {
            source,
            entry,
            work_dir,
            output,
            clang,
        } => sail::link(&root, &source, &entry, &work_dir, output.as_deref(), &clang),
        Action::Release { command } => match command {
            ReleaseAction::Prepare {
                build_dir,
                archive_dir,
            } => release::prepare(
                &root,
                &build_dir.unwrap_or_else(|| root.join("build")),
                &absolute_output(&archive_dir)?,
            ),
            ReleaseAction::Verify {
                build_dir,
                archive_dir,
                unpack_dir,
            } => release::verify(
                &root,
                &archive_dir,
                &absolute_output(&unpack_dir)?,
                build_dir.as_deref(),
            ),
            ReleaseAction::NextTag {
                commit,
                remote,
                allocated,
            } => release::next_tag(&root, &remote, &commit, allocated.as_deref()),
        },
        Action::Reference {
            program_dir,
            mode,
            work_dir,
            output,
            lld,
            firmware,
            slot_address,
            slot_length,
            helper_address,
        } => {
            let target = if let Some(firmware) = firmware {
                elf_target(&fs::read(firmware)?)?
            } else {
                TargetLayout {
                    slot: slot_address.context("missing slot address")?,
                    capacity: slot_length.context("missing slot capacity")?,
                    helper: helper_address.context("missing helper address")?,
                }
            };
            let program = program_dir.canonicalize()?;
            let output = absolute_output(&output)?;
            ensure!(
                !output.starts_with(&program),
                "reference output must be outside the program directory"
            );
            fs::create_dir_all(&work_dir)?;
            let work = work_dir.canonicalize()?;
            ensure!(
                !work.starts_with(&program),
                "reference intermediates must be outside the program directory"
            );
            let bytes = reference::generate(&program, mode, target, &work, &lld)?;
            write_atomic(&output, &bytes)
        }
        Action::Diagnostic(action) => action.run(),
    }
}
