use std::{fs, io::ErrorKind, path::PathBuf};

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use mcu_image::{Layout, Mode, Region, RegionKind, TargetLayout};
use mcu_index::{Index, verify_tree};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Check a Compact ELF V0 container and optionally print metadata.
    Scan {
        file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    ImageAot {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        reference: PathBuf,
        #[arg(long)]
        elf: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        program: String,
    },
    ImageEbpf {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        map_layout: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
    },
    ReportPrepare {
        #[arg(long)]
        image: PathBuf,
        #[arg(long)]
        layout: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Report {
        #[arg(long)]
        program_dir: PathBuf,
        #[arg(long)]
        linked: PathBuf,
        #[arg(long)]
        listing: PathBuf,
        #[arg(long)]
        modes: String,
    },
    Index {
        #[arg(long)]
        program_dir: PathBuf,
        #[arg(long)]
        modes: String,
    },
    /// Verify indexed artifacts and their canonical image encodings.
    Verify {
        #[arg(long)]
        build_dir: PathBuf,
    },
    /// Bind a portable image using only its indexed release members.
    Bind {
        #[arg(long)]
        program_dir: PathBuf,
        #[arg(long)]
        mode: Mode,
        #[arg(long, requires_all = ["slot_length", "helper_address"], conflicts_with = "firmware")]
        slot_address: Option<String>,
        #[arg(long, requires = "slot_address")]
        slot_length: Option<String>,
        #[arg(long, requires = "slot_address")]
        helper_address: Option<String>,
        #[arg(long, required_unless_present = "slot_address")]
        firmware: Option<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },

    CheckNative {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[command(flatten)]
        inputs: Inputs,
    },
    /// Run PREVAIL and publish the exact accepted object.
    BpfVerify {
        #[arg(long)]
        checker: PathBuf,
        #[command(flatten)]
        inputs: Inputs,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(clap::Args)]
struct Inputs {
    #[arg(long, requires_all = ["source", "sdk"])]
    dependencies: Option<PathBuf>,
    #[arg(long, requires = "dependencies")]
    source: Option<PathBuf>,
    #[arg(long, requires = "dependencies")]
    sdk: Option<PathBuf>,
}

impl Inputs {
    fn verify(&self) -> Result<()> {
        if let Some(depfile) = &self.dependencies {
            mcu_deps::dependencies(
                depfile,
                &std::env::current_dir()?,
                self.source.as_deref().context("missing source")?,
                self.sdk.as_deref().context("missing SDK")?,
            )?;
        }
        Ok(())
    }
}

fn modes(value: &str) -> Result<Vec<Mode>> {
    if value.is_empty() {
        Ok(Vec::new())
    } else {
        value.split(',').map(str::parse).collect()
    }
}

fn number(text: Option<String>) -> Result<u32> {
    let number = text.context("missing target address or capacity")?;
    Ok(if let Some(hex) = number.strip_prefix("0x") {
        u32::from_str_radix(hex, 16)?
    } else {
        number.parse()?
    })
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Action::Scan { file, json } => {
            let bytes = fs::read(file)?;
            let mut reader = bytes.as_slice();
            let xpost_elf::ScanOutcome::Ok(container) = xpost_elf::scan_at(&mut reader, 0) else {
                anyhow::bail!("invalid Compact ELF V0 container");
            };
            ensure!(
                container.file_len == bytes.len(),
                "container extent differs from file"
            );
            if json {
                println!(
                    "{}",
                    serde_json::json!({"name": container.name.as_str(), "slot_address":container.slot_address,
                    "helper_address":container.helper_address, "machine":1})
                );
            }
            Ok(())
        }
        Action::ImageAot {
            input,
            reference,
            elf,
            output_dir,
            program,
        } => {
            let (layout, bytes) = mcu_image::aot(
                program,
                &fs::read(elf)?,
                &fs::read(reference)?,
                &fs::read(input)?,
            )?;
            layout.write_pair(&output_dir, &bytes)
        }
        Action::ImageEbpf {
            input,
            map_layout,
            output_dir,
        } => {
            let aot = Layout::read(&map_layout)?;
            ensure!(
                aot.mode == Mode::Aot && aot.schema == mcu_image::SCHEMA && aot.base == 0,
                "expected canonical AOT map layout"
            );
            let names: Vec<_> = aot.maps.iter().map(|map| map.name.as_str()).collect();
            let (section, bytes) = mcu_bpf::map_indexed(&fs::read(input)?, &names)?;
            let region = Region {
                name: section,
                kind: RegionKind::Code,
                offset: 0,
                size: u32::try_from(bytes.len())?,
                alignment: 8,
            };
            Layout::new(aot.program, Mode::Ebpf, vec![region], aot.maps, vec![])
                .write_pair(&output_dir, &bytes)
        }
        Action::ReportPrepare {
            image,
            layout,
            output,
        } => mcu_report::prepare(&image, &layout, &output),
        Action::Report {
            program_dir,
            linked,
            listing,
            modes: selected,
        } => mcu_report::generate(&program_dir, &linked, &listing, &modes(&selected)?),
        Action::Index {
            program_dir,
            modes: selected,
        } => Index::generate(&program_dir, &modes(&selected)?)?.write(&program_dir),
        Action::Verify { build_dir } => {
            for index in verify_tree(&build_dir)? {
                let dir = if build_dir.join("index.toml").is_file() {
                    build_dir.clone()
                } else {
                    build_dir.join(&index.program)
                };
                mcu_report::verify(&dir, &index)
                    .with_context(|| format!("verify {} report", index.program))?;
                println!(
                    "{}: {} indexed modes verified",
                    index.program,
                    index.mode.len()
                );
            }
            Ok(())
        }
        Action::Bind {
            program_dir,
            mode,
            slot_address,
            slot_length,
            helper_address,
            firmware,
            output,
        } => {
            let target = if let Some(firmware) = firmware {
                mcu_image::elf_target(&fs::read(firmware)?)?
            } else {
                TargetLayout {
                    slot: number(slot_address)?,
                    capacity: number(slot_length)?,
                    helper: number(helper_address)?,
                }
            };
            let parent = output
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or(std::path::Path::new("."));
            ensure!(
                !parent
                    .canonicalize()?
                    .starts_with(program_dir.canonicalize()?),
                "write bound output outside the program directory"
            );
            let index = Index::read(&program_dir)?;
            mcu_image::write_atomic(&output, &index.bind(&program_dir, mode, target)?)
        }

        Action::CheckNative {
            input,
            output,
            inputs,
        } => {
            inputs.verify()?;
            mcu_image::write_atomic(&output, &fs::read(input)?)
        }
        Action::BpfVerify {
            checker,
            input,
            output,
            inputs,
        } => {
            let original = fs::read(&input);
            ensure!(
                input != output && input.canonicalize().ok() != output.canonicalize().ok(),
                "verification output cannot replace its input"
            );
            let result = (|| {
                let original = original?;
                inputs.verify()?;
                mcu_bpf::verify(&checker, &input)?;
                ensure!(
                    fs::read(&input)? == original,
                    "BPF object changed during verification"
                );
                mcu_image::write_atomic(&output, &original)
            })();
            if result.is_err() {
                match fs::remove_file(&output) {
                    Ok(()) => {}
                    Err(error) if error.kind() == ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            result
        }
    }
}
