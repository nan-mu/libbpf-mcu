//! Host CLI: read firmware XPM1 and pack Compact ELF via `xpost-elf`.

mod bpf_meta;

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use object::{Object, ObjectSection, ObjectSymbol};
use xpost_elf::{SECTION_NAME, build_container, decode};

use bpf_meta::metadata_from_bpf_toml;

#[derive(Parser, Debug)]
#[command(name = "xpost-mcu-elf", about = "XPM1 + Compact ELF helpers (xpost-elf)")]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Print `{addr,size}` for one firmware ELF symbol.
    Symbol {
        firmware: PathBuf,
        name: String,
    },
    /// Dump firmware `.xpost.mem` (XPM1) addresses as one JSON object on stdout.
    MemMap {
        /// Linked firmware ELF carrying `.xpost.mem`.
        firmware: PathBuf,
    },
    /// Encode AOT image + bpf.toml into Compact ELF V0 (`<stem>.elf`).
    Pack {
        #[arg(long)]
        image: PathBuf,
        #[arg(long)]
        bpf_toml: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long, value_parser = parse_u32)]
        slot_address: u32,
        #[arg(long, value_parser = parse_u32)]
        helper_address: u32,
        #[arg(long, default_value_t = 1, value_parser = parse_u32_as_u8)]
        machine: u8,
        #[arg(short = 'o', long)]
        out: PathBuf,
    },
}

fn parse_u32(s: &str) -> Result<u32, String> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).map_err(|e| e.to_string())
    } else {
        t.parse::<u32>().map_err(|e| e.to_string())
    }
}

fn parse_u32_as_u8(s: &str) -> Result<u8, String> {
    let v = parse_u32(s)?;
    u8::try_from(v).map_err(|_| format!("machine out of u8 range: {v}"))
}

fn dump_symbol(firmware: &PathBuf, name: &str) -> Result<()> {
    let data = fs::read(firmware).with_context(|| format!("read {}", firmware.display()))?;
    let file = object::File::parse(&*data).context("parse firmware ELF")?;
    let sym = file
        .symbols()
        .find(|sym| sym.name().ok() == Some(name))
        .ok_or_else(|| anyhow::anyhow!("ELF missing symbol `{name}`"))?;
    println!("{{\"addr\":{},\"size\":{}}}", sym.address(), sym.size());
    Ok(())
}

fn dump_mem_map(firmware: &PathBuf) -> Result<()> {
    let data = fs::read(firmware).with_context(|| format!("read {}", firmware.display()))?;
    let file = object::File::parse(&*data).context("parse firmware ELF")?;
    let sec = file
        .section_by_name(SECTION_NAME)
        .ok_or_else(|| anyhow::anyhow!("ELF missing section `{SECTION_NAME}`"))?;
    let bytes = sec.data().context("section data")?;
    let mem = decode(bytes).map_err(|e| anyhow::anyhow!("decode {SECTION_NAME}: {e:?}"))?;
    println!(
        "{{\"helper_addr\":{},\"slot_addr\":{},\"slot_len\":{},\"table_addr\":{},\"table_len\":{}}}",
        mem.helper_addr, mem.slot_addr, mem.slot_len, mem.table_addr, mem.table_len
    );
    Ok(())
}

fn pack(args: Cmd) -> Result<()> {
    let Cmd::Pack {
        image,
        bpf_toml,
        name,
        slot_address,
        helper_address,
        machine,
        out,
    } = args
    else {
        unreachable!()
    };
    if name.is_empty() || !name.is_ascii() {
        bail!("--name must be non-empty ASCII");
    }
    let image_bytes = fs::read(&image).with_context(|| format!("read {}", image.display()))?;
    let meta = metadata_from_bpf_toml(&bpf_toml, &name, slot_address, helper_address, machine)?;
    let blob = build_container(&image_bytes, &meta, None)
        .map_err(|e| anyhow::anyhow!("build_container: {e:?}"))?;
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }
    fs::write(&out, blob.as_slice()).with_context(|| format!("write {}", out.display()))?;
    Ok(())
}

fn run(args: Args) -> Result<()> {
    match args.cmd {
        Cmd::Symbol { firmware, name } => dump_symbol(&firmware, &name),
        Cmd::MemMap { firmware } => dump_mem_map(&firmware),
        pack_cmd @ Cmd::Pack { .. } => pack(pack_cmd),
    }
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xpost-mcu-elf: {e:#}");
            ExitCode::FAILURE
        }
    }
}
