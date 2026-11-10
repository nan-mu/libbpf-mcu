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
        /// Write each map's index into the `lddw` that references it.
        ///
        /// Needed for a bytecode image the interpreter runs: the interpreter has
        /// no map table, so an unresolved reference becomes a null pointer and
        /// every lookup silently misses.
        #[arg(long)]
        map_index: bool,
        /// The `bpf.o` the image was extracted from. Required with `--map-index`:
        /// the map identity lives in its relocation table, not in the bytes.
        #[arg(long)]
        obj: Option<PathBuf>,
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
        map_index,
        obj,
        out,
    } = args
    else {
        unreachable!()
    };
    if name.is_empty() || !name.is_ascii() {
        bail!("--name must be non-empty ASCII");
    }
    let mut image_bytes = fs::read(&image).with_context(|| format!("read {}", image.display()))?;
    // A bytecode image reaches the interpreter with its map references
    // unresolved: the object file names each map by symbol and leaves the
    // instruction's immediate at zero. Writing the map's index into that
    // immediate is what lets the loader turn an index into an address; without
    // it the interpreter hands a null pointer to every map helper and each
    // lookup silently misses.
    if map_index {
        let obj = obj.context("--map-index needs --obj <bpf.o> to read relocations")?;
        let patched = index_map_references(&image_bytes, &obj, &bpf_toml)?;
        image_bytes = patched;
    }
    let meta = metadata_from_bpf_toml(&bpf_toml, &name, slot_address, helper_address, machine)?;
    let blob = build_container(&image_bytes, &meta, None)
        .map_err(|e| anyhow::anyhow!("build_container: {e:?}"))?;
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }
    fs::write(&out, blob.as_slice()).with_context(|| format!("write {}", out.display()))?;
    Ok(())
}

/// Rewrite each map-carrying `lddw` so its immediate is the map's index.
///
/// The index is the map's position in the same filtered, sorted order the
/// container metadata uses, because that is the order the loader reads its
/// binding table in. Getting the two orders out of step would silently point a
/// reference at the wrong map, so both come from `bpf.toml` through the same
/// metadata builder.
fn index_map_references(image: &[u8], obj_path: &PathBuf, bpf_toml: &PathBuf) -> Result<Vec<u8>> {
    use object::{Object, ObjectSection, ObjectSymbol};

    let data = fs::read(obj_path).with_context(|| format!("read {}", obj_path.display()))?;
    let file = object::File::parse(&*data).context("parse bpf object")?;

    // Map order as the container will record it: the metadata builder's order.
    // The addresses here are placeholders; only the names and their order matter
    // for resolving a reference, and a zero address would fail that builder's
    // own validation, so a plausible slot address is supplied.
    let meta = metadata_from_bpf_toml(bpf_toml, "probe", 0x1000, 0x1000, 1)?;
    let order: Vec<String> = meta
        .maps
        .iter()
        .map(|m| m.name.as_str().to_string())
        .collect();
    if order.is_empty() {
        // Nothing to resolve. Leaving the image untouched is right: a program
        // without maps cannot need one.
        return Ok(image.to_vec());
    }

    // The program section holds the instructions. `--only-section` extracted it
    // before this call, so its first instruction is offset zero.
    let mut out = image.to_vec();
    let mut patched = 0usize;
    // Relocations hang off the section they apply to, not off the `.rel*`
    // section itself: `Section::relocations` reads the latter. So the walk is
    // over program sections, and the filter is "a section whose name marks it as
    // XDP code".
    for section in file.sections() {
        let Ok(section_name) = section.name() else {
            continue;
        };
        if !(section_name == "xdp" || section_name.starts_with("xdp")) {
            continue;
        }
        let relocs = section.relocations();
        for (offset, reloc) in relocs {
            // The relocation's target symbol is the map's name in the object.
            // The symbol is the identity; the relocation kind is whatever the
            // object crate maps `R_BPF_64_64` to, which is not a value this
            // code should depend on.
            let symbol = match reloc.target() {
                object::RelocationTarget::Symbol(sym) => sym,
                _ => continue,
            };
            let name = match file.symbol_by_index(symbol).and_then(|s| Ok(s.name()?.to_string())) {
                Ok(n) => n,
                Err(_) => continue,
            };
            let Some(idx) = order.iter().position(|m| m == &name) else {
                // A relocation to something that is not a map in this image: a
                // map the container omits (ring buffer, for example). Skipping it
                // is right, because the program cannot reach it either.
                eprintln!(
                    "xpost-mcu-elf: reloc at {offset:#x} -> `{name}`, not a recorded map; skipped"
                );
                continue;
            };
            let at = offset as usize;
            if at + 8 > out.len() {
                bail!("relocation at {offset:#x} is past the image ({} bytes)", out.len());
            }
            if out[at] != 0x18 {
                bail!(
                    "relocation at {offset:#x} is not an lddw (opcode {:#04x})",
                    out[at]
                );
            }
            out[at + 4..at + 8].copy_from_slice(&(idx as u32).to_le_bytes());
            out[at + 12..at + 16].copy_from_slice(&0u32.to_le_bytes());
            // src = 1 marks "this immediate is a map index", which the loader
            // uses to tell a map reference from an ordinary constant.
            out[at + 1] |= 1 << 4;
            patched += 1;
        }
    }
    if patched == 0 {
        bail!(
            "no map relocations found for {}; the image carries {order:?} but no reference to them",
            obj_path.display()
        );
    }
    Ok(out)
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
