//! Host CLI: read firmware XPM1 and pack Compact ELF via `xpost-elf`.

mod bpf_meta;
mod jit_image;

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use object::{Object, ObjectSection, ObjectSymbol};
use xpost_elf::{SECTION_NAME, ScanOutcome, build_container, decode, scan_at};

use bpf_meta::{metadata_from_value, read_maps, with_linked_maps};

#[derive(Parser, Debug)]
#[command(
    name = "xpost-mcu-elf",
    about = "XPM1 + Compact ELF helpers (xpost-elf)"
)]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Print `{addr,size}` for one firmware ELF symbol.
    Symbol { firmware: PathBuf, name: String },
    /// Dump firmware `.xpost.mem` (XPM1) addresses as one JSON object on stdout.
    MemMap {
        /// Linked firmware ELF carrying `.xpost.mem`.
        firmware: PathBuf,
    },
    /// Encode an image and its map bindings as Compact ELF V0.
    Pack {
        #[arg(long)]
        image: PathBuf,
        #[arg(long)]
        maps: PathBuf,
        /// Linked AOT ELF supplying map VMAs.
        #[arg(long)]
        linked_elf: PathBuf,
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
        /// Write the image bytes that the container carries, after map-index
        /// rewriting when that flag is set.
        #[arg(long)]
        export_image: Option<PathBuf>,
        #[arg(short = 'o', long)]
        out: PathBuf,
    },
    /// Compile eBPF to RV32IM, link it at the firmware slot, and write the stage.
    ///
    /// The stage directory must be named `.jit-stage`. This command does not
    /// publish, run PREVAIL, or execute the image.
    PackJit {
        /// Linked firmware ELF carrying `.xpost.mem`; supplies slot and helper addresses.
        #[arg(long)]
        firmware: PathBuf,
        /// Clang-produced eBPF object.
        #[arg(long)]
        obj: PathBuf,
        #[arg(long)]
        maps: PathBuf,
        #[arg(long, value_parser = parse_u32)]
        slot_address: u32,
        #[arg(long, value_parser = parse_u32)]
        slot_length: u32,
        #[arg(long)]
        name: String,
        /// Directory named `.jit-stage`. The only place this command writes.
        #[arg(long)]
        stage: PathBuf,
    },
    /// Accept one Compact ELF file only when `scan_at` returns Ok.
    Scan {
        file: PathBuf,
        #[arg(long)]
        json: bool,
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

fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }
    let tmp = path.with_extension("partial");
    fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("rename {}", path.display()))?;
    Ok(())
}

fn pack(args: Cmd) -> Result<()> {
    let Cmd::Pack {
        image,
        maps,
        linked_elf,
        name,
        slot_address,
        helper_address,
        machine,
        map_index,
        obj,
        export_image,
        out,
    } = args
    else {
        unreachable!()
    };
    if name.is_empty() || !name.is_ascii() {
        bail!("--name must be non-empty ASCII");
    }
    let mut image_bytes = fs::read(&image).with_context(|| format!("read {}", image.display()))?;
    let overlaid = with_linked_maps(read_maps(&maps)?, &linked_elf)?;
    let meta = metadata_from_value(
        &overlaid,
        &maps.display().to_string(),
        &name,
        slot_address,
        helper_address,
        machine,
    )?;
    // A bytecode image reaches the interpreter with its map references
    // unresolved: the object file names each map by symbol and leaves the
    // instruction's immediate at zero. Writing the map's index into that
    // immediate is what lets the loader turn an index into an address; without
    // it the interpreter hands a null pointer to every map helper and each
    // lookup silently misses.
    if map_index {
        let obj = obj.context("--map-index needs --obj <bpf.o> to read relocations")?;
        let patched = index_map_references(&image_bytes, &obj, &meta)?;
        image_bytes = patched;
    }
    if let Some(export) = &export_image {
        write_atomic(export, &image_bytes)?;
    }
    let blob = build_container(&image_bytes, &meta, None)
        .map_err(|e| anyhow::anyhow!("build_container: {e:?}"))?;
    write_atomic(&out, blob.as_slice())?;
    Ok(())
}

/// Rewrite each map-carrying `lddw` so its immediate is the map's index.
///
/// The index is the map's position in the same filtered, sorted order the
/// container metadata uses, because that is the order the loader reads its
/// binding table in. Getting the two orders out of step would silently point a
/// reference at the wrong map, so both use the same metadata.
fn index_map_references(
    image: &[u8],
    obj_path: &PathBuf,
    meta: &xpost_elf::ImageMetadataV0,
) -> Result<Vec<u8>> {
    use object::{Object, ObjectSection, ObjectSymbol};

    let data = fs::read(obj_path).with_context(|| format!("read {}", obj_path.display()))?;
    let file = object::File::parse(&*data).context("parse bpf object")?;

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
            let name = match file
                .symbol_by_index(symbol)
                .and_then(|s| Ok(s.name()?.to_string()))
            {
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
            if at + 16 > out.len() {
                bail!(
                    "relocation at {offset:#x} is past the image ({} bytes)",
                    out.len()
                );
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

fn pack_jit_cmd(args: Cmd) -> Result<()> {
    let Cmd::PackJit {
        firmware,
        obj,
        maps,
        slot_address,
        slot_length,
        name,
        stage,
    } = args
    else {
        unreachable!()
    };
    let artifact =
        jit_image::JitArtifact::assemble(&firmware, &obj, &maps, &name, slot_address, slot_length)?;
    artifact.write_stage(&stage)?;
    Ok(())
}

fn scan_file(file: &PathBuf, json: bool) -> Result<()> {
    let blob = fs::read(file).with_context(|| format!("read {}", file.display()))?;
    let mut reader = blob.as_slice();
    match scan_at(&mut reader, 0) {
        ScanOutcome::Ok(parsed) => {
            if json {
                // scan_at accepts only the V0 profile with machine code 1.
                println!(
                    "{}",
                    serde_json::json!({
                        "name": parsed.name.as_str(),
                        "slot_address": parsed.slot_address,
                        "helper_address": parsed.helper_address,
                        "machine": 1,
                    })
                );
            }
            Ok(())
        }
        ScanOutcome::SoftSkip { file_len } => bail!("SoftSkip (file_len {file_len})"),
        ScanOutcome::HardFail => bail!("HardFail"),
    }
}

fn run(args: Args) -> Result<()> {
    match args.cmd {
        Cmd::Symbol { firmware, name } => dump_symbol(&firmware, &name),
        Cmd::MemMap { firmware } => dump_mem_map(&firmware),
        pack_cmd @ Cmd::Pack { .. } => pack(pack_cmd),
        jit_cmd @ Cmd::PackJit { .. } => pack_jit_cmd(jit_cmd),
        Cmd::Scan { file, json } => scan_file(&file, json),
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
