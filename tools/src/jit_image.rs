//! Link a JIT image at the firmware's slot address and pack it as Compact ELF V0.
//!
//! The device does no relocation and parses no sections: it copies one flat span
//! to the slot and jumps to its base. So every address is closed here, and the
//! map placeholders live inside that span at the addresses the code uses.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use object::{Object, ObjectSection};
use xpost_elf::{SECTION_NAME, ScanOutcome, build_container, decode, scan_at, sha256};
use xpost_jit::{LinkIn, RelocKind, compile, link, load_bpf};

use crate::bpf_meta::metadata_from_bpf_toml;

/// Bytes reserved per map inside the image, matching the AOT link's `.maps`
/// placeholder. The firmware never reads them: it binds the address to real
/// storage through its VMR table, so only the address carries meaning.
const MAP_PLACEHOLDER: u32 = 16;

pub struct Packed {
    pub container: Vec<u8>,
    pub slot_addr: u32,
    pub slot_len: u32,
    pub helper_addr: u32,
    pub code_bytes: u32,
    pub image_len: u32,
    pub maps: Vec<(String, u32)>,
    pub relocs: usize,
}

pub fn pack_jit(
    firmware: &Path,
    obj: &Path,
    bpf_toml: &Path,
    name: &str,
    section: Option<&str>,
    toml_out: &Path,
) -> Result<Packed> {
    let fw = fs::read(firmware).with_context(|| format!("read {}", firmware.display()))?;
    let elf = object::File::parse(&*fw).context("parse firmware ELF")?;
    let sec = elf
        .section_by_name(SECTION_NAME)
        .ok_or_else(|| anyhow::anyhow!("firmware has no `{SECTION_NAME}`"))?;
    let mem = decode(sec.data().context("section data")?)
        .map_err(|e| anyhow::anyhow!("decode {SECTION_NAME}: {e:?}"))?;
    let (slot, slot_len, helper) = (mem.slot_addr, mem.slot_len, mem.helper_addr);

    let src = load_bpf(obj, section).map_err(|e| anyhow::anyhow!("{}", e))?;
    let image = compile(&src.insns, &src.symbols).map_err(|e| anyhow::anyhow!("{}", e))?;

    // The metadata builder omits a map it cannot encode. Ask it which maps
    // survive before assigning real addresses, so a referenced map that would
    // be dropped is an error rather than a lookup that silently misses.
    let declared = map_names(bpf_toml)?;
    let provisional: HashMap<String, u32> = declared
        .iter()
        .enumerate()
        .map(|(i, n)| (n.clone(), 0x1000 + i as u32 * MAP_PLACEHOLDER))
        .collect();
    let probe_path = toml_out.with_extension("probe.toml");
    write_vmas(bpf_toml, &provisional, &probe_path)?;
    let probe = metadata_from_bpf_toml(&probe_path, name, slot, helper, 1)?;
    let _ = fs::remove_file(&probe_path);
    let eligible: Vec<String> = probe.maps.iter().map(|m| m.name.as_str().to_string()).collect();

    for reloc in &image.relocs {
        if reloc.kind != RelocKind::Lddw {
            continue;
        }
        let sym = reloc
            .symbol
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("lddw at bpf pc {} has no symbol", reloc.bpf_pc))?;
        if !eligible.iter().any(|n| n == sym) {
            bail!(
                "program references `{sym}` but it cannot enter Compact ELF V0; \
                 recorded maps are {eligible:?}. Refusing rather than emitting a \
                 reference the firmware would leave unbound."
            );
        }
    }

    let code_bytes = image.code.len() as u32 * 4;
    let mut cursor = code_bytes;
    let mut vmas = HashMap::new();
    for n in &eligible {
        vmas.insert(n.clone(), slot + cursor);
        cursor += MAP_PLACEHOLDER;
    }
    let image_len = cursor;
    if image_len == 0 {
        bail!("the image is empty");
    }
    if image_len > slot_len {
        bail!(
            "image is {image_len} bytes but slot {slot:#x} holds {slot_len}; \
             refusing to truncate"
        );
    }

    let code = link(&image, &LinkIn { helper, maps: &vmas })
        .map_err(|e| anyhow::anyhow!("link: {}", e))?;
    xpost_jit::check_rv32im(&code).map_err(|e| anyhow::anyhow!("ISA: {e}"))?;

    let mut bytes = Vec::with_capacity(image_len as usize);
    for word in &code {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes.resize(image_len as usize, 0);

    write_vmas(bpf_toml, &vmas, toml_out)?;
    let meta = metadata_from_bpf_toml(toml_out, name, slot, helper, 1)?;
    let blob = build_container(&bytes, &meta, Some(slot_len))
        .map_err(|e| anyhow::anyhow!("build_container: {e:?}"))?;

    // Accept with the same parser the firmware loader runs, not a second reader.
    let mut reader = blob.as_slice();
    let parsed = match scan_at(&mut reader, 0) {
        ScanOutcome::Ok(p) => p,
        ScanOutcome::SoftSkip { file_len } => {
            bail!("the loader would skip this container (file_len {file_len})")
        }
        ScanOutcome::HardFail => bail!("the loader would stop at this container"),
    };
    if parsed.slot_address != slot as usize {
        bail!("entry {:#x} is not the slot base {slot:#x}", parsed.slot_address);
    }
    if parsed.helper_address != helper as usize {
        bail!("container helper {:#x} != firmware {helper:#x}", parsed.helper_address);
    }
    if parsed.image_size != bytes.len() {
        bail!("container image {} != assembled {}", parsed.image_size, bytes.len());
    }
    if parsed.digest != sha256(&bytes) {
        bail!("container digest does not match the image");
    }
    let mut want: Vec<u32> = vmas.values().copied().collect();
    let mut got: Vec<u32> = parsed.maps.iter().map(|m| m.vma).collect();
    want.sort_unstable();
    got.sort_unstable();
    if want != got {
        bail!("container binds {got:#x?} but the code references {want:#x?}");
    }

    let mut maps: Vec<(String, u32)> = vmas.into_iter().collect();
    maps.sort();
    Ok(Packed {
        container: blob.to_vec(),
        slot_addr: slot,
        slot_len,
        helper_addr: helper,
        code_bytes,
        image_len,
        maps,
        relocs: image.relocs.len(),
    })
}

fn map_names(bpf_toml: &Path) -> Result<Vec<String>> {
    let text = fs::read_to_string(bpf_toml).with_context(|| format!("read {}", bpf_toml.display()))?;
    let root: toml::Value = toml::from_str(&text).context("parse bpf.toml")?;
    let mut names = Vec::new();
    if let Some(toml::Value::Table(maps)) = root.get("maps") {
        for name in maps.keys() {
            names.push(name.clone());
        }
    }
    names.sort();
    Ok(names)
}

/// Record the addresses this link chose. `aot_addr` is dropped because the
/// metadata builder refuses a `map_vma` that disagrees with it, and these
/// addresses come from the JIT layout rather than an AOT link.
fn write_vmas(bpf_toml: &Path, vmas: &HashMap<String, u32>, out: &Path) -> Result<()> {
    let text = fs::read_to_string(bpf_toml).with_context(|| format!("read {}", bpf_toml.display()))?;
    let mut root: toml::Value = toml::from_str(&text).context("parse bpf.toml")?;
    if let Some(toml::Value::Table(maps)) = root.get_mut("maps") {
        for (name, item) in maps.iter_mut() {
            if let toml::Value::Table(fields) = item {
                fields.remove("aot_addr");
                fields.remove("map_vma");
                if let Some(v) = vmas.get(name) {
                    fields.insert("map_vma".into(), toml::Value::Integer(i64::from(*v)));
                }
            }
        }
    }
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }
    fs::write(out, toml::to_string(&root).context("serialize jit toml")?)
        .with_context(|| format!("write {}", out.display()))?;
    Ok(())
}