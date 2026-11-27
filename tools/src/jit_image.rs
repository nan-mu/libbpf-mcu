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
use serde_json::json;
use toml::Value;
use xpost_elf::{SECTION_NAME, ScanOutcome, build_container, decode, scan_at, sha256};
use xpost_jit::{LinkIn, RelocKind, check_rv32im, compile, link, load_bpf};

use crate::bpf_meta::{metadata_from_value, read_maps};

/// Bytes reserved per map inside the image, matching the AOT link's `.maps`
/// placeholder. The firmware never reads them: it binds the address to real
/// storage through its VMR table, so only the address carries meaning.
pub(crate) const MAP_PLACEHOLDER: u32 = 16;

/// Bytes of one successful assembly and the code extent inside its payload.
pub struct JitArtifact {
    image: Vec<u8>,
    container: Vec<u8>,
    generation: serde_json::Value,
    code_len: u32,
}

impl JitArtifact {
    pub fn assemble(
        firmware: &Path,
        obj: &Path,
        maps: &Path,
        name: &str,
        slot: u32,
        slot_len: u32,
    ) -> Result<Self> {
        let fw = fs::read(firmware).with_context(|| format!("read {}", firmware.display()))?;
        let elf = object::File::parse(&*fw).context("parse firmware ELF")?;
        let sec = elf
            .section_by_name(SECTION_NAME)
            .ok_or_else(|| anyhow::anyhow!("firmware has no `{SECTION_NAME}`"))?;
        let mem = decode(sec.data().context("section data")?)
            .map_err(|e| anyhow::anyhow!("decode {SECTION_NAME}: {e:?}"))?;
        let helper = mem.helper_addr;
        let loaded = load_bpf(obj, None).map_err(|e| anyhow::anyhow!("{e}"))?;
        let image = compile(&loaded.insns, &loaded.symbols).map_err(|e| anyhow::anyhow!("{e}"))?;

        let doc = read_maps(maps)?;
        let eligible = eligible_maps(&doc, name, &image)?;

        let code_bytes = (image.code.len() * 4) as u32;
        let holes = MAP_PLACEHOLDER
            .checked_mul(eligible.len() as u32)
            .context("map hole length overflow")?;
        let image_len = code_bytes
            .checked_add(holes)
            .context("image length overflow")?;
        if image_len == 0 {
            bail!("the image is empty");
        }
        if image_len > slot_len {
            bail!(
                "image is {image_len} bytes but slot {slot:#x} holds {slot_len}; \
                 refusing to truncate"
            );
        }

        let mut vmas = HashMap::new();
        for (i, n) in eligible.iter().enumerate() {
            let vmr = slot
                .checked_add(code_bytes)
                .and_then(|base| base.checked_add(MAP_PLACEHOLDER * i as u32))
                .context("map VMR overflow")?;
            vmas.insert(n.clone(), vmr);
        }

        let words = link(
            &image,
            &LinkIn {
                helper,
                maps: &vmas,
            },
        )
        .map_err(|e| anyhow::anyhow!("link: {e}"))?;
        check_rv32im(&words).map_err(|e| anyhow::anyhow!("ISA: {e}"))?;
        let mut bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        bytes.resize(image_len as usize, 0);
        let meta = metadata_from_value(&with_vmas(doc, &vmas), "BTF maps", name, slot, helper, 1)?;
        let blob = build_container(&bytes, &meta, Some(slot_len))
            .map_err(|e| anyhow::anyhow!("build_container: {e:?}"))?;

        let mut reader = blob.as_slice();
        let parsed = match scan_at(&mut reader, 0) {
            ScanOutcome::Ok(p) => p,
            ScanOutcome::SoftSkip { file_len } => {
                bail!("the loader would skip this container (file_len {file_len})")
            }
            ScanOutcome::HardFail => bail!("the loader would stop at this container"),
        };
        if parsed.slot_address != slot as usize {
            bail!(
                "entry {:#x} is not the slot base {slot:#x}",
                parsed.slot_address
            );
        }
        if parsed.helper_address != helper as usize {
            bail!(
                "container helper {:#x} != firmware {helper:#x}",
                parsed.helper_address
            );
        }
        if parsed.image_size != bytes.len() {
            bail!(
                "container image {} != assembled {}",
                parsed.image_size,
                bytes.len()
            );
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

        let generation = json!([
            {"step": "firmware", "call": "xpost_elf::decode", "parameters": {"elf": firmware, "section": SECTION_NAME}},
            {"step": "load", "call": "xpost_jit::load_bpf", "parameters": {"object": obj, "section": loaded.section}},
            {"step": "compile", "call": "xpost_jit::compile", "parameters": {"isa": "rv32im", "abi": "helper_dispatcher-ilp32", "instructions": "loaded.insns", "symbols": "loaded.symbols"}},
            {"step": "link", "call": "xpost_jit::link", "parameters": {"helper": helper, "maps": vmas}},
            {"step": "pack", "call": "xpost_elf::build_container", "parameters": {"image": "linked words and map placeholders", "name": name, "machine": 1, "slot": slot, "slot_len": slot_len, "helper": helper}}
        ]);
        Ok(Self {
            image: bytes,
            container: blob.as_slice().to_vec(),
            generation,
            code_len: code_bytes,
        })
    }

    pub fn write_stage(&self, stage: &Path) -> Result<()> {
        if stage.file_name().and_then(|name| name.to_str()) != Some(".jit-stage") {
            bail!("refusing to write JIT bytes outside .jit-stage");
        }
        fs::create_dir_all(stage).with_context(|| format!("mkdir {}", stage.display()))?;
        fs::write(stage.join("jit.bin"), &self.image)?;
        fs::write(stage.join("container.elf"), &self.container)?;
        fs::write(
            stage.join("code.json"),
            serde_json::to_vec(&json!({"code_len": self.code_len, "generation": self.generation}))?,
        )?;
        Ok(())
    }
}

pub(crate) fn with_vmas(mut doc: Value, vmas: &HashMap<String, u32>) -> Value {
    if let Some(Value::Table(maps)) = doc.get_mut("maps") {
        for (name, fields) in maps {
            if let (Some(vma), Value::Table(fields)) = (vmas.get(name), fields) {
                fields.insert("map_vma".into(), i64::from(*vma).into());
            }
        }
    }
    doc
}

pub(crate) fn eligible_maps(
    doc: &Value,
    name: &str,
    image: &xpost_jit::Image,
) -> Result<Vec<String>> {
    let provisional: HashMap<String, u32> = doc
        .get("maps")
        .and_then(Value::as_table)
        .into_iter()
        .flat_map(|table| table.keys())
        .enumerate()
        .map(|(i, n)| (n.clone(), 0x1000 + i as u32 * MAP_PLACEHOLDER))
        .collect();
    let probe = metadata_from_value(
        &with_vmas(doc.clone(), &provisional),
        "BTF maps",
        name,
        4,
        4,
        1,
    )?;
    let eligible: Vec<String> = probe
        .maps
        .iter()
        .map(|m| m.name.as_str().to_string())
        .collect();

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

    Ok(eligible)
}
