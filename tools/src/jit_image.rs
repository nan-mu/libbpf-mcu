//! Link a JIT image at the firmware's slot address and pack it as Compact ELF V0.
//!
//! The device does no relocation and parses no sections: it copies one flat span
//! to the slot and jumps to its base. So every address is closed here, and the
//! map placeholders live inside that span at the addresses the code uses.
//!
//! `LinkedImage` owns the linked words. `JitArtifact::write_stage` is the only
//! writer, and it writes only inside a directory named `.jit-stage`.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use object::{Object, ObjectSection};
use toml::Value;
use xpost_elf::{SECTION_NAME, ScanOutcome, build_container, decode, scan_at, sha256};
use xpost_jit::{
    LinkIn, RelocKind, check_rv32im, compile, disassemble, frame_bytes, link, load_bpf,
};

use crate::bpf_meta::metadata_from_toml_text;

/// Bytes reserved per map inside the image, matching the AOT link's `.maps`
/// placeholder. The firmware never reads them: it binds the address to real
/// storage through its VMR table, so only the address carries meaning.
const MAP_PLACEHOLDER: u32 = 16;

const ISA: &str = "RV32IM";
const ABI: &str = "helper_dispatcher-ilp32";

/// Where a map's value bytes live. This host build does not know.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MapStorage {
    Unknown,
}

impl MapStorage {
    fn as_str(self) -> &'static str {
        match self {
            MapStorage::Unknown => "unknown",
        }
    }
}

/// The only owner of the linked instruction words for one pack.
/// Holes are a length, not a second buffer. Bytes are derived.
struct LinkedImage {
    words: Vec<u32>,
    holes: u32,
    slot: u32,
    helper: u32,
}

impl LinkedImage {
    fn from_linked(words: Vec<u32>, holes: u32, slot: u32, helper: u32) -> Self {
        Self {
            words,
            holes,
            slot,
            helper,
        }
    }

    fn words(&self) -> &[u32] {
        &self.words
    }

    fn code_len(&self) -> u32 {
        (self.words.len() * 4) as u32
    }

    fn image_len(&self) -> u32 {
        self.code_len() + self.holes
    }

    /// Little-endian words, then `holes` zero bytes.
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.words.len() * 4 + self.holes as usize);
        for word in &self.words {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out.resize(out.len() + self.holes as usize, 0);
        out
    }
}

struct RelocRecord {
    kind: &'static str,
    source_bpf_pc: u32,
    symbol: String,
    target: u32,
    patch_site: u32,
    result: Vec<u32>,
}

struct MapRecord {
    name: String,
    metadata_index: u32,
    vmr: u32,
    storage: MapStorage,
}

struct JitReport {
    source: PathBuf,
    section: String,
    isa: &'static str,
    abi: &'static str,
    ebpf_insns: u32,
    rv_insns: u32,
    code_len: u32,
    slot: u32,
    helper: u32,
    image_len: u32,
    container_len: u32,
    frame_size: u32,
    disassembly: String,
    relocs: Vec<RelocRecord>,
    maps: Vec<MapRecord>,
    jit_bin_sha256: [u8; 32],
    container_sha256: [u8; 32],
}

/// Content of one successful pack, before any public path exists.
pub struct JitArtifact {
    image: LinkedImage,
    container: Vec<u8>,
    report: JitReport,
    /// `bpf.toml` with `map_vma` set and `aot_addr` removed. `[jit]` is added
    /// by the one serialize in `write_stage`.
    maps_doc: Value,
}

impl JitArtifact {
    pub fn assemble(
        firmware: &Path,
        obj: &Path,
        bpf_toml: &Path,
        src: &Path,
        name: &str,
    ) -> Result<JitArtifact> {
        let fw = fs::read(firmware).with_context(|| format!("read {}", firmware.display()))?;
        let elf = object::File::parse(&*fw).context("parse firmware ELF")?;
        let sec = elf
            .section_by_name(SECTION_NAME)
            .ok_or_else(|| anyhow::anyhow!("firmware has no `{SECTION_NAME}`"))?;
        let mem = decode(sec.data().context("section data")?)
            .map_err(|e| anyhow::anyhow!("decode {SECTION_NAME}: {e:?}"))?;
        let (slot, slot_len, helper) = (mem.slot_addr, mem.slot_len, mem.helper_addr);

        let loaded = load_bpf(obj, None).map_err(|e| anyhow::anyhow!("{e}"))?;
        let image = compile(&loaded.insns, &loaded.symbols).map_err(|e| anyhow::anyhow!("{e}"))?;

        let text =
            fs::read_to_string(bpf_toml).with_context(|| format!("read {}", bpf_toml.display()))?;
        let declared = map_names(&text)?;
        let provisional: HashMap<String, u32> = declared
            .iter()
            .enumerate()
            .map(|(i, n)| (n.clone(), 0x1000 + i as u32 * MAP_PLACEHOLDER))
            .collect();
        let probe_doc = with_vmas(&text, &provisional)?;
        let probe_text = toml::to_string(&probe_doc).context("serialize map probe")?;
        let probe = metadata_from_toml_text(&probe_text, "bpf.toml", name, slot, helper, 1)?;
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
        let linked = LinkedImage::from_linked(words, holes, slot, helper);
        let bytes = linked.to_bytes();
        if bytes.len() != image_len as usize || linked.image_len() != image_len {
            bail!(
                "jit.bin is {} bytes but the linked image is {image_len}",
                bytes.len()
            );
        }

        let maps_doc = with_vmas(&text, &vmas)?;
        let meta_text = toml::to_string(&maps_doc).context("serialize map metadata")?;
        let meta = metadata_from_toml_text(&meta_text, "bpf.toml", name, slot, helper, 1)?;
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

        let relocs = reloc_records(&image.relocs, linked.words(), helper, &vmas)?;
        let maps = eligible
            .iter()
            .enumerate()
            .map(|(i, name)| MapRecord {
                name: name.clone(),
                metadata_index: i as u32,
                vmr: vmas[name],
                storage: MapStorage::Unknown,
            })
            .collect();
        let container = blob.as_slice().to_vec();
        let report = JitReport {
            source: src.to_path_buf(),
            section: loaded.section,
            isa: ISA,
            abi: ABI,
            ebpf_insns: u32::try_from(loaded.insns.len()).context("eBPF program is too long")?,
            rv_insns: u32::try_from(linked.words().len()).context("RV program is too long")?,
            code_len: linked.code_len(),
            slot,
            helper,
            image_len,
            container_len: u32::try_from(container.len()).context("container is too long")?,
            frame_size: frame_bytes(),
            disassembly: disassemble(linked.words(), slot),
            relocs,
            maps,
            jit_bin_sha256: sha256(&bytes),
            container_sha256: sha256(&container),
        };
        Ok(JitArtifact {
            image: linked,
            container,
            report,
            maps_doc,
        })
    }

    pub fn write_stage(&self, stage: &Path) -> Result<()> {
        match stage.file_name().and_then(|name| name.to_str()) {
            Some(".jit-stage") => {}
            other => bail!("refusing to write JIT bytes outside .jit-stage (got {other:?})"),
        }
        debug_assert_eq!(sha256(&self.image.to_bytes()), self.report.jit_bin_sha256);
        let bytes = self.image.to_bytes();
        let toml_text = serialize_toml(&self.maps_doc, &self.report)?;
        fs::create_dir_all(stage).with_context(|| format!("mkdir {}", stage.display()))?;
        let bin_path = stage.join("jit.bin");
        let toml_path = stage.join("jit.toml");
        let elf_path = stage.join("container.elf");
        fs::write(&bin_path, &bytes).with_context(|| format!("write {}", bin_path.display()))?;
        fs::write(&toml_path, toml_text)
            .with_context(|| format!("write {}", toml_path.display()))?;
        fs::write(&elf_path, &self.container)
            .with_context(|| format!("write {}", elf_path.display()))?;
        Ok(())
    }
}

fn reloc_records(
    relocs: &[xpost_jit::Reloc],
    words: &[u32],
    helper: u32,
    vmas: &HashMap<String, u32>,
) -> Result<Vec<RelocRecord>> {
    let mut out = Vec::with_capacity(relocs.len());
    for reloc in relocs {
        let target = match reloc.kind {
            RelocKind::Call => helper,
            RelocKind::Lddw => {
                let sym = reloc.symbol.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("lddw at bpf pc {} has no symbol", reloc.bpf_pc)
                })?;
                *vmas
                    .get(sym)
                    .with_context(|| format!("map `{sym}` has no VMR"))?
            }
            RelocKind::Func => bail!("bpf-to-bpf call at bpf pc {}", reloc.bpf_pc),
        };
        let symbol = match &reloc.symbol {
            Some(name) => name.clone(),
            None => format!("helper:{}", reloc.imm),
        };
        let n = reloc.kind.patch_words();
        if reloc.rv_off % 4 != 0 {
            bail!("reloc at {:#x} is not aligned", reloc.rv_off);
        }
        let at = (reloc.rv_off / 4) as usize;
        let end = at
            .checked_add(n)
            .filter(|end| *end <= words.len())
            .ok_or_else(|| anyhow::anyhow!("reloc at {:#x} is past the image", reloc.rv_off))?;
        out.push(RelocRecord {
            kind: reloc.kind.as_str(),
            source_bpf_pc: reloc.bpf_pc,
            symbol,
            target,
            patch_site: reloc.rv_off,
            result: words[at..end].to_vec(),
        });
    }
    Ok(out)
}

fn map_names(text: &str) -> Result<Vec<String>> {
    let root: Value = toml::from_str(text).context("parse bpf.toml")?;
    let mut names = Vec::new();
    if let Some(Value::Table(maps)) = root.get("maps") {
        for name in maps.keys() {
            names.push(name.clone());
        }
    }
    names.sort();
    Ok(names)
}

fn with_vmas(text: &str, vmas: &HashMap<String, u32>) -> Result<Value> {
    let mut root: Value = toml::from_str(text).context("parse bpf.toml")?;
    if let Some(Value::Table(maps)) = root.get_mut("maps") {
        for (name, item) in maps.iter_mut() {
            if let Value::Table(fields) = item {
                fields.remove("aot_addr");
                fields.remove("map_vma");
                if let Some(v) = vmas.get(name) {
                    fields.insert("map_vma".into(), Value::Integer(i64::from(*v)));
                }
            }
        }
    }
    Ok(root)
}

fn serialize_toml(maps_doc: &Value, report: &JitReport) -> Result<String> {
    let mut root = maps_doc.clone();
    let Value::Table(table) = &mut root else {
        bail!("bpf.toml root must be a table");
    };
    table.insert("jit".into(), jit_table(report));
    toml::to_string(&root).context("serialize jit toml")
}

fn jit_table(report: &JitReport) -> Value {
    let mut table = toml::map::Map::new();
    table.insert(
        "source".into(),
        Value::String(report.source.display().to_string()),
    );
    table.insert("section".into(), Value::String(report.section.clone()));
    table.insert("isa".into(), Value::String(report.isa.to_string()));
    table.insert("abi".into(), Value::String(report.abi.to_string()));
    table.insert(
        "ebpf_insns".into(),
        Value::Integer(i64::from(report.ebpf_insns)),
    );
    table.insert(
        "rv_insns".into(),
        Value::Integer(i64::from(report.rv_insns)),
    );
    table.insert(
        "code_len".into(),
        Value::Integer(i64::from(report.code_len)),
    );
    table.insert("slot".into(), Value::Integer(i64::from(report.slot)));
    table.insert("helper".into(), Value::Integer(i64::from(report.helper)));
    table.insert(
        "image_len".into(),
        Value::Integer(i64::from(report.image_len)),
    );
    table.insert(
        "container_len".into(),
        Value::Integer(i64::from(report.container_len)),
    );
    table.insert(
        "frame_size".into(),
        Value::Integer(i64::from(report.frame_size)),
    );
    table.insert(
        "jit_bin_sha256".into(),
        Value::String(hex_bytes(&report.jit_bin_sha256)),
    );
    table.insert(
        "container_sha256".into(),
        Value::String(hex_bytes(&report.container_sha256)),
    );
    table.insert(
        "disassembly".into(),
        Value::String(report.disassembly.clone()),
    );
    table.insert(
        "reloc".into(),
        Value::Array(report.relocs.iter().map(reloc_table).collect()),
    );
    table.insert(
        "map".into(),
        Value::Array(report.maps.iter().map(map_table).collect()),
    );
    Value::Table(table)
}

fn reloc_table(reloc: &RelocRecord) -> Value {
    let mut table = toml::map::Map::new();
    table.insert("kind".into(), Value::String(reloc.kind.to_string()));
    table.insert(
        "source_bpf_pc".into(),
        Value::Integer(i64::from(reloc.source_bpf_pc)),
    );
    table.insert("symbol".into(), Value::String(reloc.symbol.clone()));
    table.insert("target".into(), Value::Integer(i64::from(reloc.target)));
    table.insert(
        "patch_site".into(),
        Value::Integer(i64::from(reloc.patch_site)),
    );
    table.insert(
        "result".into(),
        Value::Array(
            reloc
                .result
                .iter()
                .map(|word| Value::Integer(i64::from(*word)))
                .collect(),
        ),
    );
    Value::Table(table)
}

fn map_table(map: &MapRecord) -> Value {
    let mut table = toml::map::Map::new();
    table.insert("name".into(), Value::String(map.name.clone()));
    table.insert(
        "metadata_index".into(),
        Value::Integer(i64::from(map.metadata_index)),
    );
    table.insert("vmr".into(), Value::Integer(i64::from(map.vmr)));
    table.insert(
        "storage".into(),
        Value::String(map.storage.as_str().to_string()),
    );
    Value::Table(table)
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stub_artifact(words: Vec<u32>, holes: u32) -> JitArtifact {
        let image = LinkedImage::from_linked(words, holes, 0x4038_0200, 0x4200_0000);
        let bytes = image.to_bytes();
        let hash = sha256(&bytes);
        let report = JitReport {
            source: PathBuf::from("firewall.c"),
            section: "xdp".into(),
            isa: ISA,
            abi: ABI,
            ebpf_insns: 1,
            rv_insns: image.words().len() as u32,
            code_len: image.code_len(),
            slot: image.slot,
            helper: image.helper,
            image_len: image.image_len(),
            container_len: 0,
            frame_size: 0,
            disassembly: String::new(),
            relocs: Vec::new(),
            maps: Vec::new(),
            jit_bin_sha256: hash,
            container_sha256: sha256(&[]),
        };
        JitArtifact {
            image,
            container: Vec::new(),
            report,
            maps_doc: Value::Table(toml::map::Map::new()),
        }
    }

    #[test]
    fn linked_words_round_trip_and_stage_must_be_named() {
        let words = vec![0x0000_0013u32, 0xfff0_0093];
        let artifact = stub_artifact(words.clone(), 16);
        let bytes = artifact.image.to_bytes();
        assert_eq!(bytes.len(), 8 + 16);
        assert_eq!(
            u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            words[0]
        );
        assert_eq!(
            u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            words[1]
        );
        assert!(bytes[8..].iter().all(|byte| *byte == 0));

        let root = std::env::temp_dir().join(format!(
            "xpost-jit-stage-{}-{}",
            std::process::id(),
            words[0]
        ));
        let _ = fs::remove_dir_all(&root);
        let public = root.join("firewall");
        let err = artifact.write_stage(&public).unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains(".jit-stage"), "{message}");
        assert!(!public.join("jit.bin").is_file());

        let stage = root.join(".jit-stage");
        artifact.write_stage(&stage).unwrap();
        assert_eq!(fs::read(stage.join("jit.bin")).unwrap(), bytes);
        let _ = fs::remove_dir_all(&root);
    }
}
