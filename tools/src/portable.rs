//! Producer commands for portable images and the resolved Compact ELF encoder.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use object::{Object, ObjectSection, ObjectSymbol};
use serde::Deserialize;
use serde_json::{Value, json};
use xpost_elf::{ImageMetadataV0, MapDescriptorV0, build_container};
use xpost_jit::{RelocKind, check_rv32im, compile, link_at_zero, load_bpf};

use crate::bpf_meta::{heapless_name, metadata_from_value, read_maps, with_linked_maps};
use crate::jit_image::{MAP_PLACEHOLDER, eligible_maps, with_vmas};
use crate::{index_map_references, write_atomic};

fn map_record(map: &MapDescriptorV0, size: u32) -> Value {
    json!({
        "name": map.name.as_str(),
        "map_type": map.map_type,
        "len": map.len,
        "offset": map.map_vma,
        "placeholder_bytes": size,
        "key_layout": map.key_layout.as_deref(),
        "value_layout": map.value_layout.as_deref(),
    })
}

pub fn describe_maps(maps: &Path, linked: &Path, name: &str) -> Result<()> {
    let bytes = fs::read(linked)?;
    let elf = object::File::parse(&*bytes)?;
    let maps_section = elf.section_by_name(".maps").map(|s| s.index());
    let doc = with_linked_maps(read_maps(maps)?, linked)?;
    let meta = metadata_from_value(&doc, "canonical AOT map definitions", name, 4, 4, 1)?;
    let rows = meta
        .maps
        .iter()
        .map(|map| {
            let size = elf
                .symbols()
                .find(|s| {
                    s.section_index().is_some()
                        && s.section_index() == maps_section
                        && s.name() == Ok(map.name.as_str())
                        && s.address() == u64::from(map.map_vma)
                })
                .context("map missing its canonical ELF symbol")?
                .size();
            Ok(map_record(map, u32::try_from(size)?))
        })
        .collect::<Result<Vec<_>>>()?;
    println!("{}", json!(rows));
    Ok(())
}

pub fn emit_jit(obj: &Path, maps: &Path, name: &str, output: &Path) -> Result<()> {
    let loaded = load_bpf(obj, None).map_err(|e| anyhow::anyhow!("{e}"))?;
    let image = compile(&loaded.insns, &loaded.symbols).map_err(|e| anyhow::anyhow!("{e}"))?;
    check_rv32im(&image.code).map_err(|e| anyhow::anyhow!("ISA: {e}"))?;
    let doc = read_maps(maps)?;
    let eligible = eligible_maps(&doc, name, &image)?;
    let code_bytes = u32::try_from(image.code.len() * 4)?;
    let vmas: HashMap<_, _> = eligible
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let offset = code_bytes
                .checked_add(MAP_PLACEHOLDER * u32::try_from(i)?)
                .context("JIT map offset overflow")?;
            Ok((name.clone(), offset))
        })
        .collect::<Result<_>>()?;
    let words = link_at_zero(&image, &vmas).map_err(|e| anyhow::anyhow!("zero link: {e}"))?;
    let mut bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    let meta = metadata_from_value(&with_vmas(doc, &vmas), "JIT map definitions", name, 4, 4, 1)?;
    let fixups = image
        .relocs
        .iter()
        .map(|reloc| {
            let (kind, target) = match reloc.kind {
                RelocKind::Call if reloc.symbol.is_none() => ("call-abs", "helper_dispatcher"),
                RelocKind::Lddw if reloc.imm == 0 => (
                    "map-lddw",
                    reloc.symbol.as_deref().context("map symbol missing")?,
                ),
                _ => bail!("unsupported JIT relocation at BPF pc {}", reloc.bpf_pc),
            };
            Ok(json!({"offset": reloc.rv_off, "kind": kind, "target": target, "addend": 0}))
        })
        .collect::<Result<Vec<_>>>()?;
    let hole_bytes = MAP_PLACEHOLDER * u32::try_from(meta.maps.len())?;
    bytes.resize(
        code_bytes
            .checked_add(hole_bytes)
            .context("JIT image overflow")? as usize,
        0,
    );
    let mut regions = vec![json!({
        "name": ".text", "kind": "code", "offset": 0, "size": code_bytes, "alignment": 4
    })];
    if hole_bytes != 0 {
        regions.push(json!({
            "name": ".maps", "kind": "maps", "offset": code_bytes,
            "size": hole_bytes, "alignment": 4
        }));
    }
    write_atomic(output, &bytes)?;
    println!(
        "{}",
        json!({
            "regions": regions,
            "maps": meta.maps.iter().map(|map| map_record(map, MAP_PLACEHOLDER)).collect::<Vec<_>>(),
            "fixups": fixups
        })
    );
    Ok(())
}

#[derive(Deserialize)]
struct IndexMap {
    name: String,
}

#[derive(Deserialize)]
struct InterpreterLayout {
    maps: Vec<IndexMap>,
}

pub fn emit_ebpf(obj: &PathBuf, layout: &Path, output: &Path) -> Result<()> {
    let layout: InterpreterLayout = serde_json::from_slice(&fs::read(layout)?)?;
    let original = fs::read(obj)?;
    let file = object::File::parse(&*original)?;
    let section = file
        .sections()
        .find(|s| matches!(s.name(), Ok("xdp" | "xdp1")) && s.size() != 0)
        .context("object has no XDP code")?;
    let names: Vec<_> = layout.maps.iter().map(|m| m.name.as_str()).collect();
    let (image, _) = index_map_references(section.data()?, obj, &names)?;
    rbpf::EbpfVmMbuff::verify(&image).map_err(|e| anyhow::anyhow!("rBPF verifier: {e:?}"))?;
    write_atomic(output, &image)?;
    println!("{}", json!(section.name()?));
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolvedMap {
    name: String,
    map_type: u8,
    len: u32,
    map_vma: u32,
    key_layout: Option<Vec<u8>>,
    value_layout: Option<Vec<u8>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolvedLayout {
    slot_address: u32,
    helper_address: u32,
    machine: u8,
    name: String,
    maps: Vec<ResolvedMap>,
}

pub fn pack_resolved(image: &Path, metadata: &Path, capacity: u32, out: &Path) -> Result<()> {
    let image = fs::read(image)?;
    let resolved: ResolvedLayout = serde_json::from_slice(&fs::read(metadata)?)?;
    let mut meta = ImageMetadataV0 {
        slot_address: resolved.slot_address,
        helper_address: resolved.helper_address,
        machine: resolved.machine,
        name: heapless_name(&resolved.name)?,
        maps: Default::default(),
    };
    for item in resolved.maps {
        ensure!(
            item.map_vma >= meta.slot_address && item.map_vma - meta.slot_address < capacity,
            "map VMR outside the supplied slot"
        );
        let layout = |value: Option<Vec<u8>>| {
            value
                .map(|bytes| {
                    heapless::Vec::from_slice(&bytes)
                        .map_err(|_| anyhow::anyhow!("map layout exceeds Compact ELF limits"))
                })
                .transpose()
        };
        meta.maps
            .push(MapDescriptorV0 {
                name: heapless_name(&item.name)?,
                map_type: item.map_type,
                len: item.len,
                map_vma: item.map_vma,
                key_layout: layout(item.key_layout)?,
                value_layout: layout(item.value_layout)?,
            })
            .map_err(|_| anyhow::anyhow!("too many Compact ELF maps"))?;
    }
    let blob = build_container(&image, &meta, Some(capacity))
        .map_err(|e| anyhow::anyhow!("encode bound image: {e:?}"))?;
    write_atomic(out, blob.as_slice())
}
