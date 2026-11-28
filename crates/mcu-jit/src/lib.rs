use std::{collections::HashMap, fs, path::Path};

use anyhow::{Context, Result, bail};
use mcu_image::{Fixup, FixupKind, Layout, Map, Mode, Region, RegionKind, map_record};
use xpost_jit::{Image, RelocKind, check_rv32im, compile, link_at_zero, load_bpf};

pub fn compile_object(input: &Path) -> Result<(Image, Vec<Map>)> {
    let loaded = load_bpf(input, None).map_err(|e| anyhow::anyhow!("{e}"))?;
    let image = compile(&loaded.insns, &loaded.symbols).map_err(|e| anyhow::anyhow!("{e}"))?;
    check_rv32im(&image.code).map_err(|e| anyhow::anyhow!("ISA: {e}"))?;
    let code = u32::try_from(image.code.len() * 4)?;
    let maps: Vec<_> = mcu_bpf::maps(&fs::read(input)?)?
        .into_iter()
        .enumerate()
        .map(|(i, (name, definition))| {
            let offset = code
                .checked_add(u32::try_from(i)? * 16)
                .context("JIT map offset overflow")?;
            Ok(map_record(name, definition, offset, 16))
        })
        .collect::<Result<_>>()?;
    Ok((image, maps))
}

pub fn portable(input: &Path) -> Result<(Layout, Vec<u8>)> {
    let (image, maps) = compile_object(input)?;
    let map_offsets = maps
        .iter()
        .map(|map| (map.name.clone(), map.offset))
        .collect::<HashMap<_, _>>();
    let words =
        link_at_zero(&image, &map_offsets).map_err(|e| anyhow::anyhow!("zero link: {e}"))?;
    let fixups = image
        .relocs
        .iter()
        .map(|reloc| {
            let (kind, target) = match reloc.kind {
                RelocKind::Call if reloc.symbol.is_none() => {
                    (FixupKind::CallAbs, "helper_dispatcher")
                }
                RelocKind::Lddw if reloc.imm == 0 => (
                    FixupKind::MapLddw,
                    reloc.symbol.as_deref().context("map symbol missing")?,
                ),
                _ => bail!("unsupported JIT relocation at BPF pc {}", reloc.bpf_pc),
            };
            Ok(Fixup {
                offset: reloc.rv_off,
                kind,
                target: target.to_owned(),
                addend: 0,
            })
        })
        .collect::<Result<_>>()?;
    let mut bytes: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    let code = u32::try_from(bytes.len())?;
    let mut regions = vec![Region {
        name: ".text".to_owned(),
        kind: RegionKind::Code,
        offset: 0,
        size: code,
        alignment: 4,
    }];
    if !maps.is_empty() {
        let size = u32::try_from(maps.len())? * 16;
        regions.push(Region {
            name: ".maps".to_owned(),
            kind: RegionKind::Maps,
            offset: code,
            size,
            alignment: 4,
        });
        bytes.resize((code + size) as usize, 0);
    }
    let name = input
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix("_bpf.o"))
        .context("expected an object named <program>_bpf.o")?
        .to_owned();
    Ok((Layout::new(name, Mode::Jit, regions, maps, fixups), bytes))
}
