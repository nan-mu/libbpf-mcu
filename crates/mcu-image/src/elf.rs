use std::{collections::BTreeMap, ops::Range};

use anyhow::{Context, Result, bail, ensure};
use object::{
    Object, ObjectSection, ObjectSymbol, RelocationTarget, SectionFlags, SymbolSection, elf::*,
};

use crate::{Fixup, FixupKind, Layout, Map, Region, RegionKind};

fn rv32(bytes: &[u8], linked: bool) -> Result<object::File<'_>> {
    let elf = object::File::parse(bytes)?;
    let kind = if linked {
        object::ObjectKind::Executable
    } else {
        object::ObjectKind::Relocatable
    };
    ensure!(
        elf.format() == object::BinaryFormat::Elf
            && elf.architecture() == object::Architecture::Riscv32
            && elf.is_little_endian()
            && elf.kind() == kind
            && matches!(elf.flags(), object::FileFlags::Elf { e_flags, .. } if e_flags & !EF_RISCV_RVC == 0),
        "expected an RV32IMC ILP32 ELF"
    );
    Ok(elf)
}

fn alloc<'a>(section: &impl ObjectSection<'a>, flag: u32) -> bool {
    matches!(section.flags(), SectionFlags::Elf { sh_flags } if sh_flags & u64::from(flag) == u64::from(flag))
}

fn relocations(elf: &object::File<'_>, linked: bool) -> Result<Vec<(object::SectionIndex, Fixup)>> {
    let mut fixups = Vec::new();
    for area in elf.sections().filter(|s| alloc(s, SHF_ALLOC)) {
        for (at, relocation) in area.relocations() {
            let RelocationTarget::Symbol(index) = relocation.target() else {
                bail!("unsupported relocation target");
            };
            let symbol = elf.symbol_by_index(index)?;
            let name = symbol.name()?;
            let target = symbol
                .section_index()
                .map(|i| elf.section_by_index(i))
                .transpose()?;
            let object::RelocationFlags::Elf { r_type } = relocation.flags() else {
                bail!("expected ELF relocation");
            };
            let offset = at
                .checked_sub(if linked { area.address() } else { 0 })
                .context("relocation before section")?;
            let local = match r_type {
                R_RISCV_BRANCH | R_RISCV_JAL => Some(4),
                R_RISCV_RVC_BRANCH | R_RISCV_RVC_JUMP => Some(2),
                _ => None,
            };
            if let Some(width) = local {
                ensure!(
                    target.is_some_and(|s| alloc(&s, SHF_EXECINSTR))
                        && alloc(&area, SHF_EXECINSTR)
                        && offset + width <= area.size(),
                    "non-local branch relocation"
                );
                continue;
            }
            let kind = match r_type {
                R_RISCV_CALL | R_RISCV_CALL_PLT => FixupKind::CallPcrel,
                R_RISCV_HI20 => FixupKind::Hi20,
                R_RISCV_LO12_I => FixupKind::Lo12I,
                R_RISCV_LO12_S => FixupKind::Lo12S,
                _ => bail!("unsupported allocatable RV32 relocation {r_type} to {name:?}"),
            };
            ensure!(
                !relocation.has_implicit_addend()
                    && relocation.addend() == 0
                    && alloc(&area, SHF_EXECINSTR)
                    && offset % 2 == 0
                    && offset + kind.width() as u64 <= area.size(),
                "invalid RV32 relocation"
            );
            if kind == FixupKind::CallPcrel {
                let expected = if linked {
                    SymbolSection::Absolute
                } else {
                    SymbolSection::Undefined
                };
                ensure!(
                    symbol.section() == expected
                        && symbol.address() == 0
                        && name == "helper_dispatcher",
                    "RV32 helper must be external or unresolved at zero"
                );
            } else {
                ensure!(
                    target.is_some_and(|s| matches!(s.name(), Ok(".maps" | "maps"))),
                    "unsupported absolute RV32 reference to {name}"
                );
            }
            fixups.push((
                area.index(),
                Fixup {
                    offset: u32::try_from(at)?,
                    kind,
                    target: name.to_owned(),
                    addend: 0,
                },
            ));
        }
    }
    Ok(fixups)
}

/// Read actual allocatable bytes, including linker-specified holes and zero storage.
fn payload(elf: &object::File<'_>, base: u32, limit: u32) -> Result<(Vec<u8>, Vec<Region>)> {
    let mut sections: Vec<_> = elf
        .sections()
        .filter(|s| s.size() != 0 && alloc(s, SHF_ALLOC))
        .collect();
    sections.sort_by_key(ObjectSection::address);
    let mut image = Vec::new();
    let mut regions = Vec::new();
    for section in sections {
        let name = section.name()?.to_owned();
        let offset = u32::try_from(section.address())?
            .checked_sub(base)
            .context("section before image base")?;
        let size = u32::try_from(section.size())?;
        let end = offset
            .checked_add(size)
            .context("section extent overflow")?;
        ensure!(
            offset as usize >= image.len() && end <= limit,
            "section {name} outside image"
        );
        let data = section.data()?;
        let bss = section.kind() == object::SectionKind::UninitializedData;
        ensure!(
            bss || data.len() == size as usize,
            "missing ELF section data: {name}"
        );
        let kind = if name == ".maps" {
            RegionKind::Maps
        } else if alloc(&section, SHF_EXECINSTR) && !bss {
            RegionKind::Code
        } else if bss {
            RegionKind::Zero
        } else {
            RegionKind::Data
        };
        image.resize(offset as usize, 0);
        if bss {
            image.resize(end as usize, 0);
        } else {
            image.extend_from_slice(data);
        }
        regions.push(Region {
            name,
            kind,
            offset,
            size,
            alignment: u32::try_from(section.align())?,
        });
    }
    ensure!(
        !image.is_empty() && elf.entry() == u64::from(base),
        "ELF image must start at entry"
    );
    Ok((image, regions))
}

pub fn map_record(
    name: String,
    definition: mcu_bpf::MapDefinition,
    offset: u32,
    placeholder_bytes: u32,
) -> Map {
    Map {
        name,
        offset,
        placeholder_bytes,
        map_type: definition.map_type,
        len: definition.len,
        key_layout: definition.key_layout,
        value_layout: definition.value_layout,
    }
}

pub fn aot_payload(
    linked: &[u8],
    bpf: &[u8],
    base: u32,
    limit: u32,
) -> Result<(Vec<u8>, Vec<Region>, Vec<Map>)> {
    let elf = rv32(linked, true)?;
    let (image, regions) = payload(&elf, base, limit)?;
    let map_section = elf.section_by_name(".maps").map(|section| section.index());
    let maps = mcu_bpf::maps(bpf)?
        .into_iter()
        .map(|(name, definition)| {
            let symbol = elf
                .symbols()
                .find(|sym| {
                    map_section.is_some()
                        && sym.section_index() == map_section
                        && sym.name() == Ok(&name)
                })
                .with_context(|| format!("linked ELF is missing the BPF map {name:?}"))?;
            Ok(map_record(
                name,
                definition,
                u32::try_from(symbol.address())?
                    .checked_sub(base)
                    .context("map before image base")?,
                u32::try_from(symbol.size())?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((image, regions, maps))
}

pub fn aot(
    program: String,
    linked: &[u8],
    reference: &[u8],
    bpf: &[u8],
) -> Result<(Layout, Vec<u8>)> {
    let elf = rv32(linked, true)?;
    let (image, regions, maps) = aot_payload(linked, bpf, 0, 1 << 24)?;
    let mut fixups: Vec<_> = relocations(&elf, true)?
        .into_iter()
        .map(|(_, fixup)| fixup)
        .collect();
    fixups.sort_by_key(|fixup| fixup.offset);
    let layout = Layout::new(program, crate::Mode::Aot, regions, maps, fixups);
    verify_aot(reference, &layout)?;
    Ok((layout, image))
}

pub fn verify_aot(reference: &[u8], layout: &Layout) -> Result<()> {
    let elf = rv32(reference, false)?;
    let mut offsets = BTreeMap::new();
    for region in layout
        .regions
        .iter()
        .filter(|region| region.kind == RegionKind::Code)
    {
        let patterns: &[&str] = match region.name.as_str() {
            ".xdp" => &["xdp", "xdp1", ".xdp", ".xdp.*"],
            ".text" => &[".text", ".text.*"],
            name => &[name],
        };
        let mut at = u64::from(region.offset);
        for pattern in patterns {
            for section in elf
                .sections()
                .filter(|section| alloc(section, SHF_ALLOC | SHF_EXECINSTR) && section.size() > 0)
            {
                let name = section.name()?;
                if !pattern
                    .strip_suffix('*')
                    .map_or(name == *pattern, |prefix| name.starts_with(prefix))
                {
                    continue;
                }
                let alignment = section.align().max(1);
                ensure!(
                    alignment.is_power_of_two() && alignment <= u64::from(region.alignment),
                    "invalid reference code alignment"
                );
                at = (at + alignment - 1) & !(alignment - 1);
                ensure!(
                    offsets.insert(section.index().0, at).is_none(),
                    "reference section appears twice"
                );
                at = at
                    .checked_add(section.size())
                    .context("reference code extent overflow")?;
            }
        }
        ensure!(
            at == u64::from(region.offset) + u64::from(region.size),
            "AOT code differs from no-relax reference extent"
        );
    }
    let mut expected = Vec::new();
    for (section, mut fixup) in relocations(&elf, false)? {
        let bias = offsets
            .get(&section.0)
            .context("reference fixup outside canonical code")?;
        fixup.offset = u32::try_from(bias + u64::from(fixup.offset))?;
        expected.push(fixup);
    }
    expected.sort_by_key(|fixup| fixup.offset);
    ensure!(
        expected == layout.fixups,
        "AOT fixups disagree with the reference object's relocation inventory"
    );
    Ok(())
}

pub fn elf_target(firmware: &[u8]) -> Result<crate::TargetLayout> {
    let elf = rv32(firmware, true)?;
    let section = elf
        .section_by_name(xpost_elf::SECTION_NAME)
        .context("firmware is missing the XPM1 section")?;
    let layout =
        xpost_elf::decode(section.data()?).map_err(|e| anyhow::anyhow!("decode XPM1: {e:?}"))?;
    Ok(crate::TargetLayout {
        slot: layout.slot_addr,
        capacity: layout.slot_len,
        helper: layout.helper_addr,
    })
}

pub fn code_range(region: &Region, image: &[u8]) -> Result<Range<usize>> {
    let end = region
        .offset
        .checked_add(region.size)
        .context("code region overflow")?;
    ensure!(end as usize <= image.len(), "code region outside image");
    Ok(region.offset as usize..end as usize)
}
