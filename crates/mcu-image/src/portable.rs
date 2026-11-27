use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use xpost_elf::{ImageMetadataV0, MapDescriptorV0, build_container, sha256};

use super::{Mode, write_atomic};

pub const SCHEMA: &str = "libbpf-mcu.portable-image.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RegionKind {
    Code,
    Data,
    Maps,
    Zero,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Region {
    pub name: String,
    pub kind: RegionKind,
    pub offset: u32,
    pub size: u32,
    pub alignment: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Map {
    pub name: String,
    pub map_type: u8,
    pub len: u32,
    pub offset: u32,
    pub placeholder_bytes: u32,
    pub key_layout: Option<Vec<u8>>,
    pub value_layout: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FixupKind {
    Hi20,
    Lo12I,
    Lo12S,
    CallPcrel,
    CallAbs,
    MapLddw,
}

impl FixupKind {
    pub fn width(self) -> usize {
        match self {
            Self::Hi20 | Self::Lo12I | Self::Lo12S => 4,
            Self::CallPcrel | Self::CallAbs => 8,
            Self::MapLddw => 16,
        }
    }

    fn mode(self) -> Mode {
        match self {
            Self::Hi20 | Self::Lo12I | Self::Lo12S | Self::CallPcrel => Mode::Aot,
            Self::CallAbs | Self::MapLddw => Mode::Jit,
        }
    }

    fn is_helper(self) -> bool {
        matches!(self, Self::CallAbs | Self::CallPcrel)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Fixup {
    pub offset: u32,
    pub kind: FixupKind,
    pub target: String,
    pub addend: i32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Layout {
    pub schema: String,
    pub program: String,
    pub mode: Mode,
    pub base: u32,
    pub entry_offset: u32,
    pub alignment: u32,
    pub regions: Vec<Region>,
    pub maps: Vec<Map>,
    pub fixups: Vec<Fixup>,
}

#[derive(Clone, Copy)]
pub struct TargetLayout {
    pub slot: u32,
    pub capacity: u32,
    pub helper: u32,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    sha256(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn patch(kind: FixupKind, words: &mut [u32], value: u32) -> Result<()> {
    let high = value.wrapping_add(0x800) & 0xffff_f000;
    let low_i = |word: u32| (word & 0x000f_ffff) | ((value & 0xfff) << 20);
    match (kind, words) {
        (FixupKind::Hi20, [word]) if *word & 0x7f == 0x37 => *word = (*word & 0xfff) | high,
        (FixupKind::Lo12I, [word]) if *word & 0x7f == 0x03 || *word & 0x707f == 0x13 => {
            *word = low_i(*word)
        }
        (FixupKind::Lo12S, [word]) if *word & 0x7f == 0x23 => {
            *word = (*word & 0x01ff_f07f) | ((value & 0xfe0) << 20) | ((value & 0x1f) << 7);
        }
        (FixupKind::CallPcrel | FixupKind::CallAbs, [upper, lower]) => {
            let want = if kind == FixupKind::CallPcrel {
                (0x097, 0x080e7)
            } else {
                (0x337, 0x300e7)
            };
            ensure!(
                (*upper & 0xfff, *lower & 0x000f_ffff) == want,
                "invalid helper call encoding"
            );
            *upper = want.0 | high;
            *lower = low_i(*lower);
        }
        (FixupKind::MapLddw, [lo, lo_add, hi, hi_add]) => {
            let lo_reg = (*lo >> 7) & 31;
            let hi_reg = (*hi >> 7) & 31;
            ensure!(
                lo_reg != 0
                    && hi_reg != 0
                    && lo_reg != hi_reg
                    && *lo & 0x7f == 0x37
                    && *hi == (hi_reg << 7) | 0x37
                    && *lo_add & 0x000f_ffff == (lo_reg << 15) | (lo_reg << 7) | 0x13
                    && *hi_add == (hi_reg << 15) | (hi_reg << 7) | 0x13,
                "invalid JIT LDDW encoding"
            );
            *lo = (*lo & 0xfff) | high;
            *lo_add = low_i(*lo_add);
        }
        _ => bail!("unsupported {kind:?} instruction encoding"),
    }
    Ok(())
}

fn words(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
        .collect()
}

fn jit_sites(code: &[u8]) -> Vec<(u32, FixupKind)> {
    let mut sites = Vec::new();
    for offset in (0..code.len()).step_by(4) {
        if let Some(code) = code.get(offset..offset + 8) {
            if words(code) == [0x337, 0x300e7] {
                sites.push((offset as u32, FixupKind::CallAbs));
            }
        }
        if let Some(code) = code.get(offset..offset + 16) {
            if patch(FixupKind::MapLddw, &mut words(code), 0).is_ok() {
                sites.push((offset as u32, FixupKind::MapLddw));
            }
        }
    }
    sites
}

impl Layout {
    pub fn new(
        program: String,
        mode: Mode,
        regions: Vec<Region>,
        maps: Vec<Map>,
        fixups: Vec<Fixup>,
    ) -> Self {
        let alignment = regions
            .iter()
            .fold(4, |maximum, region| maximum.max(region.alignment));
        Self {
            schema: SCHEMA.to_owned(),
            program,
            mode,
            base: 0,
            entry_offset: 0,
            alignment,
            regions,
            maps,
            fixups,
        }
    }

    pub fn read(path: &Path) -> Result<Self> {
        serde_json::from_slice(&fs::read(path)?)
            .with_context(|| format!("parse {}", path.display()))
    }

    pub fn sites(&self) -> Vec<u32> {
        self.fixups.iter().map(|fixup| fixup.offset).collect()
    }

    pub fn write_pair(&self, output: &Path, image: &[u8]) -> Result<()> {
        self.validate(&self.program, self.mode, image, &self.sites())?;
        let mut json = serde_json::to_vec_pretty(self)?;
        json.push(b'\n');
        write_atomic(&output.join(format!("{}.bin", self.mode)), image)?;
        write_atomic(&output.join(format!("{}.json", self.mode)), &json)
    }

    pub fn validate(&self, program: &str, mode: Mode, image: &[u8], sites: &[u32]) -> Result<()> {
        ensure!(
            self.schema == SCHEMA && self.program == program && self.mode == mode,
            "portable image identity or version mismatch"
        );
        ensure!(
            self.base == 0 && self.entry_offset == 0,
            "expected zero base and entry"
        );
        ensure!(
            self.alignment.is_power_of_two() && (4..=4096).contains(&self.alignment),
            "invalid image alignment"
        );
        let stride = match mode {
            Mode::Aot => 2,
            Mode::Jit => 4,
            Mode::Ebpf => 8,
        };
        let code = self.validate_regions(image, stride)?;
        let maps = self.validate_maps(mode)?;
        let mut rv32_words = BTreeSet::new();
        if mode == Mode::Aot {
            for region in &code {
                let mut at = region.offset as usize;
                let end = at + region.size as usize;
                while at < end {
                    let first = image[at];
                    if first & 3 != 3 {
                        at += 2;
                        continue;
                    }
                    ensure!(
                        first & 0x1f != 0x1f && at + 4 <= end,
                        "invalid RV32IMC instruction extent"
                    );
                    rv32_words.insert(at);
                    at += 4;
                }
            }
        }
        let mut end = 0;
        for fixup in &self.fixups {
            let at = fixup.offset as usize;
            let width = fixup.kind.width();
            ensure!(
                fixup.addend == 0 && fixup.kind.mode() == mode && at >= end,
                "invalid or unordered fixup {fixup:?}"
            );
            end = at.checked_add(width).context("fixup end overflow")?;
            ensure!(
                at.is_multiple_of(stride)
                    && code
                        .iter()
                        .any(|r| r.offset as usize <= at && end <= (r.offset + r.size) as usize),
                "fixup outside code or misaligned"
            );
            ensure!(
                mode != Mode::Aot || (at..end).step_by(4).all(|at| rv32_words.contains(&at)),
                "RV32 fixup must start on a 32-bit instruction boundary"
            );
            let value = if fixup.kind.is_helper() {
                ensure!(
                    fixup.target == "helper_dispatcher",
                    "invalid helper fixup target"
                );
                if fixup.kind == FixupKind::CallPcrel {
                    0u32.wrapping_sub(fixup.offset)
                } else {
                    0
                }
            } else {
                *maps
                    .get(fixup.target.as_str())
                    .context("unknown map fixup target")?
            };
            let old = words(&image[at..end]);
            let mut canonical = old.clone();
            patch(fixup.kind, &mut canonical, value)?;
            ensure!(
                old == canonical,
                "{:?} at {at:#x} differs from the zero-address encoding",
                fixup.kind
            );
        }
        ensure!(
            self.sites() == sites,
            "fixups disagree with indexed required sites"
        );
        if mode == Mode::Jit {
            ensure!(
                code.len() == 1 && code[0].name == ".text",
                "invalid JIT code region"
            );
            ensure!(
                self.fixups
                    .iter()
                    .map(|f| (f.offset, f.kind))
                    .eq(jit_sites(&image[..code[0].size as usize])),
                "JIT fixups disagree with unresolved instruction sites"
            );
        }
        if mode == Mode::Ebpf {
            ensure!(
                code.len() == 1 && image.len() == code[0].size as usize,
                "invalid rBPF bytecode layout"
            );
            for (i, insn) in image.chunks_exact(8).enumerate() {
                if insn[0] == 0x18 && insn[1] >> 4 == 1 {
                    ensure!(
                        image.get(i * 8 + 8..i * 8 + 16) == Some(&[0; 8])
                            && (u32::from_le_bytes(insn[4..8].try_into().unwrap()) as usize)
                                < maps.len(),
                        "invalid rBPF map index"
                    );
                }
            }
        }
        Ok(())
    }

    fn validate_regions(&self, image: &[u8], stride: usize) -> Result<Vec<&Region>> {
        let mut names = BTreeSet::new();
        let mut code = Vec::new();
        let mut end = 0;
        ensure!(
            self.regions
                .first()
                .is_some_and(|r| r.offset == 0 && r.kind == RegionKind::Code),
            "regions do not cover the entry"
        );
        let length = u32::try_from(image.len())?;
        for region in &self.regions {
            let start = region.offset;
            let limit = start
                .checked_add(region.size)
                .context("region extent overflow")?;
            ensure!(
                region.size != 0
                    && start >= end
                    && limit <= length
                    && region.alignment.is_power_of_two()
                    && region.alignment <= self.alignment
                    && start.is_multiple_of(region.alignment)
                    && !region.name.is_empty()
                    && names.insert(&region.name)
                    && image[end as usize..start as usize]
                        .iter()
                        .all(|byte| *byte == 0),
                "invalid image region or padding: {}",
                region.name
            );
            if matches!(region.kind, RegionKind::Zero | RegionKind::Maps) {
                ensure!(
                    image[start as usize..limit as usize]
                        .iter()
                        .all(|byte| *byte == 0),
                    "nonzero map or zero-fill region"
                );
            }
            if region.kind == RegionKind::Code {
                ensure!(
                    (start as usize).is_multiple_of(stride)
                        && (region.size as usize).is_multiple_of(stride),
                    "misaligned code region"
                );
                code.push(region);
            }
            end = limit;
        }
        ensure!(end == length, "regions do not cover the image");
        Ok(code)
    }

    fn validate_maps(&self, mode: Mode) -> Result<BTreeMap<&str, u32>> {
        let mut ranges = Vec::new();
        let mut maps = BTreeMap::new();
        let mut previous = None;
        for map in &self.maps {
            let end = map
                .offset
                .checked_add(map.placeholder_bytes)
                .context("map extent overflow")?;
            ensure!(
                map.offset >= 4
                    && map.placeholder_bytes >= 4
                    && map.offset.is_multiple_of(4)
                    && map.placeholder_bytes.is_multiple_of(4),
                "invalid map placeholder extent"
            );
            ensure!(
                previous.is_none_or(|name| name < map.name.as_str()),
                "map names must be sorted and unique"
            );
            previous = Some(map.name.as_str());
            ensure!(
                mode == Mode::Ebpf
                    || self.regions.iter().any(|r| r.kind == RegionKind::Maps
                        && r.offset <= map.offset
                        && end <= r.offset + r.size),
                "map placeholder lies outside map regions"
            );
            ranges.push((map.offset, end));
            maps.insert(map.name.as_str(), map.offset);
        }
        ranges.sort_unstable();
        ensure!(
            ranges.windows(2).all(|pair| pair[0].1 <= pair[1].0),
            "overlapping map placeholders"
        );
        let meta = self.metadata(4, 4)?;
        build_container(&[1], &meta, None)
            .map_err(|error| anyhow::anyhow!("invalid Compact ELF metadata: {error:?}"))?;
        Ok(maps)
    }

    pub fn metadata(&self, slot: u32, helper: u32) -> Result<ImageMetadataV0> {
        let mut meta = ImageMetadataV0 {
            slot_address: slot,
            helper_address: helper,
            machine: 1,
            name: self
                .program
                .as_str()
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid program name"))?,
            maps: Default::default(),
        };
        for map in &self.maps {
            let field = |value: &[u8]| {
                heapless::Vec::from_slice(value)
                    .map_err(|_| anyhow::anyhow!("map field layout exceeds Compact ELF limits"))
            };
            let descriptor = MapDescriptorV0 {
                name: map
                    .name
                    .as_str()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid map name"))?,
                map_type: map.map_type,
                len: map.len,
                map_vma: slot.checked_add(map.offset).context("map VMR overflow")?,
                key_layout: map.key_layout.as_deref().map(field).transpose()?,
                value_layout: Some(field(&map.value_layout)?),
            };
            meta.maps
                .push(descriptor)
                .map_err(|_| anyhow::anyhow!("too many Compact ELF maps"))?;
        }
        Ok(meta)
    }

    pub fn bind(&self, image: &[u8], sites: &[u32], target: TargetLayout) -> Result<Vec<u8>> {
        self.validate(&self.program, self.mode, image, sites)?;
        let TargetLayout {
            slot,
            capacity,
            helper,
        } = target;
        let end = u64::from(slot) + u64::from(capacity);
        ensure!(
            slot >= 4
                && helper >= 4
                && slot.is_multiple_of(self.alignment)
                && helper.is_multiple_of(4),
            "slot or helper alignment does not match the image"
        );
        ensure!(
            end <= 1u64 << 32
                && image.len() <= capacity as usize
                && self
                    .maps
                    .iter()
                    .all(|map| map.offset + map.placeholder_bytes <= capacity),
            "image or map extent exceeds the target slot capacity"
        );
        ensure!(
            !(slot <= helper && u64::from(helper) < end),
            "helper overlaps the target slot"
        );
        let meta = self.metadata(slot, helper)?;
        let maps: BTreeMap<_, _> = meta
            .maps
            .iter()
            .map(|map| (map.name.as_str(), map.map_vma))
            .collect();
        let mut bound = image.to_vec();
        for fixup in &self.fixups {
            let at = fixup.offset as usize;
            let code = &mut bound[at..at + fixup.kind.width()];
            let value = match fixup.kind {
                FixupKind::CallPcrel => {
                    i32::try_from(i64::from(helper) - i64::from(slot) - i64::from(fixup.offset))
                        .context("PC-relative helper displacement overflow")?
                        as u32
                }
                FixupKind::CallAbs => helper,
                _ => maps[fixup.target.as_str()],
            };
            let mut instructions = words(code);
            patch(fixup.kind, &mut instructions, value)?;
            for (bytes, word) in code.chunks_exact_mut(4).zip(instructions) {
                bytes.copy_from_slice(&word.to_le_bytes());
            }
        }
        let container = build_container(&bound, &meta, Some(capacity))
            .map_err(|error| anyhow::anyhow!("encode bound image: {error:?}"))?;
        Ok(container.as_slice().to_vec())
    }
}
