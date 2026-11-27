use std::collections::BTreeMap;

use anyhow::{Context, Result, bail, ensure};
use object::{Object, ObjectSection, ObjectSymbol};

#[derive(Debug)]
pub struct MapDefinition {
    pub map_type: u8,
    pub len: u32,
    pub key_layout: Option<Vec<u8>>,
    pub value_layout: Vec<u8>,
}

struct Type<'a> {
    name: &'a str,
    kind: u32,
    flag: bool,
    data: u32,
    payload: &'a [u8],
}

fn word(data: &[u8], at: usize) -> Result<u32> {
    let bytes = data.get(at..at + 4).context("truncated BTF record")?;
    Ok(u32::from_le_bytes(bytes.try_into()?))
}

fn string(strings: &[u8], offset: u32) -> Result<&str> {
    let data = strings
        .get(offset as usize..)
        .context("BTF string offset out of bounds")?;
    let end = data
        .iter()
        .position(|byte| *byte == 0)
        .context("unterminated BTF string")?;
    Ok(std::str::from_utf8(&data[..end])?)
}

struct Btf<'a> {
    types: Vec<Type<'a>>,
    strings: &'a [u8],
}

impl<'a> Btf<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        ensure!(
            bytes.starts_with(&[0x9f, 0xeb, 1, 0]),
            "expected little-endian BTF v1"
        );
        let start = word(bytes, 4)? as usize;
        ensure!(start >= 24, "invalid BTF header size");
        let section = |at| {
            let offset = start
                .checked_add(word(bytes, at)? as usize)
                .context("BTF section offset overflow")?;
            let end = offset
                .checked_add(word(bytes, at + 4)? as usize)
                .context("BTF section size overflow")?;
            bytes
                .get(offset..end)
                .context("BTF section exceeds its data")
        };
        let strings = section(16)?;
        let mut remaining = section(8)?;
        let mut types = Vec::new();
        while !remaining.is_empty() {
            let name = string(strings, word(remaining, 0)?)?;
            let info = word(remaining, 4)?;
            let kind = (info >> 24) & 31;
            let data = word(remaining, 8)?;
            let entries = (info & 0xffff) as usize;
            let size = match kind {
                1 | 14 | 17 => 4,
                3 => 12,
                4 | 5 | 15 | 19 => 12 * entries,
                6 | 13 => 8 * entries,
                0 | 2 | 7..=12 | 16 | 18 => 0,
                _ => bail!("unsupported BTF type {kind}"),
            };
            let payload = remaining.get(12..12 + size).context("truncated BTF type")?;
            types.push(Type {
                name,
                kind,
                flag: info >> 31 != 0,
                data,
                payload,
            });
            remaining = &remaining[12 + size..];
        }
        Ok(Self { types, strings })
    }

    fn get(&self, id: u32) -> Result<&Type<'a>> {
        self.types
            .get(id.wrapping_sub(1) as usize)
            .context("invalid BTF type id")
    }

    fn resolved(&self, mut id: u32) -> Result<&Type<'a>> {
        for _ in 0..self.types.len() {
            let ty = self.get(id)?;
            if !matches!(ty.kind, 8..=11 | 18) {
                return Ok(ty);
            }
            id = ty.data;
        }
        bail!("cyclic BTF typedef")
    }

    fn pointee(&self, id: u32) -> Result<u32> {
        let ty = self.resolved(id)?;
        ensure!(ty.kind == 2, "expected a pointer in BTF map definition");
        Ok(ty.data)
    }

    fn uint(&self, id: u32) -> Result<u32> {
        let ty = self.resolved(self.pointee(id)?)?;
        ensure!(ty.kind == 3, "expected an array in BTF map definition");
        word(ty.payload, 8)
    }

    fn intervals(&self, id: u32, depth: usize) -> Result<Vec<u32>> {
        ensure!(depth < 64, "BTF layout is too deeply nested");
        let ty = self.resolved(id)?;
        let bits = || ty.data.checked_mul(8).context("BTF size overflow");
        match ty.kind {
            1 | 6 | 16 | 19 => Ok(vec![bits()?]),
            3 => {
                let element = self.intervals(word(ty.payload, 0)?, depth + 1)?;
                let bits = sum(&element)?
                    .checked_mul(word(ty.payload, 8)?)
                    .context("BTF array size overflow")?;
                Ok(vec![bits])
            }
            4 => {
                let mut fields = Vec::new();
                let mut position = 0;
                let size = bits()?;
                for member in ty.payload.chunks_exact(12) {
                    let field_id = word(member, 4)?;
                    let raw = word(member, 8)?;
                    let (mut offset, mut width) = if ty.flag {
                        (raw & 0xff_ffff, raw >> 24)
                    } else {
                        (raw, 0)
                    };
                    let base = self.resolved(field_id)?;
                    if !ty.flag && base.kind == 1 {
                        let raw = word(base.payload, 0)?;
                        offset = offset
                            .checked_add((raw >> 16) & 0xff)
                            .context("field offset overflow")?;
                        let encoded = raw & 0xff;
                        if encoded != 0 && Some(encoded) != base.data.checked_mul(8) {
                            width = encoded;
                        }
                    }
                    ensure!(offset >= position, "overlapping BTF structure fields");
                    if offset > position {
                        fields.push(offset - position);
                    }
                    let intervals = if width == 0 {
                        self.intervals(field_id, depth + 1)?
                    } else {
                        ensure!(
                            matches!(base.kind, 1 | 6 | 19),
                            "unsupported BTF bitfield type"
                        );
                        vec![width]
                    };
                    position = offset
                        .checked_add(sum(&intervals)?)
                        .context("BTF structure size overflow")?;
                    ensure!(
                        position <= size && fields.len() + intervals.len() <= 256,
                        "invalid BTF structure layout"
                    );
                    fields.extend(intervals);
                }
                if position < size {
                    fields.push(size - position);
                }
                Ok(fields)
            }
            _ => bail!("unsupported BTF map field kind {}", ty.kind),
        }
    }

    fn definition(&self, var: &Type<'a>, classic: &[u8]) -> Result<Option<MapDefinition>> {
        let structure = self.resolved(var.data)?;
        ensure!(structure.kind == 4, "BTF map must be a structure");
        let mut map_type = None;
        let (mut len, mut key_size, mut value_size, mut key, mut value) = (0, 0, 0, None, None);
        for member in structure.payload.chunks_exact(12) {
            let name = string(self.strings, word(member, 0)?)?;
            let id = word(member, 4)?;
            match name {
                "type" => map_type = Some(self.uint(id)?),
                "max_entries" => len = self.uint(id)?,
                "key_size" => key_size = self.uint(id)?,
                "value_size" => value_size = self.uint(id)?,
                "key" => key = Some(self.pointee(id)?),
                "value" => value = Some(self.pointee(id)?),
                _ => {}
            }
        }
        let map_type = if let Some(map_type) = map_type {
            map_type
        } else {
            key_size = word(classic, 4)?;
            value_size = word(classic, 8)?;
            len = word(classic, 12)?;
            word(classic, 0)?
        };
        if !matches!(map_type, 1 | 2) || !(1..=xpost_elf::MAX_ENTRIES).contains(&len) {
            return Ok(None);
        }
        let intervals = |id, size: u32, limit| -> Result<Vec<u8>> {
            let bits = size.checked_mul(8).context("BTF field size overflow")?;
            let values = match id {
                Some(id) => self.intervals(id, 0)?,
                None => vec![bits],
            };
            let total = sum(&values)?;
            ensure!(
                total > 0 && total % 8 == 0 && total / 8 <= limit && (size == 0 || total == bits),
                "BTF layout does not match declared map field size"
            );
            values
                .into_iter()
                .map(|width| {
                    ensure!(width != 0, "zero-width BTF interval");
                    Ok(u8::try_from(width).context("BTF field exceeds 255 bits")?)
                })
                .collect()
        };
        let key_layout = intervals(key, key_size, 64)?;
        let key_layout = if map_type == 2 {
            ensure!(key_layout == [32], "ARRAY requires an implicit u32 key");
            None
        } else {
            Some(key_layout)
        };
        Ok(Some(MapDefinition {
            map_type: map_type as u8,
            len,
            key_layout,
            value_layout: intervals(value, value_size, 256)?,
        }))
    }
}

fn sum(widths: &[u32]) -> Result<u32> {
    widths.iter().try_fold(0u32, |total, width| {
        total
            .checked_add(*width)
            .context("BTF layout size overflow")
    })
}

pub fn maps(bytes: &[u8]) -> Result<BTreeMap<String, MapDefinition>> {
    let elf = super::object(bytes)?;
    let btf = Btf::parse(
        elf.section_by_name(".BTF")
            .context("missing BTF section")?
            .data()?,
    )?;
    let mut maps = BTreeMap::new();
    for section in btf
        .types
        .iter()
        .filter(|ty| ty.kind == 15 && matches!(ty.name, ".maps" | "maps"))
    {
        let map_section = elf
            .section_by_name(section.name)
            .context("BTF refers to missing maps section")?;
        let data = map_section.data()?;
        for record in section.payload.chunks_exact(12) {
            let var = btf.get(word(record, 0)?)?;
            ensure!(var.kind == 14, "invalid BTF map variable");
            // The ELF symbol incorporates relocations to BTF DATASEC offsets.
            let symbol = elf
                .symbols()
                .find(|s| {
                    s.section_index() == Some(map_section.index()) && s.name() == Ok(var.name)
                })
                .with_context(|| format!("missing map symbol {}", var.name))?;
            let start = usize::try_from(symbol.address())?;
            let end = start
                .checked_add(usize::try_from(symbol.size())?)
                .context("map size overflow")?;
            let classic = data
                .get(start..end)
                .context("map descriptor outside ELF section")?;
            if let Some(definition) = btf
                .definition(var, classic)
                .with_context(|| format!("map {}", var.name))?
            {
                ensure!(
                    maps.insert(var.name.to_owned(), definition).is_none(),
                    "duplicate BPF map {}",
                    var.name
                );
            }
        }
    }
    Ok(maps)
}
