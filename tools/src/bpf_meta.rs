//! Convert private BTF map inputs into Compact ELF metadata.

use std::{fs, path::Path};

use anyhow::{Context, Result, bail};
use toml::Value;

use xpost_elf::{ImageMetadataV0, MAX_ENTRIES, MAX_LAYOUT, MAX_MAPS, MAX_NAME, MapDescriptorV0};

/// Read the map definitions emitted by BTF extraction.
pub fn read_maps(path: &Path) -> Result<Value> {
    let display = path.display();
    let text = fs::read_to_string(path).with_context(|| format!("read {display}"))?;
    let root: Value = toml::from_str(&text).with_context(|| format!("parse {display}"))?;
    let Some(maps) = root
        .as_table()
        .filter(|root| root.len() == 1)
        .and_then(|root| root.get("maps"))
        .and_then(Value::as_table)
    else {
        bail!("{display}: expected a private [maps] input");
    };
    let fields = [
        "map_type",
        "max_entries",
        "key_size",
        "value_size",
        "key",
        "value",
    ];
    for (name, map) in maps {
        let Some(map) = map.as_table() else {
            bail!("{display}: map {name:?} must be a table");
        };
        if map.len() != fields.len() || fields.iter().any(|key| !map.contains_key(*key)) {
            bail!("{display}: map {name:?} must contain only BTF map definition fields");
        }
    }
    Ok(root)
}

/// Overlay map VMAs directly from the linked ELF, restricted to its maps section.
pub fn with_linked_maps(mut root: Value, path: &Path) -> Result<Value> {
    use object::{Object, ObjectSection, ObjectSymbol};

    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let elf = object::File::parse(&*bytes).context("parse linked AOT ELF")?;
    if let Some(Value::Table(maps)) = root.get_mut("maps") {
        for symbol in elf.symbols() {
            let Some(index) = symbol.section_index() else {
                continue;
            };
            let section = elf.section_by_index(index)?;
            if !matches!(section.name()?, ".maps" | "maps") || symbol.address() == 0 {
                continue;
            }
            if let Some(Value::Table(fields)) = maps.get_mut(symbol.name()?) {
                fields.insert(
                    "map_vma".into(),
                    i64::from(u32::try_from(symbol.address())?).into(),
                );
            }
        }
    }
    Ok(root)
}

pub fn metadata_from_value(
    root: &Value,
    label: &str,
    name: &str,
    slot_address: u32,
    helper_address: u32,
    machine: u8,
) -> Result<ImageMetadataV0> {
    let maps = root
        .get("maps")
        .cloned()
        .unwrap_or(Value::Table(Default::default()));
    let Value::Table(map_table) = maps else {
        bail!("{label}: maps must be TOML tables");
    };

    let mut records = heapless::Vec::<MapDescriptorV0, MAX_MAPS>::new();
    for (map_name, item) in &map_table {
        let Value::Table(fields) = item else {
            bail!("{label}: map {map_name:?} must be a table");
        };
        match map_descriptor(map_name, fields)
            .with_context(|| format!("{label}: map {map_name:?}"))?
        {
            None => continue,
            Some(rec) => records
                .push(rec)
                .map_err(|_| anyhow::anyhow!("{label}: more than {MAX_MAPS} maps"))?,
        }
    }

    let meta = ImageMetadataV0 {
        slot_address,
        helper_address,
        machine,
        name: heapless_name(name)?,
        maps: records,
    };
    xpost_elf::build_container(&[0x01], &meta, None)
        .map_err(|e| anyhow::anyhow!("invalid metadata: {e:?}"))?;
    Ok(meta)
}

fn map_descriptor(
    map_name: &str,
    fields: &toml::map::Map<String, Value>,
) -> Result<Option<MapDescriptorV0>> {
    let kind = match int_field(fields, "map_type")? {
        kind @ (1 | 2) => kind as u8,
        _ => return Ok(None),
    };
    let max_entries = int_field(fields, "max_entries")?;
    if !(1..=MAX_ENTRIES).contains(&max_entries) {
        return Ok(None);
    }

    let key_raw = match fields.get("key") {
        Some(Value::String(s)) => s.as_str(),
        _ => return Ok(None),
    };
    let value_raw = match fields.get("value") {
        Some(Value::String(s)) => s.as_str(),
        _ => return Ok(None),
    };
    let key_bits = layout_bit_intervals(key_raw)?;
    let value_bits = layout_bit_intervals(value_raw)?;
    if key_bits.is_empty() || value_bits.is_empty() {
        return Ok(None);
    }
    check_layout(&key_bits, 64)?;
    check_layout(&value_bits, 256)?;

    let key_size = int_field(fields, "key_size")? as usize;
    let value_size = int_field(fields, "value_size")? as usize;
    if key_bits.iter().map(|&b| usize::from(b)).sum::<usize>() != key_size * 8 {
        bail!("key layout does not match key_size");
    }
    if value_bits.iter().map(|&b| usize::from(b)).sum::<usize>() != value_size * 8 {
        bail!("value layout does not match value_size");
    }

    let key_layout = if kind == 2 {
        if key_bits.as_slice() != [32] {
            bail!("ARRAY requires an implicit u32 key");
        }
        None
    } else {
        Some(layout_vec(&key_bits)?)
    };
    let value_layout = Some(layout_vec(&value_bits)?);

    let Some(vma) = fields.get("map_vma") else {
        return Ok(None);
    };
    let vma = toml_u32(vma)?;
    Ok(Some(MapDescriptorV0 {
        name: heapless_name(map_name)?,
        map_type: kind,
        len: max_entries,
        map_vma: vma,
        key_layout,
        value_layout,
    }))
}

fn int_field(fields: &toml::map::Map<String, Value>, key: &str) -> Result<u32> {
    match fields.get(key) {
        Some(v) => toml_u32(v),
        None => bail!("missing {key}"),
    }
}

fn toml_u32(v: &Value) -> Result<u32> {
    match v {
        Value::Integer(i) if *i >= 0 && *i <= i64::from(u32::MAX) => Ok(*i as u32),
        other => bail!("expected u32, got {other:?}"),
    }
}

fn layout_bit_intervals(layout: &str) -> Result<Vec<u8>> {
    let mut intervals = Vec::new();
    for line in layout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.ends_with('{') || line == "}" {
            bail!("nested layout notation is unsupported: {line}");
        }
        let bits = parse_layout_line(line)?;
        if bits == 0 {
            bail!("layout interval must be positive");
        }
        if bits > 255 {
            bail!("layout interval bits must be 1..=255");
        }
        intervals.push(bits as u8);
    }
    Ok(intervals)
}

fn parse_layout_line(line: &str) -> Result<u32> {
    let bytes = line.as_bytes();
    if bytes.is_empty() {
        bail!("unsupported layout line `{line}`");
    }
    let kind = bytes[0];
    if kind != b'u' && kind != b'i' && kind != b'f' {
        bail!("unsupported layout line `{line}`");
    }
    let mut i = 1;
    let mut width: u32 = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        width = width
            .checked_mul(10)
            .and_then(|w| w.checked_add(u32::from(bytes[i] - b'0')))
            .ok_or_else(|| anyhow::anyhow!("unsupported layout line `{line}`"))?;
        i += 1;
    }
    if width == 0 {
        bail!("unsupported layout line `{line}`");
    }
    if i >= bytes.len() || bytes[i] != b' ' {
        bail!("unsupported layout line `{line}`");
    }
    i += 1;
    let name_start = i;
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
        i += 1;
    }
    if i == name_start {
        bail!("unsupported layout line `{line}`");
    }
    let mut count = 1u32;
    if i < bytes.len() {
        if bytes[i] != b'[' {
            bail!("unsupported layout line `{line}`");
        }
        i += 1;
        let mut n: u32 = 0;
        let digit_start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            n = n
                .checked_mul(10)
                .and_then(|w| w.checked_add(u32::from(bytes[i] - b'0')))
                .ok_or_else(|| anyhow::anyhow!("unsupported layout line `{line}`"))?;
            i += 1;
        }
        if i == digit_start || i >= bytes.len() || bytes[i] != b']' {
            bail!("unsupported layout line `{line}`");
        }
        i += 1;
        count = n;
    }
    if i != bytes.len() {
        bail!("unsupported layout line `{line}`");
    }
    width
        .checked_mul(count)
        .ok_or_else(|| anyhow::anyhow!("unsupported layout line `{line}`"))
}

fn check_layout(bits: &[u8], max_bytes: usize) -> Result<()> {
    if !(1..=MAX_LAYOUT).contains(&bits.len()) {
        bail!("layout must have 1..32 descriptors; empty is not None");
    }
    let sum: usize = bits.iter().map(|&b| usize::from(b)).sum();
    if sum % 8 != 0 || sum > max_bytes * 8 {
        bail!("layout must span whole bytes and at most {max_bytes} bytes");
    }
    Ok(())
}

fn layout_vec(bits: &[u8]) -> Result<heapless::Vec<u8, MAX_LAYOUT>> {
    let mut v = heapless::Vec::new();
    v.extend_from_slice(bits)
        .map_err(|_| anyhow::anyhow!("layout exceeds MAX_LAYOUT"))?;
    Ok(v)
}

pub(crate) fn heapless_name(s: &str) -> Result<heapless::String<{ MAX_NAME + 1 }>> {
    heapless::String::try_from(s).map_err(|_| anyhow::anyhow!("name must be 1..{MAX_NAME} ASCII"))
}
