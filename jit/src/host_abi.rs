//! Host stand-in for `helper_dispatcher`.
//!
//! The firmware identifies a map by its VMR address and keeps the bytes elsewhere.
//! This model does the same split. The bytes at the VMR are a descriptor.
//! `storage` is the address of the values. It is not the VMR.

pub const HELPER: u32 = 0x4038_0000;
pub const MAP_MAGIC: u32 = u32::from_le_bytes(*b"MAP1");
pub const KIND_ARRAY: u32 = 1;
pub const KIND_HASH: u32 = 2;

pub fn write_map(
    mem: &mut [u8],
    at: u32,
    kind: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    storage: u32,
) -> Result<(), String> {
    let at = at as usize;
    if at.checked_add(24).map(|end| end > mem.len()).unwrap_or(true) {
        return Err("map descriptor does not fit".into());
    }
    put_u32(mem, at, MAP_MAGIC);
    put_u32(mem, at + 4, kind);
    put_u32(mem, at + 8, key_size);
    put_u32(mem, at + 12, value_size);
    put_u32(mem, at + 16, max_entries);
    put_u32(mem, at + 20, storage);
    Ok(())
}

pub fn dispatch(mem: &mut [u8], args: [u32; 6]) -> u32 {
    let [id, map, key, value, _flags, _] = args;
    match id {
        1 => lookup(mem, map, key).unwrap_or(0),
        2 => update(mem, map, key, value).unwrap_or(u32::MAX),
        3 => delete(mem, map, key).unwrap_or(u32::MAX),
        5 | 6 | 28 => 0,
        _ => u32::MAX,
    }
}

fn lookup(mem: &mut [u8], map: u32, key: u32) -> Option<u32> {
    let desc = desc(mem, map)?;
    match desc.kind {
        KIND_ARRAY => {
            let index = get_u32(mem, key)?;
            if index >= desc.max_entries {
                return Some(0);
            }
            Some(desc.storage.wrapping_add(index.wrapping_mul(desc.value_size)))
        }
        KIND_HASH => {
            let slot = find_hash(mem, &desc, key, false)?;
            Some(slot)
        }
        _ => Some(0),
    }
}

fn update(mem: &mut [u8], map: u32, key: u32, value: u32) -> Option<u32> {
    let desc = desc(mem, map)?;
    match desc.kind {
        KIND_ARRAY => {
            let index = get_u32(mem, key)?;
            if index >= desc.max_entries {
                return Some(u32::MAX);
            }
            let dst = desc.storage.wrapping_add(index.wrapping_mul(desc.value_size));
            copy_bytes(mem, value, dst, desc.value_size)?;
            Some(0)
        }
        KIND_HASH => {
            let slot = find_hash(mem, &desc, key, true)?;
            if slot == 0 {
                return Some(u32::MAX);
            }
            copy_bytes(mem, value, slot, desc.value_size)?;
            Some(0)
        }
        _ => Some(u32::MAX),
    }
}

fn delete(mem: &mut [u8], map: u32, key: u32) -> Option<u32> {
    let desc = desc(mem, map)?;
    if desc.kind != KIND_HASH {
        return Some(u32::MAX);
    }
    let stride = hash_stride(&desc)?;
    let key_size = desc.key_size as usize;
    for i in 0..desc.max_entries {
        let slot = desc.storage.wrapping_add(i.wrapping_mul(stride as u32)) as usize;
        if slot.checked_add(4 + key_size).map(|e| e > mem.len()).unwrap_or(true) {
            return None;
        }
        if get_u32(mem, slot as u32)? == 0 {
            continue;
        }
        if mem[slot + 4..slot + 4 + key_size] == mem[key as usize..key as usize + key_size] {
            put_u32(mem, slot, 0);
            return Some(0);
        }
    }
    Some(u32::MAX)
}

struct Desc {
    kind: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    storage: u32,
}

fn desc(mem: &[u8], map: u32) -> Option<Desc> {
    if get_u32(mem, map)? != MAP_MAGIC {
        return None;
    }
    Some(Desc {
        kind: get_u32(mem, map.wrapping_add(4))?,
        key_size: get_u32(mem, map.wrapping_add(8))?,
        value_size: get_u32(mem, map.wrapping_add(12))?,
        max_entries: get_u32(mem, map.wrapping_add(16))?,
        storage: get_u32(mem, map.wrapping_add(20))?,
    })
}

fn find_hash(mem: &mut [u8], desc: &Desc, key: u32, insert: bool) -> Option<u32> {
    let stride = hash_stride(desc)? as u32;
    let key_size = desc.key_size as usize;
    let key_at = key as usize;
    if key_at.checked_add(key_size).map(|e| e > mem.len()).unwrap_or(true) {
        return None;
    }
    let mut empty: Option<u32> = None;
    for i in 0..desc.max_entries {
        let slot = desc.storage.wrapping_add(i.wrapping_mul(stride));
        let used = get_u32(mem, slot)?;
        if used == 0 {
            if empty.is_none() {
                empty = Some(slot);
            }
            continue;
        }
        let start = slot as usize + 4;
        if start + key_size > mem.len() {
            return None;
        }
        if mem[start..start + key_size] == mem[key_at..key_at + key_size] {
            return Some(slot.wrapping_add(4 + align4(desc.key_size)));
        }
    }
    if !insert {
        return Some(0);
    }
    let slot = empty?;
    put_u32(mem, slot as usize, 1);
    copy_bytes(mem, key, slot.wrapping_add(4), desc.key_size)?;
    Some(slot.wrapping_add(4 + align4(desc.key_size)))
}

fn hash_stride(desc: &Desc) -> Option<usize> {
    let body = 4usize
        .checked_add(align4(desc.key_size) as usize)?
        .checked_add(align4(desc.value_size) as usize)?;
    Some(align4(body as u32) as usize)
}

fn align4(n: u32) -> u32 {
    n.wrapping_add(3) & !3
}

fn copy_bytes(mem: &mut [u8], src: u32, dst: u32, len: u32) -> Option<()> {
    let n = len as usize;
    let src = src as usize;
    let dst = dst as usize;
    if src.checked_add(n).map(|e| e > mem.len()).unwrap_or(true)
        || dst.checked_add(n).map(|e| e > mem.len()).unwrap_or(true)
    {
        return None;
    }
    if src == dst || n == 0 {
        return Some(());
    }
    if src < dst && src + n > dst {
        let tmp = mem[src..src + n].to_vec();
        mem[dst..dst + n].copy_from_slice(&tmp);
    } else {
        let tmp = mem[src..src + n].to_vec();
        mem[dst..dst + n].copy_from_slice(&tmp);
    }
    Some(())
}

fn get_u32(mem: &[u8], addr: u32) -> Option<u32> {
    let at = addr as usize;
    let bytes: [u8; 4] = mem.get(at..at + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn put_u32(mem: &mut [u8], addr: usize, value: u32) {
    mem[addr..addr + 4].copy_from_slice(&value.to_le_bytes());
}
