//! Raw eBPF words, or the executable section of an ELF (`bpf.o`).

use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::path::Path;

use crate::bpf::{self, Insn};

#[derive(Debug)]
pub struct LoadError(pub String);

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LoadError {}

/// `symbols` maps a byte offset in the instruction stream to an ELF symbol
/// name (`R_BPF_*` at that offset). Raw input has an empty map.
pub struct Source {
    pub insns: Vec<Insn>,
    pub symbols: HashMap<u64, String>,
    pub section: String,
}

pub fn load_bpf(path: &Path, section: Option<&str>) -> Result<Source, LoadError> {
    let bytes = if path == Path::new("-") {
        let mut buf = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| LoadError(format!("read stdin: {e}")))?;
        buf
    } else {
        fs::read(path).map_err(|e| LoadError(format!("read {}: {e}", path.display())))?
    };
    if bytes.len() >= 4 && bytes[..4] == [0x7f, b'E', b'L', b'F'] {
        load_elf(&bytes, section)
    } else if section.is_some() {
        Err(LoadError(
            "--section applies to ELF input, and this file is not ELF".into(),
        ))
    } else {
        let insns = bpf::decode_insns(&bytes).map_err(LoadError)?;
        Ok(Source {
            insns,
            symbols: HashMap::new(),
            section: "raw".into(),
        })
    }
}

fn load_elf(bytes: &[u8], want: Option<&str>) -> Result<Source, LoadError> {
    if bytes.len() < 64 {
        return Err(LoadError("ELF header is truncated".into()));
    }
    if bytes[5] != 1 {
        return Err(LoadError("ELF is not little-endian".into()));
    }
    let class = bytes[4];
    if class != 1 && class != 2 {
        return Err(LoadError(format!("ELF class {class} is not 32 or 64")));
    }
    let elf64 = class == 2;
    let machine = u16_at(bytes, 18)?;
    if machine != 247 {
        return Err(LoadError(format!(
            "ELF machine {machine} is not EM_BPF (247)"
        )));
    }
    let (shoff, shentsize, shnum, shstrndx) = if elf64 {
        (
            u64_at(bytes, 40)? as usize,
            u16_at(bytes, 58)? as usize,
            u16_at(bytes, 60)? as usize,
            u16_at(bytes, 62)? as usize,
        )
    } else {
        (
            u32_at(bytes, 32)? as usize,
            u16_at(bytes, 46)? as usize,
            u16_at(bytes, 48)? as usize,
            u16_at(bytes, 50)? as usize,
        )
    };
    let min_shentsize = if elf64 { 64 } else { 40 };
    if shentsize < min_shentsize || shnum == 0 {
        return Err(LoadError(format!(
            "ELF section headers are absent or shorter than {min_shentsize}"
        )));
    }
    if shstrndx >= shnum {
        return Err(LoadError(format!(
            "e_shstrndx {shstrndx} is outside {shnum} sections"
        )));
    }
    let shstr = section_payload(bytes, elf64, shoff, shentsize, shstrndx)?;
    let mut names = Vec::with_capacity(shnum);
    let mut named: Option<usize> = None;
    let mut xdp: Option<usize> = None;
    let mut fallback: Option<usize> = None;
    for i in 0..shnum {
        let (name_off, ty, flags, _off, size) = shdr(bytes, elf64, shoff, shentsize, i)?;
        let name = cstr(&shstr, name_off).unwrap_or("").to_string();
        let exec = flags & 4 != 0;
        let progbits = ty == 1;
        if want == Some(name.as_str()) {
            named = Some(i);
        }
        // Clang leaves an empty executable `.text` ahead of `xdp` / `xdp1`.
        // A zero-length section is not a program. Prefer the XDP section.
        if progbits && exec && size > 0 {
            if name == "xdp" || name == "xdp1" {
                if xdp.is_some() {
                    return Err(LoadError("ELF has more than one xdp section".into()));
                }
                xdp = Some(i);
            } else if fallback.is_none() {
                fallback = Some(i);
            }
        }
        names.push(name);
    }
    let idx = if want.is_some() {
        named.ok_or_else(|| {
            LoadError(format!(
                "no eBPF section (want {}, have {})",
                want.unwrap_or("<exec PROGBITS>"),
                names.join(", ")
            ))
        })?
    } else {
        xdp.or(fallback).ok_or_else(|| {
            LoadError(format!(
                "no eBPF section (want <xdp or nonempty exec>, have {})",
                names.join(", ")
            ))
        })?
    };
    let text = section_payload(bytes, elf64, shoff, shentsize, idx)?;
    let insns = bpf::decode_insns(&text).map_err(LoadError)?;
    let symbols = relocations(bytes, elf64, shoff, shentsize, shnum, idx)?;
    Ok(Source {
        insns,
        symbols,
        section: names[idx].clone(),
    })
}

fn relocations(
    bytes: &[u8],
    elf64: bool,
    shoff: usize,
    shentsize: usize,
    shnum: usize,
    text: usize,
) -> Result<HashMap<u64, String>, LoadError> {
    let mut out = HashMap::new();
    for i in 0..shnum {
        let (_name, ty, _flags, off, size) = shdr(bytes, elf64, shoff, shentsize, i)?;
        // SHT_RELA = 4, SHT_REL = 9. sh_info is the target section.
        if ty != 4 && ty != 9 {
            continue;
        }
        let info = sh_info(bytes, elf64, shoff, shentsize, i)?;
        if info as usize != text {
            continue;
        }
        let symtab = sh_link(bytes, elf64, shoff, shentsize, i)? as usize;
        let rela = ty == 4;
        let ent = if elf64 {
            if rela {
                24
            } else {
                16
            }
        } else if rela {
            12
        } else {
            8
        };
        if ent == 0 || size % ent != 0 {
            return Err(LoadError(format!(
                "relocation section size {size} is not a multiple of {ent}"
            )));
        }
        let end = off.checked_add(size).ok_or_else(|| {
            LoadError("relocation section end overflows".into())
        })?;
        if end > bytes.len() {
            return Err(LoadError(format!(
                "relocation section extends to {end}, file is {}",
                bytes.len()
            )));
        }
        let n = size / ent;
        for k in 0..n {
            let at = off + k * ent;
            let (r_off, r_info) = if elf64 {
                (u64_at(bytes, at)?, u64_at(bytes, at + 8)?)
            } else {
                (
                    u64::from(u32_at(bytes, at)?),
                    u64::from(u32_at(bytes, at + 4)?),
                )
            };
            let (sym_idx, r_type) = if elf64 {
                ((r_info >> 32) as usize, (r_info & 0xffff_ffff) as u32)
            } else {
                ((r_info >> 8) as usize, (r_info & 0xff) as u32)
            };
            if r_type != 1 {
                return Err(LoadError(format!(
                    "relocation type {r_type} is not R_BPF_64_64"
                )));
            }
            if let Some(name) = symbol_name(bytes, elf64, shoff, shentsize, symtab, sym_idx)? {
                if !name.is_empty() {
                    out.insert(r_off, name);
                }
            }
        }
    }
    Ok(out)
}

fn symbol_name(
    bytes: &[u8],
    elf64: bool,
    shoff: usize,
    shentsize: usize,
    symtab: usize,
    sym_idx: usize,
) -> Result<Option<String>, LoadError> {
    let (_n, ty, _f, off, size) = shdr(bytes, elf64, shoff, shentsize, symtab)?;
    if ty != 2 {
        return Ok(None);
    }
    let ent = if elf64 { 24 } else { 16 };
    let step = match sym_idx.checked_mul(ent) {
        Some(step) => step,
        None => return Ok(None),
    };
    let at = match off.checked_add(step) {
        Some(at) => at,
        None => return Ok(None),
    };
    let sym_end = match at.checked_add(ent) {
        Some(end) => end,
        None => return Ok(None),
    };
    if sym_end > off + size || at + 4 > bytes.len() {
        return Ok(None);
    }
    let name_off = u32_at(bytes, at)? as usize;
    let strtab = sh_link(bytes, elf64, shoff, shentsize, symtab)? as usize;
    let strings = section_payload(bytes, elf64, shoff, shentsize, strtab)?;
    Ok(cstr(&strings, name_off).map(str::to_string))
}

fn section_payload(
    bytes: &[u8],
    elf64: bool,
    shoff: usize,
    shentsize: usize,
    idx: usize,
) -> Result<Vec<u8>, LoadError> {
    let (_n, _ty, _f, off, size) = shdr(bytes, elf64, shoff, shentsize, idx)?;
    let end = off
        .checked_add(size)
        .ok_or_else(|| LoadError("section end overflows".into()))?;
    if end > bytes.len() {
        return Err(LoadError(format!(
            "section {idx} extends to {end}, file is {}",
            bytes.len()
        )));
    }
    Ok(bytes[off..end].to_vec())
}

fn sh_at(
    bytes: &[u8],
    shoff: usize,
    shentsize: usize,
    idx: usize,
    min: usize,
) -> Result<usize, LoadError> {
    let step = shentsize
        .checked_mul(idx)
        .ok_or_else(|| LoadError("section header index overflows".into()))?;
    let at = shoff
        .checked_add(step)
        .ok_or_else(|| LoadError("section header offset overflows".into()))?;
    let end = at
        .checked_add(min)
        .ok_or_else(|| LoadError("section header end overflows".into()))?;
    if end > bytes.len() {
        return Err(LoadError(format!(
            "section header {idx} extends to {end}, file is {}",
            bytes.len()
        )));
    }
    Ok(at)
}

fn shdr(
    bytes: &[u8],
    elf64: bool,
    shoff: usize,
    shentsize: usize,
    idx: usize,
) -> Result<(usize, u32, u64, usize, usize), LoadError> {
    let at = sh_at(bytes, shoff, shentsize, idx, if elf64 { 64 } else { 40 })?;
    if elf64 {
        Ok((
            u32_at(bytes, at)? as usize,
            u32_at(bytes, at + 4)?,
            u64_at(bytes, at + 8)?,
            u64_at(bytes, at + 24)? as usize,
            u64_at(bytes, at + 32)? as usize,
        ))
    } else {
        Ok((
            u32_at(bytes, at)? as usize,
            u32_at(bytes, at + 4)?,
            u64::from(u32_at(bytes, at + 8)?),
            u32_at(bytes, at + 16)? as usize,
            u32_at(bytes, at + 20)? as usize,
        ))
    }
}

fn sh_link(
    bytes: &[u8],
    elf64: bool,
    shoff: usize,
    shentsize: usize,
    idx: usize,
) -> Result<u32, LoadError> {
    let at = sh_at(bytes, shoff, shentsize, idx, if elf64 { 44 } else { 28 })?;
    if elf64 {
        u32_at(bytes, at + 40)
    } else {
        u32_at(bytes, at + 24)
    }
}

fn sh_info(
    bytes: &[u8],
    elf64: bool,
    shoff: usize,
    shentsize: usize,
    idx: usize,
) -> Result<u32, LoadError> {
    let at = sh_at(bytes, shoff, shentsize, idx, if elf64 { 48 } else { 32 })?;
    if elf64 {
        u32_at(bytes, at + 44)
    } else {
        u32_at(bytes, at + 28)
    }
}

fn cstr(buf: &[u8], off: usize) -> Option<&str> {
    let rest = buf.get(off..)?;
    let end = rest.iter().position(|b| *b == 0).unwrap_or(rest.len());
    std::str::from_utf8(&rest[..end]).ok()
}

fn need<'a>(bytes: &'a [u8], at: usize, n: usize) -> Result<&'a [u8], LoadError> {
    bytes
        .get(at..at + n)
        .ok_or_else(|| LoadError(format!("ELF field at {at} is past end {}", bytes.len())))
}

fn u16_at(bytes: &[u8], at: usize) -> Result<u16, LoadError> {
    let b = need(bytes, at, 2)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(bytes: &[u8], at: usize) -> Result<u32, LoadError> {
    let b = need(bytes, at, 4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn u64_at(bytes: &[u8], at: usize) -> Result<u64, LoadError> {
    let b = need(bytes, at, 8)?;
    Ok(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_exec_section_and_symbol() {
        let elf = sample_elf();
        let src = load_elf(&elf, None).unwrap();
        assert_eq!(src.section, "xdp");
        assert_eq!(src.insns.len(), 1);
        assert_eq!(src.insns[0].imm, 1);
        assert_eq!(src.symbols.get(&0).map(String::as_str), Some("map_counter"));
    }

    fn sample_elf() -> Vec<u8> {
        // mov64 r0, 1
        let text = [0xb7u8, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        let shstr = b"\0xdp\0.relxdp\0.symtab\0.strtab\0.shstrtab\0";
        let strtab = b"\0map_counter\0";
        // offsets: ehdr 64, text 8, rel 16, sym 48, strtab, shstr, then shdrs
        let text_off = 64usize;
        let rel_off = text_off + text.len();
        let sym_off = rel_off + 16;
        let str_off = sym_off + 48;
        let shstr_off = str_off + strtab.len();
        let shoff = (shstr_off + shstr.len() + 7) & !7;

        let mut buf = vec![0u8; shoff + 64 * 6];
        buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        buf[4] = 2;
        buf[5] = 1;
        buf[6] = 1;
        put_u16(&mut buf, 16, 1); // ET_REL
        put_u16(&mut buf, 18, 247); // EM_BPF
        put_u32(&mut buf, 20, 1);
        put_u64(&mut buf, 40, shoff as u64);
        put_u16(&mut buf, 52, 64);
        put_u16(&mut buf, 58, 64);
        put_u16(&mut buf, 60, 6);
        put_u16(&mut buf, 62, 5);
        buf[text_off..text_off + text.len()].copy_from_slice(&text);
        // REL: r_offset=0, r_info = sym 1 << 32 | type 1
        put_u64(&mut buf, rel_off, 0);
        put_u64(&mut buf, rel_off + 8, (1u64 << 32) | 1);
        // symbol 1 at sym_off+24, st_name=1
        put_u32(&mut buf, sym_off + 24, 1);
        buf[str_off..str_off + strtab.len()].copy_from_slice(strtab);
        buf[shstr_off..shstr_off + shstr.len()].copy_from_slice(shstr);

        // name offsets in shstr: 1=xdp, 5=.relxdp, 13=.symtab, 21=.strtab, 29=.shstrtab
        write_shdr64(&mut buf, shoff, 1, 1, 1, 6, text_off, text.len(), 0, 0);
        write_shdr64(&mut buf, shoff, 2, 5, 9, 0, rel_off, 16, 3, 1);
        write_shdr64(&mut buf, shoff, 3, 13, 2, 0, sym_off, 48, 4, 1);
        write_shdr64(&mut buf, shoff, 4, 21, 3, 0, str_off, strtab.len(), 0, 0);
        write_shdr64(&mut buf, shoff, 5, 29, 3, 0, shstr_off, shstr.len(), 0, 0);
        buf
    }

    fn write_shdr64(
        buf: &mut [u8],
        shoff: usize,
        idx: usize,
        name: u32,
        ty: u32,
        flags: u64,
        off: usize,
        size: usize,
        link: u32,
        info: u32,
    ) {
        let at = shoff + idx * 64;
        put_u32(buf, at, name);
        put_u32(buf, at + 4, ty);
        put_u64(buf, at + 8, flags);
        put_u64(buf, at + 24, off as u64);
        put_u64(buf, at + 32, size as u64);
        put_u32(buf, at + 40, link);
        put_u32(buf, at + 44, info);
        put_u64(buf, at + 56, 1);
    }

    fn put_u16(buf: &mut [u8], at: usize, v: u16) {
        buf[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], at: usize, v: u32) {
        buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], at: usize, v: u64) {
        buf[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }
}
