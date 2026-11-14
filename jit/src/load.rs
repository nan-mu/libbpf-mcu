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
    let symbols = bind_relocs(bytes, elf64, shoff, shentsize, shnum, idx, &insns)?;
    Ok(Source {
        insns,
        symbols,
        section: names[idx].clone(),
    })
}

const SHT_SYMTAB: u32 = 2;
const SHT_RELA: u32 = 4;
const SHT_REL: u32 = 9;
const R_BPF_64_64: u32 = 1;

#[derive(Clone, Copy)]
enum RelocTarget {
    Program,
    OtherSection,
}

#[derive(Clone, Copy)]
enum Slot {
    LddwHead,
    LddwHigh,
    TruncatedHead,
    Other,
}

fn bind_relocs(
    bytes: &[u8],
    elf64: bool,
    shoff: usize,
    shentsize: usize,
    shnum: usize,
    program: usize,
    insns: &[Insn],
) -> Result<HashMap<u64, String>, LoadError> {
    let slots = classify(insns);
    let program_bytes = insns
        .len()
        .checked_mul(8)
        .ok_or_else(|| LoadError("program is too large to relocate".into()))?;
    let mut out = HashMap::new();
    for i in 0..shnum {
        let (_name, ty, _flags, off, size) = shdr(bytes, elf64, shoff, shentsize, i)?;
        if ty != SHT_RELA && ty != SHT_REL {
            continue;
        }
        let info = sh_info(bytes, elf64, shoff, shentsize, i)?;
        match reloc_target(info, shnum, program)? {
            RelocTarget::OtherSection => continue,
            RelocTarget::Program => {}
        }
        let symtab = sh_link(bytes, elf64, shoff, shentsize, i)? as usize;
        if symtab >= shnum {
            return Err(LoadError(format!(
                "relocation sh_link {symtab} is outside {shnum} sections"
            )));
        }
        let (_sym_name, sym_ty, _sym_flags, _sym_off, sym_size) =
            shdr(bytes, elf64, shoff, shentsize, symtab)?;
        if sym_ty != SHT_SYMTAB {
            return Err(LoadError(format!(
                "relocation sh_link {symtab} is not a symbol table"
            )));
        }
        let sym_ent = if elf64 { 24 } else { 16 };
        if sym_size % sym_ent != 0 {
            return Err(LoadError(format!(
                "symbol table size {sym_size} is not a multiple of {sym_ent}"
            )));
        }
        let rela = ty == SHT_RELA;
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
        if size % ent != 0 {
            return Err(LoadError(format!(
                "relocation section size {size} is not a multiple of {ent}"
            )));
        }
        let end = off
            .checked_add(size)
            .ok_or_else(|| LoadError("relocation section end overflows".into()))?;
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
            if r_type != R_BPF_64_64 {
                return Err(LoadError(format!(
                    "relocation type {r_type} is not R_BPF_64_64"
                )));
            }
            if r_off >= program_bytes as u64 {
                return Err(LoadError(format!(
                    "relocation offset {r_off} is outside the program"
                )));
            }
            if r_off % 8 != 0 {
                return Err(LoadError(format!(
                    "relocation offset {r_off} is not instruction-aligned"
                )));
            }
            match slots[(r_off / 8) as usize] {
                Slot::LddwHead => {}
                Slot::LddwHigh => {
                    return Err(LoadError(format!(
                        "relocation offset {r_off} is the second word of an lddw"
                    )));
                }
                Slot::TruncatedHead => {
                    return Err(LoadError(format!(
                        "relocation offset {r_off} is a truncated lddw"
                    )));
                }
                Slot::Other => {
                    return Err(LoadError(format!(
                        "relocation offset {r_off} is not an lddw"
                    )));
                }
            }
            let name = require_symbol(bytes, elf64, shoff, shentsize, shnum, symtab, sym_idx)?;
            if out.contains_key(&r_off) {
                return Err(LoadError(format!("two relocations at offset {r_off}")));
            }
            out.insert(r_off, name);
        }
    }
    Ok(out)
}

fn reloc_target(info: u32, shnum: usize, program: usize) -> Result<RelocTarget, LoadError> {
    let info = info as usize;
    if info >= shnum {
        return Err(LoadError(format!(
            "relocation sh_info {info} is outside {shnum} sections"
        )));
    }
    if info == program {
        Ok(RelocTarget::Program)
    } else {
        Ok(RelocTarget::OtherSection)
    }
}

fn classify(insns: &[Insn]) -> Vec<Slot> {
    let mut slots = vec![Slot::Other; insns.len()];
    let mut i = 0;
    while i < insns.len() {
        if bpf::is_lddw(insns[i]) && i + 1 < insns.len() {
            slots[i] = Slot::LddwHead;
            slots[i + 1] = Slot::LddwHigh;
            i += 2;
        } else if bpf::is_lddw(insns[i]) {
            slots[i] = Slot::TruncatedHead;
            i += 1;
        } else {
            i += 1;
        }
    }
    slots
}

fn require_symbol(
    bytes: &[u8],
    elf64: bool,
    shoff: usize,
    shentsize: usize,
    shnum: usize,
    symtab: usize,
    sym_idx: usize,
) -> Result<String, LoadError> {
    let (_n, _ty, _f, off, size) = shdr(bytes, elf64, shoff, shentsize, symtab)?;
    let ent = if elf64 { 24 } else { 16 };
    let step = sym_idx
        .checked_mul(ent)
        .ok_or_else(|| LoadError(format!("symbol index {sym_idx} overflows")))?;
    let at = off
        .checked_add(step)
        .ok_or_else(|| LoadError(format!("symbol index {sym_idx} overflows")))?;
    let sym_end = at
        .checked_add(ent)
        .ok_or_else(|| LoadError(format!("symbol index {sym_idx} overflows")))?;
    let table_end = off
        .checked_add(size)
        .ok_or_else(|| LoadError("symbol table end overflows".into()))?;
    if sym_end > table_end {
        return Err(LoadError(format!(
            "symbol index {sym_idx} is outside the symbol table"
        )));
    }
    let name_off = u32_at(bytes, at)? as usize;
    let str_idx = sh_link(bytes, elf64, shoff, shentsize, symtab)? as usize;
    if str_idx >= shnum {
        return Err(LoadError(format!(
            "symbol string section {str_idx} is outside {shnum} sections"
        )));
    }
    let strings = section_payload(bytes, elf64, shoff, shentsize, str_idx)?;
    if name_off >= strings.len() {
        return Err(LoadError(format!(
            "symbol name offset {name_off} is outside the string table"
        )));
    }
    // `cstr` keeps a tail that has no NUL. A symbol name has to end inside this table.
    let tail = &strings[name_off..];
    let Some(end) = tail.iter().position(|b| *b == 0) else {
        return Err(LoadError("symbol name is not NUL-terminated".into()));
    };
    let name = std::str::from_utf8(&tail[..end])
        .map_err(|_| LoadError("symbol name is not UTF-8".into()))?;
    if name.is_empty() {
        return Err(LoadError("relocation symbol name is empty".into()));
    }
    Ok(name.to_string())
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
    use crate::compile::{compile, RelocKind};
    use std::collections::HashMap;

    #[test]
    fn reads_exec_section_and_symbol() {
        let elf = sample_elf();
        let src = load_elf(&elf, None).unwrap();
        assert_eq!(src.section, "xdp");
        assert_eq!(src.insns.len(), 2);
        assert_eq!(src.insns[0].code, 0x18);
        assert_eq!(src.insns[0].src, 0);
        assert_eq!(src.insns[0].imm, 0x1111_1111);
        assert_eq!(src.insns[1].imm, 0x2222_2222);
        assert_eq!(src.symbols.get(&0).map(String::as_str), Some("map_counter"));
    }

    #[test]
    fn constant_lddw_without_reloc_emits_immediates() {
        let spec = lddw_spec();
        let src = load_elf(&elf_with(&spec), None).unwrap();
        assert!(src.symbols.is_empty());
        assert_eq!(src.insns[0].imm, 0x1111_1111);
        assert_eq!(src.insns[1].imm, 0x2222_2222);
        let image = compile(&src.insns, &src.symbols).unwrap();
        assert!(image.relocs.iter().all(|r| r.kind != RelocKind::Lddw));
        let bare = compile(&src.insns, &HashMap::new()).unwrap();
        assert_eq!(image.code, bare.code);
    }

    #[test]
    fn map_lddw_src0_keeps_name_and_placeholder() {
        let mut spec = lddw_spec();
        spec.prog = prog_recs(vec![rec(0, 1, 1)]);
        let src = load_elf(&elf_with(&spec), None).unwrap();
        assert_eq!(src.symbols.get(&0).map(String::as_str), Some("map_counter"));
        let image = compile(&src.insns, &src.symbols).unwrap();
        let lddw: Vec<_> = image
            .relocs
            .iter()
            .filter(|r| r.kind == RelocKind::Lddw)
            .collect();
        assert_eq!(lddw.len(), 1);
        assert_eq!(lddw[0].symbol.as_deref(), Some("map_counter"));
        let bare = compile(&src.insns, &HashMap::new()).unwrap();
        assert_ne!(image.code, bare.code);
    }

    #[test]
    fn symbol_index_out_of_range_is_err() {
        let mut spec = lddw_spec();
        spec.prog = prog_recs(vec![rec(0, 99, 1)]);
        assert_loader_err(&elf_with(&spec), "symbol index");
    }

    #[test]
    fn symbol_table_link_must_be_a_symtab() {
        let mut spec = lddw_spec();
        spec.prog = prog_recs(vec![rec(0, 1, 1)]);
        spec.symtab_type = 1;
        assert_loader_err(&elf_with(&spec), "sh_link type");

        spec.symtab_type = 2;
        spec.prog = Some(ProgRel {
            recs: vec![rec(0, 1, 1)],
            info: None,
            link: Some(99),
        });
        assert_loader_err(&elf_with(&spec), "sh_link index");
    }

    #[test]
    fn string_table_must_yield_a_name() {
        let cases: &[(&[u8], u32, &str)] = &[
            (b"\0map\0", 100, "st_name past the string table"),
            (b"map_counter", 0, "no NUL"),
            (b"\0\xff\0", 1, "not UTF-8"),
            (b"\0", 0, "empty name"),
        ];
        for (strtab, st_name, case) in cases {
            let mut spec = lddw_spec();
            spec.names.clear();
            spec.strtab = Some(strtab.to_vec());
            spec.st_name = Some(*st_name);
            spec.prog = prog_recs(vec![rec(0, 1, 1)]);
            assert_loader_err(&elf_with(&spec), case);
        }
    }

    #[test]
    fn reloc_offset_past_program_is_err() {
        let mut spec = lddw_spec();
        spec.prog = prog_recs(vec![rec(16, 1, 1)]);
        assert_loader_err(&elf_with(&spec), "offset past program");
    }

    #[test]
    fn reloc_offset_unaligned_is_err() {
        let mut spec = lddw_spec();
        spec.prog = prog_recs(vec![rec(4, 1, 1)]);
        assert_loader_err(&elf_with(&spec), "unaligned offset");
    }

    #[test]
    fn reloc_on_second_lddw_word_is_err() {
        let mut spec = lddw_spec();
        spec.prog = prog_recs(vec![rec(8, 1, 1)]);
        assert_loader_err(&elf_with(&spec), "second lddw word");
    }

    #[test]
    fn second_reloc_at_the_same_offset_is_err() {
        let mut spec = lddw_spec();
        spec.prog = prog_recs(vec![rec(0, 1, 1), rec(0, 1, 1)]);
        assert_loader_err(&elf_with(&spec), "same name");

        spec.names = vec![b"one".to_vec(), b"two".to_vec()];
        spec.prog = prog_recs(vec![rec(0, 1, 1), rec(0, 2, 1)]);
        assert_loader_err(&elf_with(&spec), "different names");
    }

    #[test]
    fn unsupported_type_on_the_program_is_err() {
        let mut spec = lddw_spec();
        spec.prog = prog_recs(vec![rec(0, 1, 2)]);
        assert_loader_err(&elf_with(&spec), "r_type");
    }

    #[test]
    fn bad_map_reloc_does_not_become_immediates() {
        let mut spec = lddw_spec();
        spec.prog = prog_recs(vec![rec(0, 99, 1)]);
        assert_loader_err(&elf_with(&spec), "bad map reloc");
    }

    #[test]
    fn other_section_keeps_foreign_reloc_types() {
        let mut spec = lddw_spec();
        spec.foreign = Some(ForeignRel {
            recs: vec![rec(0, 1, 2), rec(0, 1, 3), rec(0, 1, 4)],
            size: None,
            info: None,
        });
        let src = load_elf(&elf_with(&spec), None).unwrap();
        assert_eq!(src.section, "xdp");
        assert!(src.symbols.is_empty());
        assert_eq!(src.insns[0].imm, 0x1111_1111);
    }

    #[test]
    fn sh_info_out_of_range_is_err() {
        let mut spec = lddw_spec();
        spec.prog = Some(ProgRel {
            recs: vec![rec(0, 1, 1)],
            info: Some(99),
            link: None,
        });
        assert_loader_err(&elf_with(&spec), "sh_info");
    }

    #[test]
    fn helper_call_without_a_symbol_stays_a_call() {
        let spec = Spec {
            text: call_text(1),
            ..lddw_spec()
        };
        let src = load_elf(&elf_with(&spec), None).unwrap();
        assert!(src.symbols.is_empty());
        assert_eq!(src.insns.len(), 1);
        assert_eq!(src.insns[0].code, 0x85);
        let image = compile(&src.insns, &src.symbols).unwrap();
        assert_eq!(image.relocs.len(), 1);
        assert_eq!(image.relocs[0].kind, RelocKind::Call);
        assert_eq!(image.relocs[0].symbol, None);
        assert!(image.relocs.iter().all(|r| r.kind != RelocKind::Lddw));
    }

    #[test]
    fn other_section_truncated_record_is_ok() {
        let mut spec = lddw_spec();
        spec.foreign = Some(ForeignRel {
            recs: vec![rec(0, 1, 2), rec(0, 1, 3), rec(8, 1, 4)],
            size: Some(40),
            info: None,
        });
        let src = load_elf(&elf_with(&spec), None).unwrap();
        assert!(src.symbols.is_empty());

        spec.foreign = Some(ForeignRel {
            recs: vec![rec(0, 1, 2), rec(0, 1, 3), rec(0, 1, 4)],
            size: Some(1 << 28),
            info: None,
        });
        let src = load_elf(&elf_with(&spec), None).unwrap();
        assert_eq!(src.section, "xdp");
        assert!(src.symbols.is_empty());
    }

    #[test]
    fn symbol_string_section_out_of_range_is_err() {
        let mut spec = lddw_spec();
        spec.prog = prog_recs(vec![rec(0, 1, 1)]);
        spec.sym_str_oor = true;
        assert_loader_err(&elf_with(&spec), "string section index");
    }

    fn assert_loader_err(bytes: &[u8], case: &str) {
        if load_elf(bytes, None).is_ok() {
            panic!("loader returned Ok ({case})");
        }
    }

    fn lddw_text() -> Vec<u8> {
        let mut text = [0u8; 16];
        text[0] = 0x18;
        text[1] = 0;
        text[4..8].copy_from_slice(&0x1111_1111u32.to_le_bytes());
        text[12..16].copy_from_slice(&0x2222_2222u32.to_le_bytes());
        text.to_vec()
    }

    fn call_text(imm: i32) -> Vec<u8> {
        let mut text = [0u8; 8];
        text[0] = 0x85;
        text[4..8].copy_from_slice(&imm.to_le_bytes());
        text.to_vec()
    }

    struct Rec {
        offset: u64,
        sym: u32,
        ty: u32,
    }

    struct ProgRel {
        recs: Vec<Rec>,
        info: Option<u32>,
        link: Option<u32>,
    }

    struct ForeignRel {
        recs: Vec<Rec>,
        size: Option<usize>,
        info: Option<u32>,
    }

    struct Spec {
        text: Vec<u8>,
        prog: Option<ProgRel>,
        names: Vec<Vec<u8>>,
        strtab: Option<Vec<u8>>,
        st_name: Option<u32>,
        sym_count: usize,
        symtab_type: u32,
        foreign: Option<ForeignRel>,
        sym_str_oor: bool,
    }

    fn rec(offset: u64, sym: u32, ty: u32) -> Rec {
        Rec { offset, sym, ty }
    }

    fn prog_recs(recs: Vec<Rec>) -> Option<ProgRel> {
        Some(ProgRel {
            recs,
            info: None,
            link: None,
        })
    }

    fn lddw_spec() -> Spec {
        Spec {
            text: lddw_text(),
            prog: None,
            names: vec![b"map_counter".to_vec()],
            strtab: None,
            st_name: None,
            sym_count: 2,
            symtab_type: 2,
            foreign: None,
            sym_str_oor: false,
        }
    }

    fn c_name(buf: &mut Vec<u8>, name: &str) -> u32 {
        let off = buf.len() as u32;
        buf.extend_from_slice(name.as_bytes());
        buf.push(0);
        off
    }

    fn elf_with(spec: &Spec) -> Vec<u8> {
        let mut shstr = vec![0u8];
        let name_xdp = c_name(&mut shstr, "xdp");
        let name_other = c_name(&mut shstr, ".other");
        let name_rel = c_name(&mut shstr, ".relxdp");
        let name_foreign = c_name(&mut shstr, ".relother");
        let name_sym = c_name(&mut shstr, ".symtab");
        let name_str = c_name(&mut shstr, ".strtab");
        let name_shstr = c_name(&mut shstr, ".shstrtab");

        let mut computed = vec![0u32];
        let mut raw = vec![0u8];
        for name in &spec.names {
            computed.push(raw.len() as u32);
            raw.extend_from_slice(name);
            raw.push(0);
        }
        let strtab = spec.strtab.clone().unwrap_or(raw);
        let sym_count = spec.sym_count.max(computed.len());

        let prog_idx = 1usize;
        let other_idx = 2usize;
        let mut next = 3usize;
        let rel_idx = if spec.prog.is_some() {
            let i = next;
            next += 1;
            Some(i)
        } else {
            None
        };
        let foreign_idx = if spec.foreign.is_some() {
            let i = next;
            next += 1;
            Some(i)
        } else {
            None
        };
        let sym_idx = next;
        next += 1;
        let str_idx = next;
        next += 1;
        let shstr_idx = next;
        next += 1;
        let shnum = next;

        let text_off = 64usize;
        let other_off = text_off + spec.text.len();
        let mut cursor = other_off + 1;
        let rel_off = cursor;
        if let Some(prog) = &spec.prog {
            cursor += prog.recs.len() * 16;
        }
        let foreign_off = cursor;
        if let Some(foreign) = &spec.foreign {
            cursor += foreign.recs.len() * 16;
        }
        let sym_off = cursor;
        cursor += sym_count * 24;
        let str_off = cursor;
        cursor += strtab.len();
        let shstr_off = cursor;
        cursor += shstr.len();
        let shoff = (cursor + 7) & !7;

        let mut slots = shnum;
        if let Some(link) = spec.prog.as_ref().and_then(|p| p.link) {
            slots = slots.max(link as usize + 1);
        }
        if spec.sym_str_oor {
            slots = slots.max(shnum + 1);
        }
        let mut buf = vec![0u8; shoff + slots * 64];
        buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        buf[4] = 2;
        buf[5] = 1;
        buf[6] = 1;
        put_u16(&mut buf, 16, 1);
        put_u16(&mut buf, 18, 247);
        put_u32(&mut buf, 20, 1);
        put_u64(&mut buf, 40, shoff as u64);
        put_u16(&mut buf, 52, 64);
        put_u16(&mut buf, 58, 64);
        put_u16(&mut buf, 60, shnum as u16);
        put_u16(&mut buf, 62, shstr_idx as u16);

        buf[text_off..text_off + spec.text.len()].copy_from_slice(&spec.text);
        if let Some(prog) = &spec.prog {
            write_rels(&mut buf, rel_off, &prog.recs);
        }
        if let Some(foreign) = &spec.foreign {
            write_rels(&mut buf, foreign_off, &foreign.recs);
        }
        for i in 1..sym_count {
            let off = if i == 1 {
                spec.st_name
                    .unwrap_or_else(|| computed.get(i).copied().unwrap_or(0))
            } else {
                computed.get(i).copied().unwrap_or(0)
            };
            put_u32(&mut buf, sym_off + i * 24, off);
        }
        buf[str_off..str_off + strtab.len()].copy_from_slice(&strtab);
        buf[shstr_off..shstr_off + shstr.len()].copy_from_slice(&shstr);

        write_shdr64(
            &mut buf,
            shoff,
            prog_idx,
            name_xdp,
            1,
            6,
            text_off,
            spec.text.len(),
            0,
            0,
        );
        write_shdr64(
            &mut buf, shoff, other_idx, name_other, 1, 0, other_off, 1, 0, 0,
        );
        if let Some(prog) = &spec.prog {
            write_shdr64(
                &mut buf,
                shoff,
                rel_idx.unwrap(),
                name_rel,
                9,
                0,
                rel_off,
                prog.recs.len() * 16,
                prog.link.unwrap_or(sym_idx as u32),
                prog.info.unwrap_or(prog_idx as u32),
            );
        }
        if let Some(foreign) = &spec.foreign {
            write_shdr64(
                &mut buf,
                shoff,
                foreign_idx.unwrap(),
                name_foreign,
                9,
                0,
                foreign_off,
                foreign.size.unwrap_or(foreign.recs.len() * 16),
                sym_idx as u32,
                foreign.info.unwrap_or(other_idx as u32),
            );
        }
        let str_link = if spec.sym_str_oor {
            shnum as u32
        } else {
            str_idx as u32
        };
        write_shdr64(
            &mut buf,
            shoff,
            sym_idx,
            name_sym,
            spec.symtab_type,
            0,
            sym_off,
            sym_count * 24,
            str_link,
            0,
        );
        write_shdr64(
            &mut buf,
            shoff,
            str_idx,
            name_str,
            3,
            0,
            str_off,
            strtab.len(),
            0,
            0,
        );
        write_shdr64(
            &mut buf,
            shoff,
            shstr_idx,
            name_shstr,
            3,
            0,
            shstr_off,
            shstr.len(),
            0,
            0,
        );
        buf
    }

    fn write_rels(buf: &mut [u8], at: usize, recs: &[Rec]) {
        for (k, rec) in recs.iter().enumerate() {
            let pos = at + k * 16;
            put_u64(buf, pos, rec.offset);
            put_u64(buf, pos + 8, (u64::from(rec.sym) << 32) | u64::from(rec.ty));
        }
    }

    fn sample_elf() -> Vec<u8> {
        let mut text = [0u8; 16];
        text[0] = 0x18;
        text[4..8].copy_from_slice(&0x1111_1111u32.to_le_bytes());
        text[12..16].copy_from_slice(&0x2222_2222u32.to_le_bytes());
        let shstr = b"\0xdp\0.relxdp\0.symtab\0.strtab\0.shstrtab\0";
        let strtab = b"\0map_counter\0";
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
