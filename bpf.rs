#!/usr/bin/env rust-script
//! ```cargo
//! [dependencies]
//! object = "0.36"
//! anyhow = "1.0"
//! ```
//!
//! # bpf.rs — BTF / BTF.ext inspector for BPF ELF objects
//!
//! Host-side diagnostic script that opens a compiled BPF/XDP `.o` ELF, then dumps
//! the `.BTF` type graph (kinds 0–19) and, when present, `.BTF.ext` metadata:
//! function info, line info, and CO-RE relocation records.
//!
//! Usage: `rust-script bpf.rs <xdp_object.o>` (compile the object with `-g` so
//! `.BTF` is emitted). Parses little-endian BTF safely via bounds-checked reads;
//! unknown future type kinds abort that section rather than guessing trailer size.

use anyhow::{anyhow, Context, Result};
use object::{Object, ObjectSection};
use std::{env, fs, str};

/// Bounds-checked binary reader; avoids manual index panics and inline `unsafe`.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_u8(&mut self) -> Result<u8> {
        if self.pos < self.data.len() {
            let val = self.data[self.pos];
            self.pos += 1;
            Ok(val)
        } else {
            Err(anyhow!("unexpected EOF reading u8 (pos: {})", self.pos))
        }
    }

    fn read_u16(&mut self) -> Result<u16> {
        if self.pos + 2 <= self.data.len() {
            let val = u16::from_le_bytes(self.data[self.pos..self.pos + 2].try_into().unwrap());
            self.pos += 2;
            Ok(val)
        } else {
            Err(anyhow!("unexpected EOF reading u16 (pos: {})", self.pos))
        }
    }

    fn read_u32(&mut self) -> Result<u32> {
        if self.pos + 4 <= self.data.len() {
            let val = u32::from_le_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
            self.pos += 4;
            Ok(val)
        } else {
            Err(anyhow!("unexpected EOF reading u32 (pos: {})", self.pos))
        }
    }

    fn read_i32(&mut self) -> Result<i32> {
        if self.pos + 4 <= self.data.len() {
            let val = i32::from_le_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
            self.pos += 4;
            Ok(val)
        } else {
            Err(anyhow!("unexpected EOF reading i32 (pos: {})", self.pos))
        }
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.pos + len <= self.data.len() {
            let slice = &self.data[self.pos..self.pos + len];
            self.pos += len;
            Ok(slice)
        } else {
            Err(anyhow!("unexpected EOF reading slice of length {}", len))
        }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }
}

/// Extract a NUL-terminated UTF-8 string from the BTF string table.
fn get_str<'a>(str_table: &'a [u8], off: u32) -> &'a str {
    let off = off as usize;
    if off >= str_table.len() {
        return "<invalid_str_offset>";
    }
    let slice = &str_table[off..];
    let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
    str::from_utf8(&slice[..end]).unwrap_or("<invalid_utf8>")
}

/// Parse the `.BTF` section: type definitions (kinds 0–19) plus the string table.
fn parse_btf<'a>(data: &'a [u8]) -> Result<&'a [u8]> {
    let mut r = Reader::new(data);
    let magic = r.read_u16()?;
    if magic != 0xeB9F {
        return Err(anyhow!("invalid BTF magic: 0x{:04x} (expected LE 0xeB9F)", magic));
    }
    let version = r.read_u8()?;
    let flags = r.read_u8()?;
    let hdr_len = r.read_u32()?;
    let type_off = r.read_u32()?;
    let type_len = r.read_u32()?;
    let str_off = r.read_u32()?;
    let str_len = r.read_u32()?;

    println!("==================== [ .BTF Header ] ====================");
    println!("Magic: 0x{:04x} | Version: {} | Flags: 0x{:02x} | HdrLen: {}", magic, version, flags, hdr_len);
    println!("Type Section:   offset = {}, len = {} bytes", type_off, type_len);
    println!("String Section: offset = {}, len = {} bytes\n", str_off, str_len);

    if (hdr_len as usize + str_off as usize + str_len as usize) > data.len() {
        return Err(anyhow!("BTF string table offset exceeds section bounds"));
    }

    let str_table = &data[(hdr_len + str_off) as usize .. (hdr_len + str_off + str_len) as usize];
    let type_data = &data[(hdr_len + type_off) as usize .. (hdr_len + type_off + type_len) as usize];
    let mut tr = Reader::new(type_data);

    println!("==================== [ .BTF Types ] ====================");
    let mut type_id = 1u32;
    while !tr.is_empty() {
        let name_off = tr.read_u32()?;
        let info = tr.read_u32()?;
        let size_or_type = tr.read_u32()?;

        let vlen = (info & 0xffff) as usize;
        let kind = (info >> 24) & 0x1f;
        let kind_flag = (info >> 31) != 0;
        let name = get_str(str_table, name_off);

        print!("[ID {:3}] ", type_id);
        match kind {
            0 => println!("UNKNOWN      name='{}'", name),
            1 => { // INT
                let int_data = tr.read_u32()?;
                let bits = int_data & 0xff;
                let offset = (int_data >> 16) & 0xff;
                let encoding = (int_data >> 24) & 0x0f;
                let enc_str = match encoding {
                    1 => "SIGNED",
                    2 => "CHAR",
                    4 => "BOOL",
                    _ => "NONE",
                };
                println!("INT          name='{}' size={} bits={} offset={} encoding={}", name, size_or_type, bits, offset, enc_str);
            }
            2 => println!("PTR          name='{}' target_type_id={}", name, size_or_type),
            3 => { // ARRAY
                let arr_type = tr.read_u32()?;
                let idx_type = tr.read_u32()?;
                let nelems = tr.read_u32()?;
                println!("ARRAY        name='{}' elem_type={} index_type={} nelems={}", name, arr_type, idx_type, nelems);
            }
            4 | 5 => { // STRUCT | UNION
                let kind_name = if kind == 4 { "STRUCT" } else { "UNION" };
                println!("{:12} name='{}' size={} members={}", kind_name, name, size_or_type, vlen);
                for _ in 0..vlen {
                    let m_name_off = tr.read_u32()?;
                    let m_type = tr.read_u32()?;
                    let m_offset = tr.read_u32()?;
                    let m_name = get_str(str_table, m_name_off);
                    if kind_flag {
                        let bitfield_size = m_offset >> 24;
                        let bit_offset = m_offset & 0xffffff;
                        println!("             ├─ member '{}': type={}, bit_offset={}, bitfield_size={}", m_name, m_type, bit_offset, bitfield_size);
                    } else {
                        println!("             ├─ member '{}': type={}, bit_offset={}", m_name, m_type, m_offset);
                    }
                }
            }
            6 => { // ENUM
                println!("ENUM         name='{}' size={} values={}", name, size_or_type, vlen);
                for _ in 0..vlen {
                    let e_name_off = tr.read_u32()?;
                    let e_val = tr.read_i32()?;
                    println!("             ├─ val '{}' = {}", get_str(str_table, e_name_off), e_val);
                }
            }
            7 => println!("FWD          name='{}' fwd_kind={}", name, if kind_flag { "UNION" } else { "STRUCT" }),
            8 => println!("TYPEDEF      name='{}' target_type_id={}", name, size_or_type),
            9 => println!("VOLATILE     name='{}' target_type_id={}", name, size_or_type),
            10 => println!("CONST        name='{}' target_type_id={}", name, size_or_type),
            11 => println!("RESTRICT     name='{}' target_type_id={}", name, size_or_type),
            12 => { // FUNC
                let linkage = match vlen {
                    0 => "static",
                    1 => "global",
                    2 => "extern",
                    _ => "unknown",
                };
                println!("FUNC         name='{}' proto_type_id={} linkage={}", name, size_or_type, linkage);
            }
            13 => { // FUNC_PROTO
                println!("FUNC_PROTO   name='{}' ret_type_id={} params={}", name, size_or_type, vlen);
                for _ in 0..vlen {
                    let p_name_off = tr.read_u32()?;
                    let p_type = tr.read_u32()?;
                    println!("             ├─ param '{}': type={}", get_str(str_table, p_name_off), p_type);
                }
            }
            14 => { // VAR
                let linkage = tr.read_u32()?;
                let link_str = match linkage {
                    0 => "static",
                    1 => "global",
                    2 => "extern",
                    _ => "unknown",
                };
                println!("VAR          name='{}' type_id={} linkage={}", name, size_or_type, link_str);
            }
            15 => { // DATASEC
                println!("DATASEC      name='{}' size={} vars={}", name, size_or_type, vlen);
                for _ in 0..vlen {
                    let v_type = tr.read_u32()?;
                    let v_off = tr.read_u32()?;
                    let v_size = tr.read_u32()?;
                    println!("             ├─ var_type={}, offset={}, size={}", v_type, v_off, v_size);
                }
            }
            16 => println!("FLOAT        name='{}' size={}", name, size_or_type),
            17 => { // DECL_TAG
                let comp_idx = tr.read_i32()?;
                println!("DECL_TAG     name='{}' target_type_id={} component_idx={}", name, size_or_type, comp_idx);
            }
            18 => { // TYPE_TAG
                let comp_idx = tr.read_i32()?;
                println!("TYPE_TAG     name='{}' target_type_id={} component_idx={}", name, size_or_type, comp_idx);
            }
            19 => { // ENUM64
                println!("ENUM64       name='{}' size={} values={}", name, size_or_type, vlen);
                for _ in 0..vlen {
                    let e_name_off = tr.read_u32()?;
                    let val_lo = tr.read_u32()? as u64;
                    let val_hi = tr.read_u32()? as u64;
                    let val = (val_hi << 32) | val_lo;
                    println!("             ├─ val '{}' = {}", get_str(str_table, e_name_off), val);
                }
            }
            _ => {
                println!("UNKNOWN_KIND({}) name='{}' raw_info=0x{:08x}", kind, name, info);
                // Future kinds have unknown trailer size; stop to stay bounds-safe.
                break;
            }
        }
        type_id += 1;
    }
    Ok(str_table)
}

/// Parse `.BTF.ext`: func/line info and CO-RE relocation records.
fn parse_btf_ext(data: &[u8], str_table: &[u8]) -> Result<()> {
    let mut r = Reader::new(data);
    let magic = r.read_u16()?;
    if magic != 0xeB9F {
        return Err(anyhow!("invalid BTF.ext magic: 0x{:04x}", magic));
    }
    let version = r.read_u8()?;
    let _flags = r.read_u8()?;
    let hdr_len = r.read_u32()?;
    let func_info_off = r.read_u32()?;
    let func_info_len = r.read_u32()?;
    let line_info_off = r.read_u32()?;
    let line_info_len = r.read_u32()?;

    let (core_relo_off, core_relo_len) = if hdr_len >= 32 {
        (r.read_u32()?, r.read_u32()?)
    } else {
        (0, 0)
    };

    println!("\n==================== [ .BTF.ext Header ] ====================");
    println!("Magic: 0x{:04x} | Version: {} | HdrLen: {}", magic, version, hdr_len);

    // 1. Func Info
    if func_info_len > 0 {
        println!("\n--- [ Func Info ] ---");
        let mut fr = Reader::new(&data[(hdr_len + func_info_off) as usize .. (hdr_len + func_info_off + func_info_len) as usize]);
        if !fr.is_empty() {
            let rec_size = fr.read_u32()? as usize;
            while !fr.is_empty() {
                let sec_name_off = fr.read_u32()?;
                let num_info = fr.read_u32()?;
                println!("Section '{}' (records: {}):", get_str(str_table, sec_name_off), num_info);
                for _ in 0..num_info {
                    let insn_off = fr.read_u32()?;
                    let type_id = fr.read_u32()?;
                    println!("    insn_off: 0x{:04x} -> type_id: {}", insn_off, type_id);
                    if rec_size > 8 { fr.read_slice(rec_size - 8)?; }
                }
            }
        }
    }

    // 2. Line Info
    if line_info_len > 0 {
        println!("\n--- [ Line Info ] ---");
        let mut lr = Reader::new(&data[(hdr_len + line_info_off) as usize .. (hdr_len + line_info_off + line_info_len) as usize]);
        if !lr.is_empty() {
            let rec_size = lr.read_u32()? as usize;
            while !lr.is_empty() {
                let sec_name_off = lr.read_u32()?;
                let num_info = lr.read_u32()?;
                println!("Section '{}' (records: {}):", get_str(str_table, sec_name_off), num_info);
                for _ in 0..num_info {
                    let insn_off = lr.read_u32()?;
                    let file_name_off = lr.read_u32()?;
                    let line_off = lr.read_u32()?;
                    let line_col = lr.read_u32()?;
                    println!("    insn_off: 0x{:04x} -> {}:{} (col {})",
                        insn_off, get_str(str_table, file_name_off), get_str(str_table, line_off), line_col);
                    if rec_size > 16 { lr.read_slice(rec_size - 16)?; }
                }
            }
        }
    }

    // 3. CO-RE Relocations
    if core_relo_len > 0 {
        println!("\n--- [ CO-RE Relocations ] ---");
        let mut cr = Reader::new(&data[(hdr_len + core_relo_off) as usize .. (hdr_len + core_relo_off + core_relo_len) as usize]);
        if !cr.is_empty() {
            let rec_size = cr.read_u32()? as usize;
            while !cr.is_empty() {
                let sec_name_off = cr.read_u32()?;
                let num_info = cr.read_u32()?;
                println!("Section '{}' (records: {}):", get_str(str_table, sec_name_off), num_info);
                for _ in 0..num_info {
                    let insn_off = cr.read_u32()?;
                    let type_id = cr.read_u32()?;
                    let access_str_off = cr.read_u32()?;
                    let kind = cr.read_u32()?;
                    println!("    insn_off: 0x{:04x} -> type_id: {}, access_str: '{}', kind: {}",
                        insn_off, type_id, get_str(str_table, access_str_off), kind);
                    if rec_size > 16 { cr.read_slice(rec_size - 16)?; }
                }
            }
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: {} <xdp_object.o>", args[0]);
        std::process::exit(1);
    }

    let path = &args[1];
    let file_data = fs::read(path).with_context(|| format!("failed to read file: {}", path))?;
    let obj = object::File::parse(&*file_data).context("failed to parse ELF")?;

    let btf_section = obj.section_by_name(".BTF")
        .ok_or_else(|| anyhow!(".BTF section not found in {} (compile with -g)", path))?;
    let btf_data = btf_section.data().context("failed to read .BTF section data")?;

    // Parse .BTF and reuse its string table for .BTF.ext name lookups.
    let str_table = parse_btf(&btf_data)?;

    if let Some(btf_ext_section) = obj.section_by_name(".BTF.ext") {
        let btf_ext_data = btf_ext_section.data().context("failed to read .BTF.ext section data")?;
        parse_btf_ext(&btf_ext_data, str_table)?;
    } else {
        println!("\n[note] no .BTF.ext section in this file.");
    }

    Ok(())
}
