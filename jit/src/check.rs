//! Compare one eBPF program with its linked RV32 image.
//!
//! The expected result comes from [`crate::bpf_vm`], not from the lowering.

use std::collections::HashMap;
use std::ops::Range;

use crate::bpf::Insn;
use crate::bpf_vm;
use crate::compile::{self, Image};
use crate::host_abi::{self, write_map, KIND_ARRAY};
use crate::rv_vm;

pub struct Report {
    pub status: &'static str,
    pub detail: String,
    pub r0: Option<u64>,
    pub rv_bytes: usize,
    pub relocs: usize,
}

pub fn check_packet(
    insns: &[Insn],
    symbols: &HashMap<u64, String>,
    packet: &[u8],
) -> Report {
    let mut mem = vec![0u8; 0x4_0000];
    let data = 0x1000usize;
    let ctx = 0x1800usize;
    let end = match data.checked_add(packet.len()) {
        Some(end) if end <= mem.len() && ctx + 24 <= mem.len() => end,
        _ => {
            return Report {
                status: "fail",
                detail: "packet does not fit".into(),
                r0: None,
                rv_bytes: 0,
                relocs: 0,
            };
        }
    };
    mem[data..end].copy_from_slice(packet);
    mem[ctx..ctx + 4].copy_from_slice(&0x1000u32.to_le_bytes());
    mem[ctx + 4..ctx + 8].copy_from_slice(&(0x1000u32 + packet.len() as u32).to_le_bytes());
    let mut maps = HashMap::new();
    let mut watch = vec![data..end];
    let mut n = 0u32;
    for name in symbols.values() {
        if maps.contains_key(name) {
            continue;
        }
        let vmr = 0x3000 + n * 0x40;
        let storage = 0x8000 + n * 0x800;
        // The host model is an ARRAY of 256 eight-byte values for every map.
        // It does not read the object's map section, so a HASH program meets
        // array semantics here. JIT and reference share this model, so the
        // comparison stays a comparison of lowering.
        if write_map(&mut mem, vmr, KIND_ARRAY, 4, 8, 256, storage).is_err() {
            return Report {
                status: "fail",
                detail: "map descriptor does not fit".into(),
                r0: None,
                rv_bytes: 0,
                relocs: 0,
            };
        }
        maps.insert(name.clone(), vmr);
        watch.push(storage as usize..storage as usize + 0x800);
        n += 1;
    }
    compare(insns, symbols, &maps, &mem, ctx as u32, &watch)
}

pub fn compare(
    insns: &[Insn],
    symbols: &HashMap<u64, String>,
    maps: &HashMap<String, u32>,
    mem: &[u8],
    r1: u32,
    watch: &[Range<usize>],
) -> Report {
    let image = match compile::compile(insns, symbols) {
        Ok(image) => image,
        Err(e) => {
            let msg = e.to_string();
            let status = if msg.contains("unsupported") || msg.contains("bpf-to-bpf") {
                "unsupported"
            } else {
                "fail"
            };
            return Report {
                status,
                detail: msg,
                r0: None,
                rv_bytes: 0,
                relocs: 0,
            };
        }
    };
    let relocs = image.relocs.len();
    let code = match finish(&image, maps) {
        Ok(code) => code,
        Err(detail) => {
            return Report {
                status: "unsupported",
                detail,
                r0: None,
                rv_bytes: image.bytes().len(),
                relocs,
            };
        }
    };
    let mut bpf_mem = mem.to_vec();
    let bpf = bpf_vm::execute(insns, symbols, maps, &mut bpf_mem, u64::from(r1));
    let helper = if relocs == 0 { None } else { Some(host_abi::HELPER) };
    let rv = rv_vm::run(&code, r1, mem.to_vec(), helper);
    let (bpf_r0, rv) = match (bpf, rv) {
        (Err(bpf_err), Err(rv_err)) => {
            // Both engines refusing is not a comparison. The harness gives
            // each side the same memory, so a shared bound makes them fault
            // together. Calling that a pass would hide a disagreement in
            // registers or memory.
            return Report {
                status: "inconclusive",
                detail: format!("both fault: reference {bpf_err}; rv32 {rv_err}"),
                r0: None,
                rv_bytes: code.len() * 4,
                relocs,
            };
        }
        (Err(detail), Ok(_)) => {
            return Report {
                status: "fail",
                detail: format!("reference faulted and rv32 returned: {detail}"),
                r0: None,
                rv_bytes: code.len() * 4,
                relocs,
            };
        }
        (Ok(bpf_r0), Err(detail)) => {
            return Report {
                status: "fail",
                detail: format!("rv32 faulted and reference returned {bpf_r0:#x}: {detail}"),
                r0: Some(bpf_r0),
                rv_bytes: code.len() * 4,
                relocs,
            };
        }
        (Ok(bpf_r0), Ok(rv)) => (bpf_r0, rv),
    };
    let rv_r0 = u64::from(rv.a0) | (u64::from(rv.a1) << 32);
    if rv_r0 != bpf_r0 {
        return Report {
            status: "fail",
            detail: format!("r0 reference {bpf_r0:#x} rv32 {rv_r0:#x}"),
            r0: Some(bpf_r0),
            rv_bytes: code.len() * 4,
            relocs,
        };
    }
    for range in watch {
        if range.end > bpf_mem.len() || range.end > rv.mem.len() {
            return Report {
                status: "fail",
                detail: format!("watch {range:?} is outside memory"),
                r0: Some(bpf_r0),
                rv_bytes: code.len() * 4,
                relocs,
            };
        }
        if bpf_mem[range.clone()] != rv.mem[range.clone()] {
            return Report {
                status: "fail",
                detail: format!("memory {range:?} differs"),
                r0: Some(bpf_r0),
                rv_bytes: code.len() * 4,
                relocs,
            };
        }
    }
    Report {
        status: "pass",
        detail: format!("r0 {bpf_r0:#x}"),
        r0: Some(bpf_r0),
        rv_bytes: code.len() * 4,
        relocs,
    }
}

fn finish(image: &Image, maps: &HashMap<String, u32>) -> Result<Vec<u32>, String> {
    if image.relocs.is_empty() {
        return Ok(image.code.clone());
    }
    let linked = compile::link(
        image,
        &compile::LinkIn {
            helper: host_abi::HELPER,
            maps,
        },
    )
    .map_err(|e| e.to_string())?;
    Ok(linked)
}
