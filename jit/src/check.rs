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

pub const FLAT_LEN: usize = 0x4_0000;
pub const DATA: u32 = 0x1000;
pub const CTX: u32 = 0x100;
const MAP0: u32 = 0x4000;
const STORE0: u32 = 0x8000;
const STORE_STRIDE: u32 = 0x800;

pub struct PacketWorld {
    pub mem: Vec<u8>,
    pub maps: HashMap<String, u32>,
    pub watch: Vec<Range<usize>>,
}

pub fn packet_world(
    packet: &[u8],
    symbols: &HashMap<u64, String>,
) -> Result<PacketWorld, &'static str> {
    let mut mem = vec![0; FLAT_LEN];
    let end = (DATA as usize)
        .checked_add(packet.len())
        .filter(|&end| end <= MAP0 as usize)
        .ok_or("packet exceeds the test data region")?;
    let mut names: Vec<_> = symbols.values().collect();
    names.sort_unstable();
    names.dedup();
    let capacity = (bpf_vm::FRAME as usize - 512 - STORE0 as usize) / STORE_STRIDE as usize;
    if names.len() > capacity {
        return Err("map storage exceeds the test map region");
    }
    let mut maps = HashMap::new();
    let mut watch = vec![DATA as usize..end];
    for (n, name) in names.into_iter().enumerate() {
        let vmr = MAP0 + n as u32 * 0x40;
        let storage = STORE0 + n as u32 * STORE_STRIDE;
        // Both engines use the same host ARRAY model for every map.
        write_map(&mut mem, vmr, KIND_ARRAY, 4, 8, 256, storage)
            .map_err(|_| "map descriptor does not fit")?;
        maps.insert(name.clone(), vmr);
        watch.push(vmr as usize..vmr as usize + 24);
        watch.push(storage as usize..(storage + STORE_STRIDE) as usize);
    }
    let ctx = CTX as usize;
    mem[ctx..ctx + 4].copy_from_slice(&DATA.to_le_bytes());
    mem[ctx + 4..ctx + 8].copy_from_slice(&(end as u32).to_le_bytes());
    mem[watch[0].clone()].copy_from_slice(packet);
    assert_eq!(&mem[watch[0].clone()], packet);
    Ok(PacketWorld { mem, maps, watch })
}

pub struct ExpectedPacket<'a> {
    pub r0: u64,
    pub bytes: &'a [u8],
    pub array: Option<ExpectedArrayValue<'a>>,
}

pub struct ExpectedArrayValue<'a> {
    pub name: &'a str,
    pub key: u32,
    pub value: u32,
}

pub struct PacketObservation {
    pub r0: Option<u64>,
    pub bytes_match: bool,
    pub array_value: Option<u32>,
}

impl ExpectedPacket<'_> {
    pub fn observe(
        &self,
        r0: Option<u64>,
        mem: Option<&[u8]>,
        packet: Range<usize>,
        maps: &HashMap<String, u32>,
    ) -> PacketObservation {
        let array_value = self.array.as_ref().and_then(|array| {
            let addr = *maps.get(array.name)?;
            host_abi::read_array_u32(mem?, addr, array.key)
        });
        PacketObservation {
            r0,
            bytes_match: mem.and_then(|mem| mem.get(packet)) == Some(self.bytes),
            array_value,
        }
    }

    pub fn matches(&self, actual: &PacketObservation) -> bool {
        actual.r0 == Some(self.r0)
            && actual.bytes_match
            && actual.array_value == self.array.as_ref().map(|array| array.value)
    }
}

pub struct Report {
    pub status: &'static str,
    pub detail: String,
    pub r0: Option<u64>,
    pub rv_bytes: usize,
    pub relocs: usize,
}

pub fn check_packet(insns: &[Insn], symbols: &HashMap<u64, String>, packet: &[u8]) -> Report {
    check_packet_with_expected(insns, symbols, packet, None)
}

pub fn check_packet_with_expected(
    insns: &[Insn],
    symbols: &HashMap<u64, String>,
    packet: &[u8],
    expected: Option<ExpectedPacket<'_>>,
) -> Report {
    let world = match packet_world(packet, symbols) {
        Ok(world) => world,
        Err(detail) => {
            return Report {
                status: "fail",
                detail: detail.into(),
                r0: None,
                rv_bytes: 0,
                relocs: 0,
            };
        }
    };
    compare_inner(
        insns,
        symbols,
        &world.maps,
        &world.mem,
        CTX,
        &world.watch,
        expected,
    )
}

pub fn compare(
    insns: &[Insn],
    symbols: &HashMap<u64, String>,
    maps: &HashMap<String, u32>,
    mem: &[u8],
    r1: u32,
    watch: &[Range<usize>],
) -> Report {
    compare_inner(insns, symbols, maps, mem, r1, watch, None)
}

fn compare_inner(
    insns: &[Insn],
    symbols: &HashMap<u64, String>,
    maps: &HashMap<String, u32>,
    mem: &[u8],
    r1: u32,
    watch: &[Range<usize>],
    expected: Option<ExpectedPacket<'_>>,
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
    let helper = if relocs == 0 {
        None
    } else {
        Some(host_abi::HELPER)
    };
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
    let mut detail = format!("r0 {bpf_r0:#x}");
    if let Some(expected) = expected {
        let range = watch[0].clone();
        let reference = expected.observe(Some(bpf_r0), Some(&bpf_mem), range.clone(), maps);
        let native = expected.observe(Some(rv_r0), Some(&rv.mem), range, maps);
        detail = format!(
            "input=exact reference_r0={bpf_r0:#x} reference_bytes={} rv32_r0={rv_r0:#x} rv32_bytes={} expected_r0={:#x} len={}",
            reference.bytes_match, native.bytes_match, expected.r0, expected.bytes.len()
        );
        if let Some(array) = &expected.array {
            detail.push_str(&format!(
                " {}[{}] reference_array={:?} rv32_array={:?} expected_array={}",
                array.name, array.key, reference.array_value, native.array_value, array.value
            ));
        }
        if !expected.matches(&reference) || !expected.matches(&native) {
            return Report {
                status: "fail",
                detail,
                r0: Some(bpf_r0),
                rv_bytes: code.len() * 4,
                relocs,
            };
        }
    }
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
        detail,
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
