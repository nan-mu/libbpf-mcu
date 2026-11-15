//! The differential runner: one eBPF program, two engines, five observables.
//!
//! Both engines see the same logical memory. The JIT addresses it with 32-bit
//! offsets into a flat buffer, which is what the firmware does. rbpf addresses
//! it with real 64-bit host pointers into a buffer of the same shape. Helper
//! arguments are normalized back to offsets before the traces are compared.
//!
//! Map semantics are shared by construction: the rbpf helpers call
//! `xpost_jit::dispatch`, the same function the RV32 interpreter calls. The
//! comparison therefore isolates the translation, not the map model.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ops::Range;
use std::panic::{catch_unwind, AssertUnwindSafe};

use xpost_jit::isa::*;
use xpost_jit::{compile, link, Insn, LinkIn, HELPER, KIND_ARRAY};

use crate::ctx;
use crate::rv::{self, Call};

pub const FLAT_LEN: usize = 0x4_0000;
pub const DATA: u32 = 0x1000;
pub const CTX: u32 = 0x1800;
pub const MAP0: u32 = 0x3000;
pub const MAP_STRIDE: u32 = 0x40;
pub const STORE0: u32 = 0x8000;
pub const STORE_STRIDE: u32 = 0x800;

/// The JIT's BPF frame pointer. `run_rv` enters at sp = 0x3_0000 and the
/// prologue subtracts align16(9 saved regs * 4 + 10 scratch words * 4 + 512) =
/// 592, then sets fp = sp + 512. Verified against the JIT at run time by
/// `jit_frame_pointer`, so a prologue change fails loudly instead of silently
/// misaligning the two stacks.
pub const MODEL_FP: u32 = 0x2ffb0;
pub const MODEL_STACK: u32 = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    Inconclusive,
    Unsupported,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Fail => "fail",
            Status::Inconclusive => "inconclusive",
            Status::Unsupported => "unsupported",
        }
    }
}

pub struct Setup {
    pub maps: Vec<(String, u32)>,
    pub watch: Vec<Range<usize>>,
}

/// The host map model, copied from `jit/src/check.rs`: every map is an ARRAY of
/// 256 eight-byte values, whatever the object's `.maps` section declares.
fn build_world(packet: &[u8], symbols: &HashMap<u64, String>, with_ctx: bool) -> (Vec<u8>, Setup) {
    let mut mem = vec![0u8; FLAT_LEN];
    let end = DATA as usize + packet.len();
    mem[DATA as usize..end].copy_from_slice(packet);
    if with_ctx {
        put32(&mut mem, CTX as usize, DATA);
        put32(&mut mem, CTX as usize + 4, DATA + packet.len() as u32);
    }
    let mut names: Vec<&String> = symbols.values().collect();
    names.sort();
    names.dedup();
    let mut maps = Vec::new();
    let mut watch = vec![
        DATA as usize..end,
        (MODEL_FP - MODEL_STACK) as usize..MODEL_FP as usize,
    ];
    for (n, name) in names.into_iter().enumerate() {
        let vmr = MAP0 + n as u32 * MAP_STRIDE;
        let storage = STORE0 + n as u32 * STORE_STRIDE;
        xpost_jit::write_map(&mut mem, vmr, KIND_ARRAY, 4, 8, 256, storage).unwrap();
        watch.push(vmr as usize..vmr as usize + 24);
        watch.push(storage as usize..storage as usize + STORE_STRIDE as usize);
        maps.push((name.clone(), vmr));
    }
    (mem, Setup { maps, watch })
}

fn put32(mem: &mut [u8], at: usize, v: u32) {
    mem[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

/// The regions a program-level case compares, identical on both sides.
pub fn program_watch(packet: &[u8], symbols: &HashMap<u64, String>) -> Vec<Range<usize>> {
    build_world(packet, symbols, false).1.watch
}

pub fn encode(insns: &[Insn]) -> Vec<u8> {
    let mut out = Vec::with_capacity(insns.len() * 8);
    for i in insns {
        out.push(i.code);
        out.push((i.dst & 0x0f) | (i.src << 4));
        out.extend_from_slice(&i.off.to_le_bytes());
        out.extend_from_slice(&i.imm.to_le_bytes());
    }
    out
}

pub struct Side {
    pub ok: bool,
    pub term: String,
    pub r0: Option<u64>,
    pub mem: Option<Vec<u8>>,
    pub trace: Vec<Call>,
}

impl Side {
    fn refused(detail: String) -> Side {
        Side {
            ok: false,
            term: format!("refused: {detail}"),
            r0: None,
            mem: None,
            trace: Vec::new(),
        }
    }
    fn faulted(detail: String) -> Side {
        Side {
            ok: false,
            term: format!("fault: {detail}"),
            r0: None,
            mem: None,
            trace: Vec::new(),
        }
    }
    fn panicked(detail: String) -> Side {
        Side {
            ok: false,
            term: format!("panic: {detail}"),
            r0: None,
            mem: None,
            trace: Vec::new(),
        }
    }
    /// The harness could not set up a comparable run. Never a pass, and not
    /// blamed on either engine.
    fn harness(detail: String) -> Side {
        Side {
            ok: false,
            term: format!("harness: {detail}"),
            r0: None,
            mem: None,
            trace: Vec::new(),
        }
    }
    fn returned(r0: u64, mem: Vec<u8>, trace: Vec<Call>) -> Side {
        Side {
            ok: true,
            term: "exit".into(),
            r0: Some(r0),
            mem: Some(mem),
            trace,
        }
    }
}

/// A panicking engine is a recorded outcome, never an aborted suite.
fn guard<T>(f: impl FnOnce() -> T) -> Result<T, String> {
    catch_unwind(AssertUnwindSafe(f)).map_err(|e| {
        e.downcast_ref::<String>()
            .cloned()
            .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|| "unknown panic payload".into())
    })
}

pub struct Outcome {
    pub status: Status,
    pub detail: String,
    pub jit: Side,
    pub oracle: Side,
    pub diffs: Vec<String>,
    pub rv_bytes: usize,
    pub relocs: usize,
    pub ctx_patches: Vec<ctx::Patch>,
    pub stack_patches: Vec<StackPatch>,
    pub executor_split: Option<String>,
    /// Who the evidence blames: "jit", "oracle", "open", or "none".
    pub blame: &'static str,
}

/// Instruction constructs where rbpf demonstrably implements a different rule
/// than the eBPF ISA, so it cannot adjudicate a case that uses them. Each entry
/// cites the rbpf source that proves it. This is declared from code evidence,
/// never inferred from a disagreement, and the disagreement is still recorded.
pub fn oracle_gap(insns: &[Insn]) -> Option<&'static str> {
    for i in insns {
        let alu = i.class() == CLASS_ALU || i.class() == CLASS_ALU64;
        if alu && (i.op() == ALU_DIV || i.op() == ALU_MOD) && i.off == 1 {
            return Some(
                "rbpf never reads insn.off in its ALU block, so SDIV/SMOD execute as unsigned",
            );
        }
        // interpreter.rs:324 `unsigned_u64!` zero-extends, while JSGT_IMM (:604)
        // and every ALU64_IMM sign-extend the same i32 field. JSET_IMM also
        // sign-extends, so it is not listed.
        if i.class() == CLASS_JMP
            && !i.src_is_reg()
            && i.imm < 0
            && matches!(
                i.op(),
                JMP_JEQ | JMP_JGT | JMP_JGE | JMP_JNE | JMP_JLT | JMP_JLE
            )
        {
            return Some(
                "rbpf zero-extends JMP64 immediates (unsigned_u64!, interpreter.rs:324) but sign-extends the same field for JSGT_IMM (:604) and ALU64_IMM",
            );
        }
    }
    None
}

/// One helper argument relocated from rbpf's stack into the model stack.
#[derive(Clone, Copy, Debug)]
pub struct StackPatch {
    pub call: usize,
    pub arg: usize,
    pub host: u64,
    pub model: u32,
}

struct Bridge {
    world: Vec<u8>,
    base: u64,
    trace: Vec<Call>,
    /// Host windows the program may load and store, besides its own stack.
    windows: Vec<(u64, u64)>,
    stack_host: u64,
    stack_ptr: *const u8,
    stack_patches: Vec<StackPatch>,
    unmapped: Option<String>,
    steps: usize,
}

thread_local! {
    static BRIDGE: RefCell<Option<Bridge>> = RefCell::new(None);
}

fn install(world: Vec<u8>, extra_windows: Vec<(u64, u64)>) -> u64 {
    let base = world.as_ptr() as u64;
    let mut windows = extra_windows;
    if !world.is_empty() {
        windows.push((base, FLAT_LEN as u64));
    }
    BRIDGE.with(|b| {
        *b.borrow_mut() = Some(Bridge {
            world,
            base,
            trace: Vec::new(),
            windows,
            stack_host: 0,
            stack_ptr: std::ptr::null(),
            stack_patches: Vec::new(),
            unmapped: None,
            steps: 0,
        })
    });
    base
}

/// rbpf's stack is caller-owned under the `mcu` ABI, so its window is known by
/// construction rather than inferred from an allocator address.
fn install_stack(buf: &[u8]) {
    BRIDGE.with(|b| {
        let mut slot = b.borrow_mut();
        let br = slot.as_mut().expect("bridge was installed");
        br.stack_host = buf.as_ptr() as u64;
        br.stack_ptr = buf.as_ptr();
    });
}

/// `dispatch` reads the flat model, so the stack bytes have to be present at
/// their model addresses before it runs. Raw copy, not a shared reference:
/// rbpf holds the only `&mut` to this buffer for the duration of the run.
fn sync_stack_into(br: &mut Bridge) {
    if br.stack_ptr.is_null() {
        return;
    }
    let lo = (MODEL_FP - MODEL_STACK) as usize;
    unsafe {
        std::ptr::copy_nonoverlapping(
            br.stack_ptr,
            br.world.as_mut_ptr().add(lo),
            MODEL_STACK as usize,
        );
    }
}

fn sync_stack() {
    BRIDGE.with(|b| {
        let mut slot = b.borrow_mut();
        sync_stack_into(slot.as_mut().expect("bridge was installed"));
    });
}

fn uninstall() -> (Vec<u8>, Vec<Call>, Vec<StackPatch>, Option<String>) {
    BRIDGE.with(|b| {
        let br = b.borrow_mut().take().expect("bridge was installed");
        (br.world, br.trace, br.stack_patches, br.unmapped)
    })
}

/// The model's helper ABI: `dispatch(mem, [id, map, key, value, flags, _])`.
/// Only these arguments are addresses; the rest are scalars the JIT truncates
/// to 32 bits, so a large value there is not an unmapped pointer.
fn takes_address(id: u32, arg: usize) -> bool {
    matches!(
        (id, arg),
        (1, 0) | (1, 1) | (2, 0) | (2, 1) | (2, 2) | (3, 0) | (3, 1)
    )
}

fn bridge_call(id: u32, a: [u64; 5]) -> u64 {
    BRIDGE.with(|b| {
        let mut slot = b.borrow_mut();
        let br = slot.as_mut().expect("bridge was installed");
        let base = br.base;
        let flat = !br.world.is_empty();
        let mut args = [0u32; 5];
        let call = br.trace.len();
        for k in 0..5 {
            let v = a[k];
            if flat && v >= base && v < base + FLAT_LEN as u64 {
                args[k] = (v - base) as u32;
            } else if br.stack_host != 0
                && v >= br.stack_host
                && v < br.stack_host + u64::from(MODEL_STACK)
            {
                let model = MODEL_FP - MODEL_STACK + (v - br.stack_host) as u32;
                br.stack_patches.push(StackPatch {
                    call,
                    arg: k,
                    host: v,
                    model,
                });
                args[k] = model;
            } else {
                if v > u64::from(u32::MAX) && takes_address(id, k) && br.unmapped.is_none() {
                    br.unmapped = Some(format!(
                        "helper {id} arg{} = {v:#x} is outside the flat model and the stack window",
                        k + 1
                    ));
                }
                args[k] = v as u32;
            }
        }
        sync_stack_into(br);
        let ret = xpost_jit::dispatch(
            &mut br.world,
            [id, args[0], args[1], args[2], args[3], args[4]],
        );
        br.trace.push(Call { id, args, ret });
        if id == 1 && ret != 0 {
            base + u64::from(ret)
        } else {
            u64::from(ret)
        }
    })
}

fn helper_hook(id: u32, args: [u64; 5]) -> u64 {
    bridge_call(id, args)
}

fn access_hook(addr: u64, len: usize) -> bool {
    BRIDGE.with(|b| {
        let slot = b.borrow();
        let br = slot.as_ref().expect("bridge was installed");
        match addr.checked_add(len as u64) {
            Some(end) => br
                .windows
                .iter()
                .any(|(start, l)| addr >= *start && end <= start + l),
            None => false,
        }
    })
}

fn step_hook() -> rbpf::mcu::Step {
    BRIDGE.with(|b| {
        let mut slot = b.borrow_mut();
        let br = slot.as_mut().expect("bridge was installed");
        br.steps += 1;
        if br.steps > rv::STEPS {
            rbpf::mcu::Step::Exhausted
        } else {
            rbpf::mcu::Step::Go
        }
    })
}

fn mcu_env() -> rbpf::mcu::McuEnv {
    rbpf::mcu::McuEnv::new(helper_hook, access_hook, step_hook)
}

/// Run the linked image under both RV32 executors. Agreement on the return
/// value and the whole memory is what licenses using the tracing executor's
/// helper trace as the JIT side's trace.
fn execute_jit(
    code: &[u32],
    r1: u32,
    world: Vec<u8>,
    helper: Option<u32>,
) -> (Side, Option<String>) {
    let official = guard(|| xpost_jit::run_rv(code, r1, world.clone(), helper));
    let traced = guard(|| rv::run(code, r1, world, helper));
    let (o, t) = match (official, traced) {
        (Ok(o), Ok(t)) => (o, t),
        (Err(p), _) => return (Side::panicked(format!("run_rv {p}")), None),
        (_, Err(p)) => return (Side::panicked(format!("tracing executor {p}")), None),
    };
    match (o, t) {
        (Ok(o), Ok(t)) => {
            let split = if o.a0 != t.a0 || o.a1 != t.a1 || o.mem != t.mem {
                Some(format!(
                    "run_rv a0={:#x} a1={:#x}, tracing a0={:#x} a1={:#x}, memory equal {}",
                    o.a0,
                    o.a1,
                    t.a0,
                    t.a1,
                    o.mem == t.mem
                ))
            } else {
                None
            };
            let r0 = u64::from(t.a0) | (u64::from(t.a1) << 32);
            (Side::returned(r0, t.mem, t.trace), split)
        }
        (Err(e), Err(_)) => (Side::faulted(e), None),
        (Err(e), Ok(_)) => (
            Side::faulted(e.clone()),
            Some(format!(
                "run_rv faulted ({e}) but the tracing executor returned"
            )),
        ),
        (Ok(o), Err(e)) => (
            Side::returned(u64::from(o.a0) | (u64::from(o.a1) << 32), o.mem, Vec::new()),
            Some(format!(
                "tracing executor faulted ({e}) but run_rv returned"
            )),
        ),
    }
}

fn compile_link(
    insns: &[Insn],
    symbols: &HashMap<u64, String>,
    maps: &HashMap<String, u32>,
) -> Result<(Vec<u32>, usize, usize, Option<u32>), Side> {
    let image = match guard(|| compile(insns, symbols)) {
        Err(p) => return Err(Side::panicked(format!("compile {p}"))),
        Ok(Err(e)) => return Err(Side::refused(e.to_string())),
        Ok(Ok(v)) => v,
    };
    let relocs = image.relocs.len();
    let rv_bytes = image.code.len() * 4;
    if relocs == 0 {
        return Ok((image.code.clone(), rv_bytes, 0, None));
    }
    let code = match guard(|| {
        link(
            &image,
            &LinkIn {
                helper: HELPER,
                maps,
            },
        )
    }) {
        Err(p) => return Err(Side::panicked(format!("link {p}"))),
        Ok(Err(e)) => return Err(Side::refused(e.to_string())),
        Ok(Ok(v)) => v,
    };
    Ok((code, rv_bytes, relocs, Some(HELPER)))
}

/// Measure the JIT's BPF frame pointer instead of assuming it. `mov64 r1, r10;
/// call 6` makes the tracing executor report fp as helper argument 1. This is a
/// coordinate measurement, not a verdict: the case is still decided by rbpf.
fn jit_frame_pointer() -> Result<u32, String> {
    let insns = [
        Insn {
            code: CLASS_ALU64 | ALU_MOV | SRC_X,
            dst: 1,
            src: 10,
            off: 0,
            imm: 0,
        },
        Insn {
            code: CLASS_JMP | JMP_CALL,
            dst: 0,
            src: 0,
            off: 0,
            imm: 6,
        },
        Insn {
            code: CLASS_JMP | JMP_EXIT,
            dst: 0,
            src: 0,
            off: 0,
            imm: 0,
        },
    ];
    let no_symbols: HashMap<u64, String> = HashMap::new();
    let no_maps: HashMap<String, u32> = HashMap::new();
    let (code, _, _, helper) =
        compile_link(&insns, &no_symbols, &no_maps).map_err(|s| s.term)?;
    let (side, _) = execute_jit(&code, CTX, vec![0u8; FLAT_LEN], helper);
    side.trace
        .first()
        .map(|c| c.args[0])
        .ok_or_else(|| "frame-pointer calibration made no helper call".into())
}

pub fn check_program(insns: &[Insn], symbols: &HashMap<u64, String>, packet: &[u8]) -> Outcome {
    let (world, setup) = build_world(packet, symbols, true);
    let maps: HashMap<String, u32> = setup.maps.iter().cloned().collect();
    let (jit, rv_bytes, relocs, split) = match compile_link(insns, symbols, &maps) {
        Ok((code, rv_bytes, relocs, helper)) => {
            let (side, split) = execute_jit(&code, CTX, world, helper);
            (side, rv_bytes, relocs, split)
        }
        Err(side) => (side, 0, 0, None),
    };
    let (oracle, patches, stack_patches) = run_oracle(insns, symbols, packet);
    let watch = setup.watch;
    finish(
        jit,
        oracle,
        &watch,
        &watch,
        rv_bytes,
        relocs,
        patches,
        stack_patches,
        split,
        oracle_gap(insns),
    )
}

fn run_oracle(
    insns: &[Insn],
    symbols: &HashMap<u64, String>,
    packet: &[u8],
) -> (Side, Vec<ctx::Patch>, Vec<StackPatch>) {
    let adapted = match ctx::adapt(insns) {
        Ok(v) => v,
        Err(e) => {
            return (
                Side::refused(format!("ctx adaptation: {e}")),
                Vec::new(),
                Vec::new(),
            )
        }
    };
    match jit_frame_pointer() {
        Ok(v) if v == MODEL_FP => {}
        Ok(v) => {
            return (
                Side::harness(format!(
                    "JIT frame pointer {v:#x} is not the model stack top {MODEL_FP:#x}"
                )),
                adapted.patched,
                Vec::new(),
            )
        }
        Err(e) => {
            return (
                Side::harness(format!("frame-pointer calibration: {e}")),
                adapted.patched,
                Vec::new(),
            )
        }
    };
    let (world, setup) = build_world(packet, symbols, false);
    let mut ctx_buf = [0u8; 48];
    let base = install(
        world,
        vec![(ctx_buf.as_ptr() as u64, ctx_buf.len() as u64)],
    );
    let mut stack_buf = vec![0u8; MODEL_STACK as usize];
    install_stack(&stack_buf);
    let mut prog = adapted.insns;
    for (off, name) in symbols {
        let pc = (off / 8) as usize;
        let vmr = match setup.maps.iter().find(|(n, _)| n == name) {
            Some((_, v)) => *v,
            None => {
                let (_, _, sp, _) = uninstall();
                return (
                    Side::refused(format!("no map slot for {name}")),
                    adapted.patched,
                    sp,
                );
            }
        };
        if pc + 1 >= prog.len() || prog[pc].code != CLASS_LD | SIZE_DW | MODE_IMM {
            let (_, _, sp, _) = uninstall();
            return (
                Side::refused(format!("relocation at {off} is not an lddw")),
                adapted.patched,
                sp,
            );
        }
        let addr = base + u64::from(vmr);
        prog[pc].imm = addr as u32 as i32;
        prog[pc + 1].imm = (addr >> 32) as u32 as i32;
    }
    let bytes = encode(&prog);
    ctx_buf[0..8].copy_from_slice(&(base + u64::from(DATA)).to_le_bytes());
    ctx_buf[8..16].copy_from_slice(&(base + u64::from(DATA) + packet.len() as u64).to_le_bytes());

    let result = guard(|| -> Result<u64, String> {
        let vm = rbpf::EbpfVmMbuff::new(Some(&bytes)).map_err(|e| e.to_string())?;
        vm.execute_program_mcu(&[], &ctx_buf, &mut stack_buf, &mcu_env())
            .map_err(|e| e.to_string())
    });
    sync_stack();
    let (world, trace, stack_patches, unmapped) = uninstall();
    let side = match result {
        Err(p) => Side::panicked(format!("rbpf {p}")),
        Ok(Ok(r0)) => Side::returned(r0, world, trace),
        Ok(Err(e)) => Side::faulted(e),
    };
    let side = match unmapped {
        Some(msg) => Side::harness(msg),
        None => side,
    };
    (side, adapted.patched, stack_patches)
}

/// Instruction probes carry no ctx and no helpers. `r1` is the scratch base on
/// both sides, so no adaptation is needed.
pub fn check_probe(insns: &[Insn], scratch_len: usize) -> Outcome {
    let empty = HashMap::new();
    let no_maps = HashMap::new();
    let (jit, rv_bytes, relocs, split) = match compile_link(insns, &empty, &no_maps) {
        Ok((code, rv_bytes, relocs, helper)) => {
            let (side, split) = execute_jit(&code, DATA, vec![0u8; FLAT_LEN], helper);
            (side, rv_bytes, relocs, split)
        }
        Err(side) => (side, 0, 0, None),
    };
    let oracle = run_probe_oracle(insns, scratch_len);
    let jit_watch = vec![DATA as usize..DATA as usize + scratch_len];
    let oracle_watch = vec![0..scratch_len];
    finish(
        jit,
        oracle,
        &jit_watch,
        &oracle_watch,
        rv_bytes,
        relocs,
        Vec::new(),
        Vec::new(),
        split,
        oracle_gap(insns),
    )
}

fn run_probe_oracle(insns: &[Insn], scratch_len: usize) -> Side {
    let bytes = encode(insns);
    let mem = vec![0u8; scratch_len.max(64)];
    let mut stack_buf = vec![0u8; MODEL_STACK as usize];
    install(
        Vec::new(),
        vec![(mem.as_ptr() as u64, mem.len() as u64)],
    );
    install_stack(&stack_buf);
    let result = guard(|| -> Result<u64, String> {
        let vm = rbpf::EbpfVmMbuff::new(Some(&bytes)).map_err(|e| e.to_string())?;
        vm.execute_program_mcu(&[], &mem, &mut stack_buf, &mcu_env())
            .map_err(|e| e.to_string())
    });
    let (_, trace, _, unmapped) = uninstall();
    if let Some(msg) = unmapped {
        return Side::harness(msg);
    }
    match result {
        Err(p) => Side::panicked(format!("rbpf {p}")),
        Ok(Ok(r0)) => Side::returned(r0, mem, trace),
        Ok(Err(e)) => Side::faulted(e.to_string()),
    }
}

fn finish(
    jit: Side,
    oracle: Side,
    jit_watch: &[Range<usize>],
    oracle_watch: &[Range<usize>],
    rv_bytes: usize,
    relocs: usize,
    patches: Vec<ctx::Patch>,
    stack_patches: Vec<StackPatch>,
    split: Option<String>,
    gap: Option<&'static str>,
) -> Outcome {
    let mut diffs = Vec::new();
    // A JIT panic is a defect. An oracle panic means rbpf cannot execute the
    // case, which is UNSUPPORTED with its own text, never a pass.
    let (mut status, mut detail, mut blame) = if jit.term.starts_with("harness")
        || oracle.term.starts_with("harness")
    {
        (
            Status::Inconclusive,
            format!("jit {}; rbpf {}", jit.term, oracle.term),
            "oracle-harness",
        )
    } else if jit.term.starts_with("panic") {
        (Status::Fail, format!("jit {}", jit.term), "jit")
    } else if oracle.term.starts_with("panic") {
        (
            Status::Unsupported,
            format!("rbpf cannot execute: {}", oracle.term),
            "oracle",
        )
    } else {
        match (jit.ok, oracle.ok) {
            (false, false) => {
                if jit.term.starts_with("refused") || oracle.term.starts_with("refused") {
                    (
                        Status::Unsupported,
                        format!("jit {}; rbpf {}", jit.term, oracle.term),
                        "none",
                    )
                } else {
                    (
                        Status::Inconclusive,
                        format!("both fault: jit {}; rbpf {}", jit.term, oracle.term),
                        "none",
                    )
                }
            }
            // The JIT documents these opcodes as rejected, so refusing while
            // rbpf executes is a coverage limit, not a translation defect.
            (false, true) => (
                Status::Unsupported,
                format!(
                    "jit does not support this input ({}); rbpf returned {:?}",
                    jit.term, oracle.r0
                ),
                "jit-unsupported",
            ),
            (true, false) => (
                Status::Fail,
                format!(
                    "rbpf did not return ({}) but jit returned {:?}",
                    oracle.term, jit.r0
                ),
                "open",
            ),
            (true, true) => {
                if jit.r0 != oracle.r0 {
                    diffs.push(format!("return jit {:?} rbpf {:?}", jit.r0, oracle.r0));
                }
                if jit.trace != oracle.trace {
                    diffs.push(format!(
                        "helper trace jit {} calls, rbpf {} calls",
                        jit.trace.len(),
                        oracle.trace.len()
                    ));
                }
                for (jw, ow) in jit_watch.iter().zip(oracle_watch) {
                    let j = jit.mem.as_ref().unwrap();
                    let r = oracle.mem.as_ref().unwrap();
                    if jw.end > j.len() || ow.end > r.len() {
                        diffs.push(format!("watch {jw:?} is outside memory"));
                    } else if j[jw.clone()] != r[ow.clone()] {
                        let bad: Vec<usize> = jw
                            .clone()
                            .zip(ow.clone())
                            .filter(|(a, b)| j[*a] != r[*b])
                            .map(|(a, _)| a - jw.start)
                            .collect();
                        let shown: Vec<String> = bad
                            .iter()
                            .take(8)
                            .map(|o| {
                                format!(
                                    "+{o:#x} {:02x}/{:02x}",
                                    j[jw.start + o],
                                    r[ow.start + o]
                                )
                            })
                            .collect();
                        diffs.push(format!(
                            "memory jit {jw:?} rbpf {ow:?} differs in {} bytes [{}]",
                            bad.len(),
                            shown.join(" ")
                        ));
                    }
                }
                if diffs.is_empty() {
                    (Status::Pass, format!("return {:?}", jit.r0), "none")
                } else if let Some(g) = gap {
                    (
                        Status::Unsupported,
                        format!("oracle gap: {g}; {}", diffs.join("; ")),
                        "oracle",
                    )
                } else {
                    (Status::Fail, diffs.join("; "), "open")
                }
            }
        }
    };
    if status == Status::Pass {
        if let Some(s) = &split {
            status = Status::Inconclusive;
            detail = format!("rv32 executors disagree: {s}");
            blame = "open";
        }
    }
    Outcome {
        status,
        detail,
        jit,
        oracle,
        diffs,
        rv_bytes,
        relocs,
        ctx_patches: patches,
        stack_patches,
        executor_split: split,
        blame,
    }
}
