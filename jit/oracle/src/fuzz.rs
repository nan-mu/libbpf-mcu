//! Seeded random differential programs over the supported instruction set.
//!
//! The PRNG is a local xorshift64 so a failing case reproduces from its seed
//! with no new dependency. Jumps only ever go forward and always land on an
//! item boundary, so every generated program terminates and is well formed.

use xpost_jit::isa::*;
use xpost_jit::Insn;

pub struct Rng(pub u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        // splitmix64 finalizer: `seed | 1` would fold each even seed into the
        // odd one above it and halve the distinct programs.
        let mut z = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        Rng((z ^ (z >> 31)) | 1)
    }

    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    pub fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len() as u64) as usize]
    }

    pub fn reg(&mut self) -> u8 {
        self.below(9) as u8
    }

    pub fn constant(&mut self) -> u64 {
        match self.below(4) {
            0 => *self.pick(crate::probes::WIDE),
            1 => self.next(),
            2 => self.below(66),
            _ => (self.next() as u32) as u64,
        }
    }
}

enum Item {
    One(Insn),
    Wide(u8, u64),
    Cond {
        code: u8,
        dst: u8,
        src: u8,
        imm: i32,
        target: usize,
    },
}

fn layout(items: &[Item]) -> Vec<u8> {
    let mut start = Vec::with_capacity(items.len());
    let mut w = 0usize;
    for it in items {
        start.push(w);
        w += match it {
            Item::Wide(..) => 2,
            _ => 1,
        };
    }
    let mut out = Vec::with_capacity(w * 8);
    let push = |i: Insn, out: &mut Vec<u8>| {
        out.push(i.code);
        out.push((i.dst & 0x0f) | (i.src << 4));
        out.extend_from_slice(&i.off.to_le_bytes());
        out.extend_from_slice(&i.imm.to_le_bytes());
    };
    for (n, it) in items.iter().enumerate() {
        match it {
            Item::One(i) => push(*i, &mut out),
            Item::Wide(dst, v) => {
                push(
                    Insn {
                        code: CLASS_LD | SIZE_DW | MODE_IMM,
                        dst: *dst,
                        src: 0,
                        off: 0,
                        imm: *v as u32 as i32,
                    },
                    &mut out,
                );
                push(
                    Insn {
                        code: 0,
                        dst: 0,
                        src: 0,
                        off: 0,
                        imm: (*v >> 32) as u32 as i32,
                    },
                    &mut out,
                );
            }
            Item::Cond {
                code,
                dst,
                src,
                imm,
                target,
            } => {
                let off = (start[*target] - start[n] - 1) as i16;
                push(
                    Insn {
                        code: *code,
                        dst: *dst,
                        src: *src,
                        off,
                        imm: *imm,
                    },
                    &mut out,
                );
            }
        }
    }
    out
}

const BINARY: &[u8] = &[
    ALU_ADD, ALU_SUB, ALU_MUL, ALU_DIV, ALU_OR, ALU_AND, ALU_LSH, ALU_RSH, ALU_MOD, ALU_XOR,
    ALU_MOV, ALU_ARSH,
];

const CONDS: &[u8] = &[
    JMP_JEQ, JMP_JGT, JMP_JGE, JMP_JSET, JMP_JNE, JMP_JSGT, JMP_JSGE, JMP_JLT, JMP_JLE, JMP_JSLT,
    JMP_JSLE,
];

pub fn program(seed: u64, ops: usize) -> Vec<Insn> {
    let mut r = Rng::new(seed);
    let mut items = vec![Item::One(Insn {
        code: CLASS_ALU64 | ALU_MOV | SRC_X,
        dst: 9,
        src: 1,
        off: 0,
        imm: 0,
    })];
    for k in 0..9u8 {
        let v = r.constant();
        items.push(Item::Wide(k, v));
    }
    let body = items.len();
    for _ in 0..ops {
        let class = *r.pick(&[CLASS_ALU, CLASS_ALU64]);
        match r.below(10) {
            0 => {
                let dst = r.reg();
                let v = r.constant();
                items.push(Item::Wide(dst, v));
            }
            1 => {
                let dst = r.reg();
                items.push(Item::One(Insn {
                    code: class | ALU_NEG,
                    dst,
                    src: 0,
                    off: 0,
                    imm: 0,
                }));
            }
            2 => {
                let dst = r.reg();
                let bits = *r.pick(&[16i32, 32, 64]);
                let src = *r.pick(&[SRC_K, SRC_X]);
                items.push(Item::One(Insn {
                    code: CLASS_ALU | ALU_END | src,
                    dst,
                    src: 0,
                    off: 0,
                    imm: bits,
                }));
            }
            3 | 4 => {
                let dst = r.reg();
                let src = r.reg();
                let jclass = *r.pick(&[CLASS_JMP, CLASS_JMP32]);
                let code = jclass | r.pick(CONDS) | SRC_X;
                items.push(Item::Cond {
                    code,
                    dst,
                    src,
                    imm: 0,
                    target: 0,
                });
            }
            _ => {
                let dst = r.reg();
                let op = *r.pick(BINARY);
                // ALU64 div/mod are rejected by the JIT, so they would only
                // produce UNSUPPORTED cases and crowd out real coverage.
                let class = if class == CLASS_ALU64 && matches!(op, ALU_DIV | ALU_MOD) {
                    CLASS_ALU
                } else {
                    class
                };
                if r.below(2) == 0 {
                    let src = r.reg();
                    items.push(Item::One(Insn {
                        code: class | op | SRC_X,
                        dst,
                        src,
                        off: 0,
                        imm: 0,
                    }));
                } else {
                    let imm = r.constant() as u32 as i32;
                    items.push(Item::One(Insn {
                        code: class | op | SRC_K,
                        dst,
                        src: 0,
                        off: 0,
                        imm,
                    }));
                }
            }
        }
    }
    let tail = items.len();
    for k in 0..9u8 {
        items.push(Item::One(Insn {
            code: CLASS_STX | SIZE_DW | MODE_MEM,
            dst: 9,
            src: k,
            off: (k as i16) * 8,
            imm: 0,
        }));
    }
    items.push(Item::One(Insn {
        code: CLASS_JMP | JMP_EXIT,
        dst: 0,
        src: 0,
        off: 0,
        imm: 0,
    }));
    let last = items.len();
    for n in body..tail {
        if let Item::Cond { target, .. } = &mut items[n] {
            *target = n + 1 + r.below((last - n - 1) as u64) as usize;
        }
    }
    let bytes = layout(&items);
    xpost_jit::decode_insns(&bytes).expect("generated program is a whole number of words")
}
