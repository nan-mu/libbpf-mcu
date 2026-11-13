//! Machine-readable results. No serde: the shape is small and fixed.

use std::fmt::Write as _;
use std::ops::Range;

use crate::run::{Outcome, Status};

#[derive(Clone)]
pub enum J {
    Null,
    Bool(bool),
    Num(i64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(&'static str, J)>),
}

impl J {
    pub fn str(s: impl Into<String>) -> J {
        J::Str(s.into())
    }

    pub fn write(&self, out: &mut String, indent: usize) {
        let pad = "  ".repeat(indent);
        let pad2 = "  ".repeat(indent + 1);
        match self {
            J::Null => out.push_str("null"),
            J::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            J::Num(n) => {
                let _ = write!(out, "{n}");
            }
            J::Str(s) => quote(out, s),
            J::Arr(v) => {
                if v.is_empty() {
                    out.push_str("[]");
                    return;
                }
                out.push_str("[\n");
                for (i, x) in v.iter().enumerate() {
                    out.push_str(&pad2);
                    x.write(out, indent + 1);
                    if i + 1 < v.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&pad);
                out.push(']');
            }
            J::Obj(fields) => {
                if fields.is_empty() {
                    out.push_str("{}");
                    return;
                }
                out.push_str("{\n");
                for (i, (k, v)) in fields.iter().enumerate() {
                    out.push_str(&pad2);
                    quote(out, k);
                    out.push_str(": ");
                    v.write(out, indent + 1);
                    if i + 1 < fields.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&pad);
                out.push('}');
            }
        }
    }

    pub fn to_json(&self) -> String {
        let mut s = String::new();
        self.write(&mut s, 0);
        s.push('\n');
        s
    }
}

fn quote(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn trace_json(trace: &[crate::rv::Call]) -> J {
    J::Arr(
        trace
            .iter()
            .map(|c| {
                J::Obj(vec![
                    ("id", J::Num(c.id as i64)),
                    (
                        "args",
                        J::Arr(c.args.iter().map(|a| J::Num(*a as i64)).collect()),
                    ),
                    ("ret", J::Num(c.ret as i64)),
                ])
            })
            .collect(),
    )
}

/// `watch` pairs the JIT-side region with the oracle-side region.
pub fn case(
    suite: &str,
    name: &str,
    input: &str,
    o: &Outcome,
    watch: &[(Range<usize>, Range<usize>)],
) -> J {
    let regions: Vec<J> = watch
        .iter()
        .map(|(jw, ow)| {
            let equal = match (&o.jit.mem, &o.oracle.mem) {
                (Some(j), Some(r)) if jw.end <= j.len() && ow.end <= r.len() => {
                    J::Bool(j[jw.clone()] == r[ow.clone()])
                }
                _ => J::Null,
            };
            J::Obj(vec![
                ("jit_range", J::str(format!("{jw:?}"))),
                ("oracle_range", J::str(format!("{ow:?}"))),
                ("equal", equal),
            ])
        })
        .collect();
    J::Obj(vec![
        ("suite", J::str(suite)),
        ("name", J::str(name)),
        ("input", J::str(input)),
        ("status", J::str(o.status.as_str())),
        ("blame", J::str(o.blame)),
        ("detail", J::str(&o.detail)),
        ("rv_bytes", J::Num(o.rv_bytes as i64)),
        ("relocs", J::Num(o.relocs as i64)),
        (
            "observables",
            J::Obj(vec![
                ("jit_return", opt_num(o.jit.r0)),
                ("oracle_return", opt_num(o.oracle.r0)),
                ("jit_termination", J::str(&o.jit.term)),
                ("oracle_termination", J::str(&o.oracle.term)),
                ("return_equal", J::Bool(o.jit.r0 == o.oracle.r0)),
                ("trace_equal", J::Bool(o.jit.trace == o.oracle.trace)),
                ("jit_trace", trace_json(&o.jit.trace)),
                ("oracle_trace", trace_json(&o.oracle.trace)),
                ("memory_regions", J::Arr(regions)),
            ]),
        ),
        (
            "ctx_patches",
            J::Arr(
                o.ctx_patches
                    .iter()
                    .map(|p| {
                        J::Obj(vec![
                            ("pc", J::Num(p.pc as i64)),
                            ("old_off", J::Num(p.old_off as i64)),
                            ("new_off", J::Num(p.new_off as i64)),
                            ("widened", J::Bool(p.widened)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "stack_patches",
            J::Arr(
                o.stack_patches
                    .iter()
                    .map(|p| {
                        J::Obj(vec![
                            ("call", J::Num(p.call as i64)),
                            ("arg", J::Num(p.arg as i64)),
                            ("host", J::Num(p.host as i64)),
                            ("model", J::Num(p.model as i64)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "executor_split",
            match &o.executor_split {
                Some(s) => J::str(s),
                None => J::Null,
            },
        ),
        ("diffs", J::Arr(o.diffs.iter().map(|d| J::str(d)).collect())),
    ])
}

fn opt_num(v: Option<u64>) -> J {
    match v {
        Some(v) => J::Num(v as i64),
        None => J::Null,
    }
}

pub fn summary(cases: &[J]) -> J {
    let mut pass = 0;
    let mut fail = 0;
    let mut inconclusive = 0;
    let mut unsupported = 0;
    for c in cases {
        if let J::Obj(fields) = c {
            if let Some((_, J::Str(s))) = fields.iter().find(|(k, _)| *k == "status") {
                match s.as_str() {
                    "pass" => pass += 1,
                    "fail" => fail += 1,
                    "inconclusive" => inconclusive += 1,
                    "unsupported" => unsupported += 1,
                    _ => {}
                }
            }
        }
    }
    J::Obj(vec![
        ("total", J::Num(cases.len() as i64)),
        ("pass", J::Num(pass)),
        ("fail", J::Num(fail)),
        ("inconclusive", J::Num(inconclusive)),
        ("unsupported", J::Num(unsupported)),
    ])
}

pub fn status_of(c: &J) -> Status {
    if let J::Obj(fields) = c {
        if let Some((_, J::Str(s))) = fields.iter().find(|(k, _)| *k == "status") {
            return match s.as_str() {
                "pass" => Status::Pass,
                "fail" => Status::Fail,
                "inconclusive" => Status::Inconclusive,
                _ => Status::Unsupported,
            };
        }
    }
    Status::Fail
}
