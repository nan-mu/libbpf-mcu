use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use anyhow::{Context, Result, ensure};
use mcu_image::{RegionKind, code_range};
use mcu_index::{Index, bpf_path, contained};
use object::Architecture;

use crate::{Code, sections};

struct Report<'a> {
    source: String,
    listings: BTreeMap<&'a str, String>,
}

fn parse(text: &str) -> Result<Report<'_>> {
    let mut lines = text.lines();
    let mut source = None;
    let mut listings = BTreeMap::new();
    let mut isa = BTreeMap::new();
    let mut mode = "";
    let mut group = "";
    let mut build_steps = false;
    let mut recipes = false;
    let mut current = false;
    while let Some(line) = lines.next() {
        if let Some(heading) = line.strip_prefix("## ") {
            group = heading;
            mode = "";
            current |= group == "Build recipes";
            build_steps = false;
        } else if let Some(heading) = line.strip_prefix("### ") {
            mode = heading;
            build_steps = false;
            ensure!(
                isa.insert(mode, group).is_none(),
                "duplicate report mode {mode}"
            );
        } else if line == "#### Build steps" {
            build_steps = true;
        }
        let fence = line.bytes().take_while(|byte| *byte == b'`').count();
        if fence < 3 {
            continue;
        }
        let delimiter = &line[..fence];
        let language = &line[fence..];
        let mut block = String::new();
        let mut closed = false;
        for content in lines.by_ref() {
            if content == delimiter {
                closed = true;
                break;
            }
            block.push_str(content);
            block.push('\n');
        }
        ensure!(closed, "unclosed report fence");
        match (group, language, mode, build_steps) {
            ("Source", "c", _, _) => {
                ensure!(source.replace(block).is_none(), "duplicate report source");
            }
            ("Build recipes", "sh", _, _) | (_, "text", _, true) => {
                recipes |= !block.trim().is_empty();
            }
            (_, "text", "bpf" | "llvm-aot" | "jit" | "ebpf", false) => {
                ensure!(
                    listings.insert(mode, block).is_none(),
                    "duplicate report listing for {mode}"
                );
            }
            _ => {}
        }
    }
    ensure!(recipes, "missing build recipes or steps");
    if current {
        for (mode, expected) in [
            ("bpf", "eBPF"),
            ("ebpf", "eBPF"),
            ("llvm-aot", "RV32IMC"),
            ("jit", "RV32IM"),
        ] {
            ensure!(
                isa.get(mode).is_none_or(|group| group == &expected),
                "wrong ISA heading for {mode}"
            );
        }
    }
    Ok(Report {
        source: source.context("missing C source in report")?,
        listings,
    })
}

fn verify_listing(text: &str, sections: &BTreeMap<String, Code<'_>>) -> Result<()> {
    let mut active = None;
    let mut seen = BTreeSet::new();
    let mut offset = 0;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        if let Some((name, label)) = line.rsplit_once(" (") {
            if matches!(label, "section byte offset)" | "linked address)") {
                if let Some(code) = active.take() {
                    let code: &Code<'_> = code;
                    ensure!(offset == code.bytes.len(), "incomplete report code section");
                }
                let name = name.trim_end();
                ensure!(seen.insert(name), "duplicate report code section {name}");
                active = Some(
                    sections
                        .get(name)
                        .with_context(|| format!("unknown report code section {name}"))?,
                );
                offset = 0;
                continue;
            }
        }
        let code = active.context("missing report code section")?;
        let mut columns = line.splitn(3, "  ");
        let address = u64::from_str_radix(columns.next().context("missing report address")?, 16)?;
        let bytes = columns.next().context("missing report machine bytes")?;
        let assembly = columns.next().context("missing report assembly")?;
        let bytes = bytes
            .split_whitespace()
            .map(|value| {
                ensure!(value.len() == 2, "expected an instruction byte");
                Ok(u8::from_str_radix(value, 16)?)
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            address == code.address + offset as u64
                && !bytes.is_empty()
                && code.bytes.get(offset..offset + bytes.len()) == Some(bytes.as_slice())
                && !assembly.trim().is_empty(),
            "report bytes or address differ at {address:#x}"
        );
        offset += bytes.len();
    }
    ensure!(
        active.is_some_and(|code| offset == code.bytes.len()) && seen.len() == sections.len(),
        "incomplete report listing"
    );
    Ok(())
}

/// Validate archived reports using the exact indexed source and code bytes.
pub fn verify(root: &Path, index: &Index) -> Result<()> {
    let report = fs::read_to_string(contained(root, "report.md")?)?;
    let mut report = parse(&report).context("parse build report")?;
    let source = index.source.load(root, &format!("{}.c", index.program))?;
    let mut source = String::from_utf8(source)?;
    // Both renderers finish the final source line inside the Markdown fence.
    source = source.replace("\r\n", "\n");
    if !source.ends_with('\n') {
        source.push('\n');
    }
    ensure!(
        source == report.source,
        "the report source differs from the indexed source"
    );
    let bpf = index.bpf.load(root, &bpf_path(&index.program))?;
    verify_listing(
        &report
            .listings
            .remove("bpf")
            .context("missing BPF report listing")?,
        &sections(&bpf, Architecture::Bpf)?,
    )?;
    for row in &index.mode {
        if row.role == "xpost_container" {
            // Historical fixed-address rows still use the V0 container verifier.
            report.listings.remove(row.name.name());
            continue;
        }
        let (bytes, layout, _) = index.portable(root, row.name)?;
        let mut sections = BTreeMap::new();
        for region in layout
            .regions
            .iter()
            .filter(|region| region.kind == RegionKind::Code)
        {
            sections.insert(
                region.name.clone(),
                Code {
                    address: u64::from(region.offset),
                    bytes: &bytes[code_range(region, &bytes)?],
                },
            );
        }
        let listing = report
            .listings
            .remove(row.name.name())
            .with_context(|| format!("missing {} report listing", row.name))?;
        verify_listing(&listing, &sections)
            .with_context(|| format!("verify {} report listing", row.name))?;
    }
    ensure!(
        report.listings.is_empty(),
        "report has unindexed mode listings"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn rejects_duplicate_modes_and_unclosed_markdown_fences() {
        let source = concat!("## Source\n", "```c\n", "int example;\n", "```\n");
        let recipes = concat!(
            "## Build recipes\n",
            "```sh\n",
            "clang example.c\n",
            "```\n"
        );

        let repeated = format!("{source}## RV32IM\n### jit\n### jit\n{recipes}");
        let error = parse(&repeated).err().expect("duplicate mode accepted");
        assert!(error.to_string().contains("duplicate report mode jit"));

        let unclosed = format!("{source}{recipes}## eBPF\n### bpf\n```text\n");
        let error = parse(&unclosed).err().expect("unclosed fence accepted");
        assert!(error.to_string().contains("unclosed report fence"));
    }
}
