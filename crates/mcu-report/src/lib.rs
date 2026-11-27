use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write,
    fs,
    path::Path,
};

use anyhow::{Context, Result, ensure};
use mcu_image::{Layout, Mode, RegionKind, code_range, write_atomic};
use mcu_index::{bpf_path, directory_name, image_paths};
use object::{
    Architecture, BinaryFormat, Endianness, Object, ObjectSection, SectionFlags, SectionKind,
};

pub fn prepare(image: &Path, layout: &Path, output: &Path) -> Result<()> {
    let bytes = fs::read(image)?;
    let layout = Layout::read(layout)?;
    layout.validate(&layout.program, layout.mode, &bytes, &layout.sites())?;
    let arch = match layout.mode {
        Mode::Jit => Architecture::Riscv32,
        Mode::Ebpf => Architecture::Bpf,
        Mode::Aot => anyhow::bail!("use the actual linked AOT ELF"),
    };
    let mut elf = object::write::Object::new(BinaryFormat::Elf, arch, Endianness::Little);
    for region in layout
        .regions
        .iter()
        .filter(|region| region.kind == RegionKind::Code)
    {
        ensure!(
            region.offset == 0,
            "expected single zero-based disassembly section"
        );
        let code = &bytes[code_range(region, &bytes)?];
        let id = elf.add_section(
            Vec::new(),
            region.name.as_bytes().to_vec(),
            SectionKind::Text,
        );
        elf.append_section_data(id, code, u64::from(region.alignment));
    }
    write_atomic(output, &elf.write()?)
}

struct Code<'a> {
    address: u64,
    bytes: &'a [u8],
}

fn sections(bytes: &[u8], arch: Architecture) -> Result<BTreeMap<String, Code<'_>>> {
    let file = object::File::parse(bytes)?;
    ensure!(
        file.architecture() == arch
            && file.format() == BinaryFormat::Elf
            && file.is_little_endian(),
        "wrong ELF target for report"
    );
    let mut out = BTreeMap::new();
    for section in file.sections() {
        if section.size() != 0
            && matches!(section.flags(), SectionFlags::Elf { sh_flags } if sh_flags & 4 != 0)
        {
            ensure!(
                out.insert(
                    section.name()?.to_owned(),
                    Code {
                        address: section.address(),
                        bytes: section.data()?
                    }
                )
                .is_none(),
                "duplicate code section"
            );
        }
    }
    ensure!(!out.is_empty(), "missing executable sections");
    Ok(out)
}

fn raw_bytes(raw: &str, bpf: bool) -> Result<Vec<u8>> {
    let words: Vec<_> = raw.split_whitespace().collect();
    let mut data = Vec::new();
    for word in words {
        ensure!(
            !word.is_empty() && word.len() % 2 == 0 && word.len() <= 8 && word.is_ascii(),
            "invalid objdump instruction word"
        );
        let mut bytes = (0..word.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&word[i..i + 2], 16))
            .collect::<Result<Vec<_>, _>>()?;
        if !bpf {
            bytes.reverse();
        }
        data.extend(bytes);
    }
    ensure!(!data.is_empty(), "missing objdump instruction bytes");
    Ok(data)
}

fn listing(disasm: &str, sections: BTreeMap<String, Code<'_>>, bpf: bool) -> Result<String> {
    let mut current = None;
    let mut offsets = BTreeMap::new();
    let mut result = String::new();
    for line in disasm.lines() {
        if let Some(section) = line
            .strip_prefix("Disassembly of section ")
            .and_then(|s| s.strip_suffix(':'))
        {
            let code = sections
                .get(section)
                .with_context(|| format!("unexpected objdump section {section}"))?;
            ensure!(
                offsets.insert(section, 0).is_none(),
                "duplicate disassembly section"
            );
            current = Some((section, code));
            let label = if bpf {
                "section byte offset"
            } else {
                "linked address"
            };
            writeln!(result, "{section} ({label})")?;
        }
        let Some((section, code)) = current else {
            continue;
        };
        let Some((printed, content)) = line.trim_start().split_once(':') else {
            continue;
        };
        if printed.is_empty() || !printed.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let (raw, assembly) = content
            .trim_start()
            .split_once('\t')
            .context("objdump instruction lacks assembly")?;
        let bytes = raw_bytes(raw, bpf)?;
        let offset = if bpf {
            printed
                .parse::<u64>()?
                .checked_mul(8)
                .context("objdump BPF offset overflow")?
        } else {
            u64::from_str_radix(printed, 16)?
                .checked_sub(code.address)
                .context("objdump address before section")?
        };
        let at = usize::try_from(offset)?;
        let consumed = offsets.get_mut(section).unwrap();
        ensure!(
            at == *consumed && code.bytes.get(at..at + bytes.len()) == Some(bytes.as_slice()),
            "{section}+{offset:#x}: disassembly bytes differ from object"
        );
        let encoded = bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        writeln!(
            result,
            "{:08x}  {encoded:<47}  {}",
            code.address + offset,
            assembly.split_whitespace().collect::<Vec<_>>().join(" ")
        )?;
        *consumed += bytes.len();
    }
    for (name, code) in sections {
        ensure!(
            offsets.get(name.as_str()) == Some(&code.bytes.len()),
            "incomplete objdump listing for {name}"
        );
    }
    Ok(result)
}

fn fenced(output: &mut String, text: &str, language: &str) -> Result<()> {
    let count = text
        .split(|c| c != '`')
        .map(str::len)
        .max()
        .unwrap_or(0)
        .saturating_add(1)
        .max(3);
    let fence = "`".repeat(count);
    writeln!(
        output,
        "{fence}{language}\n{text}{}{fence}\n",
        if text.ends_with('\n') { "" } else { "\n" }
    )?;
    Ok(())
}

pub fn render(
    program_dir: &Path,
    linked: &Path,
    listings: &Path,
    modes: &[Mode],
) -> Result<String> {
    let program = directory_name(program_dir)?;
    let source = fs::read_to_string(program_dir.join(format!("{program}.c")))?;
    let bpf = fs::read(program_dir.join(bpf_path(program)))?;
    let bpf_listing = listing(
        &fs::read_to_string(listings.join("bpf.txt"))?,
        sections(&bpf, Architecture::Bpf)?,
        true,
    )?;
    let mut report = format!("# Build report\n\n## Source\n\n`{program}.c`\n\n");
    fenced(&mut report, &source, "c")?;
    if !source.ends_with('\n') {
        report.push_str("The source file ends without a newline.\n\n");
    }
    report.push_str("## eBPF\n\n### bpf\n\nOriginal little-endian Clang bytecode.\n\n");
    fenced(&mut report, &bpf_listing, "text")?;
    let modes: BTreeSet<_> = modes.iter().copied().collect();
    for mode in [Mode::Ebpf, Mode::Aot, Mode::Jit] {
        if !modes.contains(&mode) {
            continue;
        }
        let (image, layout) = image_paths(mode);
        let bytes = fs::read(program_dir.join(image))?;
        let layout = Layout::read(&program_dir.join(layout))?;
        layout.validate(program, mode, &bytes, &layout.sites())?;
        let elf = if mode == Mode::Aot {
            fs::read(linked)?
        } else {
            fs::read(listings.join(format!("{mode}.elf")))?
        };
        let arch = if mode == Mode::Ebpf {
            Architecture::Bpf
        } else {
            Architecture::Riscv32
        };
        let sections = sections(&elf, arch)?;
        let mut count = 0;
        for region in layout
            .regions
            .iter()
            .filter(|region| region.kind == RegionKind::Code)
        {
            let code = sections
                .get(&region.name)
                .context("missing image code section in disassembly ELF")?;
            ensure!(
                code.address == u64::from(region.offset)
                    && code.bytes == &bytes[code_range(region, &bytes)?],
                "ELF code differs from {mode} image"
            );
            count += 1;
        }
        ensure!(count == sections.len(), "ELF contains extra code sections");
        let description = match mode {
            Mode::Aot => "LLVM AOT for ESP32-C3, RV32IMC and ILP32. Linked at zero.",
            Mode::Jit => "Host JIT produces RV32IM with the ILP32 ABI. Linked at zero.",
            Mode::Ebpf => "Little-endian rBPF bytecode with canonical map indices.",
        };
        match mode {
            Mode::Aot => report.push_str("## RV32IMC\n\n"),
            Mode::Jit => report.push_str("## RV32IM\n\n"),
            Mode::Ebpf => {}
        }
        writeln!(report, "### {mode}\n\n{description}\n")?;
        let instructions = listing(
            &fs::read_to_string(listings.join(format!("{mode}.txt")))?,
            sections,
            mode == Mode::Ebpf,
        )?;
        fenced(&mut report, &instructions, "text")?;
    }
    report.push_str("## Build recipes\n\nCommands from the generated Ninja graph.\n\n");
    fenced(
        &mut report,
        &fs::read_to_string(listings.join("recipes.txt"))?,
        "sh",
    )?;
    Ok(report)
}

pub fn generate(program_dir: &Path, linked: &Path, listings: &Path, modes: &[Mode]) -> Result<()> {
    let report = render(program_dir, linked, listings, modes)?;
    write_atomic(&program_dir.join("report.md"), report.as_bytes())
}

mod verify;
pub use verify::verify;
