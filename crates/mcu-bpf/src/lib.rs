mod verifier;

pub use verifier::verify;

mod btf;

use anyhow::{Context, Result, bail, ensure};
use object::{Object, ObjectSection, ObjectSymbol, RelocationTarget};

pub use btf::{MapDefinition, maps};

fn object(bytes: &[u8]) -> Result<object::File<'_>> {
    let elf = object::File::parse(bytes)?;
    ensure!(
        elf.format() == object::BinaryFormat::Elf
            && elf.architecture() == object::Architecture::Bpf
            && elf.is_64()
            && elf.is_little_endian()
            && elf.kind() == object::ObjectKind::Relocatable,
        "expected a little-endian relocatable BPF ELF"
    );
    Ok(elf)
}

pub fn map_indexed(bytes: &[u8], map_names: &[&str]) -> Result<(String, Vec<u8>)> {
    let elf = object(bytes)?;
    let mut sections = elf
        .sections()
        .filter(|s| matches!(s.name(), Ok("xdp" | "xdp1")) && s.size() != 0);
    let section = sections.next().context("object has no XDP code")?;
    ensure!(
        sections.next().is_none(),
        "object has multiple XDP sections"
    );
    let mut code = section.data()?.to_vec();
    for (offset, reloc) in section.relocations() {
        let RelocationTarget::Symbol(index) = reloc.target() else {
            bail!("unsupported XDP relocation at {offset:#x}");
        };
        let symbol = elf.symbol_by_index(index)?;
        let name = symbol.name()?;
        ensure!(
            symbol
                .section_index()
                .and_then(|index| elf.section_by_index(index).ok())
                .is_some_and(|section| matches!(section.name(), Ok("maps" | ".maps"))),
            "unresolved XDP relocation at {offset:#x} to {name:?}"
        );
        let id = map_names
            .iter()
            .position(|map| *map == name)
            .with_context(|| format!("no canonical map entry for {name:?}"))?;
        let at = usize::try_from(offset)?;
        let end = at
            .checked_add(16)
            .context("map relocation offset overflow")?;
        let lddw = code
            .get_mut(at..end)
            .context("map relocation outside XDP code")?;
        ensure!(
            at % 8 == 0 && lddw[0] == 0x18 && lddw[8] == 0,
            "expected LDDW at {offset:#x}"
        );
        lddw[1] = (lddw[1] & 0xf) | 0x10;
        lddw[4..8].copy_from_slice(&u32::try_from(id)?.to_le_bytes());
        lddw[12..16].fill(0);
    }
    rbpf::EbpfVmMbuff::verify(&code)
        .map_err(|error| anyhow::anyhow!("rBPF verifier: {error:?}"))?;
    Ok((section.name()?.to_owned(), code))
}
