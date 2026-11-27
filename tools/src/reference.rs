use std::{collections::HashMap, fs, path::Path, process::Command};

use anyhow::{Context, Result, ensure};
use mcu_image::{Layout, Mode, TargetLayout, aot_payload, linker_script, write_atomic};
use mcu_index::{Index, bpf_path, contained, rv32_path};
use xpost_elf::build_container;

pub fn generate(
    program: &Path,
    mode: Mode,
    target: TargetLayout,
    work: &Path,
    lld: &Path,
) -> Result<Vec<u8>> {
    let index = Index::read(program)?;
    index.verify(program)?;
    let name = index.program;
    let bpf = contained(program, &bpf_path(&name))?;
    let write_reference = |payload: Vec<u8>, layout: Layout| {
        let meta = layout.metadata(target.slot, target.helper)?;
        let blob = build_container(&payload, &meta, Some(target.capacity))
            .map_err(|e| anyhow::anyhow!("encode reference image: {e:?}"))?;
        Ok(blob.as_slice().to_vec())
    };
    match mode {
        Mode::Aot => {
            let source = contained(program, &rv32_path(&name))?;
            fs::create_dir_all(work)?;
            let linker = work.join("direct.ld");
            let elf = work.join("direct.elf");
            write_atomic(
                &linker,
                linker_script(target.slot, target.capacity, target.helper).as_bytes(),
            )?;
            let status = Command::new(lld)
                .args(["-m", "elf32lriscv", "--no-relax", "-T"])
                .arg(&linker)
                .arg(source)
                .arg("-o")
                .arg(&elf)
                .status()
                .context("run LLD for the independent reference")?;
            ensure!(status.success(), "direct LLD link failed ({status})");
            let (payload, regions, maps) = aot_payload(
                &fs::read(elf)?,
                &fs::read(bpf)?,
                target.slot,
                target.capacity,
            )?;
            write_reference(payload, Layout::new(name, mode, regions, maps, vec![]))
        }
        Mode::Jit => {
            let (image, maps) = mcu_jit::compile_object(&bpf)?;
            let vmrs = maps
                .iter()
                .map(|map| {
                    let addr = target
                        .slot
                        .checked_add(map.offset)
                        .context("direct map address overflow")?;
                    Ok((map.name.clone(), addr))
                })
                .collect::<Result<HashMap<_, _>>>()?;
            let words = xpost_jit::link(
                &image,
                &xpost_jit::LinkIn {
                    helper: target.helper,
                    maps: &vmrs,
                },
            )
            .map_err(|e| anyhow::anyhow!("direct JIT link: {e}"))?;
            let mut payload = words
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect::<Vec<_>>();
            if let Some(length) = maps.last().map(|map| map.offset + map.placeholder_bytes) {
                payload.resize(length as usize, 0);
            }
            write_reference(payload, Layout::new(name, mode, vec![], maps, vec![]))
        }
        Mode::Ebpf => anyhow::bail!("rBPF bytecode has no native direct-link reference"),
    }
}
