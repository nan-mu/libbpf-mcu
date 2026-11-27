use std::{
    collections::BTreeMap,
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    time::SystemTime,
};

use anyhow::{Context, Result, ensure};
use mcu_image::{Mode, program_name, sha256_hex};
use mcu_index::{Deployment, Index, Member, bpf_path, image_paths, rv32_path};

pub fn snapshot(
    root: &Path,
    sources: &[PathBuf],
    modes: &[Mode],
) -> Result<BTreeMap<PathBuf, String>> {
    let mut inputs = sources.to_vec();
    inputs.extend(mcu_deps::sdk_files(&root.join("include-bpf"))?);
    if modes.contains(&Mode::Aot) || modes.contains(&Mode::Ebpf) {
        inputs.extend(mcu_deps::sdk_files(&root.join("include"))?);
    }
    inputs
        .into_iter()
        .map(|path| {
            let bytes =
                fs::read(&path).with_context(|| format!("read build input {}", path.display()))?;
            Ok((path, sha256_hex(&bytes)))
        })
        .collect()
}

pub fn remove(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("remove invalid output {}", path.display()))
        }
    }
}

fn mtime(path: &Path) -> Option<SystemTime> {
    path.metadata().ok()?.modified().ok()
}

fn fresh(output: &Path, inputs: &[&Path]) -> bool {
    let Some(produced) = mtime(output) else {
        return false;
    };
    inputs
        .iter()
        .all(|input| mtime(input).is_some_and(|time| time <= produced))
}

fn matching(file: &Path, other: &Path) -> bool {
    match (fs::read(file), fs::read(other)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn safe_dir(dir: &Path) -> Result<()> {
    if let Ok(meta) = dir.symlink_metadata() {
        ensure!(
            meta.is_dir() && !meta.file_type().is_symlink(),
            "invalid generated directory {}",
            dir.display()
        );
    }
    Ok(())
}

pub fn check_dirs(build: &Path, sources: &[PathBuf]) -> Result<()> {
    safe_dir(build)?;
    let inter = build.join("intermediates");
    safe_dir(&inter)?;
    for source in sources {
        let name = program_name(source)?;
        let program = build.join(name);
        let private = inter.join(name);
        for dir in [
            program.clone(),
            program.join("objects"),
            program.join("images"),
            private.clone(),
            private.join("report"),
        ] {
            safe_dir(&dir)?;
            if dir.exists() {
                for entry in fs::read_dir(&dir)? {
                    let entry = entry?;
                    ensure!(
                        !entry.file_type()?.is_symlink(),
                        "symlink in generated directory {}",
                        entry.path().display()
                    );
                }
            }
        }
    }
    Ok(())
}

fn check_member(member: Option<&Member>, program: &Path, expected: &str) -> Result<bool> {
    let matches = member.is_some_and(|member| member.load(program, expected).is_ok());
    if !matches {
        remove(&program.join(expected))?;
    }
    Ok(matches)
}

fn check_mode(row: &Deployment, program: &Path, name: &str) -> Result<bool> {
    let mode = row.name;
    if row.role != mode.role() || row.format != mode.format() {
        return Ok(false);
    }
    let (image, layout) = image_paths(mode);
    let mut valid = check_member(row.image.as_ref(), program, &image)?;
    valid &= check_member(row.layout.as_ref(), program, &layout)?;
    if mode == Mode::Aot {
        valid &= check_member(row.object.as_ref(), program, &rv32_path(name))?;
    }
    Ok(valid)
}

pub fn preflight(
    root: &Path,
    build: &Path,
    source: &Path,
    modes: &[Mode],
    tools: &super::Tools,
    force: bool,
) -> Result<()> {
    let name = program_name(source)?;
    let program = build.join(name);
    let private = build.join("intermediates").join(name);
    let index_path = program.join("index.toml");
    let bpf = program.join(bpf_path(name));
    let raw = private.join(format!("{name}_bpf.o"));
    let native = private.join(format!("{name}_rv32.raw.o"));
    let bpf_deps = mcu_deps::dependencies(
        &private.join("bpf.d"),
        root,
        source,
        &root.join("include-bpf"),
    );
    let bpf_fresh = bpf_deps.as_ref().is_ok_and(|deps| {
        let mut deps = deps.iter().map(PathBuf::as_path).collect::<Vec<_>>();
        deps.push(&tools.clang);
        fresh(&raw, &deps)
    });
    let mut valid = !force
        && bpf_fresh
        && fresh(&bpf, &[&raw, &tools.prevail, &tools.object])
        && matching(&raw, &bpf);
    if bpf_deps.is_err() || force {
        remove(&raw)?;
    }
    if !valid {
        remove(&bpf)?;
    }
    if let Ok(index) = Index::read(&program) {
        if mcu_report::verify(&program, &index).is_err() {
            remove(&program.join("report.md"))?;
        }
        if !matching(source, &program.join(format!("{name}.c"))) {
            valid = false;
            remove(&raw)?;
            remove(&native)?;
            remove(&program.join(format!("{name}.c")))?;
        }
        valid &= check_member(Some(&index.source), &program, &format!("{name}.c"))?;
        valid &= check_member(Some(&index.bpf), &program, &bpf_path(name))?;
        for row in &index.mode {
            if modes.contains(&row.name) {
                valid &= check_mode(row, &program, name)?;
            }
        }
        if valid && index.verify(&program).is_err() {
            for mode in modes {
                let (image, layout) = image_paths(*mode);
                remove(&program.join(image))?;
                remove(&program.join(layout))?;
            }
            valid = false;
        }
    } else {
        valid = false;
        // Without a trustworthy index the cached formal files have no byte identity.
        if index_path.exists() || program.join("report.md").exists() {
            for path in [&raw, &native, &bpf, &program.join("report.md")] {
                remove(path)?;
            }
        }
    }
    if force && (modes.contains(&Mode::Aot) || modes.contains(&Mode::Ebpf)) {
        remove(&native)?;
    }
    if !valid {
        remove(&index_path)?;
    }
    Ok(())
}

pub fn postflight(
    root: &Path,
    build: &Path,
    source: &Path,
    modes: &[Mode],
    execute: &mcu::Execute,
    inputs_unchanged: bool,
) -> Result<()> {
    let name = program_name(source)?;
    let program = build.join(name);
    let private = build.join("intermediates").join(name);
    let bpf = program.join(bpf_path(name));
    let raw = private.join(format!("{name}_bpf.o"));
    let deps = mcu_deps::dependencies(
        &private.join("bpf.d"),
        root,
        source,
        &root.join("include-bpf"),
    );
    let gate_current = deps
        .is_ok_and(|deps| fresh(&raw, &deps.iter().map(PathBuf::as_path).collect::<Vec<_>>()))
        && matching(&raw, &bpf)
        && execute.output_current(&bpf)
        && matching(source, &program.join(format!("{name}.c")));
    let mut stale = Vec::new();
    if gate_current && inputs_unchanged {
        let native = private.join(format!("{name}_rv32.raw.o"));
        let rv_deps = private.join("rv32.d");
        let native_current = mcu_deps::dependencies(&rv_deps, root, source, &root.join("include"))
            .is_ok_and(|deps| {
                fresh(
                    &native,
                    &deps.iter().map(PathBuf::as_path).collect::<Vec<_>>(),
                )
            });
        for &mode in modes {
            let (image, layout) = image_paths(mode);
            let current = [image, layout]
                .iter()
                .all(|path| execute.output_current(&program.join(path)))
                && (mode == Mode::Jit || native_current);
            if !current {
                stale.push(mode);
            }
        }
    }
    let index = Index::read(&program).and_then(|index| {
        ensure!(index.program == name, "wrong program identity");
        ensure!(
            index.mode.iter().map(|r| r.name).eq(modes.iter().copied()),
            "wrong built modes"
        );
        index.verify(&program)?;
        mcu_report::verify(&program, &index)?;
        Ok(())
    });
    if inputs_unchanged && gate_current && stale.is_empty() && index.is_ok() {
        return Ok(());
    }
    remove(&program.join("index.toml"))?;
    if !gate_current || !inputs_unchanged {
        for path in [
            format!("{name}.c"),
            bpf_path(name),
            rv32_path(name),
            "report.md".into(),
        ] {
            remove(&program.join(path))?;
        }
        for mode in Mode::ALL {
            let (image, layout) = image_paths(mode);
            remove(&program.join(image))?;
            remove(&program.join(layout))?;
        }
        if !inputs_unchanged {
            remove(&raw)?;
            remove(&private.join(format!("{name}_rv32.raw.o")))?;
        }
    }
    for mode in &stale {
        let (image, layout) = image_paths(*mode);
        remove(&program.join(image))?;
        remove(&program.join(layout))?;
    }
    ensure!(inputs_unchanged, "build inputs changed while Ninja ran");
    ensure!(gate_current, "{name}: no current PREVAIL-accepted object");
    ensure!(
        stale.is_empty(),
        "{name}: stale deployment outputs {stale:?}"
    );
    index
}
