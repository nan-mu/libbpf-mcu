use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use mcu_image::{Layout, Mode, TargetLayout, sha256_hex, verify_aot, write_atomic};
use object::Object;
use serde::{Deserialize, Serialize};

pub const SCHEMA: &str = "libbpf-mcu.program-index.v3";

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
}

pub fn contained(root: &Path, relative: &str) -> Result<PathBuf> {
    let path = Path::new(relative);
    ensure!(
        !relative.is_empty()
            && !relative.contains(['\\', ':'])
            && !relative
                .split('/')
                .any(|part| matches!(part, "" | "." | ".."))
            && path.components().all(|c| matches!(c, Component::Normal(_))),
        "invalid relative path {relative:?}"
    );
    let mut absolute = root.to_owned();
    for part in path.components() {
        absolute.push(part);
        ensure!(
            !absolute.symlink_metadata()?.file_type().is_symlink(),
            "symlink is not an artifact: {}",
            absolute.display()
        );
    }
    ensure!(absolute.is_file(), "expected file: {}", absolute.display());
    Ok(absolute)
}

impl Member {
    pub fn new(root: &Path, path: String) -> Result<Self> {
        let bytes = fs::read(contained(root, &path)?)?;
        Ok(Self {
            path,
            size_bytes: bytes.len() as u64,
            sha256: sha256_hex(&bytes),
        })
    }

    pub fn load(&self, root: &Path, expected: &str) -> Result<Vec<u8>> {
        ensure!(
            self.path == expected,
            "invalid index path, expected {expected}"
        );
        let bytes = fs::read(contained(root, expected)?)?;
        ensure!(
            self.size_bytes == bytes.len() as u64 && self.sha256 == sha256_hex(&bytes),
            "size or SHA-256 mismatch: {expected}"
        );
        Ok(bytes)
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    pub name: Mode,
    pub role: String,
    pub format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<Member>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layout: Option<Member>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixup_sites: Option<Vec<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object: Option<Member>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elf: Option<Member>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Index {
    pub schema: String,
    pub program: String,
    pub source: Member,
    pub bpf: Member,
    #[serde(default)]
    pub mode: Vec<Deployment>,
}

fn relocatable(bytes: &[u8], arch: object::Architecture) -> Result<()> {
    let elf = object::File::parse(bytes)?;
    ensure!(
        elf.format() == object::BinaryFormat::Elf
            && elf.architecture() == arch
            && elf.is_little_endian()
            && elf.kind() == object::ObjectKind::Relocatable,
        "expected a little-endian relocatable {arch:?} ELF"
    );
    Ok(())
}

impl Index {
    pub fn read(root: &Path) -> Result<Self> {
        ensure!(
            !root.symlink_metadata()?.file_type().is_symlink(),
            "program directory is a symlink"
        );
        let file = fs::read_to_string(contained(root, "index.toml")?)?;
        let index: Self = toml::from_str(&file)?;
        ensure!(index.schema == SCHEMA, "expected {SCHEMA}");
        ensure!(
            !index.program.is_empty()
                && !index.program.contains(['/', '\\', ':', '.'])
                && !index.program.chars().any(char::is_control),
            "invalid program identifier"
        );
        let mut modes = BTreeSet::new();
        ensure!(
            index.mode.iter().all(|row| modes.insert(row.name)),
            "duplicate deployment mode"
        );
        Ok(index)
    }

    pub fn generate(root: &Path, modes: &[Mode]) -> Result<Self> {
        let program = directory_name(root)?.to_owned();
        let mut mode = Vec::new();
        for &name in modes {
            let paths = image_paths(name);
            let layout = Layout::read(&contained(root, &paths.1)?)?;
            mode.push(Deployment {
                name,
                role: name.role().into(),
                format: name.format().into(),
                fixup_sites: Some(layout.sites()),
                image: Some(Member::new(root, paths.0)?),
                layout: Some(Member::new(root, paths.1)?),
                object: if name == Mode::Aot {
                    Some(Member::new(root, rv32_path(&program))?)
                } else {
                    None
                },
                elf: None,
            });
        }
        let index = Self {
            schema: SCHEMA.to_owned(),
            source: Member::new(root, format!("{program}.c"))?,
            bpf: Member::new(root, bpf_path(&program))?,
            mode,
            program,
        };
        index.verify(root)?;
        Ok(index)
    }

    pub fn write(&self, root: &Path) -> Result<()> {
        write_atomic(&root.join("index.toml"), toml::to_string(self)?.as_bytes())
    }

    pub fn portable(&self, root: &Path, mode: Mode) -> Result<(Vec<u8>, Layout, &[u32])> {
        let row = self
            .mode
            .iter()
            .find(|row| row.name == mode)
            .context("missing portable deployment")?;
        ensure!(
            row.role == mode.role()
                && row.format == mode.format()
                && row.elf.is_none()
                && row.object.is_some() == (mode == Mode::Aot),
            "invalid role, format or members for {mode}"
        );
        let paths = image_paths(mode);
        let bytes = row
            .image
            .as_ref()
            .context("missing image")?
            .load(root, &paths.0)?;
        let layout: Layout = serde_json::from_slice(
            &row.layout
                .as_ref()
                .context("missing layout")?
                .load(root, &paths.1)?,
        )?;
        let sites = row
            .fixup_sites
            .as_deref()
            .context("missing index fixup sites")?;
        layout.validate(&self.program, mode, &bytes, sites)?;
        Ok((bytes, layout, sites))
    }

    pub fn verify(&self, root: &Path) -> Result<()> {
        let program = &self.program;
        self.source.load(root, &format!("{program}.c"))?;
        let bpf = self.bpf.load(root, &bpf_path(program))?;
        relocatable(&bpf, object::Architecture::Bpf)?;
        let mut aot = None;
        let mut ebpf = None;
        for row in &self.mode {
            if row.role == "xpost_container" {
                self.verify_container(root, row)?;
                continue;
            }
            let (image, layout, _) = self
                .portable(root, row.name)
                .with_context(|| format!("{program}/{}", row.name))?;
            match row.name {
                Mode::Aot => {
                    let object = row
                        .object
                        .as_ref()
                        .context("AOT reference object missing")?;
                    verify_aot(&object.load(root, &rv32_path(program))?, &layout)?;
                    aot = Some(layout.maps);
                }
                Mode::Ebpf => {
                    let names = layout
                        .maps
                        .iter()
                        .map(|map| map.name.as_str())
                        .collect::<Vec<_>>();
                    let (_, expected) = mcu_bpf::map_indexed(&bpf, &names)?;
                    ensure!(
                        image == expected,
                        "{program}/ebpf differs from map-indexed eBPF"
                    );
                    ebpf = Some(layout.maps);
                }
                Mode::Jit => {}
            }
        }
        if let (Some(aot), Some(ebpf)) = (aot, ebpf) {
            ensure!(
                aot == ebpf,
                "{program}/ebpf map order or offsets differ from AOT"
            );
        }
        Ok(())
    }

    fn verify_container(&self, root: &Path, row: &Deployment) -> Result<()> {
        ensure!(
            row.format == "xpost-compact-elf-v0"
                && row.image.is_none()
                && row.layout.is_none()
                && row.fixup_sites.is_none()
                && row.object.is_some() == (row.name == Mode::Aot),
            "invalid legacy container row"
        );
        if let Some(reference) = &row.object {
            relocatable(
                &reference.load(root, &rv32_path(&self.program))?,
                object::Architecture::Riscv32,
            )?;
        }
        let suffix = if row.name == Mode::Aot {
            "aot"
        } else {
            row.name.name()
        };
        let path = format!("containers/{}-vm-{suffix}.elf", self.program);
        let bytes = row
            .elf
            .as_ref()
            .context("missing container")?
            .load(root, &path)?;
        let mut reader = bytes.as_slice();
        let xpost_elf::ScanOutcome::Ok(parsed) = xpost_elf::scan_at(&mut reader, 0) else {
            anyhow::bail!("invalid Compact ELF {path}");
        };
        ensure!(
            parsed.file_len == bytes.len(),
            "container extent differs from file"
        );
        Ok(())
    }

    pub fn bind(&self, root: &Path, mode: Mode, target: TargetLayout) -> Result<Vec<u8>> {
        let (image, layout, sites) = self.portable(root, mode)?;
        layout.bind(&image, sites, target)
    }
}

pub fn bpf_path(name: &str) -> String {
    format!("objects/{name}_bpf.o")
}
pub fn rv32_path(name: &str) -> String {
    format!("objects/{name}_rv32.o")
}
pub fn image_paths(mode: Mode) -> (String, String) {
    (format!("images/{mode}.bin"), format!("images/{mode}.json"))
}

pub fn directory_name(path: &Path) -> Result<&str> {
    path.file_name()
        .and_then(|name| name.to_str())
        .context("missing program directory name")
}

pub fn verify_tree(root: &Path) -> Result<Vec<Index>> {
    if root.join("index.toml").is_file() {
        let index = Index::read(root)?;
        index.verify(root)?;
        return Ok(vec![index]);
    }
    let mut indexes = Vec::new();
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.join("index.toml").is_file() {
            let index = Index::read(&path)?;
            ensure!(
                index.program == directory_name(&path)?,
                "program identity differs from directory"
            );
            index.verify(&path)?;
            indexes.push(index);
        }
    }
    ensure!(
        !indexes.is_empty(),
        "no program indexes under {}",
        root.display()
    );
    indexes.sort_by(|a, b| a.program.cmp(&b.program));
    Ok(indexes)
}
