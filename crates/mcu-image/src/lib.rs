use std::{fmt, fs, io::Write, path::Path, str::FromStr};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Mode {
    #[serde(rename = "llvm-aot")]
    Aot,
    #[serde(rename = "jit")]
    Jit,
    #[serde(rename = "ebpf")]
    Ebpf,
}

impl Mode {
    pub const ALL: [Self; 3] = [Self::Aot, Self::Jit, Self::Ebpf];

    pub fn name(self) -> &'static str {
        match self {
            Self::Aot => "llvm-aot",
            Self::Jit => "jit",
            Self::Ebpf => "ebpf",
        }
    }

    pub fn format(self) -> &'static str {
        match self {
            Self::Aot => "rv32imc-le",
            Self::Jit => "rv32im-le",
            Self::Ebpf => "rbpf-map-index-le",
        }
    }

    pub fn role(self) -> &'static str {
        match self {
            Self::Aot | Self::Jit => "native_image",
            Self::Ebpf => "interpreter_image",
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Mode {
    type Err = anyhow::Error;

    fn from_str(name: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|mode| mode.name() == name)
            .with_context(|| format!("unknown deployment mode {name:?}"))
    }
}

/// Replace a file atomically within the file's parent directory.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut output = tempfile::NamedTempFile::new_in(dir)
        .with_context(|| format!("write {}", path.display()))?;
    output.write_all(bytes)?;
    output.persist(path)?;
    Ok(())
}

pub fn write_if_changed(path: &Path, bytes: &[u8]) -> Result<()> {
    if fs::read(path).as_deref().ok() != Some(bytes) {
        write_atomic(path, bytes)?;
    }
    Ok(())
}

pub fn program_name(path: &Path) -> Result<&str> {
    let name = path
        .file_stem()
        .and_then(|name| name.to_str())
        .context("missing program stem")?;
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        bail!("invalid program stem {name:?}");
    }
    Ok(name)
}

pub fn linker_script(base: u32, length: u32, helper: u32) -> String {
    include_str!("../../../linker/rv32imc.ld")
        .replace("@BASE@", &base.to_string())
        .replace("@LENGTH@", &length.to_string())
        .replace("@HELPER@", &helper.to_string())
}

mod portable;
pub use portable::*;

mod elf;
pub use elf::*;
