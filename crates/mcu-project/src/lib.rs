use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub const LLVM_BIN_DIRS: &[&str] = &["/opt/homebrew/opt/llvm/bin", "/usr/local/opt/llvm/bin"];

pub fn preferred_clang() -> PathBuf {
    LLVM_BIN_DIRS
        .iter()
        .map(|dir| Path::new(dir).join("clang"))
        .find(|path| {
            path.metadata().is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
        .unwrap_or_else(|| PathBuf::from("clang"))
}

#[derive(Deserialize, Serialize)]
pub struct Tools {
    pub clang: PathBuf,
    pub lld: PathBuf,
    pub objdump: PathBuf,
    pub ninja: PathBuf,
    pub prevail: PathBuf,
    pub object: PathBuf,
    pub jit: PathBuf,
}

impl Tools {
    const GRAPH_PREFIX: &str = "# Tool paths: ";

    pub fn inputs(&self) -> [(&'static str, &Path); 7] {
        [
            ("clang", &self.clang),
            ("lld", &self.lld),
            ("objdump", &self.objdump),
            ("ninja", &self.ninja),
            ("prevail", &self.prevail),
            ("object", &self.object),
            ("jit", &self.jit),
        ]
    }

    pub fn graph_comment(&self) -> Result<String> {
        Ok(format!(
            "{}{}",
            Self::GRAPH_PREFIX,
            serde_json::to_string(self)?
        ))
    }

    pub fn from_graph(graph: &str) -> Result<Self> {
        let tools = graph
            .lines()
            .find_map(|line| line.strip_prefix(Self::GRAPH_PREFIX))
            .context("the build graph is missing the resolved tool paths")?;
        Ok(serde_json::from_str(tools)?)
    }
}

/// Discover production programs, independently of diagnostics and fixtures.
pub fn program_sources(root: &std::path::Path) -> anyhow::Result<Vec<std::path::PathBuf>> {
    let mut paths = Vec::new();
    for experiment in std::fs::read_dir(root.join("experiments"))? {
        let experiment = experiment?;
        if !experiment.file_type()?.is_dir() {
            continue;
        }
        for source in std::fs::read_dir(experiment.path())? {
            let source = source?;
            if source.file_type()?.is_file()
                && source.path().extension().is_some_and(|ext| ext == "c")
            {
                paths.push(source.path());
            }
        }
    }
    paths.sort();
    Ok(paths)
}

/// Hold a filesystem lock while the selected output root is read or changed.
pub fn lock_build(build: &std::path::Path) -> anyhow::Result<std::fs::File> {
    let parent = build
        .parent()
        .ok_or_else(|| anyhow::anyhow!("build root has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let directory = std::fs::File::open(parent)?;
    fs2::FileExt::lock_exclusive(&directory)?;
    Ok(directory)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    // Compare with the release program IDs independently of file discovery.
    #[test]
    fn discovers_only_the_twelve_production_programs() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let paths = super::program_sources(&root).unwrap();
        let mut names = paths
            .iter()
            .map(|path| path.file_stem().unwrap().to_str().unwrap())
            .collect::<Vec<_>>();
        names.sort_unstable();
        assert_eq!(
            names,
            [
                "bsort",
                "case_mark",
                "case_swap",
                "copy",
                "firewall",
                "fletcher32",
                "just_drop",
                "just_tx",
                "log2",
                "noop",
                "prime",
                "strcmp"
            ]
        );
        for path in paths {
            assert!(
                path.parent().unwrap().join("README.md").is_file(),
                "{}",
                path.display()
            );
        }
    }
}
