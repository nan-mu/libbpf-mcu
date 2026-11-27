mod graph;

pub use graph::{Execute, Generate, Tools};
pub use mcu_image::Mode;

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
