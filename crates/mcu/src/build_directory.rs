use std::{
    env, fs,
    io::ErrorKind,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Component, Path, PathBuf, absolute},
    process::Command,
};

use anyhow::{Context, Result, ensure};

const OWNER: &str = ".mcu-build";

// Resolve each existing component before processing "..", including aliases
// such as /tmp on macOS. The tail may be a directory yet to be created.
fn resolve(path: &Path) -> Result<PathBuf> {
    let mut resolved = PathBuf::new();
    for component in absolute(path)?.components() {
        if component == Component::ParentDir {
            resolved.pop();
        } else {
            resolved.push(component);
            match resolved.symlink_metadata() {
                Ok(_) => resolved = resolved.canonicalize()?,
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(resolved)
}

fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let result = Command::new("git")
        .current_dir(root)
        .env_remove("GIT_DIR")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .args(args)
        .output()?;
    ensure!(
        result.status.success(),
        "cannot inspect checkout for build directory safety: {}",
        String::from_utf8_lossy(&result.stderr).trim()
    );
    Ok(result.stdout)
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

pub fn select(root: &Path, selected: Option<&Path>) -> Result<PathBuf> {
    let default = root.join("build");
    let requested = selected.unwrap_or(&default);
    ensure!(
        !requested
            .symlink_metadata()
            .is_ok_and(|entry| entry.is_symlink()),
        "build directory is a symlink: {}",
        requested.display()
    );
    let path = resolve(requested)?;
    ensure!(
        !root.starts_with(&path),
        "build directory would contain the checkout: {}",
        path.display()
    );
    let git_dirs = git(
        root,
        &[
            "rev-parse",
            "--path-format=absolute",
            "--git-dir",
            "--git-common-dir",
        ],
    )?;
    for metadata in git_dirs
        .strip_suffix(b"\n")
        .unwrap_or(&git_dirs)
        .split(|b| *b == b'\n')
    {
        let metadata = resolve(Path::new(std::ffi::OsStr::from_bytes(metadata)))?;
        ensure!(
            !overlaps(&path, &metadata),
            "build directory overlaps Git metadata: {}",
            path.display()
        );
    }
    ensure!(
        !path.components().any(|part| part.as_os_str() == ".git"),
        "build directory overlaps Git metadata: {}",
        path.display()
    );
    let tracked = git(root, &["ls-files", "-z"])?;
    for entry in tracked
        .split(|b| *b == b'\0')
        .filter(|entry| !entry.is_empty())
    {
        let name = entry.split(|b| *b == b'/').next().unwrap();
        ensure!(
            !path.starts_with(root.join(std::ffi::OsStr::from_bytes(name))),
            "build directory overlaps checkout content: {}",
            path.display()
        );
    }
    let cargo_targets = [
        env::var_os("CARGO_TARGET_DIR"),
        env::var_os("CARGO_BUILD_TARGET_DIR"),
    ];
    for target in cargo_targets
        .into_iter()
        .flatten()
        .map(PathBuf::from)
        .chain([root.join("target")])
    {
        // The nested Cargo command runs from the checkout.
        ensure!(
            !overlaps(&path, &resolve(&root.join(target))?),
            "build directory overlaps the Cargo target directory: {}",
            path.display()
        );
    }
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")));
    if let Some(home) = cargo_home {
        ensure!(
            !overlaps(&path, &resolve(&root.join(home))?),
            "build directory overlaps Cargo home: {}",
            path.display()
        );
    }
    check_containing_output(&path)?;
    Ok(path)
}

// A single marker identifies a dedicated output root. Binding it to the
// checkout and directory identity prevents a copied graph or marker from
// authorizing replacement or deletion of another directory.
fn owner(root: &Path, metadata: &fs::Metadata) -> Vec<u8> {
    let mut value = format!(
        "mcu build directory v1\n{}:{}\n",
        metadata.dev(),
        metadata.ino()
    )
    .into_bytes();
    value.extend_from_slice(root.as_os_str().as_bytes());
    value
}

fn check_containing_output(path: &Path) -> Result<()> {
    ensure!(
        !path
            .ancestors()
            .skip(1)
            .any(|parent| parent.join(OWNER).symlink_metadata().is_ok()),
        "build directory is inside another build tree: {}",
        path.display()
    );
    Ok(())
}

fn ownership(root: &Path, path: &Path) -> Result<Option<bool>> {
    check_containing_output(path)?;
    let metadata = match path.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        metadata.is_dir(),
        "invalid build directory: {}",
        path.display()
    );
    let marker = path.join(OWNER);
    if let Ok(entry) = marker.symlink_metadata()
        && entry.is_file()
        && fs::read(&marker)? == owner(root, &metadata)
    {
        return Ok(Some(true));
    }
    ensure!(
        fs::read_dir(path)?.next().is_none(),
        "build directory is nonempty and is not owned by this checkout: {}",
        path.display()
    );
    Ok(Some(false))
}

pub fn claim(root: &Path, path: &Path) -> Result<()> {
    match ownership(root, path)? {
        Some(true) => {
            for name in ["build.ninja", ".ninja_log", ".ninja_deps"] {
                let file = path.join(name);
                match file.symlink_metadata() {
                    Ok(entry) => ensure!(
                        entry.is_file() && entry.nlink() == 1,
                        "invalid generated build file: {}",
                        file.display()
                    ),
                    Err(error) if error.kind() == ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            return Ok(());
        }
        Some(false) => {}
        None => fs::create_dir(path)?,
    }
    mcu_image::write_atomic(&path.join(OWNER), &owner(root, &path.symlink_metadata()?))
}

fn check_clean_tree(path: &Path) -> Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        ensure!(
            entry.file_name() != ".git" && entry.file_name() != "CACHEDIR.TAG",
            "build directory contains Git metadata or a cache: {}",
            entry.path().display()
        );
        if entry.file_type()?.is_dir() {
            check_clean_tree(&entry.path())?;
        }
    }
    Ok(())
}

pub fn clean(root: &Path, path: &Path) -> Result<()> {
    if ownership(root, path)? == Some(true) {
        check_clean_tree(path)?;
        fs::remove_dir_all(path)
            .with_context(|| format!("clean build directory {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn output_selection_protects_an_isolated_checkout_and_its_aliases() {
        // Build and clean use the same selector. Use an isolated Git checkout
        // so an erroneous acceptance cannot point either action at real sources.
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().canonicalize().unwrap();
        let root = parent.join("test checkout");
        fs::create_dir(&root).unwrap();
        git(&root, &["init", "--quiet"]).unwrap();
        for name in ["crates", "experiments", "include", "tests", "docs"] {
            let protected = root.join(name);
            fs::create_dir(&protected).unwrap();
            fs::write(protected.join("tracked"), name).unwrap();
            git(&root, &["add", "--", name]).unwrap();
            assert!(select(&root, Some(&protected)).is_err());
            assert!(select(&root, Some(&protected.join("new"))).is_err());
            assert_eq!(fs::read_to_string(protected.join("tracked")).unwrap(), name);
        }
        let alias = parent.join("experiment alias");
        symlink(root.join("experiments"), &alias).unwrap();
        for bad in [
            root.clone(),
            parent.clone(),
            root.join(".git"),
            root.join(".git/new"),
            root.join("crates/../experiments"),
            root.join("target/cache"),
            alias.clone(),
            alias.join("child"),
        ] {
            assert!(select(&root, Some(&bad)).is_err(), "{bad:?}");
        }
        let default = select(&root, None).unwrap();
        assert_eq!(default, root.join("build"));
        claim(&root, &default).unwrap();
        // Simulate the failure of a first build before a Ninja graph exists.
        claim(&root, &default).unwrap();
        clean(&root, &default).unwrap();
        assert!(!default.exists());

        fs::create_dir(&default).unwrap();
        fs::write(default.join("unrelated"), "keep").unwrap();
        assert!(claim(&root, &default).is_err());
        assert!(clean(&root, &default).is_err());
        assert_eq!(
            fs::read_to_string(default.join("unrelated")).unwrap(),
            "keep"
        );
    }
}
