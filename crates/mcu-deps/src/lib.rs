use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};

/// Parse the Make depfile format emitted by Clang with a single -MQ target.
pub fn dependencies(
    depfile: &Path,
    work: &Path,
    source: &Path,
    sdk: &Path,
) -> Result<Vec<PathBuf>> {
    let text =
        fs::read_to_string(depfile).with_context(|| format!("read {}", depfile.display()))?;
    let sdk = sdk.canonicalize()?;
    let source = source.canonicalize()?;
    let mut chars = text.chars().peekable();
    let mut target = true;
    let mut tokens = Vec::new();
    let mut token = String::new();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                let next = chars.next().context("trailing escape in depfile")?;
                if next != '\n' {
                    token.push(next);
                }
            }
            ':' if target && chars.peek().is_some_and(|c| c.is_ascii_whitespace()) => {
                target = false;
                token.clear();
            }
            '$' if chars.peek() == Some(&'$') => {
                chars.next();
                token.push('$');
            }
            ' ' | '\t' | '\n' | '\r' => {
                if !target && !token.is_empty() {
                    tokens.push(std::mem::take(&mut token));
                }
            }
            _ => token.push(ch),
        }
    }
    if !token.is_empty() {
        tokens.push(token);
    }
    ensure!(!target, "missing depfile target");
    let mut paths = Vec::new();
    for token in tokens {
        let path = work
            .join(&token)
            .canonicalize()
            .with_context(|| format!("resolve dependency {token:?}"))?;
        ensure!(
            path == source || path.starts_with(&sdk),
            "undeclared dependency {} outside target SDK {}",
            path.display(),
            sdk.display()
        );
        ensure!(
            path.is_file(),
            "dependency is not a file: {}",
            path.display()
        );
        paths.push(path);
    }
    ensure!(
        paths.contains(&source),
        "depfile is missing the compilation source"
    );
    Ok(paths)
}

pub fn sdk_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        ensure!(
            !kind.is_symlink(),
            "SDK contains a symlink: {}",
            entry.path().display()
        );
        if kind.is_dir() {
            files.extend(sdk_files(&entry.path())?);
        }
        if kind.is_file() {
            files.push(entry.path());
        }
    }
    files.sort();
    Ok(files)
}
