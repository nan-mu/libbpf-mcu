use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::Path,
    process::{Command, Stdio},
};

use anyhow::{Context, Result, bail, ensure};
use mcu_image::{Layout, Mode, program_name, sha256_hex, write_atomic};
use mcu_index::{Deployment, Index, Member, bpf_path, contained, image_paths, rv32_path};
use serde::{Deserialize, Serialize};

const SCHEMA: &str = "libbpf-mcu.release.v1";
const LEDGER: &str = "release.json";

#[derive(Deserialize, Eq, PartialEq, Serialize)]
struct ArchiveMode {
    #[serde(flatten)]
    deployment: Deployment,
    entry_offset: u32,
    image_bytes: u64,
    maps: usize,
}

#[derive(Deserialize, Eq, PartialEq, Serialize)]
struct Archive {
    program: String,
    archive: String,
    sha256: String,
    size_bytes: u64,
    members: Vec<Member>,
    modes: Vec<ArchiveMode>,
}

#[derive(Deserialize, Serialize)]
struct Ledger {
    schema: String,
    commit: String,
    toolchain: BTreeMap<String, serde_json::Value>,
    archives: Vec<Archive>,
}

fn programs(root: &Path) -> Result<BTreeSet<String>> {
    let sources = mcu_project::program_sources(root)?;
    let names = sources
        .iter()
        .map(|path| Ok(program_name(path)?.to_owned()))
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        names.len() == 12 && sources.len() == names.len(),
        "expected the twelve distinct release programs"
    );
    Ok(names)
}

fn wanted(program: &str) -> BTreeSet<String> {
    let mut files = BTreeSet::from([
        "index.toml".into(),
        "report.md".into(),
        format!("{program}.c"),
        bpf_path(program),
        rv32_path(program),
    ]);
    for mode in Mode::ALL {
        let (image, layout) = image_paths(mode);
        files.extend([image, layout]);
    }
    files
}

fn members(root: &Path) -> Result<BTreeSet<String>> {
    let mut paths = BTreeSet::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let filename = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("non-UTF-8 program files"))?;
        if entry.file_type()?.is_file() {
            paths.insert(filename);
        } else if entry.file_type()?.is_dir() && matches!(filename.as_str(), "objects" | "images") {
            for child in fs::read_dir(entry.path())? {
                let child = child?;
                ensure!(
                    child.file_type()?.is_file(),
                    "invalid program file {}",
                    child.path().display()
                );
                let name = child
                    .file_name()
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("non-UTF-8 program file"))?;
                paths.insert(format!("{filename}/{name}"));
            }
        } else {
            bail!("invalid archive member {}", entry.path().display());
        }
    }
    Ok(paths)
}

fn require_program(root: &Path, program: &str) -> Result<Index> {
    let index = Index::read(root).with_context(|| format!("read {program} index"))?;
    ensure!(index.program == program, "index has wrong program name");
    index
        .verify(root)
        .with_context(|| format!("verify {program}"))?;
    mcu_report::verify(root, &index).with_context(|| format!("verify {program} report"))?;
    ensure!(
        index.mode.len() == 3 && index.mode.iter().all(|row| row.role == row.name.role()),
        "{program} must contain all three portable modes"
    );
    let actual = members(root)?;
    let wanted = wanted(program);
    ensure!(
        actual == wanted,
        "{program}: missing {:?}, extra {:?}",
        wanted.difference(&actual),
        actual.difference(&wanted)
    );
    Ok(index)
}

fn archiver() -> Result<Command> {
    for name in ["7zz", "7z"] {
        if let Some(path) = env::var_os("PATH")
            .into_iter()
            .flat_map(|value| env::split_paths(&value).collect::<Vec<_>>())
            .map(|prefix| prefix.join(name))
            .find(|path| path.is_file())
        {
            return Ok(Command::new(path));
        }
    }
    bail!("7zz or 7z is required for release archives")
}

fn stdout(command: &mut Command) -> Result<String> {
    let output = command
        .output()
        .with_context(|| format!("run {command:?}"))?;
    ensure!(
        output.status.success(),
        "{command:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}

fn inspect(listing: &str, program: &str) -> Result<()> {
    let mut seen = BTreeSet::new();
    let mut files = BTreeSet::new();
    let valid = wanted(program);
    let listing = listing.replace("\r\n", "\n");
    for record in listing.trim().split("\n\n") {
        let mut fields = BTreeMap::new();
        for (k, v) in record.lines().filter_map(|line| line.split_once(" = ")) {
            ensure!(fields.insert(k, v).is_none(), "ambiguous archive listing");
        }
        let name = *fields.get("Path").context("missing archive member path")?;
        ensure!(seen.insert(name), "duplicate archive path {name:?}");
        let attributes = fields
            .get("Attributes")
            .context("missing archive member attributes")?;
        let mut attrs = attributes.split_whitespace();
        let windows = attrs.next().context("empty archive attributes")?;
        let directory = fields.get("Folder") == Some(&"+") || windows.starts_with('D');
        ensure!(
            !windows.contains('L')
                && !fields.contains_key("Symbolic Link")
                && !fields.contains_key("Hard Link")
                && attrs
                    .next()
                    .is_none_or(|mode| mode.starts_with(if directory { 'd' } else { '-' })),
            "archive contains a link or special member: {name:?}"
        );
        if directory {
            ensure!(
                matches!(name, "images" | "objects"),
                "unexpected archive directory {name:?}"
            );
        } else {
            ensure!(valid.contains(name), "unexpected archive member {name:?}");
            files.insert(name.to_owned());
        }
    }
    ensure!(files == valid, "archive member list is incomplete");
    Ok(())
}

fn extract(archive: &Path, root: &Path, program: &str) -> Result<Index> {
    let listing = stdout(
        archiver()?
            .args(["l", "-t7z", "-slt", "-ba", "-sccUTF-8", "--"])
            .arg(archive),
    )?;
    inspect(&listing, program)?;
    fs::create_dir(root)?;
    stdout(
        archiver()?
            .args(["x", "-t7z", "-bd", "-y"])
            .arg(format!("-o{}", root.display()))
            .arg("--")
            .arg(archive),
    )?;
    require_program(root, program)
}

fn collect(
    archives: &Path,
    unpacked: &Path,
    names: &BTreeSet<String>,
    build: Option<&Path>,
    expected: Option<&[Archive]>,
) -> Result<Vec<Archive>> {
    let files = fs::read_dir(archives)?
        .filter_map(|entry| match entry {
            Ok(entry)
                if entry
                    .path()
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("7z")) =>
            {
                Some(
                    entry
                        .file_name()
                        .into_string()
                        .map_err(|_| anyhow::anyhow!("invalid archive filename")),
                )
            }
            Ok(_) => None,
            Err(error) => Some(Err(error.into())),
        })
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        files == names.iter().map(|name| format!("{name}.7z")).collect(),
        "archive directory differs from program matrix"
    );
    if let Some(build) = build {
        let indexes = mcu_index::verify_tree(build)?;
        ensure!(
            indexes
                .into_iter()
                .map(|i| i.program)
                .collect::<BTreeSet<_>>()
                == *names,
            "build differs from release matrix"
        );
    }
    fs::create_dir(unpacked)?;
    let mut delivered = Vec::new();
    for program in names {
        let filename = format!("{program}.7z");
        let archive = contained(archives, &filename)?;
        let data = fs::read(&archive)?;
        let digest = sha256_hex(&data);
        let prior = expected
            .map(|rows| {
                rows.iter()
                    .find(|row| &row.program == program)
                    .context("program missing from ledger")
            })
            .transpose()?;
        if let Some(prior) = prior {
            ensure!(
                prior.archive == filename
                    && prior.sha256 == digest
                    && prior.size_bytes == data.len() as u64,
                "{program}: archive digest or length mismatch"
            );
        }
        let root = unpacked.join(program);
        let index =
            extract(&archive, &root, program).with_context(|| format!("validate {filename}"))?;
        ensure!(
            fs::read(&archive)? == data,
            "archive changed while verifying {filename}"
        );
        let members = wanted(program)
            .into_iter()
            .map(|path| Member::new(&root, path))
            .collect::<Result<Vec<_>>>()?;
        if let Some(build) = build {
            for item in &members {
                item.load(&build.join(program), &item.path)
                    .with_context(|| format!("compare {program} to build"))?;
            }
        }
        let modes = index
            .mode
            .into_iter()
            .map(|deployment| {
                let file = deployment.layout.as_ref().context("missing layout")?;
                let doc = Layout::read(&root.join(&file.path))?;
                let image_bytes = deployment
                    .image
                    .as_ref()
                    .context("missing image")?
                    .size_bytes;
                Ok(ArchiveMode {
                    deployment,
                    image_bytes,
                    entry_offset: doc.entry_offset,
                    maps: doc.maps.len(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let actual = Archive {
            program: program.clone(),
            archive: filename,
            sha256: digest,
            size_bytes: data.len() as u64,
            members,
            modes,
        };
        if let Some(prior) = prior {
            ensure!(
                prior == &actual,
                "{program}: release ledger differs from verified archives"
            );
        }
        println!("verified {}", actual.archive);
        delivered.push(actual);
    }
    Ok(delivered)
}

fn clean_commit(root: &Path, temp: &Path) -> Result<String> {
    let git = |args: &[&str]| {
        stdout(
            Command::new("git")
                .current_dir(root)
                .env("GIT_OPTIONAL_LOCKS", "0")
                .env("TMPDIR", temp)
                .args(args),
        )
    };
    ensure!(
        git(&["status", "--porcelain"])?.is_empty(),
        "prepare release from a clean checkout"
    );
    Ok(git(&["rev-parse", "HEAD"])?.trim().to_owned())
}

fn publish_local(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir(destination)
        .with_context(|| format!("create new directory {}", destination.display()))?;
    let deliver = (|| {
        for file in fs::read_dir(source)? {
            let file = file?;
            fs::copy(file.path(), destination.join(file.file_name()))?;
        }
        Ok(())
    })();
    if deliver.is_err() {
        fs::remove_dir_all(destination)?;
    }
    deliver
}

pub fn prepare(root: &Path, build: &Path, destination: &Path) -> Result<()> {
    let build = build.canonicalize()?;
    let _lock = mcu_project::lock_build(&build)?;
    ensure!(
        !destination.exists() && !destination.starts_with(&build),
        "archive directory must be new and outside the build root"
    );
    let temp = tempfile::tempdir()?;
    let commit = clean_commit(root, temp.path())?;
    let names = programs(root)?;
    let stage = temp.path().join("archives");
    fs::create_dir(&stage)?;
    for program in &names {
        let path = build.join(program);
        let index = require_program(&path, program)?;
        let source = mcu_project::program_sources(root)?
            .into_iter()
            .find(|p| program_name(p).ok() == Some(program))
            .context("missing source")?;
        ensure!(
            index.source.sha256 == sha256_hex(&fs::read(source)?),
            "{program}: build differs from checkout source"
        );
        let mut command = archiver()?;
        command
            .current_dir(path)
            .args(["a", "-t7z", "-bd", "-mtm=off", "--"])
            .arg(stage.join(format!("{program}.7z")))
            .arg(".")
            .stdin(Stdio::null());
        stdout(&mut command)?;
    }
    let archives = collect(
        &stage,
        &temp.path().join("unpacked"),
        &names,
        Some(&build),
        None,
    )?;
    let graph = fs::read_to_string(build.join("build.ninja"))?;
    let tools = mcu_project::Tools::from_graph(&graph)?;
    let mut toolchain = BTreeMap::from([
        (
            "build_graph_sha256".to_owned(),
            sha256_hex(graph.as_bytes()).into(),
        ),
        (
            "rustc".to_owned(),
            stdout(
                Command::new("rustc")
                    .env("TMPDIR", temp.path())
                    .arg("--version"),
            )?
            .trim()
            .into(),
        ),
        (
            "cargo".to_owned(),
            stdout(
                Command::new("cargo")
                    .env("TMPDIR", temp.path())
                    .arg("--version"),
            )?
            .trim()
            .into(),
        ),
        (
            "7z".to_owned(),
            stdout(archiver()?.arg("i"))?
                .trim()
                .lines()
                .next()
                .unwrap_or_default()
                .into(),
        ),
    ]);
    for (name, path) in tools.inputs() {
        toolchain.insert(name.to_owned(), serde_json::json!({
            "path": path,
            "sha256": sha256_hex(&fs::read(path).with_context(|| format!("hash resolved tool {}", path.display()))?),
        }));
    }
    ensure!(
        clean_commit(root, temp.path())? == commit,
        "checkout changed during archive preparation"
    );
    let ledger = Ledger {
        schema: SCHEMA.to_owned(),
        commit,
        toolchain,
        archives,
    };
    let mut json = serde_json::to_vec_pretty(&ledger)?;
    json.push(b'\n');
    write_atomic(&stage.join(LEDGER), &json)?;
    publish_local(&stage, destination)
}

pub fn verify(root: &Path, archives: &Path, unpacked: &Path, build: Option<&Path>) -> Result<()> {
    let build = build.map(Path::canonicalize).transpose()?;
    let _lock = build.as_deref().map(mcu_project::lock_build).transpose()?;
    let archives = archives.canonicalize()?;
    let ledger: Ledger = serde_json::from_slice(&fs::read(contained(&archives, LEDGER)?)?)?;
    ensure!(
        ledger.schema == SCHEMA
            && ledger.commit.len() == 40
            && ledger
                .commit
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "invalid release provenance"
    );
    let names = programs(root)?;
    let entries = ledger
        .archives
        .iter()
        .map(|entry| entry.program.clone())
        .collect::<BTreeSet<_>>();
    ensure!(
        entries == names && entries.len() == ledger.archives.len(),
        "incomplete release ledger"
    );
    let temp = tempfile::tempdir()?;
    let expanded = temp.path().join("unpacked");
    collect(
        &archives,
        &expanded,
        &names,
        build.as_deref(),
        Some(&ledger.archives),
    )?;
    ensure!(!unpacked.exists(), "unpack directory already exists");
    fs::create_dir(unpacked)?;
    let result = (|| {
        for program in names {
            let output = unpacked.join(&program);
            fs::create_dir(&output)?;
            fs::create_dir(output.join("objects"))?;
            fs::create_dir(output.join("images"))?;
            for path in wanted(&program) {
                fs::copy(expanded.join(&program).join(&path), output.join(path))?;
            }
        }
        Ok(())
    })();
    if result.is_err() {
        fs::remove_dir_all(unpacked)?;
    }
    result
}

fn patch(tag: &str) -> Option<&str> {
    let patch = tag.strip_prefix("v0.1.")?;
    (!patch.is_empty()
        && (patch == "0" || !patch.starts_with('0'))
        && patch.bytes().all(|b| b.is_ascii_digit()))
    .then_some(patch)
}

fn increment(digits: &str) -> String {
    let mut number = digits.as_bytes().to_vec();
    for byte in number.iter_mut().rev() {
        if *byte < b'9' {
            *byte += 1;
            return String::from_utf8(number).unwrap();
        }
        *byte = b'0';
    }
    number.insert(0, b'1');
    String::from_utf8(number).unwrap()
}

fn select_tag(refs: &str, commit: &str, allocated: Option<&str>) -> Result<String> {
    let mut tags = BTreeMap::new();
    let mut annotated = BTreeMap::new();
    for line in refs.lines() {
        let (oid, reference) = line.split_once('\t').context("malformed remote tag")?;
        let Some(tag) = reference.strip_prefix("refs/tags/") else {
            continue;
        };
        if let Some(tag) = tag.strip_suffix("^{}") {
            if patch(tag).is_some() {
                annotated.insert(tag, oid);
            }
        } else if patch(tag).is_some() {
            tags.insert(tag, oid);
        }
    }
    let matching: Vec<_> = tags
        .iter()
        .filter(|(tag, oid)| annotated.get(*tag).unwrap_or(oid) == &commit)
        .collect();
    ensure!(matching.len() < 2, "ambiguous v0.1 tags for {commit}");
    if let Some((tag, _)) = matching.first() {
        return Ok((*tag).to_string());
    }
    if let Some(tag) = allocated {
        ensure!(
            patch(tag).is_some(),
            "allocated tag is outside the v0.1 series"
        );
        if !tags.contains_key(tag) {
            return Ok(tag.to_owned());
        }
    }
    let next = tags
        .keys()
        .filter_map(|tag| patch(tag))
        .max_by_key(|digits| (digits.len(), *digits))
        .map_or_else(|| "0".into(), increment);
    Ok(format!("v0.1.{next}"))
}

pub fn next_tag(root: &Path, remote: &str, commit: &str, allocated: Option<&str>) -> Result<()> {
    let refs =
        stdout(
            Command::new("git")
                .current_dir(root)
                .args(["ls-remote", "--tags", "--", remote]),
        )?;
    println!("{}", select_tag(&refs, commit, allocated)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_numeric_tags_and_reuses_an_unclaimed_allocation() {
        let refs = "alpha\trefs/tags/v0.1.99\nbeta\trefs/tags/v0.1.100\ngamma\trefs/tags/v0.1.101-rc.1\ngamma\trefs/tags/v0.1.90\ndelta\trefs/tags/v0.1.90^{}\n";
        assert_eq!(select_tag(refs, "delta", None).unwrap(), "v0.1.90");
        assert_eq!(
            select_tag(refs, "new", Some("v0.1.100")).unwrap(),
            "v0.1.101"
        );
        assert_eq!(
            select_tag(refs, "new", Some("v0.1.103")).unwrap(),
            "v0.1.103"
        );
        assert_eq!(select_tag("", "new", None).unwrap(), "v0.1.0");
    }

    #[test]
    fn refuses_to_extract_path_escape_or_symlink() {
        assert!(inspect("Path = ../outside\nAttributes = A -rw-r--r--", "firewall").is_err());
        assert!(inspect("Path = index.toml\nAttributes = A lrwxrwxrwx", "firewall").is_err());
    }
}
