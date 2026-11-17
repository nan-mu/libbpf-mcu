from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import tomllib
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

MAKE_DIR = Path(__file__).resolve().parent
ROOT = MAKE_DIR.parent
NINJA_TEMPLATE = MAKE_DIR / "ninja" / "graph.ninja"

SCHEMA_INDEX = "libbpf-mcu.artifacts.v1"
SCHEMA_PROGRAM = "libbpf-mcu.program.v1"
SCHEMA_REPORT = "libbpf-mcu.report.v1"
SCHEMA_LEGACY = "libbpf-mcu.legacy-export.v1"

MODES = ("bpf", "rv32", "jit", "bpf-xpost")
LEGACY_MODES = ("rv32", "jit", "bpf-xpost")
FORMATS = frozenset(
    {
        "elf-bpf-relocatable",
        "elf-riscv-relocatable",
        "elf-riscv-linked",
        "raw-rv32-image",
        "raw-ebpf-image",
        "xpost-compact-elf-v0",
    }
)
ROLES = frozenset(
    {
        "bpf_object",
        "aot_object",
        "debug_elf",
        "image",
        "xpost_container",
    }
)
BODY_TABLES = ("xdp", "text", "maps", "CORE", "jit", "rbpf")
_ABS_PATH = re.compile(r"(?:^|[=\s\"'])(/[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)+)")


class LayoutError(Exception):
    pass


@dataclass(frozen=True)
class Spec:
    role: str
    pattern: str
    format: str
    primary: bool
    kind: str


MODE_SPECS: dict[str, tuple[Spec, ...]] = {
    "bpf": (
        Spec("bpf_object", "{program}_bpf.o", "elf-bpf-relocatable", True, "object"),
    ),
    "rv32": (
        Spec("aot_object", "{program}_rv32.o", "elf-riscv-relocatable", False, "object"),
        Spec("debug_elf", "{program}_rv32.debug.elf", "elf-riscv-linked", False, "debug"),
        Spec("image", "{program}_rv32.bin", "raw-rv32-image", False, "image"),
        Spec("xpost_container", "{program}_rv32.elf", "xpost-compact-elf-v0", True, "container"),
    ),
    "jit": (
        Spec("image", "{program}_jit.bin", "raw-rv32-image", False, "image"),
        Spec("xpost_container", "{program}_jit.elf", "xpost-compact-elf-v0", True, "container"),
    ),
    "bpf-xpost": (
        Spec("image", "{program}_bpf-xpost.bin", "raw-ebpf-image", False, "image"),
        Spec(
            "xpost_container",
            "{program}_bpf-xpost.elf",
            "xpost-compact-elf-v0",
            True,
            "container",
        ),
    ),
}


@dataclass(frozen=True)
class SourceRecord:
    repo: str
    commit: str
    dirty: bool
    path: str
    sha256: str

    def source_id(self) -> str:
        return sha256_text(
            canon(
                {
                    "commit": self.commit,
                    "path": self.path,
                    "repo": self.repo,
                    "sha256": self.sha256,
                }
            )
        )


@dataclass(frozen=True)
class Dependency:
    path: str
    role: str
    sha256: str


@dataclass(frozen=True)
class InputArtifact:
    role: str
    path: str
    sha256: str


@dataclass(frozen=True)
class ArtifactFile:
    role: str
    format: str
    primary: bool
    file: Path
    rel: str


@dataclass(frozen=True)
class BuildFacts:
    argv: tuple[str, ...]
    diagnostic_argv: tuple[str, ...]
    cflags: str
    ldflags: str
    opt: str
    target: str
    isa: str
    abi: str
    endian: str
    options: tuple[tuple[str, str], ...]

    def configuration_id(self, toolchain: dict[str, str]) -> str:
        return sha256_text(
            canon(
                {
                    "abi": self.abi,
                    "argv": list(self.argv),
                    "cflags": self.cflags,
                    "endian": self.endian,
                    "isa": self.isa,
                    "ldflags": self.ldflags,
                    "opt": self.opt,
                    "options": list(self.options),
                    "target": self.target,
                    "toolchain": toolchain,
                }
            )
        )


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canon(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def check_program(name: str) -> str:
    if not name or name in {".", ".."} or any(ch in name for ch in "/\\"):
        raise LayoutError(f"program name is not a single path segment: {name!r}")
    return name


def parse_mode(mode: str) -> str:
    if mode not in MODES:
        raise LayoutError(f"unknown mode {mode!r}")
    return mode


def filename(program: str, spec: Spec) -> str:
    return spec.pattern.format(program=check_program(program))


def mode_dir(build_dir: Path, program: str, mode: str) -> Path:
    return build_dir / check_program(program) / parse_mode(mode)


def report_path(build_dir: Path, program: str, mode: str) -> Path:
    return mode_dir(build_dir, program, mode) / "report.toml"


def manifest_path(build_dir: Path, program: str) -> Path:
    return build_dir / check_program(program) / "manifest.toml"


def index_path(build_dir: Path) -> Path:
    return build_dir / "index.toml"


def stamp_path(build_dir: Path, program: str) -> Path:
    return mode_dir(build_dir, program, "bpf") / "prevail.ok"


def spec_path(build_dir: Path, program: str, mode: str, role: str) -> Path:
    for spec in MODE_SPECS[parse_mode(mode)]:
        if spec.role == role:
            return mode_dir(build_dir, program, mode) / filename(program, spec)
    raise LayoutError(f"{mode} has no {role}")


def logical_flag_block() -> str:
    lines = []
    for line in NINJA_TEMPLATE.read_text().splitlines():
        if line.startswith(
            ("bpf_cflags ", "bpf_includes ", "mcu_cflags ", "mcu_includes ", "ldflags ")
        ):
            lines.append(line.replace("@ROOT@", "$ROOT").replace("@LINKER@", "$LINKER"))
    return "\n".join(lines)


def flag_lines(prefix: str) -> str:
    block = logical_flag_block()
    return "\n".join(line for line in block.splitlines() if line.startswith(prefix))


def q(value: str) -> str:
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\t", "\\t")
    )
    return f'"{escaped}"'


def q_array(items: list[str] | tuple[str, ...]) -> str:
    if not items:
        return "[]"
    return "[" + ", ".join(q(item) for item in items) + "]"


def toml_bool(value: bool) -> str:
    return "true" if value else "false"


def input_set_id(
    deps: list[Dependency], extra: tuple[tuple[str, str], ...] = ()
) -> str:
    rows = [{"path": dep.path, "sha256": dep.sha256} for dep in deps]
    rows.extend({"path": path, "sha256": sha} for path, sha in extra)
    rows.sort(key=lambda row: (row["path"], row["sha256"]))
    return sha256_text(canon(rows))


def rel_join(base: Path, rel: str) -> Path:
    if not rel or rel.startswith(("/", "\\")) or PureWindowsPath(rel).is_absolute() or ".." in Path(rel).parts:
        raise LayoutError(f"path is not relative to its report: {rel!r}")
    path = base / rel
    resolved = path.resolve()
    if base.resolve() not in resolved.parents and resolved != base.resolve():
        raise LayoutError(f"path escapes its report directory: {rel!r}")
    return path


def _git(args: list[str], cwd: Path) -> str | None:
    proc = subprocess.run(
        ["git", "-C", str(cwd), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def repo_relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.name


def probe_source(path: Path) -> SourceRecord:
    sha = sha256_file(path)
    url = _git(["remote", "get-url", "origin"], ROOT) or ""
    commit = _git(["rev-parse", "HEAD"], ROOT) or ""
    status = _git(["status", "--porcelain"], ROOT)
    dirty = bool(status)
    return SourceRecord(url, commit, dirty, repo_relative(path), sha)


def parse_depfile(text: str) -> list[str]:
    text = text.replace("\\\n", " ")
    if ":" not in text:
        return []
    _target, rest = text.split(":", 1)
    deps: list[str] = []
    current: list[str] = []
    escaped = False
    for ch in rest:
        if escaped:
            current.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch.isspace():
            if current:
                deps.append("".join(current))
                current = []
        else:
            current.append(ch)
    if current:
        deps.append("".join(current))
    return deps


def dependency_for(path: Path, source: Path) -> Dependency:
    sha = sha256_file(path)
    if path.resolve() == source.resolve():
        return Dependency(repo_relative(path), "source", sha)
    suffix = path.suffix
    try:
        rel = path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return Dependency(f"external/{sha[:16]}/{path.name}", "external", sha)
    if suffix in {".ld", ".tmpl"} or "linker" in path.parts:
        role = "linker"
    else:
        role = "header"
    return Dependency(rel, role, sha)


def dependencies_from(source: Path, depfile: Path | None, extra: list[Path]) -> list[Dependency]:
    paths = [source, *extra]
    if depfile is not None and depfile.is_file():
        for item in parse_depfile(depfile.read_text()):
            paths.append(Path(item))
    found: dict[tuple[str, str], Dependency] = {}
    for path in paths:
        if not path.is_file():
            continue
        dep = dependency_for(path, source)
        found[(dep.path, dep.sha256)] = dep
    return sorted(found.values(), key=lambda dep: (dep.path, dep.role))


def tool_version(cmd: list[str]) -> str | None:
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        return None
    lines = (proc.stdout or proc.stderr).splitlines()
    return lines[0].strip() if lines else None


def cargo_package(path: Path) -> str:
    name = ""
    version = ""
    for line in path.read_text().splitlines():
        if line.startswith("name = ") and not name:
            name = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("version = ") and not version:
            version = line.split("=", 1)[1].strip().strip('"')
        if name and version:
            break
    if not name or not version:
        raise LayoutError(f"missing package version in {path.name}")
    return f"{name} {version}"


def prevail_commit() -> str | None:
    return _git(["rev-parse", "HEAD"], ROOT / "prevail")


def selected_body(text: str, skip: frozenset[str] = frozenset()) -> str:
    lines = text.splitlines(keepends=True)
    kept: list[str] = []
    grabbing = False
    quoted = False
    for line in lines:
        if not quoted:
            stripped = line.strip()
            if stripped.startswith("[") and not stripped.startswith("[["):
                grabbing = stripped not in skip and (
                    stripped in {"[xdp]", "[text]", "[CORE]", "[jit]", "[rbpf]"}
                    or stripped.startswith("[maps.")
                    or stripped.split(".", 1)[0].strip("[]") in BODY_TABLES
                )
            elif stripped.startswith("[["):
                header = stripped.strip("[]").split(".", 1)[0]
                grabbing = header in BODY_TABLES
        if grabbing:
            kept.append(line)
        if line.count('"""') % 2 == 1:
            quoted = not quoted
    return "".join(kept).strip() + ("\n" if kept else "")


def compose_report(
    *,
    program: str,
    mode: str,
    status: str,
    source: SourceRecord,
    build: BuildFacts,
    deps: list[Dependency],
    toolchain: dict[str, str],
    inputs: list[InputArtifact],
    firmware: dict[str, str] | None,
    verification: dict[str, str],
    artifacts: list[dict[str, object]],
    body: str,
) -> str:
    if status not in {"success", "failed", "unsupported"}:
        raise LayoutError(f"bad status {status}")
    extra = tuple((item.path, item.sha256) for item in inputs)
    if firmware and firmware.get("sha256"):
        extra = extra + (("firmware", firmware["sha256"]),)
    lines = [
        f"schema = {q(SCHEMA_REPORT)}",
        f"program = {q(program)}",
        f"mode = {q(mode)}",
        f"status = {q(status)}",
        "",
        "[source]",
        f"repo = {q(source.repo)}",
        f"commit = {q(source.commit)}",
        f"dirty = {toml_bool(source.dirty)}",
        f"path = {q(source.path)}",
        f"sha256 = {q(source.sha256)}",
        "",
        "[build]",
        f"source_id = {q(source.source_id())}",
        f"input_set_id = {q(input_set_id(deps, extra))}",
        f"configuration_id = {q(build.configuration_id(toolchain))}",
        f"argv = {q_array(build.argv)}",
        f"diagnostic_argv = {q_array(build.diagnostic_argv)}",
        f"cflags = {q(build.cflags)}",
        f"ldflags = {q(build.ldflags)}",
        f"opt = {q(build.opt)}",
        f"target = {q(build.target)}",
        f"isa = {q(build.isa)}",
        f"abi = {q(build.abi)}",
        f"endian = {q(build.endian)}",
        "",
    ]
    for dep in deps:
        lines.extend(
            [
                "[[dependency]]",
                f"path = {q(dep.path)}",
                f"role = {q(dep.role)}",
                f"sha256 = {q(dep.sha256)}",
                "",
            ]
        )
    lines.append("[toolchain]")
    if not toolchain:
        lines.append("")
    for key in sorted(toolchain):
        lines.append(f"{key} = {q(toolchain[key])}")
    lines.append("")
    for item in inputs:
        lines.extend(
            [
                "[[input_artifact]]",
                f"role = {q(item.role)}",
                f"path = {q(item.path)}",
                f"sha256 = {q(item.sha256)}",
                "",
            ]
        )
    if firmware is not None:
        lines.append("[firmware]")
        for key in (
            "sha256",
            "helper_addr",
            "slot_addr",
            "slot_len",
            "table_addr",
            "table_len",
            "slot_symbol",
        ):
            if key in firmware:
                lines.append(f"{key} = {q(firmware[key])}")
        lines.append("")
    lines.extend(
        [
            "[verification]",
            f"status = {q(verification['status'])}",
            f"input_sha256 = {q(verification.get('input_sha256', ''))}",
            f"verifier = {q(verification.get('verifier', ''))}",
            f"verifier_id = {q(verification.get('verifier_id', ''))}",
            f"options = {q(verification.get('options', ''))}",
            "",
        ]
    )
    for art in artifacts:
        lines.extend(
            [
                "[[artifact]]",
                f"role = {q(str(art['role']))}",
                f"path = {q(str(art['path']))}",
                f"format = {q(str(art['format']))}",
                f"sha256 = {q(str(art['sha256']))}",
                f"size_bytes = {int(art['size_bytes'])}",
                f"primary = {toml_bool(bool(art['primary']))}",
                "",
            ]
        )
    text = "\n".join(lines).rstrip() + "\n"
    extra = body.strip()
    if extra:
        text += "\n" + extra + "\n"
    return text


def artifact_records(items: list[ArtifactFile]) -> list[dict[str, object]]:
    records = []
    for item in items:
        if item.role not in ROLES or item.format not in FORMATS:
            raise LayoutError(f"bad artifact role or format: {item.role} {item.format}")
        if not item.rel or item.rel.startswith(("/", "\\")) or ".." in Path(item.rel).parts:
            raise LayoutError(f"artifact path is not report-relative: {item.rel}")
        data = item.file.read_bytes()
        records.append(
            {
                "role": item.role,
                "path": item.rel,
                "format": item.format,
                "sha256": sha256_bytes(data),
                "size_bytes": len(data),
                "primary": item.primary,
            }
        )
    return records


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text)
    os.replace(tmp, path)


@contextmanager
def _index_lock(build_dir: Path):
    build_dir.mkdir(parents=True, exist_ok=True)
    handle = (build_dir / ".index.lock").open("a+")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def _load_toml(path: Path) -> dict:
    if not path.is_file():
        return {}
    return tomllib.loads(path.read_text())


def _as_list(value: object) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _write_manifest(
    build_dir: Path,
    program: str,
    source: SourceRecord,
    modes: list[dict[str, str]],
    stale: list[dict[str, str]],
    failed: list[dict[str, str]],
) -> None:
    order = {name: index for index, name in enumerate(MODES)}
    modes = sorted(modes, key=lambda item: order.get(item["name"], 99))
    stale = sorted(stale, key=lambda item: item["name"])
    failed = sorted(failed, key=lambda item: item["name"])
    lines = [
        f"schema = {q(SCHEMA_PROGRAM)}",
        f"program = {q(program)}",
        "",
        "[source]",
        f"repo = {q(source.repo)}",
        f"commit = {q(source.commit)}",
        f"dirty = {toml_bool(source.dirty)}",
        f"path = {q(source.path)}",
        f"sha256 = {q(source.sha256)}",
        "",
    ]
    for mode in modes:
        lines.extend(
            [
                "[[mode]]",
                f"name = {q(mode['name'])}",
                f"report = {q(mode['report'])}",
                f"report_sha256 = {q(mode['report_sha256'])}",
                "",
            ]
        )
    for item in stale:
        lines.extend(
            [
                "[[stale]]",
                f"name = {q(item['name'])}",
                f"report = {q(item['report'])}",
                f"reason = {q(item['reason'])}",
                "",
            ]
        )
    for item in failed:
        lines.extend(
            [
                "[[failed]]",
                f"name = {q(item['name'])}",
                f"report = {q(item['report'])}",
                f"reason = {q(item['reason'])}",
                "",
            ]
        )
    _atomic_write(manifest_path(build_dir, program), "\n".join(lines).rstrip() + "\n")


def _mode_rows(doc: dict, key: str) -> list[dict[str, str]]:
    rows = []
    for item in _as_list(doc.get(key)):
        if isinstance(item, dict) and "name" in item:
            rows.append({str(k): str(v) for k, v in item.items()})
    return rows


def _source_from_doc(doc: dict, fallback: SourceRecord) -> SourceRecord:
    source = doc.get("source")
    if not isinstance(source, dict) or "sha256" not in source:
        return fallback
    return SourceRecord(
        str(source.get("repo", "")),
        str(source.get("commit", "")),
        bool(source.get("dirty", False)),
        str(source.get("path", "")),
        str(source["sha256"]),
    )


def _sibling_stale(
    build_dir: Path,
    program: str,
    keep_mode: str,
    source: SourceRecord,
    bpf_sha: str | None,
) -> list[dict[str, str]]:
    doc = _load_toml(manifest_path(build_dir, program))
    stale = [row for row in _mode_rows(doc, "stale") if row["name"] != keep_mode]
    already = {row["name"] for row in stale}
    for row in _mode_rows(doc, "mode"):
        name = row["name"]
        if name == keep_mode or name in already:
            continue
        reason = _mismatch_reason(build_dir, program, row, source, bpf_sha)
        if reason is None:
            continue
        stale.append({"name": name, "report": row["report"], "reason": reason})
    return stale


def _input_file(report: Path, rel: object) -> Path:
    text = rel if isinstance(rel, str) else ""
    if (
        not text
        or text.startswith(("/", "\\"))
        or Path(text).is_absolute()
        or PureWindowsPath(text).is_absolute()
        or _ABS_PATH.search(text)
    ):
        raise LayoutError(f"input path is absolute: {text}")
    root = report.parent.parent.resolve()
    path = (report.parent / text).resolve()
    if not path.is_relative_to(root):
        raise LayoutError(f"input path escapes its program directory: {text}")
    return path


def _input_problem(report: Path, item: object) -> str | None:
    if not isinstance(item, dict):
        return "input artifact is not a table"
    rel = item.get("path", "")
    try:
        file_path = _input_file(report, rel)
    except LayoutError as exc:
        return str(exc)
    if not file_path.is_file():
        return f"missing input {rel}"
    if sha256_file(file_path) != item.get("sha256"):
        return f"input hash mismatch: {rel}"
    return None


def _mismatch_reason(
    build_dir: Path,
    program: str,
    row: dict[str, str],
    source: SourceRecord,
    _bpf_sha: str | None,
) -> str | None:
    path = manifest_path(build_dir, program).parent / row["report"]
    if not path.is_file():
        return "report missing"
    try:
        report = tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError:
        return "report unreadable"
    build = report.get("build")
    if not isinstance(build, dict) or build.get("source_id") != source.source_id():
        return "source identity changed"
    for item in _as_list(report.get("input_artifact")):
        reason = _input_problem(path, item)
        if reason is not None:
            return reason
    return None


def _rewrite_index(build_dir: Path) -> None:
    programs = []
    if build_dir.is_dir():
        for manifest in sorted(build_dir.glob("*/manifest.toml")):
            doc = _load_toml(manifest)
            if doc.get("schema") != SCHEMA_PROGRAM:
                continue
            if not _as_list(doc.get("mode")):
                continue
            rel = manifest.relative_to(build_dir).as_posix()
            programs.append(
                {
                    "name": str(doc.get("program", manifest.parent.name)),
                    "manifest": rel,
                    "manifest_sha256": sha256_file(manifest),
                }
            )
    programs.sort(key=lambda item: item["name"])
    lines = [f"schema = {q(SCHEMA_INDEX)}", ""]
    for item in programs:
        lines.extend(
            [
                "[[program]]",
                f"name = {q(item['name'])}",
                f"manifest = {q(item['manifest'])}",
                f"manifest_sha256 = {q(item['manifest_sha256'])}",
                "",
            ]
        )
    _atomic_write(index_path(build_dir), "\n".join(lines).rstrip() + "\n")


def commit_mode(
    build_dir: Path,
    program: str,
    mode: str,
    source: SourceRecord,
    build: BuildFacts,
    deps: list[Dependency],
    toolchain: dict[str, str],
    inputs: list[InputArtifact],
    firmware: dict[str, str] | None,
    verification: dict[str, str],
    artifacts: list[ArtifactFile],
    body: str,
    *,
    bpf_sha: str | None = None,
) -> Path:
    program = check_program(program)
    mode = parse_mode(mode)
    if verification.get("status") not in {"not_run", "accepted", "rejected", "unsupported"}:
        raise LayoutError("verification status is missing")
    records = artifact_records(artifacts)
    if not any(bool(art["primary"]) for art in records):
        raise LayoutError(f"{mode} success has no primary artifact")
    text = compose_report(
        program=program,
        mode=mode,
        status="success",
        source=source,
        build=build,
        deps=deps,
        toolchain=toolchain,
        inputs=inputs,
        firmware=firmware,
        verification=verification,
        artifacts=records,
        body=body,
    )
    destination = report_path(build_dir, program, mode)
    with _index_lock(build_dir):
        _atomic_write(destination, text)
        digest = sha256_file(destination)
        existing = _load_toml(manifest_path(build_dir, program))
        modes = [row for row in _mode_rows(existing, "mode") if row["name"] != mode]
        modes.append(
            {
                "name": mode,
                "report": f"{mode}/report.toml",
                "report_sha256": digest,
            }
        )
        stale = _sibling_stale(build_dir, program, mode, source, bpf_sha)
        stale_names = {row["name"] for row in stale}
        modes = [row for row in modes if row["name"] not in stale_names]
        failed = [
            row
            for row in _mode_rows(existing, "failed")
            if row["name"] != mode and row["name"] not in stale_names
        ]
        kept = _source_from_doc(existing, source)
        _write_manifest(build_dir, program, source if modes else kept, modes, stale, failed)
        _rewrite_index(build_dir)
    return destination


def retract_mode(build_dir: Path, program: str, mode: str, reason: str) -> None:
    program = check_program(program)
    mode = parse_mode(mode)
    directory = mode_dir(build_dir, program, mode)
    for spec in MODE_SPECS[mode]:
        if spec.kind in {"container", "image"} or mode == "bpf":
            (directory / filename(program, spec)).unlink(missing_ok=True)
    source = SourceRecord("", "", False, "", "")
    build = BuildFacts((), (), "", "", "", mode, "", "", "little", ())
    text = compose_report(
        program=program,
        mode=mode,
        status="failed",
        source=source,
        build=build,
        deps=[],
        toolchain={},
        inputs=[],
        firmware=None,
        verification={"status": "rejected", "input_sha256": "", "verifier": "", "verifier_id": "", "options": ""},
        artifacts=[],
        body=f'reason = {q(reason)}\n',
    )
    with _index_lock(build_dir):
        existing = _load_toml(manifest_path(build_dir, program))
        if not existing and not directory.exists():
            _atomic_write(report_path(build_dir, program, mode), text)
            return
        _atomic_write(report_path(build_dir, program, mode), text)
        modes = [row for row in _mode_rows(existing, "mode") if row["name"] != mode]
        stale = [row for row in _mode_rows(existing, "stale") if row["name"] != mode]
        failed = [row for row in _mode_rows(existing, "failed") if row["name"] != mode]
        failed.append({"name": mode, "report": f"{mode}/report.toml", "reason": reason})
        manifest_source = _source_from_doc(existing, source)
        if existing or modes or stale:
            _write_manifest(build_dir, program, manifest_source, modes, stale, failed)
        _rewrite_index(build_dir)


def _replace_verification(text: str, verification: dict[str, str]) -> str:
    block = "\n".join(
        [
            "[verification]",
            f"status = {q(verification['status'])}",
            f"input_sha256 = {q(verification.get('input_sha256', ''))}",
            f"verifier = {q(verification.get('verifier', ''))}",
            f"verifier_id = {q(verification.get('verifier_id', ''))}",
            f"options = {q(verification.get('options', ''))}",
            "",
        ]
    )
    pattern = re.compile(r"(?ms)^\[verification\]\n.*?(?=^\[|\Z)")
    if not pattern.search(text):
        raise LayoutError("report has no [verification] table")
    return pattern.sub(block, text, count=1)


def record_verification(
    build_dir: Path,
    program: str,
    verification: dict[str, str],
) -> None:
    path = report_path(build_dir, program, "bpf")
    if not path.is_file():
        raise LayoutError(f"bpf report is missing: {path}")
    text = _replace_verification(path.read_text(), verification)
    with _index_lock(build_dir):
        _atomic_write(path, text)
        digest = sha256_file(path)
        existing = _load_toml(manifest_path(build_dir, program))
        if not existing:
            return
        modes = []
        for row in _mode_rows(existing, "mode"):
            if row["name"] == "bpf":
                row = {**row, "report_sha256": digest}
            modes.append(row)
        _write_manifest(
            build_dir,
            program,
            _source_from_doc(existing, SourceRecord("", "", False, "", "")),
            modes,
            _mode_rows(existing, "stale"),
            _mode_rows(existing, "failed"),
        )
        _rewrite_index(build_dir)


def parse_stamp(text: str) -> dict[str, str]:
    parsed = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed[key] = value
    return parsed


def verification_from_stamp(stamp: Path, bpf_file: Path) -> dict[str, str]:
    digest = sha256_file(bpf_file)
    if not stamp.is_file():
        return {
            "status": "not_run",
            "input_sha256": digest,
            "verifier": "",
            "verifier_id": "",
            "options": "",
        }
    parsed = parse_stamp(stamp.read_text())
    if parsed.get("bpf_sha256") != digest or not parsed.get("verifier_id"):
        return {
            "status": "rejected",
            "input_sha256": digest,
            "verifier": parsed.get("verifier", ""),
            "verifier_id": parsed.get("verifier_id", ""),
            "options": parsed.get("options", ""),
        }
    return {
        "status": "accepted",
        "input_sha256": digest,
        "verifier": parsed.get("verifier", "prevail"),
        "verifier_id": parsed["verifier_id"],
        "options": parsed.get("options", ""),
    }


def _check_report_file(path: Path, expected_sha: str | None = None) -> dict:
    if not path.is_file():
        raise LayoutError(f"missing report {path}")
    actual = sha256_file(path)
    if expected_sha is not None and actual != expected_sha:
        raise LayoutError(f"report hash mismatch for {path.name}")
    try:
        doc = tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError as exc:
        raise LayoutError(f"report is not toml: {path}") from exc
    if doc.get("schema") != SCHEMA_REPORT:
        raise LayoutError("report schema mismatch")
    if doc.get("status") != "success":
        raise LayoutError(f"report status is {doc.get('status')}")
    build = doc.get("build")
    if not isinstance(build, dict):
        raise LayoutError("report has no [build]")
    for key in ("source_id", "input_set_id", "configuration_id"):
        if not build.get(key):
            raise LayoutError(f"report missing {key}")
    if build.get("source_id") == doc.get("source", {}).get("sha256"):
        raise LayoutError("source_id must not be the source file sha alone")
    for art in _as_list(doc.get("artifact")):
        if not isinstance(art, dict):
            raise LayoutError("artifact entry is not a table")
        rel = str(art.get("path", ""))
        if _ABS_PATH.search(rel):
            raise LayoutError(f"artifact path is absolute: {rel}")
        file_path = rel_join(path.parent, rel)
        if not file_path.is_file():
            raise LayoutError(f"missing artifact {rel}")
        if sha256_file(file_path) != art.get("sha256"):
            raise LayoutError(f"artifact hash mismatch: {rel}")
        if file_path.stat().st_size != int(art.get("size_bytes", -1)):
            raise LayoutError(f"artifact size mismatch: {rel}")
        if art.get("format") not in FORMATS or art.get("role") not in ROLES:
            raise LayoutError(f"unknown artifact kind {art.get('role')} {art.get('format')}")
    for item in _as_list(doc.get("input_artifact")):
        reason = _input_problem(path, item)
        if reason is not None:
            raise LayoutError(reason)
    return doc


def load_mode(build_dir: Path, program: str, mode: str) -> dict:
    program = check_program(program)
    mode = parse_mode(mode)
    index = _load_toml(index_path(build_dir))
    if index.get("schema") != SCHEMA_INDEX:
        raise LayoutError("index schema mismatch")
    listed = _as_list(index.get("program"))
    names = [str(item.get("name")) for item in listed if isinstance(item, dict)]
    if names != sorted(names):
        raise LayoutError("index is not sorted by program")
    match = next(
        (item for item in listed if isinstance(item, dict) and item.get("name") == program),
        None,
    )
    if match is None:
        raise LayoutError(f"{program} is not in the index")
    manifest = rel_join(build_dir, str(match["manifest"]))
    if sha256_file(manifest) != match.get("manifest_sha256"):
        raise LayoutError("manifest hash mismatch")
    doc = _load_toml(manifest)
    if doc.get("schema") != SCHEMA_PROGRAM:
        raise LayoutError("manifest schema mismatch")
    row = next(
        (item for item in _as_list(doc.get("mode")) if isinstance(item, dict) and item.get("name") == mode),
        None,
    )
    if row is None:
        raise LayoutError(f"{mode} is not a consumable mode of {program}")
    report = rel_join(manifest.parent, str(row["report"]))
    return _check_report_file(report, str(row["report_sha256"]))


def verify_tree(build_dir: Path) -> list[tuple[str, str]]:
    index = _load_toml(index_path(build_dir))
    if index.get("schema") != SCHEMA_INDEX:
        raise LayoutError("index schema mismatch")
    found = []
    for item in _as_list(index.get("program")):
        if not isinstance(item, dict):
            raise LayoutError("index program is not a table")
        program = str(item["name"])
        manifest = _load_toml(rel_join(build_dir, str(item["manifest"])))
        for row in _as_list(manifest.get("mode")):
            if not isinstance(row, dict):
                continue
            load_mode(build_dir, program, str(row["name"]))
            found.append((program, str(row["name"])))
    return found


def export_legacy(build_dir: Path, out: Path, mode: str) -> list[str]:
    mode = parse_mode(mode)
    if mode not in LEGACY_MODES:
        raise LayoutError("export-legacy does not export the raw bpf mode")
    build_dir = build_dir.resolve()
    out = out.resolve()
    if out == build_dir or build_dir in out.parents or out in build_dir.parents:
        raise LayoutError("legacy output must be a different tree from the canonical build root")
    identity = out / "legacy-mode.txt"
    if identity.is_file():
        current = tomllib.loads(identity.read_text())
        if current.get("mode") != mode:
            raise LayoutError(
                f"refusing to overwrite a {current.get('mode')} export with {mode}"
            )
    elif out.exists() and any(out.iterdir()):
        raise LayoutError("legacy output is not empty and has no mode identity")
    index = _load_toml(index_path(build_dir))
    exported = []
    for item in _as_list(index.get("program")):
        if not isinstance(item, dict):
            continue
        program = str(item["name"])
        try:
            mode_report = load_mode(build_dir, program, mode)
            bpf_report = load_mode(build_dir, program, "bpf")
        except LayoutError:
            continue
        destination = out / program
        destination.mkdir(parents=True, exist_ok=True)
        bpf_file = _artifact_file(build_dir, program, "bpf", bpf_report, "bpf_object")
        _copy_file(bpf_file, destination / "bpf.o")
        if mode == "rv32":
            write_legacy_toml(
                destination / "bpf.toml",
                report_path(build_dir, program, "bpf"),
                bpf_file,
                report_path(build_dir, program, "rv32"),
            )
            _copy_role(build_dir, program, mode, mode_report, "aot_object", destination / "esp32c3.o")
            _copy_role(build_dir, program, mode, mode_report, "debug_elf", destination / "esp32c3.elf")
            _copy_role(build_dir, program, mode, mode_report, "image", destination / "esp32c3.bin")
            _copy_role(build_dir, program, mode, mode_report, "xpost_container", destination / f"{program}.elf")
        elif mode == "jit":
            write_legacy_toml(
                destination / "bpf.toml",
                report_path(build_dir, program, "jit"),
                bpf_file,
                None,
                skip=frozenset({"[jit]", "[rbpf]"}),
            )
            _copy_role(build_dir, program, mode, mode_report, "image", destination / "jit.bin")
            _copy_role(build_dir, program, mode, mode_report, "xpost_container", destination / f"{program}.elf")
            (destination / "jit.toml").write_text(
                selected_body(report_path(build_dir, program, mode).read_text())
            )
            stamp = stamp_path(build_dir, program)
            if stamp.is_file():
                _copy_file(stamp, destination / "prevail.ok")
        else:
            write_legacy_toml(
                destination / "bpf.toml",
                report_path(build_dir, program, "bpf"),
                bpf_file,
                None,
            )
            _copy_role(build_dir, program, mode, mode_report, "image", destination / f"{program}.bin")
            _copy_role(build_dir, program, mode, mode_report, "xpost_container", destination / f"{program}.elf")
        exported.append(program)
    if not exported:
        raise LayoutError(f"no verified {mode} program to export")
    _atomic_write(
        identity,
        "\n".join(
            [
                f"schema = {q(SCHEMA_LEGACY)}",
                f"mode = {q(mode)}",
                "note = \"path transition only; files are copies and are not written back\"",
                "",
            ]
        ),
    )
    return exported


def _artifact_file(build_dir: Path, program: str, mode: str, report: dict, role: str) -> Path:
    for art in _as_list(report.get("artifact")):
        if isinstance(art, dict) and art.get("role") == role:
            return rel_join(report_path(build_dir, program, mode).parent, str(art["path"]))
    raise LayoutError(f"{program} {mode} has no {role}")


def _copy_role(
    build_dir: Path,
    program: str,
    mode: str,
    report: dict,
    role: str,
    dest: Path,
) -> None:
    try:
        source = _artifact_file(build_dir, program, mode, report, role)
    except LayoutError:
        return
    _copy_file(source, dest)


def _copy_file(source: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(source.read_bytes())


def _legacy_header(report: dict, size: int) -> str:
    source = report.get("source")
    path = source.get("path", "") if isinstance(source, dict) else ""
    return f"source = {q(str(path))}\nsize = {size}\n"


def write_legacy_toml(
    dest: Path,
    report_file: Path,
    bpf_file: Path,
    addr_file: Path | None,
    skip: frozenset[str] = frozenset(),
) -> None:
    report = tomllib.loads(report_file.read_text())
    text = _legacy_header(report, bpf_file.stat().st_size) + "\n" + selected_body(
        report_file.read_text(), skip
    )
    dest.write_text(text)
    if addr_file is None or not addr_file.is_file():
        return
    from obj_report import merge_aot_addrs_into_toml

    addr = tomllib.loads(addr_file.read_text())
    addrs: dict[str, int] = {}
    maps = addr.get("maps")
    if isinstance(maps, dict):
        for name, fields in maps.items():
            if isinstance(fields, dict) and "aot_addr" in fields:
                addrs[str(name)] = int(str(fields["aot_addr"]), 0)
    if addrs:
        merge_aot_addrs_into_toml(dest, addrs)


def verifier_identity() -> str:
    commit = prevail_commit()
    if commit:
        return commit
    from prevail_gate import prevail_bin

    binary = prevail_bin()
    if binary.is_file():
        return "bin:" + sha256_file(binary)[:16]
    raise LayoutError("PREVAIL has no commit and no binary")


def redact(text: str, build_dir: Path | None = None) -> str:
    pairs = [(str(ROOT), "$REPO"), (str(Path.home()), "$HOME")]
    if build_dir is not None:
        pairs.append((str(build_dir), "$BUILD"))
    for raw, token in pairs:
        if raw and raw not in {"/", ""}:
            text = text.replace(raw, token)
    return re.sub(r"(?<![A-Za-z0-9$.])/[^\s\"]+", "$PATH", text)


def _flag_text(*prefixes: str) -> str:
    return "\n".join(
        line
        for line in logical_flag_block().splitlines()
        if line.startswith(prefixes)
    )


def _require_version(cmd: list[str]) -> str:
    version = tool_version(cmd)
    if not version:
        raise LayoutError(f"{' '.join(cmd)} failed")
    return version


def _die(message: str, code: int = 1) -> None:
    sys.stderr.write(message + "\n")
    raise SystemExit(code)


def _bpf_body(obj: Path, src: Path, objdump: str, release: bool) -> str:
    stage = obj.parent / ".stage"
    stage.mkdir(parents=True, exist_ok=True)
    out = stage / "body.toml"
    proc = subprocess.run(
        [
            sys.executable,
            str(MAKE_DIR / "obj_report.py"),
            "--obj",
            str(obj),
            "--src",
            str(src),
            "--out",
            str(out),
            "--objdump",
            objdump,
            "--btf",
            "--body-only",
            *(["--no-content"] if release else []),
        ]
    )
    if proc.returncode != 0:
        raise SystemExit(proc.returncode)
    text = out.read_text()
    out.unlink(missing_ok=True)
    return text


def _firmware_dict(
    firmware: Path,
    helper: str,
    slot: str,
    slot_len: str,
    table: str,
    table_len: str,
    slot_symbol: str,
) -> dict[str, str]:
    record = {
        "sha256": sha256_file(firmware),
        "helper_addr": helper,
        "slot_addr": slot,
        "slot_len": slot_len,
        "table_addr": table,
        "table_len": table_len,
    }
    if slot_symbol:
        record["slot_symbol"] = slot_symbol
    return record


def _read_mem_map(tool: Path, firmware: Path) -> dict[str, str]:
    proc = subprocess.run(
        [str(tool), "mem-map", str(firmware)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise LayoutError((proc.stderr or proc.stdout or "mem-map failed").strip())
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    if not lines:
        raise LayoutError("mem-map produced no stdout")
    data = json.loads(lines[-1])
    return _firmware_dict(
        firmware,
        hex(int(data["helper_addr"])),
        hex(int(data["slot_addr"])),
        hex(int(data["slot_len"])),
        hex(int(data["table_addr"])),
        hex(int(data["table_len"])),
        "",
    )


def cmd_commit_bpf(args: argparse.Namespace) -> None:
    obj = args.object
    src = args.src
    release = args.release == "1"
    argv = ["build", "bpf", "-c", args.program]
    if release:
        argv.append("--release")
    build = BuildFacts(
        tuple(argv),
        tuple(redact(part, args.build_dir) for part in (str(args.clang), "-c", str(src), "-o", str(obj))),
        _flag_text("bpf_cflags", "bpf_includes"),
        "",
        "O2",
        "bpf",
        "ebpf",
        "",
        "little",
        (("release", "1" if release else "0"),),
    )
    stamp = stamp_path(args.build_dir, args.program)
    verification = (
        verification_from_stamp(stamp, obj)
        if stamp.is_file()
        else {
            "status": "not_run",
            "input_sha256": sha256_file(obj),
            "verifier": "",
            "verifier_id": "",
            "options": "",
        }
    )
    commit_mode(
        args.build_dir,
        args.program,
        "bpf",
        probe_source(src),
        build,
        dependencies_from(src, args.headers if args.headers.is_file() else None, []),
        {"clang": _require_version([str(args.clang), "--version"])},
        [],
        None,
        verification,
        [
            ArtifactFile(
                "bpf_object",
                "elf-bpf-relocatable",
                True,
                obj,
                obj.name,
            )
        ],
        _bpf_body(obj, src, args.objdump, release),
        bpf_sha=sha256_file(obj),
    )


def _backend_facts(
    program: str,
    mode: str,
    release: bool,
    engine: str,
    image_name: str,
    slot_symbol: str,
    firmware: dict[str, str],
    *,
    target: str,
    isa: str,
    abi: str,
    cflags: str,
    ldflags: str,
    diagnostic: tuple[str, ...],
) -> BuildFacts:
    argv = ["build", mode, "-c", program, "--engine", engine]
    if release:
        argv.append("--release")
    if image_name:
        argv.extend(["--image-name", image_name])
    if slot_symbol:
        argv.extend(["--slot-symbol", slot_symbol])
    options = (
        ("engine", engine),
        ("helper", firmware.get("helper_addr", "")),
        ("image_name", image_name),
        ("release", "1" if release else "0"),
        ("slot", firmware.get("slot_addr", "")),
        ("slot_len", firmware.get("slot_len", "")),
        ("slot_symbol", slot_symbol),
    )
    return BuildFacts(
        tuple(argv),
        diagnostic,
        cflags,
        ldflags,
        "O2",
        target,
        isa,
        abi,
        "little",
        options,
    )


def cmd_commit_rv32(args: argparse.Namespace) -> None:
    bpf_sha = sha256_file(args.bpf_object)
    verification = verification_from_stamp(args.stamp, args.bpf_object)
    if verification["status"] != "accepted":
        retract_mode(args.build_dir, args.program, "rv32", "PREVAIL did not accept this BPF object")
        _die("refusing to publish rv32 without an accepted gate stamp")
    container = args.container if args.container and args.container.is_file() else None
    body = args.body.read_text()
    if container is not None:
        body = body.rstrip() + f"\nelf_size_kb = {container.stat().st_size / 1024:.3f}\n"
    artifacts = [
        ArtifactFile("aot_object", "elf-riscv-relocatable", False, args.object, args.object.name),
        ArtifactFile("debug_elf", "elf-riscv-linked", False, args.debug_elf, args.debug_elf.name),
        ArtifactFile(
            "image",
            "raw-rv32-image",
            container is None,
            args.image,
            args.image.name,
        ),
    ]
    if container is not None:
        artifacts.append(
            ArtifactFile(
                "xpost_container",
                "xpost-compact-elf-v0",
                True,
                container,
                container.name,
            )
        )
    extra = [args.linker]
    template = MAKE_DIR / "linker" / "esp32c3-slot.ld.tmpl"
    if template.is_file():
        extra.append(template)
    firmware = _firmware_dict(
        args.firmware,
        args.helper,
        args.slot,
        args.slot_len,
        args.table,
        args.table_len,
        args.slot_symbol,
    )
    toolchain = {"clang": _require_version([str(args.clang), "--version"])}
    if container is not None:
        toolchain["rustc"] = _require_version(["rustc", "--version"])
        toolchain["packer"] = cargo_package(ROOT / "tools" / "Cargo.toml")
    toolchain["prevail"] = verification["verifier_id"]
    release = args.release == "1"
    commit_mode(
        args.build_dir,
        args.program,
        "rv32",
        probe_source(args.src),
        _backend_facts(
            args.program,
            "rv32",
            release,
            args.engine,
            args.image_name,
            args.slot_symbol,
            firmware,
            target="riscv32-unknown-none-elf",
            isa="rv32imc",
            abi="ilp32",
            cflags=_flag_text("mcu_cflags", "mcu_includes"),
            ldflags=_flag_text("ldflags"),
            diagnostic=tuple(
                redact(part, args.build_dir)
                for part in (str(args.clang), "-c", str(args.src), "-o", str(args.object))
            ),
        ),
        dependencies_from(args.src, args.headers if args.headers.is_file() else None, extra),
        toolchain,
        [InputArtifact("gate_bpf", f"../bpf/{args.bpf_object.name}", bpf_sha)],
        firmware,
        verification,
        artifacts,
        body,
        bpf_sha=bpf_sha,
    )


def cmd_commit_xpost(args: argparse.Namespace) -> None:
    bpf_sha = sha256_file(args.bpf_object)
    verification = verification_from_stamp(args.stamp, args.bpf_object)
    if verification["status"] != "accepted":
        retract_mode(args.build_dir, args.program, "bpf-xpost", "PREVAIL did not accept this BPF object")
        _die("refusing to publish bpf-xpost without an accepted gate stamp")
    addr_sha = sha256_file(args.addr_report)
    body = "\n".join(
        [
            "[rbpf]",
            "map_index = true",
            f"addr_report = {q('../rv32/report.toml')}",
            f"addr_sha256 = {q(addr_sha)}",
            "",
        ]
    )
    firmware = _firmware_dict(
        args.firmware,
        args.helper,
        args.slot,
        args.slot_len,
        args.table,
        args.table_len,
        "",
    )
    release = args.release == "1"
    commit_mode(
        args.build_dir,
        args.program,
        "bpf-xpost",
        probe_source(args.src),
        _backend_facts(
            args.program,
            "bpf-xpost",
            release,
            "rbpf",
            args.image_name,
            "",
            firmware,
            target="bpf",
            isa="ebpf",
            abi="",
            cflags="",
            ldflags="",
            diagnostic=(redact(str(args.image), args.build_dir),),
        ),
        dependencies_from(args.src, None, []),
        {
            "rustc": _require_version(["rustc", "--version"]),
            "packer": cargo_package(ROOT / "tools" / "Cargo.toml"),
            "prevail": verification["verifier_id"],
        },
        [
            InputArtifact("bpf_object", f"../bpf/{args.bpf_object.name}", bpf_sha),
            InputArtifact("map_index_basis", "../rv32/report.toml", addr_sha),
        ],
        firmware,
        verification,
        [
            ArtifactFile("image", "raw-ebpf-image", False, args.image, args.image.name),
            ArtifactFile(
                "xpost_container",
                "xpost-compact-elf-v0",
                True,
                args.container,
                args.container.name,
            ),
        ],
        body,
        bpf_sha=bpf_sha,
    )


def finish_jit(
    build_dir: Path,
    program: str,
    src: Path,
    bpf_object: Path,
    image: Path,
    container: Path,
    stage_toml: Path,
    firmware_path: Path,
    tool: Path,
    *,
    release: bool,
    image_name: str | None,
) -> None:
    bpf_sha = sha256_file(bpf_object)
    verification = verification_from_stamp(stamp_path(build_dir, program), bpf_object)
    if verification["status"] != "accepted":
        raise LayoutError("JIT publish requires an accepted gate stamp")
    firmware = _read_mem_map(tool, firmware_path)
    commit_mode(
        build_dir,
        program,
        "jit",
        probe_source(src),
        _backend_facts(
            program,
            "jit",
            release,
            "jit",
            image_name or "",
            "",
            firmware,
            target="rv32im",
            isa="RV32IM",
            abi="helper_dispatcher-ilp32",
            cflags="",
            ldflags="",
            diagnostic=tuple(
                redact(part, build_dir) for part in (str(tool), "pack-jit", str(bpf_object))
            ),
        ),
        dependencies_from(src, None, []),
        {
            "rustc": _require_version(["rustc", "--version"]),
            "jit": cargo_package(ROOT / "jit" / "Cargo.toml"),
            "packer": cargo_package(ROOT / "tools" / "Cargo.toml"),
            "prevail": verification["verifier_id"],
        },
        [InputArtifact("bpf_object", f"../bpf/{bpf_object.name}", bpf_sha)],
        firmware,
        verification,
        [
            ArtifactFile("image", "raw-rv32-image", False, image, image.name),
            ArtifactFile(
                "xpost_container",
                "xpost-compact-elf-v0",
                True,
                container,
                container.name,
            ),
        ],
        selected_body(stage_toml.read_text()),
        bpf_sha=bpf_sha,
    )


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--program", required=True)
    parser.add_argument("--src", type=Path, required=True)
    parser.add_argument("--release", choices=("0", "1"), default="0")


def main() -> None:
    parser = argparse.ArgumentParser(prog="layout")
    commands = parser.add_subparsers(dest="command", required=True)

    bpf = commands.add_parser("commit-bpf")
    _add_common(bpf)
    bpf.add_argument("--object", type=Path, required=True)
    bpf.add_argument("--headers", type=Path, required=True)
    bpf.add_argument("--objdump", required=True)
    bpf.add_argument("--clang", required=True)
    bpf.set_defaults(func=cmd_commit_bpf)

    rv32 = commands.add_parser("commit-rv32")
    _add_common(rv32)
    rv32.add_argument("--object", type=Path, required=True)
    rv32.add_argument("--debug-elf", type=Path, required=True)
    rv32.add_argument("--image", type=Path, required=True)
    rv32.add_argument("--container", type=Path)
    rv32.add_argument("--body", type=Path, required=True)
    rv32.add_argument("--bpf-object", type=Path, required=True)
    rv32.add_argument("--stamp", type=Path, required=True)
    rv32.add_argument("--linker", type=Path, required=True)
    rv32.add_argument("--firmware", type=Path, required=True)
    rv32.add_argument("--objdump", required=True)
    rv32.add_argument("--clang", required=True)
    rv32.add_argument("--engine", default="aot")
    rv32.add_argument("--image-name", default="")
    rv32.add_argument("--slot-symbol", default="")
    rv32.add_argument("--headers", type=Path, required=True)
    rv32.add_argument("--helper", required=True)
    rv32.add_argument("--slot", required=True)
    rv32.add_argument("--slot-len", required=True)
    rv32.add_argument("--table", required=True)
    rv32.add_argument("--table-len", required=True)
    rv32.set_defaults(func=cmd_commit_rv32)

    xpost = commands.add_parser("commit-xpost")
    _add_common(xpost)
    xpost.add_argument("--image", type=Path, required=True)
    xpost.add_argument("--container", type=Path, required=True)
    xpost.add_argument("--bpf-object", type=Path, required=True)
    xpost.add_argument("--addr-report", type=Path, required=True)
    xpost.add_argument("--stamp", type=Path, required=True)
    xpost.add_argument("--firmware", type=Path, required=True)
    xpost.add_argument("--image-name", default="")
    xpost.add_argument("--helper", required=True)
    xpost.add_argument("--slot", required=True)
    xpost.add_argument("--slot-len", required=True)
    xpost.add_argument("--table", required=True)
    xpost.add_argument("--table-len", required=True)
    xpost.set_defaults(func=cmd_commit_xpost)

    verify = commands.add_parser("verify")
    verify.add_argument("--build-dir", type=Path, required=True)

    export = commands.add_parser("export-legacy")
    export.add_argument("--build-dir", type=Path, required=True)
    export.add_argument("--out", type=Path, required=True)
    export.add_argument("--mode", required=True)

    args = parser.parse_args()
    try:
        if args.command == "verify":
            found = verify_tree(args.build_dir)
            for program, mode in found:
                print(f"{program} {mode}")
            return
        if args.command == "export-legacy":
            for program in export_legacy(args.build_dir, args.out, args.mode):
                print(program)
            return
        args.func(args)
    except LayoutError as exc:
        _die(str(exc))


if __name__ == "__main__":
    main()

