#!/usr/bin/env python3
"""Build and publish a self-contained, verified artifact archive."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from contextlib import nullcontext
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "make"))
import layout

LOG_DIR: Path | None = None


class PublishError(Exception):
    pass


def run(args: list[str], *, allow_failure: bool = False) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            args, cwd=ROOT, text=True, capture_output=True, check=False
        )
    except OSError as exc:
        raise PublishError(f"cannot run {args[0]}: {exc}") from exc
    if LOG_DIR is not None and args[0] != "gh":
        with (LOG_DIR / "commands.log").open("a") as log:
            log.write(
                f"argv={args!r}\nexit={result.returncode}\n{result.stdout}\n{result.stderr}\n"
            )
    if result.returncode and not allow_failure:
        detail = (
            "GitHub CLI request failed"
            if args[0] == "gh"
            else (result.stderr or result.stdout).strip()
        )
        raise PublishError(f"{args[0]} failed ({result.returncode}): {detail}")
    return result


def document(path: Path) -> dict:
    return tomllib.loads(path.read_text())


def contained(root: Path, rel: str) -> Path:
    if (
        not isinstance(rel, str)
        or not rel
        or "\\" in rel
        or PurePosixPath(rel).is_absolute()
        or ".." in PurePosixPath(rel).parts
    ):
        raise PublishError(f"unsafe path: {rel!r}")
    path = root / rel
    if not path.resolve().is_relative_to(root.resolve()) or any(
        p.is_symlink()
        for p in [path, *path.parents]
        if p != root and p.is_relative_to(root)
    ):
        raise PublishError(f"path escapes tree or uses symlink: {rel}")
    return path


def official(root: Path, programs: list[str]) -> set[str]:
    """Validate the protocol and return precisely the files allowed in the archive."""
    root = root.resolve()
    index = document(contained(root, "index.toml"))
    rows = index.get("program", [])
    if (
        index.get("schema") != layout.SCHEMA_INDEX
        or not isinstance(rows, list)
        or [r.get("name") for r in rows] != programs
    ):
        raise PublishError("index programs are missing, duplicated, or not sorted")
    files = {"index.toml"}
    inputs = []
    for row in rows:
        name = row["name"]
        if row.get("manifest") != f"{name}/manifest.toml":
            raise PublishError(f"invalid manifest path for {name}")
        manifest_path = contained(root, row["manifest"])
        manifest = document(manifest_path)
        if (
            layout.sha256_file(manifest_path) != row.get("manifest_sha256")
            or manifest.get("schema") != layout.SCHEMA_PROGRAM
            or manifest.get("program") != name
        ):
            raise PublishError(f"invalid manifest for {name}")
        modes = manifest.get("mode", [])
        if (
            manifest.get("stale")
            or manifest.get("failed")
            or not isinstance(modes, list)
            or [r.get("name") for r in modes] != list(layout.MODES)
        ):
            raise PublishError(f"{name}: missing, duplicated, stale, or failed modes")
        files.add(row["manifest"])
        for mode in modes:
            m = mode["name"]
            expected_report = f"{m}/report.toml"
            if mode.get("report") != expected_report:
                raise PublishError(f"{name}/{m}: invalid report path")
            rel = f"{name}/{expected_report}"
            report_path = contained(root, rel)
            report = document(report_path)
            if (
                layout.sha256_file(report_path) != mode.get("report_sha256")
                or report.get("program") != name
                or report.get("mode") != m
                or report.get("source") != manifest.get("source")
            ):
                raise PublishError(f"{name}/{m}: report identity or hash mismatch")
            files.add(rel)
            artifacts = report.get("artifact", [])
            specs = layout.MODE_SPECS[m]
            if not isinstance(artifacts, list) or len(artifacts) != len(specs):
                raise PublishError(f"{name}/{m}: missing or duplicated artifacts")
            expected = {
                (s.role, layout.filename(name, s), s.format, s.primary) for s in specs
            }
            actual = {
                (a.get("role"), a.get("path"), a.get("format"), a.get("primary"))
                for a in artifacts
            }
            if actual != expected:
                raise PublishError(f"{name}/{m}: artifact identities mismatch")
            for a in artifacts:
                artifact_rel = f"{name}/{m}/{a['path']}"
                artifact = contained(root, artifact_rel)
                if layout.sha256_file(artifact) != a.get(
                    "sha256"
                ) or artifact.stat().st_size != a.get("size_bytes"):
                    raise PublishError(f"{name}/{m}: artifact hash or size mismatch")
                files.add(artifact_rel)
            expected_inputs = {
                "bpf": set(),
                "rv32": {"gate_bpf"},
                "jit": {"bpf_object"},
                "bpf-xpost": {"bpf_object", "map_index_basis"},
            }[m]
            input_rows = report.get("input_artifact", [])
            if (
                not isinstance(input_rows, list)
                or {i.get("role") for i in input_rows} != expected_inputs
                or len(input_rows) != len(expected_inputs)
            ):
                raise PublishError(
                    f"{name}/{m}: missing or duplicated input dependencies"
                )
            for item in input_rows:
                raw = item.get("path", "")
                if not raw or "\\" in raw or PurePosixPath(raw).is_absolute():
                    raise PublishError(f"{name}/{m}: invalid input path")
                cursor = report_path.parent
                for part in PurePosixPath(raw).parts:
                    cursor = cursor.parent if part == ".." else cursor / part
                    if cursor.is_symlink():
                        raise PublishError(f"{name}/{m}: input uses symlink")
                target = (report_path.parent / raw).resolve()
                if not target.is_relative_to((root / name).resolve()):
                    raise PublishError(f"{name}/{m}: input escapes program")
                input_rel = target.relative_to(root.resolve()).as_posix()
                expected_input = (
                    root / name / "rv32/report.toml"
                    if item["role"] == "map_index_basis"
                    else root / name / "bpf" / f"{name}_bpf.o"
                )
                if target != expected_input:
                    raise PublishError(f"{name}/{m}: incorrect path for {item['role']}")
                lexical = Path(os.path.normpath(str(report_path.parent / raw)))
                contained(root, lexical.relative_to(root).as_posix())
                if target != lexical or layout.sha256_file(target) != item.get(
                    "sha256"
                ):
                    raise PublishError(f"{name}/{m}: input hash or symlink mismatch")
                inputs.append(input_rel)
            verification = report.get("verification", {})
            bpf_hash = layout.sha256_file(contained(root, f"{name}/bpf/{name}_bpf.o"))
            if (
                verification.get("status") != "accepted"
                or verification.get("input_sha256") != bpf_hash
                or not verification.get("verifier_id")
            ):
                raise PublishError(
                    f"{name}/{m}: verification was not accepted for these BPF bytes"
                )
            layout.load_mode(root, name, m)
    if not set(inputs) <= files:
        raise PublishError("input artifact is not in the official file set")
    if set(layout.verify_tree(root)) != {
        (p, m) for p in programs for m in layout.MODES
    }:
        raise PublishError("tree verification failed")
    return files


def sums(root: Path, files: set[str]) -> str:
    return "".join(
        f"{layout.sha256_file(contained(root, f))}  {f}\n" for f in sorted(files)
    )


def verify_package(root: Path, programs: list[str]) -> None:
    files = official(root, programs)
    actual = {
        p.relative_to(root).as_posix()
        for p in root.rglob("*")
        if p.is_file() or p.is_symlink()
    }
    if actual != files | {"SHA256SUMS"} or (root / "SHA256SUMS").read_text() != sums(
        root, files
    ):
        raise PublishError("package file set or checksum mismatch")


def release_repository() -> str:
    remote = run(["git", "remote", "get-url", "origin"]).stdout.strip()
    match = re.fullmatch(
        r"(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/)([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?",
        remote,
    )
    if match is None:
        raise PublishError("origin must be an SSH or HTTPS github.com repository")
    return "github.com/" + match[1]


def absent(tag: str, repository: str) -> None:
    if run(["git", "tag", "--list", tag]).stdout.strip():
        raise PublishError(f"local tag already exists: {tag}")
    if run(["git", "ls-remote", "--tags", "origin", f"refs/tags/{tag}"]).stdout.strip():
        raise PublishError(f"remote tag already exists: {tag}")
    release = run(
        ["gh", "release", "view", tag, "--repo", repository], allow_failure=True
    )
    if release.returncode == 0:
        raise PublishError(f"GitHub release already exists: {tag}")
    if "release not found" not in (release.stderr + release.stdout).lower():
        raise PublishError("could not check GitHub release")


def main(argv: list[str] | None = None) -> int:
    global LOG_DIR
    LOG_DIR = None
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--firmware", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--program", action="append")
    parser.add_argument("--out", type=Path)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--dry-run", action="store_true")
    group.add_argument("--package-only", action="store_true")
    parser.add_argument("--draft", action="store_true")
    args = parser.parse_args(argv)
    try:
        print("[1/5] Check source, firmware, tools, and publication destination")
        if (
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", args.tag)
            or ".." in args.tag
            or args.tag.endswith(".")
        ):
            raise PublishError("tag must be a safe single path segment")
        firmware = args.firmware.expanduser().resolve()
        if not firmware.is_file():
            raise PublishError(f"firmware not found: {firmware}")
        firmware_hash = layout.sha256_file(firmware)
        out = (
            (
                args.out
                or Path(tempfile.gettempdir()) / "libbpf-mcu-publications" / args.tag
            )
            .expanduser()
            .absolute()
        )
        if (
            out.resolve().is_relative_to(ROOT.resolve())
            or out.exists()
            or out.is_symlink()
        ):
            raise PublishError(
                f"output must be a new directory outside the repository: {out}"
            )
        commit = run(["git", "rev-parse", "HEAD"]).stdout.strip()
        status = run(["git", "status", "--porcelain", "--untracked-files=all"]).stdout
        branch = run(["git", "branch", "--show-current"]).stdout.strip()
        print(f"source commit={commit} branch={branch} dirty={bool(status)}")
        if not args.package_only:
            if (
                status
                or branch != "main"
                or run(["git", "rev-parse", "refs/heads/main"]).stdout.strip() != commit
            ):
                raise PublishError(
                    "formal and dry-run publication require clean local main at HEAD"
                )
            repository = release_repository()
            run(["gh", "auth", "status", "--hostname", "github.com"])
            absent(args.tag, repository)
        from build import (
            _default_inputs,
            ensure_tool,
            load_mem_map_from_firmware,
            CLANG,
            DEFAULT_OBJDUMP,
            DEFAULT_OBJCOPY,
        )
        from prevail_gate import prevail_bin

        paths = _default_inputs()
        names = [p.stem for p in paths]
        programs = sorted(args.program if args.program is not None else names)
        if (
            not programs
            or len(set(programs)) != len(programs)
            or any(names.count(p) != 1 for p in programs)
        ):
            raise PublishError(
                "program selection contains unknown, ambiguous, or duplicate stems"
            )
        for tool in (CLANG, "ninja", "cargo", DEFAULT_OBJDUMP, DEFAULT_OBJCOPY):
            if shutil.which(tool) is None:
                raise PublishError(f"required tool missing: {tool}")
        if not prevail_bin().is_file() or not os.access(prevail_bin(), os.X_OK):
            raise PublishError(f"PREVAIL executable missing: {prevail_bin()}")
        load_mem_map_from_firmware(firmware, ensure_tool())
        work = Path(tempfile.mkdtemp(prefix="libbpf-mcu-publish-"))
        LOG_DIR = work
        print(f"Diagnostic work directory retained: {work}")
        with nullcontext(work) as temp:
            build = temp / "build"
            build.mkdir()
            stage = temp / "stage" / "libbpf-mcu-artifacts"
            stage.mkdir(parents=True)
            extract = temp / "extract"
            extract.mkdir()
            for program in programs:
                for target, engine in (
                    ("bpf", None),
                    ("esp32c3", None),
                    ("jit", None),
                    ("esp32c3", "rbpf"),
                ):
                    cmd = [
                        sys.executable,
                        str(ROOT / "make/cli.py"),
                        "build",
                        target,
                        "-c",
                        program,
                        "--build-dir",
                        str(build),
                    ]
                    if target != "bpf":
                        cmd += ["--firmware", str(firmware)]
                    if engine:
                        cmd += ["--engine", engine]
                    print(f"[2/5] Build {program}/{engine or target}", flush=True)
                    try:
                        run(cmd)
                    except PublishError as exc:
                        raise PublishError(
                            f"{program}/{engine or target}: {exc}"
                        ) from exc
            print("[3/5] Validate all programs and four-mode dependencies")
            files = official(build, programs)
            for program in programs:
                for mode in ("rv32", "jit", "bpf-xpost"):
                    report = document(build / program / mode / "report.toml")
                    if report.get("firmware", {}).get("sha256") != firmware_hash:
                        raise PublishError(f"{program}/{mode}: firmware hash mismatch")
            print("[4/5] Stage, checksum, archive, extract, and validate again")
            for rel in sorted(files):
                dest = stage / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(contained(build, rel), dest)
            (stage / "SHA256SUMS").write_text(sums(stage, files))
            verify_package(stage, programs)
            archive_name = f"libbpf-mcu-artifacts-{args.tag}.tar.gz"
            archive = temp / archive_name
            with tarfile.open(archive, "w:gz") as tar:
                tar.add(stage, arcname=stage.name, recursive=True)
            with tarfile.open(archive, "r:gz") as tar:
                for member in tar.getmembers():
                    path = PurePosixPath(member.name)
                    if (
                        path.is_absolute()
                        or ".." in path.parts
                        or not path.parts
                        or path.parts[0] != stage.name
                        or not (member.isfile() or member.isdir())
                    ):
                        raise PublishError(f"unsafe archive entry: {member.name}")
                tar.extractall(extract, filter="data")
            verify_package(extract / stage.name, programs)
            out.mkdir(parents=True, exist_ok=False)
            shutil.copyfile(archive, out / archive_name)
            (out / "SHA256SUMS").write_text(
                f"{layout.sha256_file(out / archive_name)}  {archive_name}\n"
            )
            print(f"verified archive: {out / archive_name}")
            if not args.package_only and not args.dry_run:
                absent(args.tag, repository)
                if (
                    run(["git", "rev-parse", "HEAD"]).stdout.strip() != commit
                    or run(
                        ["git", "status", "--porcelain", "--untracked-files=all"]
                    ).stdout
                    != status
                    or run(["git", "branch", "--show-current"]).stdout.strip() != "main"
                ):
                    raise PublishError("repository state changed during build")
                reply = input(
                    f"Type {args.tag} {commit} to create the tag and release in {repository}: "
                )
                if reply != f"{args.tag} {commit}":
                    raise PublishError("release confirmation denied")
                absent(args.tag, repository)
                if (
                    run(["git", "rev-parse", "HEAD"]).stdout.strip() != commit
                    or run(
                        ["git", "status", "--porcelain", "--untracked-files=all"]
                    ).stdout
                    != status
                    or run(["git", "branch", "--show-current"]).stdout.strip() != "main"
                ):
                    raise PublishError("repository state changed before release")
                if layout.sha256_file(firmware) != firmware_hash:
                    raise PublishError("firmware changed during publication")
                if release_repository() != repository:
                    raise PublishError("publication repository changed during build")
                toolchain = {
                    mode: document(stage / programs[0] / mode / "report.toml").get(
                        "toolchain", {}
                    )
                    for mode in layout.MODES
                }
                notes = f"Source commit: {commit}\nSource branch: {branch}; dirty: {bool(status)}\nFirmware SHA256: {firmware_hash}\nToolchains: {toolchain}\n"
                print("[5/5] Create confirmed tag and upload release assets")
                # Creating the ref is atomic: a concurrent tag cannot be reused.
                run(
                    [
                        "gh",
                        "api",
                        "--hostname",
                        "github.com",
                        "--method",
                        "POST",
                        f"repos/{repository.removeprefix('github.com/')}/git/refs",
                        "-f",
                        f"ref=refs/tags/{args.tag}",
                        "-f",
                        f"sha={commit}",
                    ]
                )
                print(
                    f"Created confirmed tag {args.tag} at {commit}; failures after this point require manual inspection"
                )
                cmd = [
                    "gh",
                    "release",
                    "create",
                    args.tag,
                    str(out / archive_name),
                    str(out / "SHA256SUMS"),
                    "--repo",
                    repository,
                    "--verify-tag",
                    "--target",
                    commit,
                    "--title",
                    f"libbpf-mcu artifacts {args.tag}",
                    "--notes",
                    notes,
                ]
                if args.draft:
                    cmd.append("--draft")
                run(cmd)
                print(f"created release {args.tag}")
            else:
                print("[5/5] Local validation complete; upload disabled")
        return 0
    except (
        PublishError,
        layout.LayoutError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        EOFError,
        tomllib.TOMLDecodeError,
    ) as exc:
        print(f"publication failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
