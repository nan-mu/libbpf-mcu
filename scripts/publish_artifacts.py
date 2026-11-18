#!/usr/bin/env python3
"""Build and publish a self-contained, verified artifact archive."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "make"))
import layout

LOG_DIR: Path | None = None


class PublishError(Exception):
    pass


@dataclass(frozen=True)
class BuildSet:
    id: str
    program: str
    modes: tuple[str, ...]
    firmware: Path | None
    firmware_sha256: str | None
    image_name: str | None
    slot_symbol: str | None
    release: bool
    mem_map: Any | None


def load_plan(path: Path) -> tuple[BuildSet, ...]:
    """Validate every plan entry and inspect firmware before returning any set."""
    from build import (
        _default_inputs,
        apply_slot_symbol,
        ensure_tool,
        load_mem_map_from_firmware,
    )

    doc = document(path)
    if set(doc) != {"schema", "build"} or doc["schema"] != "libbpf-mcu.release-plan.v1":
        raise PublishError("invalid release plan schema or keys")
    rows = doc["build"]
    if not isinstance(rows, list) or not rows:
        raise PublishError("release plan must contain build entries")
    names = [p.stem for p in _default_inputs()]
    ids: set[str] = set()
    sets = []
    allowed = {
        "id",
        "program",
        "modes",
        "firmware",
        "image_name",
        "slot_symbol",
        "release",
    }
    for row in rows:
        if not isinstance(row, dict) or set(row) - allowed:
            raise PublishError("invalid build entry or unknown keys")
        ident, program, modes = row.get("id"), row.get("program"), row.get("modes")
        if not isinstance(ident, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_-]*", ident
        ):
            raise PublishError(f"unsafe build id: {ident!r}")
        if ident.casefold() in ids:
            raise PublishError(f"duplicate build id: {ident}")
        ids.add(ident.casefold())
        if not isinstance(program, str) or names.count(program) != 1:
            raise PublishError(f"unknown or ambiguous program: {program!r}")
        if (
            not isinstance(modes, list)
            or not modes
            or any(
                not isinstance(mode, str) or mode not in layout.MODES for mode in modes
            )
            or len(set(modes)) != len(modes)
        ):
            raise PublishError(f"{ident}: invalid modes")
        release = row.get("release", False)
        if type(release) is not bool:
            raise PublishError(f"{ident}: release must be a boolean")
        image_name = row.get("image_name")
        if image_name is not None and (
            not isinstance(image_name, str)
            or not re.fullmatch(r"[A-Za-z0-9_]{1,31}", image_name)
        ):
            raise PublishError(f"{ident}: invalid image name")
        slot = row.get("slot_symbol")
        if slot is not None and (
            not isinstance(slot, str)
            or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", slot)
        ):
            raise PublishError(f"{ident}: invalid slot symbol")
        if slot and "jit" in modes:
            raise PublishError(f"{ident}: jit does not support slot_symbol")
        backend = any(mode != "bpf" for mode in modes)
        raw_firmware = row.get("firmware")
        if not backend and (
            raw_firmware is not None
            or image_name is not None
            or slot is not None
            or release
        ):
            raise PublishError(f"{ident}: backend options require a backend mode")
        if backend and (not isinstance(raw_firmware, str) or not raw_firmware):
            raise PublishError(f"{ident}: firmware is required")
        firmware = (path.parent / raw_firmware).resolve() if backend else None
        if firmware is not None and not firmware.is_file():
            raise PublishError(f"{ident}: firmware not found: {firmware}")
        sets.append(
            BuildSet(
                ident,
                program,
                tuple(modes),
                firmware,
                layout.sha256_file(firmware) if firmware else None,
                image_name,
                slot,
                release,
                None,
            )
        )
    if not any(item.firmware for item in sets):
        return tuple(sets)
    from dataclasses import replace

    try:
        tool = ensure_tool(force=True)
    except SystemExit as exc:
        raise PublishError("host tool build failed") from exc
    inspected = []
    for item in sets:
        if item.firmware is None:
            inspected.append(item)
            continue
        try:
            mem = load_mem_map_from_firmware(item.firmware, tool)
            if item.slot_symbol:
                mem = apply_slot_symbol(mem, item.firmware, tool, item.slot_symbol)
        except SystemExit as exc:
            raise PublishError(f"{item.id}: firmware inspection failed") from exc
        inspected.append(replace(item, mem_map=mem))
    return tuple(inspected)


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


def official(
    root: Path, programs: list[str], expected_modes: tuple[str, ...] | None = None
) -> set[str]:
    """Validate the protocol and return precisely the files allowed in the archive."""
    root = root.resolve()
    expected_modes = expected_modes if expected_modes is not None else layout.MODES
    index = document(contained(root, "index.toml"))
    rows = index.get("program", [])
    if (
        index.get("schema") != layout.SCHEMA_INDEX
        or not isinstance(rows, list)
        or [r.get("name") for r in rows] != programs
    ):
        raise PublishError("index programs are missing, duplicated, or not sorted")
    files = {"index.toml"}
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
            or [r.get("name") for r in modes] != list(expected_modes)
        ):
            raise PublishError(f"{name}: missing, duplicated, stale, or failed modes")
        files.add(row["manifest"])
        for mode in modes:
            files.update(layout.validate_release_mode(root, name, mode["name"]))
    if set(layout.verify_tree(root)) != {
        (p, m) for p in programs for m in expected_modes
    }:
        raise PublishError("tree verification failed")
    return files


def sums(root: Path, files: set[str]) -> str:
    return "".join(
        f"{layout.sha256_file(contained(root, f))}  {f}\n" for f in sorted(files)
    )


def produced_modes(requested: tuple[str, ...]) -> tuple[str, ...]:
    modes = set(requested) | {"bpf"}
    if "bpf-xpost" in modes:
        modes.add("rv32")
    return tuple(mode for mode in layout.MODES if mode in modes)


def inspect_container(path: Path) -> dict:
    from build import tool_bin_path

    result = run([str(tool_bin_path()), "scan", str(path), "--json"])
    try:
        data = json.loads(result.stdout)
        if not isinstance(data, dict):
            raise ValueError("expected an object")
        return data
    except (ValueError, TypeError) as exc:
        raise PublishError(f"invalid container inspection output: {path}") from exc


def verify_package(root: Path, sets: tuple[BuildSet, ...]) -> None:
    index = document(contained(root, "release-index.toml"))
    rows = index.get("set")
    if (
        index.get("schema") != "libbpf-mcu.release-index.v1"
        or not isinstance(rows, list)
        or len(rows) != len(sets)
    ):
        raise PublishError("invalid release index")
    files = {"release-index.toml"}
    for item, row in zip(sets, rows):
        rel = f"sets/{item.id}"
        modes = produced_modes(item.modes)
        expected = {
            "id": item.id,
            "program": item.program,
            "root": rel,
            "requested_modes": list(item.modes),
            "produced_modes": list(modes),
        }
        if item.firmware_sha256 is not None:
            expected["firmware_sha256"] = item.firmware_sha256
        if row != expected:
            raise PublishError(f"{item.id}: release index mismatch")
        set_root = contained(root, rel)
        for path in official(set_root, [item.program], modes):
            files.add(f"{rel}/{path}")
        for mode in modes:
            if mode != "bpf":
                report = document(set_root / item.program / mode / "report.toml")
                firmware = report.get("firmware", {})
                if firmware.get("sha256") != item.firmware_sha256:
                    raise PublishError(f"{item.id}/{mode}: firmware hash mismatch")
                for key in (
                    "helper_addr",
                    "slot_addr",
                    "slot_len",
                    "table_addr",
                    "table_len",
                ):
                    try:
                        matches = int(firmware[key], 0) == getattr(item.mem_map, key)
                    except (KeyError, TypeError, ValueError, AttributeError):
                        matches = False
                    if not matches:
                        raise PublishError(f"{item.id}/{mode}: firmware {key} mismatch")
                options = report.get("build", {}).get("options", {})
                for key, expected in (
                    ("image_name", item.image_name or ""),
                    ("release", "1" if item.release else "0"),
                    ("slot_symbol", item.slot_symbol or ""),
                ):
                    if options.get(key) != expected:
                        raise PublishError(
                            f"{item.id}/{mode}: build option {key} mismatch"
                        )
                spec = next(
                    s for s in layout.MODE_SPECS[mode] if s.role == "xpost_container"
                )
                container = (
                    set_root / item.program / mode / layout.filename(item.program, spec)
                )
                metadata = inspect_container(container)
                expected = {
                    "name": item.image_name or item.program,
                    "slot_address": item.mem_map.slot_addr,
                    "helper_address": item.mem_map.helper_addr,
                    "machine": 1,
                }
                if metadata != expected:
                    raise PublishError(f"{item.id}/{mode}: container metadata mismatch")
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
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--tag", required=True)
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
        plan = args.plan.expanduser().resolve()
        plan_hash = layout.sha256_file(plan)
        sets = load_plan(plan)
        if layout.sha256_file(plan) != plan_hash:
            raise PublishError("plan changed during preflight")
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

            def check_remote_main() -> None:
                try:
                    remote = run(["git", "ls-remote", "origin", "refs/heads/main"])
                except PublishError as exc:
                    raise PublishError(
                        "cannot check origin main; local main may be behind or divergent; manually update and retry"
                    ) from exc
                match = re.fullmatch(
                    r"([0-9a-fA-F]{40}|[0-9a-fA-F]{64})\s+refs/heads/main\s*",
                    remote.stdout,
                )
                if not match or match.group(1).lower() != commit.lower():
                    raise PublishError(
                        "origin main is invalid or differs; local main may be behind or divergent; manually update and retry"
                    )

            if (
                status
                or branch != "main"
                or run(["git", "rev-parse", "refs/heads/main"]).stdout.strip() != commit
            ):
                raise PublishError(
                    "formal and dry-run publication require clean local main at HEAD"
                )
            check_remote_main()
            repository = release_repository()
            run(["gh", "auth", "status", "--hostname", "github.com"])
            absent(args.tag, repository)
        from build import CLANG, DEFAULT_OBJDUMP, DEFAULT_OBJCOPY
        from prevail_gate import prevail_bin

        for tool in (CLANG, "ninja", "cargo", DEFAULT_OBJDUMP, DEFAULT_OBJCOPY):
            if shutil.which(tool) is None:
                raise PublishError(f"required tool missing: {tool}")
        if any(set(item.modes) != {"bpf"} for item in sets):
            if not prevail_bin().is_file() or not os.access(prevail_bin(), os.X_OK):
                raise PublishError(f"PREVAIL executable missing: {prevail_bin()}")
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
            files = {"release-index.toml"}
            index_lines = ['schema = "libbpf-mcu.release-index.v1"', ""]
            for item in sets:
                set_build = build / item.id
                modes = produced_modes(item.modes)
                # rbpf produces rv32 and bpf-xpost together; run it before jit.
                commands = []
                if "bpf-xpost" in modes:
                    commands.append(("bpf-xpost", "esp32c3", "rbpf"))
                elif "rv32" in modes:
                    commands.append(("rv32", "esp32c3", None))
                if "jit" in modes:
                    commands.append(("jit", "jit", None))
                if not commands:
                    commands.append(("bpf", "bpf", None))
                for mode, target, engine in commands:
                    cmd = [
                        sys.executable,
                        str(ROOT / "make/cli.py"),
                        "build",
                        target,
                        "-c",
                        item.program,
                        "--build-dir",
                        str(set_build),
                    ]
                    if mode != "bpf":
                        cmd += ["--firmware", str(item.firmware)]
                        if item.image_name:
                            cmd += ["--image-name", item.image_name]
                        if item.release:
                            cmd.append("--release")
                        if item.slot_symbol and mode in ("rv32", "bpf-xpost"):
                            cmd += ["--slot-symbol", item.slot_symbol]
                    if engine:
                        cmd += ["--engine", engine]
                    print(f"[2/5] Build {item.id}/{mode}", flush=True)
                    run(cmd)
                for rel in official(set_build, [item.program], modes):
                    dest_rel = f"sets/{item.id}/{rel}"
                    dest = stage / dest_rel
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(contained(set_build, rel), dest)
                    files.add(dest_rel)
                row = {
                    "id": item.id,
                    "program": item.program,
                    "root": f"sets/{item.id}",
                    "requested_modes": list(item.modes),
                    "produced_modes": list(modes),
                }
                if item.firmware_sha256 is not None:
                    row["firmware_sha256"] = item.firmware_sha256
                index_lines.append("[[set]]")
                index_lines.extend(
                    f"{key} = {json.dumps(value)}" for key, value in row.items()
                )
                index_lines.append("")
            print("[3/5] Validate sets and dependencies")
            (stage / "release-index.toml").write_text("\n".join(index_lines))
            print("[4/5] Stage, checksum, archive, extract, and validate again")
            (stage / "SHA256SUMS").write_text(sums(stage, files))
            verify_package(stage, sets)
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
            verify_package(extract / stage.name, sets)
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
                check_remote_main()
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
                if (
                    run(["git", "rev-parse", "refs/heads/main"]).stdout.strip()
                    != commit
                ):
                    raise PublishError("local main changed before release")
                check_remote_main()
                if layout.sha256_file(plan) != plan_hash:
                    raise PublishError("plan changed during publication")
                for item in sets:
                    if (
                        item.firmware
                        and layout.sha256_file(item.firmware) != item.firmware_sha256
                    ):
                        raise PublishError(
                            f"{item.id}: firmware changed during publication"
                        )
                if release_repository() != repository:
                    raise PublishError("publication repository changed during build")
                notes = f"Source commit: {commit}\nSource branch: {branch}; dirty: {bool(status)}\nPlan SHA256: {plan_hash}\n"
                for item in sets:
                    notes += f"Set {item.id}: {item.program}, requested {', '.join(item.modes)}, produced {', '.join(produced_modes(item.modes))}\n"
                    if item.firmware:
                        notes += f"Firmware SHA256: {item.firmware_sha256}\n"
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
