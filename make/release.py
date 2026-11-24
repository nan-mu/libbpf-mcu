"""Prepare and verify the formal archive batch before any publication step."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from build import DEFAULT_BUILD_DIR
from build_state import read_state, verify_state
from build_steps import check_deployment
from layout import (
    MODES,
    ROOT,
    LayoutError,
    contained,
    container_path,
    load_index,
    lock,
    sha256_file,
    state_path,
    write_if_changed,
)
from release_firmware import CARRIERS, PROGRAMS, cold_capacity, firmware_name
from retarget import retarget

LEDGER = "release.json"
RELEASE_TAG = re.compile(r"refs/tags/(v0\.1\.(0|[1-9][0-9]*))(\^\{\})?")


def expected_files(program: str) -> set[str]:
    return {
        "index.toml", "report.md", f"{program}.c",
        f"objects/{program}_bpf.o", f"objects/{program}_rv32.o",
        *(container_path(Path(), program, mode).relative_to(program).as_posix()
          for mode in MODES),
    }


def require_program(directory: Path, program: str) -> dict:
    try:
        index = load_index(directory, program)
    except (OSError, ValueError) as exc:
        raise LayoutError(f"{program}: {exc}") from exc
    missing = set(MODES) - {row["name"] for row in index["mode"]}
    if missing:
        mode = sorted(missing)[0]
        raise LayoutError(f"{program}/{mode}: missing required deployment")
    paths = set()
    for path in directory.rglob("*"):
        relative = path.relative_to(directory).as_posix()
        if not path.is_symlink() and path.is_dir() and relative in ("containers", "objects"):
            continue
        if path.is_symlink() or not path.is_file():
            raise LayoutError(f"{program}: invalid member {relative}")
        paths.add(relative)
    wanted = expected_files(program)
    if paths != wanted:
        raise LayoutError(f"{program}: missing {sorted(wanted - paths)}, extra {sorted(paths - wanted)}")
    return index


def read_archive_paths(tool: str, archive: Path, program: str) -> set[str]:
    listing = subprocess.check_output(
        [tool, "l", "-t7z", "-slt", "-ba", "-sccUTF-8", "--", archive],
        text=True,
        encoding="utf-8",
    )
    files = set()
    seen = set()
    wanted = expected_files(program)
    for record in listing.strip().split("\n\n"):
        fields = dict(line.split(" = ", 1) for line in record.splitlines() if " = " in line)
        relative = fields.get("Path")
        if relative is None:
            raise LayoutError(f"{program}: invalid archive listing")
        if relative in seen:
            raise LayoutError(f"{program}: duplicate archive member {relative!r}")
        seen.add(relative)
        attrs = fields.get("Attributes", "").split()
        directory = fields.get("Folder") == "+" or bool(attrs and attrs[0].startswith("D"))
        if (
            "Symbolic Link" in fields
            or "Hard Link" in fields
            or (len(attrs) > 1 and not attrs[1].startswith(("d", "-")))
            or relative not in ({"objects", "containers"} if directory else wanted)
        ):
            raise LayoutError(f"{program}: unexpected archive member {relative!r}")
        if not directory:
            files.add(relative)
    return files


def extract_archive(tool: str, archive: Path, directory: Path, program: str) -> dict:
    listed = read_archive_paths(tool, archive, program)
    directory.mkdir()
    subprocess.run([tool, "x", "-t7z", "-bd", "-y", f"-o{directory}", "--", archive],
                   check=True, stdout=subprocess.DEVNULL)
    index = require_program(directory, program)
    if listed != expected_files(program):
        raise LayoutError(f"{program}: listing differs from extracted files")
    return index


def verify_deployment(directory: Path, index: dict, row: dict, build: Path,
                      carrier: str, checked: dict, work: Path) -> dict:
    name, mode = index["program"], row["name"]
    state = state_path(build, name, mode)
    if reason := verify_state(state, checked):
        raise LayoutError(reason)
    cfg = read_state(state.with_name("config.json"))
    source = cfg["firmware_provenance"]
    expected = firmware_name(carrier, mode)
    if (source.get("file"), source.get("path"), source.get("cold_capacity")) != (
        expected, cfg["firmware"], cold_capacity(carrier)
    ):
        raise LayoutError(f"expected a release build using supplied firmware {expected}")
    if sha256_file(Path(cfg["firmware"])) != cfg["firmware_digest"] or cfg["firmware_digest"] != source["sha256"]:
        raise LayoutError("firmware digest differs from the verified build")
    file = directory / row["elf"]["path"]
    data = file.read_bytes()
    meta, image = check_deployment(cfg, data)
    if meta.name != name:
        raise LayoutError(f"unexpected embedded name {meta.name!r}")
    subprocess.run([cfg["tool"], "scan", file], check=True, stdout=subprocess.DEVNULL)
    bindings = None
    if mode == "ebpf":
        bindings = json.loads(subprocess.check_output(
            [cfg["tool"], "check-ebpf", file, directory / index["bpf"]["path"]], text=True
        ))
    elif retarget(directory, index, row, cfg, work) != data:
        raise LayoutError("rebuilding from archived objects differs from the linked deployment")
    return {
        **row["elf"],
        "name": mode,
        "image_bytes": len(image),
        "slot_address": hex(meta.slot_address),
        "helper_address": hex(meta.helper_address),
        "slot_capacity": cfg["slot_len"],
        "firmware": source,
        "maps": [dict(name=m.name, vma=hex(m.map_vma), capacity=m.len) for m in meta.maps],
        "rbpf_bindings": bindings,
    }


def archiver() -> str:
    tool = shutil.which("7zz") or shutil.which("7z")
    if tool is None:
        raise LayoutError("7zz or 7z is required to prepare a release")
    return tool


def verify_batch(build: Path, archives: Path, unpacked: Path, ledger: dict | None = None) -> list[dict]:
    names = {path.name for path in archives.iterdir() if path.suffix.lower() == ".7z"}
    wanted = {f"{name}.7z" for name in PROGRAMS}
    if names != wanted:
        raise LayoutError(f"release archives: missing {sorted(wanted - names)}, extra {sorted(names - wanted)}")
    extra = {p.parent.name for p in build.glob("*/index.toml")} - set(PROGRAMS)
    if extra:
        raise LayoutError(f"release build: unexpected programs {sorted(extra)}")
    tool = archiver()
    entries = []
    checked = {}
    unpacked.mkdir()
    for carrier, programs in CARRIERS.items():
        for name in programs:
            archive = contained(archives, f"{name}.7z")
            digest = sha256_file(archive)
            if ledger is not None and ledger.get(archive.name) != digest:
                raise LayoutError(f"{name}: archive SHA-256 differs from release ledger")
            directory = unpacked / name
            index = extract_archive(tool, archive, directory, name)
            require_program(build / name, name)
            for path in sorted(expected_files(name)):
                if sha256_file(directory / path) != sha256_file(build / name / path):
                    raise LayoutError(f"{name}: extracted {path} differs from the build")
            modes = []
            for row in index["mode"]:
                with tempfile.TemporaryDirectory(dir=unpacked.parent) as tmp:
                    try:
                        modes.append(verify_deployment(directory, index, row, build, carrier,
                                                       checked, Path(tmp)))
                    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
                        raise LayoutError(f"{name}/{row['name']}: {exc}") from exc
            entries.append({"program": name, "archive": archive.name, "sha256": digest,
                            "members": sorted(expected_files(name)), "modes": modes})
            print(f"verified {archive.name}: {', '.join(row['name'] for row in modes)}")
    return entries


def clean_commit() -> str:
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT).strip():
        raise LayoutError("prepare release from a clean worktree")
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()


def prepare(build: Path, destination: Path, firmware_dir: Path | None) -> None:
    if destination.exists() or destination.is_relative_to(build):
        raise LayoutError("--archive-dir must be a new directory outside the build root")
    tool = archiver()
    commit = clean_commit()
    command = [sys.executable, ROOT / "make" / "cli.py", "build"]
    if build != DEFAULT_BUILD_DIR:
        command.extend(["--build-dir", build])
    if firmware_dir is not None:
        command.extend(["--firmware-dir", firmware_dir])
    subprocess.run(command, check=True, cwd=ROOT)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with lock(build), tempfile.TemporaryDirectory(dir=destination.parent) as temp:
        stage = Path(temp) / "archives"
        stage.mkdir()
        for name in PROGRAMS:
            require_program(build / name, name)
            subprocess.run([tool, "a", "-t7z", "-bd", "-mtm=off", "--", stage / f"{name}.7z", "."],
                           cwd=build / name, check=True, stdout=subprocess.DEVNULL)
        entries = verify_batch(build, stage, Path(temp) / "unpacked")
        if clean_commit() != commit:
            raise LayoutError("checkout changed during preparation")
        write_if_changed(stage / LEDGER, (json.dumps({"commit": commit, "archives": entries}, indent=2) + "\n").encode())
        if destination.exists():
            raise LayoutError(f"archive directory already exists: {destination}")
        stage.rename(destination)


def select_tag(refs: str, commit: str, allocated: str | None = None) -> str:
    tags = {}
    peeled = {}
    for line in refs.splitlines():
        oid, ref = line.split("\t", 1)
        if match := RELEASE_TAG.fullmatch(ref):
            tag = match[1]
            (peeled if match[3] else tags)[tag] = oid
    matching = [tag for tag, oid in tags.items() if peeled.get(tag, oid) == commit]
    if len(matching) > 1:
        raise LayoutError(f"ambiguous v0.1 tags for {commit}: {', '.join(matching)}")
    if matching:
        return matching[0]
    if allocated is not None:
        match = RELEASE_TAG.fullmatch(f"refs/tags/{allocated}")
        if match is None or match[3] is not None:
            raise LayoutError(f"allocated tag is outside the v0.1 series: {allocated}")
        if allocated not in tags:
            return allocated
    patch = max((int(tag.rsplit(".", 1)[1]) for tag in tags), default=-1) + 1
    return f"v0.1.{patch}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for verb in ("prepare", "verify"):
        command = commands.add_parser(verb)
        command.add_argument("--build-dir", type=Path, default=DEFAULT_BUILD_DIR)
        command.add_argument("--archive-dir", type=Path, required=True)
        if verb == "verify":
            command.add_argument("--unpack-dir", type=Path, required=True)
        else:
            command.add_argument("--firmware-dir", type=Path)
    tag = commands.add_parser("next-tag")
    tag.add_argument("--commit", required=True)
    tag.add_argument("--remote", default="origin")
    tag.add_argument("--allocated", help="tag already allocated locally for this commit")
    args = parser.parse_args()
    try:
        if args.command == "next-tag":
            refs = subprocess.check_output(["git", "ls-remote", "--tags", args.remote], cwd=ROOT, text=True)
            print(select_tag(refs, args.commit, args.allocated))
        elif args.command == "prepare":
            firmware_dir = (
                args.firmware_dir.expanduser().resolve() if args.firmware_dir is not None else None
            )
            prepare(args.build_dir.resolve(), args.archive_dir.resolve(), firmware_dir)
        else:
            build, archives = args.build_dir.resolve(), args.archive_dir.resolve()
            document = read_state(contained(archives, LEDGER))
            if document["commit"] != clean_commit():
                raise LayoutError("release ledger is for a different commit")
            digests = {entry["archive"]: entry["sha256"] for entry in document["archives"]}
            if set(digests) != {f"{name}.7z" for name in PROGRAMS} or len(document["archives"]) != len(PROGRAMS):
                raise LayoutError("release ledger does not identify the complete program matrix")
            with lock(build):
                entries = verify_batch(build, archives, args.unpack_dir.resolve(), digests)
            if entries != document["archives"]:
                raise LayoutError("release ledger differs from the verified archives and bindings")
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
