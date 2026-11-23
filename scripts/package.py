"""Build and verify one offline 7z archive per release program."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "make"))

from layout import (  # noqa: E402
    MODES,
    LayoutError,
    check_program,
    contained,
    load_index,
    lock,
    sha256_file,
    write_index,
)

SCHEMA = "libbpf-mcu.release-plan.v2"
DEFAULT_PLAN = ROOT / "release" / "programs.toml"
DEFAULT_OUT = ROOT / "build" / "packages"


@dataclass(frozen=True)
class Firmware:
    path: Path
    sha256: str
    image_name: str | None
    slot_symbol: str | None


@dataclass(frozen=True)
class Program:
    name: str
    source: Path
    modes: tuple[str, ...]
    firmware: dict[str, Firmware]


def _require_fields(row: object, allowed: set[str], label: str) -> dict:
    if not isinstance(row, dict) or row.keys() - allowed:
        raise LayoutError(
            f"{label}: expected these fields: {', '.join(sorted(allowed))}"
        )
    return row


def _input(root: Path, path: str, label: str) -> Path:
    try:
        return contained(root, path)
    except LayoutError as exc:
        raise LayoutError(f"{label}: {exc}") from exc


def _check_firmware(label: str, firmware: Firmware) -> None:
    if not firmware.path.is_file():
        raise LayoutError(f"{label}: firmware missing: {firmware.path}")
    if sha256_file(firmware.path) != firmware.sha256:
        raise LayoutError(f"{label}: firmware SHA-256 mismatch: {firmware.path}")


def load_plan(path: Path, root: Path = ROOT) -> tuple[Program, ...]:
    plan = _require_fields(
        tomllib.loads(path.read_text()), {"schema", "program"}, str(path)
    )
    entries = plan.get("program")
    if plan.get("schema") != SCHEMA or not isinstance(entries, list) or not entries:
        raise LayoutError(f"{path}: expected {SCHEMA} with at least one program")
    programs = []
    seen = set()
    for row in entries:
        row = _require_fields(row, {"name", "source", "modes", "firmware"}, str(path))
        name = check_program(row.get("name"))
        if name.casefold() in seen:
            raise LayoutError(f"{name}: conflicting archive filename")
        seen.add(name.casefold())
        source = _input(root, row.get("source"), f"{name}/bpf source")
        if source.suffix != ".c" or source.stem != name:
            raise LayoutError(f"{name}/bpf: source must be named {name}.c")
        modes = row.get("modes")
        if not isinstance(modes, list) or any(mode not in MODES for mode in modes):
            raise LayoutError(f"{name}: modes must contain only {', '.join(MODES)}")
        if len(set(modes)) != len(modes):
            raise LayoutError(f"{name}: duplicate deployment mode")
        data = _require_fields(row.get("firmware", {}), set(modes), f"{name} firmware")
        firmware = {}
        for mode in modes:
            label = f"{name}/{mode}"
            if mode not in data:
                raise LayoutError(f"{label}: missing firmware configuration")
            spec = _require_fields(
                data[mode], {"path", "sha256", "image_name", "slot_symbol"}, label
            )
            elf = _input(root, spec.get("path"), f"{label} firmware")
            digest = spec.get("sha256")
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise LayoutError(f"{label}: expected a lowercase firmware SHA-256")
            options = {}
            for key, pattern in (
                ("image_name", r"[A-Za-z0-9_]{1,31}"),
                ("slot_symbol", r"[A-Za-z_.$][A-Za-z0-9_.$]*"),
            ):
                value = spec.get(key)
                if value is not None and (
                    not isinstance(value, str) or not re.fullmatch(pattern, value)
                ):
                    raise LayoutError(f"{label}: invalid {key}: {value!r}")
                options[key] = value
            firmware[mode] = Firmware(elf, digest, **options)
            _check_firmware(label, firmware[mode])
        programs.append(Program(name, source, tuple(modes), firmware))
    return tuple(programs)


def _machine_paths(index: dict) -> set[str]:
    return {"index.toml", index["source"]["path"], index["bpf"]["path"]} | {
        row["elf"]["path"] for row in index["mode"]
    }


def _report_paths(modes: tuple[str, ...]) -> set[str]:
    return {f"{mode}/report.toml" for mode in ("bpf", *modes)}


def select_modes(index: dict, modes: tuple[str, ...]) -> dict:
    available = {row["name"]: row for row in index["mode"]}
    for mode in modes:
        if mode not in available:
            raise LayoutError(f"{index['program']}/{mode}: required mode is missing")
    return dict(index, mode=[available[mode] for mode in modes])


def verify_package(root: Path, name: str, modes: tuple[str, ...]) -> dict:
    index = load_index(root, name)
    available = {row["name"] for row in index["mode"]}
    select_modes(index, modes)
    if available != set(modes):
        raise LayoutError(
            f"{name}: unexpected modes: {', '.join(sorted(available - set(modes)))}"
        )
    allowed = _machine_paths(index) | _report_paths(modes)
    allowed_dirs = {str(Path(rel).parent) for rel in allowed} - {"."}
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink() or (
            relative not in (allowed_dirs if path.is_dir() else allowed)
        ):
            raise LayoutError(f"{name}: unexpected archive member: {relative}")
    return index


def run(argv: list, *, cwd: Path = ROOT) -> None:
    subprocess.run(list(map(str, argv)), cwd=cwd, stdout=sys.stderr, check=True)


def build(root: Path, program: Program) -> None:
    entry = [sys.executable, ROOT / "make" / "cli.py", "build"]
    source = ["--inputs", shlex.quote(str(program.source)), "--build-dir", root]
    calls = {
        "llvm-aot": ["esp32c3"],
        "ebpf": ["esp32c3", "--engine", "rbpf"],
        "jit": ["jit"],
    }
    for mode in program.modes or ("bpf",):
        print(f"build {program.name}/{mode}", file=sys.stderr)
        if mode == "bpf":
            cmd = [*entry, "bpf", *source]
        else:
            fw = program.firmware[mode]
            _check_firmware(f"{program.name}/{mode}", fw)
            cmd = [*entry, *calls[mode], *source, "--firmware", fw.path]
            if fw.image_name:
                cmd.extend(["--image-name", fw.image_name])
            if fw.slot_symbol:
                cmd.extend(["--slot-symbol", fw.slot_symbol])
        try:
            run(cmd)
        except subprocess.CalledProcessError as exc:
            raise LayoutError(
                f"{program.name}/{mode}: build failed (exit {exc.returncode})"
            ) from exc


def stage_program(
    built: Path, stage: Path, program: Program, source_digest: str
) -> dict:
    index = select_modes(load_index(built, program.name), program.modes)
    if index["source"]["sha256"] != source_digest:
        raise LayoutError(f"{program.name}/bpf: source changed during packaging")
    stage.mkdir()
    write_index(stage / "index.toml", index)
    members = (_machine_paths(index) - {"index.toml"}) | _report_paths(program.modes)
    for rel in sorted(members):
        source = contained(built, rel)
        dest = stage / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, dest)
    return verify_package(stage, program.name, program.modes)


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def package(plan: Path, out: Path) -> dict:
    plan_digest = sha256_file(plan)
    programs = load_plan(plan)
    sources = {program.name: sha256_file(program.source) for program in programs}
    commit = git("rev-parse", "HEAD")
    dirty = bool(git("status", "--porcelain", "--untracked-files=normal"))
    sevenzip = shutil.which("7zz") or shutil.which("7z")
    if not sevenzip:
        raise LayoutError("7zz or 7z is required to package and verify archives")
    names = [f"{program.name}.7z" for program in programs]
    with lock(out):
        out.mkdir(parents=True, exist_ok=True)
        existing = {child.name.casefold() for child in out.iterdir()}
        for name in names:
            if name.casefold() in existing:
                raise LayoutError(f"archive output already exists: {out / name}")
        archives = []
        with tempfile.TemporaryDirectory(prefix=".package-", dir=out) as directory:
            work = Path(directory)
            built = work / "build"
            for program, name in zip(programs, names, strict=True):
                try:
                    build(built, program)
                    stage = work / "stage" / program.name
                    stage.parent.mkdir(exist_ok=True)
                    expected = stage_program(
                        built / program.name, stage, program, sources[program.name]
                    )
                    archive = work / name
                    run([sevenzip, "a", "-t7z", "-bd", "-bb0", archive, "."], cwd=stage)
                    with tempfile.TemporaryDirectory(
                        dir=work, prefix="verify-"
                    ) as verify:
                        run(
                            [sevenzip, "x", "-bd", "-bb0", "-y", "-o" + verify, archive]
                        )
                        extracted = Path(verify)
                        index = verify_package(extracted, program.name, program.modes)
                        if index != expected:
                            raise LayoutError(
                                "extracted index differs from the staged index"
                            )
                        for rel in _report_paths(program.modes):
                            contained(extracted, rel)
                    archives.append(
                        {
                            "path": str(out / name),
                            "name": name,
                            "sha256": sha256_file(archive),
                        }
                    )
                except (OSError, ValueError, subprocess.CalledProcessError) as exc:
                    raise LayoutError(f"{program.name}: {exc}") from exc
            if commit != git("rev-parse", "HEAD") or plan_digest != sha256_file(plan):
                raise LayoutError(
                    "source commit or release configuration changed during packaging"
                )
            if not dirty and git("status", "--porcelain", "--untracked-files=no"):
                raise LayoutError("tracked checkout inputs changed during packaging")
            for program in programs:
                if sources[program.name] != sha256_file(program.source):
                    raise LayoutError(
                        f"{program.name}/bpf: source changed during packaging"
                    )
                for mode, firmware in program.firmware.items():
                    _check_firmware(f"{program.name}/{mode}", firmware)
            for name in names:
                os.link(work / name, out / name)
    return {"commit": commit, "dirty": dirty, "archives": archives}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    try:
        print(json.dumps(package(args.plan.resolve(), args.out.resolve()), indent=2))
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        sys.exit(str(exc))


if __name__ == "__main__":
    main()
