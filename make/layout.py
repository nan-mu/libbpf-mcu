"""Program index, independent artifact verification, and legacy export."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import struct
import sys
import tempfile
import tomllib
from contextlib import contextmanager
from pathlib import Path, PureWindowsPath

from xpost_elf import parse_container

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_INDEX = "libbpf-mcu.program-index.v2"
MODES = ("llvm-aot", "ebpf", "jit")
LEGACY_MODES = {"rv32": "llvm-aot", "jit": "jit", "bpf-xpost": "ebpf"}
CONTAINER_ROLE = "xpost_container"
CONTAINER_FORMAT = "xpost-compact-elf-v0"


class LayoutError(ValueError):
    pass


def check_program(name: str) -> str:
    if (
        not isinstance(name, str)
        or name in {"", ".", "..", ".ninja"}
        or PureWindowsPath(name).drive
        or any(ch in "/\\" or ord(ch) < 32 or ord(ch) == 127 for ch in name)
    ):
        raise LayoutError(f"invalid program name: {name!r}")
    return name


def sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temp = Path(stream.name)
        try:
            stream.write(data)
            stream.close()
            temp.replace(path)
        finally:
            temp.unlink(missing_ok=True)


def write_if_changed(path: Path, data: bytes) -> None:
    if not path.is_file() or path.read_bytes() != data:
        atomic_write(path, data)


@contextmanager
def lock(root: Path):
    # Keep the lock beside the root so removing the default tree does not
    # replace the lock inode while a build or export is waiting on it.
    root.parent.mkdir(parents=True, exist_ok=True)
    with (root.parent / f".{root.name}.lock").open("a") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def q(value: str) -> str:
    return json.dumps(value, ensure_ascii=False).replace("\x7f", "\\u007f")


def append_multiline(lines: list[str], field: str, text: str) -> None:
    if "'''" not in text and all(
        ch in "\n\t" or ord(ch) >= 32 and ord(ch) != 127 for ch in text
    ):
        lines.append(f"{field} = '''\n{text}'''")
    else:
        escaped = "\n".join(q(line)[1:-1] for line in text.split("\n"))
        lines.append(f'{field} = """\n{escaped}"""')


def source_path(root: Path, program: str) -> Path:
    return root / program / "src" / f"{program}.c"


def bpf_path(root: Path, program: str) -> Path:
    return root / program / "bpf" / f"{program}_bpf.o"


def report_path(root: Path, program: str, mode: str) -> Path:
    return root / program / mode / "report.toml"


def container_path(root: Path, program: str, mode: str) -> Path:
    suffix = {"llvm-aot": "aot", "ebpf": "ebpf", "jit": "jit"}[mode]
    return root / program / mode / f"{program}-vm-{suffix}.elf"


def state_path(root: Path, program: str, mode: str) -> Path:
    return root / ".ninja" / program / mode / "state.json"


def contained(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or PureWindowsPath(relative).drive:
        raise LayoutError(f"invalid relative path: {relative!r}")
    path = root
    for part in relative.split("/"):
        if part in {"", ".", ".."} or "\\" in part or "\0" in part:
            raise LayoutError(f"invalid relative path: {relative!r}")
        path /= part
        if path.is_symlink():
            raise LayoutError(f"symlink is not an artifact: {path}")
    if not path.is_file():
        raise LayoutError(f"missing file: {path}")
    return path


def member(root: Path, path: Path) -> dict:
    relative = path.relative_to(root).as_posix()
    file = contained(root, relative)
    return {
        "path": relative,
        "size_bytes": file.stat().st_size,
        "sha256": sha256_file(file),
    }


def make_index(program_root: Path, program: str, modes: tuple[str, ...]) -> dict:
    return {
        "schema": SCHEMA_INDEX,
        "program": check_program(program),
        "source": member(program_root, source_path(program_root.parent, program)),
        "bpf": member(program_root, bpf_path(program_root.parent, program)),
        "mode": [
            {
                "name": mode,
                "role": CONTAINER_ROLE,
                "format": CONTAINER_FORMAT,
                "elf": member(
                    program_root, container_path(program_root.parent, program, mode)
                ),
            }
            for mode in modes
        ],
    }


def _inline_member(record: dict) -> str:
    return (
        f"{{ path = {q(record['path'])}, size_bytes = {record['size_bytes']}, "
        f"sha256 = {q(record['sha256'])} }}"
    )


def write_index(path: Path, index: dict) -> None:
    lines = [
        f"schema = {q(index['schema'])}",
        f"program = {q(index['program'])}",
        f"source = {_inline_member(index['source'])}",
        f"bpf = {_inline_member(index['bpf'])}",
    ]
    for mode in index["mode"]:
        lines.extend(
            [
                "",
                "[[mode]]",
                f"name = {q(mode['name'])}",
                f"role = {q(mode['role'])}",
                f"format = {q(mode['format'])}",
                f"elf = {_inline_member(mode['elf'])}",
            ]
        )
    write_if_changed(path, ("\n".join(lines) + "\n").encode())


def _verify_member(root: Path, record: dict, expected: str) -> Path:
    if not isinstance(record, dict) or record.get("path") != expected:
        raise LayoutError(f"invalid index path, expected {expected}")
    path = contained(root, expected)
    if (
        type(record.get("size_bytes")) is not int
        or record["size_bytes"] != path.stat().st_size
    ):
        raise LayoutError(f"size mismatch: {path}")
    if record.get("sha256") != sha256_file(path):
        raise LayoutError(f"SHA-256 mismatch: {path}")
    return path


def check_bpf(path: Path) -> None:
    with path.open("rb") as stream:
        header = stream.read(64)
    if (
        len(header) != 64
        or header[:7] != b"\x7fELF\x02\x01\x01"
        or struct.unpack_from("<HH", header, 16) != (1, 247)
    ):
        raise LayoutError(f"expected a little-endian relocatable eBPF ELF: {path}")


def load_index(program_root: Path, program: str | None = None) -> dict:
    index = tomllib.loads(contained(program_root, "index.toml").read_text())
    if index.get("schema") != SCHEMA_INDEX:
        raise LayoutError(f"{program_root}: expected {SCHEMA_INDEX}")
    name = check_program(index.get("program"))
    if program is not None and name != program:
        raise LayoutError(f"{program_root}: program is {name}, expected {program}")
    _verify_member(program_root, index.get("source"), f"src/{name}.c")
    check_bpf(_verify_member(program_root, index.get("bpf"), f"bpf/{name}_bpf.o"))
    rows = index.setdefault("mode", [])
    if not isinstance(rows, list):
        raise LayoutError(f"{name}: mode must be an array of tables")
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or row.get("name") not in MODES:
            raise LayoutError(f"{name}: invalid mode {row!r}")
        mode = row["name"]
        if mode in seen:
            raise LayoutError(f"{name}/{mode}: duplicate mode")
        seen.add(mode)
        if row.get("role") != CONTAINER_ROLE or row.get("format") != CONTAINER_FORMAT:
            raise LayoutError(f"{name}/{mode}: invalid role or format")
        suffix = {"llvm-aot": "aot", "ebpf": "ebpf", "jit": "jit"}[mode]
        path = _verify_member(
            program_root, row.get("elf"), f"{mode}/{name}-vm-{suffix}.elf"
        )
        try:
            parse_container(path.read_bytes())
        except ValueError as exc:
            raise LayoutError(f"{name}/{mode}: {exc}") from exc
    return index


def program_indexes(root: Path):
    for path in sorted(root.glob("*/index.toml")):
        if path.parent.is_symlink():
            raise LayoutError(f"symlink is not a program directory: {path.parent}")
        yield path.parent, load_index(path.parent, path.parent.name)


def verify_tree(root: Path) -> list[dict]:
    if (root / "index.toml").is_file():
        return [load_index(root)]
    indexes = [index for _, index in program_indexes(root)]
    if not indexes:
        raise LayoutError(f"{root}: no program indexes")
    return indexes


def export_legacy(root: Path, out: Path, mode: str) -> list[str]:
    from legacy_export import export

    root, out = root.resolve(), out.resolve()
    if root == out or root in out.parents or out in root.parents:
        raise LayoutError("legacy output must be separate from the build root")
    first, second = sorted((root, out))
    with lock(first), lock(second):
        return export(root, out, mode)


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("verify", "reports", "export-legacy"):
        cmd = sub.add_parser(command)
        cmd.add_argument("--build-dir", required=True, type=Path)
    export = sub.choices["export-legacy"]
    export.add_argument("--mode", choices=LEGACY_MODES, required=True)
    export.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "verify":
            for index in verify_tree(args.build_dir):
                print(
                    f"verified {index['program']}: {', '.join(m['name'] for m in index['mode']) or 'bpf'}"
                )
        elif args.command == "reports":
            from build_state import render_reports

            root = args.build_dir.resolve()
            with lock(root):
                for index in verify_tree(root):
                    render_reports(root, index["program"], force=True)
        else:
            print(
                "exported "
                + ", ".join(export_legacy(args.build_dir, args.out, args.mode))
            )
    except (OSError, ValueError) as exc:
        sys.exit(str(exc))


if __name__ == "__main__":
    main()
