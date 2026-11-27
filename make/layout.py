"""Program index and independent artifact verification."""

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
SCHEMA_INDEX = "libbpf-mcu.program-index.v3"
MODES = ("llvm-aot", "ebpf", "jit")
CONTAINER_ROLE = "xpost_container"
CONTAINER_FORMAT = "xpost-compact-elf-v0"


class LayoutError(ValueError):
    pass


def check_program(name: str) -> str:
    if (
        not isinstance(name, str)
        or name.casefold() in {"", ".", "..", ".ninja", "index.toml"}
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
    if path.is_symlink():
        raise LayoutError(f"symlink is not a build output: {path}")
    if not path.is_file() or path.read_bytes() != data:
        atomic_write(path, data)


@contextmanager
def lock(root: Path):
    # Keep the lock beside the root so removing the default tree does not
    # replace the lock inode while another build is waiting on it.
    root.parent.mkdir(parents=True, exist_ok=True)
    with (root.parent / f".{root.name}.lock").open("a") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def q(value: str) -> str:
    return json.dumps(value, ensure_ascii=False).replace("\x7f", "\\u007f")


def source_path(root: Path, program: str) -> Path:
    return root / program / f"{program}.c"


def bpf_path(root: Path, program: str) -> Path:
    return root / program / "objects" / f"{program}_bpf.o"


def native_object_path(root: Path, program: str) -> Path:
    return root / program / "objects" / f"{program}_rv32.o"


def report_path(root: Path, program: str) -> Path:
    return root / program / "report.md"


def container_path(root: Path, program: str, mode: str) -> Path:
    suffix = {"llvm-aot": "aot", "ebpf": "ebpf", "jit": "jit"}[mode]
    return root / program / "containers" / f"{program}-vm-{suffix}.elf"


def portable_paths(root: Path, program: str, mode: str) -> tuple[Path, Path]:
    base = root / program / "images" / mode
    return base.with_suffix(".bin"), base.with_suffix(".json")


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


def make_index(program_root: Path, program: str, modes: tuple[str, ...], *,
               portable: set[str] = frozenset()) -> dict:
    from native_image import FORMATS, ROLES, read_document

    check_program(program)
    root = program_root.parent
    rows = []
    for mode in modes:
        if mode in portable:
            image, layout = portable_paths(root, program, mode)
            row = {
                "name": mode, "role": ROLES[mode], "format": FORMATS[mode],
                "image": member(program_root, image),
                "layout": member(program_root, layout),
                "fixup_sites": [fixup["offset"] for fixup in read_document(layout)["fixups"]],
            }
        else:
            row = {
                "name": mode, "role": CONTAINER_ROLE, "format": CONTAINER_FORMAT,
                "elf": member(program_root, container_path(root, program, mode)),
            }
        if mode == "llvm-aot":
            row["object"] = member(program_root, native_object_path(root, program))
        rows.append(row)
    return {
        "schema": SCHEMA_INDEX,
        "program": program,
        "source": member(program_root, source_path(root, program)),
        "bpf": member(program_root, bpf_path(root, program)),
        "mode": rows,
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
            ]
        )
        for key in ("elf", "image", "layout"):
            if key in mode:
                lines.append(f"{key} = {_inline_member(mode[key])}")
        if "fixup_sites" in mode:
            lines.append(f"fixup_sites = {json.dumps(mode['fixup_sites'])}")
        if "object" in mode:
            lines.append(f"object = {_inline_member(mode['object'])}")
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


def check_relocatable(path: Path, *, bpf: bool) -> None:
    with path.open("rb") as stream:
        header = stream.read(64)
    elf_class, machine, size = (2, 247, 64) if bpf else (1, 243, 52)
    if (
        len(header) < size
        or header[:7] != b"\x7fELF" + bytes([elf_class, 1, 1])
        or struct.unpack_from("<HH", header, 16) != (1, machine)
    ):
        arch = "eBPF" if bpf else "RV32"
        raise LayoutError(f"expected a little-endian relocatable {arch} ELF: {path}")


def _read_index(program_root: Path, program: str | None = None) -> dict:
    index = tomllib.loads(contained(program_root, "index.toml").read_text())
    if index.get("schema") != SCHEMA_INDEX:
        raise LayoutError(f"{program_root}: expected {SCHEMA_INDEX}")
    name = check_program(index.get("program"))
    if program is not None and name != program:
        raise LayoutError(f"{program_root}: program is {name}, expected {program}")
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
    return index


def _portable_inputs(root: Path, program: str, row: dict) -> tuple[bytes, dict]:
    from native_image import FORMATS, ROLES, fields, read_document, validate_image

    mode = row["name"]
    reference = " object" if mode == "llvm-aot" else ""
    fields(row, "name role format image layout fixup_sites" + reference, f"{mode} index row")
    if (row["role"], row["format"]) != (ROLES[mode], FORMATS[mode]):
        raise LayoutError(f"{program}/{mode}: invalid portable role or format")
    image, layout = portable_paths(Path(), program, mode)
    data = _verify_member(root, row["image"], image.relative_to(program).as_posix()).read_bytes()
    doc = read_document(_verify_member(root, row["layout"], layout.relative_to(program).as_posix()))
    validate_image(program, mode, data, doc, row["fixup_sites"])
    return data, doc


def load_portable_mode(root: Path, mode: str) -> tuple[str, dict, bytes, dict]:
    """Open only the selected binding inputs, leaving audit objects unopened."""
    index = _read_index(root)
    program = index["program"]
    row = next((row for row in index["mode"] if row["name"] == mode), None)
    if row is None or row.get("role") == CONTAINER_ROLE:
        raise LayoutError(f"{program}/{mode}: missing portable deployment")
    image, doc = _portable_inputs(root, program, row)
    return program, row, image, doc


def load_index(program_root: Path, program: str | None = None) -> dict:
    from rv32_release_elf import verify_aot_records

    index = _read_index(program_root, program)
    name = index["program"]
    _verify_member(program_root, index.get("source"), f"{name}.c")
    bpf = _verify_member(program_root, index.get("bpf"), f"objects/{name}_bpf.o")
    check_relocatable(bpf, bpf=True)
    layouts = {}
    for row in index["mode"]:
        mode = row["name"]
        if row.get("role") != CONTAINER_ROLE:
            try:
                _, doc = _portable_inputs(program_root, name, row)
                if mode == "llvm-aot":
                    native = _verify_member(
                        program_root, row["object"], f"objects/{name}_rv32.o"
                    )
                    verify_aot_records(native, doc)
                layouts[mode] = doc
            except ValueError as exc:
                raise LayoutError(f"{name}/{mode}: {exc}") from exc
            continue
        if row.get("format") != CONTAINER_FORMAT:
            raise LayoutError(f"{name}/{mode}: invalid role or format")
        path = _verify_member(
            program_root, row.get("elf"),
            container_path(Path(), name, mode).relative_to(name).as_posix(),
        )
        if mode == "llvm-aot":
            native = _verify_member(
                program_root, row.get("object"), f"objects/{name}_rv32.o"
            )
            check_relocatable(native, bpf=False)
        elif "object" in row:
            raise LayoutError(f"{name}/{mode}: unexpected native object")
        try:
            parse_container(path.read_bytes())
        except ValueError as exc:
            raise LayoutError(f"{name}/{mode}: {exc}") from exc
    if {"llvm-aot", "ebpf"} <= layouts.keys() and layouts["llvm-aot"]["maps"] != layouts["ebpf"]["maps"]:
        raise LayoutError(f"{name}/ebpf: map layout differs from AOT")
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


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("verify", "reports"):
        cmd = sub.add_parser(command)
        cmd.add_argument("--build-dir", required=True, type=Path)
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
    except (OSError, ValueError) as exc:
        sys.exit(str(exc))


if __name__ == "__main__":
    main()
