"""Render a human report from the exact executable bytes and recorded calls."""

from __future__ import annotations

import re
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from layout import append_multiline, q, write_if_changed

ELF32 = struct.Struct("<16sHHIIIIIHHHHHH")
ELF64 = struct.Struct("<16sHHIQQQIHHHHHH")
SECTION32 = struct.Struct("<10I")
SECTION64 = struct.Struct("<IIQQQQIIQQ")
BPF, RISCV = 247, 243


@dataclass(frozen=True)
class CodeSection:
    name: str
    address: int
    data: bytes


def executable_sections(data: bytes) -> list[CodeSection]:
    if data[:4] != b"\x7fELF" or data[5] != 1:
        raise ValueError("expected a little-endian ELF")
    header, section = {1: (ELF32, SECTION32), 2: (ELF64, SECTION64)}[data[4]]
    *_, offset, _, _, _, _, size, count, names_index = header.unpack_from(data)
    if size != section.size or not 0 < names_index < count:
        raise ValueError("invalid ELF section table")
    rows = [section.unpack_from(data, offset + i * size) for i in range(count)]
    names_offset, names_size = rows[names_index][4:6]
    names = data[names_offset : names_offset + names_size]
    sections = []
    for name, kind, flags, address, start, length, *_ in rows:
        if kind != 1 or not flags & 4 or not length:
            continue
        end = names.index(b"\0", name)
        if start + length > len(data):
            raise ValueError("ELF code lies outside the file")
        sections.append(
            CodeSection(names[name:end].decode(), address, data[start : start + length])
        )
    return sections


def code_elf(code: CodeSection, machine: int) -> bytes:
    """Give objdump a single executable section containing the supplied bytes."""
    elf, section, elf_class = (
        (ELF64, SECTION64, 2) if machine == BPF else (ELF32, SECTION32, 1)
    )
    ident = b"\x7fELF" + bytes((elf_class, 1, 1)) + bytes(9)
    names = b"\0" + code.name.encode() + b"\0.shstrtab\0"
    start = elf.size + 3 * section.size
    return b"".join(
        [
            elf.pack(
                ident,
                1 if machine == BPF else 2,
                machine,
                1,
                code.address,
                0,
                elf.size,
                0,
                elf.size,
                0,
                0,
                section.size,
                3,
                2,
            ),
            bytes(section.size),
            section.pack(1, 1, 6, code.address, start, len(code.data), 0, 0, 4, 0),
            section.pack(
                len(names) - len(b".shstrtab\0"),
                3,
                0,
                0,
                start + len(code.data),
                len(names),
                0,
                0,
                1,
                0,
            ),
            code.data,
            names,
        ]
    )


INSN = re.compile(r"^\s*([0-9a-fA-F]+):\s*([\da-fA-F ]+?)\t+\s*(.+)$")


def format_disasm(
    objdump: str, obj: Path, code: CodeSection, *, bpf: bool, compressed: bool = False
) -> str:
    cmd = [objdump, "-d", "-z", "--section=" + code.name]
    if not bpf:
        cmd.append("--mattr=+m," + ("+c" if compressed else "-c"))
    text = subprocess.check_output([*cmd, str(obj)], text=True)
    label = "section byte offset" if bpf else "linked address"
    lines = [f"{code.name}  ({label})"]
    offset = 0
    for line in text.splitlines():
        if not (match := INSN.fullmatch(line)):
            continue
        printed, raw, assembly = match.groups()
        if bpf:
            position = int(printed) * 8
            decoded = bytes.fromhex(raw)
        else:
            position = int(printed, 16) - code.address
            chunks = raw.split()
            decoded = (
                int(chunks[0], 16).to_bytes(len(chunks[0]) // 2, "little")
                if len(chunks) == 1
                else bytes.fromhex(raw)
            )
        if offset != position or code.data[offset : offset + len(decoded)] != decoded:
            raise ValueError(
                f"{code.name}+{offset:#x}: disassembler bytes differ from code"
            )
        at = offset if bpf else code.address + offset
        lines.append(f"{at:08x}  {decoded.hex(' '):<47}  {' '.join(assembly.split())}")
        offset += len(decoded)
    if offset != len(code.data):
        raise ValueError(
            f"{code.name}: decoded {offset} of {len(code.data)} code bytes"
        )
    return "\n".join(lines) + "\n"


def disassemble_payload(objdump: str, code: CodeSection, machine: int) -> str:
    with tempfile.TemporaryDirectory(prefix="libbpf-disasm-") as tmp:
        elf = Path(tmp) / "payload.elf"
        elf.write_bytes(code_elf(code, machine))
        return format_disasm(objdump, elf, code, bpf=machine == BPF)


def parameter(value: object) -> str:
    if isinstance(value, dict):
        fields = ", ".join(f"{q(k)} = {parameter(v)}" for k, v in sorted(value.items()))
        return "{ " + fields + " }"
    if isinstance(value, list):
        return "[" + ", ".join(map(parameter, value)) + "]"
    if isinstance(value, int):
        return str(value)
    return q(str(value))


def write_report(
    path: Path, source: str, snapshot: bytes, listing: str, generation: list[dict]
) -> None:
    lines = ["[source]", f"path = {q(source)}"]
    append_multiline(lines, "text", snapshot.decode("utf-8"))
    lines.extend(["", "[assembly]"])
    append_multiline(lines, "listing", listing)
    for step in generation:
        lines.extend(["", "[[generation]]"])
        lines.extend(f"{key} = {parameter(value)}" for key, value in step.items())
    write_if_changed(path, ("\n".join(lines) + "\n").encode())
