"""Render a human report from the exact executable bytes and recorded calls."""

from __future__ import annotations

import json
import re
import shlex
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from layout import write_if_changed

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


MACHINES = {
    "bpf": (
        "Little-endian eBPF. The listing shows the executable sections of the "
        "original Clang object. Addresses are byte offsets within each section."
    ),
    "llvm-aot": (
        "RV32IMC, ILP32, no FPU. LLVM compiles the C source for the MCU. "
        "The listing shows the linked instructions at their firmware slot addresses."
    ),
    "ebpf": (
        "Little-endian eBPF for the rBPF interpreter on RV32IMC. The container payload "
        "uses map indices. Addresses are byte offsets in the rewritten program."
    ),
    "jit": (
        "ILP32, no FPU. The host JIT translates eBPF to the RV32IM subset of RV32IMC. "
        "The listing covers the linked instructions at their firmware slot addresses "
        "and ends before map storage."
    ),
}


def fenced(text: str, language: str) -> str:
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    newline = "" if text.endswith(("\r", "\n")) else "\n"
    return f"{fence}{language}\n{text}{newline}{fence}"


def write_report(
    path: Path, source: str, snapshot: bytes, sections: list[tuple[str, str, list[dict]]]
) -> None:
    blocks = [
        "# Build report",
        "## Source",
        fenced(source, "text"),
        fenced(snapshot.decode("utf-8"), "c"),
    ]
    if snapshot and not snapshot.endswith((b"\r", b"\n")):
        blocks.append("The source file ends without a newline.")
    architectures = {"eBPF": [], "RV32IMC": []}
    for mode, listing, generation in sections:
        group = architectures["eBPF" if mode in ("bpf", "ebpf") else "RV32IMC"]
        group.extend(
            [
                f"### {mode}",
                MACHINES[mode],
                "#### Machine code and assembly",
                fenced(listing, "text"),
                "#### Build steps",
            ]
        )
        calls = []
        for step in generation:
            if "argv" in step:
                details = "$ " + shlex.join(step["argv"])
            else:
                params = json.dumps(step["parameters"], ensure_ascii=False, indent=2)
                details = step["call"] + "\n" + params
            calls.append(step["step"] + "\n" + details)
        group.append(fenced("\n\n".join(calls), "text"))
    for architecture, group in architectures.items():
        if group:
            blocks.extend([f"## {architecture}", *group])
    write_if_changed(path, ("\n\n".join(blocks) + "\n").encode("utf-8"))
