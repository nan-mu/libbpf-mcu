"""Generate object section reports (.toml) via llvm-objdump."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

SECTION_LINE = re.compile(
    r"^\s*(\d+)\s+(\S+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s*(.*?)\s*$"
)
HEX_CHUNK = re.compile(r"^\s*[0-9a-fA-F]+\s+((?:[0-9a-fA-F]{2,8}\s*)+)")


def run_objdump(objdump: str, args: list[str]) -> str:
    result = subprocess.run(
        [objdump, *args], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr or result.stdout)
        sys.exit(result.returncode or 1)
    return result.stdout


def parse_sections(objdump: str, obj: Path) -> list[dict]:
    text = run_objdump(objdump, ["-h", str(obj)])
    sections = []
    for line in text.splitlines():
        match = SECTION_LINE.match(line)
        if not match:
            continue
        name = match.group(2)
        size = int(match.group(3), 16)
        vma = int(match.group(4), 16)
        typ = match.group(5).strip()
        if size == 0:
            continue
        sections.append({"name": name, "size": size, "vma": vma, "type": typ})
    return sections


def section_key(name: str) -> str:
    return name.lstrip(".")


def content_kind(name: str) -> str:
    key = section_key(name)
    if key == "strtab":
        return "ascii"
    if key == "xdp" or key.startswith("xdp/"):
        return "disasm"
    return "hex"


def parse_section_bytes(objdump: str, obj: Path, name: str) -> bytes:
    text = run_objdump(objdump, ["-s", "-j", name, str(obj)])
    raw = bytearray()
    for line in text.splitlines():
        match = HEX_CHUNK.match(line)
        if not match:
            continue
        for token in match.group(1).split():
            raw.extend(bytes.fromhex(token))
    return bytes(raw)


def _ascii_side(chunk: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)


def format_hex(data: bytes) -> str:
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]
        left = " ".join(f"{b:02x}" for b in chunk[:8])
        right = " ".join(f"{b:02x}" for b in chunk[8:])
        hex_part = f"{left:<23}  {right:<23}"
        lines.append(f"{offset:04x}  {hex_part}  |{_ascii_side(chunk)}|")
    return "\n".join(lines)


def format_ascii(data: bytes) -> list[str]:
    return [part.decode("utf-8", errors="replace") for part in data.split(b"\0") if part]


def format_disasm(objdump: str, obj: Path, name: str) -> str:
    text = run_objdump(objdump, ["-d", "-j", name, str(obj)])
    lines = []
    started = False
    for line in text.splitlines():
        if line.startswith("Disassembly of section"):
            started = True
            continue
        if not started:
            continue
        if line.strip():
            lines.append(line.rstrip())
    return "\n".join(lines)


def toml_escape(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace('"""', '\\"""')
        .replace("\r\n", "\n")
    )


def toml_string(value: str) -> str:
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\t", "\\t")
    )
    return f'"{escaped}"'


def append_content(lines: list[str], kind: str, payload: str | list[str]) -> None:
    if kind == "ascii":
        lines.append("ascii = [")
        for item in payload:
            lines.append(f"  {toml_string(item)},")
        lines.append("]")
        return

    field = "disasm" if kind == "disasm" else "hex"
    lines.append(f'{field} = """\n{toml_escape(payload)}\n"""')


def write_report(
    obj: Path,
    source: Path,
    out: Path,
    objdump: str,
    with_content: bool,
) -> None:
    sections = parse_sections(objdump, obj)
    size = obj.stat().st_size

    lines = [
        f'source = "{source}"',
        f"size = {size}",
        "",
    ]

    for sec in sections:
        key = section_key(sec["name"])
        lines.append(f"[section.{key}]")
        lines.append(f'name = "{sec["name"]}"')
        lines.append(f"size = {sec['size']}")
        lines.append(f"vma = {sec['vma']}")
        lines.append(f'type = "{sec["type"]}"')
        if with_content:
            kind = content_kind(sec["name"])
            if kind == "disasm":
                payload = format_disasm(objdump, obj, sec["name"])
            elif kind == "ascii":
                payload = format_ascii(parse_section_bytes(objdump, obj, sec["name"]))
            else:
                payload = format_hex(parse_section_bytes(objdump, obj, sec["name"]))
            append_content(lines, kind, payload)
        lines.append("")

    out.write_text("\n".join(lines).rstrip() + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(prog="obj_report")
    parser.add_argument("--obj", required=True, type=Path)
    parser.add_argument("--src", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--objdump", default="llvm-objdump-mp-22")
    parser.add_argument("--no-content", action="store_true")
    args = parser.parse_args()

    write_report(
        obj=args.obj.resolve(),
        source=args.src.resolve(),
        out=args.out.resolve(),
        objdump=args.objdump,
        with_content=not args.no_content,
    )


if __name__ == "__main__":
    main()
