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
# llvm-objdump -s: addr + ≤4 groups of 2–8 even hex digits, then ASCII.
# Even-length only so the ASCII column (e.g. "addr...") is not consumed.
HEX_CHUNK = re.compile(
    r"^\s*[0-9a-fA-F]+\s+((?:[0-9a-fA-F]{2}){1,4}(?:\s+(?:[0-9a-fA-F]{2}){1,4}){0,3})"
)


def run_objdump(objdump: str, args: list[str]) -> str:
    result = subprocess.run(
        [objdump, *args], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr or result.stdout)
        sys.exit(result.returncode or 1)
    return result.stdout


def skip_section(name: str) -> bool:
    return name.startswith((".debug_", ".rel.debug_"))


def section_key(name: str) -> str:
    return name.lstrip(".")


def parse_sections(objdump: str, obj: Path, *, keep_empty: bool = False) -> list[dict]:
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
        if skip_section(name):
            continue
        if size == 0 and not keep_empty:
            continue
        sections.append({"name": name, "size": size, "vma": vma, "type": typ})
    return sections


def find_section(sections: list[dict], *names: str) -> dict | None:
    want = set(names)
    for sec in sections:
        if sec["name"] in want or section_key(sec["name"]) in want:
            return sec
    return None


def content_kind(name: str) -> str:
    key = section_key(name)
    if key == "strtab":
        return "ascii"
    if key == "xdp" or key.startswith("xdp/") or key == "text":
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


INSN_LINE = re.compile(
    r"^(\s*)(\d+):\t(?:[0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})*)\t(.*)$"
)


def format_disasm(objdump: str, obj: Path, name: str) -> str:
    """Disassembly with insn index + mnemonic; opcode hex bytes stripped."""
    text = run_objdump(objdump, ["-d", "-j", name, str(obj)])
    lines = []
    started = False
    for line in text.splitlines():
        if line.startswith("Disassembly of section"):
            started = True
            continue
        if not started or not line.strip():
            continue
        match = INSN_LINE.match(line)
        if match:
            indent, idx, mnemonic = match.groups()
            lines.append(f"{indent}{idx}:\t{mnemonic.rstrip()}")
        else:
            # Label / other non-insn lines (e.g. `0000... <sym>:`).
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


def append_multiline(lines: list[str], field: str, payload: str) -> None:
    lines.append(f'{field} = """\n{toml_escape(payload)}\n"""')


def append_content(lines: list[str], kind: str, payload: str | list[str]) -> None:
    if kind == "ascii":
        lines.append("ascii = [")
        for item in payload:
            lines.append(f"  {toml_string(item)},")
        lines.append("]")
        return
    field = "disasm" if kind == "disasm" else "hex"
    append_multiline(lines, field, payload if isinstance(payload, str) else "")


def _asm_block(
    lines: list[str],
    table: str,
    objdump: str,
    obj: Path,
    sec: dict | None,
    with_content: bool,
) -> None:
    size = int(sec["size"]) if sec else 0
    lines.append(f"[{table}]")
    lines.append(f"size = {size}")
    if with_content and sec and size > 0:
        append_multiline(lines, "asm", format_disasm(objdump, obj, sec["name"]))
    else:
        lines.append('asm = ""')
    lines.append("")


def write_bpf_report(
    obj: Path,
    source: Path,
    out: Path,
    objdump: str,
    with_content: bool,
    btf_toml_lines: list[str],
) -> None:
    """bpf.toml: [xdp] → [text] → [maps.*] → [CORE]."""
    sections = parse_sections(objdump, obj, keep_empty=True)
    xdp = find_section(sections, "xdp")
    text = find_section(sections, "text", ".text")

    lines = [
        f'source = "{source}"',
        f"size = {obj.stat().st_size}",
        "",
    ]
    _asm_block(lines, "xdp", objdump, obj, xdp, with_content)
    _asm_block(lines, "text", objdump, obj, text, with_content)

    lines.extend(btf_toml_lines)
    out.write_text("\n".join(lines).rstrip() + "\n")


def write_section_report(
    obj: Path,
    source: Path,
    out: Path,
    objdump: str,
    with_content: bool,
) -> None:
    """Legacy / non-bpf object dump (all non-debug sections)."""
    sections = parse_sections(objdump, obj, keep_empty=False)
    lines = [
        f'source = "{source}"',
        f"size = {obj.stat().st_size}",
        "",
    ]
    for sec in sections:
        key = section_key(sec["name"])
        lines.append(f"[section.{key}]")
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


def write_report(
    obj: Path,
    source: Path,
    out: Path,
    objdump: str,
    with_content: bool,
    btf_toml_lines: list[str] | None = None,
) -> None:
    if btf_toml_lines is not None:
        write_bpf_report(
            obj=obj,
            source=source,
            out=out,
            objdump=objdump,
            with_content=with_content,
            btf_toml_lines=btf_toml_lines,
        )
        return
    write_section_report(
        obj=obj,
        source=source,
        out=out,
        objdump=objdump,
        with_content=with_content,
    )


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
