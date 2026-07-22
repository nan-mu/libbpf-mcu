"""Generate object reports (.toml) via llvm-objdump.

Shared skeleton for all targets:
  source / size → [xdp] → [text?] → optional BTF maps/CORE (bpf only).

MCU linked ELFs may also stamp `aot_addr` into the sibling `bpf.toml`
(`[maps.*]` from BTF) using `.maps` symbol VMAs.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

SECTION_LINE = re.compile(
    r"^\s*(\d+)\s+(\S+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s*(.*?)\s*$"
)

# llvm-objdump -t: `403818cc g     O .maps	00000010 arr_map`
MAPS_SYM_LINE = re.compile(
    r"^([0-9a-fA-F]+)\s+\S+\s+\S+\s+\.maps\s+[0-9a-fA-F]+\s+(\S+)\s*$"
)

# Sections with no value in the architecture report (tooling / ELF / reloc / dump noise).
_SKIP_EXACT = frozenset(
    {
        ".strtab",
        ".symtab",
        ".llvm_addrsig",
        ".comment",
        ".eh_frame",
        ".relaxdp",
        ".note.GNU-stack",
        ".maps",
        "license",
        ".BTF",
        ".BTF.ext",
    }
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
    if name in _SKIP_EXACT:
        return True
    if name.startswith((".debug_", ".rel", ".rela", ".note")):
        return True
    if name.endswith(".attributes") or name.endswith("_attributes"):
        return True
    return False


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


INSN_LINE = re.compile(
    r"^(\s*)(\d+):\t(?:[0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})*)\t(.*)$"
)


def format_disasm(objdump: str, obj: Path, name: str) -> str:
    """Disassembly with insn index + mnemonic; opcode hex bytes stripped when present."""
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


def append_header(lines: list[str], source: Path, size: int) -> None:
    lines.append(f'source = "{source}"')
    lines.append(f"size = {size}")
    lines.append("")


def _asm_block(
    lines: list[str],
    table: str,
    objdump: str,
    obj: Path,
    sec: dict | None,
    with_content: bool,
    *,
    omit_if_empty: bool = False,
) -> None:
    size = int(sec["size"]) if sec else 0
    if omit_if_empty and size == 0:
        return
    lines.append(f"[{table}]")
    lines.append(f"size = {size}")
    if with_content and sec and size > 0:
        append_multiline(lines, "asm", format_disasm(objdump, obj, sec["name"]))
    else:
        lines.append('asm = ""')
    lines.append("")


def write_report(
    obj: Path,
    source: Path,
    out: Path,
    objdump: str,
    with_content: bool,
    btf_toml_lines: list[str] | None = None,
) -> None:
    """All targets: header → [xdp] → [text?] → optional BTF tail."""
    sections = parse_sections(objdump, obj, keep_empty=True)
    xdp = find_section(sections, "xdp")
    text = find_section(sections, "text", ".text")

    lines: list[str] = []
    append_header(lines, source, obj.stat().st_size)
    _asm_block(lines, "xdp", objdump, obj, xdp, with_content)
    _asm_block(
        lines, "text", objdump, obj, text, with_content, omit_if_empty=True
    )
    if btf_toml_lines is not None:
        lines.extend(btf_toml_lines)
    out.write_text("\n".join(lines).rstrip() + "\n")


def parse_maps_aot_addrs(objdump: str, obj: Path) -> dict[str, int]:
    """Map symbol name → absolute VMA for objects linked into `.maps`."""
    text = run_objdump(objdump, ["-t", str(obj)])
    out: dict[str, int] = {}
    for line in text.splitlines():
        match = MAPS_SYM_LINE.match(line)
        if not match:
            continue
        name = match.group(2)
        if name.startswith("$"):
            continue
        addr = int(match.group(1), 16)
        if addr == 0:
            continue
        out[name] = addr
    return out


def merge_aot_addrs_into_toml(path: Path, addrs: dict[str, int]) -> int:
    """Insert/update `aot_addr = 0x…` under matching `[maps.*]` tables.

    Returns the number of map tables touched.
    """
    if not addrs:
        return 0

    text = path.read_text()
    parts = re.split(r"(?=^\[)", text, flags=re.M)
    updated = 0
    new_parts: list[str] = []

    for part in parts:
        header = re.match(r"^\[maps\.([^\]]+)\]\s*\n", part)
        if not header:
            new_parts.append(part)
            continue

        name = header.group(1)
        if name not in addrs:
            new_parts.append(part)
            continue

        addr_line = f"aot_addr = {addrs[name]:#x}"
        if re.search(r"^aot_addr\s*=", part, flags=re.M):
            part = re.sub(
                r"^aot_addr\s*=\s*.*$",
                addr_line,
                part,
                count=1,
                flags=re.M,
            )
        elif re.search(r"^estimated_bytes\s*=", part, flags=re.M):
            part = re.sub(
                r"(^estimated_bytes\s*=\s*.*$)",
                rf"\1\n{addr_line}",
                part,
                count=1,
                flags=re.M,
            )
        elif re.search(r"^max_entries\s*=", part, flags=re.M):
            part = re.sub(
                r"(^max_entries\s*=\s*.*$)",
                rf"\1\n{addr_line}",
                part,
                count=1,
                flags=re.M,
            )
        else:
            lines = part.splitlines(keepends=True)
            lines.insert(1, addr_line + "\n")
            part = "".join(lines)

        updated += 1
        new_parts.append(part)

    path.write_text("".join(new_parts))
    return updated


def main() -> None:
    parser = argparse.ArgumentParser(prog="obj_report")
    parser.add_argument("--obj", required=True, type=Path)
    parser.add_argument("--src", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--objdump", default="llvm-objdump-mp-22")
    parser.add_argument("--no-content", action="store_true")
    parser.add_argument(
        "--btf",
        action="store_true",
        help="Analyze .BTF/.BTF.ext and append [maps.*]/[CORE]",
    )
    parser.add_argument(
        "--merge-aot-addrs",
        action="store_true",
        help="Stamp .maps VMAs as aot_addr into sibling bpf.toml [maps.*]",
    )
    args = parser.parse_args()

    obj = args.obj.resolve()
    out = args.out.resolve()
    btf_toml_lines = None
    if args.btf:
        from btf import analyze, format_btf_toml

        try:
            btf_toml_lines = format_btf_toml(analyze(obj))
        except Exception as exc:
            sys.stderr.write(f"obj_report: BTF 分析失败 ({obj}): {exc}\n")
            sys.exit(1)

    write_report(
        obj=obj,
        source=args.src.resolve(),
        out=out,
        objdump=args.objdump,
        with_content=not args.no_content,
        btf_toml_lines=btf_toml_lines,
    )

    if args.merge_aot_addrs:
        addrs = parse_maps_aot_addrs(args.objdump, obj)
        bpf_toml = out.parent / "bpf.toml"
        if not addrs:
            sys.stderr.write(
                f"obj_report: --merge-aot-addrs: no .maps symbols in {obj}\n"
            )
        elif not bpf_toml.is_file():
            sys.stderr.write(
                f"obj_report: --merge-aot-addrs: missing {bpf_toml}\n"
            )
        else:
            n = merge_aot_addrs_into_toml(bpf_toml, addrs)
            sys.stderr.write(
                f"obj_report: merged aot_addr for {n}/{len(addrs)} maps "
                f"into {bpf_toml}\n"
            )


if __name__ == "__main__":
    main()
