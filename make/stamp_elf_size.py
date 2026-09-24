#!/usr/bin/env python3
"""Stamp Compact ELF file size (KB) into esp32c3.toml."""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


def stamp(report: Path, elf: Path) -> None:
    size_kb = elf.stat().st_size / 1024
    line = f"elf_size_kb = {size_kb:.3f}\n"
    if report.is_file():
        text = report.read_text()
        if re.search(r"^elf_size_kb\s*=", text, flags=re.M):
            text = re.sub(
                r"^elf_size_kb\s*=\s*.*$",
                f"elf_size_kb = {size_kb:.3f}",
                text,
                count=1,
                flags=re.M,
            )
            report.write_text(text if text.endswith("\n") else text + "\n")
            return
        report.write_text(text.rstrip() + "\n" + line)
    else:
        report.write_text(line)


def main() -> None:
    p = argparse.ArgumentParser(prog="stamp_elf_size")
    p.add_argument("--report", required=True, type=Path)
    p.add_argument("--elf", required=True, type=Path)
    args = p.parse_args()
    if not args.elf.is_file():
        sys.stderr.write(f"stamp_elf_size: missing elf {args.elf}\n")
        sys.exit(1)
    stamp(args.report, args.elf)


if __name__ == "__main__":
    main()
