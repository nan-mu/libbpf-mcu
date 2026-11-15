"""Extract the XDP program section from a bpf object, as raw instructions.

The section name varies with how the source declares its program: `xdp` for
`SEC("xdp")` and `xdp1` for `SEC("xdp1")`. Picking the name by hand in a build
edge would silently produce an empty image for one of the two forms, so this
script finds the section that actually holds instructions and refuses when there
is none or when more than one could be the program.

Usage: `xdp_section.py --obj build/<stem>/bpf.o --out build/<stem>/xdp.bin`
"""

import argparse
import subprocess
import sys
from pathlib import Path

from llvm_tools import resolve_llvm_tool


def sections(obj: Path) -> list[tuple[str, int]]:
    """(name, size) for every section the object reports."""
    out = subprocess.run(
        [resolve_llvm_tool("llvm-objdump"), "-h", str(obj)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    found: list[tuple[str, int]] = []
    for line in out.splitlines():
        parts = line.split()
        # objdump -h: "idx name size vma lma fileoff algn"
        if len(parts) >= 3 and parts[0].rstrip(":").isdigit():
            try:
                size = int(parts[2], 16)
            except ValueError:
                continue
            found.append((parts[1], size))
    return found


def program_section(obj: Path) -> str:
    """The one section holding the XDP program.

    A declaration-form mismatch between `xdp` and `xdp1` is a fact about the
    source, so the name is read rather than assumed.
    """
    names = [name for name, size in sections(obj) if name in ("xdp", "xdp1") and size > 0]
    if not names:
        raise SystemExit(
            f"{obj}: no xdp section with code; sections are {[n for n, _ in sections(obj)]}"
        )
    if len(names) > 1:
        raise SystemExit(f"{obj}: more than one xdp section {names}; refusing to guess")
    return names[0]


def main() -> None:
    p = argparse.ArgumentParser(prog="xdp_section")
    p.add_argument("--obj", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    args = p.parse_args()

    section = program_section(args.obj)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            resolve_llvm_tool("llvm-objcopy"),
            "-O",
            "binary",
            f"--only-section={section}",
            str(args.obj),
            str(args.out),
        ],
        check=True,
    )
    size = args.out.stat().st_size
    if size == 0:
        raise SystemExit(f"{args.obj}: section {section} extracted to nothing")
    print(f"xdp_section: {args.obj.name} {section} -> {args.out.name} ({size} bytes)")


if __name__ == "__main__":
    main()
