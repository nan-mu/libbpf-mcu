#!/usr/bin/env python3
"""Compile unused/ negatives and require PREVAIL rejection (S1–S4)."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FAILED = ROOT / "tests" / "unused"
PREVAIL = ROOT.parent / "prevail" / "bin" / "prevail"
CLANG = "clang"

CASES = [
    ("xdp_oob_packet.c", "xdp", None),
    ("xdp_null_map_deref.c", "xdp", None),
    ("xdp_uninit_key.c", "xdp", None),
]


def compile_bpf(src: Path, out: Path) -> None:
    cmd = [
        CLANG,
        "-O2",
        "--target=bpf",
        "-Wall",
        "-Wno-unused-variable",
        "-fno-stack-protector",
        "-g",
        f"-I{ROOT / 'include-bpf'}",
        "-include",
        "vmlinux.h",
        "-c",
        str(src),
        "-o",
        str(out),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"compile failed {src.name}:\n{proc.stderr}")


def prevail_must_reject(obj: Path, section: str) -> None:
    cmd = [str(PREVAIL), str(obj), "--section", section]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    out = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode == 0 and "PASS" in out:
        raise RuntimeError(f"PREVAIL unexpectedly PASS for {obj.name}:\n{out}")
    if "PASS" in out and "FAIL" not in out and proc.returncode == 0:
        raise RuntimeError(f"PREVAIL unexpectedly accepted {obj.name}:\n{out}")


def main() -> None:
    if not PREVAIL.is_file():
        sys.stderr.write(f"missing prevail binary: {PREVAIL}\n")
        sys.exit(2)
    failed = 0
    with tempfile.TemporaryDirectory(prefix="bs-neg-") as tmp:
        tmp_path = Path(tmp)
        for name, section, _fn in CASES:
            src = FAILED / name
            obj = tmp_path / (src.stem + ".o")
            try:
                compile_bpf(src, obj)
                prevail_must_reject(obj, section)
                print(f"OK reject: {name}")
            except Exception as exc:
                failed += 1
                sys.stderr.write(f"FAIL {name}: {exc}\n")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
