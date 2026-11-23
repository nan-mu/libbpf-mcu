#!/usr/bin/env python3
"""Compile unused/ negatives and require PREVAIL rejection (S1–S4)."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FAILED = ROOT / "tests" / "unused"
sys.path.insert(0, str(Path(__file__).resolve().parent))
from prevail_gate import prevail_bin  # noqa: E402
from llvm_tools import resolve_llvm_tool  # noqa: E402

PREVAIL = prevail_bin()
CLANG = resolve_llvm_tool("clang", prefer_homebrew=True)

CASES = ("xdp_oob_packet", "xdp_null_map_deref", "xdp_uninit_key")


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


def prevail_must_reject(obj: Path) -> None:
    function = obj.stem
    cmd = [str(PREVAIL), "--stack-size", "512", "--section", "xdp", "--function", function, str(obj)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 1 or f"FAIL: xdp/{function}" not in proc.stdout.splitlines():
        raise RuntimeError(
            f"expected a verifier rejection for {function}, got exit {proc.returncode}\n"
            f"{proc.stdout}{proc.stderr}"
        )


def main() -> None:
    if not PREVAIL.is_file():
        sys.stderr.write(f"missing prevail binary: {PREVAIL}\n")
        sys.exit(2)
    failed = 0
    with tempfile.TemporaryDirectory(prefix="bs-neg-") as tmp:
        tmp_path = Path(tmp)
        for name in CASES:
            src = FAILED / f"{name}.c"
            obj = tmp_path / (src.stem + ".o")
            try:
                compile_bpf(src, obj)
                prevail_must_reject(obj)
                print(f"OK reject: {name}")
            except Exception as exc:
                failed += 1
                sys.stderr.write(f"FAIL {name}: {exc}\n")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
