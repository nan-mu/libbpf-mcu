"""Resolve LLVM host tools: PATH first, then Homebrew keg-only llvm."""

from __future__ import annotations

import shutil
from pathlib import Path

_HOMEBREW_LLVM = (
    Path("/opt/homebrew/opt/llvm/bin"),
    Path("/usr/local/opt/llvm/bin"),
)


def resolve_llvm_tool(name: str, *, prefer_homebrew: bool = False) -> str:
    """Return absolute path or bare name for `clang` / `llvm-objcopy` / …"""
    if prefer_homebrew:
        for prefix in _HOMEBREW_LLVM:
            candidate = prefix / name
            if candidate.is_file():
                return str(candidate)
    found = shutil.which(name)
    if found and not (prefer_homebrew and _is_apple_clang(found)):
        return found
    for prefix in _HOMEBREW_LLVM:
        candidate = prefix / name
        if candidate.is_file():
            return str(candidate)
    return found or name


def _is_apple_clang(path: str) -> bool:
    # Apple clang has no bpf backend; prefer Homebrew llvm when building BPF.
    return path in ("/usr/bin/clang", "/usr/bin/clang++") or path.endswith(
        "/usr/bin/clang"
    )
