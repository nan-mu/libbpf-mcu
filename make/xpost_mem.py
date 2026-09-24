#!/usr/bin/env python3
"""Read firmware XPM1 (`.xpost.mem`) via llvm-objcopy."""
from __future__ import annotations

import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

SECTION_NAME = ".xpost.mem"
WIRE_SIZE = 24
MAGIC = int.from_bytes(b"XPM1", "little")


@dataclass(frozen=True)
class MemMapV0:
    helper_addr: int
    slot_addr: int
    slot_len: int
    table_addr: int
    table_len: int


def decode_xpm1(data: bytes) -> MemMapV0:
    if len(data) < WIRE_SIZE:
        raise ValueError(f"{SECTION_NAME}: truncated ({len(data)} < {WIRE_SIZE})")
    magic, helper, slot, slot_len, table, table_len = struct.unpack_from("<6I", data, 0)
    if magic != MAGIC:
        raise ValueError(f"{SECTION_NAME}: bad magic {magic:#x} (expected XPM1)")
    if helper == 0:
        raise ValueError(f"{SECTION_NAME}: helper_addr is 0")
    if slot == 0:
        raise ValueError(f"{SECTION_NAME}: slot_addr is 0")
    if slot_len == 0:
        raise ValueError(f"{SECTION_NAME}: slot_len is 0")
    if table_len == 0:
        raise ValueError(f"{SECTION_NAME}: table_len is 0")
    return MemMapV0(helper, slot, slot_len, table, table_len)


def load_mem_map_from_firmware(firmware_elf: Path, objcopy: str) -> MemMapV0:
    """Dump `.xpost.mem` with llvm-objcopy and decode XPM1."""
    if not firmware_elf.is_file():
        raise FileNotFoundError(f"firmware ELF not found: {firmware_elf}")
    with tempfile.TemporaryDirectory(prefix="xpost-mem-") as tmp:
        out = Path(tmp) / "xpm1.bin"
        cmd = [
            objcopy,
            f"--dump-section={SECTION_NAME}={out}",
            str(firmware_elf),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(
                f"objcopy dump {SECTION_NAME} failed (exit {proc.returncode}): "
                f"{proc.stderr.strip() or proc.stdout.strip()}"
            )
        if not out.is_file():
            raise RuntimeError(f"objcopy did not write {out}")
        return decode_xpm1(out.read_bytes())
