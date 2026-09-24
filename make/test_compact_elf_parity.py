#!/usr/bin/env python3
"""Byte-compare Rust xpost-compact-elf vs Python build_container golden."""
from __future__ import annotations

import platform
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from xpost_elf import ImageMetadataV0, MapDescriptorV0, build_container

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "xpost" / "xpost-build" / "Cargo.toml"


def host_triple() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "darwin" and machine in ("arm64", "aarch64"):
        return "aarch64-apple-darwin"
    if system == "darwin":
        return "x86_64-apple-darwin"
    if machine in ("arm64", "aarch64"):
        return "aarch64-unknown-linux-gnu"
    return "x86_64-unknown-linux-gnu"


class RustPythonParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not MANIFEST.is_file():
            raise unittest.SkipTest(f"missing {MANIFEST}")

    def test_golden_matches_rust_cli(self):
        image = b"\x01\x00\x82\x80\xff"
        meta = ImageMetadataV0(
            0x40380000,
            0x40381000,
            1,
            "example",
            (MapDescriptorV0("stats", 2, 16, 0x40380100, None, (32, 32)),),
        )
        expected = build_container(image, meta)
        toml_text = """[maps.stats]
map_type = "BPF_MAP_TYPE_ARRAY"
key_size = 4
value_size = 8
max_entries = 16
aot_addr = 0x40380100
key = "u32 index"
value = "u32 a\\nu32 b"
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            img = root / "img.bin"
            bpf = root / "bpf.toml"
            out = root / "example.elf"
            img.write_bytes(image)
            bpf.write_text(toml_text)
            cmd = [
                "cargo",
                "run",
                "--manifest-path",
                str(MANIFEST),
                "--target",
                host_triple(),
                "--release",
                "--bin",
                "xpost-compact-elf",
                "--",
                "--image",
                str(img),
                "--bpf-toml",
                str(bpf),
                "--name",
                "example",
                "--slot-address",
                "0x40380000",
                "--helper-address",
                "0x40381000",
                "-o",
                str(out),
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode != 0:
                self.fail(f"rust cli failed: {proc.stderr}\n{proc.stdout}")
            self.assertEqual(out.read_bytes(), expected)


if __name__ == "__main__":
    unittest.main()
