#!/usr/bin/env python3
"""Compare the production host packer and Python Compact ELF V0 codec."""
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from build import CLANG, ensure_tool
from xpost_elf import ImageMetadataV0, MapDescriptorV0, build_container, parse_container


class RustPythonParity(unittest.TestCase):
    def test_host_pack_matches_python_codec(self):
        meta = ImageMetadataV0(
            0x40380000,
            0x40381000,
            1,
            "example",
            (MapDescriptorV0("stats", 2, 16, 0x40380100, None, (32, 32)),),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tool = ensure_tool(root)
            assembly = root / "fixture.S"
            linked = root / "fixture.elf"
            maps = root / "maps.toml"
            raw = root / "image.bin"
            out = root / "example.elf"
            assembly.write_text(
                '.text\n.globl _start\n_start: nop\n'
                '.section .maps,"aw",@progbits\n.globl stats\nstats: .zero 8\n'
            )
            subprocess.run(
                [
                    CLANG, "--target=riscv32-unknown-none-elf", "-nostdlib",
                    "-fuse-ld=lld", "-Wl,--section-start=.maps=0x40380100",
                    assembly, "-o", linked,
                ],
                check=True,
            )
            maps.write_text(
                '[maps.stats]\nmap_type = 2\n'
                'key_size = 4\nvalue_size = 8\nmax_entries = 16\n'
                'key = "u32 index"\nvalue = "u32 a\\nu32 b"\n'
            )
            # The same large input exercises both encoders and the Python reader.
            for image in (b"\x01\x00\x82\x80\xff", b"\xa5" * 17_001):
                with self.subTest(image_bytes=len(image)):
                    raw.write_bytes(image)
                    proc = subprocess.run(
                        [
                            tool, "pack", "--linked-elf", linked, "--maps", maps,
                            "--image", raw, "--name", meta.name,
                            "--slot-address", hex(meta.slot_address),
                            "--helper-address", hex(meta.helper_address),
                            "--slot-length", "0x5000", "-o", out,
                        ],
                        capture_output=True, text=True,
                    )
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    rust = out.read_bytes()
                    python = build_container(image, meta)
                    self.assertEqual(parse_container(rust), (meta, image))
                    self.assertEqual(parse_container(python), (meta, image))
                    self.assertEqual(rust, python)


if __name__ == "__main__":
    unittest.main()
