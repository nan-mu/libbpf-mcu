from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from package import DEFAULT_PLAN, ROOT, load_plan, select_modes, verify_package
from layout import (
    LayoutError,
    bpf_path,
    make_index,
    sha256_file,
    source_path,
    write_index,
)
from obj_report import BPF, CodeSection, code_elf


class PackageTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.source = self.root / "example.c"
        self.source.write_text("/* input */\n")
        self.plan = self.root / "plan.toml"
        self.entry = '[[program]]\nname = "example"\nsource = "example.c"\n'

    def load(self, entries):
        self.plan.write_text('schema = "libbpf-mcu.release-plan.v2"\n' + entries)
        return load_plan(self.plan, self.root)

    def test_versioned_config_covers_exactly_formal_programs(self):
        programs = load_plan(DEFAULT_PLAN)
        self.assertEqual(
            {p.source for p in programs}, set((ROOT / "tests/xdp").glob("*.c"))
        )
        self.assertEqual(len(programs), 17)

    def test_missing_firmware_and_bad_digest(self):
        with self.assertRaisesRegex(LayoutError, "example/jit: missing firmware"):
            self.load(self.entry + 'modes = ["jit"]\n')
        spec = (
            self.entry + 'modes = ["jit"]\n[program.firmware.jit]\npath = "image.elf"\n'
        )
        expected = "a" * 64
        with self.assertRaisesRegex(LayoutError, "example/jit firmware: missing file"):
            self.load(spec + f'sha256 = "{expected}"\n')
        image = self.root / "image.elf"
        image.write_bytes(b"firmware")
        with self.assertRaisesRegex(
            LayoutError, "example/jit: firmware SHA-256 mismatch"
        ):
            self.load(spec + f'sha256 = "{expected}"\n')
        (plan,) = self.load(
            spec
            + f'sha256 = "{sha256_file(image)}"\nimage_name = "sample"\nslot_symbol = "xdp_slot_idle"\n'
        )
        self.assertEqual(plan.firmware["jit"].image_name, "sample")
        self.assertEqual(plan.firmware["jit"].slot_symbol, "xdp_slot_idle")

    def test_duplicate_mode_conflicting_archive_and_path_escape(self):
        for text, error in (
            (self.entry + 'modes = ["ebpf", "ebpf"]\n', "duplicate deployment mode"),
            ((self.entry + "modes = []\n") * 2, "conflicting archive"),
            (
                self.entry.replace("example.c", "../example.c") + "modes = []\n",
                "invalid relative path",
            ),
        ):
            with self.subTest(error=error), self.assertRaisesRegex(LayoutError, error):
                self.load(text)

    def test_archive_collision_aborts_before_build(self):
        output = self.root / "out"
        output.mkdir()
        existing = output / "BITSWAP.7Z"
        existing.write_bytes(b"existing archive")
        command = [sys.executable, ROOT / "scripts/package.py", "--out", output]
        env = {
            k: v for k, v in os.environ.items() if k not in ("GITHUB_TOKEN", "GH_TOKEN")
        }
        result = subprocess.run(command, capture_output=True, text=True, env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("archive output already exists", result.stderr)
        self.assertEqual(existing.read_bytes(), b"existing archive")
        self.assertNotIn("build bitswap", result.stderr)

    def test_package_verification_is_independent_of_reports(self):
        stage = self.root / "example"
        obj, src = bpf_path(self.root, "example"), source_path(self.root, "example")
        obj.parent.mkdir(parents=True)
        src.parent.mkdir(parents=True)
        obj.write_bytes(code_elf(CodeSection("xdp", 0, b"\x95" + bytes(7)), BPF))
        src.write_bytes(self.source.read_bytes())
        index = make_index(stage, "example", ())
        write_index(stage / "index.toml", index)
        self.assertEqual(verify_package(stage, "example", ()), index)
        (stage / "bpf" / "report.toml").write_text("This is opaque to verification")
        self.assertEqual(verify_package(stage, "example", ()), index)
        with self.assertRaisesRegex(LayoutError, "example/jit: required mode"):
            select_modes(index, ("jit",))
        (stage / "manifest.toml").touch()
        with self.assertRaisesRegex(LayoutError, "unexpected archive member"):
            verify_package(stage, "example", ())


if __name__ == "__main__":
    unittest.main()
