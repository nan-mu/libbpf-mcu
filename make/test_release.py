from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from layout import MODES, LayoutError, bpf_path, container_path, load_index, make_index, native_object_path, portable_paths, sha256_file, source_path, write_index
from obj_report import BPF, RISCV, CodeSection, code_elf
from native_image import SCHEMA
from release import PROGRAMS, archiver, read_archive_paths, select_tag, verify_batch
from xpost_elf import ImageMetadataV0, build_container


class ReleaseTests(unittest.TestCase):
    def make_program(self, root):
        name = "firewall"
        program = root / name
        bpf = bpf_path(root, name)
        bpf.parent.mkdir(parents=True)
        bytecode = bytes.fromhex("95 00 00 00 00 00 00 00")
        bpf.write_bytes(code_elf(CodeSection("xdp", 0, bytecode), BPF))
        obj = bytearray(code_elf(CodeSection(".text", 0, b"\x13\0\0\0"), RISCV))
        obj[16:18] = b"\x01\0"
        native_object_path(root, name).write_bytes(obj)
        source_path(root, name).write_text("/* source */\n")
        (program / "report.md").write_text("# Build report\n")
        for mode in MODES:
            image, layout = portable_paths(root, name, mode)
            image.parent.mkdir(exist_ok=True)
            payload = {
                "llvm-aot": b"\x13\0\0\0",
                "ebpf": bytecode,
                "jit": bytes.fromhex("37 03 00 00 e7 00 03 00"),
            }[mode]
            image.write_bytes(payload)
            layout.write_text(json.dumps(dict(
                schema=SCHEMA, program=name, mode=mode, base=0, entry_offset=0, alignment=4,
                regions=[dict(name=".text", kind="code", offset=0, size=len(payload), alignment=4)],
                maps=[], fixups=([dict(offset=0, kind="call-abs", target="helper_dispatcher", addend=0)]
                                if mode == "jit" else []),
            )))
        index = make_index(program, name, MODES, portable=set(MODES))
        write_index(program / "index.toml", index)
        self.assertEqual(load_index(program), index)
        return name, program, index

    def repack(self, root, name, program):
        archives = root / "archives"
        archives.mkdir()
        archive = archives / f"{name}.7z"
        subprocess.run([archiver(), "a", "-t7z", "--", archive, "."], cwd=program,
                       check=True, stdout=subprocess.DEVNULL)
        # The first invalid archive is rejected before examining any other archive.
        for other in PROGRAMS:
            if other != name:
                (archives / f"{other}.7z").touch()
        return archives, {archive.name: sha256_file(archive)}

    def test_repacked_missing_mode_fails_the_release_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            name, program, index = self.make_program(root)
            for path in portable_paths(root, name, "jit"):
                path.unlink()
            index["mode"] = [mode for mode in index["mode"] if mode["name"] != "jit"]
            write_index(program / "index.toml", index)
            self.assertEqual(load_index(program), index)
            archives, ledger = self.repack(root, name, program)
            with self.assertRaisesRegex(LayoutError, "firewall/jit: missing required deployment"):
                verify_batch(None, archives, root / "unpacked", ledger)

    def test_repacked_missing_jit_fixup_is_rejected_with_new_hash_and_sites(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            name, program, _ = self.make_program(root)
            _, layout = portable_paths(root, name, "jit")
            doc = json.loads(layout.read_bytes())
            doc["fixups"].clear()
            layout.write_text(json.dumps(doc))
            write_index(program / "index.toml", make_index(program, name, MODES, portable=set(MODES)))
            archives, ledger = self.repack(root, name, program)
            with self.assertRaisesRegex(LayoutError, "unresolved instruction sites"):
                verify_batch(None, archives, root / "unpacked", ledger)

    def test_fixed_address_containers_are_rejected_by_release_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            name, program, _ = self.make_program(root)
            meta = ImageMetadataV0(0x1000, 0x2000, 1, name)
            for mode in MODES:
                image, layout = portable_paths(root, name, mode)
                elf = container_path(root, name, mode)
                elf.parent.mkdir(exist_ok=True)
                elf.write_bytes(build_container(image.read_bytes(), meta))
                image.unlink()
                layout.unlink()
            (program / "images").rmdir()
            index = make_index(program, name, MODES)
            write_index(program / "index.toml", index)
            self.assertEqual(load_index(program), index)
            archives, ledger = self.repack(root, name, program)
            with self.assertRaisesRegex(LayoutError, "unexpected archive member 'containers'"):
                verify_batch(None, archives, root / "unpacked", ledger)

    def test_duplicate_and_wrapped_archive_paths(self):
        for listing, reason in (
            ("Path = index.toml\n\nPath = index.toml\n", "duplicate archive member"),
            ("Path = just_tx/index.toml\n", "unexpected archive member"),
        ):
            with self.subTest(listing=listing):
                with patch("release.subprocess.check_output", return_value=listing):
                    with self.assertRaisesRegex(LayoutError, reason):
                        read_archive_paths("7zz", Path("just_tx.7z"), "just_tx")

    def test_series_and_retry(self):
        for patch, next_patch in ((0, 1), (9, 10), (99, 100)):
            with self.subTest(patch=patch):
                self.assertEqual(select_tag(f"old\trefs/tags/v0.1.{patch}", "new"),
                                 f"v0.1.{next_patch}")
        refs = "a\trefs/tags/v0.1.9\nb\trefs/tags/v0.1.10\nc\trefs/tags/v0.2.0"
        self.assertEqual(select_tag(refs, "new"), "v0.1.11")
        self.assertEqual(select_tag(refs, "b"), "v0.1.10")
        self.assertEqual(select_tag(refs, "new", "v0.1.10"), "v0.1.11")
        self.assertEqual(select_tag(refs, "new", "v0.1.8"), "v0.1.8")
        self.assertEqual(select_tag(refs + "\nnew\trefs/tags/v0.1.10^{}", "new"), "v0.1.10")


if __name__ == "__main__":
    unittest.main()
