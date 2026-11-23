from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from layout import (
    LayoutError,
    bpf_path,
    container_path,
    load_index,
    make_index,
    native_object_path,
    source_path,
    verify_tree,
    write_index,
)
from obj_report import BPF, RISCV, CodeSection, code_elf, write_report
from xpost_elf import ImageMetadataV0, build_container


class LayoutTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.program = self.root / "example"
        self.index = self.program / "index.toml"
        elf = code_elf(
            CodeSection("xdp", 0, bytes.fromhex("95 00 00 00 00 00 00 00")), BPF
        )
        metadata = ImageMetadataV0(0x1000, 0x2000, 1, "example")
        self.obj = bpf_path(self.root, "example")
        self.deployment = container_path(self.root, "example", "jit")
        self.source = source_path(self.root, "example")
        for path, data in (
            (self.source, b"// program\n"),
            (self.obj, elf),
            (self.deployment, build_container(b"\x13\0\0\0", metadata)),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.document = make_index(self.program, "example", ("jit",))
        write_index(self.index, self.document)

    def test_verify_independently(self):
        self.assertEqual(load_index(self.program), self.document)
        self.assertEqual(verify_tree(self.root), [self.document])
        (self.program / "report.md").write_text("edited by a human")
        self.assertEqual(verify_tree(self.root), [self.document])

    def test_all_indexed_members_are_hashed(self):
        for path in (self.source, self.obj, self.deployment):
            data = path.read_bytes()
            with self.subTest(path=path):
                path.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
                with self.assertRaisesRegex(LayoutError, "SHA-256"):
                    load_index(self.program)
                path.write_bytes(data)

    def test_missing_file_and_symlink(self):
        data = self.obj.read_bytes()
        self.obj.unlink()
        with self.assertRaisesRegex(LayoutError, "missing file"):
            load_index(self.program)
        outside = self.root / "outside.o"
        outside.write_bytes(data)
        self.obj.symlink_to(outside)
        with self.assertRaisesRegex(LayoutError, "symlink"):
            load_index(self.program)

    def test_aot_native_object_is_indexed_and_checked(self):
        aot = container_path(self.root, "example", "llvm-aot")
        aot.write_bytes(self.deployment.read_bytes())
        obj = native_object_path(self.root, "example")
        data = bytearray(code_elf(CodeSection(".text", 0, b"\x13\0\0\0"), RISCV))
        data[16:18] = (1).to_bytes(2, "little")  # ET_REL
        obj.write_bytes(data)
        index = make_index(self.program, "example", ("llvm-aot",))
        write_index(self.index, index)
        self.assertEqual(
            load_index(self.program)["mode"][0]["object"]["path"],
            "objects/example_rv32.o",
        )
        obj.write_bytes(bytes(data[:-1]) + b"!")
        with self.assertRaisesRegex(LayoutError, "SHA-256"):
            load_index(self.program)
        obj.write_bytes(self.obj.read_bytes())
        write_index(self.index, make_index(self.program, "example", ("llvm-aot",)))
        with self.assertRaisesRegex(LayoutError, "relocatable RV32 ELF"):
            load_index(self.program)

    def test_duplicate_mode_and_escaped_path(self):
        self.document["mode"] *= 2
        write_index(self.index, self.document)
        with self.assertRaisesRegex(LayoutError, "duplicate mode"):
            load_index(self.program)
        self.document["mode"].pop()
        self.document["mode"][0]["elf"]["path"] = "../outside"
        write_index(self.index, self.document)
        with self.assertRaisesRegex(LayoutError, "invalid index path"):
            load_index(self.program)

    def test_invalid_container_cannot_be_indexed_as_usable(self):
        self.deployment.write_bytes(b"not a container")
        write_index(self.index, make_index(self.program, "example", ("jit",)))
        with self.assertRaisesRegex(LayoutError, "invalid container"):
            load_index(self.program)

    def test_report_keeps_source_bytes_and_fences_untrusted_content(self):
        report = self.program / "report.md"
        calls = [{"step": "compile", "argv": ["clang", "two words.c", "file`name.o"]}]
        sections = [
            ("bpf", "raw listing\n", calls),
            ("llvm-aot", "compiled RV32IMC\n", []),
            ("ebpf", "rewritten listing\n", []),
            ("jit", "linked RV32IM\n", []),
        ]
        for source, block in (
            (b"// comments\n\nint x;\n", b"```c\n// comments\n\nint x;\n```"),
            (b"/*\r\n````\r\n*/\r\n", b"`````c\n/*\r\n````\r\n*/\r\n`````"),
            (b"int x;", b"```c\nint x;\n```"),
        ):
            with self.subTest(source=source):
                write_report(report, "example.c", source, sections)
                text = report.read_bytes()
                self.assertEqual(text.count(block), 1)
                self.assertEqual(
                    b"ends without a newline" in text, not source.endswith(b"\n")
                )
                headings = [
                    line for line in text.splitlines() if line.startswith((b"## ", b"### "))
                ]
                self.assertEqual(
                    headings,
                    [
                        b"## Source", b"## eBPF", b"### bpf", b"### ebpf",
                        b"## RV32IMC", b"### llvm-aot", b"### jit",
                    ],
                )
                self.assertEqual(text.count(b"#### Machine code and assembly\n"), 4)
                self.assertEqual(text.count(b"#### Build steps\n"), 4)
                self.assertIn(b"$ clang 'two words.c' 'file`name.o'", text)


if __name__ == "__main__":
    unittest.main()
