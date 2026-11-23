"""Real BPF, AOT, interpreter and JIT build and report regressions."""

from __future__ import annotations

import re
import struct
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

from build import tool_bin_path
from build_state import read_state, render_reports
from layout import (
    ROOT,
    LayoutError,
    bpf_path,
    container_path,
    export_legacy,
    load_index,
    report_path,
    source_path,
    state_path,
)
from obj_report import executable_sections
from xpost_elf import parse_container
from xpost_mem import MAGIC, WIRE_SIZE

HELPER = 0x40380000
SLOT = 0x40380200
SLOT_LEN = 0xE00


def xpm1_record() -> bytes:
    payload = struct.pack("<6I", MAGIC, HELPER, SLOT, SLOT_LEN, 0x310000, 0x10000)
    if len(payload) != WIRE_SIZE:
        raise RuntimeError(f"XPM1 record is {len(payload)} bytes, not {WIRE_SIZE}")
    return payload


def firmware_elf(payload: bytes) -> bytes:
    """ELF32 whose only payload is the 24-byte `.xpost.mem` record."""
    shstr = b"\0.shstrtab\0.xpost.mem\0"
    payload_off = 52
    shstr_off = payload_off + len(payload)
    shoff = (shstr_off + len(shstr) + 3) & ~3
    shnum = 3
    shentsize = 40

    def shdr(name: int, typ: int, off: int, size: int) -> bytes:
        return struct.pack("<10I", name, typ, 0, 0, off, size, 0, 0, 1, 0)

    ident = bytearray(16)
    ident[0:4] = b"\x7fELF"
    ident[4] = 1
    ident[5] = 1
    ident[6] = 1
    header = struct.pack(
        "<16sHHIIIIIHHHHHH",
        bytes(ident),
        2,
        243,
        1,
        0,
        0,
        shoff,
        0,
        52,
        0,
        0,
        shentsize,
        shnum,
        1,
    )
    blob = bytearray(shoff + shnum * shentsize)
    blob[:52] = header
    blob[payload_off : payload_off + len(payload)] = payload
    blob[shstr_off : shstr_off + len(shstr)] = shstr
    blob[shoff : shoff + 40] = shdr(0, 0, 0, 0)
    blob[shoff + 40 : shoff + 80] = shdr(1, 3, shstr_off, len(shstr))
    blob[shoff + 80 : shoff + 120] = shdr(11, 1, payload_off, len(payload))
    return bytes(blob)


def run_build(*args, build_dir: Path, check=True):
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "make" / "cli.py"),
            "build",
            *map(str, args),
            "--build-dir",
            str(build_dir),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    if check and result.returncode:
        raise AssertionError(
            f"build exited {result.returncode}\n{result.stdout}\n{result.stderr}"
        )
    return result


class ProgramBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory(prefix="program-build-")
        cls.addClassCleanup(tmp.cleanup)
        cls.root = Path(tmp.name).resolve()
        cls.firmware = cls.root / "firmware.elf"
        cls.firmware.write_bytes(firmware_elf(xpm1_record()))
        cls.build_dir = cls.root / "build"
        cls.program = cls.build_dir / "just_tx"
        cls.aot_args = ("esp32c3", "-c", "just_tx", "--firmware", cls.firmware)
        cls.ebpf_args = (*cls.aot_args, "--engine", "rbpf")
        cls.jit_args = ("jit", "-c", "just_tx", "--firmware", cls.firmware)
        for args in (cls.aot_args, cls.ebpf_args, cls.jit_args):
            run_build(*args, build_dir=cls.build_dir)

    def test_exact_executable_bytes_and_source(self):
        root, name = self.build_dir, "just_tx"
        original = (ROOT / "tests/xdp/just_tx.c").read_bytes()
        self.assertEqual(original, source_path(root, name).read_bytes())
        native = executable_sections(
            (self.program / "llvm-aot" / "just_tx_rv32.debug.elf").read_bytes()
        )
        bpf = executable_sections(bpf_path(root, name).read_bytes())
        for mode in ("bpf", "llvm-aot", "ebpf", "jit"):
            with self.subTest(mode=mode):
                path = report_path(root, name, mode)
                doc = tomllib.loads(path.read_text())
                self.assertEqual(set(doc), {"source", "assembly", "generation"})
                self.assertEqual(doc["source"]["path"], "tests/xdp/just_tx.c")
                self.assertEqual(doc["source"]["text"].encode(), original)
                self.assertIn("rxcnt = {", doc["source"]["text"])
                if mode == "bpf":
                    expected = {code.name: (0, code.data) for code in bpf}
                else:
                    container = container_path(root, name, mode)
                    meta, image = parse_container(container.read_bytes())
                    self.assertEqual(
                        (meta.helper_address, meta.slot_address), (HELPER, SLOT)
                    )
                    self.assertEqual([item.name for item in meta.maps], ["rxcnt"])
                    if mode == "llvm-aot":
                        expected = {
                            code.name: (
                                code.address,
                                image[
                                    code.address - SLOT : code.address
                                    - SLOT
                                    + len(code.data)
                                ],
                            )
                            for code in native
                        }
                    elif mode == "ebpf":
                        expected = {"xdp1": (0, image)}
                        self.assertNotEqual(
                            image,
                            next(code.data for code in bpf if code.name == "xdp1"),
                        )
                    else:
                        code_len = meta.maps[0].map_vma - SLOT
                        expected = {".text": (SLOT, image[:code_len])}
                        self.assertEqual(image[code_len:], bytes(16))
                seen = set()
                at, payload = 0, b""
                for line in doc["assembly"]["listing"].splitlines():
                    match = re.fullmatch(r"([a-z0-9_.]+)  \(.+\)", line)
                    if match:
                        self.assertEqual(payload, b"")
                        section = match.group(1)
                        self.assertNotIn(section, seen)
                        seen.add(section)
                        at, payload = expected[section]
                    else:
                        offset, encoded, mnemonic = re.split(r" {2,}", line, maxsplit=2)
                        raw = bytes.fromhex(encoded)
                        self.assertEqual(int(offset, 16), at)
                        self.assertTrue(payload.startswith(raw))
                        self.assertNotEqual(mnemonic, "<unknown>")
                        at, payload = at + len(raw), payload[len(raw) :]
                self.assertEqual(payload, b"")
                self.assertEqual(seen, expected.keys())
                generation = read_state(state_path(root, name, "bpf"))["generation"]
                if mode == "ebpf":
                    generation += read_state(state_path(root, name, "ebpf-native"))[
                        "generation"
                    ]
                if mode != "bpf":
                    generation += read_state(state_path(root, name, mode))["generation"]
                self.assertEqual(doc["generation"], generation)
                self.assertIn("--target=bpf", generation[0]["argv"])
                self.assertIn("-O2", generation[0]["argv"])
                if mode != "bpf":
                    subprocess.run([tool_bin_path(root), "scan", container], check=True)

    def test_incremental_and_reports_are_not_inputs(self):
        root, name = self.build_dir, "just_tx"
        reports = [
            report_path(root, name, mode) for mode in ("bpf", "llvm-aot", "ebpf", "jit")
        ]
        saved = {p: p.read_bytes() for p in reports}
        try:
            reports[0].write_text("changed report")
            for path in reports[1:]:
                path.unlink()
            self.assertEqual(len(load_index(self.program)["mode"]), 3)
            for mode in ("rv32", "bpf-xpost", "jit"):
                self.assertIn(
                    name, export_legacy(root, self.root / f"legacy-{mode}", mode)
                )
            legacy = self.root / "legacy-rv32" / name
            addresses = tomllib.loads((legacy / "bpf.toml").read_text())["maps"][
                "rxcnt"
            ]
            meta, _ = parse_container(
                container_path(root, name, "llvm-aot").read_bytes()
            )
            self.assertEqual(addresses["aot_addr"], meta.maps[0].map_vma)
            with self.assertRaisesRegex(LayoutError, "refusing to mix"):
                export_legacy(root, self.root / "legacy-rv32", "jit")
            for args in (self.aot_args, self.ebpf_args, self.jit_args):
                run = run_build(*args, build_dir=root)
                self.assertIn("ninja: no work to do.", run.stdout)
                graph = (root / ".ninja" / "build.ninja").read_text()
                self.assertNotIn("report.toml", graph)
                self.assertNotIn("--bpf-toml", graph)
                self.assertNotIn("--addr-toml", graph)
            for args in (self.aot_args, self.ebpf_args, self.jit_args):
                for path in reports:
                    path.unlink(missing_ok=True)
                run = run_build(*args, "--force", build_dir=root)
                self.assertIn("prevail just_tx", run.stdout)
                self.assertEqual(len(load_index(self.program)["mode"]), 3)
            render_reports(root, name, force=True)
            for path, data in saved.items():
                self.assertEqual(path.read_bytes(), data)
        finally:
            for path, data in saved.items():
                path.write_bytes(data)

    def test_firmware_rebuild_only_retracts_invalid_mode(self):
        root = self.build_dir
        firmware = self.root / "other-firmware.elf"
        firmware.write_bytes(self.firmware.read_bytes())
        jit = ("jit", "-c", "just_drop", "--firmware", firmware)
        aot = ("esp32c3", "-c", "just_drop", "--firmware", self.firmware)
        run_build(*aot, build_dir=root)
        run_build(*jit, build_dir=root)
        program = root / "just_drop"
        bpf = bpf_path(root, "just_drop")
        bpf_time = bpf.stat().st_mtime_ns
        original = container_path(root, "just_drop", "jit").read_bytes()
        data = bytearray(xpm1_record())
        struct.pack_into("<I", data, 8, SLOT + 0x1000)
        firmware.write_bytes(firmware_elf(bytes(data)))
        rebuilt = run_build(*jit, build_dir=root)
        self.assertIn("host JIT:", rebuilt.stdout)
        self.assertEqual(bpf.stat().st_mtime_ns, bpf_time)
        self.assertNotEqual(
            container_path(root, "just_drop", "jit").read_bytes(), original
        )
        firmware.write_bytes(b"broken firmware")
        failure = run_build(*jit, build_dir=root, check=False)
        self.assertNotEqual(failure.returncode, 0)
        self.assertEqual(
            [row["name"] for row in load_index(program)["mode"]], ["llvm-aot"]
        )
        self.assertTrue((root / ".ninja/just_drop/diagnostics.json").is_file())
        firmware.write_bytes(firmware_elf(bytes(data)))
        run_build(*jit, build_dir=root)
        self.assertEqual(
            [row["name"] for row in load_index(program)["mode"]], ["llvm-aot", "jit"]
        )

    def test_prevail_rejection_leaves_only_the_raw_object(self):
        source = ROOT / "tests/unused/xdp_oob_packet.c"
        process = run_build(
            "jit",
            "--inputs",
            source,
            "--firmware",
            self.firmware,
            build_dir=self.build_dir,
            check=False,
        )
        self.assertNotEqual(process.returncode, 0)
        self.assertFalse((self.build_dir / source.stem / "bpf" / "prevail.ok").exists())
        self.assertEqual(load_index(self.build_dir / source.stem)["mode"], [])


if __name__ == "__main__":
    unittest.main()
