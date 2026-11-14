#!/usr/bin/env python3
"""Build-only checks for `build jit`. No device and no oracle sweep."""

from __future__ import annotations

import shutil
import struct
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from build import tool_bin_path  # noqa: E402
from jit_publish import JitDeliverables  # noqa: E402
from xpost_mem import MAGIC, WIRE_SIZE  # noqa: E402

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


def build_argv(*args: str) -> list[str]:
    pixi = shutil.which("pixi")
    if pixi is not None:
        return [pixi, "run", "build", *args]
    return [sys.executable, str(ROOT / "make" / "cli.py"), "build", *args]


def run_build(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        build_argv(*args),
        cwd=ROOT,
        text=True,
        capture_output=True,
    )


class JitBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory(prefix="jit-build-")
        cls.root = Path(cls.tmp.name)
        cls.firmware = cls.root / "firmware.elf"
        cls.firmware.write_bytes(firmware_elf(xpm1_record()))
        cls.jit_dir = cls.root / "jit"
        cls.oob_dir = cls.root / "oob"
        cls.mcu_dir = cls.root / "mcu"
        cls.rbpf_dir = cls.root / "rbpf"
        proc = run_build(
            "jit",
            "-c",
            "firewall",
            "--firmware",
            str(cls.firmware),
            "--build-dir",
            str(cls.jit_dir),
        )
        if proc.returncode != 0:
            raise AssertionError(
                f"jit build exited {proc.returncode}\n{proc.stdout}\n{proc.stderr}"
            )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def test_firewall_lands_in_the_requested_dir(self) -> None:
        stem = self.jit_dir / "firewall"
        for name in ("bpf.o", "bpf.toml"):
            self.assertTrue((stem / name).is_file(), name)
        deliver = JitDeliverables.for_stem(self.jit_dir, "firewall", "firewall")
        for path in deliver.outputs():
            self.assertTrue(path.is_file(), path)
            self.assertTrue(path.is_relative_to(self.jit_dir), path)

    def test_disassembly_and_blacklist_match_jit_bin(self) -> None:
        deliver = JitDeliverables.for_stem(self.jit_dir, "firewall", "firewall")
        blob = deliver.jit_bin.read_bytes()
        doc = tomllib.loads(deliver.jit_toml.read_text())
        jit = doc["jit"]
        self.assertEqual(jit["image_len"], len(blob))
        tail = blob[jit["code_len"] :]
        self.assertEqual(tail, b"\0" * len(tail))
        self.assertEqual(len(tail), 16 * len(jit["map"]))
        lines = [line for line in jit["disassembly"].splitlines() if line.strip()]
        self.assertEqual(len(lines), jit["rv_insns"])
        for line in lines:
            addr_text, word_text, *mnemonic = line.split()
            addr = int(addr_text.rstrip(":"), 16)
            word = int(word_text, 16)
            off = addr - jit["slot"]
            self.assertEqual(int.from_bytes(blob[off : off + 4], "little"), word)
            self.assertTrue(mnemonic)
        blacklist = next(item for item in jit["map"] if item["name"] == "blacklist")
        self.assertEqual(blacklist["storage"], "unknown")
        reloc = next(item for item in jit["reloc"] if item["symbol"] == "blacklist")
        self.assertEqual(reloc["target"], blacklist["vmr"])
        self.assertEqual(reloc["kind"], "lddw")
        raw = b"".join(int(word).to_bytes(4, "little") for word in reloc["result"])
        site = reloc["patch_site"]
        self.assertEqual(blob[site : site + len(raw)], raw)
        self.assertNotEqual(blob[site], 0x18)
        calls = [item for item in jit["reloc"] if item["kind"] == "call"]
        self.assertTrue(calls)
        for item in calls:
            self.assertEqual(item["target"], jit["helper"])
            call_raw = b"".join(int(word).to_bytes(4, "little") for word in item["result"])
            at = item["patch_site"]
            self.assertEqual(blob[at : at + len(call_raw)], call_raw)
            self.assertNotEqual(blob[at], 0x18)

    def test_scan_accepts_the_container(self) -> None:
        deliver = JitDeliverables.for_stem(self.jit_dir, "firewall", "firewall")
        proc = subprocess.run(
            [str(tool_bin_path()), "scan", str(deliver.container)],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_second_build_matches(self) -> None:
        deliver = JitDeliverables.for_stem(self.jit_dir, "firewall", "firewall")
        blob = deliver.jit_bin.read_bytes()
        elf = deliver.container.read_bytes()
        proc = run_build(
            "jit",
            "-c",
            "firewall",
            "--firmware",
            str(self.firmware),
            "--build-dir",
            str(self.jit_dir),
            "-f",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(deliver.jit_bin.read_bytes(), blob)
        self.assertEqual(deliver.container.read_bytes(), elf)

    def test_prevail_failure_removes_planted_deliverables(self) -> None:
        self.oob_dir.mkdir(parents=True, exist_ok=True)
        deliver = JitDeliverables.for_stem(self.oob_dir, "xdp_oob_packet", "xdp_oob_packet")
        deliver.jit_bin.parent.mkdir(parents=True, exist_ok=True)
        for path in deliver.outputs():
            path.write_bytes(b"stale")
        proc = run_build(
            "jit",
            "--inputs",
            str(ROOT / "tests" / "unused" / "xdp_oob_packet.c"),
            "--firmware",
            str(self.firmware),
            "--build-dir",
            str(self.oob_dir),
        )
        self.assertNotEqual(proc.returncode, 0, proc.stdout)
        for path in deliver.outputs():
            self.assertFalse(path.exists(), path)
        self.assertFalse((deliver.jit_bin.parent / ".jit-stage").exists())

    def test_esp32c3_does_not_emit_jit_bin(self) -> None:
        proc = run_build(
            "esp32c3",
            "-c",
            "firewall",
            "--firmware",
            str(self.firmware),
            "--build-dir",
            str(self.mcu_dir),
        )
        self.assertEqual(proc.returncode, 0, f"{proc.stdout}\n{proc.stderr}")
        stem = self.mcu_dir / "firewall"
        self.assertTrue((stem / "esp32c3.o").is_file())
        self.assertFalse((stem / "jit.bin").exists())
        text = (self.mcu_dir / ".ninja" / "build.ninja").read_text()
        self.assertIn(": mcu_cc ", text)
        self.assertNotIn(": jit_publish ", text)

    def test_rbpf_keeps_map_index_and_skips_jit(self) -> None:
        proc = run_build(
            "-c",
            "firewall",
            "--engine",
            "rbpf",
            "--firmware",
            str(self.firmware),
            "--build-dir",
            str(self.rbpf_dir),
        )
        self.assertEqual(proc.returncode, 0, f"{proc.stdout}\n{proc.stderr}")
        self.assertFalse((self.rbpf_dir / "firewall" / "jit.bin").exists())
        text = (self.rbpf_dir / ".ninja" / "build.ninja").read_text()
        self.assertIn("--map-index", text)
        self.assertNotIn(": jit_publish ", text)


if __name__ == "__main__":
    unittest.main()
