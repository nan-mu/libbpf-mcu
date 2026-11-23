"""Real BPF, AOT, interpreter and JIT build and report regressions."""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from build import tool_bin_path
from build_state import read_state, render_reports
from layout import (
    ROOT,
    bpf_path,
    container_path,
    load_index,
    native_object_path,
    report_path,
    source_path,
    state_path,
)
from llvm_tools import resolve_llvm_tool
from obj_report import MACHINES, executable_sections
from xpost_elf import parse_container
from xpost_mem import MAGIC, WIRE_SIZE

HELPER = 0x40380000
SLOT = 0x40380200
SLOT_LEN = 0xE00


def xpm1_record(slot_len: int = SLOT_LEN) -> bytes:
    payload = struct.pack("<6I", MAGIC, HELPER, SLOT, slot_len, 0x310000, 0x10000)
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


def run_build(*args, build_dir: Path, check=True, env=None):
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
        env=env,
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
        cls.aot_args = ("rv32imc", "-c", "just_tx", "--firmware", cls.firmware)
        cls.ebpf_args = (*cls.aot_args, "--engine", "rbpf")
        cls.jit_args = ("jit", "-c", "just_tx", "--firmware", cls.firmware)
        for args in (cls.aot_args, cls.ebpf_args, cls.jit_args):
            run_build(*args, build_dir=cls.build_dir)

    def test_exact_executable_bytes_and_source(self):
        root, name = self.build_dir, "just_tx"
        original = (ROOT / "tests/xdp/just_tx.c").read_bytes()
        self.assertEqual(original, source_path(root, name).read_bytes())
        native_state = read_state(state_path(root, name, "llvm-aot"))
        native = executable_sections(Path(native_state["linked_elf"]).read_bytes())
        self.assertTrue(native_object_path(root, name).is_file())
        report = report_path(root, name).read_text()
        self.assertEqual(report.count(original.decode()), 1)
        self.assertIn("tests/xdp/just_tx.c", report)
        self.assertEqual(
            re.findall(r"^## (.+)$", report, flags=re.MULTILINE),
            ["Source", "eBPF", "RV32IMC"],
        )
        sections = re.split(r"^### (.+)$", report, flags=re.MULTILINE)
        sections = dict(zip(sections[1::2], sections[2::2], strict=True))
        self.assertEqual(set(sections), {"bpf", "llvm-aot", "ebpf", "jit"})
        bpf = executable_sections(bpf_path(root, name).read_bytes())
        for mode in ("bpf", "llvm-aot", "ebpf", "jit"):
            with self.subTest(mode=mode):
                section_text = sections[mode]
                self.assertIn(MACHINES[mode], section_text)
                match = re.search(
                    r"^#### Machine code and assembly\n+(`{3,})text\n(.*?)^\1$",
                    section_text,
                    re.MULTILINE | re.DOTALL,
                )
                self.assertIsNotNone(match)
                listing = match.group(2)
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
                        expected = {"xdp": (0, image)}
                        self.assertNotEqual(
                            image,
                            next(code.data for code in bpf if code.name == "xdp"),
                        )
                    else:
                        code_len = meta.maps[0].map_vma - SLOT
                        expected = {".text": (SLOT, image[:code_len])}
                        self.assertEqual(image[code_len:], bytes(16))
                seen = set()
                at, payload = 0, b""
                for line in listing.splitlines():
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
                steps = section_text.split("#### Build steps", 1)[1]
                for step in generation:
                    self.assertIn(step["step"], steps)
                    if "argv" in step:
                        self.assertIn("$ " + shlex.join(step["argv"]), steps)
                    else:
                        params = json.dumps(
                            step["parameters"], ensure_ascii=False, indent=2
                        )
                        self.assertIn(step["call"] + "\n" + params, steps)
                self.assertIn("--target=bpf", generation[0]["argv"])
                self.assertIn("-O2", generation[0]["argv"])
                if mode != "bpf":
                    subprocess.run([tool_bin_path(root), "scan", container], check=True)

    def test_incremental_and_reports_are_not_inputs(self):
        root, name = self.build_dir, "just_tx"
        report = report_path(root, name)
        original = report.read_bytes()
        report.unlink()
        self.assertEqual(len(load_index(self.program)["mode"]), 3)
        for args in (self.aot_args, self.ebpf_args, self.jit_args):
            run = run_build(*args, build_dir=root)
            self.assertIn("ninja: no work to do.", run.stdout)
            graph = (root / ".ninja" / "build.ninja").read_text()
            self.assertNotIn("report.md", graph)
        self.assertEqual(report.read_bytes(), original)
        for args in (self.aot_args, self.ebpf_args, self.jit_args):
            run = run_build(*args, "--force", build_dir=root)
            self.assertIn("prevail just_tx", run.stdout)
            self.assertEqual(len(load_index(self.program)["mode"]), 3)
        render_reports(root, name, force=True)
        self.assertEqual(report.read_bytes(), original)

    def test_firmware_rebuild_only_retracts_invalid_mode(self):
        root = self.build_dir
        firmware = self.root / "other-firmware.elf"
        firmware.write_bytes(self.firmware.read_bytes())
        jit = ("jit", "-c", "just_drop", "--firmware", firmware)
        aot = ("rv32imc", "-c", "just_drop", "--firmware", self.firmware)
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
        diagnostics = json.loads(
            (root / ".ninja/just_drop/diagnostics.json").read_text()
        )
        self.assertEqual(set(diagnostics), {"preflight/jit"})
        firmware.write_bytes(firmware_elf(bytes(data)))
        run_build(*jit, build_dir=root)
        self.assertEqual(
            [row["name"] for row in load_index(program)["mode"]], ["llvm-aot", "jit"]
        )

    def test_rewritten_bytecode_must_fit_firmware_slot(self):
        program = "just_tx"
        _, payload = parse_container(
            container_path(self.build_dir, program, "ebpf").read_bytes()
        )
        with tempfile.TemporaryDirectory(dir=self.root) as tmp:
            root = Path(tmp) / "build"
            firmware = Path(tmp) / "limited.elf"
            args = (
                "rv32imc",
                "-c",
                program,
                "--engine",
                "rbpf",
                "--firmware",
                firmware,
            )
            firmware.write_bytes(firmware_elf(xpm1_record(len(payload))))
            run_build(*args, build_dir=root)
            self.assertTrue(container_path(root, program, "ebpf").is_file())
            firmware.write_bytes(firmware_elf(xpm1_record(len(payload) - 1)))
            rejected = run_build(*args, build_dir=root, check=False)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("ImageExceedsSlot", rejected.stdout + rejected.stderr)
            self.assertEqual(load_index(root / program)["mode"], [])
            self.assertFalse(container_path(root, program, "ebpf").exists())

    def test_compiler_inputs_rebuild_bpf_and_native_code(self):
        root = self.build_dir
        source = self.root / "include_change.c"
        source.write_text(
            "#include <action.h>\n"
            '__attribute__((section("xdp"))) int program(void *ctx) { return ACTION; }\n'
        )
        first = self.root / "first"
        second = self.root / "second"
        alias = self.root / "alias"
        for directory, value in ((first, 1), (second, 2)):
            directory.mkdir()
            header = directory / "action.h"
            header.write_text(f"#define ACTION {value}\n")
            os.utime(header, (1, 1))
        alias.mkdir()
        link = alias / "action.h"
        link.symlink_to(first / "action.h")
        env = {
            k: v for k, v in os.environ.items() if k not in ("CPATH", "C_INCLUDE_PATH")
        }
        args = ("--firmware", self.firmware, "--inputs", source)

        def code_bytes(directory):
            paths = (
                bpf_path(directory, source.stem),
                native_object_path(directory, source.stem),
            )
            return tuple(executable_sections(path.read_bytes()) for path in paths)

        for variable in ("CPATH", "C_INCLUDE_PATH"):
            with self.subTest(variable=variable):
                run_build(
                    *args, build_dir=root, env=dict(env, **{variable: str(first)})
                )
                before = code_bytes(root)
                changed = dict(env, **{variable: str(second)})
                run_build(*args, build_dir=root, env=changed)
                fresh = self.root / ("fresh-" + variable)
                run_build(*args, build_dir=fresh, env=changed)
                self.assertNotEqual(code_bytes(root), before)
                self.assertEqual(code_bytes(root), code_bytes(fresh))

        linked = dict(env, CPATH=str(alias))
        run_build(*args, build_dir=root, env=linked)
        before = code_bytes(root)
        link.unlink()
        link.symlink_to(second / "action.h")
        run_build(*args, build_dir=root, env=linked)
        fresh = self.root / "fresh-symlink"
        run_build(*args, build_dir=fresh, env=linked)
        self.assertNotEqual(code_bytes(root), before)
        self.assertEqual(code_bytes(root), code_bytes(fresh))

    def test_rbpf_resolves_actual_map_relocations(self):
        root = self.build_dir
        args = ("rv32imc", "--engine", "rbpf", "--firmware", self.firmware)
        objdump = resolve_llvm_tool("llvm-objdump")
        firewall = (ROOT / "tests/xdp/firewall.c").read_text()
        two_maps = self.root / "two_maps.c"
        two_maps.write_text(
            firewall.replace(
                'SEC("xdp")',
                "struct {\n"
                "    __uint(type, BPF_MAP_TYPE_ARRAY);\n"
                "    __uint(max_entries, 1);\n"
                "    __type(key, __u32);\n"
                "    __type(value, __u32);\n"
                '} ahead SEC(".maps");\n\n'
                'SEC("xdp")',
            )
        )

        for program, flags, map_names in (
            ("copy", ("-c", "copy"), []),
            ("incr", ("--inputs", ROOT / "tests/unused/incr.c"), ["workload"]),
            ("firewall", ("-c", "firewall"), ["blacklist"]),
            ("two_maps", ("--inputs", two_maps), ["ahead", "blacklist"]),
        ):
            with self.subTest(program=program):
                run_build(*args, *flags, build_dir=root)
                obj = bpf_path(root, program)
                original = next(
                    code.data
                    for code in executable_sections(obj.read_bytes())
                    if code.name == "xdp"
                )
                meta, image = parse_container(
                    container_path(root, program, "ebpf").read_bytes()
                )
                self.assertEqual([m.name for m in meta.maps], map_names)
                expected = bytearray(original)
                if "blacklist" in map_names:
                    index = map_names.index("blacklist")
                    blacklist = meta.maps[index]
                    self.assertEqual(blacklist.map_type, 1)
                    self.assertEqual(blacklist.len, 256)
                    self.assertEqual(blacklist.key_layout, (32,))
                    self.assertEqual(blacklist.value_layout, (32,))
                    relocs = subprocess.check_output([objdump, "-r", obj], text=True)
                    xdp_relocations = relocs.split("RELOCATION RECORDS FOR [xdp]:\n")[
                        1
                    ].split("\n\n", 1)[0]
                    offsets = re.findall(
                        r"^([0-9a-f]+)\s+R_BPF_64_64\s+blacklist$",
                        xdp_relocations,
                        re.M,
                    )
                    self.assertTrue(offsets)
                    for offset in offsets:
                        at = int(offset, 16)
                        self.assertEqual(original[at], 0x18)
                        expected[at + 1] = (expected[at + 1] & 0xF) | 0x10
                        expected[at + 4 : at + 8] = index.to_bytes(4, "little")
                        expected[at + 12 : at + 16] = bytes(4)
                self.assertEqual(image, expected)

        source = self.root / "unbound_firewall.c"
        source.write_text(
            firewall.replace("__uint(max_entries, 256)", "__uint(max_entries, 257)")
        )
        failed = run_build(*args, "--inputs", source, build_dir=root, check=False)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn('map reference "blacklist"', failed.stdout)
        self.assertIn("has no container binding", failed.stdout)
        self.assertFalse(container_path(root, source.stem, "ebpf").exists())

    def test_rbpf_uses_the_configured_objdump_to_select_the_section(self):
        path = os.pathsep.join(
            part
            for part in os.environ["PATH"].split(os.pathsep)
            if not shutil.which("llvm-objdump", path=part)
        )
        tools = self.root / "tools"
        tools.mkdir()
        for command in ("ninja", "cargo", "rustc", "ld.lld"):
            if (resolved := shutil.which(command)) and not shutil.which(
                command, path=path
            ):
                (tools / command).symlink_to(resolved)
        path = str(tools) + os.pathsep + path
        self.assertIsNone(shutil.which("llvm-objdump", path=path))
        log = tools / "objdump.log"
        override = tools / "configured-objdump"
        override.write_text(
            "#!/bin/sh\n"
            + f'printf "%s\\n" "$1" >> {shlex.quote(str(log))}\n'
            + f'exec {shlex.quote(resolve_llvm_tool("llvm-objdump"))} "$@"\n'
        )
        override.chmod(0o755)
        env = dict(os.environ, PATH=path, LIBBPF_MCU_OBJDUMP=str(override))
        run_build(
            "rv32imc",
            "--engine",
            "rbpf",
            "--firmware",
            self.firmware,
            "-c",
            "noop",
            build_dir=self.build_dir,
            env=env,
        )
        self.assertIn("-h", log.read_text().splitlines())
        self.assertEqual(
            [row["name"] for row in load_index(self.build_dir / "noop")["mode"]],
            ["ebpf"],
        )

    def test_prevail_rejection_blocks_every_public_member(self):
        source = ROOT / "tests/unused/xdp_oob_packet.c"
        process = run_build(
            "bpf",
            "--inputs",
            source,
            build_dir=self.build_dir,
            check=False,
        )
        self.assertNotEqual(process.returncode, 0)
        self.assertFalse(
            any(p.is_file() for p in (self.build_dir / source.stem).rglob("*"))
        )
        diagnostic = self.build_dir / ".ninja" / source.stem / "diagnostics.json"
        recorded = json.loads(diagnostic.read_text())
        self.assertEqual(set(recorded), {"prevail"})
        self.assertIn(f"FAIL: xdp/{source.stem}", recorded["prevail"])
        run_build("bpf", "-c", "just_drop", build_dir=self.build_dir)
        self.assertEqual(json.loads(diagnostic.read_text()), recorded)
        self.assertTrue(
            any(
                source.stem in log.read_text()
                for log in (self.build_dir / ".ninja").glob("bpf-*.log")
            )
        )


if __name__ == "__main__":
    unittest.main()
