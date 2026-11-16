#!/usr/bin/env python3
"""Ninja rebuild scope for the PREVAIL stamp and the RV32 commit."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from build import GraphPlan, JitLink, McuLink, edges_for_stem  # noqa: E402
from layout import report_path  # noqa: E402
from xpost_mem import MemMapV0  # noqa: E402

STUB = """
import sys
from pathlib import Path

log, step, out = sys.argv[1], sys.argv[2], sys.argv[3]
dest = Path(out)
dest.parent.mkdir(parents=True, exist_ok=True)
extra = sys.argv[4] if len(sys.argv) > 4 else ""
if step == "prevail":
    dest.write_text("stamp\\n")
    report = dest.with_name("report.toml")
    previous = report.read_text() if report.is_file() else ""
    report.write_text(previous + "verified\\n")
elif step == "commit_rv32":
    dest.write_text(Path(extra).read_bytes().hex())
else:
    dest.write_text(step + "\\n")
with Path(log).open("a") as handle:
    handle.write(step + "\\n")
"""


def _mem() -> MemMapV0:
    return MemMapV0(0x10, 0x20, 0x30, 0x40, 0x50)


def _build_line(edges: str, marker: str) -> str:
    for line in edges.splitlines():
        if line.startswith("build ") and marker in line:
            return line
    raise AssertionError(marker)


def _rules(stub: Path, log: Path) -> str:
    run = f"{sys.executable} {stub} {log}"
    return (
        f"rule bpf_cc\n  command = {run} bpf_cc $out\n"
        f"rule commit_bpf\n  command = {run} commit_bpf $out\n"
        f"rule prevail\n  command = {run} prevail $out\n  restat = 1\n"
        f"rule mcu_cc\n  command = {run} mcu_cc $out\n"
        f"rule link\n  command = {run} link $out\n"
        f"rule bin\n  command = {run} bin $out\n"
        f"rule report\n  command = {run} report $out\n"
        f"rule commit_rv32\n  command = {run} commit_rv32 $out $firmware\n"
        f"rule jit_publish\n  command = {run} jit_publish $out\n"
    )


def _ninja(path: Path) -> None:
    proc = subprocess.run(
        ["ninja", "-f", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"ninja exited {proc.returncode}\n{proc.stdout}\n{proc.stderr}"
        )


def _graph(root: Path, edges: str, build: Path) -> tuple[Path, Path]:
    kept = [
        line
        for line in edges.splitlines()
        if not line.startswith("  depfile =")
    ]
    log = root / "steps.log"
    stub = root / "stub.py"
    stub.write_text(STUB)
    ninja = root / "build.ninja"
    target = report_path(build, "firewall", "rv32")
    ninja.write_text(_rules(stub, log) + "\n" + "\n".join(kept) + f"\ndefault {target}\n")
    return ninja, log


class IncrementalTests(unittest.TestCase):
    def test_second_run_skips_prevail_and_downstream(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            edges, build = _aot_edges(root)
            prevail = _build_line(edges, ": prevail ")
            report = str(report_path(build, "firewall", "bpf"))
            _left, _sep, right = prevail.partition("||")
            self.assertIn(report, right)
            self.assertNotIn(report, _left)
            ninja, log = _graph(root, edges, build)
            _ninja(ninja)
            first = log.read_text()
            log.write_text("")
            _ninja(ninja)
            second = log.read_text()
            self.assertIn("prevail", first)
            self.assertNotIn("prevail", second)
            for step in ("bpf_cc", "mcu_cc", "link", "bin", "commit_rv32", "commit_bpf"):
                self.assertNotIn(step, second)

    def test_firmware_change_reruns_only_commit_rv32(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            edges, build = _aot_edges(root)
            firmware = root / "firmware.elf"
            commit = _build_line(edges, ": commit_rv32 ")
            implicit = commit.split("|", 1)[1]
            self.assertIn(str(firmware), implicit)
            for marker in (": bpf_cc ", ": mcu_cc ", ": link ", ": bin "):
                self.assertNotIn(str(firmware), _build_line(edges, marker))
            ninja, log = _graph(root, edges, build)
            _ninja(ninja)
            before = report_path(build, "firewall", "rv32").read_text()
            log.write_text("")
            firmware.write_bytes(b"fw-v2")
            _ninja(ninja)
            self.assertEqual(log.read_text().split(), ["commit_rv32"])
            self.assertEqual(
                report_path(build, "firewall", "rv32").read_text(),
                firmware.read_bytes().hex(),
            )
            self.assertNotEqual(before, firmware.read_bytes().hex())

    def test_jit_firmware_dep_is_not_duplicated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            edges = _jit_edges(root)
            line = _build_line(edges, ": jit_publish ")
            firmware = str(root / "firmware.elf")
            self.assertEqual(line.count(firmware), 1)
            self.assertNotIn("commit_rv32", edges)


def _aot_edges(root: Path) -> tuple[str, Path]:
    previous = os.environ.get("PREVAIL")
    os.environ["PREVAIL"] = str(root / "prevail-bin")
    (root / "prevail-bin").write_bytes(b"bin")
    try:
        src = root / "firewall.c"
        src.write_text("int firewall(void) { return 0; }\n")
        firmware = root / "firmware.elf"
        firmware.write_bytes(b"fw-v1")
        linker = root / "link.ld"
        linker.write_text("SECTIONS {}\n")
        tool = root / "tool"
        tool.write_bytes(b"tool")
        build = root / "build"
        plan = GraphPlan(
            sources=(src,),
            backend=McuLink(_mem(), linker, tool, firmware, False),
            release=False,
            objdump="llvm-objdump",
            build_dir=build,
        )
        return edges_for_stem(src, plan), build
    finally:
        if previous is None:
            os.environ.pop("PREVAIL", None)
        else:
            os.environ["PREVAIL"] = previous


def _jit_edges(root: Path) -> str:
    src = root / "firewall.c"
    src.write_text("int firewall(void) { return 0; }\n")
    firmware = root / "firmware.elf"
    firmware.write_bytes(b"fw-v1")
    tool = root / "tool"
    tool.write_bytes(b"tool")
    plan = GraphPlan(
        sources=(src,),
        backend=JitLink(firmware, tool, _mem()),
        release=False,
        objdump="llvm-objdump",
        build_dir=root / "build",
    )
    return edges_for_stem(src, plan)


if __name__ == "__main__":
    unittest.main()
