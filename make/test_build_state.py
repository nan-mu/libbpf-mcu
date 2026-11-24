"""BPF publication, failed rebuilds and Ninja path handling."""

from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

import cli

from layout import ROOT, bpf_path, load_index


class BuildTargetTests(unittest.TestCase):
    def test_explicit_bpf_still_discovers_sources_without_firmware(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = root / "tests" / "new-program.c"
            excluded = root / "tests" / "unused" / "negative.c"
            excluded.parent.mkdir(parents=True)
            selected.touch()
            excluded.touch()
            with patch("build.ROOT", root), patch.object(cli, "build") as build:
                with patch.object(sys, "argv", ["cli", "build", "bpf"]):
                    cli.main()
            output, sources, mode, args = build.call_args.args
            self.assertEqual((output, sources, mode, args.firmware),
                             (cli.DEFAULT_BUILD_DIR, [selected], "bpf", None))

    def test_rv32imc_dispatches_the_selected_engine(self):
        for target in ([], ["rv32imc"]):
            for options, mode in (([], "llvm-aot"), (["--engine", "rbpf"], "ebpf")):
                with self.subTest(target=target, mode=mode), patch.object(cli, "build") as build:
                    argv = ["cli", "build", *target, "--firmware", "slot.elf", "-c", "just_tx", *options]
                    with patch.object(sys, "argv", argv):
                        cli.main()
                    _, sources, selected_mode, args = build.call_args.args
                    self.assertEqual(selected_mode, mode)
                    self.assertEqual(sources, [ROOT / "tests/xdp/just_tx.c"])
                    self.assertEqual(args.firmware, Path("slot.elf"))

    def test_invalid_target_and_firmware_combinations(self):
        for arguments, message in (
            (["bpf", "--firmware", "slot.elf"], "require rv32imc or jit"),
            (["--engine", "rbpf"], "only available for rv32imc"),
            (["rv32imc"], "rv32imc requires --firmware"),
            (["esp32c3"], "invalid choice"),
        ):
            with self.subTest(arguments=arguments), redirect_stderr(io.StringIO()) as errors:
                with patch.object(sys, "argv", ["cli", "build", *arguments]), self.assertRaises(SystemExit):
                    cli.main()
                self.assertIn(message, errors.getvalue())


class PublicationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.build_dir = self.root / "build: #,$ space"
        directory = self.root / "sources: #,$ space"
        directory.mkdir()
        self.source = directory / "test$! program.c"
        self.header = directory / "action: #$.h"
        self.header.write_text("#define ACTION 1\n")
        self.source.write_text(
            '#include "action: #$.h"\n'
            '__attribute__((section("xdp"))) int program(void *ctx) { return ACTION; }\n'
        )
        self.program = self.build_dir / self.source.stem
        self.verifier = self.root / "verifier"
        self.set_verdict("PASS: xdp/program")

    def set_verdict(self, line):
        self.verifier.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = "-l" ]; then echo "section=xdp function=program"; exit 0; fi\n'
            f"echo '{line}'\n"
        )
        self.verifier.chmod(0o755)

    def build(self, source=None, *, target="bpf", options=(), success=True):
        command = [
            sys.executable, str(ROOT / "make/cli.py"), "build", target,
            "--build-dir", str(self.build_dir), "--inputs", str(source or self.source),
            *options,
        ]
        result = subprocess.run(
            command, env=dict(os.environ, PREVAIL=str(self.verifier)),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        self.assertEqual(result.returncode == 0, success, result.stdout)
        return result.stdout

    def assert_withdrawn(self):
        self.assertFalse(any(path.is_file() for path in self.program.rglob("*")))

    def test_preserve_unmanaged_file_with_source_name(self):
        self.program.mkdir(parents=True)
        existing = self.program / self.source.name
        existing.write_bytes(b"original contents")
        self.assertIn("not owned", self.build(success=False))
        self.assertEqual(existing.read_bytes(), b"original contents")

    def test_header_rebuild_and_verifier_with_wrong_pass_label(self):
        self.build()
        obj = bpf_path(self.build_dir, self.source.stem)
        first = obj.read_bytes()
        self.assertIn("no work to do", self.build())
        self.header.write_text("#define ACTION 2\n")
        self.build()
        self.assertNotEqual(first, obj.read_bytes())
        self.assertEqual(load_index(self.program)["mode"], [])
        self.assertTrue((self.program / "report.md").is_file())

        self.set_verdict("PASS: xdp/wrong_program")
        self.assertIn("did not report PASS for xdp/program", self.build(success=False))
        self.assert_withdrawn()

    def test_new_source_with_same_stem_withdraws_previous_build_on_preflight_failure(self):
        self.build()
        self.assertTrue((self.program / "index.toml").is_file())
        other = self.root / self.source.name
        other.write_text("int unrelated;\n")
        self.build(other, target="jit", options=["--firmware", str(self.root / "absent.elf")],
                   success=False)
        self.assert_withdrawn()


if __name__ == "__main__":
    unittest.main()
