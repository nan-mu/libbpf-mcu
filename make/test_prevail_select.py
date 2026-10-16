#!/usr/bin/env python3
"""prevail -l selection keeps exactly one xdp or xdp1 program."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from prevail_gate import _select_program  # noqa: E402


class SelectProgramTests(unittest.TestCase):
    def test_xdp1_prog1(self) -> None:
        program = _select_program("# section=xdp1 function=xdp_prog1")
        self.assertEqual(program.section, "xdp1")
        self.assertEqual(program.function, "xdp_prog1")

    def test_xdp_firewall(self) -> None:
        program = _select_program("# section=xdp function=firewall")
        self.assertEqual(program.section, "xdp")
        self.assertEqual(program.function, "firewall")

    def test_two_xdp_programs_exit_1(self) -> None:
        listing = "# section=xdp function=one\n# section=xdp function=two\n"
        with self.assertRaises(SystemExit) as caught:
            _select_program(listing)
        self.assertEqual(caught.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
