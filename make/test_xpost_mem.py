#!/usr/bin/env python3
"""XPM1 decode unit tests (no llvm required)."""
from __future__ import annotations

import struct
import unittest

from xpost_mem import MAGIC, MemMapV0, WIRE_SIZE, decode_xpm1


class Xpm1Tests(unittest.TestCase):
    def test_round_trip(self):
        wire = struct.pack(
            "<6I",
            MAGIC,
            0x4038_0000,
            0x4038_0200,
            0xE00,
            0x31_0000,
            0x1_0000,
        )
        self.assertEqual(len(wire), WIRE_SIZE)
        self.assertEqual(
            decode_xpm1(wire),
            MemMapV0(0x4038_0000, 0x4038_0200, 0xE00, 0x31_0000, 0x1_0000),
        )

    def test_reject_bad_magic(self):
        wire = bytearray(
            struct.pack("<6I", MAGIC, 1, 2, 3, 4, 5)
        )
        wire[0:4] = b"XPL1"
        with self.assertRaisesRegex(ValueError, "bad magic"):
            decode_xpm1(bytes(wire))

    def test_reject_truncated(self):
        with self.assertRaisesRegex(ValueError, "truncated"):
            decode_xpm1(b"\0" * 8)

    def test_reject_zero_fields(self):
        with self.assertRaisesRegex(ValueError, "helper"):
            decode_xpm1(struct.pack("<6I", MAGIC, 0, 2, 3, 4, 5))
        with self.assertRaisesRegex(ValueError, "slot_addr"):
            decode_xpm1(struct.pack("<6I", MAGIC, 1, 0, 3, 4, 5))
        with self.assertRaisesRegex(ValueError, "slot_len"):
            decode_xpm1(struct.pack("<6I", MAGIC, 1, 2, 0, 4, 5))
        with self.assertRaisesRegex(ValueError, "table_len"):
            decode_xpm1(struct.pack("<6I", MAGIC, 1, 2, 3, 4, 0))


if __name__ == "__main__":
    unittest.main()
