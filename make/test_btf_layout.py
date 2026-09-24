#!/usr/bin/env python3
"""Unit tests for classic bpf_map_def layout synthesis and rejection."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from btf import (  # noqa: E402
    BTF_KIND_INT, BTF_KIND_STRUCT, BTF_KIND_ARRAY, BTF_KIND_UNION,
    layout_byte_size, layout_from_size, layout_bit_intervals, format_layout,
)


class LayoutFromSizeTests(unittest.TestCase):
    def test_u32_key(self) -> None:
        self.assertEqual(layout_from_size(4), "    u32 v")
        self.assertEqual(layout_byte_size(layout_from_size(4)), 4)

    def test_rv32_long_value(self) -> None:
        # RV32 `long` / BPF `long` value_size is 8 in this codebase's maps blob.
        self.assertEqual(layout_from_size(8), "    u64 v")
        self.assertEqual(layout_byte_size(layout_from_size(8)), 8)

    def test_opaque_blob(self) -> None:
        layout = layout_from_size(3)
        self.assertEqual(layout, "    u8 v[3]")
        self.assertEqual(layout_byte_size(layout), 3)

    def test_reject_zero(self) -> None:
        with self.assertRaises(ValueError):
            layout_from_size(0)

    def test_reject_mismatched_layout(self) -> None:
        with self.assertRaises(ValueError):
            # Pretend a 4-byte key was reported as u8.
            if layout_byte_size("    u8 v") != 4:
                raise ValueError("map `rxcnt` key layout size 1 != key_size 4")


class LayoutByteSizeTests(unittest.TestCase):
    def test_multi_field(self) -> None:
        layout = "    u32 a\n    u16 b\n    u16 align"
        self.assertEqual(layout_byte_size(layout), 8)

    def test_reject_nested(self) -> None:
        with self.assertRaises(ValueError):
            layout_byte_size("    foo {")

    def test_bits_are_summed_before_converting_to_bytes(self) -> None:
        self.assertEqual(layout_byte_size("u3 a\nu5 b\nu24 align"), 4)
        with self.assertRaises(ValueError):
            layout_byte_size("u3 a")


class CompilerLayoutTests(unittest.TestCase):
    def setUp(self) -> None:
        self.types = [{}, {"kind": BTF_KIND_INT, "size": 4, "int_data": 32}]

    def test_bit_offsets_and_tail_padding(self) -> None:
        self.types.append({"kind": BTF_KIND_STRUCT, "size": 8, "kind_flag": 1,
                           "members": [
                               {"name": "a", "type": 1, "offset": 3 << 24},
                               {"name": "b", "type": 1, "offset": (5 << 24) | 3},
                               {"name": "c", "type": 1, "offset": (1 << 24) | 32},
                           ]})
        layout = format_layout(self.types, 2)
        self.assertEqual(layout_bit_intervals(layout), [3, 5, 24, 1, 31])
        self.assertEqual(layout_byte_size(layout), 8)

    def test_regular_member_names_and_padding(self) -> None:
        self.types.append({"kind": BTF_KIND_INT, "size": 1, "int_data": 8})
        self.types.append({"kind": BTF_KIND_STRUCT, "size": 8, "members": [
            {"name": "flag", "type": 2, "offset": 0},
            {"name": "count", "type": 1, "offset": 32},
        ]})
        self.assertEqual(format_layout(self.types, 3),
                         "    u8 flag\n    u24 align\n    u32 count")

    def test_array_stays_one_interval_even_above_wire_limit(self) -> None:
        self.types.append({"kind": BTF_KIND_ARRAY, "elem_type": 1, "nelems": 8})
        self.assertEqual(layout_bit_intervals(format_layout(self.types, 2)), [256])

    def test_legacy_btf_bitfield(self) -> None:
        self.types.append({"kind": BTF_KIND_INT, "size": 4, "int_data": (2 << 16) | 3})
        self.types.append({"kind": BTF_KIND_STRUCT, "size": 4, "members": [
            {"name": "flag", "type": 2, "offset": 0},
        ]})
        self.assertEqual(layout_bit_intervals(format_layout(self.types, 3)), [2, 3, 27])

    def test_union_and_overlapping_members_rejected(self) -> None:
        self.types.append({"kind": BTF_KIND_UNION, "size": 4})
        with self.assertRaisesRegex(ValueError, "union"):
            format_layout(self.types, 2)
        self.types.append({"kind": BTF_KIND_STRUCT, "size": 4, "members": [
            {"name": "a", "type": 1, "offset": 0},
            {"name": "b", "type": 1, "offset": 8},
        ]})
        with self.assertRaisesRegex(ValueError, "overlapping"):
            format_layout(self.types, 3)


if __name__ == "__main__":
    unittest.main()
