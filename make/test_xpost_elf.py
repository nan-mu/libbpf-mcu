#!/usr/bin/env python3
"""Version 0 wire vectors, malformed-input checks and compiler integration."""
from __future__ import annotations

import hashlib
import json
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from xpost_elf import (
    MAX_ENTRIES, ImageMetadataV0, MapDescriptorV0, build_container, parse_container,
    SECTION_NAMES,
)


class CompactElfTests(unittest.TestCase):
    def setUp(self):
        self.image = b'\x01\x00\x82\x80\xff'
        self.map = MapDescriptorV0('stats', 2, 16, 0x40380100, None, (32, 32))
        self.meta = ImageMetadataV0(0x40380000, 0x40381000, 1, 'example', (self.map,))
        self.data = build_container(self.image, self.meta)

    def test_independent_wire_vector(self):
        # 8 prefix + 8 name + (8 name + 16 fixed + 2 layout + 2 padding).
        meta = bytes.fromhex(
            '00 01 01 00 00 10 38 40'
            '65 78 61 6d 70 6c 65 00'
            '73 74 61 74 73 00 00 00'
            '02 10 00 00 00 01 38 40 00 00 00 00 02 00 00 00'
            '20 20 00 00')
        self.assertEqual(len(meta), 44)
        self.assertEqual(self.data[212:256], meta)
        self.assertEqual(self.data[256:261], self.image)
        self.assertEqual(self.data[261:297], SECTION_NAMES)
        self.assertEqual(self.data[297:300], bytes(3))
        self.assertEqual(struct.unpack_from('<I', self.data, 32)[0], 52)
        headers = [struct.unpack_from('<10I', self.data, 52 + 40*i) for i in range(4)]
        self.assertEqual(headers, [
            (0,)*10,
            (1, 0x80000001, 0, 0, 212, 44, 2, 0, 4, 0),
            (13, 0x80000002, 6, 0x40380000, 256, 5, 0, 0, 4, 0),
            (26, 3, 0, 0, 261, 36, 0, 0, 1, 0),
        ])
        self.assertEqual(len(self.data), 332)
        self.assertEqual(self.data[-32:], hashlib.sha256(self.image).digest())
        self.assertEqual(parse_container(self.data), (self.meta, self.image))

    def test_all_image_alignment_residues_and_empty_maps(self):
        for n in range(1, 9):
            meta = replace(self.meta, maps=())
            raw = bytes(range(n))
            data = build_container(raw, meta)
            self.assertEqual(parse_container(data), (meta, raw))
            self.assertEqual(struct.unpack_from('<I', data, 32)[0], 52)

    def test_bitfields_and_padding_round_trip(self):
        item = replace(self.map, map_type=1, key_layout=(3, 5, 24), value_layout=(8, 24, 32))
        meta = replace(self.meta, maps=(item,))
        self.assertEqual(parse_container(build_container(self.image, meta))[0], meta)

    def test_every_truncation_and_appended_bytes_rejected(self):
        for n in range(len(self.data)):
            with self.subTest(n=n), self.assertRaises(ValueError):
                parse_container(self.data[:n])
        with self.assertRaises(ValueError):
            parse_container(self.data + b'\0')

    def test_raw_image_and_digest_corruption(self):
        for offset in (256, len(self.data)-1):
            data = bytearray(self.data)
            data[offset] ^= 1
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                parse_container(bytes(data))

    def test_digest_intentionally_excludes_metadata(self):
        data = bytearray(self.data)
        struct.pack_into('<I', data, 216, 0x40382000)
        meta, image = parse_container(bytes(data))
        self.assertEqual(meta.helper_address, 0x40382000)
        self.assertEqual(image, self.image)
        self.assertEqual(data[-32:], self.data[-32:])

    def test_header_section_padding_and_version_mutations(self):
        offsets = [7, 16, 18, 20, 24, 28, 32, 36, 40, 42, 44, 46, 48, 50,
                   52, 92, 132, 172, 212, 213, 214, 234, 254, 261, 297]
        for offset in offsets:
            with self.subTest(offset=offset):
                data = bytearray(self.data)
                data[offset] ^= 1
                with self.assertRaises(ValueError):
                    parse_container(bytes(data))

    def test_overflowing_layout_length_and_section_range(self):
        for offset in (244, 248, 132 + 16, 132 + 20):
            data = bytearray(self.data)
            struct.pack_into('<I', data, offset, 0xffffffff)
            with self.assertRaises(ValueError):
                parse_container(bytes(data))

    def test_profile_rejections(self):
        bad_maps = [
            replace(self.map, name=''), replace(self.map, name='a'*32),
            replace(self.map, name='a\0b'), replace(self.map, name='汉'),
            replace(self.map, map_type=27), replace(self.map, map_type=0),
            replace(self.map, len=0), replace(self.map, len=MAX_ENTRIES + 1),
            replace(self.map, map_vma=0), replace(self.map, map_vma=5),
            replace(self.map, key_layout=(32,)), replace(self.map, value_layout=None),
            replace(self.map, value_layout=()), replace(self.map, value_layout=(0,)),
            replace(self.map, value_layout=(256,)), replace(self.map, value_layout=(3,)),
            replace(self.map, value_layout=(8,)*33),
            replace(self.map, value_layout=(128,)*17),
            replace(self.map, map_type=1, key_layout=None),
            replace(self.map, map_type=1, key_layout=(128,)*5),
        ]
        for item in bad_maps:
            with self.subTest(item=item), self.assertRaises(ValueError):
                build_container(self.image, replace(self.meta, maps=(item,)))
        for meta in [replace(self.meta, machine=2), replace(self.meta, slot_address=1),
                     replace(self.meta, helper_address=0),
                     replace(self.meta, maps=(self.map,)*9),
                     replace(self.meta, maps=(self.map, replace(self.map, map_vma=0x1000))),
                     replace(self.meta, maps=(self.map, replace(self.map, name='other')))]:
            with self.subTest(meta=meta), self.assertRaises(ValueError):
                build_container(self.image, meta)
        with self.assertRaises(ValueError):
            build_container(b'', self.meta)

    def test_255_bit_interval_boundary(self):
        meta = replace(self.meta, maps=(replace(self.map, value_layout=(255, 1)),))
        self.assertEqual(parse_container(build_container(self.image, meta))[0], meta)

class CompilerIntegrationTests(unittest.TestCase):
    def test_compiled_bitfield_map_to_native_container(self):
        llvm = Path('/opt/homebrew/opt/llvm/bin')
        def tool(name):
            return str(llvm/name) if (llvm/name).is_file() else shutil.which(name)
        clang, objcopy, objdump, readelf = [tool(n) for n in ('clang', 'llvm-objcopy', 'llvm-objdump', 'llvm-readelf')]
        if not all((clang, objcopy, objdump, readelf)):
            self.skipTest('LLVM clang/objcopy/objdump/readelf required')
        from build import ensure_tool
        from build_steps import write_maps
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            src = root/'sample.c'
            src.write_text('''
struct key { unsigned a:3; unsigned b:5; unsigned tail; };
struct { int (*type)[1]; int (*max_entries)[4]; struct key *key; unsigned *value; }
stats __attribute__((section(".maps"), used));
extern unsigned consume_map(unsigned long, unsigned long);
unsigned _start(void) {
    struct key k = {0};
    return consume_map((unsigned long)&stats, (unsigned long)&k);
}
_Static_assert(sizeof(struct key) == 8, "key size");
_Static_assert(_Alignof(struct key) <= 4, "key alignment");
''')
            def run(*args):
                proc = subprocess.run(args, capture_output=True, text=True)
                self.assertEqual(proc.returncode, 0, f"{args}\n{proc.stderr}")
                return proc.stdout
            bpf = root/'bpf.o'
            run(clang, '--target=bpf', '-O2', '-g', '-c', str(src), '-o', str(bpf))
            maps = root/'maps.toml'
            write_maps([], bpf, maps)
            obj = root/'native.o'
            run(clang, '--target=riscv32-unknown-none-elf', '-march=rv32imc', '-mabi=ilp32',
                '-O2', '-ffreestanding', '-c', str(src), '-o', str(obj))
            ld = root/'slot.ld'
            ld.write_text('''ENTRY(_start)
consume_map = 0x40381000;
SECTIONS { . = 0x40380000; .text : { *(.text*) } .maps : ALIGN(4) { *(.maps) } }
''')
            elf = root/'native.elf'
            run(clang, '--target=riscv32-unknown-none-elf', '-nostdlib', '-fuse-ld=lld',
                '-Wl,-T,'+str(ld), str(obj), '-o', str(elf))
            raw = root/'sample.bin'
            run(objcopy, '-O', 'binary', str(elf), str(raw))
            out = root/'sample.elf'
            pack = ensure_tool(root)
            address = json.loads(run(pack, "symbol", elf, "stats"))["addr"]
            args = [
                pack, 'pack', '--image', raw, '--linked-elf', elf,
                '--out', out, '--name', 'sample', '--slot-address', '0x40380000',
                '--helper-address', '0x40381000',
            ]
            exported = root/'rewritten.bin'
            size = len(raw.read_bytes())
            rejected = subprocess.run([*args, '--maps', maps, '--slot-length', str(size - 1),
                                       '--export-image', exported], capture_output=True, text=True)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertFalse(out.exists())
            self.assertFalse(exported.exists())
            args.extend(['--slot-length', str(size)])
            run(*args, '--maps', maps)
            report = root/'no-maps.toml'
            report.write_text('[source]\npath = "sample.c"\n[assembly]\nlisting = "example"\n')
            rejected = subprocess.run([*args, '--maps', report], capture_output=True, text=True)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn('expected a private [maps] input', rejected.stderr)
            metadata, image = parse_container(out.read_bytes())
            self.assertEqual(image, raw.read_bytes())
            self.assertEqual(metadata.maps[0].key_layout, (3, 5, 24, 32))
            self.assertEqual(metadata.maps[0].map_vma, address)
            output = run(readelf, '-h', '-S', str(out))
            for name in ('.xpost.meta', '.xpost.image', '.shstrtab'):
                self.assertIn(name, output)


if __name__ == '__main__':
    unittest.main()
