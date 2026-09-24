#!/usr/bin/env python3
"""Version 0 wire vectors, malformed-input checks and compiler integration."""
from __future__ import annotations

import hashlib
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
    ImageMetadataV0, MapDescriptorV0, build_container, parse_container,
    metadata_from_bpf_toml, SECTION_NAMES,
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

    def test_exact_container_limit(self):
        meta = replace(self.meta, maps=(), name='x')
        # 52 EHDR + 160 SHT + 12 metadata + 3804 image + 36 names + 32 digest.
        data = build_container(bytes(3804), meta)
        self.assertEqual(len(data), 4096)
        parse_container(data)
        with self.assertRaisesRegex(ValueError, '4096'):
            build_container(bytes(3805), meta)

    def test_profile_rejections(self):
        bad_maps = [
            replace(self.map, name=''), replace(self.map, name='a'*32),
            replace(self.map, name='a\0b'), replace(self.map, name='汉'),
            replace(self.map, map_type=27), replace(self.map, map_type=0),
            replace(self.map, len=0), replace(self.map, len=65),
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

    def test_toml_layouts_and_link_address(self):
        text = '''[maps.stats]
map_type = "BPF_MAP_TYPE_ARRAY"
key_size = 4
value_size = 8
max_entries = 16
aot_addr = 0x40380100
key = "u32 index"
value = "u32 a\\nu32 b"
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'bpf.toml'
            def load(s):
                path.write_text(s)
                return metadata_from_bpf_toml(path, name='example', slot_address=0x40380000,
                                              helper_address=0x40381000, machine=1)
            self.assertEqual(load(text), self.meta)
            for bad in [text.replace('value_size = 8', 'value_size = 4'),
                        text.replace('key = "u32 index"', ''),
                        text.replace('aot_addr = 0x40380100', ''),
                        text + 'map_vma = 0x40380104\n',
                        text.replace('u32 a\\nu32 b', 'u8 blob[32]').replace('value_size = 8', 'value_size = 32')]:
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    load(bad)


class CompilerIntegrationTests(unittest.TestCase):
    def test_compiled_bitfield_map_to_native_container(self):
        llvm = Path('/opt/homebrew/opt/llvm/bin')
        def tool(name):
            return str(llvm/name) if (llvm/name).is_file() else shutil.which(name)
        clang, objcopy, objdump, readelf = [tool(n) for n in ('clang', 'llvm-objcopy', 'llvm-objdump', 'llvm-readelf')]
        if not all((clang, objcopy, objdump, readelf)):
            self.skipTest('LLVM clang/objcopy/objdump/readelf required')
        from btf import analyze, format_btf_toml
        from obj_report import parse_maps_aot_addrs, merge_aot_addrs_into_toml
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            src = root/'sample.c'
            src.write_text('''
struct key { unsigned a:3; unsigned b:5; unsigned tail; };
struct { int (*type)[1]; int (*max_entries)[4]; struct key *key; unsigned *value; }
stats __attribute__((section(".maps"), used));
extern unsigned helper_dispatcher(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
unsigned _start(void) {
    struct key k = {0};
    return helper_dispatcher(1, (unsigned long)&stats, (unsigned long)&k, 0, 0, 0);
}
_Static_assert(sizeof(struct key) == 8, "key size");
_Static_assert(_Alignof(struct key) <= 4, "key alignment");
''')
            def run(*args):
                return subprocess.run(args, check=True, capture_output=True, text=True).stdout
            bpf = root/'bpf.o'
            run(clang, '--target=bpf', '-O2', '-g', '-c', str(src), '-o', str(bpf))
            report = analyze(bpf)
            toml = root/'bpf.toml'
            toml.write_text('\n'.join(format_btf_toml(report)))
            obj = root/'native.o'
            run(clang, '--target=riscv32-unknown-none-elf', '-march=rv32imc', '-mabi=ilp32',
                '-O2', '-ffreestanding', '-c', str(src), '-o', str(obj))
            ld = root/'slot.ld'
            ld.write_text('''ENTRY(_start)
helper_dispatcher = 0x40381000;
SECTIONS { . = 0x40380000; .text : { *(.text*) } .maps : ALIGN(4) { *(.maps) } }
''')
            elf = root/'native.elf'
            run(clang, '--target=riscv32-unknown-none-elf', '-nostdlib', '-fuse-ld=lld',
                '-Wl,-T,'+str(ld), str(obj), '-o', str(elf))
            raw = root/'sample.bin'
            run(objcopy, '-O', 'binary', str(elf), str(raw))
            addresses = parse_maps_aot_addrs(objdump, elf)
            self.assertIn('stats', addresses)
            merge_aot_addrs_into_toml(toml, addresses)
            out = root/'sample.elf'
            rust_bin = Path(__file__).resolve().parents[2] / 'xpost' / 'xpost-build'
            manifest = rust_bin / 'Cargo.toml'
            if not manifest.is_file():
                self.skipTest(f'xpost-build missing: {manifest}')
            import platform
            system = platform.system().lower()
            machine = platform.machine().lower()
            if system == 'darwin' and machine in ('arm64', 'aarch64'):
                triple = 'aarch64-apple-darwin'
            elif system == 'darwin':
                triple = 'x86_64-apple-darwin'
            elif machine in ('arm64', 'aarch64'):
                triple = 'aarch64-unknown-linux-gnu'
            else:
                triple = 'x86_64-unknown-linux-gnu'
            run('cargo', 'run', '--manifest-path', str(manifest),
                '--target', triple, '--release', '--bin', 'xpost-compact-elf', '--',
                '--image', str(raw), '--bpf-toml', str(toml), '--out', str(out),
                '--name', 'sample',
                '--slot-address', '0x40380000', '--helper-address', '0x40381000')
            metadata, image = parse_container(out.read_bytes())
            self.assertEqual(image, raw.read_bytes())
            self.assertEqual(metadata.maps[0].key_layout, (3, 5, 24, 32))
            self.assertEqual(metadata.maps[0].map_vma, addresses['stats'])
            output = run(readelf, '-h', '-S', str(out))
            for name in ('.xpost.meta', '.xpost.image', '.shstrtab'):
                self.assertIn(name, output)


if __name__ == '__main__':
    unittest.main()
