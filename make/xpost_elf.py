"""Canonical XPOST Compact ELF version 0 codec; see docs/xpost_compact_elf.proto."""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

ELF32_EHDR_SIZE = 52
ELF32_SHDR_SIZE = 40
SHT_SIZE = 4 * ELF32_SHDR_SIZE
META_OFFSET = ELF32_EHDR_SIZE + SHT_SIZE
IMAGE_DIGEST_SIZE = 32
MAX_META_SIZE = 1024
MAX_MAPS = 8
MAX_NAME = 31
MAX_LAYOUT = 32
MAX_ENTRIES = 256
XPOST_VERSION = 0
SHT_XPOST_META = 0x80000001
SHT_XPOST_IMAGE = 0x80000002
SECTION_NAMES = b"\0.xpost.meta\0.xpost.image\0.shstrtab\0"
IDENT = b"\x7fELF\x01\x01\x01" + bytes(9)
EHDR = struct.Struct("<16sHHIIIIIHHHHHH")
SHDR = struct.Struct("<10I")


@dataclass(frozen=True)
class MapDescriptorV0:
    name: str
    map_type: int
    len: int
    map_vma: int
    key_layout: tuple[int, ...] | None
    value_layout: tuple[int, ...] | None


@dataclass(frozen=True)
class ImageMetadataV0:
    slot_address: int
    helper_address: int
    machine: int
    name: str
    maps: tuple[MapDescriptorV0, ...] = ()


def align4(n: int) -> int:
    return (n + 3) & ~3


def _pad(data: bytes) -> bytes:
    return data + bytes(align4(len(data)) - len(data))


def _integer(value: int, low: int, high: int, label: str) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{label} must be in {low}..{high}: {value!r}")
    return value


def _address(value: int, label: str) -> int:
    _integer(value, 4, 0xFFFFFFFC, label)
    if value % 4:
        raise ValueError(f"{label} must be 4-byte aligned")
    return value


def _name(value: str) -> bytes:
    try:
        raw = value.encode("ascii")
    except (AttributeError, UnicodeEncodeError) as exc:
        raise ValueError("name must be ASCII") from exc
    if not 1 <= len(raw) <= MAX_NAME or b"\0" in raw:
        raise ValueError("name must contain 1..31 ASCII bytes without NUL")
    return _pad(raw + b"\0")


def _layout(value: tuple[int, ...] | None, max_bytes: int) -> bytes:
    if value is None:
        return b""
    if not 1 <= len(value) <= MAX_LAYOUT:
        raise ValueError("layout must have 1..32 descriptors; empty is not None")
    for bits in value:
        _integer(bits, 1, 255, "layout interval bits")
    if sum(value) % 8 or sum(value) > max_bytes * 8:
        raise ValueError(f"layout must span whole bytes and at most {max_bytes} bytes")
    return bytes(value)


def encode_map(item: MapDescriptorV0) -> bytes:
    name = _name(item.name)
    if item.map_type not in (1, 2) or type(item.map_type) is not int:
        raise ValueError("unsupported Linux map_type (supported: HASH=1, ARRAY=2)")
    _integer(item.len, 1, MAX_ENTRIES, "map capacity")
    _address(item.map_vma, "map_vma")
    key = _layout(item.key_layout, 64)
    value = _layout(item.value_layout, 256)
    if not value or (item.map_type == 1 and not key) or (item.map_type == 2 and key):
        raise ValueError("invalid HASH/ARRAY key/value layout combination")
    return _pad(name + bytes([item.map_type]) + item.len.to_bytes(3, "little")
                + struct.pack("<III", item.map_vma, len(key), len(value)) + key + value)


def encode_metadata(metadata: ImageMetadataV0) -> bytes:
    _address(metadata.slot_address, "slot_address")
    _address(metadata.helper_address, "helper_address")
    if metadata.machine != 1 or type(metadata.machine) is not int:
        raise ValueError("unsupported XPOST machine (expected ESP32_C3=1)")
    _integer(len(metadata.maps), 0, MAX_MAPS, "map count")
    if len({m.name for m in metadata.maps}) != len(metadata.maps):
        raise ValueError("duplicate map name")
    if len({m.map_vma for m in metadata.maps}) != len(metadata.maps):
        raise ValueError("duplicate map_vma")
    data = (struct.pack("<BBHI", XPOST_VERSION, metadata.machine, len(metadata.maps), metadata.helper_address)
            + _name(metadata.name) + b"".join(encode_map(m) for m in metadata.maps))
    if len(data) > MAX_META_SIZE:
        raise ValueError("metadata exceeds 1024 bytes")
    return data


def build_container(image: bytes, metadata: ImageMetadataV0) -> bytes:
    meta = encode_metadata(metadata)
    if not image:
        raise ValueError("raw image must be nonempty")
    image_off = META_OFFSET + len(meta)
    names_off = image_off + len(image)
    _integer(names_off, 0, 0xFFFFFFFF, "section name table offset")
    if metadata.slot_address + len(image) > 0x100000000:
        raise ValueError("image address extent overflows ELF32")
    header = EHDR.pack(IDENT, 1, 243, 1, 0, 0, ELF32_EHDR_SIZE, 1, 52, 0, 0, 40, 4, 3)
    sections = (
        (0,) * 10,
        (1, SHT_XPOST_META, 0, 0, META_OFFSET, len(meta), 2, 0, 4, 0),
        (13, SHT_XPOST_IMAGE, 6, metadata.slot_address, image_off, len(image), 0, 0, 4, 0),
        (26, 3, 0, 0, names_off, 36, 0, 0, 1, 0),
    )
    return (header + b"".join(SHDR.pack(*s) for s in sections)
            + _pad(meta + image + SECTION_NAMES) + hashlib.sha256(image).digest())


def _range(data: bytes, offset: int, size: int, label: str) -> bytes:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ValueError(f"{label} lies outside file/section")
    return data[offset:offset + size]


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    end = data.find(b"\0", offset, min(offset + MAX_NAME + 1, len(data)))
    if end < 0:
        raise ValueError("name missing NUL or exceeds 31 bytes")
    try:
        name = data[offset:end].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("name must be ASCII") from exc
    encoded = _name(name)
    if _range(data, offset, len(encoded), "name") != encoded:
        raise ValueError("nonzero name padding")
    return name, offset + len(encoded)


def parse_container(data: bytes) -> tuple[ImageMetadataV0, bytes]:
    """Strict bounds/profile/canonical validation and raw-image checksum check."""
    if len(data) < ELF32_EHDR_SIZE:
        raise ValueError("invalid container size")
    header = EHDR.unpack_from(data)
    if header != (IDENT, 1, 243, 1, 0, 0, ELF32_EHDR_SIZE, 1, 52, 0, 0, 40, 4, 3):
        raise ValueError("invalid ELF header")
    table = _range(data, ELF32_EHDR_SIZE, SHT_SIZE, "section table")
    sections = [SHDR.unpack_from(table, i * ELF32_SHDR_SIZE) for i in range(4)]
    meta_off, meta_size = sections[1][4], sections[1][5]
    if not 12 <= meta_size <= MAX_META_SIZE or meta_size % 4:
        raise ValueError("invalid metadata size")
    meta = _range(data, meta_off, meta_size, "metadata")
    version, machine, count, helper = struct.unpack_from("<BBHI", meta)
    if version != XPOST_VERSION:
        raise ValueError("unsupported xpost_version")
    _integer(count, 0, MAX_MAPS, "map count")
    name, cursor = _read_name(meta, 8)
    maps = []
    for _ in range(count):
        map_name, cursor = _read_name(meta, cursor)
        fixed = _range(meta, cursor, 16, "map header")
        kind, capacity = fixed[0], int.from_bytes(fixed[1:4], "little")
        vma, nk, nv = struct.unpack_from("<III", fixed, 4)
        _integer(nk, 0, MAX_LAYOUT, "key layout length")
        _integer(nv, 0, MAX_LAYOUT, "value layout length")
        cursor += 16
        key = tuple(_range(meta, cursor, nk, "key layout")) or None
        value = tuple(_range(meta, cursor + nk, nv, "value layout")) or None
        end = cursor + nk + nv
        if any(_range(meta, end, align4(end) - end, "record padding")):
            raise ValueError("nonzero map padding")
        cursor = align4(end)
        maps.append(MapDescriptorV0(map_name, kind, capacity, vma, key, value))
    if cursor != len(meta):
        raise ValueError("metadata not consumed exactly")
    image = _range(data, sections[2][4], sections[2][5], "image")
    metadata = ImageMetadataV0(sections[2][3], helper, machine, name, tuple(maps))
    expected = build_container(image, metadata)
    if expected[:-IMAGE_DIGEST_SIZE] != data[:-IMAGE_DIGEST_SIZE]:
        raise ValueError("noncanonical section headers, offsets, padding or metadata")
    if expected[-IMAGE_DIGEST_SIZE:] != data[-IMAGE_DIGEST_SIZE:]:
        raise ValueError("raw image SHA-256 mismatch")
    return metadata, image
