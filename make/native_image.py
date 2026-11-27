"""Validate and bind portable ESP32-C3 images without producer inputs."""

from __future__ import annotations

import argparse
import json
import struct
import subprocess
import tempfile
from dataclasses import asdict
from pathlib import Path

from xpost_elf import ImageMetadataV0, MapDescriptorV0, encode_metadata, parse_container

SCHEMA = "libbpf-mcu.portable-image.v1"
FORMATS = {
    "llvm-aot": "rv32imc-le",
    "jit": "rv32im-le",
    "ebpf": "rbpf-map-index-le",
}
ROLES = {"llvm-aot": "native_image", "jit": "native_image", "ebpf": "interpreter_image"}
AOT_WIDTHS = {"hi20": 4, "lo12-i": 4, "lo12-s": 4, "call-pcrel": 8}
JIT_WIDTHS = {"call-abs": 8, "map-lddw": 16}
U32_MAX = (1 << 32) - 1


def integer(value, label: str, low: int = 0, high: int = U32_MAX) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{label} must be an integer in {low}..{high}")
    return value


def fields(value, names: str, label: str) -> None:
    if not isinstance(value, dict) or set(value) != set(names.split()):
        raise ValueError(f"invalid {label} fields")


def words_at(image: bytes, offset: int, size: int) -> tuple[int, ...]:
    return struct.unpack_from(f"<{size // 4}I", image, offset)


def lo12_i(word: int, low: int) -> int:
    return (word & 0xFFFFF) | ((low & 0xFFF) << 20)


def patched_words(kind: str, words: tuple[int, ...], value: int) -> tuple[int, ...]:
    high = (value + 0x800) & 0xFFFFF000
    if kind == "hi20" and words[0] & 0x7F == 0x37:
        return ((words[0] & 0xFFF) | high,)
    if kind == "lo12-i" and (words[0] & 0x7F == 0x03 or words[0] & 0x707F == 0x13):
        return (lo12_i(words[0], value),)
    if kind == "lo12-s" and words[0] & 0x7F == 0x23:
        low = ((value & 0xFE0) << 20) | ((value & 0x1F) << 7)
        return ((words[0] & 0x1FFF07F) | low,)
    if kind in ("call-pcrel", "call-abs"):
        upper, lower = (word & mask for word, mask in zip(words, (0xFFF, 0xFFFFF)))
        want = (0x097, 0x080E7) if kind == "call-pcrel" else (0x337, 0x300E7)
        if (upper, lower) == want:
            return upper | high, lo12_i(lower, value)
    if kind == "map-lddw":
        lo, lo_add, hi, hi_add = words
        lo_reg, hi_reg = (lo >> 7) & 31, (hi >> 7) & 31
        if (lo_reg and hi_reg and lo_reg != hi_reg and lo & 0x7F == 0x37
                and hi == (hi_reg << 7) | 0x37
                and lo_add & 0xFFFFF == (lo_reg << 15) | (lo_reg << 7) | 0x13
                and hi_add == (hi_reg << 15) | (hi_reg << 7) | 0x13):
            return (lo & 0xFFF) | high, lo12_i(lo_add, value), hi, hi_add
    raise ValueError(f"{kind}: unsupported instruction encoding")


def jit_sites(image: bytes, code_size: int) -> list[tuple[int, str]]:
    """Inventory reserved call and four-word map sequences in JIT code."""
    sites = []
    for offset in range(0, code_size, 4):
        if offset + 8 <= code_size and words_at(image, offset, 8) == (0x337, 0x300E7):
            sites.append((offset, "call-abs"))
        if offset + 16 <= code_size:
            try:
                patched_words("map-lddw", words_at(image, offset, 16), 0)
            except ValueError:
                continue
            sites.append((offset, "map-lddw"))
    return sites


def read_document(path: Path) -> dict:
    def unique_keys(items):
        result = dict(items)
        if len(result) != len(items):
            raise ValueError(f"{path}: duplicate JSON field")
        return result
    return json.loads(path.read_bytes(), object_pairs_hook=unique_keys)


def validate_image(program: str, mode: str, image: bytes, doc: dict, sites) -> None:
    fields(doc, "schema program mode base entry_offset alignment regions maps fixups", "image")
    if (doc["schema"], doc["program"], doc["mode"]) != (SCHEMA, program, mode):
        raise ValueError("portable image identity or version mismatch")
    integer(doc["base"], "base", 0, 0)
    integer(doc["entry_offset"], "entry offset", 0, 0)
    alignment = integer(doc["alignment"], "alignment", 4, 4096)
    if alignment & (alignment - 1) or not image:
        raise ValueError("invalid image alignment or empty payload")
    if not isinstance(doc["regions"], list) or not doc["regions"]:
        raise ValueError("missing image regions")
    end = 0
    names = set()
    for region in doc["regions"]:
        fields(region, "name kind offset size alignment", "region")
        start = integer(region["offset"], "region offset", end, len(image))
        size = integer(region["size"], "region size", 1, len(image) - start)
        align = integer(region["alignment"], "region alignment", 1, alignment)
        if (align & (align - 1) or start % align
                or region["kind"] not in ("code", "data", "maps", "zero")
                or not isinstance(region["name"], str) or not region["name"]
                or region["name"] in names
                or any(image[end:start])
                or (region["kind"] in ("maps", "zero") and any(image[start:start + size]))):
            raise ValueError("invalid image region or padding")
        names.add(region["name"])
        end = start + size
    if (end != len(image) or doc["regions"][0]["offset"] != 0
            or doc["regions"][0]["kind"] != "code"):
        raise ValueError("regions do not cover the image and entry")
    stride = {"llvm-aot": 2, "jit": 4, "ebpf": 8}[mode]
    code = [r for r in doc["regions"] if r["kind"] == "code"]
    if any(r["size"] % stride or r["offset"] % stride for r in code):
        raise ValueError("misaligned code region")
    word_sites = set()
    if mode == "llvm-aot":
        for region in code:
            offset = region["offset"]
            limit = offset + region["size"]
            while offset < limit:
                halfword = int.from_bytes(image[offset:offset + 2], "little")
                if halfword & 3 != 3:
                    offset += 2
                elif halfword & 0x1F == 0x1F or offset + 4 > limit:
                    raise ValueError("invalid RV32IMC instruction extent")
                else:
                    word_sites.add(offset)
                    offset += 4
    if not isinstance(doc["maps"], list):
        raise ValueError("invalid map descriptors")
    maps = {}
    ranges = []
    for item in doc["maps"]:
        fields(item, "name map_type len offset placeholder_bytes key_layout value_layout", "map")
        offset = integer(item["offset"], "map offset", 4)
        size = integer(item["placeholder_bytes"], "map placeholder size", 4)
        if offset + size > U32_MAX or offset % 4 or size % 4:
            raise ValueError("invalid map placeholder extent")
        if mode != "ebpf" and not any(
            r["kind"] == "maps" and r["offset"] <= offset
            and offset + size <= r["offset"] + r["size"] for r in doc["regions"]
        ):
            raise ValueError("map placeholder is outside the map region")
        if not isinstance(item["name"], str) or item["name"] in maps:
            raise ValueError("invalid or duplicate map name")
        if item["key_layout"] is not None and not isinstance(item["key_layout"], list):
            raise ValueError("invalid key layout")
        if not isinstance(item["value_layout"], list):
            raise ValueError("invalid value layout")
        maps[item["name"]] = offset
        ranges.append((offset, offset + size))
    ranges.sort()
    if list(maps) != sorted(maps) or any(a[1] > b[0] for a, b in zip(ranges, ranges[1:])):
        raise ValueError("map names must be sorted and map extents must be disjoint")
    encode_metadata(metadata(program, doc, 4, 4, canonical=True))

    widths = AOT_WIDTHS if mode == "llvm-aot" else JIT_WIDTHS if mode == "jit" else {}
    if not isinstance(doc["fixups"], list):
        raise ValueError("invalid fixup list")
    found = []
    end = 0
    for fixup in doc["fixups"]:
        fields(fixup, "offset kind target addend", "fixup")
        offset = integer(fixup["offset"], "fixup offset", end, len(image))
        kind, target = fixup["kind"], fixup["target"]
        if not isinstance(kind, str) or kind not in widths:
            raise ValueError(f"unsupported fixup kind: {kind!r}")
        size = widths[kind]
        end = offset + size
        if offset % stride or not any(
            r["offset"] <= offset and end <= r["offset"] + r["size"] for r in code
        ):
            raise ValueError("fixup outside code or misaligned")
        if mode == "llvm-aot" and any(at not in word_sites for at in range(offset, end, 4)):
            raise ValueError("RV32 fixup must start on a 32-bit instruction boundary")
        integer(fixup["addend"], "fixup addend", 0, 0)
        if kind in ("call-pcrel", "call-abs"):
            if target != "helper_dispatcher":
                raise ValueError("invalid helper fixup target")
            value = -offset if kind == "call-pcrel" else 0
        else:
            if not isinstance(target, str) or target not in maps:
                raise ValueError("invalid map fixup target")
            value = maps[target]
        words = words_at(image, offset, size)
        if patched_words(kind, words, value) != words:
            raise ValueError(f"{kind} at {offset:#x} differs from the zero-address encoding")
        found.append((offset, kind))
    if not isinstance(sites, list) or any(type(site) is not int for site in sites):
        raise ValueError("invalid indexed fixup sites")
    if [offset for offset, _ in found] != sites:
        raise ValueError("fixups disagree with indexed required sites")
    if mode == "jit":
        if len(code) != 1 or doc["regions"][0]["name"] != ".text":
            raise ValueError("invalid JIT code region")
        if found != jit_sites(image, code[0]["size"]):
            raise ValueError("JIT fixups disagree with the unresolved instruction sites")
    if mode == "ebpf":
        if len(code) != 1 or found or len(image) != code[0]["size"]:
            raise ValueError("invalid rBPF bytecode layout")
        for offset in range(0, len(image), 8):
            if image[offset] == 0x18 and image[offset + 1] >> 4 == 1:
                if (offset + 16 > len(image) or image[offset + 8:offset + 16] != bytes(8)
                        or int.from_bytes(image[offset + 4:offset + 8], "little") >= len(maps)):
                    raise ValueError("invalid rBPF map index")


def metadata(program: str, doc: dict, slot: int, helper: int, *,
             canonical: bool = False) -> ImageMetadataV0:
    maps = tuple(
        MapDescriptorV0(
            item["name"], item["map_type"], item["len"],
            item["offset"] if canonical else slot + item["offset"],
            None if item["key_layout"] is None else tuple(item["key_layout"]),
            tuple(item["value_layout"]),
        )
        for item in doc["maps"]
    )
    return ImageMetadataV0(slot, helper, 1, program, maps)


def bind_image(program: str, mode: str, image: bytes, doc: dict, sites: list[int],
               slot: int, capacity: int, helper: int) -> tuple[bytes, ImageMetadataV0]:
    """Return the bound bytes and Compact ELF metadata for one explicit layout."""
    validate_image(program, mode, image, doc, sites)
    integer(slot, "slot address", 4)
    integer(capacity, "slot capacity", 1)
    integer(helper, "helper address", 4)
    if slot % doc["alignment"] or helper % 4:
        raise ValueError("slot or helper alignment does not match the image")
    if (slot + capacity > U32_MAX + 1 or len(image) > capacity
            or any(m["offset"] + m["placeholder_bytes"] > capacity for m in doc["maps"])):
        raise ValueError("image or map extent exceeds the target slot capacity")
    if slot <= helper < slot + capacity:
        raise ValueError("helper overlaps the target slot")
    meta = metadata(program, doc, slot, helper)
    encode_metadata(meta)
    addresses = {m.name: m.map_vma for m in meta.maps}
    bound = bytearray(image)
    widths = AOT_WIDTHS | JIT_WIDTHS
    for fixup in doc["fixups"]:
        at, kind, target = (fixup[k] for k in ("offset", "kind", "target"))
        value = helper if kind.startswith("call-") else addresses[target]
        if kind == "call-pcrel":
            value -= slot + at
            integer(value, "PC-relative helper displacement", -(1 << 31), (1 << 31) - 1)
        words = patched_words(kind, words_at(image, at, widths[kind]), value)
        struct.pack_into(f"<{len(words)}I", bound, at, *words)
    return bytes(bound), meta


def main() -> None:
    from layout import LayoutError, load_portable_mode, write_if_changed

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--program-dir", type=Path, required=True)
    parser.add_argument("--mode", choices=FORMATS, required=True)
    parser.add_argument("--slot-address", type=lambda s: int(s, 0), required=True)
    parser.add_argument("--slot-length", type=lambda s: int(s, 0), required=True)
    parser.add_argument("--helper-address", type=lambda s: int(s, 0), required=True)
    parser.add_argument("--encoder", default="xpost-mcu-elf", help="prebuilt xpost-elf host encoder")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    directory = args.program_dir.resolve()
    if args.output.resolve().is_relative_to(directory):
        parser.error("--output must be outside the indexed program directory")
    try:
        program, row, image, doc = load_portable_mode(directory, args.mode)
        payload, meta = bind_image(
            program, args.mode, image, doc, row["fixup_sites"],
            args.slot_address, args.slot_length, args.helper_address,
        )
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "image.bin").write_bytes(payload)
            (tmp / "metadata.json").write_text(json.dumps(asdict(meta)))
            subprocess.run([
                args.encoder, "pack-resolved", "--image", tmp / "image.bin",
                "--metadata", tmp / "metadata.json", "--slot-length",
                str(args.slot_length), "--out", tmp / "container.elf",
            ], check=True)
            data = (tmp / "container.elf").read_bytes()
            # JSON arrays are restored as tuples by the Compact ELF decoder.
            if parse_container(data) != (meta, payload):
                raise LayoutError("encoder output differs from validated payload or layout")
            write_if_changed(args.output, data)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
