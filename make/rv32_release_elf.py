"""Extract the zero-based AOT bytes and retained RV32 relocations from LLD."""

from __future__ import annotations

import struct
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from obj_report import ELF32, SECTION32, RISCV

AOT_TYPES = {18: "call-pcrel", 19: "call-pcrel", 26: "hi20", 27: "lo12-i", 28: "lo12-s"}
LOCAL_BRANCHES = {16: 4, 17: 4, 44: 2, 45: 2}
ALLOCATION_LIMIT = 1 << 24  # Producer/parser limit, independent of device capacity.


@dataclass(frozen=True)
class Section:
    name: str
    kind: int
    flags: int
    address: int
    offset: int
    size: int
    link: int
    info: int
    alignment: int
    entsize: int


class ReleaseElf:
    def __init__(self, path: Path, *, linked: bool):
        self.data = path.read_bytes()
        self.linked = linked
        if len(self.data) < ELF32.size:
            raise ValueError("truncated RV32 ELF")
        ident, kind, machine, version, entry, _, offset, flags, _, _, _, size, count, names = (
            ELF32.unpack_from(self.data)
        )
        if (
            ident[:7] != b"\x7fELF\x01\x01\x01" or kind != (2 if linked else 1)
            or machine != RISCV or version != 1 or entry != 0 or flags & ~1
            or size != SECTION32.size or not 0 < names < count
        ):
            raise ValueError("expected zero-entry RV32IMC ILP32 ELF")
        self.read(offset, count * size)
        rows = [SECTION32.unpack_from(self.data, offset + i * size) for i in range(count)]
        strings = self.read(*rows[names][4:6])
        self.sections = [Section(self.string(strings, row[0]), *row[1:]) for row in rows]

    def read(self, at: int, size: int) -> bytes:
        if at < 0 or size < 0 or at + size > len(self.data):
            raise ValueError("RV32 ELF data outside file")
        return self.data[at:at + size]

    @staticmethod
    def string(data: bytes, at: int) -> str:
        return data[at:data.index(0, at)].decode("ascii")

    def section(self, index: int) -> Section:
        if not 0 < index < len(self.sections):
            raise ValueError("invalid RV32 ELF section index")
        return self.sections[index]

    def relocations(self):
        for rel in self.sections:
            if rel.kind not in (4, 9):
                continue
            area = self.section(rel.info)
            if not area.flags & 2:
                continue  # Debug relocations never reach the payload.
            symtab = self.section(rel.link)
            if (rel.kind != 4 or rel.entsize != 12 or rel.size % 12
                    or symtab.kind != 2 or symtab.entsize != 16 or symtab.size % 16):
                raise ValueError("expected RV32 RELA entries and ELF32 symbols")
            strings = self.section(symtab.link)
            names = self.read(strings.offset, strings.size)
            table = self.read(symtab.offset, symtab.size)
            for at, info, addend in struct.iter_unpack("<IIi", self.read(rel.offset, rel.size)):
                sym = info >> 8
                if not 0 < sym < len(table) // 16:
                    raise ValueError("invalid relocation symbol index")
                name, value, _, _, _, index = struct.unpack_from("<IIIBBH", table, sym * 16)
                tag = info & 0xFF
                target = self.section(index) if 0 < index < 0xFF00 else None
                label = self.string(names, name)
                offset = at - area.address if self.linked else at
                if tag in LOCAL_BRANCHES:
                    if (target is None or not target.flags & 4 or not area.flags & 4
                            or not 0 <= offset <= area.size - LOCAL_BRANCHES[tag]):
                        raise ValueError("non-local RV32 branch relocation")
                    continue  # Both executable sections translate by the slot base.
                if tag not in AOT_TYPES or not area.flags & 4 or addend != 0:
                    raise ValueError(f"unsupported RV32 relocation {tag} to {label!r} (+{addend})")
                kind = AOT_TYPES[tag]
                width = 8 if kind == "call-pcrel" else 4
                if offset % 2 or not 0 <= offset <= area.size - width:
                    raise ValueError("RV32 relocation outside its code section")
                if kind == "call-pcrel":
                    if (label != "helper_dispatcher" or value != 0
                            or index != (0xFFF1 if self.linked else 0)):
                        raise ValueError("RV32 helper must be external or unresolved at zero")
                elif target is None or target.name not in (".maps", "maps"):
                    raise ValueError(f"unsupported absolute RV32 reference to {label!r}")
                yield area, {"offset": at, "kind": kind, "target": label, "addend": addend}

    def payload(self) -> tuple[bytes, list[dict], list[dict]]:
        alloc = sorted(
            (s for s in self.sections if s.flags & 2 and s.size),
            key=lambda s: s.address,
        )
        image = bytearray()
        regions = []
        for section in alloc:
            end = section.address + section.size
            if (section.kind not in (1, 8) or section.address < len(image)
                    or end > ALLOCATION_LIMIT):
                raise ValueError(f"unsupported allocatable section {section.name}")
            if section.name == ".maps":
                kind = "maps"
            elif section.flags & 4 and section.kind == 1:
                kind = "code"
            else:
                kind = "zero" if section.kind == 8 else "data"
            image.extend(bytes(section.address - len(image)))
            image.extend(bytes(section.size) if section.kind == 8
                         else self.read(section.offset, section.size))
            regions.append({"name": section.name, "kind": kind, "offset": section.address,
                            "size": section.size, "alignment": section.alignment})
        fixups = sorted((row for _, row in self.relocations()), key=lambda item: item["offset"])
        return bytes(image), regions, fixups


def verify_aot_records(path: Path, doc: dict) -> None:
    """Check the exact address-dependent sites against the AOT reference object."""
    elf = ReleaseElf(path, linked=False)
    offsets = {}
    for region in doc["regions"]:
        if region["kind"] != "code":
            continue
        name = region["name"]
        patterns = ("xdp", "xdp1", ".xdp", ".xdp.*") if name == ".xdp" else (
            (".text", ".text.*") if name == ".text" else (name,)
        )
        position = region["offset"]
        for pattern in patterns:
            for section in elf.sections:
                match = (section.name.startswith(pattern[:-1]) if pattern.endswith("*")
                         else section.name == pattern)
                if match and section.flags & 6 == 6 and section.size:
                    alignment = max(1, section.alignment)
                    if alignment & (alignment - 1) or alignment > region["alignment"]:
                        raise ValueError("invalid reference code alignment")
                    position = (position + alignment - 1) & -alignment
                    offsets[section] = position
                    position += section.size
        if position != region["offset"] + region["size"]:
            raise ValueError("AOT code extent differs from the no-relax reference object")
    def identity(record):
        return record["offset"], record["kind"], record["target"], record["addend"]

    expected = Counter()
    for section, record in elf.relocations():
        if section not in offsets:
            raise ValueError("AOT reference fixup outside the canonical code regions")
        expected[identity({**record, "offset": offsets[section] + record["offset"]})] += 1
    if expected != Counter(map(identity, doc["fixups"])):
        raise ValueError("AOT fixups disagree with the reference object's relocation inventory")
