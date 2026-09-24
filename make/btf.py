#!/usr/bin/env python3
"""BTF map / CO-RE extraction for BPF ELF objects.

Host-side helper used by `obj_report` / `cli` when target is `bpf`. Parses
`.BTF` and `.BTF.ext`, then formats `[maps.*]` + `[CORE]` TOML fragments.

CLI: `python3 btf.py --obj <bpf.o>` still dumps one-line JSON for debugging.
"""

from __future__ import annotations

import argparse
import json
import keyword
import re
import struct
import sys
from pathlib import Path
from typing import Any

# BTF kinds
BTF_KIND_INT = 1
BTF_KIND_PTR = 2
BTF_KIND_ARRAY = 3
BTF_KIND_STRUCT = 4
BTF_KIND_UNION = 5
BTF_KIND_ENUM = 6
BTF_KIND_FWD = 7
BTF_KIND_TYPEDEF = 8
BTF_KIND_VOLATILE = 9
BTF_KIND_CONST = 10
BTF_KIND_RESTRICT = 11
BTF_KIND_FUNC = 12
BTF_KIND_FUNC_PROTO = 13
BTF_KIND_VAR = 14
BTF_KIND_DATASEC = 15
BTF_KIND_FLOAT = 16
BTF_KIND_DECL_TAG = 17
BTF_KIND_TYPE_TAG = 18
BTF_KIND_ENUM64 = 19

KIND_NAME = {
    0: "UNKNOWN",
    BTF_KIND_INT: "INT",
    BTF_KIND_PTR: "PTR",
    BTF_KIND_ARRAY: "ARRAY",
    BTF_KIND_STRUCT: "STRUCT",
    BTF_KIND_UNION: "UNION",
    BTF_KIND_ENUM: "ENUM",
    BTF_KIND_FWD: "FWD",
    BTF_KIND_TYPEDEF: "TYPEDEF",
    BTF_KIND_VOLATILE: "VOLATILE",
    BTF_KIND_CONST: "CONST",
    BTF_KIND_RESTRICT: "RESTRICT",
    BTF_KIND_FUNC: "FUNC",
    BTF_KIND_FUNC_PROTO: "FUNC_PROTO",
    BTF_KIND_VAR: "VAR",
    BTF_KIND_DATASEC: "DATASEC",
    BTF_KIND_FLOAT: "FLOAT",
    BTF_KIND_DECL_TAG: "DECL_TAG",
    BTF_KIND_TYPE_TAG: "TYPE_TAG",
    BTF_KIND_ENUM64: "ENUM64",
}

MAP_TYPE_NAME = {
    0: "BPF_MAP_TYPE_UNSPEC",
    1: "BPF_MAP_TYPE_HASH",
    2: "BPF_MAP_TYPE_ARRAY",
    3: "BPF_MAP_TYPE_PROG_ARRAY",
    4: "BPF_MAP_TYPE_PERF_EVENT_ARRAY",
    5: "BPF_MAP_TYPE_PERCPU_HASH",
    6: "BPF_MAP_TYPE_PERCPU_ARRAY",
    7: "BPF_MAP_TYPE_STACK_TRACE",
    8: "BPF_MAP_TYPE_CGROUP_ARRAY",
    9: "BPF_MAP_TYPE_LRU_HASH",
    10: "BPF_MAP_TYPE_LRU_PERCPU_HASH",
    11: "BPF_MAP_TYPE_LPM_TRIE",
    12: "BPF_MAP_TYPE_ARRAY_OF_MAPS",
    13: "BPF_MAP_TYPE_HASH_OF_MAPS",
    14: "BPF_MAP_TYPE_DEVMAP",
    15: "BPF_MAP_TYPE_SOCKMAP",
    16: "BPF_MAP_TYPE_CPUMAP",
    17: "BPF_MAP_TYPE_XSKMAP",
    18: "BPF_MAP_TYPE_SOCKHASH",
    19: "BPF_MAP_TYPE_CGROUP_STORAGE",
    20: "BPF_MAP_TYPE_REUSEPORT_SOCKARRAY",
    21: "BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE",
    22: "BPF_MAP_TYPE_QUEUE",
    23: "BPF_MAP_TYPE_STACK",
    24: "BPF_MAP_TYPE_SK_STORAGE",
    25: "BPF_MAP_TYPE_DEVMAP_HASH",
    26: "BPF_MAP_TYPE_STRUCT_OPS",
    27: "BPF_MAP_TYPE_RINGBUF",
    28: "BPF_MAP_TYPE_INODE_STORAGE",
    29: "BPF_MAP_TYPE_TASK_STORAGE",
    30: "BPF_MAP_TYPE_BLOOM_FILTER",
    31: "BPF_MAP_TYPE_USER_RINGBUF",
    32: "BPF_MAP_TYPE_CGRP_STORAGE",
    33: "BPF_MAP_TYPE_ARENA",
}

# Coarse storage class for MCU budgeting (not kernel allocator truth).
STORAGE_KIND = {
    1: "hash",
    2: "array",
    3: "array",
    4: "array",
    5: "hash",
    6: "array",
    7: "array",
    8: "array",
    9: "hash",
    10: "hash",
    11: "hash",
    12: "array",
    13: "hash",
    14: "array",
    15: "array",
    16: "array",
    17: "array",
    18: "hash",
    19: "storage",
    20: "array",
    21: "storage",
    22: "queue",
    23: "queue",
    24: "storage",
    25: "hash",
    26: "other",
    27: "ringbuf",
    28: "storage",
    29: "storage",
    30: "other",
    31: "ringbuf",
    32: "storage",
    33: "other",
}

CORE_KIND_NAME = {
    0: "FIELD_BYTE_OFFSET",
    1: "FIELD_BYTE_SIZE",
    2: "FIELD_EXISTS",
    3: "FIELD_SIGNED",
    4: "FIELD_LSHIFT_U64",
    5: "FIELD_RSHIFT_U64",
    6: "TYPE_ID_LOCAL",
    7: "TYPE_ID_TARGET",
    8: "TYPE_EXISTS",
    9: "TYPE_SIZE",
    10: "ENUMVAL_EXISTS",
    11: "ENUMVAL_VALUE",
    12: "TYPE_MATCHES",
}


class Reader:
    def __init__(self, data: bytes, pos: int = 0):
        self.data = data
        self.pos = pos

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def empty(self) -> bool:
        return self.pos >= len(self.data)

    def read(self, fmt: str):
        size = struct.calcsize(fmt)
        if self.pos + size > len(self.data):
            raise ValueError(f"unexpected EOF at {self.pos} need {size}")
        vals = struct.unpack_from(fmt, self.data, self.pos)
        self.pos += size
        return vals[0] if len(vals) == 1 else vals

    def slice(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError(f"unexpected EOF at {self.pos} need {n}")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out


def elf_section(data: bytes, name: str) -> bytes | None:
    """Return section bytes for `name` from a little-endian ELF64 REL object."""
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    if data[4] != 2 or data[5] != 1:
        raise ValueError("only ELF64 little-endian is supported")

    (
        _e_type,
        _e_machine,
        _e_version,
        _e_entry,
        _e_phoff,
        e_shoff,
        _e_flags,
        _e_ehsize,
        _e_phentsize,
        _e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)

    if e_shentsize < 64 or e_shnum == 0:
        raise ValueError("invalid ELF section header table")

    def shdr(i: int) -> tuple[int, int, int]:
        off = e_shoff + i * e_shentsize
        sh_name, _sh_type, _sh_flags, _sh_addr, sh_offset, sh_size = struct.unpack_from(
            "<IIQQQQ", data, off
        )
        return sh_name, sh_offset, sh_size

    _str_name, str_off, str_size = shdr(e_shstrndx)
    shstr = data[str_off : str_off + str_size]

    def cstr(off: int) -> str:
        end = shstr.find(b"\0", off)
        if end < 0:
            end = len(shstr)
        return shstr[off:end].decode("utf-8", errors="replace")

    for i in range(e_shnum):
        sh_name, sh_offset, sh_size = shdr(i)
        if cstr(sh_name) == name:
            return data[sh_offset : sh_offset + sh_size]
    return None


def btf_str(strtab: bytes, off: int) -> str:
    if off < 0 or off >= len(strtab):
        return ""
    end = strtab.find(b"\0", off)
    if end < 0:
        end = len(strtab)
    return strtab[off:end].decode("utf-8", errors="replace")


def parse_btf(data: bytes) -> tuple[list[dict[str, Any]], bytes]:
    r = Reader(data)
    magic, version, flags, hdr_len = r.read("<HBBI")
    if magic != 0xEB9F:
        raise ValueError(f"invalid BTF magic 0x{magic:04x}")
    type_off, type_len, str_off, str_len = r.read("<IIII")

    base = hdr_len
    types_blob = data[base + type_off : base + type_off + type_len]
    strtab = data[base + str_off : base + str_off + str_len]

    types: list[dict[str, Any]] = [{"kind": 0, "name": "", "size": 0}]  # id 0 void
    tr = Reader(types_blob)
    while not tr.empty():
        name_off, info, size_or_type = tr.read("<III")
        vlen = info & 0xFFFF
        kind = (info >> 24) & 0x1F
        kind_flag = bool(info >> 31)
        name = btf_str(strtab, name_off)
        entry: dict[str, Any] = {
            "kind": kind,
            "kind_flag": kind_flag,
            "name": name,
            "size_or_type": size_or_type,
            "vlen": vlen,
        }

        if kind == BTF_KIND_INT:
            entry["int_data"] = tr.read("<I")
            entry["size"] = size_or_type
        elif kind == BTF_KIND_PTR:
            entry["type"] = size_or_type
        elif kind == BTF_KIND_ARRAY:
            elem, idx, nelems = tr.read("<III")
            entry["elem_type"] = elem
            entry["index_type"] = idx
            entry["nelems"] = nelems
        elif kind in (BTF_KIND_STRUCT, BTF_KIND_UNION):
            entry["size"] = size_or_type
            members = []
            for _ in range(vlen):
                m_name_off, m_type, m_offset = tr.read("<III")
                members.append(
                    {
                        "name": btf_str(strtab, m_name_off),
                        "type": m_type,
                        "offset": m_offset,
                    }
                )
            entry["members"] = members
        elif kind == BTF_KIND_ENUM:
            entry["size"] = size_or_type
            vals = []
            for _ in range(vlen):
                e_name_off, e_val = tr.read("<Ii")
                vals.append({"name": btf_str(strtab, e_name_off), "val": e_val})
            entry["values"] = vals
        elif kind == BTF_KIND_FWD:
            pass
        elif kind in (
            BTF_KIND_TYPEDEF,
            BTF_KIND_VOLATILE,
            BTF_KIND_CONST,
            BTF_KIND_RESTRICT,
            BTF_KIND_TYPE_TAG,
        ):
            entry["type"] = size_or_type
        elif kind == BTF_KIND_FUNC:
            entry["type"] = size_or_type
            entry["linkage"] = vlen
        elif kind == BTF_KIND_FUNC_PROTO:
            entry["type"] = size_or_type
            params = []
            for _ in range(vlen):
                p_name_off, p_type = tr.read("<II")
                params.append({"name": btf_str(strtab, p_name_off), "type": p_type})
            entry["params"] = params
        elif kind == BTF_KIND_VAR:
            entry["type"] = size_or_type
            entry["linkage"] = tr.read("<I")
        elif kind == BTF_KIND_DATASEC:
            entry["size"] = size_or_type
            vars_ = []
            for _ in range(vlen):
                v_type, v_off, v_size = tr.read("<III")
                vars_.append({"type": v_type, "offset": v_off, "size": v_size})
            entry["vars"] = vars_
        elif kind == BTF_KIND_FLOAT:
            entry["size"] = size_or_type
        elif kind == BTF_KIND_DECL_TAG:
            entry["type"] = size_or_type
            entry["component_idx"] = tr.read("<i")
        elif kind == BTF_KIND_ENUM64:
            entry["size"] = size_or_type
            vals = []
            for _ in range(vlen):
                e_name_off, lo, hi = tr.read("<III")
                vals.append(
                    {
                        "name": btf_str(strtab, e_name_off),
                        "val": (hi << 32) | lo,
                    }
                )
            entry["values"] = vals
        else:
            # Unknown kind: cannot skip trailer safely.
            break

        types.append(entry)

    return types, strtab


def skip_mods(types: list[dict[str, Any]], type_id: int, *, typedefs: bool = True) -> int:
    """Follow const/volatile/restrict/type_tag (and optionally typedef) chains."""
    seen = set()
    while type_id and type_id not in seen:
        seen.add(type_id)
        if type_id >= len(types):
            return type_id
        t = types[type_id]
        kind = t["kind"]
        if kind in (
            BTF_KIND_VOLATILE,
            BTF_KIND_CONST,
            BTF_KIND_RESTRICT,
            BTF_KIND_TYPE_TAG,
        ) or (typedefs and kind == BTF_KIND_TYPEDEF):
            type_id = t.get("type", 0)
            continue
        break
    return type_id


def type_size(types: list[dict[str, Any]], type_id: int) -> int:
    type_id = skip_mods(types, type_id)
    if type_id <= 0 or type_id >= len(types):
        return 0
    t = types[type_id]
    kind = t["kind"]
    if kind == BTF_KIND_PTR:
        return type_size(types, t.get("type", 0))
    if kind == BTF_KIND_ARRAY:
        return type_size(types, t["elem_type"]) * int(t.get("nelems", 0))
    if "size" in t:
        return int(t["size"])
    if kind == BTF_KIND_ENUM:
        return int(t.get("size", 4))
    return 0


def map_field_type(types: list[dict[str, Any]], member_type: int) -> int:
    """Pointee of a `__type(key/value, T)` member; keep typedef for naming."""
    type_id = skip_mods(types, member_type, typedefs=False)
    if type_id <= 0 or type_id >= len(types):
        return 0
    t = types[type_id]
    if t["kind"] == BTF_KIND_PTR:
        return skip_mods(types, t.get("type", 0), typedefs=False)
    return type_id


def uint_attr(types: list[dict[str, Any]], member_type: int) -> int | None:
    """Decode `__uint(name, val)` → PTR to ARRAY[val] of int."""
    tid = skip_mods(types, member_type)
    if tid <= 0 or tid >= len(types):
        return None
    t = types[tid]
    if t["kind"] != BTF_KIND_PTR:
        return None
    arr_id = skip_mods(types, t.get("type", 0))
    if arr_id <= 0 or arr_id >= len(types):
        return None
    arr = types[arr_id]
    if arr["kind"] != BTF_KIND_ARRAY:
        return None
    return int(arr.get("nelems", 0))


def primitive_name(types: list[dict[str, Any]], type_id: int) -> str:
    """Map a BTF type to u8/u16/i32/... for layout pseudocode."""
    tid = skip_mods(types, type_id)
    if tid <= 0 or tid >= len(types):
        return "u8"
    t = types[tid]
    kind = t["kind"]
    if kind == BTF_KIND_INT:
        bits = int(t.get("size", 1)) * 8
        encoding = (int(t.get("int_data", 0)) >> 24) & 0x0F
        signed = encoding == 1
        return f"{'i' if signed else 'u'}{bits}"
    if kind == BTF_KIND_ENUM or kind == BTF_KIND_ENUM64:
        bits = int(t.get("size", 4)) * 8
        return f"u{bits}"
    if kind == BTF_KIND_FLOAT:
        return f"f{int(t.get('size', 4)) * 8}"
    if kind == BTF_KIND_PTR:
        return "u64"
    if kind == BTF_KIND_ARRAY:
        return primitive_name(types, t.get("elem_type", 0))
    return "u8"


def layout_lines(types: list[dict[str, Any]], type_id: int, indent: int = 4) -> list[str]:
    """Flatten compiler bit offsets, retaining each field/gap as one interval.

    This is layout notation, not C source. For example `u3 flag` records a
    three-bit field and `u29 align` the following padding interval.
    """
    pad = " " * indent
    tid = skip_mods(types, type_id)
    if not 0 < tid < len(types):
        raise ValueError("invalid layout type")
    t = types[tid]
    kind = t["kind"]
    if kind == BTF_KIND_UNION:
        raise ValueError("overlapping union layout is unsupported")
    if kind == BTF_KIND_PTR:
        raise ValueError("pointer-bearing map layout is target-dependent and unsupported")
    if kind == BTF_KIND_STRUCT:
        lines = []
        cursor = 0
        total = int(t["size"]) * 8
        for member in t.get("members", []):
            raw = int(member["offset"])
            offset = raw & 0xFFFFFF if t.get("kind_flag") else raw
            width = raw >> 24 if t.get("kind_flag") else 0
            mid = skip_mods(types, member["type"])
            if not 0 < mid < len(types):
                raise ValueError("invalid member type")
            # Older BTF encodes bitfields in BTF_INT_BITS/OFFSET.
            mt = types[mid]
            if not t.get("kind_flag") and mt["kind"] == BTF_KIND_INT:
                int_data = int(mt.get("int_data", 0))
                bits = int_data & 0xFF
                offset += (int_data >> 16) & 0xFF
                if bits and bits != int(mt["size"]) * 8:
                    width = bits
            if offset < cursor:
                raise ValueError("overlapping map layout is unsupported")
            if offset > cursor:
                lines.append(f"{pad}u{offset - cursor} align")
            if width:
                if mt["kind"] not in (BTF_KIND_INT, BTF_KIND_ENUM, BTF_KIND_ENUM64):
                    raise ValueError("invalid bitfield base type")
                lines.append(f"{pad}u{width} {member['name'] or '_'}")
            else:
                nested = layout_lines(types, mid, indent)
                if mt["kind"] != BTF_KIND_STRUCT:
                    nested = [re.sub(r"\bv$", member["name"] or "_", line) for line in nested]
                lines.extend(nested)
                width = sum(layout_bit_intervals("\n".join(nested)))
            cursor = offset + width
            if cursor > total:
                raise ValueError("member exceeds structure size")
        if cursor < total:
            lines.append(f"{pad}u{total - cursor} align")
        return lines
    if kind == BTF_KIND_ARRAY:
        # Validate elements recursively (reject pointers/unions), but an array
        # field is a single interval, never split to evade the 255-bit limit.
        element = layout_lines(types, t["elem_type"], indent)
        bits = sum(layout_bit_intervals("\n".join(element))) * int(t["nelems"])
        if bits <= 0:
            raise ValueError("empty/flexible array layout is unsupported")
        return [f"{pad}u{bits} v"]
    if kind not in (BTF_KIND_INT, BTF_KIND_ENUM, BTF_KIND_ENUM64, BTF_KIND_FLOAT):
        raise ValueError("unsupported map layout type")
    return [f"{pad}{primitive_name(types, tid)} v"]


def format_layout(types: list[dict[str, Any]], type_id: int) -> str:
    return "\n".join(layout_lines(types, type_id))


def layout_from_size(size: int) -> str:
    """Synthesize a single-field layout when only byte size is known.

    Classic `struct bpf_map_def` carries `key_size`/`value_size` in the maps
    blob but no BTF key/value type ids. Prefer ABI-natural unsigned widths.
    """
    if size <= 0:
        raise ValueError(f"invalid map field size {size}")
    if size in (1, 2, 4, 8):
        return f"    u{size * 8} v"
    # Opaque blob: expose as a byte array of the declared width.
    return f"    u8 v[{size}]"


def layout_bit_intervals(layout: str) -> list[int]:
    """One interval per field/array/padding line, measured in bits."""
    if not isinstance(layout, str):
        raise ValueError("layout must be a string")
    intervals = []
    for line in layout.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.endswith("{") or line == "}":
            raise ValueError(f"nested layout notation is unsupported: {line}")
        match = re.fullmatch(r"[uif](\d+)\s+\w+(?:\[(\d+)\])?", line)
        if not match:
            raise ValueError(f"unsupported layout line `{line}`")
        bits = int(match.group(1)) * (int(match.group(2)) if match.group(2) else 1)
        if bits <= 0:
            raise ValueError("layout interval must be positive")
        intervals.append(bits)
    return intervals


def layout_byte_size(layout: str) -> int:
    """Sum final storage bits, including padding, before converting to bytes."""
    total = sum(layout_bit_intervals(layout))
    if total % 8:
        raise ValueError("layout total is not byte aligned")
    return total // 8


def estimate_bytes(
    map_type: int, max_entries: int, key_size: int, value_size: int
) -> int:
    kind = STORAGE_KIND.get(map_type, "other")
    if kind == "ringbuf":
        return max_entries
    if kind == "array":
        return max_entries * value_size
    if kind == "queue":
        return max_entries * value_size
    if kind == "storage":
        return value_size
    if kind == "hash":
        return max_entries * (key_size + value_size)
    return max_entries * (key_size + value_size)


def extract_maps(
    types: list[dict[str, Any]], maps_blob: bytes | None = None
) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for t in types[1:]:
        if t["kind"] != BTF_KIND_DATASEC or t.get("name") not in (".maps", "maps"):
            continue
        for var_info in t.get("vars", []):
            var_id = var_info["type"]
            if var_id <= 0 or var_id >= len(types):
                continue
            var = types[var_id]
            if var["kind"] != BTF_KIND_VAR:
                continue
            map_name = var.get("name") or ""
            struct_id = skip_mods(types, var.get("type", 0))
            if struct_id <= 0 or struct_id >= len(types):
                continue
            st = types[struct_id]
            if st["kind"] != BTF_KIND_STRUCT:
                continue

            map_type = None
            max_entries = 0
            key_size = 0
            value_size = 0
            key_type_id = 0
            value_type_id = 0

            for m in st.get("members", []):
                mname = m["name"]
                if mname == "type":
                    map_type = uint_attr(types, m["type"])
                elif mname == "max_entries":
                    max_entries = uint_attr(types, m["type"]) or 0
                elif mname == "key_size":
                    key_size = uint_attr(types, m["type"]) or 0
                elif mname == "value_size":
                    value_size = uint_attr(types, m["type"]) or 0
                elif mname == "key":
                    key_type_id = map_field_type(types, m["type"])
                    key_size = type_size(types, key_type_id)
                elif mname == "value":
                    value_type_id = map_field_type(types, m["type"])
                    value_size = type_size(types, value_type_id)

            # Classic `struct bpf_map_def` — field values live in the maps blob.
            if map_type is None and maps_blob is not None:
                off = int(var_info.get("offset", 0))
                if off + 16 <= len(maps_blob):
                    map_type, key_size, value_size, max_entries = struct.unpack_from(
                        "<IIII", maps_blob, off
                    )

            if map_type is None:
                continue

            # RINGBUF / USER_RINGBUF: max_entries is buffer size; no key/value types.
            kind = STORAGE_KIND.get(map_type, "other")
            if kind == "ringbuf":
                est = estimate_bytes(map_type, max_entries, 0, 0)
                items.append(
                    {
                        "name": map_name,
                        "map_type": map_type,
                        "map_type_name": MAP_TYPE_NAME.get(
                            map_type, f"BPF_MAP_TYPE_{map_type}"
                        ),
                        "max_entries": max_entries,
                        "key_size": 0,
                        "value_size": 0,
                        "estimated_bytes": est,
                        "key": "",
                        "value": "",
                    }
                )
                continue

            if key_size <= 0 or value_size <= 0:
                raise ValueError(
                    f"map `{map_name}` missing positive key_size/value_size "
                    f"(got key_size={key_size}, value_size={value_size})"
                )

            if key_type_id:
                key_layout = format_layout(types, key_type_id)
            else:
                key_layout = layout_from_size(key_size)
            if value_type_id:
                value_layout = format_layout(types, value_type_id)
            else:
                value_layout = layout_from_size(value_size)

            # Fail closed when BTF-derived layout disagrees with declared sizes.
            key_layout_size = layout_byte_size(key_layout)
            value_layout_size = layout_byte_size(value_layout)
            if key_layout_size != key_size:
                raise ValueError(
                    f"map `{map_name}` key layout size {key_layout_size} "
                    f"!= key_size {key_size}"
                )
            if value_layout_size != value_size:
                raise ValueError(
                    f"map `{map_name}` value layout size {value_layout_size} "
                    f"!= value_size {value_size}"
                )

            est = estimate_bytes(map_type, max_entries, key_size, value_size)
            item: dict[str, Any] = {
                "name": map_name,
                "map_type": map_type,
                "map_type_name": MAP_TYPE_NAME.get(map_type, f"BPF_MAP_TYPE_{map_type}"),
                "max_entries": max_entries,
                "key_size": key_size,
                "value_size": value_size,
                "estimated_bytes": est,
                "key": key_layout,
                "value": value_layout,
            }
            items.append(item)

    total = sum(int(i["estimated_bytes"]) for i in items)
    return {"total_estimated_bytes": total, "items": items}


def parse_core(data: bytes, types: list[dict[str, Any]], strtab: bytes) -> list[dict[str, Any]]:
    r = Reader(data)
    magic, version, _flags, hdr_len = r.read("<HBBI")
    if magic != 0xEB9F:
        raise ValueError(f"invalid BTF.ext magic 0x{magic:04x}")
    func_info_off, func_info_len, line_info_off, line_info_len = r.read("<IIII")
    core_relo_off = core_relo_len = 0
    if hdr_len >= 32:
        core_relo_off, core_relo_len = r.read("<II")

    if core_relo_len == 0:
        return []

    blob = data[hdr_len + core_relo_off : hdr_len + core_relo_off + core_relo_len]
    cr = Reader(blob)
    if cr.empty():
        return []

    rec_size = cr.read("<I")
    relos: list[dict[str, Any]] = []
    while not cr.empty():
        sec_name_off, num_info = cr.read("<II")
        section = btf_str(strtab, sec_name_off)
        for _ in range(num_info):
            start = cr.pos
            insn_off, type_id, access_str_off, kind = cr.read("<IIII")
            type_name = ""
            if 0 < type_id < len(types):
                type_name = types[type_id].get("name") or ""
            relos.append(
                {
                    "section": section,
                    "insn_off": insn_off,
                    "type_id": type_id,
                    "type_name": type_name,
                    "access_str": btf_str(strtab, access_str_off),
                    "kind": kind,
                    "kind_name": CORE_KIND_NAME.get(kind, f"KIND_{kind}"),
                }
            )
            consumed = cr.pos - start
            if rec_size > consumed:
                cr.slice(rec_size - consumed)
    return relos


def analyze(obj_path: Path) -> dict[str, Any]:
    data = obj_path.read_bytes()
    btf_data = elf_section(data, ".BTF")
    if btf_data is None:
        raise ValueError(f".BTF section not found in {obj_path} (compile with -g)")

    types, strtab = parse_btf(btf_data)
    maps_blob = elf_section(data, "maps") or elf_section(data, ".maps")
    maps = extract_maps(types, maps_blob)

    core: list[dict[str, Any]] = []
    ext = elf_section(data, ".BTF.ext")
    if ext is not None:
        core = parse_core(ext, types, strtab)

    return {"maps": maps, "core": core}


from obj_report import append_multiline, toml_string


def _maps_table_name(name: str) -> str:
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) and not keyword.iskeyword(name):
        return f"maps.{name}"
    return f"maps.{toml_string(name)}"


def format_core_csv(core: list[dict[str, Any]]) -> str:
    rows = ["insn_off,type_id,access_str,kind,type_name,section"]
    for relo in core:
        rows.append(
            "{insn_off:#06x},{type_id},{access_str},{kind},{type_name},{section}".format(
                insn_off=int(relo.get("insn_off", 0)),
                type_id=int(relo.get("type_id", 0)),
                access_str=str(relo.get("access_str", "")),
                kind=int(relo.get("kind", 0)),
                type_name=str(relo.get("type_name", "")),
                section=str(relo.get("section", "")),
            )
        )
    return "\n".join(rows)


def format_btf_toml(report: dict[str, Any]) -> list[str]:
    """Render maps + CORE for bpf.toml (after [xdp]/[text])."""
    maps = report.get("maps") or {}
    items = maps.get("items") or []
    core = report.get("core") or []
    lines: list[str] = []

    for item in items:
        lines.append(f"[{_maps_table_name(str(item.get('name', '')))}]")
        lines.append(f"map_type = {toml_string(str(item.get('map_type_name', '')))}")
        lines.append(f"max_entries = {int(item.get('max_entries', 0))}")
        lines.append(f"key_size = {int(item.get('key_size', 0))}")
        lines.append(f"value_size = {int(item.get('value_size', 0))}")
        lines.append(f"estimated_bytes = {int(item.get('estimated_bytes', 0))}")
        append_multiline(lines, "key", str(item.get("key", "")))
        append_multiline(lines, "value", str(item.get("value", "")))
        lines.append("")

    lines.append("[CORE]")
    append_multiline(lines, "records", format_core_csv(core))
    lines.append("")
    return lines


def main() -> None:
    parser = argparse.ArgumentParser(prog="btf")
    parser.add_argument("--obj", required=True, type=Path)
    args = parser.parse_args()

    try:
        report = analyze(args.obj.resolve())
    except Exception as exc:
        sys.stderr.write(f"btf: {exc}\n")
        sys.exit(1)

    # One-line JSON; stable key order for serde consumers.
    sys.stdout.write(json.dumps(report, ensure_ascii=True, separators=(",", ":")))
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
