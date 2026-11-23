"""Materialize legacy filenames from actual objects and Compact ELF payloads."""

from __future__ import annotations

import re
import subprocess
import tomllib
from os.path import relpath
from pathlib import Path

from btf import analyze, format_btf_toml
from build_state import read_state, verify_state
from layout import (
    LEGACY_MODES,
    ROOT,
    LayoutError,
    append_multiline,
    bpf_path,
    check_bpf,
    check_program,
    contained,
    container_path,
    load_index,
    q,
    sha256_file,
    state_path,
    write_if_changed,
)
from llvm_tools import resolve_llvm_tool
from obj_report import (
    RISCV,
    CodeSection,
    disassemble_payload,
    executable_sections,
    format_disasm,
)
from xpost_elf import parse_container


MAPS_SYM_LINE = re.compile(
    r"^([0-9a-fA-F]+)\s+\S+\s+\S+\s+\.?maps\s+[0-9a-fA-F]+\s+(\S+)\s*$"
)


def parse_maps_aot_addrs(objdump: str, obj: Path) -> dict[str, int]:
    text = subprocess.check_output([objdump, "-t", str(obj)], text=True)
    addresses = {}
    for line in text.splitlines():
        if match := MAPS_SYM_LINE.fullmatch(line):
            addr, name = match.groups()
            if int(addr, 16) and not name.startswith("$"):
                addresses[name] = int(addr, 16)
    return addresses


def merge_aot_addrs_into_toml(path: Path, addrs: dict[str, int]) -> int:
    """Add linked addresses to legacy map tables."""
    output = []
    count = 0
    for line in path.read_text().splitlines(keepends=True):
        output.append(line)
        if line.startswith("[maps."):
            name = next(iter(tomllib.loads(line)["maps"]))
            if name in addrs:
                output.append(f"aot_addr = {addrs[name]:#x}\n")
                count += 1
    write_if_changed(path, "".join(output).encode())
    return count


def _legacy_bpf(path, obj, source, objdump, *, linked=None, vmas=None):
    lines = [f"source = {q(source)}", f"size = {obj.stat().st_size}", ""]
    for code in executable_sections(obj.read_bytes()):
        lines.append(f"[{q(code.name.lstrip('.'))}]")
        lines.append(f"size = {len(code.data)}")
        append_multiline(lines, "disasm", format_disasm(objdump, obj, code, bpf=True))
        lines.append("")
    lines.extend(format_btf_toml(analyze(obj)))
    if vmas:
        text = "\n".join(lines)
        for name, address in vmas.items():
            # The BTF formatter quotes non-identifier map names.
            for key in (name, q(name)):
                start = f"[maps.{key}]\n"
                text = text.replace(start, start + f"map_vma = {address:#x}\n")
    else:
        text = "\n".join(lines)
    write_if_changed(path, text.encode())
    if linked is not None:
        merge_aot_addrs_into_toml(path, parse_maps_aot_addrs(objdump, linked))


def _jit_toml(obj, source, objdump, container, meta, image):
    # Both layouts use a 16-byte placeholder per map after the RV32IM words.
    extent = len(image) - 16 * len(meta.maps)
    if (
        extent <= 0
        or extent % 4
        or image[extent:] != bytes(16 * len(meta.maps))
        or sorted(item.map_vma for item in meta.maps)
        != list(range(meta.slot_address + extent, meta.slot_address + len(image), 16))
    ):
        raise LayoutError(
            "cannot recover JIT code extent and map VMAs; rebuild from source"
        )
    from xdp_section import program_section

    section = program_section(obj)
    bpf_code = next(
        code for code in executable_sections(obj.read_bytes()) if code.name == section
    )
    code = CodeSection(".text", meta.slot_address, image[:extent])
    listing = disassemble_payload(objdump, code, RISCV)
    lines = [
        "[jit]",
        f"source = {q(source)}",
        f"section = {q(section)}",
        'isa = "RV32IM"',
        'abi = "helper_dispatcher-ilp32"',
        f"ebpf_insns = {len(bpf_code.data) // 8}",
        f"rv_insns = {extent // 4}",
        f"code_len = {extent}",
        f"slot = {meta.slot_address}",
        f"helper = {meta.helper_address}",
        f"image_len = {len(image)}",
        f"container_len = {container.stat().st_size}",
    ]
    # Retain the legacy word column for callers reading this export.
    entries = []
    for row in listing.splitlines()[1:]:
        address, b0, b1, b2, b3, mnemonic = row.split(maxsplit=5)
        word = int.from_bytes(bytes.fromhex(" ".join((b0, b1, b2, b3))), "little")
        entries.append(f"{address}: {word:08x}  {mnemonic}")
    append_multiline(lines, "disassembly", "\n".join(entries) + "\n")
    for i, item in enumerate(meta.maps):
        lines.extend(
            [
                "",
                "[[jit.map]]",
                f"name = {q(item.name)}",
                f"metadata_index = {i}",
                f"vmr = {item.map_vma}",
                'storage = "unknown"',
            ]
        )
    return "\n".join(lines) + "\n"


def _historical(root: Path, legacy_mode: str):
    # The v1 manifest supplies source identity and mode availability. Reports
    # and their digests are deliberately ignored, including for v1 exports.
    index = tomllib.loads(contained(root, "index.toml").read_text())
    if index.get("schema") != "libbpf-mcu.artifacts.v1":
        raise LayoutError(f"{root}: unknown historical build index")
    for row in index.get("program", []):
        name = check_program(row["name"])
        relative = f"{name}/manifest.toml"
        manifest_path = contained(root, relative)
        if row.get("manifest") != relative or row.get("manifest_sha256") != sha256_file(
            manifest_path
        ):
            raise LayoutError(
                f"{name}: historical manifest identity or SHA-256 mismatch"
            )
        manifest = tomllib.loads(manifest_path.read_text())
        if (
            manifest.get("schema") != "libbpf-mcu.program.v1"
            or manifest.get("program") != name
        ):
            raise LayoutError(f"{name}: invalid historical manifest")
        if not any(
            item.get("name") == legacy_mode for item in manifest.get("mode", [])
        ):
            continue
        yield name, manifest["source"]["path"]


def _v2(root: Path, mode: str):
    for path in sorted(root.glob("*/index.toml")):
        if path.parent.is_symlink():
            raise LayoutError(f"symlink is not a program directory: {path.parent}")
        name = path.parent.name
        index = load_index(path.parent, name)
        state = state_path(root, name, mode)
        if any(item["name"] == mode for item in index["mode"]) or (
            mode == "llvm-aot" and state.is_file() and not verify_state(state, {})
        ):
            bpf = read_state(state_path(root, name, "bpf"))
            yield name, relpath(bpf["source"], ROOT)


def _export_program(
    root: Path,
    out: Path,
    name: str,
    source: str,
    mode: str,
    legacy_mode: str,
    historical: bool,
):
    objdump = resolve_llvm_tool("llvm-objdump")
    folder = legacy_mode if historical else mode
    program = root / name
    obj = contained(program, f"bpf/{bpf_path(root, name).name}")
    check_bpf(obj)
    if historical:
        container_name = f"{name}_{legacy_mode}.elf"
    else:
        container_name = container_path(root, name, mode).name
        state = state_path(root, name, mode)
        if reason := verify_state(state, {}):
            raise LayoutError(f"{name}/{mode}: {reason}; rebuild from source")
    container = program / folder / container_name
    meta, image = None, None
    if container.is_file():
        # The v2 index may omit an AOT container left by a prior compact build.
        if historical or str(container) in read_state(state)["outputs"]:
            container = contained(program, f"{folder}/{container_name}")
            meta, image = parse_container(container.read_bytes())
    destination = out / name
    if destination.is_symlink():
        raise LayoutError(f"symlink is not a legacy output: {destination}")
    stamp = program / "bpf" / "prevail.ok"
    if mode == "llvm-aot":

        def native(suffix):
            try:
                return contained(program, f"{folder}/{name}_rv32{suffix}")
            except LayoutError as exc:
                raise LayoutError(
                    f"{name}/rv32: missing AOT {suffix}; rebuild from source"
                ) from exc

        aot_obj, linked, raw = native(".o"), native(".debug.elf"), native(".bin")
        if image is not None and raw.read_bytes() != image:
            raise LayoutError(f"{name}/rv32: linked image differs from container")
        exports = {"esp32c3.o": aot_obj, "esp32c3.elf": linked, "esp32c3.bin": raw}
        _legacy_bpf(destination / "bpf.toml", obj, source, objdump, linked=linked)
    else:
        if image is None:
            raise LayoutError(
                f"{name}/{legacy_mode}: missing deployment ELF; rebuild from source"
            )
        exports = {}
        vmas = (
            {item.name: item.map_vma for item in meta.maps} if mode == "jit" else None
        )
        _legacy_bpf(destination / "bpf.toml", obj, source, objdump, vmas=vmas)
        if mode == "jit":
            write_if_changed(destination / "jit.bin", image)
            write_if_changed(
                destination / "jit.toml",
                _jit_toml(obj, source, objdump, container, meta, image).encode(),
            )
            if stamp.is_file():
                exports["prevail.ok"] = contained(program, "bpf/prevail.ok")
        else:
            write_if_changed(destination / f"{name}.bin", image)
    if meta is not None:
        exports[f"{name}.elf"] = container
    else:
        (destination / f"{name}.elf").unlink(missing_ok=True)
    for filename, path in {"bpf.o": obj, **exports}.items():
        write_if_changed(destination / filename, path.read_bytes())


def export(root: Path, out: Path, legacy_mode: str) -> list[str]:
    if legacy_mode not in LEGACY_MODES:
        raise LayoutError(f"invalid legacy mode: {legacy_mode}")
    mode = LEGACY_MODES[legacy_mode]
    identity = out / "legacy-mode.txt"
    if identity.is_file():
        recorded = tomllib.loads(contained(out, "legacy-mode.txt").read_text())
        if recorded.get("mode") != legacy_mode:
            raise LayoutError(
                f"refusing to mix {legacy_mode} with {recorded.get('mode')}"
            )
    elif out.exists() and any(out.iterdir()):
        raise LayoutError("legacy output is not empty and has no mode identity")
    historical = (root / "index.toml").is_file()
    programs = list(_historical(root, legacy_mode) if historical else _v2(root, mode))
    if not programs:
        raise LayoutError(f"no {legacy_mode} programs to export")
    write_if_changed(
        identity,
        f'schema = "libbpf-mcu.legacy-export.v1"\nmode = {q(legacy_mode)}\n'.encode(),
    )
    for name, source in programs:
        _export_program(root, out, name, source, mode, legacy_mode, historical)
    return [name for name, _ in programs]
