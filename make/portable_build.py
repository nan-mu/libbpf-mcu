"""Produce versioned, firmware-independent deployment inputs after PREVAIL."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from build_state import record
from build_steps import compile_native_source, link_native, write_maps
from layout import bpf_path, native_object_path, portable_paths, state_path, write_if_changed
from native_image import SCHEMA, read_document, validate_image
from rv32_release_elf import ReleaseElf, verify_aot_records

AOT_LINK_OPTIONS = ("-Wl,--no-relax,--emit-relocs",)


def capture(generation, step, argv):
    generation.append({"step": step, "argv": [str(arg) for arg in argv]})
    return json.loads(subprocess.check_output(argv))


def build_portable(root: Path, mode: str, src: Path, cfg: dict, config: Path, state: Path) -> None:
    program = src.stem
    bpf = bpf_path(root, program)
    upstream = [state_path(root, program, "prevail")]
    inputs = [config, cfg["tool"]]
    outputs = []
    generation = []
    stage = state.with_name("payload.bin")
    linked = None
    obj = None
    if mode in ("llvm-aot", "jit"):
        definitions = state.with_name("maps.toml")
        write_maps(generation, bpf, definitions)
    if mode == "llvm-aot":
        obj = state.with_name(f"{program}_rv32.o")
        linked = state.with_name(f"{program}_rv32.debug.elf")
        headers = compile_native_source(root, src, cfg, obj, state, generation)
        link_native(generation, dict(cfg, link_options=AOT_LINK_OPTIONS), obj, linked)
        image, regions, fixups = ReleaseElf(linked, linked=True).payload()
        maps = capture(generation, "canonical map symbols",
                       [cfg["tool"], "portable-maps", definitions, linked, program])
        doc = dict(regions=regions, maps=maps, fixups=fixups)
        generation.append({"step": "extract", "call": "ReleaseElf.payload",
                           "parameters": {"linked_elf": str(linked)}})
        inputs.extend([src, cfg["clang"], cfg["linker"], *headers])
        outputs.extend([obj, linked, native_object_path(root, program)])
    elif mode == "jit":
        doc = capture(generation, "compile RV32IM with fixups",
                      [cfg["tool"], "portable-jit", bpf, definitions, program, stage])
        image = stage.read_bytes()
    else:
        aot_layout = portable_paths(root, program, "llvm-aot")[1]
        section = capture(generation, "rewrite and verify rBPF",
                          [cfg["tool"], "portable-ebpf", bpf, aot_layout, stage])
        image = stage.read_bytes()
        doc = dict(regions=[dict(name=section, kind="code", offset=0, size=len(image), alignment=8)],
                   maps=read_document(aot_layout)["maps"], fixups=[])
        upstream.append(state_path(root, program, "llvm-aot"))
        inputs.append(aot_layout)
    alignment = max(4, *(region["alignment"] for region in doc["regions"]))
    doc.update(schema=SCHEMA, program=program, mode=mode, base=0, entry_offset=0,
               alignment=alignment)
    sites = [fixup["offset"] for fixup in doc["fixups"]]
    validate_image(program, mode, image, doc, sites)
    image_path, layout_path = portable_paths(root, program, mode)
    if obj is not None:
        verify_aot_records(obj, doc)
        write_if_changed(native_object_path(root, program), obj.read_bytes())
    write_if_changed(image_path, image)
    write_if_changed(layout_path, (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode())
    record(state, inputs=inputs, outputs=[*outputs, image_path, layout_path],
           upstream=upstream, generation=generation, objdump=cfg["objdump"], portable=True)
