"""Build an independent reference from archived compiler objects and a layout ELF."""

from __future__ import annotations

import argparse
import os
import subprocess
import tempfile
from pathlib import Path

from build import (
    CLANG,
    DEFAULT_OBJCOPY,
    deployment_backend,
    ensure_tool,
    write_slot_linker,
)
from build_steps import check_firmware, link_native, pack_jit, pack_native
from layout import CONTAINER_ROLE, LayoutError, load_index, write_if_changed
from prevail_gate import examine
from xpost_elf import parse_container


def retarget(program_root: Path, index: dict, row: dict, cfg: dict, work: Path) -> bytes:
    bpf = program_root / index["bpf"]["path"]
    name = index["program"]
    if row["role"] == CONTAINER_ROLE:
        meta, _ = parse_container((program_root / row["elf"]["path"]).read_bytes())
        name = meta.name
    else:
        cfg = dict(cfg, link_options=("-Wl,--no-relax",))
    cfg = dict(cfg, image_name=name)
    steps = []
    if row["name"] == "jit":
        data, _ = pack_jit(steps, cfg, bpf, work / ".jit-stage")
    else:
        cfg["linker"] = work / "slot.ld"
        write_slot_linker(cfg["linker"], cfg)
        debug = work / "linked.elf"
        link_native(steps, cfg, program_root / row["object"]["path"], debug)
        data = pack_native(steps, cfg, bpf, debug, work / "image.bin")
    check_firmware(cfg)
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--program-dir", required=True, type=Path)
    parser.add_argument("--mode", required=True, choices=("llvm-aot", "jit"))
    parser.add_argument("--firmware", required=True, type=Path)
    parser.add_argument("--slot-symbol")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    program = args.program_dir.resolve()
    if args.output.resolve().is_relative_to(program):
        parser.error("--output must be outside the indexed program directory")
    try:
        index = load_index(program)
        row = next((row for row in index["mode"] if row["name"] == args.mode), None)
        if row is None:
            raise LayoutError(f"{index['program']}/{args.mode}: missing deployment")
        examine(program / index["bpf"]["path"])
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            tool = ensure_tool(work)
            cfg = deployment_backend(args.firmware, tool, args)
            cfg.update(clang=CLANG, objcopy=os.environ.get("LIBBPF_MCU_OBJCOPY", DEFAULT_OBJCOPY))
            write_if_changed(args.output, retarget(program, index, row, cfg, work))
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
