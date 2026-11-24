"""Select caller-supplied linked ELFs for the formal release matrix."""

from __future__ import annotations

import os
from pathlib import Path

from layout import MODES, LayoutError

FIRMWARE_DIR_ENV = "LIBBPF_MCU_FIRMWARE_DIR"

# Required independently of the files and mode rows produced by a build.
CARRIERS = {
    "firewall": ("firewall",),
    "just_xdp": ("just_drop", "just_tx"),
    "exec_bench": ("noop", "prime", "log2", "copy", "fletcher32", "bsort", "strcmp"),
    "case_xdp": ("case_swap", "case_mark"),
}
PROGRAMS = tuple(sorted(program for names in CARRIERS.values() for program in names))


def firmware_name(carrier: str, mode: str) -> str:
    variant = "interp" if mode == "ebpf" else "native"
    return f"{carrier}-{variant}.elf"


def cold_capacity(carrier: str) -> int:
    return 8192 if carrier == "exec_bench" else 4096


def release_inputs(directory: Path | None) -> dict[str, tuple[Path, int]]:
    """Require all eight files before configuring deployments."""
    if directory is None and (configured := os.environ.get(FIRMWARE_DIR_ENV)):
        directory = Path(configured)
    if directory is not None:
        directory = directory.expanduser().resolve()

    files = {}
    missing = {}
    for carrier, programs in CARRIERS.items():
        for mode in MODES:
            name = firmware_name(carrier, mode)
            path = directory / name if directory is not None else Path(name)
            if directory is None or not path.is_file():
                missing.setdefault(path, []).extend(f"{program}/{mode}" for program in programs)
            else:
                files[name] = (path, cold_capacity(carrier))
    if missing:
        details = "\n".join(f"{', '.join(modes)}: required linked ELF {path}"
                            for path, modes in missing.items())
        hint = f"Use --firmware-dir DIR or set {FIRMWARE_DIR_ENV}.\n" if directory is None else ""
        raise LayoutError(f"{hint}{details}")
    return files
