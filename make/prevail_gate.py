"""PREVAIL listing parse and the stamp that unlocks one MCU compile."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

MAKE_DIR = Path(__file__).resolve().parent
ROOT = MAKE_DIR.parent

XdpSection = Literal["xdp", "xdp1"]

_LISTING_LINE = re.compile(r"^\s*#?\s*section=(\S+)\s+function=(\S+)\s*$")


@dataclass(frozen=True)
class ProgramRef:
    """The one xdp or xdp1 program from `prevail -l`."""

    section: XdpSection
    function: str


def prevail_bin() -> Path:
    """Absolute path of the PREVAIL binary inside this repo."""
    return ROOT / "prevail" / "bin" / "prevail"


def _select_program(listing: str) -> ProgramRef:
    """Keep programs whose section is xdp or xdp1. Require exactly one."""
    found: list[ProgramRef] = []
    for line in listing.splitlines():
        match = _LISTING_LINE.match(line)
        if match is None:
            continue
        section = match.group(1)
        if section != "xdp" and section != "xdp1":
            continue
        found.append(ProgramRef(section=section, function=match.group(2)))
    if len(found) != 1:
        sys.stderr.write(listing)
        if listing and not listing.endswith("\n"):
            sys.stderr.write("\n")
        raise SystemExit(1)
    return found[0]


def _run_prevail(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except OSError as exc:
        sys.stderr.write(f"{exc}\n")
        raise SystemExit(1) from exc
    if proc.stderr:
        sys.stderr.write(proc.stderr)
        if not proc.stderr.endswith("\n"):
            sys.stderr.write("\n")
    return proc


def accept(obj: Path, stamp: Path) -> None:
    """Unlink the stamp, select the program, and publish the witness only on exit 0."""
    stamp.unlink(missing_ok=True)
    listed = _run_prevail([str(prevail_bin()), "-l", str(obj)])
    if listed.returncode != 0:
        raise SystemExit(1)
    program = _select_program(listed.stdout)
    checked = _run_prevail(
        [
            str(prevail_bin()),
            "--stack-size",
            "512",
            "--section",
            program.section,
            "--function",
            program.function,
            str(obj),
        ]
    )
    if checked.returncode != 0:
        raise SystemExit(1)
    body = (
        f"section={program.section}\n"
        f"function={program.function}\n"
        f"bpf_o={obj.resolve()}\n"
    )
    tmp = stamp.with_name(stamp.name + ".tmp")
    tmp.write_text(body)
    os.replace(tmp, stamp)


def main() -> None:
    parser = argparse.ArgumentParser(prog="prevail_gate")
    parser.add_argument("--obj", type=Path, required=True)
    parser.add_argument("--stamp", type=Path, required=True)
    args = parser.parse_args()
    accept(args.obj, args.stamp)


if __name__ == "__main__":
    main()
