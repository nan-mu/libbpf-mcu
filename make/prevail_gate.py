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
    """Absolute path of the PREVAIL binary inside this repo.

    `PREVAIL` overrides that path when this checkout has not built the submodule.
    """
    override = os.environ.get("PREVAIL")
    if override:
        return Path(override)
    return ROOT / "prevail" / "bin" / "prevail"


def select_program(listing: str) -> ProgramRef:
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


def examine(obj: Path) -> ProgramRef:
    """List, select the one xdp or xdp1 program, and run the checker. No stamp I/O."""
    listed = _run_prevail([str(prevail_bin()), "-l", str(obj)])
    if listed.returncode != 0:
        raise SystemExit(1)
    program = select_program(listed.stdout)
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
    return program


def published_path(path: Path) -> str:
    path = Path(path)
    if not path.is_absolute():
        return path.as_posix()
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.name


def write_stamp(stamp: Path, obj: Path, program: ProgramRef) -> None:
    from layout import sha256_file, verifier_identity

    body = (
        f"section={program.section}\n"
        f"function={program.function}\n"
        f"bpf_o={published_path(obj)}\n"
        f"bpf_sha256={sha256_file(obj)}\n"
        f"verifier=prevail\n"
        f"verifier_id={verifier_identity()}\n"
        f"options=stack-size=512\n"
    )
    tmp = stamp.with_name(stamp.name + ".tmp")
    tmp.write_text(body)
    os.replace(tmp, stamp)


def stamp_aot(obj: Path, stamp: Path) -> None:
    stamp.unlink(missing_ok=True)
    write_stamp(stamp, obj, examine(obj))


def main() -> None:
    parser = argparse.ArgumentParser(prog="prevail_gate")
    parser.add_argument("--obj", type=Path, required=True)
    parser.add_argument("--stamp", type=Path, required=True)
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--program", default="")
    args = parser.parse_args()
    try:
        stamp_aot(args.obj, args.stamp)
    except SystemExit:
        _record_gate(args, accepted=False)
        raise
    _record_gate(args, accepted=True)


def _record_gate(args: argparse.Namespace, accepted: bool) -> None:
    if args.build_dir is None or not args.program:
        return
    from layout import LayoutError, parse_stamp, record_verification, retract_mode, sha256_file

    try:
        if accepted:
            parsed = parse_stamp(args.stamp.read_text())
            record_verification(
                args.build_dir,
                args.program,
                {
                    "status": "accepted",
                    "input_sha256": parsed.get("bpf_sha256", ""),
                    "verifier": "prevail",
                    "verifier_id": parsed.get("verifier_id", ""),
                    "options": parsed.get("options", ""),
                },
            )
            return
        digest = sha256_file(args.obj) if args.obj.is_file() else ""
        record_verification(
            args.build_dir,
            args.program,
            {
                "status": "rejected",
                "input_sha256": digest,
                "verifier": "prevail",
                "verifier_id": "",
                "options": "stack-size=512",
            },
        )
        retract_mode(args.build_dir, args.program, "rv32", "PREVAIL rejected the program")
        retract_mode(
            args.build_dir, args.program, "bpf-xpost", "PREVAIL rejected the program"
        )
    except LayoutError as exc:
        sys.stderr.write(f"{exc}\n")


if __name__ == "__main__":
    main()
