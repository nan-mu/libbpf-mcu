"""Select and verify the program in a BPF object."""

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
VERIFY_TIMEOUT = 300

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
        return Path(override).expanduser().resolve()
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


class PrevailError(ValueError):
    pass


def _run_prevail(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=VERIFY_TIMEOUT
        )
    except subprocess.TimeoutExpired as exc:
        detail = (exc.stdout or b"") + (exc.stderr or b"")
        raise PrevailError(
            f"PREVAIL timed out after {VERIFY_TIMEOUT}s: {detail.decode(errors='replace').strip()}"
        ) from exc
    except OSError as exc:
        raise PrevailError(f"cannot execute PREVAIL: {exc}") from exc


def examine(obj: Path, verifier: Path | None = None) -> ProgramRef:
    """List, select the one xdp or xdp1 program, and run the checker."""
    verifier = verifier or prevail_bin()
    listed = _run_prevail([str(verifier), "-l", str(obj)])
    if listed.returncode:
        raise PrevailError(
            f"PREVAIL could not list programs: {(listed.stdout + listed.stderr).strip()}"
        )
    try:
        program = select_program(listed.stdout)
    except SystemExit as exc:
        raise PrevailError(
            f"PREVAIL expected one XDP entry: {listed.stdout.strip()}"
        ) from exc
    label = program.section
    if program.function != program.section:
        label += "/" + program.function
    try:
        checked = _run_prevail(
            [
                str(verifier),
                "--stack-size",
                "512",
                "--section",
                program.section,
                "--function",
                program.function,
                str(obj),
            ]
        )
    except PrevailError as exc:
        raise PrevailError(f"{label}: {exc}") from exc
    detail = (checked.stdout + checked.stderr).strip()
    if checked.returncode:
        raise PrevailError(f"PREVAIL exited {checked.returncode} for {label}: {detail}")
    verdict = re.compile(
        rf"PASS: {re.escape(label)}(?: \(terminates within [0-9]+ loop iterations\))?"
    )
    if not any(verdict.fullmatch(line) for line in checked.stdout.splitlines()):
        raise PrevailError(f"PREVAIL did not report PASS for {label}: {detail}")
    return program


def main() -> None:
    parser = argparse.ArgumentParser(prog="prevail_gate")
    parser.add_argument("--obj", type=Path, required=True)
    args = parser.parse_args()
    try:
        examine(args.obj)
    except PrevailError as exc:
        sys.exit(str(exc))


if __name__ == "__main__":
    main()
