"""PREVAIL listing parse and the stamp that unlocks one MCU compile."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from typing import Literal

XdpSection = Literal["xdp", "xdp1"]

_LISTING_LINE = re.compile(r"^\s*#?\s*section=(\S+)\s+function=(\S+)\s*$")


@dataclass(frozen=True)
class ProgramRef:
    """The one program PREVAIL will check. Built only by _select_program."""

    section: XdpSection
    function: str


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
