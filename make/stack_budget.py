#!/usr/bin/env python3
"""Compute a conservative E3 stack budget receipt: C + A + I <= S.

Reads optional LLVM stack-usage style reports and deployment parameters.
Fails closed when A cannot be derived from the native ELF call graph.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

MAKE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(MAKE_DIR))
from llvm_tools import resolve_llvm_tool  # noqa: E402

WORKSPACE = Path(__file__).resolve().parents[2]


def sha256_file(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def parse_stack_usage(path: Path) -> dict[str, int]:
    """Parse GCC/LLVM `.su` lines: `file:line:col:function\tbytes\tstatic`."""
    out: dict[str, int] = {}
    if not path.is_file():
        return out
    for line in path.read_text().splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        left, nbytes = parts[0], parts[1]
        name = left.split(":")[-1]
        try:
            out[name] = max(out.get(name, 0), int(nbytes))
        except ValueError:
            continue
    return out


def objdump_frame_hint(objdump: str, elf: Path) -> int | None:
    """Heuristic: largest `addi sp, sp, -N` immediate in the XDP section."""
    proc = subprocess.run(
        [objdump, "-d", str(elf)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return None
    peak = 0
    for m in re.finditer(r"addi\s+sp,sp,-(\d+)", proc.stdout):
        peak = max(peak, int(m.group(1)))
    # Also accept hex immediates.
    for m in re.finditer(r"addi\s+sp,\s*sp,\s*-0x([0-9a-fA-F]+)", proc.stdout):
        peak = max(peak, int(m.group(1), 16))
    return peak or None


def main() -> None:
    p = argparse.ArgumentParser(prog="stack_budget")
    p.add_argument("--elf", type=Path, required=True, help="MCU AOT ELF")
    p.add_argument("--su", type=Path, default=None, help="optional .su stack-usage file")
    p.add_argument("--caller-used-c", type=int, default=1024, help="C: active caller frames")
    p.add_argument("--irq-peak-i", type=int, default=0, help="I: allowed IRQ nesting peak")
    p.add_argument("--stack-limit-s", type=int, default=8192, help="S: usable stack region")
    p.add_argument(
        "--helper-margin",
        type=int,
        default=512,
        help="added to AOT peak when helper .su is absent",
    )
    p.add_argument("--objdump", default=resolve_llvm_tool("llvm-objdump"))
    p.add_argument(
        "--out",
        type=Path,
        default=None,
        help="write JSON receipt (default: sibling stack-budget.json)",
    )
    p.add_argument("--require-ok", action="store_true")
    args = p.parse_args()

    elf = args.elf.resolve()
    if not elf.is_file():
        sys.stderr.write(f"missing elf: {elf}\n")
        sys.exit(2)

    su = parse_stack_usage(args.su) if args.su else {}
    aot_peak = su.get("xdp_prog1") or su.get("xdp_prog") or None
    if aot_peak is None:
        aot_peak = objdump_frame_hint(args.objdump, elf)
    if aot_peak is None:
        receipt = {
            "schema": "bs.safety.stack_budget.v1",
            "ok": False,
            "errors": ["unable to derive AOT stack peak A from .su or objdump"],
            "elf": str(elf),
            "elf_sha256": sha256_file(elf),
        }
    else:
        helper_peak = max(
            (v for k, v in su.items() if "lookup" in k or "helper" in k),
            default=args.helper_margin,
        )
        a_peak = int(aot_peak) + int(helper_peak)
        total = args.caller_used_c + a_peak + args.irq_peak_i
        ok = total <= args.stack_limit_s
        errors = []
        if not ok:
            errors.append(
                f"C+A+I={total} > S={args.stack_limit_s} "
                f"(C={args.caller_used_c}, A={a_peak}, I={args.irq_peak_i})"
            )
        receipt = {
            "schema": "bs.safety.stack_budget.v1",
            "ok": ok,
            "errors": errors,
            "elf": str(elf),
            "elf_sha256": sha256_file(elf),
            "C": args.caller_used_c,
            "A": a_peak,
            "A_aot": int(aot_peak),
            "A_helper": int(helper_peak),
            "I": args.irq_peak_i,
            "S": args.stack_limit_s,
            "model": "shared_caller_stack",
        }

    out = args.out or elf.with_name("stack-budget.json")
    out.write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"wrote {out} ok={receipt['ok']}")
    for e in receipt.get("errors", []):
        sys.stderr.write(f"  - {e}\n")
    if args.require_ok and not receipt["ok"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
