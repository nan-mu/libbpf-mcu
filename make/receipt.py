#!/usr/bin/env python3
"""Host-side safety receipt for a fixed BPF + MCU artifact pair.

Records digests, PREVAIL acceptance, ELF/ISA checks, and layout fields.
Does not embed into MCU firmware — this is an evidence binding for P0/P5.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

MAKE_DIR = Path(__file__).resolve().parent
ROOT = MAKE_DIR.parent

# Late import so `python receipt.py` works from make/.
sys.path.insert(0, str(MAKE_DIR))
from layout import LayoutError, bpf_path, load_index  # noqa: E402
from btf import analyze  # noqa: E402
from legacy_export import parse_maps_aot_addrs  # noqa: E402
from llvm_tools import resolve_llvm_tool  # noqa: E402
from prevail_gate import prevail_bin  # noqa: E402

DEFAULT_PREVAIL = prevail_bin()

DEFAULT_OBJDUMP = resolve_llvm_tool("llvm-objdump")
DEFAULT_READELF = resolve_llvm_tool("llvm-readelf")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def prevail_accept(
    prevail: Path, bpf_o: Path, section: str, function: str | None
) -> dict:
    cmd = [str(prevail), str(bpf_o), "--section", section]
    if function:
        cmd.extend(["--function", function])
    # Contract §7.1: default config — no termination/strict.
    proc = run(cmd)
    out = (proc.stdout or "") + (proc.stderr or "")
    ok = proc.returncode == 0 and "PASS" in out
    return {
        "command": cmd,
        "exit_code": proc.returncode,
        "stdout": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
        "accepted": ok,
        "commit": git_head(ROOT / "prevail"),
    }


def git_head(repo: Path) -> str | None:
    if not (repo / ".git").exists() and not (repo / ".git").is_file():
        # submodule pointer may be a file
        pass
    proc = run(["git", "-C", str(repo), "rev-parse", "HEAD"])
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def bpf_elf_checks(bpf_o: Path, readelf: str, expect_section: str) -> dict:
    hdr = run([readelf, "-h", str(bpf_o)])
    secs = run([readelf, "-S", str(bpf_o)])
    text = hdr.stdout + secs.stdout
    machine_bpf = "BPF" in text or "EM_BPF" in text or "Machine:" in text and "247" in text
    has_section = bool(re.search(rf"\b{re.escape(expect_section)}\b", secs.stdout))
    return {
        "machine_looks_bpf": machine_bpf or "Class:" in hdr.stdout,
        "has_section": has_section,
        "section": expect_section,
        "readelf_h": hdr.stdout.strip()[:2000],
    }


def mcu_elf_checks(elf: Path, objdump: str, readelf: str) -> dict:
    hdr = run([readelf, "-h", str(elf)])
    attrs = run([objdump, "-m", "riscv:rv32", "-d", str(elf)])
    text = hdr.stdout
    is_rv32 = "RISC-V" in text or "Machine:                 RISC-V" in text
    # Class ELF32 is expected for RV32.
    is_elf32 = "Class:                             ELF32" in text or "ELF32" in text
    return {
        "is_riscv": is_rv32,
        "is_elf32": is_elf32,
        "has_disasm": attrs.returncode == 0 and len(attrs.stdout) > 0,
        "readelf_h": hdr.stdout.strip()[:2000],
    }


def build_receipt(
    *,
    source: Path,
    stem: str,
    build_dir: Path,
    prevail: Path,
    section: str,
    function: str | None,
    objdump: str,
    readelf: str,
) -> dict:
    program = build_dir / stem
    index = load_index(program, stem)
    bpf_o = bpf_path(build_dir, stem)
    mcu_elf = program / "llvm-aot" / f"{stem}_rv32.debug.elf"
    mcu_bin = program / "llvm-aot" / f"{stem}_rv32.bin"
    if sha256_file(source) != index["source"]["sha256"]:
        raise LayoutError(f"{source} differs from the built source snapshot")
    addrs = parse_maps_aot_addrs(objdump, mcu_elf) if mcu_elf.is_file() else {}
    prev = prevail_accept(prevail, bpf_o, section, function)
    bpf_chk = bpf_elf_checks(bpf_o, readelf, section)
    maps = [
        {
            "name": item["name"],
            "map_type": item["map_type_name"],
            "key_size": str(item["key_size"]),
            "value_size": str(item["value_size"]),
            "aot_addr": hex(addrs[item["name"]]) if item["name"] in addrs else None,
        }
        for item in analyze(bpf_o)["maps"]["items"]
    ]

    mcu_chk = None
    if mcu_elf.is_file():
        mcu_chk = mcu_elf_checks(mcu_elf, objdump, readelf)

    errors: list[str] = []
    if not prev["accepted"]:
        errors.append("PREVAIL did not accept program")
    if not bpf_chk["has_section"]:
        errors.append(f"BPF object missing section {section}")
    if mcu_elf.is_file():
        if mcu_chk and not mcu_chk["is_riscv"]:
            errors.append("MCU ELF is not RISC-V")
        if mcu_chk and not mcu_chk["is_elf32"]:
            errors.append("MCU ELF is not ELF32 (expected RV32)")
    else:
        errors.append("MCU ELF missing (run esp32c3 build)")
    if not mcu_bin.is_file():
        errors.append("MCU bin missing (run esp32c3 build)")
    for item in maps:
        if item.get("map_type") == "BPF_MAP_TYPE_ARRAY":
            if item.get("key_size") not in ("4",):
                errors.append(f"map {item['name']}: expected key_size=4")
            if item.get("value_size") not in ("8",):
                errors.append(f"map {item['name']}: expected value_size=8 for long")
        if mcu_bin.is_file() and not item.get("aot_addr"):
            errors.append(f"map {item['name']}: missing aot_addr after MCU link")

    def show(path: Path) -> str:
        for base in (ROOT, build_dir):
            try:
                return path.resolve().relative_to(base.resolve()).as_posix()
            except ValueError:
                continue
        return path.name

    receipt = {
        "schema": "bs.safety.receipt.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "case": stem,
        "source": {
            "path": show(source),
            "sha256": sha256_file(source),
        },
        "bpf": {
            "path": show(bpf_o),
            "sha256": sha256_file(bpf_o),
            "section": section,
            "function": function,
            "checks": bpf_chk,
            "maps": maps,
        },
        "mcu": {
            "elf_path": show(mcu_elf) if mcu_elf.is_file() else None,
            "elf_sha256": sha256_file(mcu_elf) if mcu_elf.is_file() else None,
            "bin_path": show(mcu_bin) if mcu_bin.is_file() else None,
            "bin_sha256": sha256_file(mcu_bin) if mcu_bin.is_file() else None,
            "isa": "rv32imc",
            "abi": "ilp32",
            "checks": mcu_chk,
        },
        "prevail": prev,
        "ok": len(errors) == 0,
        "errors": errors,
    }
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(prog="receipt")
    parser.add_argument("--stem", default="xdp_paper")
    parser.add_argument(
        "--source",
        type=Path,
        default=None,
        help="C source (default: libbpf-mcu/tests/xdp/<stem>.c)",
    )
    parser.add_argument("--build-dir", type=Path, default=ROOT / "build")
    parser.add_argument("--section", default="xdp1")
    parser.add_argument("--function", default="xdp_prog1")
    parser.add_argument("--prevail", type=Path, default=DEFAULT_PREVAIL)
    parser.add_argument("--objdump", default=DEFAULT_OBJDUMP)
    parser.add_argument("--readelf", default=DEFAULT_READELF)
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Write receipt JSON (default: build/<stem>/safety-receipt.json)",
    )
    parser.add_argument(
        "--require-ok",
        action="store_true",
        help="Exit non-zero if receipt.ok is false",
    )
    args = parser.parse_args()

    source = args.source or (ROOT / "tests" / "xdp" / f"{args.stem}.c")
    out = args.out or (args.build_dir / args.stem / "llvm-aot" / "safety-receipt.json")

    try:
        receipt = build_receipt(
            source=source.resolve(),
            stem=args.stem,
            build_dir=args.build_dir.resolve(),
            prevail=args.prevail,
            section=args.section,
            function=args.function,
            objdump=args.objdump,
            readelf=args.readelf,
        )
    except Exception as exc:
        sys.stderr.write(f"receipt: {exc}\n")
        sys.exit(2)

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(receipt, indent=2, ensure_ascii=True) + "\n")
    sys.stdout.write(f"wrote {out} ok={receipt['ok']}\n")
    for err in receipt["errors"]:
        sys.stderr.write(f"  - {err}\n")
    if args.require_ok and not receipt["ok"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
