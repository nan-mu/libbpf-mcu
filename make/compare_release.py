"""Audit both native modes from unpacked release bytes against direct links."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

from build import CLANG, DEFAULT_OBJCOPY, DEFAULT_OBJDUMP, deployment_backend
from layout import ROOT, load_index, load_portable_mode, sha256_file
from obj_report import RISCV, CodeSection, disassemble_payload
from release import PROGRAMS, archiver
from retarget import retarget
from xpost_elf import parse_container

NATIVE_MODES = ("llvm-aot", "jit")
SLOT_B = 0x40381000
HELPER_B = 0x40380040
CAPACITY_B = 0x4000


def write_json(file: Path, value) -> None:
    file.write_text(json.dumps(value, indent=2) + "\n")


def firmware_fixture(root: Path, slot: int, capacity: int, helper: int) -> Path:
    """Create the XPM1 input for the existing direct-link path."""
    root.mkdir()
    source = root / "layout.s"
    source.write_text(
        '.section .xpost.mem,"a"\n.ascii "XPM1"\n'
        f".long {helper:#x}, {slot:#x}, {capacity:#x}, 0x3fc80000, 1\n"
    )
    target = root / "layout.elf"
    subprocess.run([
        CLANG, "--target=riscv32-unknown-none-elf", "-nostdlib", "-fuse-ld=lld",
        "-Wl,-e,0", source, "-o", target,
    ], check=True)
    return target


def image_info(data: bytes) -> dict:
    meta, image = parse_container(data)
    return {**asdict(meta), "image_bytes": len(image),
            "payload_sha256": hashlib.sha256(image).hexdigest(),
            "container_sha256": hashlib.sha256(data).hexdigest()}


def diff_payload(actual: bytes, expected: bytes) -> dict:
    actual_meta, actual_image = parse_container(actual)
    expect_meta, expect_image = parse_container(expected)
    end = max(len(actual_image), len(expect_image))
    offsets = [i for i in range(end) if actual_image[i:i + 1] != expect_image[i:i + 1]]
    return {"equal": not offsets and actual_meta == expect_meta,
            "different_byte_offsets": offsets,
            "different_metadata": [k for k in asdict(actual_meta)
                                   if getattr(actual_meta, k) != getattr(expect_meta, k)]}


def save_disassembly(path: Path, data: bytes, mode: str, doc: dict | None = None) -> None:
    meta, image = parse_container(data)
    length = doc["regions"][0]["size"] if doc else len(image)
    listing = disassemble_payload(
        DEFAULT_OBJDUMP, CodeSection(".text", meta.slot_address, image[:length]),
        RISCV, compressed=mode == "llvm-aot",
    )
    path.write_text(listing)


def compare(args) -> bool:
    evidence = args.evidence_dir.resolve()
    evidence.mkdir()
    binder = evidence / "binder"
    binder.mkdir()
    for script in ("native_image.py", "layout.py", "xpost_elf.py"):
        shutil.copyfile(ROOT / "make" / script, binder / script)
    encoder = binder / "xpost-mcu-elf"
    shutil.copy2(args.encoder, encoder)
    # Binding uses the interpreter and encoder by absolute path. The binder
    # has no PATH entries, objects, source, or private build directories.
    bind_env = {**os.environ, "PATH": "", "PYTHONDONTWRITEBYTECODE": "1"}
    historical = json.loads((args.legacy_dir / "release.json").read_bytes())
    remote = json.loads(args.legacy_assets.read_bytes())
    if remote["tag"] != "v0.1.1":
        raise ValueError("expected the v0.1.1 asset manifest")
    history = {entry["program"]: entry for entry in historical["archives"]}
    assets = {item["name"]: item for item in remote["assets"]}
    shutil.copyfile(args.legacy_assets, evidence / "v0.1.1-assets.json")
    # Retain the exact historical reference inputs used for comparison.
    old_archives = evidence / "v0.1.1-archives"
    old_archives.mkdir()
    write_json(old_archives / "layout-ledger.json", {
        "commit": historical["commit"],
        "archive_ledger_sha256": sha256_file(args.legacy_dir / "release.json"),
        "archives": [
            {"program": row["program"], "sha256": row["sha256"], "modes": [
                {**mode, "firmware": {k: mode["firmware"][k] for k in ("file", "sha256")}}
                for mode in row["modes"]
            ]}
            for row in historical["archives"]
        ],
    })
    results = []
    r_bpf = []
    metadata_only = []
    passed = True
    for name in PROGRAMS:
        indexed = args.unpacked / name
        index = load_index(indexed, name)
        out = evidence / name
        out.mkdir()
        old_archive = args.legacy_dir / f"{name}.7z"
        record = assets[old_archive.name]
        digest = sha256_file(old_archive)
        if (old_archive.stat().st_size != record["size"] or "sha256:" + digest != record["digest"]
                or digest != history[name]["sha256"]):
            raise ValueError(f"{name}: historical archive differs from the published asset")
        shutil.copyfile(old_archive, old_archives / old_archive.name)
        old = out / "historical"
        subprocess.run([archiver(), "x", "-y", f"-o{old}", "--", old_archive],
                       check=True, stdout=subprocess.DEVNULL)
        load_index(old, name)
        reference = out / "reference-objects"
        shutil.copytree(indexed / "objects", reference)
        mode_results = {mode: {"program": name, "mode": mode} for mode in NATIVE_MODES}
        for spec in history[name]["modes"]:
            mode = spec["name"]
            row = next(row for row in index["mode"] if row["name"] == mode)
            previous = (old / spec["path"]).read_bytes()
            old_meta, old_payload = parse_container(previous)
            slot, capacity, helper = old_meta.slot_address, spec["slot_capacity"], old_meta.helper_address
            if spec["sha256"] != hashlib.sha256(previous).hexdigest():
                raise ValueError(f"{name}/{mode}: historical ledger container digest differs")
            _, _, canonical, doc = load_portable_mode(indexed, mode)
            mode_out = out / mode
            mode_out.mkdir()
            inputs = mode_out / "isolated"
            (inputs / "images").mkdir(parents=True)
            for member in ("index.toml", row["image"]["path"], row["layout"]["path"]):
                shutil.copyfile(indexed / member, inputs / member)
            parity = []
            targets = (("historical-layout", slot, capacity, helper),)
            if mode in NATIVE_MODES:
                targets += (("alternate-layout", SLOT_B, CAPACITY_B, HELPER_B),)
            for layout, address, length, dispatcher in targets:
                work = mode_out / layout
                if mode in NATIVE_MODES:
                    fw = firmware_fixture(work, address, length, dispatcher)
                    cfg = deployment_backend(fw, encoder, SimpleNamespace(slot_symbol=None))
                    cfg.update(clang=CLANG, objcopy=DEFAULT_OBJCOPY)
                    ref = retarget(indexed, index, row, cfg, work)
                    (work / "direct.elf").write_bytes(ref)
                else:
                    work.mkdir()
                bound = work / "bound.elf"
                subprocess.run([
                    sys.executable, binder / "native_image.py",
                    "--program-dir", inputs, "--mode", mode,
                    "--slot-address", hex(address), "--slot-length", hex(length),
                    "--helper-address", hex(dispatcher), "--encoder", encoder, "--output", bound,
                ], check=True, cwd=inputs, env=bind_env)
                bound_data = bound.read_bytes()
                meta, payload = parse_container(bound_data)
                if mode == "ebpf":
                    if old_payload != payload or payload != canonical:
                        passed = False
                    r_bpf.append({"program": name, "unchanged_instructions": old_payload == payload == canonical,
                                  "historical": image_info(previous), "bound": image_info(bound_data)})
                    continue
                comparison = diff_payload(bound_data, ref)
                parity.append({"layout": layout, "capacity": length,
                               **comparison, "bound": image_info(bound_data), "direct": image_info(ref)})
                if not comparison["equal"]:
                    passed = False
                    save_disassembly(work / "bound.asm", bound_data, mode, doc)
                    save_disassembly(work / "direct.asm", ref, mode, doc)
                if layout == "historical-layout":
                    historical_result = diff_payload(bound_data, previous)
                    mode_results[mode]["historical"] = {
                        **historical_result, "capacity": capacity,
                        "old": image_info(previous), "new": image_info(bound_data),
                    }
                    if not historical_result["equal"]:
                        save_disassembly(work / "old.asm", previous, mode)
                        save_disassembly(work / "new.asm", bound_data, mode, doc)

                if name == "just_tx" and layout == "alternate-layout":
                    # Keep the canonical code, and change only its container metadata.
                    write_json(work / "metadata.json", asdict(meta))
                    subprocess.run([
                        encoder, "pack-resolved", "--image", inputs / row["image"]["path"],
                        "--metadata", work / "metadata.json", "--slot-length", str(length),
                        "--out", work / "metadata-only.elf",
                    ], check=True)
                    negative = diff_payload((work / "metadata-only.elf").read_bytes(), ref)
                    passed &= bool(negative["different_byte_offsets"] and not negative["different_metadata"])
                    metadata_only.append({"program": name, "mode": mode, **negative})
            if mode in NATIVE_MODES:
                mode_results[mode]["direct_links"] = parity
                results.append(mode_results[mode])
    write_json(evidence / "comparison.json", {"native": results, "rbpf": r_bpf, "metadata_only": metadata_only})
    direct = [p for row in results for p in row["direct_links"]]
    print(f"direct links {sum(p['equal'] for p in direct)}/{len(direct)}; "
          f"v0.1.1 exact {sum(r['historical']['equal'] for r in results)}/{len(results)}; "
          f"rBPF bytes {sum(r['unchanged_instructions'] for r in r_bpf)}/{len(r_bpf)}")
    # The executable is a local comparison tool, not an archive input.
    encoder.unlink()
    return passed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unpacked", type=Path, required=True)
    parser.add_argument("--legacy-dir", type=Path, required=True)
    parser.add_argument("--legacy-assets", type=Path, required=True)
    parser.add_argument("--encoder", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    if not compare(args):
        parser.exit(1, "direct comparison or bytecode check failed\n")


if __name__ == "__main__":
    main()
