"""Commands executed by Ninja for each machine artifact."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from btf import analyze
from build_state import parse_depfile, record
from layout import (
    LayoutError,
    bpf_path,
    container_path,
    q,
    sha256_file,
    source_path,
    state_path,
    write_if_changed,
)
from prevail_gate import prevail_bin, stamp_aot
from xdp_section import program_section
from xpost_elf import parse_container


def run(generation: list[dict], step: str, argv: list) -> None:
    command = list(map(str, argv))
    print(step + ": " + subprocess.list2cmdline(command), flush=True)
    subprocess.run(command, check=True)
    generation.append({"step": step, "argv": command})


def write_maps(generation: list[dict], obj: Path, maps: Path) -> None:
    lines = ["[maps]"]
    for item in analyze(obj)["maps"]["items"]:
        lines.append(f"[maps.{q(item['name'])}]")
        for field in (
            "map_type",
            "max_entries",
            "key_size",
            "value_size",
            "key",
            "value",
        ):
            value = item[field]
            lines.append(f"{field} = {q(value) if isinstance(value, str) else value}")
    write_if_changed(maps, ("\n".join(lines) + "\n").encode())
    generation.append(
        {
            "step": "extract map definitions",
            "call": "build_steps.write_maps",
            "parameters": {"object": str(obj), "output": str(maps)},
        }
    )


def compile_c(generation, src, obj, dep, clang, flags) -> list[Path]:
    run(
        generation,
        "compile",
        [
            clang,
            "-c",
            "-MD",
            "-MF",
            dep,
            "-MQ",
            dep.with_name("state.json"),
            *flags,
            src,
            "-o",
            obj,
        ],
    )
    return [
        Path(path.replace("$$", "$")).resolve()
        for path in parse_depfile(dep.read_text())
    ]


def build_bpf(
    root: Path, src: Path, config: dict, config_path: Path, state: Path
) -> None:
    program = src.stem
    obj, snapshot = bpf_path(root, program), source_path(root, program)
    original = src.read_bytes()
    generation = []
    headers = compile_c(
        generation,
        src,
        obj,
        state.with_name("headers.d"),
        config["clang"],
        config["flags"],
    )
    if src.read_bytes() != original:
        raise LayoutError(f"{src} changed during BPF compilation")
    write_if_changed(snapshot, original)
    record(
        state,
        inputs=[src, config_path, config["clang"], *headers],
        outputs=[obj, snapshot],
        generation=generation,
        source=str(src),
        objdump=config["objdump"],
    )


def verify_bpf(root: Path, program: str, state: Path) -> None:
    obj = bpf_path(root, program)
    stamp = obj.parent / "prevail.ok"
    stamp_aot(obj, stamp)
    record(
        state,
        inputs=[prevail_bin().resolve()],
        outputs=[stamp],
        upstream=[state_path(root, program, "bpf")],
    )


def check_firmware(cfg):
    if sha256_file(Path(cfg["firmware"])) != cfg["firmware_digest"]:
        raise LayoutError(f"firmware changed during build: {cfg['firmware']}")


def pack_args(cfg, image, maps, debug):
    return [
        cfg["tool"],
        "pack",
        "--image",
        image,
        "--maps",
        maps,
        "--linked-elf",
        debug,
        "--name",
        cfg["image_name"],
        "--slot-address",
        hex(cfg["slot_addr"]),
        "--helper-address",
        hex(cfg["helper_addr"]),
        "--machine",
        "1",
    ]


def build_native(
    root: Path, mode: str, src: Path, cfg: dict, config: Path, state: Path
) -> None:
    name = src.stem
    out = root / name / mode if mode == "llvm-aot" else state.parent
    obj = out / f"{name}_rv32.o"
    debug = out / f"{name}_rv32.debug.elf"
    snapshot = source_path(root, name).read_bytes()
    if src.read_bytes() != snapshot:
        raise LayoutError(f"{src} differs from the BPF source snapshot")
    generation = list(cfg["firmware_calls"])
    headers = compile_c(
        generation, src, obj, state.with_name("headers.d"), cfg["clang"], cfg["flags"]
    )
    if src.read_bytes() != snapshot:
        raise LayoutError(f"{src} changed during MCU compilation")
    run(
        generation,
        "link",
        [
            cfg["clang"],
            "-target",
            "riscv32-unknown-none-elf",
            "-nostdlib",
            "-fuse-ld=lld",
            "-Wl,-T," + cfg["linker"],
            "-Wl",
            obj,
            "-o",
            debug,
        ],
    )
    files = [obj, debug]
    facts = {"linked_elf": str(debug)}
    if mode == "llvm-aot":
        image = out / f"{name}_rv32.bin"
        run(generation, "convert", [cfg["objcopy"], "-O", "binary", debug, image])
        files.append(image)
        facts.update(image=str(image), slot=cfg["slot_addr"])
        if cfg["compact"]:
            maps = state.with_name("maps.toml")
            write_maps(generation, bpf_path(root, name), maps)
            container = container_path(root, name, mode)
            run(
                generation,
                "pack",
                [*pack_args(cfg, image, maps, debug), "-o", container],
            )
            _meta, payload = parse_container(container.read_bytes())
            if payload != image.read_bytes():
                raise LayoutError("AOT payload differs from the linked image")
            files.append(container)
        else:
            container_path(root, name, mode).unlink(missing_ok=True)
    check_firmware(cfg)
    tools = [cfg["clang"], cfg["tool"]]
    if mode == "llvm-aot":
        tools.append(cfg["objcopy"])
    record(
        state,
        inputs=[src, config, cfg["firmware"], cfg["linker"], *tools, *headers],
        outputs=files,
        upstream=[state_path(root, name, "prevail")],
        generation=generation,
        objdump=cfg["objdump"],
        **facts,
    )


def build_ebpf(root: Path, program: str, cfg: dict, config: Path, state: Path) -> None:
    from build_state import read_state

    obj = bpf_path(root, program)
    maps = state.with_name("maps.toml")
    generation = []
    write_maps(generation, obj, maps)
    basis = state_path(root, program, "ebpf-native")
    debug = read_state(basis)["linked_elf"]
    section = program_section(obj)
    raw = state.with_name("section.bin")
    image = root / program / "ebpf" / f"{program}_bpf-xpost.bin"
    container = container_path(root, program, "ebpf")
    run(
        generation,
        "extract",
        [cfg["objcopy"], "-O", "binary", f"--only-section={section}", obj, raw],
    )
    run(
        generation,
        "pack",
        [
            *pack_args(cfg, raw, maps, debug),
            "--map-index",
            "--obj",
            obj,
            "--export-image",
            image,
            "-o",
            container,
        ],
    )
    _meta, payload = parse_container(container.read_bytes())
    if payload != image.read_bytes():
        raise LayoutError("rBPF payload differs from the rewritten instructions")
    check_firmware(cfg)
    record(
        state,
        inputs=[config, cfg["firmware"], cfg["tool"], cfg["objcopy"]],
        outputs=[container, image],
        upstream=[basis],
        generation=generation,
        objdump=cfg["objdump"],
        section=section,
    )


def build_jit(root: Path, program: str, cfg: dict, config: Path, state: Path) -> None:
    obj = bpf_path(root, program)
    maps = state.with_name("maps.toml")
    generation = list(cfg["firmware_calls"])
    write_maps(generation, obj, maps)
    stage = state.parent / ".jit-stage"
    shutil.rmtree(stage, ignore_errors=True)
    container = container_path(root, program, "jit")
    image = container.with_name("jit.bin")
    try:
        run(
            generation,
            "host JIT",
            [
                cfg["tool"],
                "pack-jit",
                "--firmware",
                cfg["firmware"],
                "--obj",
                obj,
                "--maps",
                maps,
                "--name",
                cfg["image_name"],
                "--slot-address",
                hex(cfg["slot_addr"]),
                "--slot-length",
                hex(cfg["slot_len"]),
                "--stage",
                stage,
            ],
        )
        info = json.loads((stage / "code.json").read_text())
        data = (stage / "container.elf").read_bytes()
        _meta, payload = parse_container(data)
        if payload != (stage / "jit.bin").read_bytes():
            raise LayoutError("JIT payload differs from the linked words")
        os.replace(stage / "jit.bin", image)
        os.replace(stage / "container.elf", container)
        generation.extend(info["generation"])
        check_firmware(cfg)
        record(
            state,
            inputs=[config, cfg["firmware"], cfg["tool"]],
            outputs=[container, image],
            upstream=[state_path(root, program, "prevail")],
            generation=generation,
            objdump=cfg["objdump"],
            code_len=info["code_len"],
        )
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode")
    parser.add_argument("root", type=Path)
    parser.add_argument("src", type=Path)
    parser.add_argument("config", nargs="?", type=Path)
    args = parser.parse_args()
    state = state_path(args.root, args.src.stem, args.mode)
    state.unlink(missing_ok=True)
    try:
        cfg = json.loads(args.config.read_text()) if args.config else {}
        if "firmware" in cfg:
            check_firmware(cfg)
        if args.mode == "bpf":
            build_bpf(args.root, args.src, cfg, args.config, state)
        elif args.mode == "prevail":
            verify_bpf(args.root, args.src.stem, state)
        elif args.mode in ("llvm-aot", "ebpf-native"):
            build_native(args.root, args.mode, args.src, cfg, args.config, state)
        elif args.mode == "ebpf":
            build_ebpf(args.root, args.src.stem, cfg, args.config, state)
        elif args.mode == "jit":
            build_jit(args.root, args.src.stem, cfg, args.config, state)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        sys.exit(f"{args.src.stem}/{args.mode}: {exc}")


if __name__ == "__main__":
    main()
