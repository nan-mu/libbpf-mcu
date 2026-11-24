"""Commands executed by Ninja for each machine artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from btf import analyze
from build_state import parse_depfile, record, update_diagnostic
from layout import (
    ROOT,
    LayoutError,
    bpf_path,
    container_path,
    native_object_path,
    q,
    sha256_file,
    source_path,
    state_path,
    write_if_changed,
)
from prevail_gate import examine
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
        Path(path.replace("$$", "$")).absolute()
        for path in parse_depfile(dep.read_text())
    ]


COMMENT_OR_LITERAL = (
    rb'(?P<comment>/\*[\s\S]*?\*/|//[^\n]*)|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\''
)
SOURCE_DIRECTIVES = re.compile(
    COMMENT_OR_LITERAL
    + rb'|^[ \t]*#[ \t]*(?:include[ \t]*"(?P<header>[^"\n]+)"|(?P<once>pragma[ \t]+once\b))'
    rb"(?P<trailer>[ \t]*(?:/\*[\s\S]*?\*/[ \t]*)*(?://[^\r\n]*)?)(?:\r?\n|$)",
    re.MULTILINE,
)
GUARD_OPENING = re.compile(
    rb"#[ \t]*(?:ifndef[ \t]+([A-Za-z_]\w*)"
    rb"|if[ \t]+![ \t]*defined(?:[ \t]*\([ \t]*([A-Za-z_]\w*)[ \t]*\)|[ \t]+([A-Za-z_]\w*)))"
)
CONDITIONAL = re.compile(rb"#[ \t]*(ifn?def|if|endif|else|elif(?:n?def)?)\b")


def controlling_guard(text: bytes) -> bytes | None:
    """Recognize a negative macro condition that encloses the entire file."""
    clean = re.sub(
        COMMENT_OR_LITERAL,
        lambda m: b" " + b"\n" * m[0].count(b"\n") if m["comment"] else m[0],
        text,
    ).strip()
    lines = clean.splitlines()
    opening = GUARD_OPENING.fullmatch(lines[0].strip()) if lines else None
    if not opening:
        return None
    depth = 1
    for index, line in enumerate(lines[1:], 1):
        directive = CONDITIONAL.match(line.lstrip())
        if directive is None:
            continue
        operator = directive[1]
        if operator.startswith(b"if"):
            depth += 1
        elif operator == b"endif":
            depth -= 1
            if depth == 0:
                if index == len(lines) - 1:
                    return next(guard for guard in opening.groups() if guard)
                break
        elif depth == 1:
            break
    return None


def source_snapshot(src: Path) -> tuple[bytes, list[Path]]:
    """Inline quoted program headers while keeping SDK includes and conditions."""
    headers = []
    sdk_roots = (ROOT / "include", ROOT / "include-bpf")

    def expand(path: Path, stack: tuple[Path, ...]) -> bytes:
        target = path.resolve()
        text = path.read_bytes()
        once = None
        if any(match["once"] for match in SOURCE_DIRECTIVES.finditer(text)):
            relative = os.fsencode(os.path.relpath(target, src.parent))
            once = (
                b"LIBBPF_MCU_SNAPSHOT_ONCE_"
                + hashlib.sha256(relative).hexdigest().encode()
            )

        if target in stack:
            # The compiler decides whether this edge is active for its target.
            # A conventional guard or an already executed pragma can suppress it.
            guards = [guard for guard in (controlling_guard(text), once) if guard]
            error = b"#error cyclic program include in source snapshot\n"
            if not guards:
                return error
            condition = b" && ".join(b"!defined(" + guard + b")" for guard in guards)
            return b"#if " + condition + b"\n" + error + b"#endif\n"

        def inline(match: re.Match[bytes]) -> bytes:
            if once is not None and match["once"]:
                # Set the guard at this directive, inside its original branch.
                return b"#define " + once + match["trailer"] + b"\n"
            name = match["header"]
            if name is None:
                return match[0]
            header = path.parent / os.fsdecode(name)
            included = header.resolve()
            if not header.is_file() or any(
                included.is_relative_to(sdk) for sdk in sdk_roots
            ):
                return match[0]
            headers.append(header)
            relative = (
                included.relative_to(ROOT) if included.is_relative_to(ROOT) else name
            )
            label = os.fsencode(relative)
            trailer = match["trailer"].lstrip(b" \t")
            content = expand(header, (*stack, target))
            if content and not content.endswith(b"\n"):
                content += b"\n"
            return (
                (trailer + b"\n" if trailer else b"")
                + b"/* Begin "
                + label
                + b" */\n"
                + content
                + b"/* End "
                + label
                + b" */\n"
            )

        snapshot = SOURCE_DIRECTIVES.sub(inline, text)
        if once:
            if not snapshot.endswith(b"\n"):
                snapshot += b"\n"
            return b"#ifndef " + once + b"\n" + snapshot + b"#endif\n"
        return snapshot

    return expand(src, ()), headers


def build_bpf(
    root: Path, src: Path, config: dict, config_path: Path, state: Path
) -> None:
    program = src.stem
    obj, snapshot = state.with_name(f"{program}_bpf.o"), state.with_name(f"{program}.c")
    original, included = source_snapshot(src)
    generation = []
    headers = compile_c(
        generation,
        src,
        obj,
        state.with_name("headers.d"),
        config["clang"],
        config["flags"],
    )
    if source_snapshot(src) != (original, included):
        raise LayoutError(
            f"{src} or its program headers changed during BPF compilation"
        )
    write_if_changed(snapshot, original)
    record(
        state,
        inputs=[src, config_path, config["clang"], *headers, *included],
        outputs=[obj, snapshot],
        generation=generation,
        source=str(src),
        objdump=config["objdump"],
    )


def verify_bpf(root: Path, program: str, state: Path, config: Path) -> None:
    basis = state_path(root, program, "bpf")
    obj = basis.with_name(f"{program}_bpf.o")
    snapshot = basis.with_name(f"{program}.c")
    verifier = Path(json.loads(config.read_text())["verifier"])
    examine(obj, verifier)
    public_obj, public_src = bpf_path(root, program), source_path(root, program)
    write_if_changed(public_obj, obj.read_bytes())
    write_if_changed(public_src, snapshot.read_bytes())
    record(
        state,
        inputs=[config, verifier, Path(__file__).with_name("prevail_gate.py")],
        outputs=[public_obj, public_src],
        upstream=[basis],
    )


def check_firmware(cfg):
    if sha256_file(Path(cfg["firmware"])) != cfg["firmware_digest"]:
        raise LayoutError(f"firmware changed during build: {cfg['firmware']}")


def check_deployment(cfg: dict, data: bytes):
    meta, payload = parse_container(data)
    if (meta.slot_address, meta.helper_address) != (cfg["slot_addr"], cfg["helper_addr"]):
        raise LayoutError("container target differs from the linked firmware")
    if len(payload) > cfg["slot_len"]:
        raise LayoutError(f"image is {len(payload)} bytes but target slot holds {cfg['slot_len']}")
    return meta, payload


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
        "--slot-length",
        hex(cfg["slot_len"]),
        "--helper-address",
        hex(cfg["helper_addr"]),
        "--machine",
        "1",
    ]


def link_native(generation, cfg, obj: Path, debug: Path) -> None:
    run(
        generation,
        "link",
        [
            cfg["clang"], "-target", "riscv32-unknown-none-elf", "-nostdlib",
            "-fuse-ld=lld", "-Xlinker", "-T", "-Xlinker", cfg["linker"],
            obj, "-o", debug,
        ],
    )


def pack_native(generation, cfg, bpf: Path, debug: Path, image: Path) -> bytes:
    run(generation, "convert", [cfg["objcopy"], "-O", "binary", debug, image])
    maps = image.with_name("maps.toml")
    write_maps(generation, bpf, maps)
    packed = image.with_name("container.elf")
    run(generation, "pack", [*pack_args(cfg, image, maps, debug), "-o", packed])
    data = packed.read_bytes()
    _meta, payload = check_deployment(cfg, data)
    if payload != image.read_bytes():
        raise LayoutError("AOT payload differs from the linked image")
    return data


def build_native(
    root: Path, mode: str, src: Path, cfg: dict, config: Path, state: Path
) -> None:
    name = src.stem
    out = state.parent
    obj = out / f"{name}_rv32.o"
    debug = out / f"{name}_rv32.debug.elf"
    snapshot = source_path(root, name).read_bytes()
    original, included = source_snapshot(src)
    if original != snapshot:
        raise LayoutError(f"{src} differs from the BPF source snapshot")
    generation = list(cfg["firmware_calls"])
    headers = compile_c(
        generation, src, obj, state.with_name("headers.d"), cfg["clang"], cfg["flags"]
    )
    if source_snapshot(src) != (original, included):
        raise LayoutError(
            f"{src} or its program headers changed during MCU compilation"
        )
    link_native(generation, cfg, obj, debug)
    files = [obj, debug]
    facts = {"linked_elf": str(debug)}
    if mode == "llvm-aot":
        image = out / f"{name}_rv32.bin"
        data = pack_native(generation, cfg, bpf_path(root, name), debug, image)
        files.append(image)
        facts.update(image=str(image), slot=cfg["slot_addr"])
        check_firmware(cfg)
        container = container_path(root, name, mode)
        public_obj = native_object_path(root, name)
        write_if_changed(container, data)
        write_if_changed(public_obj, obj.read_bytes())
        files.extend([container, public_obj])
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
    generation = list(cfg["firmware_calls"])
    write_maps(generation, obj, maps)
    basis = state_path(root, program, "ebpf-native")
    debug = read_state(basis)["linked_elf"]
    section = program_section(obj, cfg["objdump"])
    raw = state.with_name("section.bin")
    image = state.with_name("rewritten.bin")
    packed = state.with_name("container.elf")
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
            packed,
        ],
    )
    data = packed.read_bytes()
    _meta, payload = check_deployment(cfg, data)
    if payload != image.read_bytes():
        raise LayoutError("rBPF payload differs from the rewritten instructions")
    check_firmware(cfg)
    write_if_changed(container, data)
    record(
        state,
        inputs=[config, cfg["firmware"], cfg["tool"], cfg["objcopy"]],
        outputs=[container, image],
        upstream=[basis],
        generation=generation,
        objdump=cfg["objdump"],
        section=section,
    )


def pack_jit(generation, cfg, obj: Path, stage: Path) -> tuple[bytes, int]:
    maps = stage.with_name("maps.toml")
    write_maps(generation, obj, maps)
    run(
        generation,
        "host JIT",
        [
            cfg["tool"], "pack-jit", "--firmware", cfg["firmware"],
            "--obj", obj, "--maps", maps, "--name", cfg["image_name"],
            "--slot-address", hex(cfg["slot_addr"]),
            "--slot-length", hex(cfg["slot_len"]), "--stage", stage,
        ],
    )
    info = json.loads((stage / "code.json").read_text())
    data = (stage / "container.elf").read_bytes()
    _meta, payload = check_deployment(cfg, data)
    if payload != (stage / "jit.bin").read_bytes():
        raise LayoutError("JIT payload differs from the linked words")
    generation.extend(info["generation"])
    return data, info["code_len"]


def build_jit(root: Path, program: str, cfg: dict, config: Path, state: Path) -> None:
    obj = bpf_path(root, program)
    generation = list(cfg["firmware_calls"])
    stage = state.parent / ".jit-stage"
    shutil.rmtree(stage, ignore_errors=True)
    container = container_path(root, program, "jit")
    image = state.with_name("jit.bin")
    try:
        data, code_len = pack_jit(generation, cfg, obj, stage)
        check_firmware(cfg)
        os.replace(stage / "jit.bin", image)
        write_if_changed(container, data)
        record(
            state,
            inputs=[config, cfg["firmware"], cfg["tool"]],
            outputs=[container, image],
            upstream=[state_path(root, program, "prevail")],
            generation=generation,
            objdump=cfg["objdump"],
            code_len=code_len,
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
            verify_bpf(args.root, args.src.stem, state, args.config)
        elif args.mode in ("llvm-aot", "ebpf-native"):
            build_native(args.root, args.mode, args.src, cfg, args.config, state)
        elif args.mode == "ebpf":
            build_ebpf(args.root, args.src.stem, cfg, args.config, state)
        elif args.mode == "jit":
            build_jit(args.root, args.src.stem, cfg, args.config, state)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        update_diagnostic(args.root, args.src.stem, args.mode, str(exc))
        sys.exit(f"{args.src.stem}/{args.mode}: {exc}")
    update_diagnostic(args.root, args.src.stem, args.mode, None)


if __name__ == "__main__":
    main()
