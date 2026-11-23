"""Configure and run the producer's Ninja build."""

from __future__ import annotations

import json
import os
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from build_state import (
    PRIVATE_MODES,
    prepare_program,
    read_state,
    reconcile,
    render_reports,
    update_diagnostic,
)
from layout import (
    ROOT,
    LayoutError,
    bpf_path,
    check_program,
    container_path,
    lock,
    native_object_path,
    source_path,
    sha256_file,
    state_path,
    write_if_changed,
)
from llvm_tools import resolve_llvm_tool
from prevail_gate import prevail_bin
from tiny_log import error, info

MAKE = ROOT / "make"
DEFAULT_BUILD_DIR = ROOT / "build"
CLANG = resolve_llvm_tool("clang", prefer_homebrew=True)
DEFAULT_OBJDUMP = resolve_llvm_tool("llvm-objdump")
DEFAULT_OBJCOPY = resolve_llvm_tool("llvm-objcopy")
SLOT_LD_TMPL = MAKE / "linker" / "rv32imc-slot.ld.tmpl"
TOOLS_MANIFEST = ROOT / "tools" / "Cargo.toml"

BPF_FLAGS = [
    "-O2",
    "--target=bpf",
    "-Wall",
    "-Wno-missing-declarations",
    "-fno-stack-protector",
    "-g",
    f"-ffile-prefix-map={ROOT}/=",
    "-fdebug-compilation-dir=.",
    "-I",
    str(ROOT / "include-bpf"),
    "-include",
    "vmlinux.h",
]
MCU_FLAGS = [
    "-O2",
    "--target=riscv32-unknown-none-elf",
    "-march=rv32imc",
    "-mabi=ilp32",
    "-nostdlib",
    "-ffreestanding",
    "-fno-builtin",
    "-fno-exceptions",
    "-fno-rtti",
    "-fno-jump-tables",
    "-fno-omit-frame-pointer",
    "-Wall",
    "-Wno-unused-function",
    "-g",
    "-I",
    str(ROOT / "include"),
    "-include",
    "vmlinux.h",
]


@dataclass(frozen=True)
class MemMapV0:
    helper_addr: int
    slot_addr: int
    slot_len: int
    table_addr: int
    table_len: int


def resolve_sources(inputs: list[str] | None, crate: str | None) -> list[Path]:
    if inputs is not None and crate is not None:
        raise LayoutError("--inputs and -c are mutually exclusive")
    if inputs is not None:
        sources = [Path(item).expanduser().resolve() for item in inputs]
    else:
        sources = sorted(
            path
            for path in (ROOT / "tests").rglob("*.c")
            if "unused" not in path.relative_to(ROOT / "tests").parts
            and (
                crate is not None
                or "diagnostics" not in path.relative_to(ROOT / "tests").parts
            )
            and (crate is None or path.stem == crate)
        )
    if not sources:
        raise LayoutError(f"no C sources selected for {crate or 'build'}")
    seen = set()
    for path in sources:
        if path.suffix != ".c" or not path.is_file():
            raise LayoutError(f"expected a C source file: {path}")
        name = check_program(path.stem).casefold()
        if name in seen:
            raise LayoutError(f"conflicting program output: {path.stem}")
        seen.add(name)
    return sources


def _host_triple() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "darwin" and machine in ("arm64", "aarch64"):
        return "aarch64-apple-darwin"
    if system == "darwin" and machine in ("x86_64", "amd64"):
        return "x86_64-apple-darwin"
    if system == "linux" and machine in ("x86_64", "amd64"):
        return "x86_64-unknown-linux-gnu"
    if system == "linux" and machine in ("arm64", "aarch64"):
        return "aarch64-unknown-linux-gnu"
    return "aarch64-apple-darwin"


def tool_bin_path(build_dir: Path) -> Path:
    return build_dir / ".ninja" / "cargo" / _host_triple() / "release" / "xpost-mcu-elf"


def ensure_tool(build_dir: Path) -> Path:
    """Let Cargo check the Rust tool and its sibling XPOST dependencies."""

    if not TOOLS_MANIFEST.is_file():
        error(f"tools manifest missing: {TOOLS_MANIFEST}")
        sys.exit(1)
    out = tool_bin_path(build_dir)
    cmd = [
        "cargo",
        "build",
        "--manifest-path",
        str(TOOLS_MANIFEST),
        "--release",
        "--locked",
        "--target-dir",
        str(build_dir / ".ninja" / "cargo"),
        "--target",
        _host_triple(),
        "--bin",
        "xpost-mcu-elf",
    ]
    proc = subprocess.run(cmd)
    if proc.returncode != 0:
        error(f"cargo build xpost-mcu-elf failed: exit={proc.returncode}")
        sys.exit(proc.returncode)
    if not out.is_file():
        error(f"tool binary missing after build: {out}")
        sys.exit(1)
    return out


def load_mem_map_from_firmware(
    firmware_elf: Path, tool: Path, generation: list[dict]
) -> MemMapV0:
    """Read `.xpost.mem` via prebuilt `xpost-mcu-elf mem-map`."""
    if not firmware_elf.is_file():
        error(f"firmware ELF not found: {firmware_elf}")
        sys.exit(1)
    argv = [str(tool), "mem-map", str(firmware_elf)]
    generation.append({"step": "firmware", "argv": argv})
    proc = subprocess.run(
        argv,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        error(f"xpost-mcu-elf mem-map failed: exit={proc.returncode}: {err}")
        sys.exit(proc.returncode)
    lines = [ln for ln in (proc.stdout or "").splitlines() if ln.strip()]
    if not lines:
        error("xpost-mcu-elf mem-map produced no stdout")
        sys.exit(1)
    line = lines[-1]
    try:
        data = json.loads(line)
        return MemMapV0(
            helper_addr=int(data["helper_addr"]),
            slot_addr=int(data["slot_addr"]),
            slot_len=int(data["slot_len"]),
            table_addr=int(data["table_addr"]),
            table_len=int(data["table_len"]),
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        error(f"xpost-mcu-elf mem-map bad stdout: {line!r} ({exc})")
        sys.exit(1)


def apply_slot_symbol(
    mem: MemMapV0, firmware_elf: Path, tool: Path, name: str, generation: list[dict]
) -> MemMapV0:
    """Replace the XPM1 slot with one firmware symbol. Images are not relocatable."""
    argv = [str(tool), "symbol", str(firmware_elf), name]
    generation.append({"step": "slot symbol", "argv": argv})
    proc = subprocess.run(
        argv,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        error(f"xpost-mcu-elf symbol {name} failed: exit={proc.returncode}: {err}")
        sys.exit(proc.returncode)
    lines = [ln for ln in (proc.stdout or "").splitlines() if ln.strip()]
    if not lines:
        error(f"xpost-mcu-elf symbol {name} produced no stdout")
        sys.exit(1)
    line = lines[-1]
    try:
        data = json.loads(line)
        addr = int(data["addr"])
        size = int(data["size"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        error(f"xpost-mcu-elf symbol bad stdout: {line!r} ({exc})")
        sys.exit(1)
    if addr == 0 or size == 0:
        error(f"symbol {name} has addr={addr:#x} size={size:#x}")
        sys.exit(1)
    info(f"slot symbol {name} addr={addr:#x} size={size:#x}")
    return replace(mem, slot_addr=addr, slot_len=size)


def _ninja(value: str | Path) -> str:
    return str(value).replace("$", "$$").replace(" ", "$ ").replace(":", "$:")


def _edge(
    outputs: list[Path],
    deps: list[Path],
    argv: list,
    label: str,
    *,
    depfile: Path | None = None,
) -> str:
    rule = "compile" if depfile is not None else "produce"
    lines = [
        f"build {' '.join(map(_ninja, outputs))}: {rule} {' '.join(map(_ninja, deps))}",
        f"  argv = {shlex.join(map(str, argv)).replace('$', '$$')}",
        f"  label = {label.replace('$', '$$')}",
    ]
    if depfile is not None:
        lines.append(f"  depfile = {_ninja(depfile)}")
    return "\n".join(lines)


def write_build_ninja(
    root: Path, sources: list[Path], mode: str, args, backend: dict
) -> Path:
    template = MAKE / "ninja" / "graph.ninja"
    scripts = [
        MAKE / name
        for name in (
            "build.py",
            "build_steps.py",
            "build_state.py",
            "layout.py",
            "btf.py",
            "xpost_elf.py",
        )
    ] + [template]
    compiler_env = {key: os.environ.get(key) for key in ("CPATH", "C_INCLUDE_PATH")}
    edges, targets = [], []
    for src in sources:
        name = src.stem
        bpf = bpf_path(root, name)
        snapshot = source_path(root, name)
        bpf_state = state_path(root, name, "bpf")
        gate = state_path(root, name, "prevail")
        raw_obj = bpf_state.with_name(f"{name}_bpf.o")
        raw_src = bpf_state.with_name(f"{name}.c")
        modes = ["bpf", "prevail"]
        if mode == "ebpf":
            modes.append("ebpf-native")
        if mode != "bpf":
            modes.append(mode)
        targets.append(gate if mode == "bpf" else state_path(root, name, mode))
        for item in modes:
            state = state_path(root, name, item)
            outputs, deps = [state], list(scripts)
            cfg = None
            depfile = None
            if item == "bpf":
                cfg = {
                    "clang": CLANG,
                    "flags": BPF_FLAGS,
                    "objdump": args.objdump,
                    "compiler_env": compiler_env,
                }
                outputs.extend([raw_obj, raw_src])
                deps.extend([src, Path(CLANG)])
                depfile = state.with_name("headers.d")
            elif item == "prevail":
                cfg = {"verifier": str(prevail_bin())}
                outputs.extend([bpf, snapshot])
                deps.extend(
                    [
                        bpf_state,
                        raw_obj,
                        raw_src,
                        prevail_bin(),
                        MAKE / "prevail_gate.py",
                    ]
                )
            else:
                cfg = dict(
                    backend,
                    objdump=args.objdump,
                    objcopy=args.objcopy,
                    image_name=args.image_name or name,
                )
                deps.extend([Path(cfg["firmware"]), Path(cfg["tool"])])
                if item in ("llvm-aot", "ebpf-native"):
                    cfg.update(clang=CLANG, flags=MCU_FLAGS, compiler_env=compiler_env)
                    linker = state.with_name("slot.ld")
                    write_if_changed(
                        linker,
                        SLOT_LD_TMPL.read_text()
                        .format(
                            slot_index=0,
                            origin=cfg["slot_addr"],
                            length=cfg["slot_len"],
                            helper_base=cfg["helper_addr"],
                        )
                        .encode(),
                    )
                    cfg["linker"] = str(linker)
                    deps.extend([src, gate, Path(CLANG), linker])
                    depfile = state.with_name("headers.d")
                    outputs.extend(
                        [
                            state.with_name(f"{name}_rv32.o"),
                            state.with_name(f"{name}_rv32.debug.elf"),
                        ]
                    )
                    if item == "llvm-aot":
                        outputs.extend(
                            [
                                state.with_name(f"{name}_rv32.bin"),
                                native_object_path(root, name),
                                container_path(root, name, item),
                            ]
                        )
                        deps.append(Path(cfg["objcopy"]))
                elif item == "ebpf":
                    deps.extend(
                        [
                            state_path(root, name, "ebpf-native"),
                            Path(cfg["objcopy"]),
                            MAKE / "xdp_section.py",
                        ]
                    )
                    outputs.extend(
                        [
                            container_path(root, name, item),
                            state.with_name("rewritten.bin"),
                        ]
                    )
                else:
                    deps.append(gate)
                    container = container_path(root, name, item)
                    outputs.extend([container, state.with_name("jit.bin")])
            argv = [sys.executable, MAKE / "build_steps.py", item, root, src]
            if cfg is not None:
                config = state.with_name("config.json")
                write_if_changed(config, json.dumps(cfg, sort_keys=True).encode())
                deps.append(config)
                argv.append(config)
            state.parent.mkdir(parents=True, exist_ok=True)
            edges.append(_edge(outputs, deps, argv, f"{item} {name}", depfile=depfile))
    path = root / ".ninja" / "build.ninja"
    body = template.read_text().replace("@EDGES@", "\n\n".join(edges))
    body = body.replace("@DEFAULT@", " ".join(map(_ninja, targets)))
    write_if_changed(path, body.encode())
    return path


def build(root: Path, sources: list[Path], mode: str, args) -> None:
    selected = (mode,)
    attempted = tuple(dict.fromkeys(("bpf", "prevail", mode)))
    with lock(root):
        if (root / "index.toml").exists():
            raise LayoutError(
                f"{root}: use a separate build root from existing artifact indexes"
            )
        names = {src.stem for src in sources}
        for src in sources:
            if src.is_relative_to(root / ".ninja") or any(
                src.is_relative_to(root / name) for name in names
            ):
                raise LayoutError(f"source overlaps generated output: {src}")
        if (root / ".ninja").is_symlink():
            raise LayoutError(f"symlink is not a build directory: {root / '.ninja'}")
        programs = names | {
            p.name for p in (root / ".ninja").glob("*") if (p / "bpf").is_dir()
        }
        # Withhold any mode being replaced, while preserving unrelated valid
        # modes. Ninja and the receipts determine which modes can return.
        for program in sorted(programs):
            prepare_program(root, check_program(program))
        for src in sources:
            receipt = state_path(root, src.stem, "bpf")
            if receipt.is_file():
                try:
                    previous_source = read_state(receipt)["source"]
                except (KeyError, TypeError, ValueError):
                    previous_source = None
                if previous_source != str(src):
                    receipt.unlink()
        for program in sorted(programs):
            reconcile(root, program, selected if program in names else ())
        backend = {}
        graph_ready = False
        failure = ""
        try:
            if not prevail_bin().is_file():
                for src in sources:
                    state_path(root, src.stem, "prevail").unlink(missing_ok=True)
                raise LayoutError(f"PREVAIL binary missing: {prevail_bin()}")
            if mode != "bpf":
                firmware = args.firmware.expanduser().resolve()
                if not firmware.is_file():
                    raise LayoutError(f"firmware ELF not found: {firmware}")
                generation = []
                firmware_digest = sha256_file(firmware)
                tool = ensure_tool(root)
                mem = load_mem_map_from_firmware(firmware, tool, generation)
                if args.slot_symbol:
                    mem = apply_slot_symbol(
                        mem, firmware, tool, args.slot_symbol, generation
                    )
                backend = dict(
                    asdict(mem),
                    firmware=str(firmware),
                    tool=str(tool),
                    firmware_calls=generation,
                    firmware_digest=firmware_digest,
                )
            path = write_build_ninja(root, sources, mode, args, backend)
            for src in sources:
                update_diagnostic(root, src.stem, f"preflight/{mode}", None)
            force_modes = {mode, "bpf", "prevail"}
            if mode == "ebpf":
                force_modes.add("ebpf-native")
            for src in sources:
                reasons = reconcile(root, src.stem, selected)
                for item in PRIVATE_MODES:
                    receipt = state_path(root, src.stem, item)
                    if item in reasons or (args.force and item in force_modes):
                        receipt.unlink(missing_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="w",
                prefix=f"{mode}-",
                suffix=".log",
                dir=root / ".ninja",
                delete=False,
            ) as log:
                with subprocess.Popen(
                    ["ninja", "-f", str(path), "-k", "0"],
                    cwd=root,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                ) as proc:
                    graph_ready = True
                    for line in proc.stdout:
                        log.write(line)
                        print(line, end="", flush=True)
                if proc.returncode:
                    raise LayoutError(
                        f"Ninja failed ({proc.returncode}), see {log.name}"
                    )
        except (OSError, ValueError, SystemExit, KeyboardInterrupt) as exc:
            failure = str(exc) or type(exc).__name__
            if not graph_ready:
                target = "prevail" if mode == "bpf" else mode
                for src in sources:
                    state_path(root, src.stem, target).unlink(missing_ok=True)
                    update_diagnostic(root, src.stem, f"preflight/{mode}", failure)
            raise
        finally:
            final_errors = []
            for program in sorted(programs):
                reasons = reconcile(root, program)
                if program in names and not failure:
                    for step in attempted:
                        if step in reasons:
                            final_errors.append(f"{program}/{step}: {reasons[step]}")
                            break
                if "bpf" in reasons or "prevail" in reasons:
                    continue
                try:
                    render_reports(root, program)
                except (OSError, ValueError, subprocess.SubprocessError) as exc:
                    final_errors.append(f"{program}: report generation failed: {exc}")
            if final_errors:
                message = "\n".join(final_errors)
                if not failure:
                    raise LayoutError(message)
                print(message, file=sys.stderr)


def clean_build() -> None:
    with lock(DEFAULT_BUILD_DIR):
        if DEFAULT_BUILD_DIR.exists():
            shutil.rmtree(DEFAULT_BUILD_DIR)
            info(f"removed {DEFAULT_BUILD_DIR}")
