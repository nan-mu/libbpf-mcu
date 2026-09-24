"""Build orchestration for libbpf-mcu (ninja: compile + object reports + pack)."""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from tiny_log import error, info, warning
from llvm_tools import resolve_llvm_tool

MAKE_DIR = Path(__file__).resolve().parent
ROOT = MAKE_DIR.parent
WORKSPACE_ROOT = ROOT.parent
DEFAULT_BUILD_DIR = WORKSPACE_ROOT / "build"
TESTS_DIR = ROOT / "tests"
NINJA_DIR = MAKE_DIR / "ninja"
LINKER_DIR = MAKE_DIR / "linker"
TOOLS_DIR = ROOT / "tools"
TOOLS_MANIFEST = TOOLS_DIR / "Cargo.toml"
TOOLS_SRC = TOOLS_DIR / "src" / "main.rs"
TOOLS_TARGET = TOOLS_DIR / "target"
XPOST_ELF_MANIFEST = WORKSPACE_ROOT / "xpost" / "xpost-elf" / "Cargo.toml"
CLANG = resolve_llvm_tool("clang", prefer_homebrew=True)
DEFAULT_OBJDUMP = resolve_llvm_tool("llvm-objdump")
DEFAULT_OBJCOPY = resolve_llvm_tool("llvm-objcopy")
REPORT_SCRIPTS = (MAKE_DIR / "obj_report.py", MAKE_DIR / "btf.py")
SLOT_LD_TMPL = LINKER_DIR / "esp32c3-slot.ld.tmpl"
XPOST_ESP32_C3_ARCH = 1


@dataclass(frozen=True)
class MemMapV0:
    helper_addr: int
    slot_addr: int
    slot_len: int
    table_addr: int
    table_len: int


@dataclass(frozen=True)
class BuildPaths:
    inputs: list[Path]
    outputs: list[Path]


@dataclass(frozen=True)
class BuildTarget:
    target: str
    inputs: list[Path]
    outputs: list[Path]


class BuildRegistry:
    def __init__(self):
        self._targets = None

    def _load_targets(self):
        make_dir = NINJA_DIR
        if not make_dir.is_dir():
            error(f"目录不存在: {make_dir}")
            sys.exit(1)

        self._targets = sorted(
            file_path.stem.lower()
            for file_path in make_dir.iterdir()
            if file_path.is_file()
        )

    def get(self):
        if self._targets is None:
            self._load_targets()
        return self._targets[:]

    def verify(self, target):
        if self._targets is None:
            self._load_targets()
        return target.lower() in self._targets


build_registry = BuildRegistry()


def _split_paths(value):
    if value is None:
        return None
    return [item for item in value.split() if item]


def _default_inputs(crate: str | None = None):
    inputs = sorted(
        path
        for path in TESTS_DIR.rglob("*.c")
        if "failed" not in path.relative_to(TESTS_DIR).parts
    )
    if crate is not None:
        matched = [path for path in inputs if path.stem == crate]
        if not matched:
            error(f"未找到 stem={crate!r} 的测试源（tests/**/{crate}.c）")
            sys.exit(1)
        if len(matched) > 1:
            error(f"stem={crate!r} 匹配多个文件: {matched}")
            sys.exit(1)
        inputs = matched
    if not inputs:
        error(f"默认测试输入为空: {TESTS_DIR}")
        sys.exit(1)
    return inputs


def _derive_default_outputs(inputs, target):
    outputs = []
    seen = {}
    for input_path in inputs:
        stem = Path(input_path).stem
        output_path = DEFAULT_BUILD_DIR / stem / f"{target}.o"
        if stem in seen:
            error(
                f"默认输出冲突: {seen[stem]} 与 {input_path} 都映射到 {output_path}"
            )
            sys.exit(1)
        seen[stem] = input_path
        outputs.append(output_path)
    return outputs


def check_build_args(target, inputs, outputs, crate: str | None = None):
    if target is None:
        targets = build_registry.get()
        if not targets:
            error("未找到任何 target")
            sys.exit(1)
    else:
        normalized_target = target.lower()
        if not build_registry.verify(normalized_target):
            error(f"未找到 target: {target}")
            sys.exit(1)
        targets = [normalized_target]

    input_items = _split_paths(inputs)
    output_items = _split_paths(outputs)

    if crate is not None and input_items is not None:
        error("不能同时指定 -c 与 --inputs/-i")
        sys.exit(1)

    if input_items is None and output_items is not None:
        warning(
            "不能只指定 --output/-o；默认输入会包含多个测试文件，请同时指定 --inputs/-i"
        )
        sys.exit(1)

    if output_items is not None and len(targets) > 1:
        error("构建多个 target 时不能指定 --output/-o")
        sys.exit(1)

    raw_inputs = (
        _default_inputs(crate)
        if input_items is None
        else [Path(item) for item in input_items]
    )

    builds = []
    for item in targets:
        raw_outputs = (
            _derive_default_outputs(raw_inputs, item)
            if output_items is None
            else [Path(path) for path in output_items]
        )
        if len(raw_inputs) != len(raw_outputs):
            error(
                f"输入文件和输出文件数量不一致: inputs={len(raw_inputs)}, outputs={len(raw_outputs)}"
            )
            sys.exit(1)
        builds.append(BuildTarget(item, raw_inputs, raw_outputs))

    return builds


def check_build_fs(paths):
    checked_inputs = []
    checked_outputs = []
    for input_path, output_path in zip(paths.inputs, paths.outputs):
        resolved_input = input_path.expanduser().resolve()
        if not resolved_input.is_file():
            error(f"输入文件不可用: {resolved_input}")
            sys.exit(1)
        if resolved_input.suffix != ".c":
            error(f"输入文件必须是 .c: {resolved_input}")
            sys.exit(1)

        resolved_output = output_path.expanduser().resolve()
        if resolved_output.exists() and resolved_output.is_dir():
            error(f"输出路径必须是文件，不能是目录: {resolved_output}")
            sys.exit(1)

        resolved_output.parent.mkdir(parents=True, exist_ok=True)
        checked_inputs.append(resolved_input)
        checked_outputs.append(resolved_output)

    return BuildPaths(checked_inputs, checked_outputs)


def _report_flags(target: str, release: bool, has_linker: bool = False) -> str:
    flags: list[str] = []
    if target == "bpf":
        flags.append("--btf")
    elif has_linker:
        flags.append("--merge-aot-addrs")
    if release:
        flags.append("--no-content")
    return " ".join(flags)


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


def tool_bin_path() -> Path:
    return TOOLS_TARGET / _host_triple() / "release" / "xpost-mcu-elf"


def _generate_esp32c3_slot_ld(mem: MemMapV0, out_dir: Path) -> Path:
    if not SLOT_LD_TMPL.is_file():
        error(f"linker template missing: {SLOT_LD_TMPL}")
        sys.exit(1)
    tmpl = SLOT_LD_TMPL.read_text()
    body = tmpl.format(
        slot_index=0,
        origin=mem.slot_addr,
        length=mem.slot_len,
        helper_base=mem.helper_addr,
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "esp32c3-slot-0.ld"
    out_path.write_text(body)
    return out_path


def _linker_script(target: str, mem: MemMapV0 | None) -> Path | None:
    if target != "esp32c3":
        path = LINKER_DIR / f"{target}.ld"
        return path if path.is_file() else None
    assert mem is not None
    ninja_dir = DEFAULT_BUILD_DIR / ".ninja"
    return _generate_esp32c3_slot_ld(mem, ninja_dir)


def ensure_tool(force: bool = False) -> Path:
    """Return xpost-mcu-elf path; cargo-build only if missing or force."""
    import os

    if not TOOLS_MANIFEST.is_file():
        error(f"tools manifest missing: {TOOLS_MANIFEST}")
        sys.exit(1)
    out = tool_bin_path()
    if out.is_file() and not force:
        return out
    cmd = [
        "cargo",
        "build",
        "--manifest-path",
        str(TOOLS_MANIFEST),
        "--release",
        "--target",
        _host_triple(),
        "--bin",
        "xpost-mcu-elf",
    ]
    run_env = os.environ.copy()
    run_env["CARGO_TARGET_DIR"] = str(TOOLS_TARGET)
    proc = subprocess.run(cmd, env=run_env)
    if proc.returncode != 0:
        error(f"cargo build xpost-mcu-elf failed: exit={proc.returncode}")
        sys.exit(proc.returncode)
    if not out.is_file():
        error(f"tool binary missing after build: {out}")
        sys.exit(1)
    return out


def load_mem_map_from_firmware(firmware_elf: Path, tool: Path) -> MemMapV0:
    """Read `.xpost.mem` via prebuilt `xpost-mcu-elf mem-map`."""
    if not firmware_elf.is_file():
        error(f"firmware ELF not found: {firmware_elf}")
        sys.exit(1)
    proc = subprocess.run(
        [str(tool), "mem-map", str(firmware_elf)],
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


def build_target(
    build,
    force=False,
    release=False,
    objdump=DEFAULT_OBJDUMP,
    objcopy=DEFAULT_OBJCOPY,
    firmware: Path | None = None,
    compact_elf=True,
):
    del objcopy
    template = NINJA_DIR / f"{build.target}.ninja"
    if not template.is_file():
        error(f"ninja 模板不可用: {template}")
        sys.exit(1)

    mem: MemMapV0 | None = None
    tool: Path | None = None
    if build.target == "esp32c3":
        if firmware is None:
            error("esp32c3 需要 --firmware <firmware.elf>（含 .xpost.mem / XPM1）")
            sys.exit(1)
        tool = ensure_tool(force=force)
        mem = load_mem_map_from_firmware(Path(firmware), tool)
        info(
            f"XPM1 helper={mem.helper_addr:#x} slot={mem.slot_addr:#x}+{mem.slot_len:#x} "
            f"table={mem.table_addr:#x}+{mem.table_len:#x}"
        )

    linker = _linker_script(build.target, mem)
    ninja_dir = DEFAULT_BUILD_DIR / ".ninja"
    ninja_dir.mkdir(parents=True, exist_ok=True)
    ninja_file = ninja_dir / "build.ninja"

    host = _host_triple()
    tool_bin = tool_bin_path()
    implicit = " ".join(str(path) for path in REPORT_SCRIPTS)
    edges: list[str] = []
    defaults: list[Path] = []

    if build.target == "esp32c3" and compact_elf:
        tool_deps = " ".join(
            str(p)
            for p in (
                TOOLS_MANIFEST,
                TOOLS_SRC,
                TOOLS_DIR / "src" / "bpf_meta.rs",
                XPOST_ELF_MANIFEST,
            )
            if p.is_file()
        )
        edges.append(f"build {tool_bin}: tool | {tool_deps}")

    for input_path, output_path in zip(build.inputs, build.outputs):
        stem = Path(input_path).stem
        depfile = output_path.with_suffix(".d")
        edges.append(
            f"build {output_path}: cc {input_path}\n"
            f"  depfile = {depfile}"
        )

        if linker is not None:
            linked_elf = output_path.with_suffix(".elf")
            bin_path = output_path.with_suffix(".bin")
            report_path = output_path.with_suffix(".toml")
            bpf_toml = output_path.parent / "bpf.toml"
            edges.append(f"build {linked_elf}: link {output_path} | {linker}")
            edges.append(f"build {bin_path}: bin {linked_elf}")
            edges.append(
                f"build {report_path}: report {linked_elf} | {implicit} {bpf_toml}\n"
                f"  src = {input_path}"
            )
            defaults.append(bin_path)
            defaults.append(report_path)
            if build.target == "esp32c3" and compact_elf:
                assert mem is not None
                compact = output_path.parent / f"{stem}.elf"
                edges.append(
                    f"build {compact}: pack {bin_path} | {tool_bin} {bpf_toml} {report_path}\n"
                    f"  image = {bin_path}\n"
                    f"  bpf_toml = {bpf_toml}\n"
                    f"  name = {stem}\n"
                    f"  slot = {mem.slot_addr:#x}\n"
                    f"  helper = {mem.helper_addr:#x}\n"
                    f"  machine = {XPOST_ESP32_C3_ARCH}\n"
                    f"  report = {report_path}"
                )
                defaults.append(compact)
        else:
            report_path = output_path.with_suffix(".toml")
            defaults.append(report_path)
            edges.append(
                f"build {report_path}: report {output_path} | {implicit}\n"
                f"  src = {input_path}"
            )

    content = template.read_text()
    content = content.replace("@ROOT@", str(ROOT))
    content = content.replace("@CLANG@", CLANG)
    content = content.replace("@PYTHON@", sys.executable)
    content = content.replace("@MAKE@", str(MAKE_DIR))
    content = content.replace("@OBJDUMP@", objdump)
    content = content.replace("@OBJCOPY@", DEFAULT_OBJCOPY)
    content = content.replace(
        "@LINKER@", str(linker) if linker is not None else ""
    )
    content = content.replace(
        "@REPORT_FLAGS@",
        _report_flags(build.target, release, has_linker=linker is not None),
    )
    content = content.replace("@TOOLS_MANIFEST@", str(TOOLS_MANIFEST))
    content = content.replace("@TOOLS_TARGET@", str(TOOLS_TARGET))
    content = content.replace("@HOST_TRIPLE@", host)
    content = content.replace("@TOOL_BIN@", str(tool_bin))
    content = content.replace("@EDGES@", "\n".join(edges))
    content = content.replace("@DEFAULT@", " ".join(str(path) for path in defaults))
    ninja_file.write_text(content)

    info(f"已生成 ninja: {ninja_file}")
    if linker is not None:
        info(f"linker: {linker}")
    run_ninja(ninja_file, force=force)


def run_ninja(ninja_file, force=False):
    if force:
        info("强制重建: ninja -t clean")
        clean = subprocess.run(
            ["ninja", "-f", str(ninja_file), "-t", "clean"],
            cwd=DEFAULT_BUILD_DIR,
        )
        if clean.returncode != 0:
            error(f"ninja clean 失败: exit={clean.returncode}")
            sys.exit(clean.returncode)

    info(f"运行 ninja: {ninja_file}")
    result = subprocess.run(
        ["ninja", "-f", str(ninja_file)], cwd=DEFAULT_BUILD_DIR
    )
    if result.returncode != 0:
        error(f"ninja 失败: exit={result.returncode}")
        sys.exit(result.returncode)
    info("ninja 完成")


def clean_build():
    if not DEFAULT_BUILD_DIR.exists():
        info(f"构建目录不存在，无需清理: {DEFAULT_BUILD_DIR}")
        return
    shutil.rmtree(DEFAULT_BUILD_DIR)
    info(f"已清空构建目录: {DEFAULT_BUILD_DIR}")
