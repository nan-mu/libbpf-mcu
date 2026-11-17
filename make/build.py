"""Build orchestration for libbpf-mcu (ninja: compile + object reports + pack)."""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, replace
from pathlib import Path

from llvm_tools import resolve_llvm_tool
from jit_publish import JitDeliverables
from layout import mode_dir, report_path, spec_path, stamp_path
from prevail_gate import prevail_bin
from tiny_log import error, info

MAKE_DIR = Path(__file__).resolve().parent
ROOT = MAKE_DIR.parent
WORKSPACE_ROOT = ROOT.parent
DEFAULT_BUILD_DIR = WORKSPACE_ROOT / "build"
TESTS_DIR = ROOT / "tests"
NINJA_DIR = MAKE_DIR / "ninja"
LINKER_DIR = MAKE_DIR / "linker"
TOOLS_DIR = ROOT / "tools"
TOOLS_MANIFEST = TOOLS_DIR / "Cargo.toml"
TOOLS_TARGET = TOOLS_DIR / "target"
XPOST_ELF_MANIFEST = WORKSPACE_ROOT / "xpost" / "xpost-elf" / "Cargo.toml"
CLANG = resolve_llvm_tool("clang", prefer_homebrew=True)
DEFAULT_OBJDUMP = resolve_llvm_tool("llvm-objdump")
DEFAULT_OBJCOPY = resolve_llvm_tool("llvm-objcopy")
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
class McuLink:
    """Present only when this graph may compile ESP32-C3 code."""

    mem: MemMapV0
    linker: Path
    tool_bin: Path
    firmware: Path
    compact_elf: bool
    image_name: str | None = None
    slot_symbol: str | None = None
    engine: str = "aot"

    def __post_init__(self) -> None:
        if self.engine not in {"aot", "rbpf"}:
            raise ValueError(f"engine must be aot or rbpf, got {self.engine!r}")


@dataclass(frozen=True)
class JitLink:
    """JIT publication. Slot and helper stay in the firmware file."""

    firmware: Path
    tool_bin: Path
    mem: MemMapV0
    image_name: str | None = None


@dataclass(frozen=True)
class PrevailStamp:
    """Absence is the refusal."""

    stem: str
    build_dir: Path

    @property
    def path(self) -> Path:
        return stamp_path(self.build_dir, self.stem)


@dataclass(frozen=True)
class GraphPlan:
    sources: tuple[Path, ...]
    backend: McuLink | JitLink | None
    release: bool
    objdump: str
    build_dir: Path


@dataclass(frozen=True)
class BuildPaths:
    inputs: list[Path]
    outputs: list[Path]


@dataclass(frozen=True)
class BuildTarget:
    target: str
    inputs: list[Path]
    outputs: list[Path]


TARGETS = ("bpf", "esp32c3")
EXPLICIT_TARGETS = (*TARGETS, "jit")


def _split_paths(value):
    if value is None:
        return None
    return [item for item in value.split() if item]


def _default_inputs(crate: str | None = None):
    inputs = sorted(
        path
        for path in TESTS_DIR.rglob("*.c")
        if "unused" not in path.relative_to(TESTS_DIR).parts
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


def _derive_default_outputs(inputs, target, build_dir: Path):
    outputs = []
    seen = {}
    mode = "rv32" if target == "esp32c3" else "bpf"
    suffix = "_rv32.o" if target == "esp32c3" else "_bpf.o"
    for input_path in inputs:
        stem = Path(input_path).stem
        output_path = build_dir / stem / mode / f"{stem}{suffix}"
        if stem in seen:
            error(
                f"默认输出冲突: {seen[stem]} 与 {input_path} 都映射到 {output_path}"
            )
            sys.exit(1)
        seen[stem] = input_path
        outputs.append(output_path)
    return outputs


def check_build_args(target, inputs, outputs, crate: str | None = None, build_dir: Path = DEFAULT_BUILD_DIR):
    if target is None:
        targets = list(TARGETS)
    else:
        normalized_target = target.lower()
        if normalized_target not in EXPLICIT_TARGETS:
            error(f"未找到 target: {target}")
            sys.exit(1)
        targets = [normalized_target]

    input_items = _split_paths(inputs)
    output_items = _split_paths(outputs)

    if crate is not None and input_items is not None:
        error("不能同时指定 -c 与 --inputs/-i")
        sys.exit(1)

    if output_items is not None:
        error(
            "--output 不再选择产物路径。文件名由程序名和模式决定，目录由 --build-dir 决定。"
            "旧布局用 artifacts export-legacy 导出到另一个目录。"
        )
        sys.exit(2)

    raw_inputs = (
        _default_inputs(crate)
        if input_items is None
        else [Path(item) for item in input_items]
    )

    builds = []
    for item in targets:
        raw_outputs = (
            _derive_default_outputs(raw_inputs, item, build_dir)
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
    if not out_path.is_file() or out_path.read_text() != body:
        out_path.write_text(body)
    return out_path


def _linker_script(target: str, mem: MemMapV0 | None, build_dir: Path) -> Path | None:
    if target != "esp32c3":
        path = LINKER_DIR / f"{target}.ld"
        return path if path.is_file() else None
    assert mem is not None
    return _generate_esp32c3_slot_ld(mem, build_dir / ".ninja")


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


def apply_slot_symbol(mem: MemMapV0, firmware_elf: Path, tool: Path, name: str) -> MemMapV0:
    """Replace the XPM1 slot with one firmware symbol. Images are not relocatable."""
    proc = subprocess.run(
        [str(tool), "symbol", str(firmware_elf), name],
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


def mcu_cc_edge(src: Path, obj: Path, stamp: PrevailStamp, depfile: Path) -> str:
    """Explicit input is src only. Implicit input is stamp.path."""
    return f"build {obj}: mcu_cc {src} | {stamp.path}\n  depfile = {depfile}"


def compact_name(plan: GraphPlan, stem: str) -> str:
    """Container name. A second link of the same source passes `--image-name`."""
    backend = plan.backend
    if isinstance(backend, (McuLink, JitLink)) and backend.image_name:
        return backend.image_name
    return stem


def _defaults_for_stem(src: Path, plan: GraphPlan) -> list[Path]:
    stem = src.stem
    root = plan.build_dir
    paths = [report_path(root, stem, "bpf")]
    backend = plan.backend
    if isinstance(backend, JitLink):
        paths.extend(
            JitDeliverables.for_stem(
                root, stem, compact_name(plan, stem)
            ).outputs()
        )
    elif isinstance(backend, McuLink):
        paths.append(report_path(root, stem, "rv32"))
        if backend.compact_elf:
            paths.append(spec_path(root, stem, "rv32", "xpost_container"))
        if backend.engine == "rbpf":
            paths.append(report_path(root, stem, "bpf-xpost"))
    return paths


def _publish_inputs() -> str:
    names = (
        "layout.py",
        "obj_report.py",
        "btf.py",
        "prevail_gate.py",
        "jit_publish.py",
        "xdp_section.py",
        "llvm_tools.py",
    )
    return " ".join(str(MAKE_DIR / name) for name in names)


def edges_for_stem(src: Path, plan: GraphPlan) -> str:
    """Emit one stem. plan.backend is the MCU cone, the jit edge, or neither."""
    stem = src.stem
    root = plan.build_dir
    bpf_dir = mode_dir(root, stem, "bpf")
    bpf_o = bpf_dir / f"{stem}_bpf.o"
    dep = bpf_dir / f"{stem}_bpf.d"
    bpf_report = report_path(root, stem, "bpf")
    release = "1" if plan.release else "0"
    scripts = _publish_inputs()
    lines = [
        f"build {bpf_o}: bpf_cc {src}\n  depfile = {dep}",
        (
            f"build {bpf_report}: commit_bpf {bpf_o} | {scripts}\n"
            f"  program = {stem}\n"
            f"  src = {src}\n"
            f"  build_dir = {root}\n"
            f"  headers = {dep}\n"
            f"  release = {release}"
        ),
    ]
    backend = plan.backend
    if backend is None:
        return "\n".join(lines)
    if isinstance(backend, JitLink):
        deliver = JitDeliverables.for_stem(root, stem, compact_name(plan, stem))
        outs = " ".join(str(path) for path in deliver.outputs())
        lines.append(
            f"build {outs}: jit_publish {bpf_o} | "
            f"{backend.tool_bin} {backend.firmware} {bpf_report} {scripts}\n"
            f"  src = {src}\n"
            f"  obj = {bpf_o}\n"
            f"  bpf_toml = {bpf_report}\n"
            f"  firmware = {backend.firmware}\n"
            f"  stem = {stem}\n"
            f"  name = {compact_name(plan, stem)}\n"
            f"  out_dir = {deliver.jit_bin.parent}\n"
            f"  tool = {backend.tool_bin}\n"
            f"  build_dir = {root}\n"
            f"  release = {release}"
        )
        return "\n".join(lines)

    stamp = PrevailStamp(stem, root)
    rv = mode_dir(root, stem, "rv32")
    mcu_o = rv / f"{stem}_rv32.o"
    mcu_dep = rv / f"{stem}_rv32.d"
    debug = rv / f"{stem}_rv32.debug.elf"
    image = rv / f"{stem}_rv32.bin"
    body = rv / ".stage" / "body.toml"
    rv_report = report_path(root, stem, "rv32")
    mem = backend.mem
    content = " --no-content" if plan.release else ""
    lines.append(
        f"build {stamp.path}: prevail {bpf_o} | {prevail_bin()} {scripts} || {bpf_report}\n"
        f"  build_dir = {root}\n"
        f"  program = {stem}"
    )
    lines.append(mcu_cc_edge(src, mcu_o, stamp, mcu_dep))
    lines.append(f"build {debug}: link {mcu_o} | {backend.linker}")
    lines.append(f"build {image}: bin {debug}")
    lines.append(
        f"build {body}: report {debug} | {bpf_report} {scripts}\n"
        f"  src = {src}\n"
        f"  report_flags = --body-only --maps-from {bpf_report} --merge-aot-addrs{content}"
    )
    image_name = compact_name(plan, stem)
    container_arg = ""
    aot_container: Path | None = None
    if backend.compact_elf:
        aot_container = spec_path(root, stem, "rv32", "xpost_container")
        container_arg = f"--container {aot_container}"
        lines.append(
            f"build {aot_container}: pack {image} | "
            f"{backend.tool_bin} {bpf_report} {body}\n"
            f"  image = {image}\n"
            f"  bpf_toml = {bpf_report}\n"
            f"  addr_toml = {body}\n"
            f"  name = {image_name}\n"
            f"  slot = {mem.slot_addr:#x}\n"
            f"  helper = {mem.helper_addr:#x}\n"
            f"  machine = {XPOST_ESP32_C3_ARCH}\n"
            f"  engine_flags = {engine_flags('aot', bpf_o)}\n"
            f"  export_flags = \n"
            f"  out_file = {aot_container}"
        )
    commit_inputs = f"{mcu_o} {debug} {image} {body}"
    if aot_container is not None:
        commit_inputs = f"{commit_inputs} {aot_container}"
    slot_symbol = backend.slot_symbol or ""
    lines.append(
        f"build {rv_report}: commit_rv32 {commit_inputs} | "
        f"{stamp.path} {bpf_o} {backend.linker} {backend.firmware} {scripts}\n"
        f"  program = {stem}\n"
        f"  src = {src}\n"
        f"  build_dir = {root}\n"
        f"  object = {mcu_o}\n"
        f"  debug = {debug}\n"
        f"  image = {image}\n"
        f"  body = {body}\n"
        f"  container_arg = {container_arg}\n"
        f"  bpf_object = {bpf_o}\n"
        f"  stamp = {stamp.path}\n"
        f"  linker = {backend.linker}\n"
        f"  firmware = {backend.firmware}\n"
        f"  release = {release}\n"
        f"  engine = aot\n"
        f"  image_arg = {('--image-name ' + image_name) if backend.image_name else ''}\n"
        f"  slot_arg = {('--slot-symbol ' + slot_symbol) if slot_symbol else ''}\n"
        f"  headers = {mcu_dep}\n"
        f"  helper = {mem.helper_addr:#x}\n"
        f"  slot = {mem.slot_addr:#x}\n"
        f"  slot_len = {mem.slot_len:#x}\n"
        f"  table = {mem.table_addr:#x}\n"
        f"  table_len = {mem.table_len:#x}"
    )
    if backend.engine == "rbpf":
        xdir = mode_dir(root, stem, "bpf-xpost")
        section = xdir / ".stage" / "section.bin"
        patched = spec_path(root, stem, "bpf-xpost", "image")
        pack_out = spec_path(root, stem, "bpf-xpost", "xpost_container")
        lines.append(
            f"build {section}: section {bpf_o} | {MAKE_DIR / 'xdp_section.py'} {MAKE_DIR / 'llvm_tools.py'}\n"
            f"  obj = {bpf_o}\n"
            f"  sec_out = {section}"
        )
        lines.append(
            f"build {pack_out} {patched}: pack {section} | "
            f"{backend.tool_bin} {bpf_report} {rv_report}\n"
            f"  image = {section}\n"
            f"  bpf_toml = {bpf_report}\n"
            f"  addr_toml = {rv_report}\n"
            f"  name = {image_name}\n"
            f"  slot = {mem.slot_addr:#x}\n"
            f"  helper = {mem.helper_addr:#x}\n"
            f"  machine = {XPOST_ESP32_C3_ARCH}\n"
            f"  engine_flags = {engine_flags('rbpf', bpf_o)}\n"
            f"  export_flags = --export-image {patched}\n"
            f"  out_file = {pack_out}"
        )
        xreport = report_path(root, stem, "bpf-xpost")
        patched = spec_path(root, stem, "bpf-xpost", "image")
        lines.append(
            f"build {xreport}: commit_xpost {patched} {pack_out} | "
            f"{rv_report} {bpf_o} {stamp.path} {scripts}\n"
            f"  program = {stem}\n"
            f"  src = {src}\n"
            f"  build_dir = {root}\n"
            f"  image = {patched}\n"
            f"  container = {pack_out}\n"
            f"  bpf_object = {bpf_o}\n"
            f"  addr_report = {rv_report}\n"
            f"  stamp = {stamp.path}\n"
            f"  firmware = {backend.firmware}\n"
            f"  release = {release}\n"
            f"  image_arg = {('--image-name ' + image_name) if backend.image_name else ''}\n"
            f"  helper = {mem.helper_addr:#x}\n"
            f"  slot = {mem.slot_addr:#x}\n"
            f"  slot_len = {mem.slot_len:#x}\n"
            f"  table = {mem.table_addr:#x}\n"
            f"  table_len = {mem.table_len:#x}"
        )
    return "\n".join(lines)


def _tool_inputs() -> list[Path]:
    paths = [
        TOOLS_MANIFEST,
        XPOST_ELF_MANIFEST,
        ROOT / "jit" / "Cargo.toml",
    ]
    paths.extend(sorted((TOOLS_DIR / "src").glob("*.rs")))
    paths.extend(sorted((ROOT / "jit" / "src").glob("*.rs")))
    return [path for path in paths if path.is_file()]


def engine_flags(engine: str, bpf_o: Path) -> str:
    """Extra `pack` arguments for one engine.

    A bytecode image needs its map references turned into indices. The map
    identity lives in the object's relocation table, not in the bytes, so the
    object is passed along; without it `pack` cannot tell which `lddw` refers to
    which map and refuses rather than guessing.
    """
    if engine == "rbpf":
        return f"--map-index --obj {bpf_o}"
    return ""


def write_build_ninja(plan: GraphPlan) -> Path:
    """Fill make/ninja/graph.ninja into <build>/.ninja/build.ninja."""
    backend = plan.backend
    if isinstance(backend, (McuLink, JitLink)) and not prevail_bin().is_file():
        error(f"PREVAIL binary missing: {prevail_bin()}")
        sys.exit(1)

    template = NINJA_DIR / "graph.ninja"
    if not template.is_file():
        error(f"ninja 模板不可用: {template}")
        sys.exit(1)

    ninja_dir = plan.build_dir / ".ninja"
    ninja_dir.mkdir(parents=True, exist_ok=True)
    ninja_file = ninja_dir / "build.ninja"

    edges: list[str] = []
    defaults: list[Path] = []
    needs_tool = isinstance(backend, JitLink) or (
        isinstance(backend, McuLink) and backend.compact_elf
    )
    if needs_tool:
        tool_deps = " ".join(str(path) for path in _tool_inputs())
        edges.append(f"build {backend.tool_bin}: tool | {tool_deps}")
    for src in plan.sources:
        edges.append(edges_for_stem(src, plan))
        defaults.extend(_defaults_for_stem(src, plan))

    linker = backend.linker if isinstance(backend, McuLink) else None
    tool_bin = backend.tool_bin if isinstance(backend, (McuLink, JitLink)) else tool_bin_path()
    content = template.read_text()
    content = content.replace("@ROOT@", str(ROOT))
    content = content.replace("@CLANG@", CLANG)
    content = content.replace("@PYTHON@", sys.executable)
    content = content.replace("@MAKE@", str(MAKE_DIR))
    content = content.replace("@OBJDUMP@", plan.objdump)
    content = content.replace("@OBJCOPY@", DEFAULT_OBJCOPY)
    content = content.replace("@LINKER@", str(linker) if linker is not None else "")
    content = content.replace("@TOOLS_MANIFEST@", str(TOOLS_MANIFEST))
    content = content.replace("@TOOLS_TARGET@", str(TOOLS_TARGET))
    content = content.replace("@HOST_TRIPLE@", _host_triple())
    content = content.replace("@TOOL_BIN@", str(tool_bin))
    content = content.replace("@EDGES@", "\n".join(edges))
    content = content.replace("@DEFAULT@", " ".join(str(path) for path in defaults))
    ninja_file.write_text(content)

    info(f"已生成 ninja: {ninja_file}")
    if linker is not None:
        info(f"linker: {linker}")
    return ninja_file


def run_ninja(ninja_file, force=False, build_dir: Path = DEFAULT_BUILD_DIR):
    build_dir.mkdir(parents=True, exist_ok=True)
    if force:
        info("强制重建: ninja -t clean")
        clean = subprocess.run(
            ["ninja", "-f", str(ninja_file), "-t", "clean"],
            cwd=build_dir,
        )
        if clean.returncode != 0:
            error(f"ninja clean 失败: exit={clean.returncode}")
            sys.exit(clean.returncode)

    info(f"运行 ninja: {ninja_file}")
    result = subprocess.run(
        ["ninja", "-f", str(ninja_file)], cwd=build_dir
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
