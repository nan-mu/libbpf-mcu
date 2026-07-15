"""Build orchestration for libbpf-mcu (ninja: compile + object reports)."""

from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from tiny_log import error, info, warning

MAKE_DIR = Path(__file__).resolve().parent
ROOT = MAKE_DIR.parent
WORKSPACE_ROOT = ROOT.parent
DEFAULT_BUILD_DIR = WORKSPACE_ROOT / "build"
TESTS_DIR = ROOT / "tests"
NINJA_DIR = MAKE_DIR / "ninja"
LINKER_DIR = MAKE_DIR / "linker"
CLANG = "clang"
DEFAULT_OBJDUMP = "llvm-objdump-mp-22"
DEFAULT_OBJCOPY = "llvm-objcopy-mp-22"
REPORT_SCRIPTS = (MAKE_DIR / "obj_report.py", MAKE_DIR / "btf.py")


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


def _default_inputs():
    inputs = sorted(
        path
        for path in TESTS_DIR.rglob("*.c")
        if "failed" not in path.relative_to(TESTS_DIR).parts
    )
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


def check_build_args(target, inputs, outputs):
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

    if input_items is None and output_items is not None:
        warning("不能只指定 --output/-o；默认输入会包含多个测试文件，请同时指定 --inputs/-i")
        sys.exit(1)

    if output_items is not None and len(targets) > 1:
        error("构建多个 target 时不能指定 --output/-o")
        sys.exit(1)

    raw_inputs = _default_inputs() if input_items is None else [Path(item) for item in input_items]

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


def _report_flags(target: str, release: bool) -> str:
    flags: list[str] = []
    if target == "bpf":
        flags.append("--btf")
    if release:
        flags.append("--no-content")
    return " ".join(flags)


def _linker_script(target: str) -> Path | None:
    path = LINKER_DIR / f"{target}.ld"
    return path if path.is_file() else None


def build_target(
    build,
    force=False,
    release=False,
    objdump=DEFAULT_OBJDUMP,
    objcopy=DEFAULT_OBJCOPY,
):
    template = NINJA_DIR / f"{build.target}.ninja"
    if not template.is_file():
        error(f"ninja 模板不可用: {template}")
        sys.exit(1)

    linker = _linker_script(build.target)
    ninja_dir = DEFAULT_BUILD_DIR / ".ninja"
    ninja_dir.mkdir(parents=True, exist_ok=True)
    ninja_file = ninja_dir / "build.ninja"

    implicit = " ".join(str(path) for path in REPORT_SCRIPTS)
    edges: list[str] = []
    defaults: list[Path] = []
    for input_path, output_path in zip(build.inputs, build.outputs):
        depfile = output_path.with_suffix(".d")
        edges.append(
            f"build {output_path}: cc {input_path}\n"
            f"  depfile = {depfile}"
        )

        if linker is not None:
            elf_path = output_path.with_suffix(".elf")
            bin_path = output_path.with_suffix(".bin")
            report_path = output_path.with_suffix(".toml")
            report_obj = elf_path
            edges.append(
                f"build {elf_path}: link {output_path} | {linker}"
            )
            edges.append(f"build {bin_path}: bin {elf_path}")
            defaults.append(bin_path)
            defaults.append(report_path)
        else:
            report_path = output_path.with_suffix(".toml")
            report_obj = output_path
            defaults.append(report_path)

        edges.append(
            f"build {report_path}: report {report_obj} | {implicit}\n"
            f"  src = {input_path}"
        )

    content = template.read_text()
    content = content.replace("@ROOT@", str(ROOT))
    content = content.replace("@CLANG@", CLANG)
    content = content.replace("@PYTHON@", sys.executable)
    content = content.replace("@MAKE@", str(MAKE_DIR))
    content = content.replace("@OBJDUMP@", objdump)
    content = content.replace("@OBJCOPY@", objcopy)
    content = content.replace(
        "@LINKER@", str(linker) if linker is not None else ""
    )
    content = content.replace("@REPORT_FLAGS@", _report_flags(build.target, release))
    content = content.replace("@EDGES@", "\n".join(edges))
    content = content.replace("@DEFAULT@", " ".join(str(path) for path in defaults))
    ninja_file.write_text(content)

    info(f"已生成 ninja: {ninja_file}")
    run_ninja(ninja_file, force=force)


def run_ninja(ninja_file, force=False):
    if force:
        info(f"强制重建: ninja -t clean")
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
