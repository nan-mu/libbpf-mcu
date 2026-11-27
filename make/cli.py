import argparse
import os
import shutil
import sys
from pathlib import Path

from tiny_log import debug, error, info, set_scope

from build import (
    DEFAULT_BUILD_DIR,
    DEFAULT_OBJCOPY,
    DEFAULT_OBJDUMP,
    build,
    clean_build,
    resolve_sources,
)
from layout import ROOT, LayoutError


def check_image_name(name: str | None) -> str | None:
    if name is None:
        return None
    if (
        not name
        or any(ch in name for ch in "/\\.")
        or not all(ch.isalnum() or ch == "_" for ch in name)
    ):
        error(f"--image-name must be a single identifier, got {name!r}")
        sys.exit(2)
    return name


@set_scope("libbpf-mcu")
def main():
    if os.environ.get("DEBUG") == "1":
        debug(f"调用参数: {sys.argv}")

    parser = argparse.ArgumentParser(prog="libbpf-mcu")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser = subparsers.add_parser("build", allow_abbrev=False)
    build_parser.add_argument(
        "target",
        nargs="?",
        choices=("bpf", "rv32imc", "jit"),
        help="无程序或目标选项时构建发布矩阵；指定程序时默认 bpf；传入 --firmware 时默认 rv32imc。",
    )
    inputs = build_parser.add_mutually_exclusive_group()
    inputs.add_argument("--inputs", nargs="+", metavar="FILE", help="一个或多个 C 源文件")
    inputs.add_argument(
        "-c",
        "--crate",
        dest="crate",
        default=None,
        help="只编译 tests/**/<stem>.c 中 stem 匹配的一个源文件",
    )
    build_parser.add_argument(
        "--force", action="store_true", help="强制重新编译，忽略增量"
    )
    build_parser.add_argument(
        "--firmware",
        type=Path,
        default=None,
        help="已链接固件 ELF（须含 .xpost.mem / XPM1）；rv32imc、jit 必填",
    )
    build_parser.add_argument(
        "--slot-symbol",
        default=None,
        help="firmware ELF symbol; its address and size replace XPM1 slot_addr/slot_len",
    )
    build_parser.add_argument(
        "--image-name",
        default=None,
        help="Internal Compact ELF name. The output filename follows the program and mode.",
    )
    build_parser.add_argument(
        "--engine",
        choices=["aot", "rbpf"],
        default=None,
        help=(
            "what the container carries. aot: the linked RV32IMC machine code. "
            "rbpf: the eBPF bytecode, with each map reference rewritten to the "
            "map index so the interpreter can resolve it at load"
        ),
    )
    build_parser.add_argument(
        "--build-dir",
        type=Path,
        default=None,
        help="输出根目录，默认为 build/",
    )

    subparsers.add_parser("clean")
    subparsers.add_parser("test")
    args = parser.parse_args()
    if args.command == "build":
        full = not any(
            (
                args.target, args.inputs, args.crate, args.firmware,
                args.engine, args.slot_symbol, args.image_name,
            )
        )
        target = args.target or ("rv32imc" if args.firmware is not None else "bpf")
        if target != "rv32imc" and args.engine is not None:
            build_parser.error("--engine is only available for rv32imc")
        if target == "bpf" and any((args.firmware, args.slot_symbol, args.image_name)):
            build_parser.error("--firmware, --slot-symbol and --image-name require rv32imc or jit")
        if target != "bpf" and args.firmware is None:
            build_parser.error(f"{target} requires --firmware")
        args.image_name = check_image_name(args.image_name)
        objdump = os.environ.get("LIBBPF_MCU_OBJDUMP", DEFAULT_OBJDUMP)
        objcopy = os.environ.get("LIBBPF_MCU_OBJCOPY", DEFAULT_OBJCOPY)
        args.objdump = shutil.which(objdump) or objdump
        args.objcopy = shutil.which(objcopy) or objcopy
        mode = {
            "bpf": "bpf",
            "jit": "jit",
            "rv32imc": "ebpf" if args.engine == "rbpf" else "llvm-aot",
        }[target]
        root = (
            args.build_dir.expanduser().resolve()
            if args.build_dir
            else DEFAULT_BUILD_DIR
        )
        try:
            if full:
                from release import PROGRAMS

                sources = resolve_sources(
                    [str(ROOT / "tests" / "xdp" / f"{name}.c") for name in PROGRAMS],
                    None,
                )
            else:
                sources = resolve_sources(args.inputs, args.crate)
            build(root, sources, None if full else mode, args)
        except (OSError, LayoutError) as exc:
            error(str(exc))
            sys.exit(1)
    elif args.command == "clean":
        clean_build()
    elif args.command == "test":
        info("运行测试")
        import subprocess

        tests = [
            [sys.executable, str(Path(__file__).parent / "test_btf_layout.py")],
            [sys.executable, str(Path(__file__).parent / "test_prevail_select.py")],
            [sys.executable, str(Path(__file__).parent / "test_prevail_negatives.py")],
            [sys.executable, str(Path(__file__).parent / "test_reentrancy_model.py")],
            [sys.executable, str(Path(__file__).parent / "test_xpost_elf.py")],
            [sys.executable, str(Path(__file__).parent / "test_xpost_mem.py")],
            [sys.executable, str(Path(__file__).parent / "test_compact_elf_parity.py")],
            [sys.executable, str(Path(__file__).parent / "test_jit_build.py")],
            [sys.executable, str(Path(__file__).parent / "test_layout.py")],
            [sys.executable, str(Path(__file__).parent / "test_release.py")],
            [sys.executable, str(Path(__file__).parent / "test_build_state.py")],
        ]
        for crate in ("jit", "tools"):
            tests.append(
                [
                    "cargo",
                    "test",
                    "--manifest-path",
                    str(Path(__file__).resolve().parent.parent / crate / "Cargo.toml"),
                ]
            )
        for cmd in tests:
            info(f"→ {' '.join(cmd)}")
            result = subprocess.run(cmd, cwd=str(Path(__file__).parent))
            if result.returncode != 0:
                sys.exit(result.returncode)


if __name__ == "__main__":
    main()
