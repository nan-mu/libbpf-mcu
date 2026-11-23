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
from layout import LayoutError


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

    build_parser = subparsers.add_parser("build")
    build_parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="构建目标。默认 esp32c3（需 --firmware）。可显式选 bpf 或 jit",
    )
    build_parser.add_argument("--inputs", "-i")
    build_parser.add_argument("--output", "--outputs", "-o", dest="outputs")
    build_parser.add_argument(
        "-c",
        "--crate",
        dest="crate",
        default=None,
        help="只编译 tests/**/<stem>.c 中 stem 匹配的一个源文件",
    )
    build_parser.add_argument(
        "-f", "--force", action="store_true", help="强制重新编译，忽略增量"
    )
    build_parser.add_argument(
        "--objdump",
        default=os.environ.get("LIBBPF_MCU_OBJDUMP", DEFAULT_OBJDUMP),
        help=f"objdump 可执行文件（默认 {DEFAULT_OBJDUMP}）",
    )
    build_parser.add_argument(
        "--objcopy",
        default=os.environ.get("LIBBPF_MCU_OBJCOPY", DEFAULT_OBJCOPY),
        help=f"objcopy 可执行文件（默认 {DEFAULT_OBJCOPY}）",
    )
    build_parser.add_argument(
        "--firmware",
        type=Path,
        default=None,
        help="已链接固件 ELF（须含 .xpost.mem / XPM1）；esp32c3 必填",
    )
    build_parser.add_argument(
        "--no-compact-elf",
        action="store_true",
        help="ESP32-C3: do not emit the <program>-vm-aot.elf Compact ELF container",
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
        default="aot",
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
        help="输出根目录，含 build.ninja。省略则用默认 build/",
    )

    subparsers.add_parser("clean")
    subparsers.add_parser("test")
    artifacts = subparsers.add_parser("artifacts")
    artifact_commands = artifacts.add_subparsers(
        dest="artifacts_command", required=True
    )
    export = artifact_commands.add_parser("export-legacy")
    export.add_argument("--build-dir", type=Path, required=True)
    export.add_argument("--out", type=Path, required=True)
    export.add_argument("--mode", required=True, choices=("rv32", "jit", "bpf-xpost"))

    args = parser.parse_args()
    if args.command == "build":
        target = args.target.lower() if args.target else "esp32c3"
        if target not in ("bpf", "esp32c3", "jit"):
            build_parser.error(f"unknown target: {target}")
        if args.outputs is not None:
            build_parser.error(
                "--output is no longer supported; use --build-dir or artifacts export-legacy"
            )
        if target == "jit" and (args.no_compact_elf or args.engine != "aot"):
            build_parser.error(
                "jit requires a Compact ELF and is incompatible with --engine rbpf"
            )
        if target != "bpf" and args.firmware is None:
            build_parser.error(f"{target} requires --firmware")
        args.image_name = check_image_name(args.image_name)
        args.objdump = shutil.which(args.objdump) or args.objdump
        args.objcopy = shutil.which(args.objcopy) or args.objcopy
        mode = {
            "bpf": "bpf",
            "jit": "jit",
            "esp32c3": "ebpf" if args.engine == "rbpf" else "llvm-aot",
        }[target]
        root = (
            args.build_dir.expanduser().resolve()
            if args.build_dir
            else DEFAULT_BUILD_DIR
        )
        try:
            build(root, resolve_sources(args.inputs, args.crate), mode, args)
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
            [
                sys.executable,
                str(Path(__file__).parent.parent / "scripts" / "test_package.py"),
            ],
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
    elif args.command == "artifacts" and args.artifacts_command == "export-legacy":
        from layout import export_legacy

        try:
            programs = export_legacy(args.build_dir, args.out, args.mode)
        except LayoutError as exc:
            error(str(exc))
            sys.exit(2)
        info("exported " + ", ".join(programs))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
