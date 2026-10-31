import argparse
import os
import sys
from pathlib import Path

from tiny_log import debug, error, info, set_scope

from build import (
    DEFAULT_OBJCOPY,
    DEFAULT_OBJDUMP,
    BuildPaths,
    GraphPlan,
    McuLink,
    _linker_script,
    check_build_args,
    check_build_fs,
    clean_build,
    ensure_tool,
    apply_slot_symbol,
    load_mem_map_from_firmware,
    run_ninja,
    tool_bin_path,
    write_build_ninja,
)


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
        help="构建目标；省略则先 bpf 再 esp32c3（需 --firmware）",
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
        "--release",
        action="store_true",
        help="发布模式：对象报告不写入节内容",
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
        help="ESP32-C3: do not emit the parallel <stem>.elf Compact ELF container",
    )
    build_parser.add_argument(
        "--slot-symbol",
        default=None,
        help="firmware ELF symbol; its address and size replace XPM1 slot_addr/slot_len",
    )

    subparsers.add_parser("clean")
    subparsers.add_parser("test")

    args = parser.parse_args()
    if args.command == "build":
        target = args.target
        if args.firmware is not None and target is not None and target.lower() == "bpf":
            # Explicit bpf ignores firmware addresses.
            pass
        elif args.firmware is not None and target is not None and target.lower() != "esp32c3":
            print(
                f"error: --firmware 仅用于 bpf/esp32c3 全量或 esp32c3，不能与 target={target} 一起用",
                file=sys.stderr,
            )
            sys.exit(2)
        # With --firmware and no target: one graph that includes esp32c3.
        builds = check_build_args(target, args.inputs, args.outputs, crate=args.crate)
        checked = check_build_fs(BuildPaths(builds[0].inputs, builds[0].outputs))
        want_mcu = any(item.target == "esp32c3" for item in builds)
        mcu = None
        if want_mcu:
            if args.firmware is None:
                error("esp32c3 需要 --firmware <firmware.elf>（含 .xpost.mem / XPM1）")
                sys.exit(1)
            tool = ensure_tool(force=args.force)
            mem = load_mem_map_from_firmware(Path(args.firmware), tool)
            if args.slot_symbol:
                mem = apply_slot_symbol(mem, Path(args.firmware), tool, args.slot_symbol)
            info(
                f"XPM1 helper={mem.helper_addr:#x} slot={mem.slot_addr:#x}+{mem.slot_len:#x} "
                f"table={mem.table_addr:#x}+{mem.table_len:#x}"
            )
            linker = _linker_script("esp32c3", mem)
            assert linker is not None
            mcu = McuLink(
                mem=mem,
                linker=linker,
                tool_bin=tool_bin_path(),
                compact_elf=not args.no_compact_elf,
            )
        names = ", ".join(item.target for item in builds)
        info(f"编译目标 [{names}]")
        if os.environ.get("DEBUG") == "1":
            debug(f"输入文件: {[str(path) for path in checked.inputs]}")
        plan = GraphPlan(
            sources=tuple(checked.inputs),
            mcu=mcu,
            release=args.release,
            objdump=args.objdump,
        )
        run_ninja(write_build_ninja(plan), force=args.force)
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
        ]
        for cmd in tests:
            info(f"→ {' '.join(cmd)}")
            result = subprocess.run(cmd, cwd=str(Path(__file__).parent))
            if result.returncode != 0:
                sys.exit(result.returncode)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
