import argparse
import os
import sys

from tiny_log import debug, info, set_scope

from build import (
    DEFAULT_OBJCOPY,
    DEFAULT_OBJDUMP,
    BuildPaths,
    BuildTarget,
    build_target,
    check_build_args,
    check_build_fs,
    clean_build,
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
        help="构建目标；省略则构建全部 target",
    )
    build_parser.add_argument("--inputs", "-i")
    build_parser.add_argument("--output", "--outputs", "-o", dest="outputs")
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
        "--slot",
        default="0",
        help="MCU hot-slot index: 0..N-1 from xpost/examples/firmware/mem.toml "
        "(aliases: a=0, b=1)",
    )

    subparsers.add_parser("clean")
    subparsers.add_parser("test")

    args = parser.parse_args()
    if args.command == "build":
        builds = check_build_args(args.target, args.inputs, args.outputs)
        for build in builds:
            paths = check_build_fs(BuildPaths(build.inputs, build.outputs))
            build = BuildTarget(build.target, paths.inputs, paths.outputs)
            info(f"编译目标 [{build.target}]")
            debug(f"输入文件: {[str(path) for path in build.inputs]}")
            debug(f"输出文件: {[str(path) for path in build.outputs]}")
            build_target(
                build,
                force=args.force,
                release=args.release,
                objdump=args.objdump,
                objcopy=args.objcopy,
                slot=args.slot if build.target == "esp32c3" else None,
            )
    elif args.command == "clean":
        clean_build()
    elif args.command == "test":
        info("运行测试")


if __name__ == "__main__":
    main()
