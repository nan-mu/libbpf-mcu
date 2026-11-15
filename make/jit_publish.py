from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from prevail_gate import ProgramRef, examine, write_stamp
from layout import finish_jit, mode_dir, retract_mode, stamp_path


@dataclass(frozen=True)
class JitDeliverables:
    jit_bin: Path
    jit_toml: Path
    container: Path
    stamp: Path

    @staticmethod
    def for_stem(build_dir: Path, stem: str, name: str) -> "JitDeliverables":
        del name
        base = mode_dir(build_dir, stem, "jit")
        return JitDeliverables(
            jit_bin=base / f"{stem}_jit.bin",
            jit_toml=base / "report.toml",
            container=base / f"{stem}_jit.elf",
            stamp=stamp_path(build_dir, stem),
        )

    def outputs(self) -> tuple[Path, Path, Path, Path]:
        return (self.jit_bin, self.jit_toml, self.container, self.stamp)

    def retract(self) -> None:
        for path in self.outputs():
            path.unlink(missing_ok=True)

    def commit(self, stage: Path, program: ProgramRef, obj: Path) -> None:
        # The stamp is written after the image files. A stamp with no image
        # would look like this build succeeded.
        if stage.name != ".jit-stage":
            _die(f"refusing to publish from {stage}")
        try:
            os_replace(stage / "jit.bin", self.jit_bin)
            os_replace(stage / "container.elf", self.container)
            write_stamp(self.stamp, obj, program)
        except Exception:
            self.retract()
            raise


def publish(
    src: Path,
    obj: Path,
    bpf_toml: Path,
    firmware: Path,
    stem: str,
    name: str,
    out_dir: Path,
    tool: Path,
    build_dir: Path,
    release: bool,
) -> None:
    deliver = JitDeliverables.for_stem(build_dir, stem, name)
    if deliver.jit_bin.parent.resolve() != out_dir.resolve():
        _die(f"deliverables for {stem} are not in {out_dir}")
    deliver.retract()
    stage = out_dir / ".jit-stage"
    try:
        program = examine(obj)
    except SystemExit:
        remove_stage(stage)
        retract_mode(build_dir, stem, "jit", "PREVAIL rejected the program")
        raise
    remove_stage(stage)
    proc = subprocess.run(
        [
            str(tool),
            "pack-jit",
            "--firmware",
            str(firmware),
            "--obj",
            str(obj),
            "--bpf-toml",
            str(bpf_toml),
            "--src",
            str(src),
            "--name",
            name,
            "--stage",
            str(stage),
        ]
    )
    if proc.returncode != 0:
        remove_stage(stage)
        retract_mode(build_dir, stem, "jit", f"pack-jit exited {proc.returncode}")
        raise SystemExit(proc.returncode)
    try:
        deliver.commit(stage, program, obj)
        finish_jit(
            build_dir,
            stem,
            src,
            obj,
            deliver.jit_bin,
            deliver.container,
            stage / "jit.toml",
            firmware,
            tool,
            release=release,
            image_name=None if name == stem else name,
        )
    except Exception:
        deliver.retract()
        retract_mode(build_dir, stem, "jit", "JIT report publish failed")
        raise
    finally:
        remove_stage(stage)


def remove_stage(stage: Path) -> None:
    if stage.name != ".jit-stage":
        _die(f"refusing to delete {stage}")
    if not stage.exists():
        return
    if stage.is_dir() and not stage.is_symlink():
        shutil.rmtree(stage)
    else:
        stage.unlink()


def os_replace(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    src.replace(dest)


def _die(message: str, code: int = 1) -> None:
    sys.stderr.write(message + "\n")
    raise SystemExit(code)


def main() -> None:
    parser = argparse.ArgumentParser(prog="jit_publish")
    parser.add_argument("--src", type=Path, required=True)
    parser.add_argument("--obj", type=Path, required=True)
    parser.add_argument("--bpf-toml", type=Path, required=True)
    parser.add_argument("--firmware", type=Path, required=True)
    parser.add_argument("--stem", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--tool", type=Path, required=True)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--release", choices=("0", "1"), default="0")
    args = parser.parse_args()
    publish(
        args.src,
        args.obj,
        args.bpf_toml,
        args.firmware,
        args.stem,
        args.name,
        args.out_dir,
        args.tool,
        args.build_dir,
        args.release == "1",
    )


if __name__ == "__main__":
    main()
