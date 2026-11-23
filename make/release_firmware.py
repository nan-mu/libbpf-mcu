"""Build the pinned XPOST carriers for the formal deployment matrix."""

from __future__ import annotations

import os
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
from pathlib import Path

from layout import MODES, ROOT, LayoutError, sha256_file, write_if_changed

XPOST_REV = "b5a44072ed57657c7482758412cccf1fd93df6fa"
TARGET = "riscv32imc-unknown-none-elf"

# Required independently of the sources or mode rows produced by a build.
CARRIERS = {
    "firewall-cag": ("firewall",),
    "just-drop-cag": ("just_drop",),
    "just-tx-cag": ("just_tx",),
    "exec-bench-aot": ("noop", "prime", "log2", "copy", "fletcher32", "bsort", "strcmp"),
    "case-cag": ("case_swap", "case_mark"),
}
PROGRAMS = tuple(sorted(program for names in CARRIERS.values() for program in names))


def firmware_profile(native_profile: str, mode: str) -> str:
    if native_profile == "exec-bench-aot" and mode == "ebpf":
        return "exec-bench-rbpf"
    return native_profile


def _snapshot(work: Path) -> Path:
    source = Path(os.environ.get("LIBBPF_MCU_XPOST", ROOT.parent / "xpost")).expanduser()
    snapshot = work / "xpost"
    if snapshot.is_dir():
        return snapshot
    with tempfile.TemporaryDirectory(dir=work) as temp:
        stage = Path(temp)
        archive = stage / "source.tar"
        with archive.open("wb") as stream:
            result = subprocess.run(
                ["git", "-C", source, "archive", XPOST_REV], stdout=stream
            )
        if result.returncode:
            raise LayoutError(f"cannot read XPOST {XPOST_REV} from {source}")
        unpacked = stage / "xpost"
        with tarfile.open(archive) as tar:
            tar.extractall(unpacked, filter="data")
        unpacked.rename(snapshot)
    return snapshot


def prepare_firmware(root: Path) -> tuple[dict, Path]:
    """Return each program/mode firmware and the matching host-tool manifest."""
    work = root / ".ninja" / f"xpost-{XPOST_REV}"
    work.mkdir(parents=True, exist_ok=True)
    snapshot = _snapshot(work)
    profiles = {
        item["name"]: item
        for item in tomllib.loads((snapshot / "profiles.toml").read_text())["fw"]
    }
    toolchain = subprocess.check_output(["rustc", "-Vv"], cwd=snapshot, text=True).strip()
    out = work / "firmware"
    out.mkdir(exist_ok=True)
    built = {}
    deployments = {}
    for profile_name, programs in CARRIERS.items():
        for mode in MODES:
            interp = mode == "ebpf"
            key = firmware_profile(profile_name, mode)
            profile = profiles[key]
            directory = snapshot / profile["build"]["cwd"]
            command = [*profile["build"]["command"], "--locked"]
            features = []
            if key == "case-cag":
                # The pinned ingress calls AggregateSet::now_ticks even when
                # the case profile leaves the performance module disabled.
                features.append("xpost/perf-aggregate")
            if interp and key != "exec-bench-rbpf":
                features.append("xpost/interp")
            if features:
                command.extend(["--features", ",".join(features)])
            # just_tx and just_drop share the same build command and carrier.
            identity = (directory, tuple(command))
            if identity not in built:
                target_dir = work / "cargo"
                env = dict(os.environ, CARGO_TARGET_DIR=str(target_dir))
                result = subprocess.run(command, cwd=directory, env=env)
                if result.returncode:
                    raise LayoutError(f"{', '.join(programs)}/{mode}: XPOST {key} build failed")
                binary = Path(profile["artifact"]).name
                firmware = out / f"{binary}-{'interp' if interp else 'native'}.elf"
                write_if_changed(firmware, (target_dir / TARGET / "release" / binary).read_bytes())
                metadata = tomllib.loads((directory / "Cargo.toml").read_text())
                cold_capacity = metadata["package"]["metadata"]["xpost"]["xdp_table"]["image_capacity"]
                built[identity] = firmware, {
                    "revision": XPOST_REV,
                    "sha256": sha256_file(firmware),
                    "rustc": toolchain,
                    "cwd": profile["build"]["cwd"],
                    "argv": command,
                    "cold_capacity": cold_capacity,
                }
            for program in programs:
                # The profile name records the experiment identity even when
                # more than one experiment shares the compiled carrier.
                firmware, facts = built[identity]
                deployments[program, mode] = firmware, dict(facts, profile=key)

    # Cargo's path dependency on ../xpost resolves inside this pinned snapshot.
    producer = work / "libbpf-mcu"
    for crate in ("tools", "jit"):
        path = producer / crate
        path.mkdir(parents=True, exist_ok=True)
        for manifest in ("Cargo.toml", "Cargo.lock"):
            write_if_changed(path / manifest, (ROOT / crate / manifest).read_bytes())
        src = path / "src"
        if not src.is_symlink():
            src.symlink_to(ROOT / crate / "src", target_is_directory=True)
    return deployments, producer / "tools" / "Cargo.toml"
