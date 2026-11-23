"""Private build inputs and receipts. The program index can be used without them."""

from __future__ import annotations

import json
import os
from functools import cache
from pathlib import Path

from layout import (
    MODES,
    ROOT,
    LayoutError,
    bpf_path,
    container_path,
    make_index,
    report_path,
    sha256_file,
    source_path,
    state_path,
    write_if_changed,
    write_index,
)
from obj_report import (
    BPF,
    RISCV,
    CodeSection,
    disassemble_payload,
    executable_sections,
    format_disasm,
    write_report,
)
from xpost_elf import parse_container

PRIVATE_MODES = ("bpf", "prevail", "llvm-aot", "ebpf-native", "ebpf", "jit")


def parse_depfile(text: str) -> list[str]:
    text = text.replace("\\\n", " ")
    _target, separator, rest = text.partition(":")
    if not separator:
        raise LayoutError("invalid Clang depfile")
    paths, current = [], []
    escaped = False
    for char in rest:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char.isspace():
            if current:
                paths.append("".join(current))
                current.clear()
        else:
            current.append(char)
    if current:
        paths.append("".join(current))
    return paths


@cache
def _digest(path: Path, identity: tuple) -> str:
    return sha256_file(path)


def _fingerprint(path: Path) -> str:
    stat = path.stat()
    return _digest(
        path,
        (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns),
    )


def fingerprints(paths) -> dict[str, str]:
    return {str(path): _fingerprint(Path(path)) for path in paths}


def record(
    path: Path, *, inputs=(), outputs=(), upstream=(), generation=(), **facts
) -> None:
    state = dict(
        inputs=fingerprints([*inputs, *upstream]),
        outputs=fingerprints(outputs),
        upstream=list(map(str, upstream)),
        generation=generation,
        **facts,
    )
    write_if_changed(path, json.dumps(state, sort_keys=True).encode())


def read_state(path: Path) -> dict:
    return json.loads(path.read_bytes())


def verify_state(path: Path, checked: dict[Path, str | None]) -> str | None:
    if path in checked:
        return checked[path]
    if not path.is_file():
        return "no successful build"
    # Mark before recursion, so a corrupt private state cannot form a cycle.
    checked[path] = "cyclic build state"
    try:
        state = read_state(path)
        for group in ("inputs", "outputs"):
            for filename, digest in state[group].items():
                candidate = Path(filename)
                if not candidate.is_file() or _fingerprint(candidate) != digest:
                    checked[path] = f"{group}: {filename} changed or is missing"
                    return checked[path]
        for upstream in state["upstream"]:
            if reason := verify_state(Path(upstream), checked):
                checked[path] = reason
                return reason
        checked[path] = None
    except (OSError, KeyError, TypeError, ValueError) as exc:
        checked[path] = str(exc)
    return checked[path]


def reconcile(
    root: Path,
    program: str,
    hidden: tuple[str, ...] = (),
    failure: str = "",
    attempted: tuple[str, ...] = (),
) -> dict:
    """Update selection from current bytes, leaving diagnostics in the work directory."""
    states = {mode: state_path(root, program, mode) for mode in PRIVATE_MODES}
    checked: dict[Path, str | None] = {}
    reasons = {
        mode: reason
        for mode, path in states.items()
        if (reason := verify_state(path, checked)) is not None
    }
    index_path = root / program / "index.toml"
    if "bpf" in reasons or "bpf" in hidden:
        index_path.unlink(missing_ok=True)
        modes = ()
    else:
        modes = tuple(
            mode
            for mode in MODES
            if mode not in reasons
            and mode not in hidden
            and str(container_path(root, program, mode))
            in read_state(states[mode])["outputs"]
        )
        write_index(index_path, make_index(index_path.parent, program, modes))
    diagnostics = states["bpf"].parent.parent / "diagnostics.json"
    old = read_state(diagnostics) if diagnostics.is_file() else {}
    for mode, reason in reasons.items():
        if states[mode].is_file() or (failure and mode in attempted):
            old[mode] = failure if reason == "no successful build" else reason
    for mode in states.keys() - reasons.keys():
        old.pop(mode, None)
    if old:
        write_if_changed(diagnostics, (json.dumps(old, indent=2) + "\n").encode())
    else:
        diagnostics.unlink(missing_ok=True)
    return reasons


def render_reports(root: Path, program: str, *, force: bool = False) -> None:
    checked: dict[Path, str | None] = {}
    state_file = state_path(root, program, "bpf")
    if verify_state(state_file, checked):
        return
    bpf = read_state(state_file)
    obj = bpf_path(root, program)
    snapshot = source_path(root, program).read_bytes()
    for mode in ("bpf", *MODES):
        path = state_path(root, program, mode)
        if verify_state(path, checked):
            continue
        report = report_path(root, program, mode)
        if (
            not force
            and report.is_file()
            and report.stat().st_mtime_ns >= path.stat().st_mtime_ns
        ):
            continue
        state = read_state(path)
        objdump = state["objdump"]
        generation = list(bpf["generation"])
        if mode == "bpf":
            listing = "".join(
                format_disasm(objdump, obj, code, bpf=True)
                for code in executable_sections(obj.read_bytes())
            )
        else:
            container = container_path(root, program, mode)
            if str(container) in state["outputs"]:
                meta, image = parse_container(container.read_bytes())
                slot = meta.slot_address
            else:
                image = Path(state["image"]).read_bytes()
                slot = state["slot"]
            if mode == "llvm-aot":
                sections = executable_sections(Path(state["linked_elf"]).read_bytes())
                for code in sections:
                    offset = code.address - slot
                    if (
                        offset < 0
                        or image[offset : offset + len(code.data)] != code.data
                    ):
                        raise LayoutError(
                            f"{program}/{mode}: {code.name} differs from final payload"
                        )
                listing = "".join(
                    format_disasm(
                        objdump,
                        Path(state["linked_elf"]),
                        code,
                        bpf=False,
                        compressed=True,
                    )
                    for code in sections
                )
            elif mode == "ebpf":
                listing = disassemble_payload(
                    objdump, CodeSection(state["section"], 0, image), BPF
                )
                generation.extend(
                    read_state(state_path(root, program, "ebpf-native"))["generation"]
                )
            else:
                if not 0 < state["code_len"] <= len(image):
                    raise LayoutError(f"{program}/{mode}: invalid JIT code extent")
                listing = disassemble_payload(
                    objdump,
                    CodeSection(".text", slot, image[: state["code_len"]]),
                    RISCV,
                )
            generation.extend(state["generation"])
        if not listing:
            raise LayoutError(f"{program}/{mode}: empty code listing")
        write_report(
            report, os.path.relpath(bpf["source"], ROOT), snapshot, listing, generation
        )
