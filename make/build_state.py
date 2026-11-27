"""Private build inputs and receipts. The program index can be used without them."""

from __future__ import annotations

import json
import os
import re
from functools import cache
from pathlib import Path

from layout import (
    MODES,
    ROOT,
    LayoutError,
    bpf_path,
    container_path,
    make_index,
    native_object_path,
    portable_paths,
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
from native_image import read_document

PRIVATE_MODES = ("bpf", "prevail", "llvm-aot", "ebpf-native", "ebpf", "jit")


def parse_depfile(text: str) -> list[str]:
    text = text.replace("\\\n", " ")
    separator = re.search(r":(?=\s|$)", text)
    if separator is None:
        raise LayoutError("invalid Clang depfile")
    rest = text[separator.end() :]
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
    except (OSError, AttributeError, KeyError, TypeError, ValueError) as exc:
        checked[path] = f"invalid build state: {exc}"
    return checked[path]


def prepare_program(root: Path, program: str) -> None:
    """Retire only known v2 producer files, and keep writes inside the build root."""
    public = root / program
    private = root / ".ninja" / program
    for directory in (
        public,
        private,
        public / "objects",
        public / "containers",
        public / "images",
        *(private / mode for mode in PRIVATE_MODES),
    ):
        if directory.is_symlink():
            raise LayoutError(f"symlink is not a build directory: {directory}")
    ownership = private / "public-layout"
    if ownership.is_symlink():
        raise LayoutError(f"symlink is not a build marker: {ownership}")
    if ownership.is_file() and ownership.read_bytes() == b"v3\n":
        return
    old_object = public / "bpf" / f"{program}_bpf.o"
    receipt = state_path(root, program, "bpf")
    v2 = receipt.is_file() and str(old_object) in read_state(receipt)["outputs"]
    index = public / "index.toml"
    reserved = [
        source_path(root, program),
        bpf_path(root, program),
        native_object_path(root, program),
        report_path(root, program),
        *(container_path(root, program, mode) for mode in MODES),
        *(path for mode in MODES for path in portable_paths(root, program, mode)),
    ]
    if not v2:
        reserved.append(index)
    for path in reserved:
        if path.exists() or path.is_symlink():
            raise LayoutError(f"existing file is not owned by this build: {path}")
    if not v2:
        write_if_changed(ownership, b"v3\n")
        return
    old_files = {
        "src": [f"{program}.c"],
        "bpf": [old_object.name, "prevail.ok", "report.toml"],
        "llvm-aot": [
            f"{program}_rv32.o",
            f"{program}_rv32.debug.elf",
            f"{program}_rv32.bin",
            f"{program}-vm-aot.elf",
            "report.toml",
        ],
        "ebpf": [f"{program}_bpf-xpost.bin", f"{program}-vm-ebpf.elf", "report.toml"],
        "jit": ["jit.bin", f"{program}-vm-jit.elf", "report.toml"],
    }
    for component, filenames in old_files.items():
        directory = public / component
        if directory.is_symlink():
            raise LayoutError(f"symlink is not a build directory: {directory}")
        if directory.is_dir():
            for filename in filenames:
                (directory / filename).unlink(missing_ok=True)
            if not any(directory.iterdir()):
                directory.rmdir()
    index.unlink(missing_ok=True)
    write_if_changed(ownership, b"v3\n")


def reconcile(
    root: Path,
    program: str,
    hidden: tuple[str, ...] = (),
) -> dict:
    """Update selection from current bytes, leaving diagnostics in the work directory."""
    states = {mode: state_path(root, program, mode) for mode in PRIVATE_MODES}
    checked: dict[Path, str | None] = {}
    reasons = {
        mode: reason
        for mode, path in states.items()
        if (reason := verify_state(path, checked)) is not None
    }
    obj, source = bpf_path(root, program), source_path(root, program)
    gate = states["prevail"]
    if "prevail" not in reasons:
        if set(read_state(gate)["outputs"]) != {str(obj), str(source)}:
            reasons["prevail"] = "verified outputs changed"
    gate_invalid = "bpf" in reasons or "prevail" in reasons
    if gate_invalid:
        obj.unlink(missing_ok=True)
        source.unlink(missing_ok=True)
    portable = set()
    for mode in MODES:
        container = container_path(root, program, mode)
        image_paths = portable_paths(root, program, mode)
        if mode not in reasons:
            state = read_state(states[mode])
            if state.get("portable"):
                portable.add(mode)
        files = list(image_paths) if mode in portable else [container]
        inactive = [container] if mode in portable else image_paths
        if mode == "llvm-aot":
            files.append(native_object_path(root, program))
        if mode not in reasons and any(str(path) not in state["outputs"] for path in files):
            reasons[mode] = "published outputs changed"
        if gate_invalid or mode in reasons:
            for path in files:
                path.unlink(missing_ok=True)
        for path in inactive:
            path.unlink(missing_ok=True)
    for directory in (root / program / "containers", root / program / "images"):
        if directory.is_dir() and not any(directory.iterdir()):
            directory.rmdir()
    index_path = root / program / "index.toml"
    report = report_path(root, program)
    if gate_invalid or "bpf" in hidden:
        index_path.unlink(missing_ok=True)
        report.unlink(missing_ok=True)
    else:
        modes = tuple(
            mode for mode in MODES if mode not in reasons and mode not in hidden
        )
        before = index_path.read_bytes() if index_path.exists() else None
        write_index(index_path, make_index(index_path.parent, program, modes, portable=portable))
        if before != index_path.read_bytes():
            report.unlink(missing_ok=True)
    return reasons


def update_diagnostic(root: Path, program: str, stage: str, reason: str | None) -> None:
    """Keep the last failure of each attempted stage until that stage succeeds."""
    path = state_path(root, program, "bpf").parent.parent / "diagnostics.json"
    diagnostics = read_state(path) if path.is_file() else {}
    if reason is None:
        diagnostics.pop(stage, None)
    else:
        diagnostics[stage] = reason
    if diagnostics:
        write_if_changed(path, (json.dumps(diagnostics, indent=2) + "\n").encode())
    else:
        path.unlink(missing_ok=True)


def render_reports(
    root: Path,
    program: str,
    *,
    force: bool = False,
    modes: tuple[str, ...] | None = None,
    destination: Path | None = None,
) -> None:
    report = destination or report_path(root, program)
    try:
        _render_reports(root, program, report, modes, force)
    except (Exception, KeyboardInterrupt):
        report.unlink(missing_ok=True)
        raise


def _render_reports(root: Path, program: str, report: Path, modes, force: bool) -> None:
    checked: dict[Path, str | None] = {}
    gate = state_path(root, program, "prevail")
    if reason := verify_state(gate, checked):
        raise LayoutError(f"{program}: unable to report unverified BPF: {reason}")
    bpf = read_state(state_path(root, program, "bpf"))
    obj = bpf_path(root, program)
    snapshot = source_path(root, program).read_bytes()
    selected = ["bpf"]
    for mode in MODES:
        if modes is not None and mode not in modes:
            continue
        reason = verify_state(state_path(root, program, mode), checked)
        if not reason:
            selected.append(mode)
        elif modes is not None:
            raise LayoutError(f"{program}/{mode}: {reason}")
    if modes is None and not force and report.is_file():
        newest = max(
            state_path(root, program, mode).stat().st_mtime_ns for mode in selected
        )
        if report.stat().st_mtime_ns >= newest:
            return
    sections = []
    for mode in selected:
        path = state_path(root, program, mode)
        state = read_state(path)
        objdump = state["objdump"]
        generation = list(bpf["generation"])
        if mode == "bpf":
            listing = "".join(
                format_disasm(objdump, obj, code, bpf=True)
                for code in executable_sections(obj.read_bytes())
            )
        elif state.get("portable"):
            image_path, layout_path = portable_paths(root, program, mode)
            image = image_path.read_bytes()
            doc = read_document(layout_path)
            listing = "".join(
                disassemble_payload(
                    objdump,
                    CodeSection(r["name"], r["offset"], image[r["offset"]:r["offset"] + r["size"]]),
                    BPF if mode == "ebpf" else RISCV,
                    compressed=mode == "llvm-aot",
                )
                for r in doc["regions"] if r["kind"] == "code"
            )
            generation.extend(state["generation"])
        else:
            container = container_path(root, program, mode)
            meta, image = parse_container(container.read_bytes())
            slot = meta.slot_address
            if mode == "llvm-aot":
                code_sections = executable_sections(
                    Path(state["linked_elf"]).read_bytes()
                )
                for code in code_sections:
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
                    for code in code_sections
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
        sections.append((mode, listing, generation))
    write_report(report, os.path.relpath(bpf["source"], ROOT), snapshot, sections)
