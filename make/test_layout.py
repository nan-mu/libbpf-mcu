#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import tempfile
import tomllib
import unittest
from pathlib import Path

from layout import (
    MODES,
    MODE_SPECS,
    ArtifactFile,
    BuildFacts,
    Dependency,
    InputArtifact,
    LayoutError,
    SourceRecord,
    commit_mode,
    compose_report,
    dependencies_from,
    _backend_facts,
    export_legacy,
    input_set_id,
    load_mode,
    logical_flag_block,
    parse_depfile,
    record_verification,
    report_path,
    retract_mode,
    sha256_bytes,
    sha256_file,
    spec_path,
    stamp_path,
)


def source(sha: str = "source-sha") -> SourceRecord:
    return SourceRecord(
        "https://github.com/nan-mu/libbpf-mcu",
        "c0b9faaa5dae3525a7c9a63ecfd5bf2b8716c6a0",
        False,
        "tests/xdp/firewall.c",
        sha,
    )


def facts(release: str = "0") -> BuildFacts:
    return BuildFacts(
        argv=("build", "bpf", "-c", "firewall"),
        diagnostic_argv=("$REPO/make/cli.py", "build", "-c", "firewall"),
        cflags="-O2 --target=bpf",
        ldflags="",
        opt="O2",
        target="bpf",
        isa="ebpf",
        abi="",
        endian="little",
        options=(("release", release),),
    )


def publish(
    root: Path,
    program: str,
    mode: str,
    name: str,
    payload: bytes,
    *,
    role: str,
    fmt: str,
    src: SourceRecord | None = None,
    build: BuildFacts | None = None,
    deps: list[Dependency] | None = None,
    inputs: list[InputArtifact] | None = None,
    body: str = "",
    bpf_sha: str | None = None,
    primary: bool = True,
) -> Path:
    directory = root / program / mode
    directory.mkdir(parents=True, exist_ok=True)
    artifact = directory / name
    artifact.write_bytes(payload)
    commit_mode(
        root,
        program,
        mode,
        src or source(),
        build or facts(),
        deps
        or [
            Dependency("include-bpf/vmlinux.h", "header", "header-sha"),
        ],
        {"clang": "clang version test"},
        inputs or [],
        None,
        {
            "status": "not_run",
            "input_sha256": "",
            "verifier": "",
            "verifier_id": "",
            "options": "",
        },
        [ArtifactFile(role, fmt, primary, artifact, name)],
        body,
        bpf_sha=bpf_sha,
    )
    return artifact


class LayoutTests(unittest.TestCase):
    def test_report_identity_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            src = directory / "source.c"
            header = directory / "header.h"
            alias = directory / "alias.c"
            depfile = directory / "source.d"
            src.write_text("first")
            header.write_text("header")
            alias.symlink_to(src)
            depfile.write_text(f"out: {src} {alias} {header}\n")
            deps = dependencies_from(src, depfile, [src, alias, header])
            self.assertEqual(len(deps), 1)
            self.assertEqual(deps[0].sha256, sha256_file(header))
            firmware = {"helper_addr": "0x1", "slot_addr": "0x2", "slot_len": "0x3", "table_addr": "0x4", "table_len": "0x5"}
            build = _backend_facts("firewall", "rv32", False, "aot", "image", "entry", firmware,
                target="riscv32", isa="rv32imc", abi="ilp32", cflags="flags", ldflags="link", diagnostic=(), container=False)
            toolchain = {"clang": "clang test"}
            def report(sha: str) -> dict:
                return tomllib.loads(compose_report(program="firewall", mode="rv32", status="success",
                    source=source(sha), build=build, deps=deps, toolchain=toolchain, inputs=[],
                    firmware={**firmware, "slot_symbol": "entry"}, verification={"status": "not_run"}, artifacts=[], body=""))
            first = report(sha256_file(src))
            src.write_text("second")
            second = report(sha256_file(src))
            self.assertNotEqual(first["build"]["input_set_id"], second["build"]["input_set_id"])
            self.assertEqual(len(first["dependency"]), 1)
            self.assertEqual(first["firmware"]["slot_symbol"], "entry")
            options = first["build"]["options"]
            self.assertEqual(options["slot_symbol"], "entry")
            self.assertEqual((options["table"], options["table_len"], options["container"]), ("0x4", "0x5", "0"))
            fields = {key: first["build"][key] for key in ("abi", "argv", "cflags", "endian", "isa", "ldflags", "opt", "target")}
            fields["options"] = sorted(options.items())
            fields["toolchain"] = first["toolchain"]
            encoded = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
            self.assertEqual(first["build"]["configuration_id"], hashlib.sha256(encoded).hexdigest())

    def test_rbpf_graph_passes_slot_symbol(self) -> None:
        from build import GraphPlan, McuLink, MemMapV0, edges_for_stem

        backend = McuLink(MemMapV0(1, 2, 3, 4, 5), Path("linker"), Path("tool"),
                          Path("firmware"), True, slot_symbol="firmware_slot", engine="rbpf")
        plan = GraphPlan((Path("firewall.c"),), backend, False, "objdump", Path("build"))
        graph = edges_for_stem(Path("firewall.c"), plan)
        xpost = graph.split(": commit_xpost", 1)[1]
        self.assertIn("--slot-symbol firmware_slot", xpost)

    def test_mode_paths_do_not_collide(self) -> None:
        root = Path("/tmp/build")
        paths = [
            spec_path(root, "firewall", mode, spec.role)
            for mode in MODES
            for spec in MODE_SPECS[mode]
        ]
        self.assertEqual(len(paths), len(set(paths)))
        for path in paths:
            self.assertNotIn(path.name, {"bpf.o", "bpf.toml", "firewall.elf"})

    def test_source_sha_is_not_the_configuration(self) -> None:
        src = source()
        self.assertNotEqual(src.source_id(), src.sha256)
        self.assertNotEqual(
            facts("0").configuration_id({"clang": "clang version test"}),
            facts("1").configuration_id({"clang": "clang version test"}),
        )
        first = [
            Dependency("tests/xdp/firewall.c", "source", "source-sha"),
            Dependency("include-bpf/vmlinux.h", "header", "one"),
        ]
        second = [
            Dependency("tests/xdp/firewall.c", "source", "source-sha"),
            Dependency("include-bpf/vmlinux.h", "header", "two"),
        ]
        self.assertNotEqual(input_set_id(first), input_set_id(second))
        self.assertNotEqual(input_set_id(first), src.sha256)

    def test_depfile_lists_headers(self) -> None:
        text = "out.o: src.c header.h \\\n extra.h\n"
        self.assertEqual(parse_depfile(text), ["src.c", "header.h", "extra.h"])

    def test_logical_flags_have_no_machine_path(self) -> None:
        block = logical_flag_block()
        self.assertIn("$ROOT", block)
        self.assertNotIn("@ROOT@", block)
        self.assertNotIn("/Volumes", block)
        self.assertNotIn("/Users", block)

    def test_commit_verifies_after_the_root_is_renamed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "build"
            artifact = publish(
                root,
                "firewall",
                "bpf",
                "firewall_bpf.o",
                b"bpf-bytes",
                role="bpf_object",
                fmt="elf-bpf-relocatable",
                body='[maps.stats]\nmap_type = "BPF_MAP_TYPE_ARRAY"\n',
            )
            report = report_path(root, "firewall", "bpf")
            self.assertNotIn(sha256_file(report), report.read_text())
            moved = Path(tmp) / "moved"
            root.rename(moved)
            loaded = load_mode(moved, "firewall", "bpf")
            self.assertEqual(loaded["status"], "success")
            self.assertEqual(loaded["maps"]["stats"]["map_type"], "BPF_MAP_TYPE_ARRAY")
            artifact = moved / "firewall" / "bpf" / "firewall_bpf.o"
            artifact.write_bytes(b"tampered")
            with self.assertRaises(LayoutError):
                load_mode(moved, "firewall", "bpf")

    def test_repeating_a_commit_keeps_the_report_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            publish(
                root,
                "firewall",
                "bpf",
                "firewall_bpf.o",
                b"same",
                role="bpf_object",
                fmt="elf-bpf-relocatable",
            )
            first = report_path(root, "firewall", "bpf").read_bytes()
            publish(
                root,
                "firewall",
                "bpf",
                "firewall_bpf.o",
                b"same",
                role="bpf_object",
                fmt="elf-bpf-relocatable",
            )
            self.assertEqual(report_path(root, "firewall", "bpf").read_bytes(), first)

    def test_failed_mode_keeps_the_other_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bpf = publish(
                root,
                "firewall",
                "bpf",
                "firewall_bpf.o",
                b"bpf",
                role="bpf_object",
                fmt="elf-bpf-relocatable",
            )
            image = publish(
                root,
                "firewall",
                "rv32",
                "firewall_rv32.bin",
                b"image",
                role="image",
                fmt="raw-rv32-image",
                inputs=[
                    InputArtifact("gate_bpf", "../bpf/firewall_bpf.o", sha256_file(bpf))
                ],
                bpf_sha=sha256_file(bpf),
            )
            container = root / "firewall" / "rv32" / "firewall_rv32.elf"
            container.write_bytes(b"old-container")
            retract_mode(root, "firewall", "rv32", "prevail rejected")
            self.assertFalse(container.exists())
            self.assertFalse(image.exists())
            self.assertTrue(bpf.is_file())
            self.assertEqual(load_mode(root, "firewall", "bpf")["status"], "success")
            with self.assertRaises(LayoutError):
                load_mode(root, "firewall", "rv32")

    def test_changed_bpf_object_stales_the_backend(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bpf = publish(
                root,
                "firewall",
                "bpf",
                "firewall_bpf.o",
                b"before",
                role="bpf_object",
                fmt="elf-bpf-relocatable",
            )
            publish(
                root,
                "firewall",
                "rv32",
                "firewall_rv32.bin",
                b"image",
                role="image",
                fmt="raw-rv32-image",
                inputs=[
                    InputArtifact("gate_bpf", "../bpf/firewall_bpf.o", sha256_file(bpf))
                ],
                bpf_sha=sha256_file(bpf),
            )
            publish(
                root,
                "firewall",
                "bpf",
                "firewall_bpf.o",
                b"after",
                role="bpf_object",
                fmt="elf-bpf-relocatable",
                bpf_sha=sha256_bytes(b"after"),
            )
            self.assertEqual(load_mode(root, "firewall", "bpf")["status"], "success")
            with self.assertRaises(LayoutError):
                load_mode(root, "firewall", "rv32")

    def test_index_is_sorted_and_omits_a_failed_program(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            publish(
                root,
                "zeta",
                "bpf",
                "zeta_bpf.o",
                b"z",
                role="bpf_object",
                fmt="elf-bpf-relocatable",
            )
            publish(
                root,
                "alpha",
                "bpf",
                "alpha_bpf.o",
                b"a",
                role="bpf_object",
                fmt="elf-bpf-relocatable",
            )
            text = (root / "index.toml").read_text()
            self.assertLess(text.index('name = "alpha"'), text.index('name = "zeta"'))
            retract_mode(root, "alpha", "bpf", "compile failed")
            self.assertNotIn('name = "alpha"', (root / "index.toml").read_text())
            self.assertIn('name = "zeta"', (root / "index.toml").read_text())

    def test_verification_update_keeps_the_artifact_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = publish(
                root,
                "firewall",
                "bpf",
                "firewall_bpf.o",
                b"bpf",
                role="bpf_object",
                fmt="elf-bpf-relocatable",
            )
            before = sha256_file(artifact)
            record_verification(
                root,
                "firewall",
                {
                    "status": "accepted",
                    "input_sha256": before,
                    "verifier": "prevail",
                    "verifier_id": "abc",
                    "options": "stack-size=512",
                },
            )
            loaded = load_mode(root, "firewall", "bpf")
            self.assertEqual(loaded["verification"]["status"], "accepted")
            self.assertEqual(sha256_file(artifact), before)

    def test_export_refuses_the_canonical_root_and_a_second_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "canonical"
            bpf = publish(
                root,
                "firewall",
                "bpf",
                "firewall_bpf.o",
                b"bpf",
                role="bpf_object",
                fmt="elf-bpf-relocatable",
                body='[maps.stats]\nmap_type = "BPF_MAP_TYPE_ARRAY"\n',
            )
            publish(
                root,
                "firewall",
                "rv32",
                "firewall_rv32.bin",
                b"bin",
                role="image",
                fmt="raw-rv32-image",
                body='[maps.stats]\naot_addr = 0x10\n',
                inputs=[
                    InputArtifact("gate_bpf", "../bpf/firewall_bpf.o", sha256_file(bpf))
                ],
                bpf_sha=sha256_file(bpf),
            )
            publish(
                root,
                "firewall",
                "jit",
                "firewall_jit.bin",
                b"jit",
                role="image",
                fmt="raw-rv32-image",
                body='[maps.stats]\nmap_vma = 32\n[jit]\nimage_len = 4\n',
            )
            before = sha256_file(report_path(root, "firewall", "bpf"))
            with self.assertRaises(LayoutError):
                export_legacy(root, root, "rv32")
            out = Path(tmp) / "legacy"
            export_legacy(root, out, "rv32")
            self.assertEqual((out / "legacy-mode.txt").read_text().count('mode = "rv32"'), 1)
            legacy = (out / "firewall" / "bpf.toml").read_text()
            self.assertIn('source = "tests/xdp/firewall.c"', legacy)
            self.assertIn("aot_addr", legacy)
            self.assertEqual(sha256_file(report_path(root, "firewall", "bpf")), before)
            self.assertFalse((root / "firewall" / "bpf.toml").exists())
            with self.assertRaises(LayoutError):
                export_legacy(root, out, "jit")
            stamp = stamp_path(root, "firewall")
            self.assertFalse(stamp.exists())

    def test_rv32_report_change_stales_bpf_xpost(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bpf = _publish_bpf(root)
            _publish_rv32(root, bpf, b"image-v1")
            _publish_xpost(root, bpf)
            publish(root, "firewall", "jit", "firewall_jit.bin", b"jit",
                    role="image", fmt="raw-rv32-image",
                    inputs=[InputArtifact("bpf_object", "../bpf/firewall_bpf.o", sha256_file(bpf))])
            self.assertEqual(load_mode(root, "firewall", "bpf-xpost")["status"], "success")
            _publish_rv32(root, bpf, b"image-v2")
            manifest = _manifest(root)
            self.assertEqual(_names(manifest, "mode"), ["bpf", "rv32", "jit"])
            self.assertEqual(_names(manifest, "stale"), ["bpf-xpost"])
            self.assertEqual(_index_names(root), ["firewall"])
            self.assertEqual(load_mode(root, "firewall", "bpf")["status"], "success")
            self.assertEqual(load_mode(root, "firewall", "rv32")["status"], "success")
            self.assertEqual(load_mode(root, "firewall", "jit")["status"], "success")
            with self.assertRaises(LayoutError):
                load_mode(root, "firewall", "bpf-xpost")

    def test_missing_input_artifact_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bpf = _publish_bpf(root)
            notes = _notes(root)
            _publish_rv32(root, bpf, b"image", extra=_note_input(notes))
            notes.unlink()
            self.assertEqual(_names(_manifest(root), "mode"), ["bpf", "rv32"])
            self.assertEqual(_index_names(root), ["firewall"])
            with self.assertRaises(LayoutError) as caught:
                load_mode(root, "firewall", "rv32")
            self.assertIn("missing input", str(caught.exception))
            _publish_bpf(root, b"bpf")
            self.assertEqual(_names(_manifest(root), "stale"), ["rv32"])
            self.assertEqual(_names(_manifest(root), "mode"), ["bpf"])
            self.assertEqual(load_mode(root, "firewall", "bpf")["status"], "success")
            with self.assertRaises(LayoutError):
                load_mode(root, "firewall", "rv32")

    def test_input_hash_mismatch_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bpf = _publish_bpf(root)
            notes = _notes(root)
            _publish_rv32(root, bpf, b"image", extra=_note_input(notes))
            notes.write_bytes(b"notes-v2")
            self.assertIn("rv32", _names(_manifest(root), "mode"))
            with self.assertRaises(LayoutError) as caught:
                load_mode(root, "firewall", "rv32")
            self.assertIn("input hash mismatch", str(caught.exception))
            _publish_bpf(root, b"bpf")
            self.assertEqual(_names(_manifest(root), "stale"), ["rv32"])
            self.assertEqual(_index_names(root), ["firewall"])
            with self.assertRaises(LayoutError):
                load_mode(root, "firewall", "rv32")

    def test_unchanged_inputs_still_load(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bpf = _publish_bpf(root)
            _publish_rv32(root, bpf, b"image")
            _publish_xpost(root, bpf)
            self.assertEqual(_names(_manifest(root), "mode"), ["bpf", "rv32", "bpf-xpost"])
            self.assertNotIn("stale", _manifest(root))
            self.assertEqual(_index_names(root), ["firewall"])
            for mode in ("bpf", "rv32", "bpf-xpost"):
                self.assertEqual(load_mode(root, "firewall", mode)["status"], "success")

    def test_escaping_inputs_are_refused_and_staled(self) -> None:
        for reference in ("../../outside", "/tmp/outside", "C:\\outside", "../bpf/link"):
            with self.subTest(reference=reference), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "build"
                outside = root / "outside"
                outside.parent.mkdir(parents=True)
                outside.write_bytes(b"outside")
                bpf = _publish_bpf(root)
                (root / "firewall" / "bpf" / "link").symlink_to(outside)
                _publish_rv32(root, bpf, b"image", extra=[
                    InputArtifact("map_index_basis", reference, sha256_file(outside))
                ])
                with self.assertRaises(LayoutError):
                    load_mode(root, "firewall", "rv32")
                _publish_bpf(root)
                self.assertEqual(_names(_manifest(root), "stale"), ["rv32"])
                self.assertEqual(load_mode(root, "firewall", "bpf")["status"], "success")

    def test_absolute_input_path_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bpf = _publish_bpf(root)
            _publish_rv32(
                root,
                bpf,
                b"image",
                extra=[InputArtifact("gate_bpf", "/tmp/not/a/relative", sha256_file(bpf))],
            )
            self.assertEqual(_index_names(root), ["firewall"])
            with self.assertRaises(LayoutError) as caught:
                load_mode(root, "firewall", "rv32")
            self.assertIn("absolute", str(caught.exception))


def _publish_bpf(root: Path, payload: bytes = b"bpf") -> Path:
    return publish(
        root,
        "firewall",
        "bpf",
        "firewall_bpf.o",
        payload,
        role="bpf_object",
        fmt="elf-bpf-relocatable",
        bpf_sha=sha256_bytes(payload),
    )


def _publish_rv32(
    root: Path,
    bpf: Path,
    payload: bytes,
    extra: list[InputArtifact] | None = None,
) -> Path:
    inputs = [InputArtifact("gate_bpf", "../bpf/firewall_bpf.o", sha256_file(bpf))]
    if extra:
        inputs.extend(extra)
    return publish(
        root,
        "firewall",
        "rv32",
        "firewall_rv32.bin",
        payload,
        role="image",
        fmt="raw-rv32-image",
        inputs=inputs,
        bpf_sha=sha256_file(bpf),
    )


def _publish_xpost(root: Path, bpf: Path) -> Path:
    basis = report_path(root, "firewall", "rv32")
    return publish(
        root,
        "firewall",
        "bpf-xpost",
        "firewall_bpf-xpost.elf",
        b"container",
        role="xpost_container",
        fmt="xpost-compact-elf-v0",
        inputs=[
            InputArtifact("bpf_object", "../bpf/firewall_bpf.o", sha256_file(bpf)),
            InputArtifact("map_index_basis", "../rv32/report.toml", sha256_file(basis)),
        ],
        bpf_sha=sha256_file(bpf),
    )


def _notes(root: Path) -> Path:
    path = root / "firewall" / "bpf" / "notes.bin"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"notes-v1")
    return path


def _note_input(path: Path) -> list[InputArtifact]:
    return [InputArtifact("map_index_basis", "../bpf/notes.bin", sha256_file(path))]


def _manifest(root: Path) -> dict:
    return tomllib.loads((root / "firewall" / "manifest.toml").read_text())


def _names(doc: dict, key: str) -> list[str]:
    rows = doc.get(key, [])
    if isinstance(rows, dict):
        rows = [rows]
    return [str(row["name"]) for row in rows]


def _index_names(root: Path) -> list[str]:
    doc = tomllib.loads((root / "index.toml").read_text())
    rows = doc.get("program", [])
    if isinstance(rows, dict):
        rows = [rows]
    return [str(row["name"]) for row in rows]


if __name__ == "__main__":
    unittest.main()
