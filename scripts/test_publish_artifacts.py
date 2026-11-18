import io
import json
import shutil
import sys
import tarfile
import tempfile
import tomllib
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import publish_artifacts as pub
import layout
import build


MEM = build.MemMapV0(0x1000, 0x2000, 0x3000, 0x4000, 0x5000)


def fixture(
    root: Path,
    firmware: str = "firmware",
    modes=layout.MODES,
    image_name="",
    release=False,
):
    src = layout.SourceRecord("repo", "commit", False, "tests/firewall.c", "source")
    facts = layout.BuildFacts(("build",), (), "", "", "O2", "bpf", "", "", "little", ())
    verification = {
        "status": "accepted",
        "input_sha256": "",
        "verifier": "prevail",
        "verifier_id": "test",
        "options": "",
    }
    firmware_facts = {
        "sha256": firmware,
        **{
            key: hex(getattr(MEM, key))
            for key in (
                "helper_addr",
                "slot_addr",
                "slot_len",
                "table_addr",
                "table_len",
            )
        },
    }
    for mode in modes:
        directory = root / "firewall" / mode
        directory.mkdir(parents=True, exist_ok=True)
        artifacts = []
        for spec in layout.MODE_SPECS[mode]:
            name = layout.filename("firewall", spec)
            path = directory / name
            path.write_bytes(name.encode())
            artifacts.append(
                layout.ArtifactFile(spec.role, spec.format, spec.primary, path, name)
            )
        inputs = []
        if mode != "bpf":
            bpf = root / "firewall/bpf/firewall_bpf.o"
            role = "gate_bpf" if mode == "rv32" else "bpf_object"
            inputs = [
                layout.InputArtifact(
                    role, "../bpf/firewall_bpf.o", layout.sha256_file(bpf)
                )
            ]
            if mode == "bpf-xpost":
                inputs.append(
                    layout.InputArtifact(
                        "map_index_basis",
                        "../rv32/report.toml",
                        layout.sha256_file(root / "firewall/rv32/report.toml"),
                    )
                )
        verification["input_sha256"] = layout.sha256_file(
            root / "firewall/bpf/firewall_bpf.o"
        )
        layout.commit_mode(
            root,
            "firewall",
            mode,
            src,
            facts
            if mode == "bpf"
            else layout._backend_facts(
                "firewall",
                mode,
                release,
                "rbpf" if mode == "bpf-xpost" else mode,
                image_name,
                "",
                firmware_facts,
                target="",
                isa="",
                abi="",
                cflags="",
                ldflags="",
                diagnostic=(),
            ),
            [],
            {"clang": "test"},
            inputs,
            firmware_facts if mode != "bpf" else None,
            ({"status": "not_run"} if mode == "bpf" else verification),
            artifacts,
            "",
            bpf_sha=layout.sha256_file(root / "firewall/bpf/firewall_bpf.o"),
        )


def metadata(name="firewall"):
    return {
        "name": name,
        "slot_address": MEM.slot_addr,
        "helper_address": MEM.helper_addr,
        "machine": 1,
    }


class PublicationTests(unittest.TestCase):
    def test_conflicting_tags_and_releases_are_rejected(self):
        for conflict in ("local", "remote", "release"):

            def response(args, **kwargs):
                text = (
                    "v1"
                    if (
                        conflict == "local"
                        and args[:2] == ["git", "tag"]
                        or conflict == "remote"
                        and args[:2] == ["git", "ls-remote"]
                    )
                    else ""
                )
                return SimpleNamespace(stdout=text, stderr="", returncode=0)

            with (
                self.subTest(conflict=conflict),
                patch.object(pub, "run", side_effect=response),
            ):
                with self.assertRaises(pub.PublishError):
                    pub.absent("v1", "github.com/nan-mu/libbpf-mcu")

    def test_invalid_matrix_entries_stop_before_tool_or_build(self):
        good = {"id": "one", "program": "firewall", "modes": ["bpf"]}
        for change in (
            {"id": "../escape"},
            {"id": "ONE"},
            {"program": "absent"},
            {"modes": []},
            {"modes": ["unknown"]},
            {"modes": ["bpf", "bpf"]},
            {"modes": ["rv32"]},
            {"firmware": "unused"},
            {"release": "true"},
            {"image_name": "bad-name"},
            {"unexpected": "value"},
            {"modes": ["jit"], "slot_symbol": "xdp_slot_idle", "firmware": "fw"},
            {"modes": ["rv32"], "firmware": "missing"},
        ):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                plan = Path(temp) / "plan.toml"
                second = good | {"id": "two"} | change
                rows = ['schema = "libbpf-mcu.release-plan.v1"']
                for item in (good, second):
                    rows.append("[[build]]")
                    rows.extend(
                        f"{key} = {json.dumps(value)}" for key, value in item.items()
                    )
                plan.write_text("\n".join(rows))
                with (
                    patch.object(build, "ensure_tool") as tool,
                    patch.object(pub, "run") as run,
                ):
                    with self.assertRaises(pub.PublishError):
                        pub.load_plan(plan)
                    tool.assert_not_called()
                    run.assert_not_called()

    def test_plan_preflight_inspects_only_after_all_entries_validate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            firmware = root / "firmware.elf"
            firmware.write_bytes(b"firmware")
            plan = root / "plan.toml"
            prefix = """schema = "libbpf-mcu.release-plan.v1"
[[build]]
id = "one"
program = "firewall"
modes = ["rv32"]
firmware = "firmware.elf"
"""
            plan.write_text(
                prefix
                + """
[[build]]
id = "ONE"
program = "firewall"
modes = ["bpf"]
"""
            )
            with patch.object(build, "ensure_tool") as tool:
                with self.assertRaises(pub.PublishError):
                    pub.load_plan(plan)
                tool.assert_not_called()
            plan.write_text(prefix)
            mem = object()
            with (
                patch.object(build, "ensure_tool", return_value=Path("tool")),
                patch.object(build, "load_mem_map_from_firmware", return_value=mem),
            ):
                sets = pub.load_plan(plan)
            self.assertEqual(sets[0].firmware, firmware.resolve())
            self.assertEqual(sets[0].firmware_sha256, layout.sha256_file(firmware))
            self.assertIs(sets[0].mem_map, mem)

    def test_plan_inspection_failure_is_reported_without_traceback(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "firmware").write_bytes(b"bad firmware")
            plan = root / "plan.toml"
            plan.write_text(
                'schema = "libbpf-mcu.release-plan.v1"\n[[build]]\nid = "one"\nprogram = "firewall"\nmodes = ["rv32"]\nfirmware = "firmware"\n'
            )
            err = io.StringIO()
            with (
                patch.object(build, "ensure_tool", return_value=Path("tool")),
                patch.object(
                    build, "load_mem_map_from_firmware", side_effect=SystemExit(1)
                ),
                redirect_stdout(io.StringIO()),
                redirect_stderr(err),
            ):
                self.assertEqual(
                    pub.main(["--plan", str(plan), "--tag", "v1", "--package-only"]), 1
                )
            self.assertIn("firmware inspection failed", err.getvalue())
            self.assertNotIn("Traceback", err.getvalue())

    def test_bpf_only_plan_needs_no_firmware(self):
        with tempfile.TemporaryDirectory() as temp:
            plan = Path(temp) / "plan.toml"
            plan.write_text("""schema = "libbpf-mcu.release-plan.v1"
[[build]]
id = "one"
program = "firewall"
modes = ["bpf"]
""")
            with patch.object(build, "ensure_tool") as tool:
                self.assertIsNone(pub.load_plan(plan)[0].firmware)
                tool.assert_not_called()

    def test_full_archive_and_tamper(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "build"
            fixture(root)
            files = pub.official(root, ["firewall"])
            stage = Path(temp) / "libbpf-mcu-artifacts"
            item = pub.BuildSet(
                "one",
                "firewall",
                layout.MODES,
                Path("firmware"),
                "firmware",
                None,
                None,
                False,
                MEM,
            )
            (stage / "sets/one").mkdir(parents=True)
            (stage / "release-index.toml").write_text(
                'schema = "libbpf-mcu.release-index.v1"\n[[set]]\nid = "one"\nprogram = "firewall"\nroot = "sets/one"\nrequested_modes = ["bpf", "rv32", "jit", "bpf-xpost"]\nproduced_modes = ["bpf", "rv32", "jit", "bpf-xpost"]\nfirmware_sha256 = "firmware"\n'
            )
            for rel in files:
                dest = stage / "sets/one" / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(root / rel, dest)
            files = {f"sets/one/{rel}" for rel in files} | {"release-index.toml"}
            (stage / "SHA256SUMS").write_text(pub.sums(stage, files))
            archive = Path(temp) / "result.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                tar.add(stage, arcname=stage.name)
            with tarfile.open(archive) as tar:
                tar.extractall(Path(temp) / "extract", filter="data")
            extracted = Path(temp) / "extract" / stage.name
            with patch.object(pub, "inspect_container", return_value=metadata()):
                pub.verify_package(extracted, (item,))
            for altered in (
                {**metadata(), "name": "wrong"},
                {**metadata(), "slot_address": MEM.slot_addr + 4},
                {**metadata(), "helper_address": MEM.helper_addr + 4},
                {**metadata(), "machine": 2},
            ):
                with (
                    self.subTest(metadata=altered),
                    patch.object(pub, "inspect_container", return_value=altered),
                ):
                    with self.assertRaises(pub.PublishError):
                        pub.verify_package(extracted, (item,))
            for field in (
                "helper_addr",
                "slot_addr",
                "slot_len",
                "table_addr",
                "table_len",
            ):
                wrong_mem = replace(MEM, **{field: getattr(MEM, field) + 4})
                with (
                    self.subTest(field=field),
                    patch.object(pub, "inspect_container", return_value=metadata()),
                ):
                    with self.assertRaises(pub.PublishError):
                        pub.verify_package(
                            extracted, (replace(item, mem_map=wrong_mem),)
                        )
            for change in (
                {"image_name": "wrong"},
                {"release": True},
                {"slot_symbol": "other"},
            ):
                with (
                    self.subTest(options=change),
                    patch.object(pub, "inspect_container", return_value=metadata()),
                ):
                    with self.assertRaises(pub.PublishError):
                        pub.verify_package(extracted, (replace(item, **change),))
            (extracted / "sets/one/firewall/bpf/firewall_bpf.o").write_bytes(
                b"tampered"
            )
            with self.assertRaises((pub.PublishError, layout.LayoutError)):
                with patch.object(pub, "inspect_container", return_value=metadata()):
                    pub.verify_package(extracted, (item,))

    def test_wrong_artifact_primary_size_and_hash(self):
        for field, replacement in (
            ("primary = true", "primary = false"),
            ("size_bytes = ", "size_bytes = 999 #"),
            ("sha256 = ", 'sha256 = "wrong" #'),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                fixture(root, modes=("bpf",))
                report = root / "firewall/bpf/report.toml"
                text = report.read_text()
                start = text.index("[[artifact]]")
                old = layout.sha256_file(report)
                report.write_text(
                    text[:start] + text[start:].replace(field, replacement, 1)
                )
                manifest = root / "firewall/manifest.toml"
                old_manifest = layout.sha256_file(manifest)
                manifest.write_text(
                    manifest.read_text().replace(old, layout.sha256_file(report))
                )
                index = root / "index.toml"
                index.write_text(
                    index.read_text().replace(
                        old_manifest, layout.sha256_file(manifest)
                    )
                )
                with self.assertRaises(layout.LayoutError):
                    layout.validate_release_mode(root, "firewall", "bpf")

    def test_release_mode_rejects_identity_and_input_basis_changes(self):
        for old, new in (
            ('program = "firewall"', 'program = "other"'),
            ('mode = "bpf-xpost"', 'mode = "jit"'),
            ('path = "../rv32/report.toml"', 'path = "../bpf/report.toml"'),
            ('role = "map_index_basis"', 'role = "other"'),
            ('verifier_id = "test"', 'verifier_id = ""'),
        ):
            with self.subTest(change=old), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                fixture(root)
                report = root / "firewall/bpf-xpost/report.toml"
                before = layout.sha256_file(report)
                text = report.read_text()
                self.assertIn(old, text)
                report.write_text(text.replace(old, new, 1))
                manifest = root / "firewall/manifest.toml"
                manifest_before = layout.sha256_file(manifest)
                manifest.write_text(
                    manifest.read_text().replace(before, layout.sha256_file(report))
                )
                index = root / "index.toml"
                index.write_text(
                    index.read_text().replace(
                        manifest_before, layout.sha256_file(manifest)
                    )
                )
                with self.assertRaises(layout.LayoutError):
                    layout.validate_release_mode(root, "firewall", "bpf-xpost")

    def test_missing_mode_and_stale_and_duplicate_and_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture(root)
            index = root / "index.toml"
            original = index.read_text()
            index.write_text(
                original.replace("firewall/manifest.toml", "../manifest.toml")
            )
            with self.assertRaises(pub.PublishError):
                pub.official(root, ["firewall"])
            index.write_text(original + original[original.index("[[program]]") :])
            with self.assertRaises(pub.PublishError):
                pub.official(root, ["firewall"])
            index.write_text(original)
            manifest = root / "firewall/manifest.toml"
            text = manifest.read_text()
            for changed in (text.split("[[mode]]")[:-1],):
                manifest.write_text("[[mode]]".join(changed))
                index.write_text(
                    original.replace(
                        layout.sha256_bytes(text.encode()), layout.sha256_file(manifest)
                    )
                )
                with self.assertRaises(pub.PublishError):
                    pub.official(root, ["firewall"])
            manifest.write_text(text + '\n[[stale]]\nname = "jit"\n')
            index.write_text(
                original.replace(
                    layout.sha256_bytes(text.encode()), layout.sha256_file(manifest)
                )
            )
            with self.assertRaises(pub.PublishError):
                pub.official(root, ["firewall"])

    def test_no_gh_for_package_only_and_dry_run_never_uploads(self):
        for option in ("--package-only", "--dry-run", "--dry-run-outdated"):
            with self.subTest(option=option), tempfile.TemporaryDirectory() as temp:
                tmp = Path(temp)
                firmware = tmp / "firmware.elf"
                firmware.write_bytes(b"firmware")
                plan = tmp / "plan.toml"
                plan.write_text(
                    'schema = "libbpf-mcu.release-plan.v1"\n[[build]]\nid = "one"\nprogram = "firewall"\nmodes = ["bpf", "rv32", "jit", "bpf-xpost"]\nfirmware = "firmware.elf"\n'
                )
                out = tmp / "out"
                calls = []

                def run(
                    args, *, calls=calls, option=option, firmware=firmware, **kwargs
                ):
                    calls.append(args)
                    if args[:4] == ["git", "remote", "get-url", "origin"]:
                        return SimpleNamespace(
                            stdout="git@github.com:nan-mu/libbpf-mcu.git",
                            stderr="",
                            returncode=0,
                        )
                    if args == ["git", "ls-remote", "origin", "refs/heads/main"]:
                        sha = "b" * 40 if option == "--dry-run-outdated" else "a" * 40
                        return SimpleNamespace(
                            stdout=f"{sha}\trefs/heads/main\n", stderr="", returncode=0
                        )
                    if args[0] == sys.executable:
                        target = Path(args[args.index("--build-dir") + 1])
                        if not (target / "index.toml").exists():
                            fixture(target, layout.sha256_file(firmware))

                    class Result:
                        returncode = 1 if args[:3] == ["gh", "release", "view"] else 0
                        stdout = (
                            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            if args[:3]
                            in (
                                ["git", "rev-parse", "HEAD"],
                                ["git", "rev-parse", "refs/heads/main"],
                            )
                            else "main"
                            if args[:3] == ["git", "branch", "--show-current"]
                            else ""
                        )
                        stderr = "release not found" if returncode else ""

                    return Result()

                with (
                    patch.object(pub, "run", side_effect=run),
                    patch.object(
                        build, "_default_inputs", return_value=[Path("firewall.c")]
                    ),
                    patch.object(build, "ensure_tool"),
                    patch.object(build, "load_mem_map_from_firmware", return_value=MEM),
                    patch.object(
                        pub,
                        "inspect_container",
                        side_effect=lambda p: metadata(
                            "image" if "backend" in str(p) else "firewall"
                        ),
                    ),
                    patch.object(pub.shutil, "which", return_value="tool"),
                    patch(
                        "prevail_gate.prevail_bin", return_value=Path(sys.executable)
                    ),
                    redirect_stdout(io.StringIO()),
                    redirect_stderr(io.StringIO()),
                ):
                    result = pub.main(
                        [
                            "--plan",
                            str(plan),
                            "--tag",
                            "v1",
                            "--out",
                            str(out),
                            "--dry-run" if option == "--dry-run-outdated" else option,
                        ]
                    )
                if option == "--dry-run-outdated":
                    self.assertEqual(result, 1)
                    self.assertFalse(any(c[0] == sys.executable for c in calls))
                    continue
                self.assertEqual(result, 0)
                builds = [c for c in calls if c[0] == sys.executable]
                self.assertEqual([c[3] for c in builds], ["esp32c3", "jit"])
                self.assertIn("rbpf", builds[0])
                self.assertTrue((out / "libbpf-mcu-artifacts-v1.tar.gz").is_file())
                self.assertFalse(
                    any(c[:3] == ["gh", "release", "create"] for c in calls)
                )
                if option == "--package-only":
                    self.assertFalse(any(c[0] == "gh" for c in calls))
                    self.assertFalse(any(c[:2] == ["git", "ls-remote"] for c in calls))
                else:
                    self.assertTrue(
                        any(
                            c == ["git", "ls-remote", "origin", "refs/heads/main"]
                            for c in calls
                        )
                    )

    def test_multiple_sets_and_subset_closures(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            firmware = root / "firmware"
            firmware.write_bytes(b"firmware")
            plan = root / "plan.toml"
            plan.write_text("""schema = "libbpf-mcu.release-plan.v1"
[[build]]
id = "plain"
program = "firewall"
modes = ["bpf"]
[[build]]
id = "backend"
program = "firewall"
modes = ["bpf-xpost"]
firmware = "firmware"
image_name = "image"
release = true
""")
            calls = []

            def run(args, **kwargs):
                calls.append(args)
                if args[0] == sys.executable:
                    target = Path(args[args.index("--build-dir") + 1])
                    if not (target / "index.toml").exists():
                        modes = (
                            ("bpf",)
                            if target.name == "plain"
                            else ("bpf", "rv32", "bpf-xpost")
                        )
                        fixture(
                            target,
                            layout.sha256_file(firmware),
                            modes,
                            image_name="image" if target.name == "backend" else "",
                            release=target.name == "backend",
                        )
                return SimpleNamespace(
                    stdout="main"
                    if args[:3] == ["git", "branch", "--show-current"]
                    else "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    if args[:3] == ["git", "rev-parse", "HEAD"]
                    else "",
                    stderr="",
                    returncode=0,
                )

            with (
                patch.object(pub, "run", side_effect=run),
                patch.object(
                    build, "_default_inputs", return_value=[Path("firewall.c")]
                ),
                patch.object(build, "ensure_tool"),
                patch.object(build, "load_mem_map_from_firmware", return_value=MEM),
                patch.object(
                    pub,
                    "inspect_container",
                    side_effect=lambda p: metadata(
                        "image" if "backend" in str(p) else "firewall"
                    ),
                ),
                patch.object(pub.shutil, "which", return_value="tool"),
                patch("prevail_gate.prevail_bin", return_value=Path(sys.executable)),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(
                    pub.main(
                        [
                            "--plan",
                            str(plan),
                            "--tag",
                            "v1",
                            "--out",
                            str(root / "out"),
                            "--package-only",
                        ]
                    ),
                    0,
                )
            builds = [c for c in calls if c[0] == sys.executable]
            self.assertEqual([c[3] for c in builds], ["bpf", "esp32c3"])
            self.assertNotEqual(
                builds[0][builds[0].index("--build-dir") + 1],
                builds[1][builds[1].index("--build-dir") + 1],
            )
            self.assertIn("--engine", builds[-1])
            self.assertIn("--release", builds[-1])
            self.assertIn("--image-name", builds[-1])
            with tarfile.open(root / "out/libbpf-mcu-artifacts-v1.tar.gz") as tar:
                index = tomllib.loads(
                    tar.extractfile("libbpf-mcu-artifacts/release-index.toml")
                    .read()
                    .decode()
                )
                self.assertEqual(
                    [row["produced_modes"] for row in index["set"]],
                    [["bpf"], ["bpf", "rv32", "bpf-xpost"]],
                )
                names = tar.getnames()
                self.assertIn(
                    "libbpf-mcu-artifacts/sets/plain/firewall/bpf/firewall_bpf.o", names
                )
                self.assertIn(
                    "libbpf-mcu-artifacts/sets/backend/firewall/bpf/firewall_bpf.o",
                    names,
                )

    def test_release_preflight_and_publication_failures(self):
        for failure in (
            "dirty",
            "nonmain",
            "behind",
            "divergent",
            "queryfail",
            "malformed",
            "remote_change",
            "tag",
            "auth",
            "tool",
            "build",
            "build2",
            "tag_race",
            "firmware_change",
            "verification",
            "confirmation",
            "upload",
            "success",
        ):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temp:
                tmp = Path(temp)
                firmware = tmp / "firmware"
                firmware.write_bytes(b"firmware")
                plan = tmp / "plan.toml"
                plan.write_text(
                    'schema = "libbpf-mcu.release-plan.v1"\n[[build]]\nid = "one"\nprogram = "firewall"\nmodes = ["bpf", "rv32", "jit", "bpf-xpost"]\nfirmware = "firmware"\n'
                )
                calls = []

                def run(
                    args, *, calls=calls, failure=failure, firmware=firmware, **kwargs
                ):
                    calls.append(args)
                    if args[:4] == ["git", "remote", "get-url", "origin"]:
                        return SimpleNamespace(
                            stdout="git@github.com:nan-mu/libbpf-mcu.git",
                            stderr="",
                            returncode=0,
                        )
                    if args == ["git", "ls-remote", "origin", "refs/heads/main"]:
                        if failure == "queryfail":
                            raise pub.PublishError("git failed: offline")
                        queries = sum(c == args for c in calls)
                        sha = (
                            "b" * 40
                            if failure in ("behind", "divergent")
                            or (failure == "remote_change" and queries == 3)
                            else "a" * 40
                        )
                        remote = (
                            "invalid"
                            if failure == "malformed"
                            else f"{sha}\trefs/heads/main\n"
                        )
                        return SimpleNamespace(stdout=remote, stderr="", returncode=0)
                    if failure == "tag_race" and args[:2] == ["gh", "api"]:
                        raise pub.PublishError("reference already exists")
                    if failure == "auth" and args[:3] == ["gh", "auth", "status"]:
                        raise pub.PublishError("auth failed")
                    if args[0] == sys.executable and failure in (
                        "build",
                        "build2",
                    ):
                        count = sum(c[0] == sys.executable for c in calls)
                        if count == {"build": 1, "build2": 2}[failure]:
                            raise pub.PublishError("compiler failed")
                    if (
                        failure == "verification"
                        and args[0] == sys.executable
                        and sum(c[0] == sys.executable for c in calls) == 2
                    ):
                        target = Path(args[args.index("--build-dir") + 1])
                        (target / "firewall/bpf/firewall_bpf.o").write_bytes(b"corrupt")
                    if failure == "upload" and args[:3] == ["gh", "release", "create"]:
                        raise pub.PublishError("upload failed")
                    if args[0] == sys.executable:
                        target = Path(args[args.index("--build-dir") + 1])
                        if not (target / "index.toml").exists():
                            fixture(target, layout.sha256_file(firmware))

                    class Result:
                        returncode = 1 if args[:3] == ["gh", "release", "view"] else 0
                        stdout = (
                            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            if args[:3]
                            in (
                                ["git", "rev-parse", "HEAD"],
                                ["git", "rev-parse", "refs/heads/main"],
                            )
                            else ("dev" if failure == "nonmain" else "main")
                            if args[:3] == ["git", "branch", "--show-current"]
                            else " M file"
                            if failure == "dirty" and args[:2] == ["git", "status"]
                            else "v1"
                            if failure == "tag" and args[:3] == ["git", "tag", "--list"]
                            else ""
                        )
                        stderr = "release not found" if returncode else ""

                    return Result()

                answer = (
                    "no"
                    if failure == "confirmation"
                    else "v1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                )

                def confirm(
                    prompt, *, failure=failure, firmware=firmware, answer=answer
                ):
                    self.assertIn("github.com/nan-mu/libbpf-mcu", prompt)
                    if failure == "firmware_change":
                        firmware.write_bytes(b"changed")
                    return answer

                errors = io.StringIO()
                with (
                    patch.object(pub, "run", side_effect=run),
                    patch.object(
                        build, "_default_inputs", return_value=[Path("firewall.c")]
                    ),
                    patch.object(build, "ensure_tool"),
                    patch.object(build, "load_mem_map_from_firmware", return_value=MEM),
                    patch.object(
                        pub,
                        "inspect_container",
                        side_effect=lambda p: metadata(
                            "image" if "backend" in str(p) else "firewall"
                        ),
                    ),
                    patch.object(
                        pub.shutil,
                        "which",
                        return_value=None if failure == "tool" else "tool",
                    ),
                    patch(
                        "prevail_gate.prevail_bin", return_value=Path(sys.executable)
                    ),
                    patch("builtins.input", side_effect=confirm),
                    redirect_stdout(io.StringIO()),
                    redirect_stderr(errors),
                ):
                    result = pub.main(
                        [
                            "--plan",
                            str(plan),
                            "--tag",
                            "v1",
                            "--out",
                            str(tmp / "out"),
                        ]
                    )
                self.assertEqual(result, 0 if failure == "success" else 1)
                if failure in (
                    "behind",
                    "divergent",
                    "queryfail",
                    "malformed",
                    "remote_change",
                ):
                    self.assertIn("behind or divergent", errors.getvalue())
                    self.assertIn("manually update", errors.getvalue())
                uploads = [c for c in calls if c[:3] == ["gh", "release", "create"]]
                self.assertEqual(
                    len(uploads), 1 if failure in ("upload", "success") else 0
                )
                if uploads:
                    self.assertEqual(
                        uploads[0][uploads[0].index("--repo") + 1],
                        "github.com/nan-mu/libbpf-mcu",
                    )
                    self.assertEqual(
                        uploads[0][uploads[0].index("--target") + 1],
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    )
                    self.assertIn("--verify-tag", uploads[0])
                    if failure == "success":
                        notes = uploads[0][uploads[0].index("--notes") + 1]
                        for value in (
                            "one",
                            "firewall",
                            "requested",
                            "produced",
                            "bpf",
                            "rv32",
                            "jit",
                            "bpf-xpost",
                            "a" * 40,
                            layout.sha256_file(plan),
                            layout.sha256_file(firmware),
                        ):
                            self.assertIn(value, notes)
                        self.assertNotIn(str(firmware), notes)
                        self.assertNotIn(str(firmware.resolve()), notes)
                        self.assertNotIn(str(Path.home()), notes)

    def test_wrong_dependency_role_target_and_symlink_are_rejected(self):
        for variant in ("wrong-role-target", "symlink", "missing"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temp:
                root = Path(temp) / "build"
                fixture(root)
                bpf = root / "firewall/bpf/firewall_bpf.o"
                if variant == "wrong-role-target":
                    report = root / "firewall/bpf-xpost/report.toml"
                    text = report.read_text()
                    basis = root / "firewall/rv32/report.toml"
                    text = text.replace(
                        'path = "../rv32/report.toml"', 'path = "../bpf/firewall_bpf.o"'
                    ).replace(layout.sha256_file(basis), layout.sha256_file(bpf))
                    old = layout.sha256_file(report)
                    report.write_text(text)
                    manifest = root / "firewall/manifest.toml"
                    old_manifest = layout.sha256_file(manifest)
                    manifest.write_text(
                        manifest.read_text().replace(old, layout.sha256_file(report))
                    )
                    index = root / "index.toml"
                    index.write_text(
                        index.read_text().replace(
                            old_manifest, layout.sha256_file(manifest)
                        )
                    )
                elif variant == "symlink":
                    outside = Path(temp) / "outside"
                    bpf.rename(outside)
                    bpf.symlink_to(outside)
                else:
                    bpf.unlink()
                with self.assertRaises((pub.PublishError, layout.LayoutError, OSError)):
                    pub.official(root, ["firewall"])

    def test_repository_is_pinned_despite_gh_repo(self):
        with (
            patch.dict("os.environ", {"GH_REPO": "other/repo"}),
            patch.object(
                pub,
                "run",
                return_value=SimpleNamespace(
                    stdout="https://github.com/nan-mu/libbpf-mcu.git", returncode=0
                ),
            ),
        ):
            self.assertEqual(pub.release_repository(), "github.com/nan-mu/libbpf-mcu")

    def test_missing_firmware_and_existing_output(self):
        with tempfile.TemporaryDirectory() as temp, redirect_stderr(io.StringIO()):
            root = Path(temp)
            self.assertEqual(
                pub.main(
                    [
                        "--plan",
                        str(root / "missing"),
                        "--tag",
                        "v1",
                        "--package-only",
                    ]
                ),
                1,
            )
            firmware = root / "f"
            firmware.write_text(
                'schema = "libbpf-mcu.release-plan.v1"\n[[build]]\nid = "one"\nprogram = "firewall"\nmodes = ["bpf"]\n'
            )
            self.assertEqual(
                pub.main(
                    [
                        "--plan",
                        str(firmware),
                        "--tag",
                        "v1",
                        "--package-only",
                        "--out",
                        str(root),
                    ]
                ),
                1,
            )


if __name__ == "__main__":
    unittest.main()
