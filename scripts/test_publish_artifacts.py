import io
import shutil
import sys
import tarfile
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import publish_artifacts as pub
import layout
import build


def fixture(root: Path, firmware: str = "firmware"):
    src = layout.SourceRecord("repo", "commit", False, "tests/firewall.c", "source")
    facts = layout.BuildFacts(("build",), (), "", "", "O2", "bpf", "", "", "little", ())
    verification = {
        "status": "accepted",
        "input_sha256": "",
        "verifier": "prevail",
        "verifier_id": "test",
        "options": "",
    }
    for mode in layout.MODES:
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
            facts,
            [],
            {"clang": "test"},
            inputs,
            {"sha256": firmware} if mode != "bpf" else None,
            verification,
            artifacts,
            "",
            bpf_sha=layout.sha256_file(root / "firewall/bpf/firewall_bpf.o"),
        )


class PublicationTests(unittest.TestCase):
    def test_full_archive_and_tamper(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "build"
            fixture(root)
            files = pub.official(root, ["firewall"])
            stage = Path(temp) / "libbpf-mcu-artifacts"
            for rel in files:
                dest = stage / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(root / rel, dest)
            (stage / "SHA256SUMS").write_text(pub.sums(stage, files))
            archive = Path(temp) / "result.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                tar.add(stage, arcname=stage.name)
            with tarfile.open(archive) as tar:
                tar.extractall(Path(temp) / "extract", filter="data")
            extracted = Path(temp) / "extract" / stage.name
            pub.verify_package(extracted, ["firewall"])
            (extracted / "firewall/bpf/firewall_bpf.o").write_bytes(b"tampered")
            with self.assertRaises((pub.PublishError, layout.LayoutError)):
                pub.verify_package(extracted, ["firewall"])

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
        for option in ("--package-only", "--dry-run"):
            with self.subTest(option=option), tempfile.TemporaryDirectory() as temp:
                tmp = Path(temp)
                firmware = tmp / "firmware.elf"
                firmware.write_bytes(b"firmware")
                out = tmp / "out"
                calls = []

                def run(args, **kwargs):
                    calls.append(args)
                    if args[:4] == ["git", "remote", "get-url", "origin"]:
                        return SimpleNamespace(
                            stdout="git@github.com:nan-mu/libbpf-mcu.git",
                            stderr="",
                            returncode=0,
                        )
                    if args[0] == sys.executable:
                        target = Path(args[args.index("--build-dir") + 1])
                        if not (target / "index.toml").exists():
                            fixture(target, layout.sha256_file(firmware))

                    class Result:
                        returncode = 1 if args[:3] == ["gh", "release", "view"] else 0
                        stdout = (
                            "abc"
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
                    patch.object(build, "load_mem_map_from_firmware"),
                    patch.object(pub.shutil, "which", return_value="tool"),
                    patch(
                        "prevail_gate.prevail_bin", return_value=Path(sys.executable)
                    ),
                    redirect_stdout(io.StringIO()),
                    redirect_stderr(io.StringIO()),
                ):
                    result = pub.main(
                        [
                            "--firmware",
                            str(firmware),
                            "--tag",
                            "v1",
                            "--out",
                            str(out),
                            option,
                        ]
                    )
                self.assertEqual(result, 0)
                self.assertTrue((out / "libbpf-mcu-artifacts-v1.tar.gz").is_file())
                self.assertFalse(
                    any(c[:3] == ["gh", "release", "create"] for c in calls)
                )
                if option == "--package-only":
                    self.assertFalse(any(c[0] == "gh" for c in calls))

    def test_release_preflight_and_publication_failures(self):
        for failure in (
            "dirty",
            "nonmain",
            "tag",
            "auth",
            "tool",
            "build",
            "build2",
            "build3",
            "build4",
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
                calls = []

                def run(args, **kwargs):
                    calls.append(args)
                    if args[:4] == ["git", "remote", "get-url", "origin"]:
                        return SimpleNamespace(
                            stdout="git@github.com:nan-mu/libbpf-mcu.git",
                            stderr="",
                            returncode=0,
                        )
                    if failure == "tag_race" and args[:2] == ["gh", "api"]:
                        raise pub.PublishError("reference already exists")
                    if failure == "auth" and args[:3] == ["gh", "auth", "status"]:
                        raise pub.PublishError("auth failed")
                    if args[0] == sys.executable and failure in (
                        "build",
                        "build2",
                        "build3",
                        "build4",
                    ):
                        count = sum(c[0] == sys.executable for c in calls)
                        if (
                            count
                            == {"build": 1, "build2": 2, "build3": 3, "build4": 4}[
                                failure
                            ]
                        ):
                            raise pub.PublishError("compiler failed")
                    if (
                        failure == "verification"
                        and args[0] == sys.executable
                        and sum(c[0] == sys.executable for c in calls) == 4
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
                            "abc"
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

                answer = "no" if failure == "confirmation" else "v1 abc"

                def confirm(prompt):
                    self.assertIn("github.com/nan-mu/libbpf-mcu", prompt)
                    if failure == "firmware_change":
                        firmware.write_bytes(b"changed")
                    return answer

                with (
                    patch.object(pub, "run", side_effect=run),
                    patch.object(
                        build, "_default_inputs", return_value=[Path("firewall.c")]
                    ),
                    patch.object(build, "ensure_tool"),
                    patch.object(build, "load_mem_map_from_firmware"),
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
                    redirect_stderr(io.StringIO()),
                ):
                    result = pub.main(
                        [
                            "--firmware",
                            str(firmware),
                            "--tag",
                            "v1",
                            "--out",
                            str(tmp / "out"),
                        ]
                    )
                self.assertEqual(result, 0 if failure == "success" else 1)
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
                        uploads[0][uploads[0].index("--target") + 1], "abc"
                    )
                    self.assertIn("--verify-tag", uploads[0])

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
                        "--firmware",
                        str(root / "missing"),
                        "--tag",
                        "v1",
                        "--package-only",
                    ]
                ),
                1,
            )
            firmware = root / "f"
            firmware.write_bytes(b"x")
            self.assertEqual(
                pub.main(
                    [
                        "--firmware",
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
