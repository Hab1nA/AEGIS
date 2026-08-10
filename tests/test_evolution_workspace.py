from __future__ import annotations

import base64
import hashlib
import io
import os
import tarfile
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory

from aegis.evolution_workspace import (
    EVOLUTION_WORKFLOW_ENTRY,
    CandidatePatchArtifact,
    ChangeKind,
    EvolutionPath,
    EvolutionPolicy,
    EvolutionWorkspace,
    ValidationCommand,
)
from aegis.sandbox.fake import FakeSandboxBackend
from aegis.sandbox.types import WorkspaceAccessRule


def tar_bytes(files: dict[str, bytes], *, symlink: str | None = None) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for path, content in sorted(files.items()):
            info = tarfile.TarInfo(path)
            info.size = len(content)
            info.mtime = 0
            archive.addfile(info, io.BytesIO(content))
        if symlink is not None:
            info = tarfile.TarInfo(symlink)
            info.type = tarfile.SYMTYPE
            info.linkname = "../outside"
            archive.addfile(info)
    return output.getvalue()


def directory_tar(path: str) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        info = tarfile.TarInfo(path)
        info.type = tarfile.DIRTYPE
        archive.addfile(info)
    return output.getvalue()


class EvolutionWorkspaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "adaptive").mkdir()
        (self.root / "adaptive" / "logic.py").write_text("VALUE = 1\n", encoding="utf-8")
        (self.root / "control").mkdir()
        (self.root / "control" / "sandbox.py").write_text("TRUSTED = True\n", encoding="utf-8")
        self.control_content = (self.root / "control" / "sandbox.py").read_bytes()
        self.policy = EvolutionPolicy(
            evolvable_paths=(EvolutionPath("adaptive", recursive=True),),
            required_effective_paths=(),
            read_only_context_paths=(EvolutionPath("control", recursive=True),),
            protected_paths=("control",),
            max_files=10,
            max_file_bytes=1_024,
            max_total_bytes=8_192,
            validation_commands=(
                ValidationCommand(("python", "-m", "pytest", "-q"), timeout_seconds=120),
            ),
        )
        self.workspace = EvolutionWorkspace(self.root, self.policy)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_snapshot_is_deterministic_and_staged_through_backend(self) -> None:
        first = self.workspace.create_snapshot()
        second = self.workspace.create_snapshot()
        self.assertEqual(first, second)
        self.assertEqual(
            [item.path for item in first.files],
            ["adaptive/logic.py", "control/sandbox.py"],
        )
        self.assertIn(b"TRUSTED", first.archive)
        backend = FakeSandboxBackend()
        backend.prepare("evolution-1")
        receipt = self.workspace.stage_snapshot(backend, "evolution-1", first)
        self.assertEqual(receipt.digest, first.archive_sha256)

    def test_snapshot_from_archive_preserves_verified_champion_bytes(self) -> None:
        source = tar_bytes(
            {
                "adaptive/logic.py": b"VALUE = 3\n",
                "control/sandbox.py": self.control_content,
            }
        )
        digest = hashlib.sha256(source).hexdigest()
        snapshot = self.workspace.snapshot_from_archive(
            base64.b64encode(source).decode("ascii"), digest
        )
        self.assertEqual(snapshot.archive, source)
        self.assertEqual(snapshot.archive_sha256, digest)
        self.assertEqual(
            [item.path for item in snapshot.files],
            ["adaptive/logic.py", "control/sandbox.py"],
        )
        with self.assertRaisesRegex(ValueError, "digest"):
            self.workspace.snapshot_from_archive(source, "0" * 64)
        with self.assertRaisesRegex(ValueError, "base64"):
            self.workspace.snapshot_from_archive("not base64", digest)

    def test_default_policy_stages_complete_build_and_test_context(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src" / "aegis" / "sandbox").mkdir(parents=True)
            (root / "src" / "aegis" / "evolvable").mkdir()
            (root / "tests").mkdir()
            (root / "docs").mkdir()
            for name in ("public", "hidden", "reference", "defect", "mutants"):
                (root / "taskpacks" / "python" / "sample" / name).mkdir(parents=True)
            (root / ".git").mkdir()
            (root / ".tmp" / "campaign").mkdir(parents=True)
            (root / ".venv").mkdir()
            (root / "pyproject.toml").write_text("[build-system]\n", encoding="utf-8")
            (root / "docs" / "architecture.md").write_text("full context\n", encoding="utf-8")
            (root / ".git" / "config").write_text("host metadata\n", encoding="utf-8")
            (root / ".tmp" / "campaign" / "events.sqlite3-wal").write_bytes(b"runtime state")
            (root / ".venv" / "secret").write_text("not context\n", encoding="utf-8")
            (root / "src" / "aegis" / "strategy.py").write_text("ADAPTIVE = True\n", encoding="utf-8")
            (root / "src" / "aegis" / "challenges.py").write_text("", encoding="utf-8")
            (root / "src" / "aegis" / "knowledge.py").write_text("", encoding="utf-8")
            (root / EVOLUTION_WORKFLOW_ENTRY).write_text("WORKFLOW = True\n", encoding="utf-8")
            (root / "src" / "aegis" / "sandbox" / "agent.py").write_text(
                "CONTROL = True\n", encoding="utf-8"
            )
            (root / "tests" / "test_all.py").write_text("def test_all(): pass\n", encoding="utf-8")
            (root / "taskpacks" / "python" / "sample" / "prompt.md").write_text(
                "public prompt\n", encoding="utf-8"
            )
            (root / "taskpacks" / "python" / "sample" / "public" / "cases.json").write_text(
                "[]\n", encoding="utf-8"
            )
            for name in ("hidden", "reference", "defect", "mutants"):
                (root / "taskpacks" / "python" / "sample" / name / "secret.txt").write_text(
                    f"{name} secret\n", encoding="utf-8"
                )
            (root / "taskpacks" / "python" / "sample.validation.json").write_text(
                "{}\n", encoding="utf-8"
            )
            workspace = EvolutionWorkspace(root)
            snapshot = workspace.create_snapshot()
            self.assertEqual(
                [item.path for item in snapshot.files],
                [
                    "docs/architecture.md",
                    "pyproject.toml",
                    "src/aegis/challenges.py",
                    "src/aegis/evolvable/workflow.py",
                    "src/aegis/knowledge.py",
                    "src/aegis/sandbox/agent.py",
                    "src/aegis/strategy.py",
                    "taskpacks/python/sample/prompt.md",
                    "taskpacks/python/sample/public/cases.json",
                    "tests/test_all.py",
                ],
            )
            backend = FakeSandboxBackend()
            backend.prepare("complete-context")
            receipt = workspace.stage_snapshot(backend, "complete-context", snapshot)
            self.assertEqual((receipt.entries, receipt.digest), (10, snapshot.archive_sha256))
            self.assertEqual(
                backend.workspace_access["complete-context"],
                (WorkspaceAccessRule("src/aegis/evolvable", True),),
            )
            self.assertEqual(
                workspace.policy.validation_commands[0].argv,
                (
                    "python",
                    "-B",
                    "-m",
                    "pytest",
                    "-q",
                    "-p",
                    "no:cacheprovider",
                    "--ignore=tests/test_builtin_taskpacks.py",
                ),
            )

    def test_real_repository_snapshot_excludes_all_held_out_taskpack_assets(self) -> None:
        root = Path(__file__).resolve().parents[1]
        snapshot = EvolutionWorkspace(root).create_snapshot()
        paths = {item.path for item in snapshot.files}
        self.assertTrue(any("/public/" in path for path in paths if path.startswith("taskpacks/")))
        self.assertTrue(any(path.endswith("/prompt.md") for path in paths))
        forbidden = {"hidden", "reference", "defect", "mutants"}
        leaked = [
            path
            for path in paths
            if path.endswith(".validation.json") or forbidden.intersection(PurePosixPath(path).parts)
        ]
        self.assertEqual(leaked, [])

    def test_default_policy_rejects_inert_only_and_unchanged_candidates(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            workflow = root / EVOLUTION_WORKFLOW_ENTRY
            workflow.parent.mkdir(parents=True)
            workflow.write_text("WORKFLOW = 1\n", encoding="utf-8")
            strategy = root / "src" / "aegis" / "strategy.py"
            strategy.write_text("STRATEGY = 1\n", encoding="utf-8")
            strategy_content = strategy.read_bytes()
            workspace = EvolutionWorkspace(root)
            baseline = workspace.create_snapshot()

            with self.assertRaisesRegex(ValueError, "modified read-only"):
                workspace.candidate_from_archive(
                    baseline,
                    tar_bytes(
                        {
                            EVOLUTION_WORKFLOW_ENTRY: b"WORKFLOW = 1\n",
                            "src/aegis/strategy.py": b"STRATEGY = 2\n",
                        }
                    ),
                )
            with self.assertRaisesRegex(ValueError, "required effective path"):
                workspace.candidate_from_archive(baseline, baseline.archive)

            artifact = workspace.candidate_from_archive(
                baseline,
                tar_bytes(
                    {
                        EVOLUTION_WORKFLOW_ENTRY: b"WORKFLOW = 2\n",
                        "src/aegis/evolvable/research_helper.py": b"QUERY = 'current practice'\n",
                        "src/aegis/strategy.py": strategy_content,
                    }
                ),
            )
            self.assertEqual(
                [item.path for item in artifact.changes],
                ["src/aegis/evolvable/research_helper.py", EVOLUTION_WORKFLOW_ENTRY],
            )

    def test_candidate_diff_is_frozen_content_addressed_and_does_not_modify_host(self) -> None:
        baseline = self.workspace.create_snapshot()
        candidate = tar_bytes(
            {
                "adaptive/logic.py": b"VALUE = 2\n",
                "adaptive/new.py": b"NEW = True\n",
                "control/sandbox.py": self.control_content,
            }
        )
        artifact = self.workspace.candidate_from_archive(baseline, candidate)
        self.assertIsInstance(artifact, CandidatePatchArtifact)
        self.assertEqual(
            [(item.path, item.kind) for item in artifact.changes],
            [
                ("adaptive/logic.py", ChangeKind.MODIFIED),
                ("adaptive/new.py", ChangeKind.ADDED),
            ],
        )
        self.assertEqual(
            artifact.validation_commands[0].to_command_spec().argv,
            ("python", "-m", "pytest", "-q"),
        )
        self.assertEqual((self.root / "adaptive" / "logic.py").read_text(), "VALUE = 1\n")
        self.assertFalse((self.root / "adaptive" / "new.py").exists())
        with self.assertRaises(FrozenInstanceError):
            artifact.changes = ()  # type: ignore[misc]
        with self.assertRaises(ValueError):
            replace(artifact, artifact_id="candidate-sha256:" + "0" * 64)

    def test_stage_configures_only_evolvable_subtree_as_writable(self) -> None:
        baseline = self.workspace.create_snapshot()
        backend = FakeSandboxBackend()
        backend.prepare("bounded-write")
        self.workspace.stage_snapshot(backend, "bounded-write", baseline)
        rules = backend.workspace_access["bounded-write"]
        self.assertEqual([(rule.path, rule.recursive) for rule in rules], [("adaptive", True)])
        self.assertNotIn("control", {rule.path for rule in rules})

    def test_deleted_files_are_reported_per_file(self) -> None:
        baseline = self.workspace.create_snapshot()
        artifact = self.workspace.candidate_from_archive(
            baseline,
            tar_bytes({"control/sandbox.py": self.control_content}),
        )
        self.assertEqual(len(artifact.changes), 1)
        self.assertEqual(artifact.changes[0].kind, ChangeKind.DELETED)
        self.assertIsNone(artifact.changes[0].candidate_sha256)

    def test_candidate_rejects_protected_traversal_symlink_and_oversize(self) -> None:
        baseline = self.workspace.create_snapshot()
        invalid = (
            tar_bytes({"control/sandbox.py": b"TRUSTED = False\n"}),
            tar_bytes({"../escape.py": b"bad"}),
            tar_bytes({}, symlink="adaptive/link"),
            tar_bytes({"adaptive/large.py": b"x" * 1_025}),
            directory_tar("control"),
        )
        for archive in invalid:
            with self.subTest(), self.assertRaises(ValueError):
                self.workspace.candidate_from_archive(baseline, archive)

    def test_read_only_context_must_be_preserved_byte_for_byte(self) -> None:
        baseline = self.workspace.create_snapshot()
        with self.assertRaisesRegex(ValueError, "modified read-only"):
            self.workspace.candidate_from_archive(
                baseline,
                tar_bytes(
                    {
                        "adaptive/logic.py": b"VALUE = 1\n",
                        "control/sandbox.py": b"TRUSTED = False\n",
                    }
                ),
            )
        with self.assertRaisesRegex(ValueError, "deleted read-only"):
            self.workspace.candidate_from_archive(
                baseline,
                tar_bytes({"adaptive/logic.py": b"VALUE = 1\n"}),
            )

    def test_new_file_under_read_only_context_is_rejected(self) -> None:
        baseline = self.workspace.create_snapshot()
        with self.assertRaisesRegex(ValueError, "added a non-evolvable"):
            self.workspace.candidate_from_archive(
                baseline,
                tar_bytes(
                    {
                        "adaptive/logic.py": b"VALUE = 1\n",
                        "control/sandbox.py": self.control_content,
                        "control/new.py": b"not allowed\n",
                    }
                ),
            )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_snapshot_rejects_symlink(self) -> None:
        link = self.root / "adaptive" / "link.py"
        try:
            link.symlink_to(self.root / "control" / "sandbox.py")
        except OSError as exc:
            self.skipTest(f"cannot create symlink: {exc}")
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.workspace.create_snapshot()

    def test_policy_rejects_overlap_unsafe_paths_and_invalid_limits(self) -> None:
        with self.assertRaisesRegex(ValueError, "overlaps"):
            EvolutionPolicy(
                evolvable_paths=(EvolutionPath("src", recursive=True),),
                required_effective_paths=(),
                protected_paths=("src/aegis/sandbox",),
            )
        for path in ("../escape", "/absolute", "a\\b", "a/./b"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                EvolutionPath(path)
        with self.assertRaises(ValueError):
            EvolutionPolicy(
                evolvable_paths=(EvolutionPath("adaptive", recursive=True),),
                required_effective_paths=(),
                protected_paths=(),
                max_file_bytes=100,
                max_total_bytes=50,
            )
        with self.assertRaisesRegex(ValueError, "required_effective_paths"):
            EvolutionPolicy(evolvable_paths=(EvolutionPath("adaptive", recursive=True),))

    def test_collect_candidate_uses_freeze_and_export_without_host_execution(self) -> None:
        baseline = self.workspace.create_snapshot()
        backend = FakeSandboxBackend()
        backend.prepare("candidate")
        self.workspace.stage_snapshot(backend, "candidate", baseline)
        with TemporaryDirectory() as export_directory:
            destination = Path(export_directory) / "candidate.tar"
            artifact = self.workspace.collect_candidate(backend, "candidate", baseline, destination)
            self.assertEqual(artifact.changes, ())
            self.assertEqual(backend.commands, [])
            self.assertTrue(destination.is_file())
            self.assertEqual((self.root / "adaptive" / "logic.py").read_text(), "VALUE = 1\n")

        other_backend = FakeSandboxBackend()
        other_backend.prepare("candidate-2")
        self.workspace.stage_snapshot(other_backend, "candidate-2", baseline)
        with self.assertRaisesRegex(ValueError, "outside"):
            self.workspace.collect_candidate(
                other_backend,
                "candidate-2",
                baseline,
                self.root / "must-not-write.tar",
            )
        self.assertFalse((self.root / "must-not-write.tar").exists())


if __name__ == "__main__":
    unittest.main()
