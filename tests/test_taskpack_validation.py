from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from aegis.taskpacks.manifest import TaskPack, compute_tree_hash
from aegis.taskpacks.validation import ExecutionResult, validate_taskpack


class FakeRunner:
    def __init__(self, results: dict[tuple[str, str], ExecutionResult]) -> None:
        self.results = results
        self.calls: list[tuple[str, str]] = []

    def run(self, pack, implementation_dir, suite):
        self.calls.append((implementation_dir, suite))
        return self.results[(implementation_dir, suite)]


def make_pack(root: Path, mutants: tuple[str, ...] = ("mutants/hardcoded",)) -> TaskPack:
    directories = ("public", "hidden", "reference", "defect", *mutants)
    for directory in directories:
        path = root / directory
        path.mkdir(parents=True)
        (path / "marker.py").write_text(f"# {directory}\n", encoding="utf-8")
    digest = compute_tree_hash(root, exclude=frozenset({"manifest.json"}))
    manifest = {
        "task_id": "python-edge-1",
        "version": 1,
        "language": "python",
        "public_dir": "public",
        "hidden_dir": "hidden",
        "reference_dir": "reference",
        "defect_dir": "defect",
        "mutant_dirs": list(mutants),
        "content_hash": digest,
    }
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return TaskPack.load(root)


class TaskPackTests(unittest.TestCase):
    def test_load_verifies_layout_and_content_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pack = make_pack(root)
            self.assertNotEqual(pack.public_path, pack.hidden_path)
            (root / "hidden" / "marker.py").write_text("tampered", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                TaskPack.load(root)

    def test_manifest_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_pack(root)
            data = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
            data["hidden_dir"] = "../hidden"
            (root / "manifest.json").write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unsafe"):
                TaskPack.load(root)

    def test_validation_accepts_effective_hidden_suite(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            pack = make_pack(Path(temp))
            passing = ExecutionResult(True, 3, 0)
            failing = ExecutionResult(False, 3, 1)
            runner = FakeRunner(
                {
                    ("reference", "public"): passing,
                    ("reference", "hidden"): passing,
                    ("defect", "public"): passing,
                    ("defect", "hidden"): failing,
                    ("mutants/hardcoded", "hidden"): failing,
                }
            )
            report = validate_taskpack(pack, runner)
            self.assertTrue(report.valid)
            self.assertEqual(len(runner.calls), 5)

    def test_validation_rejects_surviving_mutant(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            pack = make_pack(Path(temp))
            passing = ExecutionResult(True, 1, 0)
            failing = ExecutionResult(False, 1, 1)
            runner = FakeRunner(
                {
                    ("reference", "public"): passing,
                    ("reference", "hidden"): passing,
                    ("defect", "public"): passing,
                    ("defect", "hidden"): failing,
                    ("mutants/hardcoded", "hidden"): passing,
                }
            )
            report = validate_taskpack(pack, runner)
            self.assertFalse(report.valid)
            self.assertIn("does not kill mutants", report.reasons[0])


if __name__ == "__main__":
    unittest.main()
