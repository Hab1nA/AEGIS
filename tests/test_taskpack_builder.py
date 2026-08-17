from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from aegis.dynamic_tasks import (
    DynamicTaskOrigin,
    DynamicTaskRegistry,
    DynamicTaskStatus,
    TaskForge,
)
from aegis.dynamic_tasks.builder import (
    TASK_SPEC_MAX_CASES,
    TASK_SPEC_MAX_MUTANTS,
    TaskPackBuilder,
    TaskSpec,
    TaskSpecError,
)
from aegis.taskpacks.builtin import load_builtin_python_taskpacks
from aegis.taskpacks.manifest import TaskPack
from aegis.taskpacks.validation import ExecutionResult


class AnchorRunner:
    """Deterministic validation runner: reference passes, defect/mutants fail."""

    def run(self, pack, implementation_dir: str, suite: str) -> ExecutionResult:
        passed = implementation_dir == pack.manifest.reference_dir
        return ExecutionResult(
            passed=passed,
            tests_run=1,
            exit_code=0 if passed else 1,
        )


class EverythingPassesRunner:
    """Deterministic runner that never detects defects or mutants."""

    def run(self, pack, implementation_dir: str, suite: str) -> ExecutionResult:
        return ExecutionResult(
            passed=True,
            tests_run=1,
            exit_code=0,
        )


def sample_spec(task_id: str = "dynamic-builder-test") -> dict[str, object]:
    source = sorted(
        load_builtin_python_taskpacks(), key=lambda item: item.manifest.task_id
    )[0]
    return {
        "task_id": task_id,
        "prompt": (source.root / "prompt.md").read_text(encoding="utf-8"),
        "public_cases": json.loads(
            (source.root / "public" / "cases.json").read_text(encoding="utf-8")
        ),
        "public_test": (source.root / "public" / "test_solution.py").read_text(
            encoding="utf-8"
        ),
        "hidden_cases": json.loads(
            (source.root / "hidden" / "cases.json").read_text(encoding="utf-8")
        ),
        "reference_solution": (source.root / "reference" / "solution.py").read_text(
            encoding="utf-8"
        ),
        "defect_solution": (source.root / "defect" / "solution.py").read_text(
            encoding="utf-8"
        ),
        "mutants": [
            {"name": path.parent.name, "solution": path.read_text(encoding="utf-8")}
            for path in sorted((source.root / "mutants").glob("*/solution.py"))
        ],
    }


class TaskPackBuilderTests(unittest.TestCase):
    def test_spec_parses_and_materializes_canonical_layout(self) -> None:
        spec = TaskSpec.from_mapping(sample_spec())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            registry = DynamicTaskRegistry(root / "tasks.sqlite3")
            try:
                builder = TaskPackBuilder(registry, AnchorRunner())
                pack = builder.materialize(spec, root)
                TaskPack.load(pack.root)
                expected = {
                    "manifest.json",
                    "prompt.md",
                    "public/cases.json",
                    "public/test_solution.py",
                    "hidden/cases.json",
                    "reference/solution.py",
                    "defect/solution.py",
                    f"mutants/{spec.mutants[0].name}/solution.py",
                }
                actual = {
                    path.relative_to(pack.root).as_posix()
                    for path in pack.root.rglob("*")
                    if path.is_file()
                }
                self.assertEqual(actual, expected)
                self.assertEqual(pack.manifest.task_id, spec.task_id)
                self.assertEqual(
                    tuple(pack.manifest.mutant_dirs),
                    tuple(f"mutants/{item.name}" for item in spec.mutants),
                )
                self.assertFalse(any("__pycache__" in item for item in actual))
            finally:
                registry.close()

    def test_from_mapping_rejects_malformed_specs(self) -> None:
        valid = sample_spec()
        missing = dict(valid)
        del missing["prompt"]
        with self.assertRaises(TaskSpecError):
            TaskSpec.from_mapping(missing)
        unknown = dict(valid)
        unknown["extra"] = True
        with self.assertRaises(TaskSpecError):
            TaskSpec.from_mapping(unknown)
        bad_slug = dict(valid)
        bad_slug["task_id"] = "1bad-slug"
        with self.assertRaises(TaskSpecError):
            TaskSpec.from_mapping(bad_slug)
        bad_python = dict(valid)
        bad_python["reference_solution"] = "def broken(:"
        with self.assertRaises(TaskSpecError):
            TaskSpec.from_mapping(bad_python)
        empty_prompt = dict(valid)
        empty_prompt["prompt"] = "   "
        with self.assertRaises(TaskSpecError):
            TaskSpec.from_mapping(empty_prompt)
        bad_cases = dict(valid)
        bad_cases["public_cases"] = {"version": 1, "cases": [{}] * (TASK_SPEC_MAX_CASES + 1)}
        with self.assertRaises(TaskSpecError):
            TaskSpec.from_mapping(bad_cases)
        empty_cases = dict(valid)
        empty_cases["public_cases"] = {"version": 1, "cases": []}
        with self.assertRaises(TaskSpecError):
            TaskSpec.from_mapping(empty_cases)
        no_mutants = dict(valid)
        no_mutants["mutants"] = []
        with self.assertRaises(TaskSpecError):
            TaskSpec.from_mapping(no_mutants)
        duplicate_mutants = dict(valid)
        duplicate_mutants["mutants"] = [
            {"name": "same", "solution": "x = 1\n"},
            {"name": "same", "solution": "y = 2\n"},
        ]
        with self.assertRaises(TaskSpecError):
            TaskSpec.from_mapping(duplicate_mutants)
        too_many_mutants = dict(valid)
        too_many_mutants["mutants"] = [
            {"name": f"m{i}", "solution": "x = 1\n"}
            for i in range(TASK_SPEC_MAX_MUTANTS + 1)
        ]
        with self.assertRaises(TaskSpecError):
            TaskSpec.from_mapping(too_many_mutants)

    def test_preflight_rejects_builtin_and_registered_task_ids(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            registry = DynamicTaskRegistry(root / "tasks.sqlite3")
            try:
                builder = TaskPackBuilder(registry, AnchorRunner())
                with self.assertRaises(TaskSpecError):
                    builder.preflight_task_id("python-clamp-range")
                spec = TaskSpec.from_mapping(sample_spec("registered-dynamic-task"))
                builder.commit(
                    spec,
                    creator_generation=1,
                    source_spec_id="test:builder",
                    source_evidence_ids=("test:builder",),
                    holdout_delay=1,
                )
                with self.assertRaises(TaskSpecError):
                    builder.preflight_task_id("registered-dynamic-task")
            finally:
                registry.close()

    def test_dry_run_reports_validation_feedback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            registry = DynamicTaskRegistry(root / "tasks.sqlite3")
            try:
                builder = TaskPackBuilder(registry, AnchorRunner())
                valid, reasons = builder.dry_run(TaskSpec.from_mapping(sample_spec()))
                self.assertTrue(valid)
                self.assertEqual(reasons, ())
                broken = sample_spec()
                broken["defect_solution"] = broken["reference_solution"]
                permissive = TaskPackBuilder(registry, EverythingPassesRunner())
                valid, reasons = permissive.dry_run(TaskSpec.from_mapping(broken))
                self.assertFalse(valid)
                self.assertTrue(
                    any("defect implementation is not detected" in item for item in reasons)
                )
            finally:
                registry.close()

    def test_commit_registers_dynamic_task_and_deduplicates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            registry = DynamicTaskRegistry(root / "tasks.sqlite3")
            try:
                builder = TaskPackBuilder(registry, AnchorRunner())
                spec = TaskSpec.from_mapping(sample_spec())
                record = builder.commit(
                    spec,
                    creator_generation=1,
                    source_spec_id="test:builder",
                    source_evidence_ids=("test:builder",),
                    holdout_delay=1,
                )
                self.assertIs(record.origin, DynamicTaskOrigin.DYNAMIC)
                self.assertIs(record.status, DynamicTaskStatus.QUARANTINED)
                with self.assertRaises(TaskSpecError):
                    builder.commit(
                        spec,
                        creator_generation=2,
                        source_spec_id="test:builder",
                        source_evidence_ids=("test:builder",),
                        holdout_delay=1,
                    )
                dynamic = [
                    item
                    for item in registry.records()
                    if item.origin is DynamicTaskOrigin.DYNAMIC
                ]
                self.assertEqual(len(dynamic), 1)
            finally:
                registry.close()


if __name__ == "__main__":
    unittest.main()
