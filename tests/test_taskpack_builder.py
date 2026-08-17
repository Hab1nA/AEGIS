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
    public_cases = json.loads(
        (source.root / "public" / "cases.json").read_text(encoding="utf-8")
    )
    hidden_cases = json.loads(
        (source.root / "hidden" / "cases.json").read_text(encoding="utf-8")
    )
    hidden_names = [str(case["name"]) for case in hidden_cases["cases"]]
    clauses = [
        {
            "clause_id": "CONTRACT.GENERAL",
            "statement": "the implementation must satisfy the declared public contract",
            "input_partition": "all documented inputs",
            "expected_outcome": "documented result",
            "security_relevant": False,
        }
    ]
    clauses.extend(
        {
            "clause_id": f"CONTRACT.{index}",
            "statement": f"hidden contract {name}",
            "input_partition": str(name),
            "expected_outcome": "no violation",
            "security_relevant": False,
        }
        for index, name in enumerate(hidden_names, start=1)
    )
    for case in public_cases["cases"]:
        case["clause_ids"] = ["CONTRACT.GENERAL"]
    for index, case in enumerate(hidden_cases["cases"]):
        case["clause_ids"] = [f"CONTRACT.{index + 1}"]
    mutants = [
        {
            "name": path.parent.name,
            "solution": path.read_text(encoding="utf-8"),
            "clause_ids": ["CONTRACT.GENERAL"],
        }
        for path in sorted((source.root / "mutants").glob("*/solution.py"))
    ]
    return {
        "task_id": task_id,
        "prompt": (source.root / "prompt.md").read_text(encoding="utf-8"),
        "public_cases": public_cases,
        "public_test": (source.root / "public" / "test_solution.py").read_text(
            encoding="utf-8"
        ),
        "hidden_cases": hidden_cases,
        "reference_solution": (source.root / "reference" / "solution.py").read_text(
            encoding="utf-8"
        ),
        "defect_solution": (source.root / "defect" / "solution.py").read_text(
            encoding="utf-8"
        ),
        "mutants": mutants,
        "clauses": clauses,
        "defect_clause_ids": ["CONTRACT.GENERAL"],
    }


class TaskPackBuilderTests(unittest.TestCase):

    def test_spec_rejects_missing_clause_traceability(self) -> None:
        spec = sample_spec()
        no_clauses = dict(spec)
        no_clauses["clauses"] = []
        with self.assertRaises(TaskSpecError):
            TaskSpec.from_mapping(no_clauses)
        for case in spec["public_cases"]["cases"]:
            case.pop("clause_ids")
        with self.assertRaises(TaskSpecError):
            TaskSpec.from_mapping(spec)

    def test_spec_rejects_undeclared_clause_ids(self) -> None:
        spec = sample_spec()
        spec["defect_clause_ids"] = ["UNDECLARED.CLAUSE"]
        with self.assertRaises(TaskSpecError):
            TaskSpec.from_mapping(spec)
        spec = sample_spec()
        spec["hidden_cases"]["cases"][0]["clause_ids"] = ["UNDECLARED.CLAUSE"]
        with self.assertRaises(TaskSpecError):
            TaskSpec.from_mapping(spec)

    def test_spec_rejects_mutant_without_clause_traceability(self) -> None:
        spec = sample_spec()
        spec["mutants"][0]["clause_ids"] = []
        with self.assertRaises(TaskSpecError):
            TaskSpec.from_mapping(spec)

    def test_spec_clause_summary_reports_full_coverage(self) -> None:
        spec = TaskSpec.from_mapping(sample_spec())
        summary = spec.clause_summary()
        assert summary["coverage"]["public_cases"] == len(spec.public_cases["cases"])
        assert summary["coverage"]["hidden_cases"] == len(spec.hidden_cases["cases"])
        assert summary["coverage"]["defect"] is True
        assert summary["coverage"]["mutants"] == len(spec.mutants)
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
                    "contract.json",
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
