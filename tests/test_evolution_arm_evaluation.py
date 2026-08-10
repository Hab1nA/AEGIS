from __future__ import annotations

import base64
import hashlib
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from aegis.cycle_ports import _sealed_tasks
from aegis.dynamic_tasks import DynamicTaskRegistry, GenesisSeeder, TaskForge
from aegis.evolution.arm_evaluation import (
    build_cohort_workspace,
    evaluate_frozen_workspace,
    freeze_workspace_bytes,
    stage_cohort_workspace,
)
from aegis.sandbox.fake import FakeSandboxBackend
from aegis.sandbox.types import (
    CommandResult,
    CommandSpec,
    SealedEvaluationResult,
)
from tests.test_cycle_ports import AnchorRunner


class ArmEvaluationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._root = tempfile.TemporaryDirectory(prefix="aegis-arm-test-")
        self.root = Path(self._root.name)
        self.dynamic = DynamicTaskRegistry(self.root / "tasks.sqlite3")
        GenesisSeeder(self.dynamic, TaskForge(self.dynamic)).seed(AnchorRunner())
        self.cohort = self.dynamic.select_dynamic_cohort(2)
        self.tasks = _sealed_tasks(self.dynamic, self.cohort)
        self.task_ids = {item["task_id"] for item in self.tasks}
        self.assertIn("python-clamp-range", self.task_ids)

    def tearDown(self) -> None:
        self.dynamic.close()
        self._root.cleanup()

    def test_build_cohort_workspace_layout(self) -> None:
        workspace = build_cohort_workspace(self.dynamic, self.tasks)
        names: list[str] = []
        with tarfile.open(fileobj=io.BytesIO(workspace), mode="r:*") as archive:
            names = [member.name for member in archive.getmembers() if member.isfile()]
        self.assertTrue(
            any(name == "tasks/python-clamp-range/solution.py" for name in names)
        )
        self.assertTrue(
            any(name == "tasks/python-clamp-range/TASK.md" for name in names)
        )
        self.assertTrue(
            any(
                name.startswith("tasks/python-clamp-range/tests/public/")
                and name.endswith(".py")
                for name in names
            )
        )
        self.assertFalse(any(name.endswith("cases.json") for name in names))

    def test_stage_freeze_and_deterministic_score(self) -> None:
        sandbox = FakeSandboxBackend()
        workspace = build_cohort_workspace(self.dynamic, self.tasks)
        sandbox.prepare("arm-1")
        digest = stage_cohort_workspace(sandbox, "arm-1", workspace)
        self.assertEqual(digest, hashlib.sha256(workspace).hexdigest())
        frozen_digest, frozen = freeze_workspace_bytes(sandbox, "arm-1")
        self.assertEqual(frozen_digest, hashlib.sha256(frozen).hexdigest())

        def sealed_evaluator(
            sandbox_id: str, payload: bytes, timeout: float
        ) -> SealedEvaluationResult:
            del payload, timeout
            files = sandbox._files.get(sandbox_id, {})
            fixed = any(
                isinstance(content, bytes) and b"FIXED" in content
                for content in files.values()
            )
            return SealedEvaluationResult(1 if fixed else 0, 1)

        sandbox.sealed_evaluator = sealed_evaluator
        evaluation = evaluate_frozen_workspace(
            self.dynamic,
            sandbox,
            frozen,
            frozen_digest,
            self.tasks,
            namespace="arm-test",
        )
        self.assertEqual(evaluation.quality, 0.0)
        self.assertEqual(evaluation.total_tasks, len(self.tasks))
        self.assertTrue(evaluation.integrity_passed)

    def test_workspace_edit_improves_score(self) -> None:
        sandbox = FakeSandboxBackend()
        workspace = build_cohort_workspace(self.dynamic, self.tasks)
        sandbox.prepare("arm-1")
        stage_cohort_workspace(sandbox, "arm-1", workspace)

        def executor(sandbox_id: str, spec: CommandSpec) -> CommandResult:
            argv = spec.argv
            if (
                len(argv) == 5
                and argv[0] == "python3"
                and argv[1] == "-c"
                and "base64" in argv[2]
            ):
                sandbox._files.setdefault(sandbox_id, {})[argv[3]] = base64.b64decode(
                    argv[4], validate=True
                )
                return CommandResult(0, "1", "", 0.0)
            return CommandResult(0, "", "", 0.0)

        sandbox.executor = executor
        fixed = (
            b"def clamp(value, lower, upper):\n"
            b"    return min(max(value, lower), upper)  # FIXED\n"
        )
        sandbox.exec(
            "arm-1",
            CommandSpec(
                (
                    "python3",
                    "-c",
                    "import base64; path=sys.argv[3]",
                    "tasks/python-clamp-range/solution.py",
                    base64.b64encode(fixed).decode("ascii"),
                ),
                timeout_seconds=10,
            ),
        )
        frozen_digest, frozen = freeze_workspace_bytes(sandbox, "arm-1")

        def sealed_evaluator(
            sandbox_id: str, payload: bytes, timeout: float
        ) -> SealedEvaluationResult:
            del payload, timeout
            files = sandbox._files.get(sandbox_id, {})
            fixed_ok = any(
                isinstance(content, bytes) and b"FIXED" in content
                for content in files.values()
            )
            return SealedEvaluationResult(1 if fixed_ok else 0, 1)

        sandbox.sealed_evaluator = sealed_evaluator
        evaluation = evaluate_frozen_workspace(
            self.dynamic,
            sandbox,
            frozen,
            frozen_digest,
            self.tasks,
            namespace="arm-edit",
        )
        self.assertGreater(evaluation.quality, 0.0)
        self.assertTrue(evaluation.integrity_passed)

    def test_tampering_during_evaluation_fails_closed(self) -> None:
        sandbox = FakeSandboxBackend()
        workspace = build_cohort_workspace(self.dynamic, self.tasks)
        sandbox.prepare("arm-1")
        stage_cohort_workspace(sandbox, "arm-1", workspace)
        frozen_digest, frozen = freeze_workspace_bytes(sandbox, "arm-1")

        def tampering_evaluator(
            sandbox_id: str, payload: bytes, timeout: float
        ) -> SealedEvaluationResult:
            del payload, timeout
            sandbox._files.setdefault(sandbox_id, {})["tampered.txt"] = b"evil"
            return SealedEvaluationResult(1, 1)

        sandbox.sealed_evaluator = tampering_evaluator
        evaluation = evaluate_frozen_workspace(
            self.dynamic,
            sandbox,
            frozen,
            frozen_digest,
            self.tasks,
            namespace="arm-tamper",
        )
        self.assertFalse(evaluation.integrity_passed)
        self.assertTrue(
            any("changed during evaluation" in item for item in evaluation.safety_violations)
        )


if __name__ == "__main__":
    unittest.main()
