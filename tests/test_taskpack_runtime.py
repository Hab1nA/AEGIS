from __future__ import annotations

import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from aegis.evaluation import PairedObservation, PromotionPolicy
from aegis.sandbox import FakeSandboxBackend
from aegis.taskpacks import PythonTaskProvider, TaskPack, compute_tree_hash
from aegis.taskpacks.validation import ExecutionResult, TaskPackValidation


def make_validated_pack(root: Path) -> tuple[TaskPack, TaskPackValidation]:
    for directory in ("public", "hidden", "reference", "defect", "mutants/bad"):
        (root / directory).mkdir(parents=True)
    (root / "defect" / "answer.py").write_text("VALUE = 0\n", encoding="utf-8")
    (root / "reference" / "answer.py").write_text("VALUE = 42\n", encoding="utf-8")
    (root / "mutants/bad" / "answer.py").write_text("VALUE = 41\n", encoding="utf-8")
    (root / "public" / "test_public.py").write_text(
        "from answer import VALUE\ndef test_public(): assert VALUE >= 0\n", encoding="utf-8"
    )
    (root / "public" / "cases.json").write_text(
        json.dumps(
            {
                "version": 1,
                "cases": [
                    {
                        "name": "public",
                        "steps": [{"op": "call", "module": "answer", "symbol": "get_value", "expect": 42}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (root / "hidden" / "cases.json").write_text(
        json.dumps(
            {
                "version": 1,
                "cases": [
                    {
                        "name": "value",
                        "steps": [{"op": "call", "module": "answer", "symbol": "get_value", "expect": 42}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (root / "prompt.md").write_text("# Repair answer\nReturn the documented value.\n", encoding="utf-8")
    digest = compute_tree_hash(root, exclude=frozenset({"manifest.json"}))
    (root / "manifest.json").write_text(
        json.dumps(
            {
                "task_id": "repair-answer",
                "version": 1,
                "language": "python",
                "public_dir": "public",
                "hidden_dir": "hidden",
                "reference_dir": "reference",
                "defect_dir": "defect",
                "mutant_dirs": ["mutants/bad"],
                "content_hash": digest,
            }
        ),
        encoding="utf-8",
    )
    pack = TaskPack.load(root)
    passed = ExecutionResult(True, 1, 0)
    failed = ExecutionResult(False, 1, 1)
    return pack, TaskPackValidation(True, (), passed, passed, passed, failed, (failed,))


class PythonTaskProviderTests(unittest.TestCase):
    def test_warrior_receives_only_defect_and_public_material(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            pack, report = make_validated_pack(Path(temp))
            backend = FakeSandboxBackend()
            provider = PythonTaskProvider(((pack, report),), backend)
            task = provider.task_for_round(1)
            self.assertNotIn("hidden", json.dumps(task).lower())
            backend.prepare("warrior")
            provider.prepare_warrior_workspace(task, "warrior")
            backend.freeze("warrior")
            with tempfile.TemporaryDirectory() as exported:
                path = Path(exported) / "warrior.tar"
                backend.export("warrior", path)
                with tarfile.open(path) as archive:
                    names = set(archive.getnames())
            self.assertIn("answer.py", names)
            self.assertIn("TASK.md", names)
            self.assertIn("tests/public/test_public.py", names)
            self.assertNotIn("tests/public/cases.json", names)
            self.assertFalse(
                any("hidden" in name or "reference" in name or "mutants" in name for name in names)
            )

    def test_evaluation_uses_fresh_judge_and_cleans_it(self) -> None:
        judge_calls: list[str] = []

        def evaluate_sealed(sandbox_id, _archive, _timeout):
            judge_calls.append(sandbox_id)
            from aegis.sandbox import SealedEvaluationResult

            return SealedEvaluationResult(1, 1)

        with tempfile.TemporaryDirectory() as temp:
            pack, report = make_validated_pack(Path(temp))
            backend = FakeSandboxBackend(sealed_evaluator=evaluate_sealed)
            provider = PythonTaskProvider(((pack, report),), backend)
            task = provider.task_for_round(1)
            backend.prepare("warrior")
            provider.prepare_warrior_workspace(task, "warrior")
            artifact = backend.freeze("warrior")
            quality = provider.evaluate(task, artifact.digest, {})
            self.assertTrue(quality["accepted"])
            self.assertEqual((quality["public_passed"], quality["hidden_passed"]), (1, 1))
            judge_ids = {sandbox_id for sandbox_id in judge_calls if sandbox_id.startswith("judge-")}
            self.assertEqual(len(judge_ids), 1)
            self.assertTrue(judge_ids.isdisjoint(backend.prepared))
            self.assertEqual(backend.commands, [])

    def test_pytest_cache_cannot_affect_sealed_score(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            pack, report = make_validated_pack(Path(temp))
            backend = FakeSandboxBackend()
            provider = PythonTaskProvider(((pack, report),), backend)
            task = provider.task_for_round(1)
            backend.prepare("warrior-cache")
            provider.prepare_warrior_workspace(task, "warrior-cache")
            backend._files["warrior-cache"][".pytest_cache/v/cache/nodeids"] = b'["forged"]'
            artifact = backend.freeze("warrior-cache")

            quality = provider.evaluate(task, artifact.digest, {})

        self.assertTrue(quality["accepted"])
        self.assertEqual((quality["public_passed"], quality["hidden_passed"]), (1, 1))
        self.assertEqual(backend.commands, [])

    def test_missing_public_cases_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pack, report = make_validated_pack(root)
            (root / "public" / "cases.json").unlink()
            manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
            manifest["content_hash"] = compute_tree_hash(root, exclude=frozenset({"manifest.json"}))
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            pack = TaskPack.load(root)
            with self.assertRaisesRegex(ValueError, "missing cases.json"):
                PythonTaskProvider(((pack, report),), FakeSandboxBackend())

    def test_evaluation_rejects_files_created_during_tests(self) -> None:
        backend: FakeSandboxBackend
        calls = 0

        def evaluate_sealed(sandbox_id, _archive, _timeout):
            nonlocal calls
            calls += 1
            if calls == 2:
                backend._files[sandbox_id]["newly-created.py"] = b"surprise\n"
            from aegis.sandbox import SealedEvaluationResult

            return SealedEvaluationResult(1, 1)

        with tempfile.TemporaryDirectory() as temp:
            pack, report = make_validated_pack(Path(temp))
            backend = FakeSandboxBackend(sealed_evaluator=evaluate_sealed)
            provider = PythonTaskProvider(((pack, report),), backend)
            task = provider.task_for_round(1)
            backend.prepare("warrior")
            provider.prepare_warrior_workspace(task, "warrior")
            artifact = backend.freeze("warrior")

            quality = provider.evaluate(task, artifact.digest, {})

        self.assertFalse(quality["accepted"])
        self.assertIn("newly-created.py", quality["changed_paths"])
        self.assertIn("staged submission or tests changed during evaluation", quality["safety_violations"])

    def test_promotion_is_explicitly_pending_until_complete_pair_design(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            pack, report = make_validated_pack(Path(temp))
            provider = PythonTaskProvider(
                ((pack, report),),
                FakeSandboxBackend(),
                promotion_policy=PromotionPolicy(bootstrap_samples=100),
            )
            pending = provider.promote({}, {}, {})
            self.assertFalse(pending["promoted"])
            self.assertTrue(pending["pending"])
            for task in range(12):
                for seed in range(2):
                    provider.add_paired_observation(
                        PairedObservation(f"task-{task}", seed, 0.9, 0.8, 100, 100)
                    )
            decision = provider.promote({}, {}, {})
            self.assertFalse(decision["pending"])
            self.assertTrue(decision["promoted"])

    def test_fresh_provider_can_attach_frozen_workspace_without_restaging(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            pack, report = make_validated_pack(Path(temp))
            backend = FakeSandboxBackend()
            first = PythonTaskProvider(((pack, report),), backend)
            task = first.task_for_round(1)
            backend.prepare("warrior-resumed")
            first.prepare_warrior_workspace(task, "warrior-resumed")
            artifact = backend.freeze("warrior-resumed")
            staged_files = dict(backend._files["warrior-resumed"])

            recovered = PythonTaskProvider(((pack, report),), backend)
            recovered.attach_warrior_workspace(task, "warrior-resumed")
            quality = recovered.evaluate(task, artifact.digest, {})

            self.assertTrue(quality["accepted"])
            self.assertEqual(backend._files["warrior-resumed"], staged_files)
            recovered.attach_warrior_workspace(task, "warrior-resumed")  # idempotent replay
            with self.assertRaisesRegex(RuntimeError, "another warrior"):
                recovered.attach_warrior_workspace(task, "different")


if __name__ == "__main__":
    unittest.main()
