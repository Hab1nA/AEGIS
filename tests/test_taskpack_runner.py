from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from aegis.sandbox import FakeSandboxBackend, SealedEvaluationResult
from aegis.sandbox.owned import OwnedSandboxBackend
from aegis.taskpacks import SandboxTaskPackRunner, validate_taskpack
from tests.test_taskpack_runtime import make_validated_pack


class SandboxTaskPackRunnerTests(unittest.TestCase):
    def test_validate_taskpack_runs_every_pair_in_a_fresh_sandbox(self) -> None:
        observed: list[tuple[str, frozenset[str], str]] = []
        backend: FakeSandboxBackend

        def evaluate_sealed(sandbox_id, _archive, _timeout):
            names = frozenset(backend._files[sandbox_id])
            suite = "tests/public" if b'"name":"public"' in _archive else "tests/hidden"
            observed.append((sandbox_id, names, suite))
            implementation = backend._files[sandbox_id]["marker.txt"].decode()
            should_pass = implementation == "reference" or (
                implementation == "defect" and suite == "tests/public"
            )
            return SealedEvaluationResult(1, 1) if should_pass else SealedEvaluationResult(0, 1, ("killed",))

        with tempfile.TemporaryDirectory() as temp:
            pack, _ = make_validated_pack(Path(temp))
            for name, value in (("reference", "reference"), ("defect", "defect"), ("mutants/bad", "mutant")):
                (pack.root / name / "marker.txt").write_text(value, encoding="utf-8")
            # Refresh the integrity-bound manifest after adding test markers.
            import json

            from aegis.taskpacks import compute_tree_hash

            manifest = json.loads((pack.root / "manifest.json").read_text(encoding="utf-8"))
            manifest["content_hash"] = compute_tree_hash(pack.root, exclude=frozenset({"manifest.json"}))
            (pack.root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            from aegis.taskpacks import TaskPack

            pack = TaskPack.load(pack.root)
            backend = FakeSandboxBackend(sealed_evaluator=evaluate_sealed)
            report = validate_taskpack(pack, SandboxTaskPackRunner(backend))

        self.assertTrue(report.valid)
        self.assertEqual(len(observed), 5)
        self.assertEqual(len({sandbox_id for sandbox_id, _, _ in observed}), 5)
        self.assertFalse(backend.prepared)
        for _, names, suite in observed:
            if suite == "tests/public":
                self.assertFalse(any(name.startswith("tests/hidden/") for name in names))
            else:
                self.assertFalse(any(name.startswith("tests/public/") for name in names))

    def test_doctor_failure_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            pack, _ = make_validated_pack(Path(temp))
            backend = FakeSandboxBackend(healthy=False)
            with self.assertRaisesRegex(RuntimeError, "doctor failed"):
                SandboxTaskPackRunner(backend).run(pack, pack.manifest.reference_dir, "public")
            self.assertFalse(backend.prepared)

    def test_executor_exception_still_destroys_temporary_sandbox(self) -> None:
        def explode(*_args):
            raise RuntimeError("runner exploded")

        with tempfile.TemporaryDirectory() as temp:
            pack, _ = make_validated_pack(Path(temp))
            backend = FakeSandboxBackend(sealed_evaluator=explode)
            with self.assertRaisesRegex(RuntimeError, "runner exploded"):
                SandboxTaskPackRunner(backend).run(pack, pack.manifest.reference_dir, "public")
            self.assertFalse(backend.prepared)

    def test_timeout_is_preserved_as_execution_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            pack, _ = make_validated_pack(Path(temp))
            backend = FakeSandboxBackend(
                sealed_evaluator=lambda *_: SealedEvaluationResult(0, 1, ("timeout",), timed_out=True),
            )
            result = SandboxTaskPackRunner(backend).run(pack, pack.manifest.reference_dir, "hidden")
            self.assertTrue(result.timed_out)
            self.assertFalse(result.passed)
            self.assertEqual(result.tests_run, 1)
            self.assertFalse(backend.prepared)

    def test_namespaced_validation_uses_durable_ownership(self) -> None:
        events: list[tuple[str, dict[str, object]]] = []
        with tempfile.TemporaryDirectory() as temp:
            pack, _ = make_validated_pack(Path(temp))
            backend = FakeSandboxBackend(
                sealed_evaluator=lambda *_: SealedEvaluationResult(1, 1),
            )
            owned = OwnedSandboxBackend(backend, lambda kind, payload: events.append((kind, payload)))
            SandboxTaskPackRunner(owned, id_namespace="campaign").run(
                pack, pack.manifest.reference_dir, "public"
            )

        intent = next(payload for kind, payload in events if kind == "sandbox_prepare_intent")
        self.assertTrue(str(intent["sandbox_id"]).startswith("validate-campaign-"))
        self.assertEqual(events[-1][0], "sandbox_destroyed")

    def test_long_namespaces_produce_bounded_distinct_sandbox_ids(self) -> None:
        observed: list[str] = []
        with tempfile.TemporaryDirectory() as temp:
            pack, _ = make_validated_pack(Path(temp))
            for suffix in ("alpha", "bravo"):
                events: list[tuple[str, dict[str, object]]] = []
                backend = FakeSandboxBackend(
                    sealed_evaluator=lambda *_: SealedEvaluationResult(1, 1),
                )
                owned = OwnedSandboxBackend(
                    backend,
                    lambda kind, payload: events.append((kind, payload)),
                )
                namespace = "autonomy-smoke-20260807-r2-preflight-" + suffix
                SandboxTaskPackRunner(owned, id_namespace=namespace).run(
                    pack,
                    pack.manifest.reference_dir,
                    "public",
                )
                intent = next(payload for kind, payload in events if kind == "sandbox_prepare_intent")
                observed.append(str(intent["sandbox_id"]))

        self.assertTrue(all(len(sandbox_id) <= 64 for sandbox_id in observed))
        self.assertEqual(len(set(observed)), 2)
        self.assertTrue(all(sandbox_id.startswith("validate-autonomy-smoke-202608") for sandbox_id in observed))


if __name__ == "__main__":
    unittest.main()
