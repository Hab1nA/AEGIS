from __future__ import annotations

import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

from aegis.evolution_validation import EvolutionValidationError, EvolutionValidator
from aegis.evolution_workspace import (
    EvolutionPath,
    EvolutionPolicy,
    EvolutionWorkspace,
    ValidationCommand,
)
from aegis.sandbox.fake import FakeSandboxBackend
from aegis.sandbox.types import (
    CommandResult,
    DoctorCheck,
    DoctorReport,
    StagedArtifact,
)


class NetworklessFakeBackend(FakeSandboxBackend):
    def doctor(self) -> DoctorReport:
        return DoctorReport((DoctorCheck("network_none", self.healthy, "test isolation"),))


class MutatingBackend(NetworklessFakeBackend):
    def exec(self, sandbox_id, command):  # type: ignore[no-untyped-def]
        result = super().exec(sandbox_id, command)
        self._files[sandbox_id][".pytest_cache/state"] = b"temporary"  # noqa: SLF001
        return result


class TamperedReceiptBackend(NetworklessFakeBackend):
    def stage_archive(self, sandbox_id, archive_base64, expected_digest):  # type: ignore[no-untyped-def]
        receipt = super().stage_archive(sandbox_id, archive_base64, expected_digest)
        return StagedArtifact(receipt.sandbox_id, "0" * 64, receipt.size_bytes, receipt.entries)


class EvolutionValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "adaptive").mkdir()
        (self.root / "adaptive" / "logic.py").write_text("VALUE = 1\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def artifact(self, commands: tuple[ValidationCommand, ...]):
        policy = EvolutionPolicy(
            evolvable_paths=(EvolutionPath("adaptive", recursive=True),),
            required_effective_paths=(),
            protected_paths=(),
            validation_commands=commands,
        )
        workspace = EvolutionWorkspace(self.root, policy)
        baseline = workspace.create_snapshot()
        return workspace.candidate_from_archive(baseline, baseline.archive), policy

    def test_commands_execute_in_order_evidence_is_bound_and_sandboxes_destroyed(self) -> None:
        commands = (
            ValidationCommand(("python", "-m", "ruff", "check")),
            ValidationCommand(("python", "-m", "pytest", "-q")),
        )
        backend = NetworklessFakeBackend()
        artifact, policy = self.artifact(commands)
        evidence = EvolutionValidator(backend, policy=policy, clock=lambda: 10.0).validate(
            artifact, validation_id="run-1"
        )
        self.assertTrue(evidence.passed)
        self.assertEqual([command.argv for _, command in backend.commands], [item.argv for item in commands])
        self.assertEqual([item.index for item in evidence.commands], [0, 1])
        self.assertEqual(backend.prepared, set())
        self.assertEqual(
            [rules for _, rules in backend.workspace_access_history],
            [policy.workspace_access_rules(), policy.workspace_access_rules()],
        )
        self.assertTrue(evidence.evidence_id.startswith("validation-sha256:"))
        with self.assertRaises(ValueError):
            replace(evidence, candidate_archive_sha256="0" * 64)

    def test_nonzero_failure_stops_remaining_commands_and_cleans_up(self) -> None:
        calls = 0

        def execute(_sandbox_id, _command):  # type: ignore[no-untyped-def]
            nonlocal calls
            calls += 1
            return CommandResult(1 if calls == 2 else 0, "out", "err", 0.1)

        commands = tuple(ValidationCommand(("python", f"check-{index}")) for index in range(3))
        backend = NetworklessFakeBackend(executor=execute)
        artifact, policy = self.artifact(commands)
        evidence = EvolutionValidator(backend, policy=policy).validate(artifact, validation_id="failed")
        self.assertFalse(evidence.passed)
        self.assertEqual(evidence.failure_reason, "nonzero-exit")
        self.assertEqual(len(evidence.commands), 2)
        self.assertEqual(backend.prepared, set())

    def test_timeout_and_output_limit_fail_closed(self) -> None:
        cases = (
            (CommandResult(0, "", "", 1.0, timed_out=True), "timeout"),
            (CommandResult(0, "x" * 65, "", 1.0), "output-limit"),
        )
        for index, (result, reason) in enumerate(cases):
            with self.subTest(reason=reason):
                backend = NetworklessFakeBackend(executor=lambda _sid, _cmd, value=result: value)
                artifact, policy = self.artifact((ValidationCommand(("python", "check")),))
                evidence = EvolutionValidator(backend, policy=policy, max_output_bytes=64).validate(
                    artifact,
                    validation_id=f"limit-{index}",
                )
                self.assertFalse(evidence.passed)
                self.assertEqual(evidence.failure_reason, reason)
                self.assertEqual(backend.prepared, set())

    def test_receipt_tampering_fails_and_still_destroys(self) -> None:
        backend = TamperedReceiptBackend()
        with self.assertRaisesRegex(EvolutionValidationError, "receipt"):
            artifact, policy = self.artifact((ValidationCommand(("python", "check")),))
            EvolutionValidator(backend, policy=policy).validate(
                artifact,
                validation_id="tamper",
            )
        self.assertEqual(backend.prepared, set())

    def test_backend_execution_exception_still_destroys_both_sandboxes(self) -> None:
        def explode(_sandbox_id, _command):  # type: ignore[no-untyped-def]
            raise RuntimeError("executor crashed")

        backend = NetworklessFakeBackend(executor=explode)
        with self.assertRaisesRegex(RuntimeError, "executor crashed"):
            artifact, policy = self.artifact((ValidationCommand(("python", "check")),))
            EvolutionValidator(backend, policy=policy).validate(
                artifact,
                validation_id="exception",
            )
        self.assertEqual(backend.prepared, set())

    def test_validation_temp_files_are_detected_but_never_promoted(self) -> None:
        artifact, policy = self.artifact((ValidationCommand(("python", "check")),))
        original_archive = artifact.candidate_archive
        backend = MutatingBackend()
        evidence = EvolutionValidator(backend, policy=policy).validate(artifact, validation_id="mutation")
        self.assertTrue(evidence.passed)
        self.assertTrue(evidence.workspace_mutated)
        self.assertEqual(artifact.candidate_archive, original_archive)
        self.assertEqual(backend.prepared, set())

    def test_requires_network_isolation_and_at_least_one_command(self) -> None:
        without_network_proof = FakeSandboxBackend()
        with self.assertRaisesRegex(EvolutionValidationError, "network"):
            artifact, policy = self.artifact((ValidationCommand(("python", "check")),))
            EvolutionValidator(without_network_proof, policy=policy).validate(
                artifact,
                validation_id="network",
            )
        with self.assertRaisesRegex(EvolutionValidationError, "no validation"):
            artifact, policy = self.artifact(())
            EvolutionValidator(NetworklessFakeBackend(), policy=policy).validate(
                artifact, validation_id="empty"
            )


if __name__ == "__main__":
    unittest.main()
