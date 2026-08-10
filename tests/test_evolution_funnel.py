from __future__ import annotations

import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from aegis.evaluation.promotion import PairedObservation
from aegis.evolution_funnel import (
    FunnelStage,
    VerifiedTokenEvidence,
    evaluate_evolution_candidate,
    evaluate_smoke_only_candidate,
    observations_sha256,
)
from aegis.evolution_validation import CommandValidationEvidence, ValidationEvidence
from aegis.evolution_workspace import (
    CandidatePatchArtifact,
    EvolutionPath,
    EvolutionPolicy,
    EvolutionWorkspace,
    ValidationCommand,
)

REPORT = "a" * 64


def tar_bytes(content: bytes) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        info = tarfile.TarInfo("adaptive/logic.py")
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))
    return stream.getvalue()


def artifact(root: Path) -> CandidatePatchArtifact:
    command = ValidationCommand(("python", "-m", "pytest", "-q"))
    workspace = EvolutionWorkspace(
        root,
        EvolutionPolicy(
            evolvable_paths=(EvolutionPath("adaptive", recursive=True),),
            required_effective_paths=(),
            protected_paths=("control",),
            validation_commands=(command,),
        ),
    )
    return workspace.candidate_from_archive(workspace.create_snapshot(), tar_bytes(b"new"))


def validation(candidate: CandidatePatchArtifact, *, passed: bool = True) -> ValidationEvidence:
    command = candidate.validation_commands[0]
    command_payload = {
        "argv": list(command.argv),
        "cwd": command.cwd,
        "timeout_seconds": command.timeout_seconds,
    }
    command_hash = hashlib.sha256(
        json.dumps(command_payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    command_evidence = CommandValidationEvidence(
        0,
        command_hash,
        "1" * 64,
        0 if passed else 1,
        False,
        1.0,
        1.0,
        "2" * 64,
        "3" * 64,
        0,
        0,
        True,
    )
    frozen = "4" * 64
    payload = {
        "schema_version": 1,
        "validation_id": "full-regression",
        "candidate_artifact_id": candidate.artifact_id,
        "baseline_archive_sha256": candidate.baseline_archive_sha256,
        "candidate_archive_sha256": candidate.candidate_archive_sha256,
        "pristine_frozen_sha256": frozen,
        "post_validation_frozen_sha256": frozen,
        "commands": [
            {
                "index": command_evidence.index,
                "command_sha256": command_evidence.command_sha256,
                "result_sha256": command_evidence.result_sha256,
                "exit_code": command_evidence.exit_code,
                "timed_out": command_evidence.timed_out,
                "reported_duration_seconds": command_evidence.reported_duration_seconds,
                "observed_duration_seconds": command_evidence.observed_duration_seconds,
                "stdout_sha256": command_evidence.stdout_sha256,
                "stderr_sha256": command_evidence.stderr_sha256,
                "stdout_bytes": command_evidence.stdout_bytes,
                "stderr_bytes": command_evidence.stderr_bytes,
                "output_within_limit": command_evidence.output_within_limit,
            }
        ],
        "passed": passed,
        "failure_reason": None if passed else "nonzero-exit",
        "workspace_mutated": False,
        "total_observed_seconds": 1.0,
    }
    identity = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
    return ValidationEvidence(
        f"validation-sha256:{identity}",
        "full-regression",
        candidate.artifact_id,
        candidate.baseline_archive_sha256,
        candidate.candidate_archive_sha256,
        frozen,
        frozen,
        (command_evidence,),
        passed,
        None if passed else "nonzero-exit",
        False,
        1.0,
    )


def smoke(*, quality_delta: float = 0.0, safety: bool = False) -> tuple[PairedObservation, ...]:
    return tuple(
        PairedObservation(f"smoke-{index}", 0, 0.8 + quality_delta, 0.8, 90, 100, True, True, safety)
        for index in range(2)
    )


def full(
    *, quality_delta: float = 0.04, candidate_tokens: int = 100, safety: bool = False
) -> tuple[PairedObservation, ...]:
    return tuple(
        PairedObservation(
            f"task-{task:02d}",
            seed,
            0.8 + quality_delta,
            0.8,
            candidate_tokens,
            100,
            True,
            True,
            safety,
        )
        for task in range(12)
        for seed in range(2)
    )


def tokens(candidate: CandidatePatchArtifact, rows: tuple[PairedObservation, ...]) -> VerifiedTokenEvidence:
    return VerifiedTokenEvidence.create(
        candidate_artifact_id=candidate.artifact_id,
        baseline_archive_sha256=candidate.baseline_archive_sha256,
        observations=rows,
        usage_verified=True,
        source_report_sha256=REPORT,
    )


class EvolutionFunnelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "adaptive").mkdir()
        (self.root / "adaptive" / "logic.py").write_bytes(b"old")
        self.artifact = artifact(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_quality_gate_promotes_only_after_complete_full_design(self) -> None:
        rows = full(quality_delta=0.04)
        result = evaluate_evolution_candidate(
            self.artifact, validation(self.artifact), smoke(), rows, tokens(self.artifact, rows)
        )
        self.assertTrue(result.promotable)
        self.assertEqual(result.report.stage, FunnelStage.PROMOTABLE)
        self.assertEqual(result.report.full_decision.pairs, 24)  # type: ignore[union-attr]
        self.assertEqual(result.promotion_evidence.candidate_artifact_id, self.artifact.artifact_id)  # type: ignore[union-attr]
        repeated = evaluate_evolution_candidate(
            self.artifact, validation(self.artifact), smoke(), reversed(rows), tokens(self.artifact, rows)
        )
        self.assertEqual(result, repeated)

    def test_smoke_only_candidate_emits_promotion_evidence_from_smoke_design(self) -> None:
        rows = smoke(quality_delta=0.04)
        result = evaluate_smoke_only_candidate(
            self.artifact,
            validation(self.artifact),
            rows,
            tokens(self.artifact, rows),
        )
        self.assertEqual(result.report.stage, FunnelStage.PROMOTABLE)
        self.assertIsNotNone(result.promotion_evidence)
        assert result.promotion_evidence is not None
        self.assertEqual(result.promotion_evidence.quality_report_sha256, observations_sha256(rows))

    def test_smoke_only_candidate_rejects_degraded_smoke(self) -> None:
        rows = smoke(quality_delta=-0.2)
        result = evaluate_smoke_only_candidate(
            self.artifact,
            validation(self.artifact),
            rows,
            tokens(self.artifact, rows),
        )
        self.assertIsNone(result.promotion_evidence)
        self.assertEqual(result.report.stage, FunnelStage.SMOKE_REJECTED)

    def test_validation_or_smoke_can_only_reject_never_promote(self) -> None:
        rows = full()
        invalid = evaluate_evolution_candidate(
            self.artifact,
            validation(self.artifact, passed=False),
            smoke(),
            rows,
            tokens(self.artifact, rows),
        )
        self.assertEqual(invalid.report.stage, FunnelStage.VALIDATION_REJECTED)
        self.assertIsNone(invalid.promotion_evidence)
        degraded = evaluate_evolution_candidate(
            self.artifact,
            validation(self.artifact),
            smoke(quality_delta=-0.2),
            rows,
            tokens(self.artifact, rows),
        )
        self.assertEqual(degraded.report.stage, FunnelStage.SMOKE_REJECTED)
        self.assertIsNone(degraded.promotion_evidence)

    def test_any_safety_failure_is_fail_closed(self) -> None:
        safe_rows = full()
        smoke_failure = evaluate_evolution_candidate(
            self.artifact,
            validation(self.artifact),
            smoke(safety=True),
            safe_rows,
            tokens(self.artifact, safe_rows),
        )
        self.assertEqual(smoke_failure.report.stage, FunnelStage.SMOKE_REJECTED)
        unsafe_rows = full(safety=True)
        full_failure = evaluate_evolution_candidate(
            self.artifact,
            validation(self.artifact),
            smoke(),
            unsafe_rows,
            tokens(self.artifact, unsafe_rows),
        )
        self.assertFalse(full_failure.promotable)
        self.assertEqual(full_failure.report.stage, FunnelStage.FULL_REJECTED)

    def test_incomplete_or_duplicate_full_sample_never_promotes(self) -> None:
        complete = full()
        for rows in (complete[:-1], complete[:-1] + (complete[0],)):
            evidence = tokens(self.artifact, rows)
            result = evaluate_evolution_candidate(
                self.artifact, validation(self.artifact), smoke(), rows, evidence
            )
            self.assertEqual(result.report.stage, FunnelStage.FULL_REJECTED)
            self.assertIsNone(result.promotion_evidence)

    def test_quality_and_efficiency_gates(self) -> None:
        mediocre = full(quality_delta=0.0, candidate_tokens=100)
        rejected = evaluate_evolution_candidate(
            self.artifact,
            validation(self.artifact),
            smoke(),
            mediocre,
            tokens(self.artifact, mediocre),
        )
        self.assertFalse(rejected.promotable)
        efficient = full(quality_delta=0.0, candidate_tokens=75)
        accepted = evaluate_evolution_candidate(
            self.artifact,
            validation(self.artifact),
            smoke(),
            efficient,
            tokens(self.artifact, efficient),
        )
        self.assertTrue(accepted.promotable)
        expensive = full(quality_delta=0.04, candidate_tokens=120)
        too_expensive = evaluate_evolution_candidate(
            self.artifact,
            validation(self.artifact),
            smoke(),
            expensive,
            tokens(self.artifact, expensive),
        )
        self.assertFalse(too_expensive.promotable)

    def test_unverified_or_mismatched_usage_and_identity_fail_closed(self) -> None:
        rows = full()
        unverified = VerifiedTokenEvidence.create(
            candidate_artifact_id=self.artifact.artifact_id,
            baseline_archive_sha256=self.artifact.baseline_archive_sha256,
            observations=rows,
            usage_verified=False,
            source_report_sha256=REPORT,
        )
        rejected = evaluate_evolution_candidate(
            self.artifact, validation(self.artifact), smoke(), rows, unverified
        )
        self.assertFalse(rejected.promotable)
        wrong_baseline = VerifiedTokenEvidence.create(
            candidate_artifact_id=self.artifact.artifact_id,
            baseline_archive_sha256="0" * 64,
            observations=rows,
            usage_verified=True,
            source_report_sha256=REPORT,
        )
        rejected = evaluate_evolution_candidate(
            self.artifact, validation(self.artifact), smoke(), rows, wrong_baseline
        )
        self.assertFalse(rejected.promotable)
        row_unverified = (replace(rows[0], candidate_usage_verified=False), *rows[1:])
        rejected = evaluate_evolution_candidate(
            self.artifact,
            validation(self.artifact),
            smoke(),
            row_unverified,
            tokens(self.artifact, row_unverified),
        )
        self.assertFalse(rejected.promotable)
        self.assertEqual(rejected.report.stage, FunnelStage.FULL_REJECTED)
        tampered = tokens(self.artifact, rows)
        object.__setattr__(tampered, "candidate_tokens", tampered.candidate_tokens + 1)
        with self.assertRaises(ValueError):
            evaluate_evolution_candidate(
                self.artifact, validation(self.artifact), smoke(), rows, tampered
            )


if __name__ == "__main__":
    unittest.main()
