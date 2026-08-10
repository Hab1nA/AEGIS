"""Pure, deterministic staged promotion funnel for self-evolution candidates."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from statistics import fmean
from typing import Iterable, Sequence

from aegis.evaluation.promotion import PairedObservation, PromotionDecision, PromotionPolicy, decide_promotion
from aegis.evolution_registry import EvolutionPromotionEvidence
from aegis.evolution_validation import ValidationEvidence
from aegis.evolution_workspace import CandidatePatchArtifact, ValidationCommand
from aegis.models import canonical_json

FULL_POLICY = PromotionPolicy(required_tasks=12, seeds_per_task=2)
SMOKE_TASKS = 2
SMOKE_SEEDS_PER_TASK = 1
SMOKE_ONLY_POLICY = PromotionPolicy(required_tasks=SMOKE_TASKS, seeds_per_task=SMOKE_SEEDS_PER_TASK)
SMOKE_MAX_QUALITY_REGRESSION = 0.05
SMOKE_MAX_TOKEN_INCREASE = 0.50
_SHA256 = re.compile(r"[0-9a-f]{64}")
_TOKEN_EVIDENCE_ID = re.compile(r"token-usage-sha256:([0-9a-f]{64})")


class EvolutionFunnelError(ValueError):
    pass


class FunnelStage(StrEnum):
    VALIDATION_REJECTED = "validation_rejected"
    SMOKE_REJECTED = "smoke_rejected"
    FULL_REJECTED = "full_rejected"
    PROMOTABLE = "promotable"


def _observation_dict(row: PairedObservation) -> dict[str, object]:
    return {
        "task_id": row.task_id,
        "seed": row.seed,
        "candidate_quality": row.candidate_quality,
        "champion_quality": row.champion_quality,
        "candidate_tokens": row.candidate_tokens,
        "champion_tokens": row.champion_tokens,
        "candidate_usage_verified": row.candidate_usage_verified,
        "champion_usage_verified": row.champion_usage_verified,
        "safety_violation": row.safety_violation,
    }


def observations_sha256(rows: Iterable[PairedObservation]) -> str:
    ordered = sorted(rows, key=lambda row: (row.task_id, row.seed))
    return hashlib.sha256(
        canonical_json({"observations": [_observation_dict(row) for row in ordered]}).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class VerifiedTokenEvidence:
    evidence_id: str
    candidate_artifact_id: str
    baseline_archive_sha256: str
    observations_sha256: str
    candidate_tokens: int
    baseline_tokens: int
    usage_verified: bool
    source_report_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.candidate_artifact_id, str) or not self.candidate_artifact_id.startswith(
            "candidate-sha256:"
        ):
            raise EvolutionFunnelError("candidate_artifact_id is invalid")
        for digest_value, name in (
            (self.candidate_artifact_id.removeprefix("candidate-sha256:"), "candidate artifact hash"),
            (self.baseline_archive_sha256, "baseline_archive_sha256"),
            (self.observations_sha256, "observations_sha256"),
            (self.source_report_sha256, "source_report_sha256"),
        ):
            if not isinstance(digest_value, str) or _SHA256.fullmatch(digest_value) is None:
                raise EvolutionFunnelError(f"{name} must be a lowercase SHA-256 digest")
        for token_value, name in (
            (self.candidate_tokens, "candidate_tokens"),
            (self.baseline_tokens, "baseline_tokens"),
        ):
            if isinstance(token_value, bool) or not isinstance(token_value, int) or token_value < 0:
                raise EvolutionFunnelError(f"{name} must be a non-negative integer")
        if not isinstance(self.usage_verified, bool):
            raise EvolutionFunnelError("usage_verified must be a bool")
        expected = self._identity()
        match = _TOKEN_EVIDENCE_ID.fullmatch(self.evidence_id)
        if match is None or match.group(1) != expected:
            raise EvolutionFunnelError("token evidence identity does not match its content")

    def _payload(self) -> dict[str, object]:
        return {
            "candidate_artifact_id": self.candidate_artifact_id,
            "baseline_archive_sha256": self.baseline_archive_sha256,
            "observations_sha256": self.observations_sha256,
            "candidate_tokens": self.candidate_tokens,
            "baseline_tokens": self.baseline_tokens,
            "usage_verified": self.usage_verified,
            "source_report_sha256": self.source_report_sha256,
        }

    def _identity(self) -> str:
        return hashlib.sha256(canonical_json(self._payload()).encode("utf-8")).hexdigest()

    @classmethod
    def create(
        cls,
        *,
        candidate_artifact_id: str,
        baseline_archive_sha256: str,
        observations: Sequence[PairedObservation],
        usage_verified: bool,
        source_report_sha256: str,
    ) -> VerifiedTokenEvidence:
        payload: dict[str, object] = {
            "candidate_artifact_id": candidate_artifact_id,
            "baseline_archive_sha256": baseline_archive_sha256,
            "observations_sha256": observations_sha256(observations),
            "candidate_tokens": sum(row.candidate_tokens for row in observations),
            "baseline_tokens": sum(row.champion_tokens for row in observations),
            "usage_verified": usage_verified,
            "source_report_sha256": source_report_sha256,
        }
        identity = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        return cls(evidence_id=f"token-usage-sha256:{identity}", **payload)  # type: ignore[arg-type]

    def to_dict(self) -> dict[str, object]:
        return {"evidence_id": self.evidence_id, **self._payload()}


@dataclass(frozen=True, slots=True)
class EvolutionFunnelReport:
    report_id: str
    candidate_artifact_id: str
    stage: FunnelStage
    reason: str
    validation_evidence_id: str
    smoke_observations_sha256: str
    full_observations_sha256: str
    token_evidence_id: str
    full_decision: PromotionDecision | None

    def to_dict(self, *, include_report_id: bool = True) -> dict[str, object]:
        decision: dict[str, object] | None = None
        if self.full_decision is not None:
            decision = {
                "promoted": self.full_decision.promoted,
                "reason": self.full_decision.reason,
                "quality_delta": self.full_decision.quality_delta,
                "quality_lower_bound": self.full_decision.quality_lower_bound,
                "token_change": self.full_decision.token_change,
                "token_saving_lower_bound": self.full_decision.token_saving_lower_bound,
                "pairs": self.full_decision.pairs,
            }
        result: dict[str, object] = {
            "candidate_artifact_id": self.candidate_artifact_id,
            "stage": self.stage.value,
            "reason": self.reason,
            "validation_evidence_id": self.validation_evidence_id,
            "smoke_observations_sha256": self.smoke_observations_sha256,
            "full_observations_sha256": self.full_observations_sha256,
            "token_evidence_id": self.token_evidence_id,
            "full_decision": decision,
        }
        if include_report_id:
            result["report_id"] = self.report_id
        return result


@dataclass(frozen=True, slots=True)
class EvolutionFunnelResult:
    report: EvolutionFunnelReport
    promotion_evidence: EvolutionPromotionEvidence | None

    @property
    def promotable(self) -> bool:
        return self.promotion_evidence is not None


def _command_hash(command: ValidationCommand) -> str:
    payload = {
        "argv": list(command.argv),
        "cwd": command.cwd,
        "timeout_seconds": command.timeout_seconds,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _validation_failure(
    artifact: CandidatePatchArtifact, evidence: ValidationEvidence
) -> str | None:
    if (
        evidence.candidate_artifact_id != artifact.artifact_id
        or evidence.baseline_archive_sha256 != artifact.baseline_archive_sha256
        or evidence.candidate_archive_sha256 != artifact.candidate_archive_sha256
    ):
        return "validation evidence identity or archive hashes do not match candidate"
    if not artifact.validation_commands or len(evidence.commands) != len(artifact.validation_commands):
        return "validation evidence does not cover every declared command"
    if any(
        item.command_sha256 != _command_hash(command)
        for item, command in zip(evidence.commands, artifact.validation_commands, strict=True)
    ):
        return "validation command hashes do not match candidate"
    if not evidence.passed or evidence.failure_reason is not None:
        return "static or full regression validation failed"
    if evidence.workspace_mutated or evidence.pristine_frozen_sha256 != evidence.post_validation_frozen_sha256:
        return "validation mutated the candidate workspace"
    if any(
        item.exit_code != 0 or item.timed_out or not item.output_within_limit
        for item in evidence.commands
    ):
        return "validation command evidence contains a failure"
    return None


def _smoke_failure(rows: Sequence[PairedObservation]) -> str | None:
    expected = SMOKE_TASKS * SMOKE_SEEDS_PER_TASK
    if len(rows) != expected:
        return f"smoke requires exactly {expected} paired observations"
    keys = {(row.task_id, row.seed) for row in rows}
    tasks = {row.task_id for row in rows}
    seeds = {row.seed for row in rows}
    if len(keys) != expected or len(tasks) != SMOKE_TASKS or len(seeds) != SMOKE_SEEDS_PER_TASK:
        return "smoke observations have an invalid task/seed design"
    if any(row.safety_violation for row in rows):
        return "safety violation in smoke evaluation"
    if any(not row.candidate_usage_verified or not row.champion_usage_verified for row in rows):
        return "unverified token usage in smoke evaluation"
    quality_delta = fmean(row.candidate_quality - row.champion_quality for row in rows)
    candidate_tokens = sum(row.candidate_tokens for row in rows)
    champion_tokens = sum(row.champion_tokens for row in rows)
    if quality_delta < -SMOKE_MAX_QUALITY_REGRESSION:
        return "candidate was eliminated by smoke quality regression"
    if candidate_tokens > champion_tokens * (1.0 + SMOKE_MAX_TOKEN_INCREASE):
        return "candidate was eliminated by smoke token regression"
    return None


def _report(
    *,
    artifact: CandidatePatchArtifact,
    stage: FunnelStage,
    reason: str,
    validation: ValidationEvidence,
    smoke_hash: str,
    full_hash: str,
    token_evidence: VerifiedTokenEvidence,
    decision: PromotionDecision | None,
) -> EvolutionFunnelReport:
    provisional = EvolutionFunnelReport(
        "",
        artifact.artifact_id,
        stage,
        reason,
        validation.evidence_id,
        smoke_hash,
        full_hash,
        token_evidence.evidence_id,
        decision,
    )
    digest = hashlib.sha256(
        canonical_json(provisional.to_dict(include_report_id=False)).encode("utf-8")
    ).hexdigest()
    return EvolutionFunnelReport(
        f"funnel-sha256:{digest}",
        artifact.artifact_id,
        stage,
        reason,
        validation.evidence_id,
        smoke_hash,
        full_hash,
        token_evidence.evidence_id,
        decision,
    )


def evaluate_evolution_candidate(
    artifact: CandidatePatchArtifact,
    validation: ValidationEvidence,
    smoke_observations: Iterable[PairedObservation],
    full_observations: Iterable[PairedObservation],
    token_evidence: VerifiedTokenEvidence,
) -> EvolutionFunnelResult:
    """Run every logical gate; only a full 12x2 decision can emit promotion evidence."""
    if not isinstance(artifact, CandidatePatchArtifact):
        raise EvolutionFunnelError("artifact must be CandidatePatchArtifact")
    if not isinstance(validation, ValidationEvidence):
        raise EvolutionFunnelError("validation must be ValidationEvidence")
    if not isinstance(token_evidence, VerifiedTokenEvidence):
        raise EvolutionFunnelError("token_evidence must be VerifiedTokenEvidence")
    try:
        rebuilt_artifact = CandidatePatchArtifact(
            artifact.artifact_id,
            artifact.baseline_archive_sha256,
            artifact.candidate_archive,
            artifact.candidate_archive_sha256,
            artifact.changes,
            artifact.validation_commands,
        )
        rebuilt_tokens = VerifiedTokenEvidence(**token_evidence.to_dict())  # type: ignore[arg-type]
        validation_mapping = dict(validation.to_mapping())
        validation_id = validation_mapping.pop("evidence_id")
        expected_validation_id = "validation-sha256:" + hashlib.sha256(
            json.dumps(
                validation_mapping,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
    except (TypeError, ValueError) as exc:
        raise EvolutionFunnelError("candidate or evidence failed immutable integrity checks") from exc
    if rebuilt_artifact != artifact or rebuilt_tokens != token_evidence:
        raise EvolutionFunnelError("candidate or token evidence identity is inconsistent")
    if validation_id != validation.evidence_id or validation.evidence_id != expected_validation_id:
        raise EvolutionFunnelError("validation evidence identity is inconsistent")
    smoke = tuple(sorted(smoke_observations, key=lambda row: (row.task_id, row.seed)))
    full = tuple(sorted(full_observations, key=lambda row: (row.task_id, row.seed)))
    if any(not isinstance(row, PairedObservation) for row in (*smoke, *full)):
        raise EvolutionFunnelError("paired observations have an invalid type")
    smoke_hash = observations_sha256(smoke)
    full_hash = observations_sha256(full)
    token_failure = (
        token_evidence.candidate_artifact_id != artifact.artifact_id
        or token_evidence.baseline_archive_sha256 != artifact.baseline_archive_sha256
        or token_evidence.observations_sha256 != full_hash
        or token_evidence.candidate_tokens != sum(row.candidate_tokens for row in full)
        or token_evidence.baseline_tokens != sum(row.champion_tokens for row in full)
        or not token_evidence.usage_verified
    )
    validation_reason = _validation_failure(artifact, validation)
    if validation_reason is not None or token_failure:
        reason = validation_reason or "verified token evidence is missing or inconsistent"
        report = _report(
            artifact=artifact,
            stage=FunnelStage.VALIDATION_REJECTED,
            reason=reason,
            validation=validation,
            smoke_hash=smoke_hash,
            full_hash=full_hash,
            token_evidence=token_evidence,
            decision=None,
        )
        return EvolutionFunnelResult(report, None)
    smoke_reason = _smoke_failure(smoke)
    if smoke_reason is not None:
        report = _report(
            artifact=artifact,
            stage=FunnelStage.SMOKE_REJECTED,
            reason=smoke_reason,
            validation=validation,
            smoke_hash=smoke_hash,
            full_hash=full_hash,
            token_evidence=token_evidence,
            decision=None,
        )
        return EvolutionFunnelResult(report, None)
    decision = decide_promotion(full, FULL_POLICY)
    if not decision.promoted:
        report = _report(
            artifact=artifact,
            stage=FunnelStage.FULL_REJECTED,
            reason=decision.reason,
            validation=validation,
            smoke_hash=smoke_hash,
            full_hash=full_hash,
            token_evidence=token_evidence,
            decision=decision,
        )
        return EvolutionFunnelResult(report, None)
    if any(row.safety_violation for row in full) or any(
        not row.candidate_usage_verified or not row.champion_usage_verified for row in full
    ):
        raise AssertionError("promotion decision violated fail-closed safety invariants")
    safety_hash = hashlib.sha256(
        canonical_json(
            {
                "artifact_id": artifact.artifact_id,
                "validation_evidence_id": validation.evidence_id,
                "smoke_observations_sha256": smoke_hash,
                "full_observations_sha256": full_hash,
                "safety_clear": True,
            }
        ).encode("utf-8")
    ).hexdigest()
    promotion = EvolutionPromotionEvidence(
        candidate_artifact_id=artifact.artifact_id,
        baseline_archive_sha256=artifact.baseline_archive_sha256,
        static_checks_passed=True,
        safety_regression_passed=True,
        quality_comparison_passed=True,
        usage_verified=True,
        candidate_tokens=token_evidence.candidate_tokens,
        baseline_tokens=token_evidence.baseline_tokens,
        static_report_sha256=validation.evidence_id.removeprefix("validation-sha256:"),
        safety_report_sha256=safety_hash,
        quality_report_sha256=full_hash,
        usage_report_sha256=token_evidence.source_report_sha256,
    )
    report = _report(
        artifact=artifact,
        stage=FunnelStage.PROMOTABLE,
        reason=decision.reason,
        validation=validation,
        smoke_hash=smoke_hash,
        full_hash=full_hash,
        token_evidence=token_evidence,
        decision=decision,
    )
    return EvolutionFunnelResult(report, promotion)


def evaluate_smoke_only_candidate(
    artifact: CandidatePatchArtifact,
    validation: ValidationEvidence,
    smoke_observations: Iterable[PairedObservation],
    token_evidence: VerifiedTokenEvidence,
) -> EvolutionFunnelResult:
    """Emit promotion evidence from the bounded smoke design (2 tasks x 1 seed).

    This is an explicit operator opt-in for loop-feasibility verification.  It
    reuses every validation/token/smoke gate from the full funnel and only
    relaxes the final paired-decision design from 12x2 to the smoke design.
    The evidence is labeled by its smoke observation digest, so a full 12x2
    acceptance verifier never mistakes this for a complete evaluation.
    """
    smoke = tuple(sorted(smoke_observations, key=lambda row: (row.task_id, row.seed)))
    preliminary = evaluate_evolution_candidate(artifact, validation, smoke, smoke, token_evidence)
    report = preliminary.report
    if report.stage is not FunnelStage.FULL_REJECTED:
        # A validation/token/smoke gate failed; propagate the rejection.
        return preliminary
    decision = decide_promotion(smoke, SMOKE_ONLY_POLICY)
    if not decision.promoted:
        rejected = _report(
            artifact=artifact,
            stage=FunnelStage.FULL_REJECTED,
            reason=decision.reason,
            validation=validation,
            smoke_hash=report.smoke_observations_sha256,
            full_hash=report.full_observations_sha256,
            token_evidence=token_evidence,
            decision=decision,
        )
        return EvolutionFunnelResult(rejected, None)
    safety_hash = hashlib.sha256(
        canonical_json(
            {
                "artifact_id": artifact.artifact_id,
                "validation_evidence_id": validation.evidence_id,
                "smoke_observations_sha256": report.smoke_observations_sha256,
                "full_observations_sha256": report.full_observations_sha256,
                "safety_clear": True,
            }
        ).encode("utf-8")
    ).hexdigest()
    promotion = EvolutionPromotionEvidence(
        candidate_artifact_id=artifact.artifact_id,
        baseline_archive_sha256=artifact.baseline_archive_sha256,
        static_checks_passed=True,
        safety_regression_passed=True,
        quality_comparison_passed=True,
        usage_verified=True,
        candidate_tokens=token_evidence.candidate_tokens,
        baseline_tokens=token_evidence.baseline_tokens,
        static_report_sha256=validation.evidence_id.removeprefix("validation-sha256:"),
        safety_report_sha256=safety_hash,
        quality_report_sha256=report.full_observations_sha256,
        usage_report_sha256=token_evidence.source_report_sha256,
    )
    promotable = _report(
        artifact=artifact,
        stage=FunnelStage.PROMOTABLE,
        reason=decision.reason,
        validation=validation,
        smoke_hash=report.smoke_observations_sha256,
        full_hash=report.full_observations_sha256,
        token_evidence=token_evidence,
        decision=decision,
    )
    return EvolutionFunnelResult(promotable, promotion)
