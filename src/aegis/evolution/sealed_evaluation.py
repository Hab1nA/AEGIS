"""Immutable evidence emitted by sealed public and hidden task evaluation."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from aegis.models import canonical_json


def _content_id(prefix: str, payload: Mapping[str, Any]) -> str:
    return prefix + hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


class EvaluationTier(StrEnum):
    """The two evidence groups used by curriculum and promotion gates."""

    FRESH = "fresh"
    REGRESSION = "regression"


@dataclass(frozen=True, slots=True)
class EvaluationTaskBinding:
    task_id: str
    artifact_id: str
    revision: int
    tier: EvaluationTier
    taskpack_sha256: str

    def to_mapping(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "artifact_id": self.artifact_id,
            "revision": self.revision,
            "tier": self.tier.value,
            "taskpack_sha256": self.taskpack_sha256,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> EvaluationTaskBinding:
        if set(value) != {"task_id", "artifact_id", "revision", "tier", "taskpack_sha256"}:
            raise ValueError("evaluation task binding has missing or unknown fields")
        return cls(
            task_id=value["task_id"],
            artifact_id=value["artifact_id"],
            revision=value["revision"],
            tier=EvaluationTier(value["tier"]),
            taskpack_sha256=value["taskpack_sha256"],
        )


@dataclass(frozen=True, slots=True)
class CandidateEvaluationDesign:
    """Content-addressed immutable contract for one paired evaluation."""

    campaign_id: str
    cycle_id: str
    snapshot_id: str
    objective_id: str
    candidate_id: str
    surface: str
    target_role: str | None
    cohort_id: str
    tasks: tuple[EvaluationTaskBinding, ...]
    seeds: tuple[int, ...]
    baseline_runtime_id: str
    candidate_runtime_id: str
    runtime_policy_id: str
    evaluator_fingerprint: str
    public_weight: float
    hidden_weight: float
    gate_policy_sha256: str
    design_id: str

    def __post_init__(self) -> None:
        if self.seeds != tuple(sorted(set(self.seeds))) or len(self.seeds) < 2:
            raise ValueError("evaluation design requires at least two distinct seeds")
        task_keys = tuple((item.artifact_id, item.revision) for item in self.tasks)
        if not self.tasks or task_keys != tuple(sorted(set(task_keys))):
            raise ValueError("evaluation tasks must be sorted and unique")
        if not any(item.tier is EvaluationTier.FRESH for item in self.tasks):
            raise ValueError("evaluation design requires fresh evidence")
        if not any(item.tier is EvaluationTier.REGRESSION for item in self.tasks):
            raise ValueError("evaluation design requires regression evidence")
        if abs(self.public_weight + self.hidden_weight - 1.0) > 1e-12:
            raise ValueError("public and hidden weights must sum to one")
        expected = _content_id(
            "candidate-evaluation-design-sha256:", self.to_mapping(include_id=False)
        )
        if self.design_id != expected:
            raise ValueError("evaluation design content id mismatch")

    @classmethod
    def create(cls, **values: Any) -> CandidateEvaluationDesign:
        payload = dict(values)
        payload["tasks"] = [item.to_mapping() for item in values["tasks"]]
        payload["seeds"] = list(values["seeds"])
        return cls(
            **values,
            design_id=_content_id("candidate-evaluation-design-sha256:", payload),
        )

    def to_mapping(self, *, include_id: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "campaign_id": self.campaign_id,
            "cycle_id": self.cycle_id,
            "snapshot_id": self.snapshot_id,
            "objective_id": self.objective_id,
            "candidate_id": self.candidate_id,
            "surface": self.surface,
            "target_role": self.target_role,
            "cohort_id": self.cohort_id,
            "tasks": [item.to_mapping() for item in self.tasks],
            "seeds": list(self.seeds),
            "baseline_runtime_id": self.baseline_runtime_id,
            "candidate_runtime_id": self.candidate_runtime_id,
            "runtime_policy_id": self.runtime_policy_id,
            "evaluator_fingerprint": self.evaluator_fingerprint,
            "public_weight": self.public_weight,
            "hidden_weight": self.hidden_weight,
            "gate_policy_sha256": self.gate_policy_sha256,
        }
        return {"design_id": self.design_id, **payload} if include_id else payload

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> CandidateEvaluationDesign:
        expected = {
            "design_id", "campaign_id", "cycle_id", "snapshot_id", "objective_id",
            "candidate_id", "surface", "target_role", "cohort_id", "tasks", "seeds",
            "baseline_runtime_id", "candidate_runtime_id", "runtime_policy_id",
            "evaluator_fingerprint", "public_weight", "hidden_weight", "gate_policy_sha256",
        }
        if set(value) != expected:
            raise ValueError("evaluation design has missing or unknown fields")
        tasks = value["tasks"]
        seeds = value["seeds"]
        if not isinstance(tasks, list) or not all(isinstance(item, Mapping) for item in tasks):
            raise TypeError("evaluation design tasks must be objects")
        if not isinstance(seeds, list):
            raise TypeError("evaluation design seeds must be an array")
        return cls(
            campaign_id=value["campaign_id"], cycle_id=value["cycle_id"],
            snapshot_id=value["snapshot_id"], objective_id=value["objective_id"],
            candidate_id=value["candidate_id"], surface=value["surface"],
            target_role=value["target_role"], cohort_id=value["cohort_id"],
            tasks=tuple(EvaluationTaskBinding.from_mapping(item) for item in tasks),
            seeds=tuple(seeds), baseline_runtime_id=value["baseline_runtime_id"],
            candidate_runtime_id=value["candidate_runtime_id"],
            runtime_policy_id=value["runtime_policy_id"],
            evaluator_fingerprint=value["evaluator_fingerprint"],
            public_weight=value["public_weight"], hidden_weight=value["hidden_weight"],
            gate_policy_sha256=value["gate_policy_sha256"], design_id=value["design_id"],
        )


@dataclass(frozen=True, slots=True)
class SealedArmEvidence:
    """Durable exact-arm evidence; aggregate gates only consume this binding."""

    design_id: str
    seed: int
    arm: str
    workspace_artifact_id: str
    workspace_sha256: str
    runtime_id: str
    role_generation_id: str | None
    plugin_ids: tuple[str, ...]
    mcp_ids: tuple[str, ...]
    environment_id: str
    task_result_ids: tuple[str, ...]
    evaluator_fingerprint: str
    verified_usage_units: int | None
    integrity_passed: bool
    evidence_id: str

    def __post_init__(self) -> None:
        if self.arm not in {"baseline", "candidate"}:
            raise ValueError("sealed arm must be baseline or candidate")
        if self.seed < 0 or isinstance(self.seed, bool):
            raise ValueError("sealed arm seed is invalid")
        for values in (self.plugin_ids, self.mcp_ids, self.task_result_ids):
            if values != tuple(sorted(set(values))):
                raise ValueError("sealed arm identity lists must be sorted and unique")
        expected = _content_id(
            "sealed-arm-evidence-sha256:", self.to_mapping(include_id=False)
        )
        if self.evidence_id != expected:
            raise ValueError("sealed arm evidence content id mismatch")

    @classmethod
    def create(cls, **values: Any) -> SealedArmEvidence:
        payload = dict(values)
        for key in ("plugin_ids", "mcp_ids", "task_result_ids"):
            payload[key] = list(values[key])
        return cls(
            **values,
            evidence_id=_content_id("sealed-arm-evidence-sha256:", payload),
        )

    def to_mapping(self, *, include_id: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "design_id": self.design_id,
            "seed": self.seed,
            "arm": self.arm,
            "workspace_artifact_id": self.workspace_artifact_id,
            "workspace_sha256": self.workspace_sha256,
            "runtime_id": self.runtime_id,
            "role_generation_id": self.role_generation_id,
            "plugin_ids": list(self.plugin_ids),
            "mcp_ids": list(self.mcp_ids),
            "environment_id": self.environment_id,
            "task_result_ids": list(self.task_result_ids),
            "evaluator_fingerprint": self.evaluator_fingerprint,
            "verified_usage_units": self.verified_usage_units,
            "integrity_passed": self.integrity_passed,
        }
        return {"evidence_id": self.evidence_id, **payload} if include_id else payload

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> SealedArmEvidence:
        expected = {
            "evidence_id", "design_id", "seed", "arm", "workspace_artifact_id",
            "workspace_sha256", "runtime_id", "role_generation_id", "plugin_ids",
            "mcp_ids", "environment_id", "task_result_ids", "evaluator_fingerprint",
            "verified_usage_units", "integrity_passed",
        }
        if set(value) != expected:
            raise ValueError("sealed arm evidence has missing or unknown fields")
        for key in ("plugin_ids", "mcp_ids", "task_result_ids"):
            if not isinstance(value[key], list):
                raise TypeError(f"{key} must be an array")
        return cls(
            design_id=value["design_id"], seed=value["seed"], arm=value["arm"],
            workspace_artifact_id=value["workspace_artifact_id"],
            workspace_sha256=value["workspace_sha256"], runtime_id=value["runtime_id"],
            role_generation_id=value["role_generation_id"],
            plugin_ids=tuple(value["plugin_ids"]), mcp_ids=tuple(value["mcp_ids"]),
            environment_id=value["environment_id"],
            task_result_ids=tuple(value["task_result_ids"]),
            evaluator_fingerprint=value["evaluator_fingerprint"],
            verified_usage_units=value["verified_usage_units"],
            integrity_passed=value["integrity_passed"], evidence_id=value["evidence_id"],
        )


@dataclass(frozen=True, slots=True)
class SealedSuiteResult:
    """Observed result for one sealed suite.

    Failed assertions are represented by ``passed < total``.  Timeout and
    safety/integrity findings are recorded separately so callers never need to
    infer an evaluator failure from a low test score.
    """

    passed: int
    total: int
    timed_out: bool = False
    integrity_violations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            isinstance(self.passed, bool)
            or isinstance(self.total, bool)
            or not isinstance(self.passed, int)
            or not isinstance(self.total, int)
            or self.total < 1
            or self.passed < 0
            or self.passed > self.total
        ):
            raise ValueError("invalid sealed suite counts")
        if not isinstance(self.timed_out, bool):
            raise TypeError("timed_out must be a bool")
        if not isinstance(self.integrity_violations, tuple) or any(
            not isinstance(item, str) or not item
            for item in self.integrity_violations
        ):
            raise TypeError("integrity_violations must be non-empty strings")

    @property
    def score(self) -> float:
        return self.passed / self.total

    @property
    def integrity_passed(self) -> bool:
        return not self.timed_out and not self.integrity_violations

    @property
    def tests_passed(self) -> bool:
        return self.passed == self.total


@dataclass(frozen=True, slots=True)
class TaskArmResult:
    """Public/hidden sealed evidence bound to an exact task artifact."""

    task_id: str
    artifact_id: str
    tier: EvaluationTier
    public: SealedSuiteResult
    hidden: SealedSuiteResult
    suite_sandbox_ids: tuple[str, str]
    staging_digest: str
    changed_paths: tuple[str, ...] = ()
    integrity_violations: tuple[str, ...] = ()

    @property
    def public_score(self) -> float:
        return self.public.score

    @property
    def hidden_score(self) -> float:
        return self.hidden.score

    @property
    def score(self) -> float:
        if not self.integrity_passed:
            return 0.0
        return 0.25 * self.public_score + 0.75 * self.hidden_score

    @property
    def integrity_passed(self) -> bool:
        return (
            self.public.integrity_passed
            and self.hidden.integrity_passed
            and len(set(self.suite_sandbox_ids)) == 2
            and bool(self.staging_digest)
            and not self.changed_paths
            and not self.integrity_violations
        )

    @property
    def passed_task(self) -> bool:
        return (
            self.integrity_passed
            and self.public.tests_passed
            and self.hidden.tests_passed
        )

    # Compatibility accessors for code that consumed the old public-only type.
    @property
    def passed(self) -> int:
        return self.public.passed + self.hidden.passed

    @property
    def total(self) -> int:
        return self.public.total + self.hidden.total

    @property
    def timed_out(self) -> bool:
        return self.public.timed_out or self.hidden.timed_out

    @property
    def safety_violations(self) -> tuple[str, ...]:
        return self.integrity_violations


@dataclass(frozen=True, slots=True)
class TierEvaluation:
    """Equal-task-weighted score for one evaluation tier."""

    tier: EvaluationTier
    quality: float | None
    task_count: int
    artifact_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ArmEvaluation:
    """Sealed evidence for a complete frozen arm workspace."""

    workspace_digest: str
    quality: float
    passed_tasks: int
    total_tasks: int
    task_results: tuple[TaskArmResult, ...]
    safety_violations: tuple[str, ...]
    fresh: TierEvaluation
    regression: TierEvaluation

    @property
    def integrity_passed(self) -> bool:
        return (
            not self.safety_violations
            and bool(self.task_results)
            and all(item.integrity_passed for item in self.task_results)
        )

    @property
    def fresh_quality(self) -> float | None:
        return self.fresh.quality

    @property
    def regression_quality(self) -> float | None:
        return self.regression.quality


__all__ = [
    "ArmEvaluation",
    "CandidateEvaluationDesign",
    "EvaluationTaskBinding",
    "EvaluationTier",
    "SealedSuiteResult",
    "SealedArmEvidence",
    "TaskArmResult",
    "TierEvaluation",
]
