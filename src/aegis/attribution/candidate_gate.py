"""Deterministic two-seed gate for sealed candidate evaluation arms.

This gate is deliberately separate from causal attribution.  Attribution proves
that the candidate is the only changed coordinate; this module decides whether
the already-paired, sealed evidence is strong enough to activate that candidate.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable, Mapping


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _content_id(prefix: str, value: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(_canonical_json(value).encode("ascii")).hexdigest()
    return f"{prefix}{digest}"


def _quality(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be numeric")
    result = float(value)
    if not math.isfinite(result) or not 0.0 <= result <= 1.0:
        raise ValueError(f"{name} must be finite and in [0,1]")
    return result


@dataclass(frozen=True, slots=True)
class SealedCandidateArm:
    """Aggregate sealed metrics for one seed and one evaluation arm."""

    overall_quality: float
    fresh_quality: float | None
    regression_quality: float | None
    cost_units: int | None
    integrity_passed: bool
    design_id: str = ""
    evidence_id: str = ""
    cohort_id: str = ""
    task_artifact_ids: tuple[str, ...] = ()
    workspace_digest: str = ""
    evaluator_fingerprint: str = ""
    runtime_policy_id: str = ""

    def __post_init__(self) -> None:
        _quality(self.overall_quality, "overall_quality")
        if self.fresh_quality is not None:
            _quality(self.fresh_quality, "fresh_quality")
        if self.regression_quality is not None:
            _quality(self.regression_quality, "regression_quality")
        if self.cost_units is not None and (
            isinstance(self.cost_units, bool) or not isinstance(self.cost_units, int)
        ):
            raise TypeError("cost_units must be an integer or null")
        if self.cost_units is not None and self.cost_units < 0:
            raise ValueError("cost_units must be non-negative")
        if not isinstance(self.integrity_passed, bool):
            raise TypeError("integrity_passed must be bool")
        if tuple(sorted(set(self.task_artifact_ids))) != self.task_artifact_ids:
            raise ValueError("task_artifact_ids must be sorted and unique")
        bindings = (
            self.design_id,
            self.evidence_id,
            self.cohort_id,
            self.workspace_digest,
            self.evaluator_fingerprint,
            self.runtime_policy_id,
        )
        if any(bindings) and (not all(bindings) or not self.task_artifact_ids):
            raise ValueError("sealed arm evidence bindings must be complete")

    @property
    def binding_complete(self) -> bool:
        return bool(
            self.design_id
            and self.evidence_id
            and self.cohort_id
            and self.task_artifact_ids
            and self.workspace_digest
            and self.evaluator_fingerprint
            and self.runtime_policy_id
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "overall_quality": float(self.overall_quality),
            "fresh_quality": (
                None if self.fresh_quality is None else float(self.fresh_quality)
            ),
            "regression_quality": (
                None
                if self.regression_quality is None
                else float(self.regression_quality)
            ),
            "cost_units": self.cost_units,
            "integrity_passed": self.integrity_passed,
            "design_id": self.design_id,
            "evidence_id": self.evidence_id,
            "cohort_id": self.cohort_id,
            "task_artifact_ids": list(self.task_artifact_ids),
            "workspace_digest": self.workspace_digest,
            "evaluator_fingerprint": self.evaluator_fingerprint,
            "runtime_policy_id": self.runtime_policy_id,
        }


@dataclass(frozen=True, slots=True)
class SealedCandidatePair:
    """Champion and candidate arms evaluated with the same deterministic seed."""

    seed: int
    baseline: SealedCandidateArm
    candidate: SealedCandidateArm

    def __post_init__(self) -> None:
        if isinstance(self.seed, bool) or not isinstance(self.seed, int) or self.seed < 0:
            raise ValueError("seed must be a non-negative integer")
        if not isinstance(self.baseline, SealedCandidateArm):
            raise TypeError("baseline must be a SealedCandidateArm")
        if not isinstance(self.candidate, SealedCandidateArm):
            raise TypeError("candidate must be a SealedCandidateArm")
        if self.baseline.binding_complete != self.candidate.binding_complete:
            raise ValueError("paired arms must use the same evidence binding mode")
        if self.baseline.binding_complete:
            for field in (
                "design_id",
                "cohort_id",
                "task_artifact_ids",
                "evaluator_fingerprint",
                "runtime_policy_id",
            ):
                if getattr(self.baseline, field) != getattr(self.candidate, field):
                    raise ValueError(f"paired arm {field} bindings differ")
            if self.baseline.evidence_id == self.candidate.evidence_id:
                raise ValueError("paired arms must reference distinct evidence")

    @property
    def pair_id(self) -> str:
        return _content_id("candidate-pair-sha256:", self.to_mapping())

    def to_mapping(self) -> dict[str, Any]:
        return {
            "seed": self.seed,
            "baseline": self.baseline.to_mapping(),
            "candidate": self.candidate.to_mapping(),
        }


@dataclass(frozen=True, slots=True)
class CandidateGatePolicy:
    required_seeds: int = 2
    fresh_improvement: float = 0.02
    regression_noninferiority_margin: float = 0.01
    max_total_cost_increase: float = 0.10
    enforce_cost_limit: bool = False
    min_seed_delta_floor: float = -0.10
    cost_savings_path: float = 0.10

    def __post_init__(self) -> None:
        if isinstance(self.required_seeds, bool) or not isinstance(self.required_seeds, int):
            raise TypeError("required_seeds must be an integer")
        if self.required_seeds < 1:
            raise ValueError("required_seeds must be positive")
        for name in (
            "fresh_improvement",
            "regression_noninferiority_margin",
            "max_total_cost_increase",
            "cost_savings_path",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"{name} must be numeric")
            if not math.isfinite(float(value)) or not 0.0 <= float(value) <= 1.0:
                raise ValueError(f"{name} must be finite and in [0,1]")
        if not isinstance(self.enforce_cost_limit, bool):
            raise TypeError("enforce_cost_limit must be bool")
        floor = self.min_seed_delta_floor
        if isinstance(floor, bool) or not isinstance(floor, (int, float)):
            raise TypeError("min_seed_delta_floor must be numeric")
        if not math.isfinite(float(floor)) or not -1.0 <= float(floor) <= 0.0:
            raise ValueError("min_seed_delta_floor must be finite and in [-1,0]")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "required_seeds": self.required_seeds,
            "fresh_improvement": float(self.fresh_improvement),
            "regression_noninferiority_margin": float(
                self.regression_noninferiority_margin
            ),
            "max_total_cost_increase": float(self.max_total_cost_increase),
            "enforce_cost_limit": self.enforce_cost_limit,
            "min_seed_delta_floor": float(self.min_seed_delta_floor),
            "cost_savings_path": float(self.cost_savings_path),
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> CandidateGatePolicy:
        expected = {
            "required_seeds",
            "fresh_improvement",
            "regression_noninferiority_margin",
            "max_total_cost_increase",
            "enforce_cost_limit",
        }
        optional = {"min_seed_delta_floor", "cost_savings_path"}
        unknown = set(value) - expected - optional
        if unknown:
            raise ValueError("candidate gate policy has unknown fields")
        if not expected <= set(value):
            raise ValueError("candidate gate policy has missing fields")
        return cls(
            required_seeds=value["required_seeds"],
            fresh_improvement=value["fresh_improvement"],
            regression_noninferiority_margin=value[
                "regression_noninferiority_margin"
            ],
            max_total_cost_increase=value["max_total_cost_increase"],
            enforce_cost_limit=value["enforce_cost_limit"],
            min_seed_delta_floor=value.get("min_seed_delta_floor", -0.10),
            cost_savings_path=value.get("cost_savings_path", 0.10),
        )


class CandidateGateDisposition(StrEnum):
    QUALIFIED = "qualified"
    INVALID_DESIGN = "invalid-design"
    NO_FRESH_EVIDENCE = "no-fresh-evidence"
    INTEGRITY_REJECTED = "integrity-rejected"
    FRESH_REJECTED = "fresh-rejected"
    REGRESSION_REJECTED = "regression-rejected"
    COST_REJECTED = "cost-rejected"


@dataclass(frozen=True, slots=True)
class CandidateSeedResult:
    seed: int
    overall_delta: float
    fresh_delta: float
    regression_delta: float

    def to_mapping(self) -> dict[str, Any]:
        return {
            "seed": self.seed,
            "overall_delta": round(self.overall_delta, 12),
            "fresh_delta": round(self.fresh_delta, 12),
            "regression_delta": round(self.regression_delta, 12),
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> CandidateSeedResult:
        if set(value) != {"seed", "overall_delta", "fresh_delta", "regression_delta"}:
            raise ValueError("candidate seed result has missing or unknown fields")
        return cls(
            seed=value["seed"],
            overall_delta=value["overall_delta"],
            fresh_delta=value["fresh_delta"],
            regression_delta=value["regression_delta"],
        )


@dataclass(frozen=True, slots=True)
class CandidateGateReport:
    report_id: str
    disposition: CandidateGateDisposition
    reason: str
    pair_ids: tuple[str, ...]
    policy: CandidateGatePolicy
    seed_results: tuple[CandidateSeedResult, ...]
    total_cost_change: float | None

    def __post_init__(self) -> None:
        if not self.reason or self.reason != self.reason.strip():
            raise ValueError("reason must be non-empty trimmed text")
        if tuple(sorted(set(self.pair_ids))) != self.pair_ids:
            raise ValueError("pair_ids must be sorted and unique")
        seeds = tuple(item.seed for item in self.seed_results)
        if seeds != tuple(sorted(set(seeds))):
            raise ValueError("seed_results must be sorted by distinct seed")
        if self.total_cost_change is not None and not math.isfinite(
            self.total_cost_change
        ):
            raise ValueError("total_cost_change must be finite or null")
        expected = _content_id(
            "candidate-gate-report-sha256:", self.to_mapping(include_id=False)
        )
        if self.report_id != expected:
            raise ValueError("report_id does not match candidate gate evidence")

    @property
    def qualified(self) -> bool:
        return self.disposition is CandidateGateDisposition.QUALIFIED

    def to_mapping(self, *, include_id: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "disposition": self.disposition.value,
            "reason": self.reason,
            "pair_ids": list(self.pair_ids),
            "policy": self.policy.to_mapping(),
            "seed_results": [item.to_mapping() for item in self.seed_results],
            "total_cost_change": (
                None
                if self.total_cost_change is None
                else round(self.total_cost_change, 12)
            ),
        }
        return {"report_id": self.report_id, **payload} if include_id else payload

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> CandidateGateReport:
        expected = {
            "report_id",
            "disposition",
            "reason",
            "pair_ids",
            "policy",
            "seed_results",
            "total_cost_change",
        }
        if set(value) != expected:
            raise ValueError("candidate gate report has missing or unknown fields")
        pair_ids = value["pair_ids"]
        policy = value["policy"]
        results = value["seed_results"]
        if not isinstance(pair_ids, list) or not all(
            isinstance(item, str) for item in pair_ids
        ):
            raise TypeError("pair_ids must be an array of strings")
        if not isinstance(policy, Mapping):
            raise TypeError("policy must be an object")
        if not isinstance(results, list) or not all(
            isinstance(item, Mapping) for item in results
        ):
            raise TypeError("seed_results must be an array of objects")
        cost_change = value["total_cost_change"]
        if cost_change is not None and (
            isinstance(cost_change, bool) or not isinstance(cost_change, (int, float))
        ):
            raise TypeError("total_cost_change must be numeric or null")
        return cls(
            report_id=value["report_id"],
            disposition=CandidateGateDisposition(value["disposition"]),
            reason=value["reason"],
            pair_ids=tuple(pair_ids),
            policy=CandidateGatePolicy.from_mapping(policy),
            seed_results=tuple(CandidateSeedResult.from_mapping(item) for item in results),
            total_cost_change=(None if cost_change is None else float(cost_change)),
        )


def _report(
    pairs: tuple[SealedCandidatePair, ...],
    policy: CandidateGatePolicy,
    disposition: CandidateGateDisposition,
    reason: str,
    *,
    results: tuple[CandidateSeedResult, ...] = (),
    total_cost_change: float | None = None,
) -> CandidateGateReport:
    pair_ids = tuple(sorted({item.pair_id for item in pairs}))
    normalized_results = tuple(
        CandidateSeedResult(
            item.seed,
            round(item.overall_delta, 12),
            round(item.fresh_delta, 12),
            round(item.regression_delta, 12),
        )
        for item in results
    )
    normalized_cost_change = (
        None if total_cost_change is None else round(total_cost_change, 12)
    )
    if results:
        per_seed = ", ".join(
            f"seed {item.seed} fresh {item.fresh_delta:+.4f}"
            for item in normalized_results
        )
        reason = f"{reason} [{per_seed}]"
    payload: dict[str, Any] = {
        "disposition": disposition.value,
        "reason": reason,
        "pair_ids": list(pair_ids),
        "policy": policy.to_mapping(),
        "seed_results": [item.to_mapping() for item in normalized_results],
        "total_cost_change": normalized_cost_change,
    }
    return CandidateGateReport(
        _content_id("candidate-gate-report-sha256:", payload),
        disposition,
        reason,
        pair_ids,
        policy,
        normalized_results,
        normalized_cost_change,
    )


def evaluate_candidate_gate(
    evidence: Iterable[SealedCandidatePair],
    policy: CandidateGatePolicy | None = None,
) -> CandidateGateReport:
    """Apply non-compensable gates to the paired sealed seed evidence.

    Fresh improvement and regression noninferiority are judged on the seed
    mean, with a per-seed floor guarding against a catastrophic single seed
    hiding inside an acceptable mean.  Cost is checked once over the total
    paired usage.
    """

    applied = policy or CandidateGatePolicy()
    pairs = tuple(sorted(evidence, key=lambda item: (item.seed, item.pair_id)))
    if len(pairs) != applied.required_seeds or len({item.seed for item in pairs}) != len(pairs):
        return _report(
            pairs,
            applied,
            CandidateGateDisposition.INVALID_DESIGN,
            f"requires exactly {applied.required_seeds} distinct paired seeds",
        )
    arms = tuple(arm for pair in pairs for arm in (pair.baseline, pair.candidate))
    if any(not arm.integrity_passed for arm in arms):
        return _report(
            pairs,
            applied,
            CandidateGateDisposition.INTEGRITY_REJECTED,
            "integrity failure is non-compensable",
        )
    if any(arm.fresh_quality is None for arm in arms):
        return _report(
            pairs,
            applied,
            CandidateGateDisposition.NO_FRESH_EVIDENCE,
            "both arms require fresh-task evidence for every seed",
        )
    if any(arm.regression_quality is None for arm in arms):
        return _report(
            pairs,
            applied,
            CandidateGateDisposition.INVALID_DESIGN,
            "both arms require HOF or anchor regression evidence for every seed",
        )

    result_rows: list[CandidateSeedResult] = []
    for pair in pairs:
        baseline_fresh = pair.baseline.fresh_quality
        candidate_fresh = pair.candidate.fresh_quality
        baseline_regression = pair.baseline.regression_quality
        candidate_regression = pair.candidate.regression_quality
        assert baseline_fresh is not None and candidate_fresh is not None
        assert baseline_regression is not None and candidate_regression is not None
        result_rows.append(
            CandidateSeedResult(
                pair.seed,
                pair.candidate.overall_quality - pair.baseline.overall_quality,
                candidate_fresh - baseline_fresh,
                candidate_regression - baseline_regression,
            )
        )
    results = tuple(result_rows)
    mean_fresh = sum(item.fresh_delta for item in results) / len(results)
    floored_fresh = tuple(
        item.seed
        for item in results
        if item.fresh_delta + 1e-12 < applied.min_seed_delta_floor
    )
    if floored_fresh:
        return _report(
            pairs,
            applied,
            CandidateGateDisposition.FRESH_REJECTED,
            (
                f"fresh delta collapsed below the per-seed floor "
                f"{applied.min_seed_delta_floor:.4f} for seeds "
                f"{','.join(map(str, floored_fresh))}"
            ),
            results=results,
        )
    mean_regression = sum(item.regression_delta for item in results) / len(results)
    floored_regression = tuple(
        item.seed
        for item in results
        if item.regression_delta + 1e-12 < applied.min_seed_delta_floor
    )
    if mean_regression + 1e-12 < -applied.regression_noninferiority_margin:
        return _report(
            pairs,
            applied,
            CandidateGateDisposition.REGRESSION_REJECTED,
            (
                f"mean regression delta {mean_regression:.4f} below the "
                f"noninferiority margin -{applied.regression_noninferiority_margin:.4f}"
            ),
            results=results,
        )
    if floored_regression:
        return _report(
            pairs,
            applied,
            CandidateGateDisposition.REGRESSION_REJECTED,
            (
                f"regression delta collapsed below the per-seed floor "
                f"{applied.min_seed_delta_floor:.4f} for seeds "
                f"{','.join(map(str, floored_regression))}"
            ),
            results=results,
        )
    baseline_costs = tuple(item.baseline.cost_units for item in pairs)
    candidate_costs = tuple(item.candidate.cost_units for item in pairs)
    total_cost_change: float | None = None
    baseline_values = tuple(item for item in baseline_costs if item is not None)
    candidate_values = tuple(item for item in candidate_costs if item is not None)
    if len(baseline_values) == len(pairs) and len(candidate_values) == len(pairs):
        baseline_cost = sum(baseline_values)
        candidate_cost = sum(candidate_values)
        if baseline_cost > 0:
            total_cost_change = candidate_cost / baseline_cost - 1.0
    if (
        applied.enforce_cost_limit
        and total_cost_change is not None
        and total_cost_change > applied.max_total_cost_increase + 1e-12
    ):
        return _report(
            pairs,
            applied,
            CandidateGateDisposition.COST_REJECTED,
            "candidate total cost exceeds the permitted increase",
            results=results,
            total_cost_change=total_cost_change,
        )
    # Qualification paths.  Fresh improvement is the primary measure, but a
    # trivial fresh task saturates both arms at 1.0 and makes any improvement
    # mathematically unreachable; in that case the regression layer judges
    # improvement, and a strictly cost-saving candidate with noninferior
    # quality can qualify through the cost path.
    fresh_saturated = all(
        arm.fresh_quality is not None and arm.fresh_quality >= 1.0 - 1e-12
        for arm in arms
    )
    if mean_fresh + 1e-12 >= applied.fresh_improvement:
        return _report(
            pairs,
            applied,
            CandidateGateDisposition.QUALIFIED,
            (
                f"seed-mean fresh improvement {mean_fresh:.4f} passed; "
                "regression, floors, and integrity gates all passed; cost is observational"
            ),
            results=results,
            total_cost_change=total_cost_change,
        )
    if (
        fresh_saturated
        and mean_regression + 1e-12 >= applied.fresh_improvement
    ):
        return _report(
            pairs,
            applied,
            CandidateGateDisposition.QUALIFIED,
            (
                "fresh evidence saturated at 1.0 on both arms; seed-mean "
                f"regression improvement {mean_regression:.4f} passed instead"
            ),
            results=results,
            total_cost_change=total_cost_change,
        )
    if (
        total_cost_change is not None
        and applied.cost_savings_path > 0.0
        and mean_fresh >= -applied.regression_noninferiority_margin - 1e-12
        and mean_regression >= -applied.regression_noninferiority_margin - 1e-12
        and total_cost_change <= -applied.cost_savings_path + 1e-12
    ):
        return _report(
            pairs,
            applied,
            CandidateGateDisposition.QUALIFIED,
            (
                f"cost path: quality noninferior with {abs(total_cost_change):.1%} "
                "total cost savings"
            ),
            results=results,
            total_cost_change=total_cost_change,
        )
    return _report(
        pairs,
        applied,
        CandidateGateDisposition.FRESH_REJECTED,
        (
            f"mean fresh improvement {mean_fresh:.4f} below threshold "
            f"{applied.fresh_improvement:.4f}"
        ),
        results=results,
        total_cost_change=total_cost_change,
    )
