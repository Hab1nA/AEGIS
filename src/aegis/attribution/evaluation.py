"""Deterministic causal qualification over strictly paired observations."""

from __future__ import annotations

from collections.abc import Iterable
from statistics import fmean

from .models import (
    AttributionDisposition,
    AttributionReport,
    PairedObservation,
    QualificationPath,
    QualificationPolicy,
)

_INTERVENTION_COORDINATES = frozenset({"plugin_ids", "runtime_variant"})


def _report(
    rows: tuple[PairedObservation, ...],
    policy: QualificationPolicy,
    disposition: AttributionDisposition,
    reason: str,
    *,
    path: QualificationPath = QualificationPath.NONE,
    quality_delta: float = 0.0,
    cost_change: float = 0.0,
) -> AttributionReport:
    return AttributionReport.create(
        disposition=disposition,
        qualification_path=path,
        reason=reason,
        observation_ids=sorted({row.observation_id for row in rows}),
        policy=policy,
        quality_delta=quality_delta,
        cost_change=cost_change,
    )


def _cohort_key(row: PairedObservation) -> tuple[object, ...]:
    baseline = row.baseline
    candidate = row.candidate
    teammate_generations = tuple(
        (item.role, item.generation, item.generation_id)
        for item in baseline.role_generations
        if item.role != row.target_role
    )
    return (
        row.target_role,
        baseline.cycle_id,
        baseline.objective_id,
        baseline.model_id,
        baseline.environment_id,
        baseline.plugin_ids,
        teammate_generations,
        baseline.generation_for(row.target_role),
        candidate.generation_for(row.target_role),
    )


def qualify_attribution(
    observations: Iterable[PairedObservation],
    policy: QualificationPolicy | None = None,
) -> AttributionReport:
    """Return a replay-stable report; all unsafe or ambiguous evidence fails closed."""

    applied = policy or QualificationPolicy()
    rows = tuple(sorted(observations, key=lambda item: item.observation_id))
    if not rows:
        raise ValueError("attribution requires at least one paired observation")
    if len({row.observation_id for row in rows}) != len(rows):
        return _report(
            rows,
            applied,
            AttributionDisposition.INVALID_DESIGN,
            "duplicate paired observations are not allowed",
        )
    if len(rows) < applied.minimum_pairs:
        return _report(
            rows,
            applied,
            AttributionDisposition.INVALID_DESIGN,
            f"requires at least {applied.minimum_pairs} paired observations",
        )

    changed_sets = {row.intervention_fields() for row in rows}
    if len(changed_sets) != 1:
        return _report(
            rows,
            applied,
            AttributionDisposition.CONFOUNDED,
            "paired observations disagree on the intervention coordinates",
        )
    changed = next(iter(changed_sets))
    if any(field not in _INTERVENTION_COORDINATES for field in changed):
        return _report(
            rows,
            applied,
            AttributionDisposition.CONFOUNDED,
            f"paired observation changes a structural coordinate: {','.join(changed)}",
        )
    if len(changed) > 1:
        return _report(
            rows,
            applied,
            AttributionDisposition.CONFOUNDED,
            f"paired observation changes multiple coordinates: {','.join(changed)}",
        )
    if changed:
        intervention = changed[0]
    else:
        intervention = ""
    if len({_cohort_key(row) for row in rows}) != 1:
        return _report(
            rows,
            applied,
            AttributionDisposition.CONFOUNDED,
            "observation cohort changes the causal intervention tuple",
        )

    arms = tuple(arm for row in rows for arm in (row.baseline, row.candidate))
    if any(not arm.integrity_passed for arm in arms):
        return _report(
            rows,
            applied,
            AttributionDisposition.INTEGRITY_REJECTED,
            "integrity failure is non-compensable",
        )
    if any(not arm.safety_passed for arm in arms):
        return _report(
            rows,
            applied,
            AttributionDisposition.SAFETY_REJECTED,
            "safety failure is non-compensable",
        )
    if any(not arm.usage_verified for arm in arms):
        return _report(
            rows,
            applied,
            AttributionDisposition.UNVERIFIED_USAGE,
            "verified usage is required for both paired arms",
        )

    quality_delta = fmean(row.candidate.quality - row.baseline.quality for row in rows)
    baseline_cost = sum(row.baseline.cost_units for row in rows)
    candidate_cost = sum(row.candidate.cost_units for row in rows)
    if baseline_cost <= 0:
        return _report(
            rows,
            applied,
            AttributionDisposition.INVALID_DESIGN,
            "baseline aggregate cost must be positive",
            quality_delta=quality_delta,
        )
    cost_change = candidate_cost / baseline_cost - 1.0
    quality_win = (
        quality_delta >= applied.quality_improvement
        and cost_change <= applied.max_cost_increase
    )
    efficiency_win = (
        quality_delta >= -applied.noninferiority_margin
        and -cost_change >= applied.minimum_cost_saving
    )
    if quality_win:
        return _report(
            rows,
            applied,
            AttributionDisposition.QUALIFIED,
            (
                f"quality improvement and cost cap passed over intervention {intervention}"
                if intervention
                else "quality improvement and cost cap passed"
            ),
            path=QualificationPath.QUALITY_IMPROVEMENT,
            quality_delta=quality_delta,
            cost_change=cost_change,
        )
    if efficiency_win:
        return _report(
            rows,
            applied,
            AttributionDisposition.QUALIFIED,
            (
                f"quality noninferiority and cost saving passed over intervention {intervention}"
                if intervention
                else "quality noninferiority and cost saving passed"
            ),
            path=QualificationPath.COST_EFFICIENCY,
            quality_delta=quality_delta,
            cost_change=cost_change,
        )
    return _report(
        rows,
        applied,
        AttributionDisposition.NOT_QUALIFIED,
        "candidate met neither deterministic qualification path",
        quality_delta=quality_delta,
        cost_change=cost_change,
    )
