"""Stable outcome classes for autonomous cycle evidence and recovery policy."""

from __future__ import annotations

from enum import StrEnum
from typing import Mapping


class CycleOutcomeClass(StrEnum):
    TASK_OUTCOME = "task-outcome"
    CANDIDATE_REJECTED = "candidate-rejected"
    INSUFFICIENT_DESIGN = "insufficient-design"
    LEARNING_DEGRADED = "learning-degraded"
    INFRASTRUCTURE_ERROR = "infrastructure-error"
    ACTIVATION_INCOMPLETE = "activation-incomplete"


def classify_completed_cycle(
    candidate_evaluation: Mapping[str, object],
    qualification: Mapping[str, object],
    activation: Mapping[str, object],
    task_validation: Mapping[str, object] | None = None,
) -> CycleOutcomeClass:
    """Classify a completed cycle without conflating task quality and infra faults."""
    if candidate_evaluation.get("insufficient_design") is not None:
        return CycleOutcomeClass.INSUFFICIENT_DESIGN
    if candidate_evaluation.get("rejection_pending") is not None:
        return CycleOutcomeClass.CANDIDATE_REJECTED
    if (
        task_validation is not None
        and task_validation.get("learning_outcome") in {"degraded", "blocked_by_supply"}
    ):
        return CycleOutcomeClass.LEARNING_DEGRADED
    if qualification.get("qualified") and not (
        activation.get("unchanged") is False and activation.get("intent_id")
    ):
        return CycleOutcomeClass.ACTIVATION_INCOMPLETE
    return CycleOutcomeClass.TASK_OUTCOME


def classify_exception(stage: str) -> CycleOutcomeClass:
    """Activation failures stay distinguishable from control-plane infra failures."""
    return (
        CycleOutcomeClass.ACTIVATION_INCOMPLETE
        if stage == "activation"
        else CycleOutcomeClass.INFRASTRUCTURE_ERROR
    )
