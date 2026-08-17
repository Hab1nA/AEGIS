from aegis.failure_taxonomy import (
    CycleOutcomeClass,
    classify_completed_cycle,
    classify_exception,
)


def test_completed_cycle_taxonomy_is_non_overlapping() -> None:
    assert classify_completed_cycle({}, {}, {"unchanged": True}) is CycleOutcomeClass.TASK_OUTCOME
    assert (
        classify_completed_cycle({"rejection_pending": {}}, {}, {"unchanged": True})
        is CycleOutcomeClass.CANDIDATE_REJECTED
    )
    assert (
        classify_completed_cycle({"insufficient_design": {}}, {}, {"unchanged": True})
        is CycleOutcomeClass.INSUFFICIENT_DESIGN
    )
    assert (
        classify_completed_cycle({}, {"qualified": {"warrior": "candidate"}}, {})
        is CycleOutcomeClass.ACTIVATION_INCOMPLETE
    )


def test_learning_degraded_when_fresh_task_supply_failed() -> None:
    blocked = {"learning_outcome": "blocked_by_supply", "registered": []}
    assert (
        classify_completed_cycle({}, {}, {"unchanged": True}, blocked)
        is CycleOutcomeClass.LEARNING_DEGRADED
    )
    degraded = {"learning_outcome": "degraded", "registered": []}
    assert (
        classify_completed_cycle({}, {}, {"unchanged": True}, degraded)
        is CycleOutcomeClass.LEARNING_DEGRADED
    )


def test_progressed_supply_keeps_prior_classification() -> None:
    progressed = {"learning_outcome": "progressed", "registered": [{"task_id": "x"}]}
    assert (
        classify_completed_cycle({}, {}, {"unchanged": True}, progressed)
        is CycleOutcomeClass.TASK_OUTCOME
    )


def test_learning_degraded_yields_to_design_and_rejection_failures() -> None:
    blocked = {"learning_outcome": "blocked_by_supply", "registered": []}
    assert (
        classify_completed_cycle({"insufficient_design": {}}, {}, {"unchanged": True}, blocked)
        is CycleOutcomeClass.INSUFFICIENT_DESIGN
    )
    assert (
        classify_completed_cycle({"rejection_pending": {}}, {}, {"unchanged": True}, blocked)
        is CycleOutcomeClass.CANDIDATE_REJECTED
    )


def test_exception_taxonomy_preserves_activation_boundary() -> None:
    assert classify_exception("activation") is CycleOutcomeClass.ACTIVATION_INCOMPLETE
    assert classify_exception("sealed-evaluation") is CycleOutcomeClass.INFRASTRUCTURE_ERROR
