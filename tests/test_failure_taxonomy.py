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


def test_exception_taxonomy_preserves_activation_boundary() -> None:
    assert classify_exception("activation") is CycleOutcomeClass.ACTIVATION_INCOMPLETE
    assert classify_exception("sealed-evaluation") is CycleOutcomeClass.INFRASTRUCTURE_ERROR
