"""Deterministic, resumable lifecycle for an AEGIS v2 curriculum cycle."""

from __future__ import annotations

from enum import StrEnum
from threading import RLock


class CycleState(StrEnum):
    CREATED = "created"
    SNAPSHOT_LOCKED = "snapshot_locked"
    COHORT_LOCKED = "cohort_locked"
    SOLUTIONS_COLLECTED = "solutions_collected"
    SUBMISSION_FROZEN = "submission_frozen"
    JUDGE_REVIEWED = "judge_reviewed"
    QUALITY_LOCKED = "quality_locked"
    PROSECUTOR_AUDITED = "prosecutor_audited"
    INDEPENDENT_REFLECTIONS_RECORDED = "independent_reflections_recorded"
    COUNCIL_COMPLETED = "council_completed"
    NEXT_TASKS_FORGED = "next_tasks_forged"
    TASKS_VALIDATED = "tasks_validated"
    ATTRIBUTION_LOCKED = "attribution_locked"
    ROLE_CANDIDATES_QUALIFIED = "role_candidates_qualified"
    ACTIVATION_SET_COMMITTED = "activation_set_committed"
    COMPLETED = "completed"
    PAUSED = "paused"
    STOPPING = "stopping"
    ABORTED = "aborted"
    FAILED = "failed"

    @property
    def terminal(self) -> bool:
        return self in {self.COMPLETED, self.ABORTED, self.FAILED}


class InvalidCycleTransitionError(ValueError):
    def __init__(self, current: CycleState, action: str) -> None:
        self.current = current
        self.action = action
        super().__init__(f"cannot {action!r} from curriculum cycle state {current.value!r}")


_ORDER = (
    CycleState.CREATED,
    CycleState.SNAPSHOT_LOCKED,
    CycleState.COHORT_LOCKED,
    CycleState.SOLUTIONS_COLLECTED,
    CycleState.SUBMISSION_FROZEN,
    CycleState.JUDGE_REVIEWED,
    CycleState.QUALITY_LOCKED,
    CycleState.PROSECUTOR_AUDITED,
    CycleState.INDEPENDENT_REFLECTIONS_RECORDED,
    CycleState.COUNCIL_COMPLETED,
    CycleState.NEXT_TASKS_FORGED,
    CycleState.TASKS_VALIDATED,
    CycleState.ATTRIBUTION_LOCKED,
    CycleState.ROLE_CANDIDATES_QUALIFIED,
    CycleState.ACTIVATION_SET_COMMITTED,
    CycleState.COMPLETED,
)

_NAMED_FORWARD: dict[tuple[CycleState, str], CycleState] = {
    (CycleState.CREATED, "lock_snapshot"): CycleState.SNAPSHOT_LOCKED,
    (CycleState.CREATED, "start"): CycleState.SNAPSHOT_LOCKED,
    (CycleState.SNAPSHOT_LOCKED, "lock_cohort"): CycleState.COHORT_LOCKED,
    (CycleState.COHORT_LOCKED, "collect_solutions"): CycleState.SOLUTIONS_COLLECTED,
    (CycleState.SOLUTIONS_COLLECTED, "freeze_submission"): CycleState.SUBMISSION_FROZEN,
    (CycleState.SUBMISSION_FROZEN, "record_judge_review"): CycleState.JUDGE_REVIEWED,
    (CycleState.JUDGE_REVIEWED, "lock_quality"): CycleState.QUALITY_LOCKED,
    (CycleState.QUALITY_LOCKED, "record_prosecutor_audit"): CycleState.PROSECUTOR_AUDITED,
    (
        CycleState.PROSECUTOR_AUDITED,
        "record_independent_reflections",
    ): CycleState.INDEPENDENT_REFLECTIONS_RECORDED,
    (
        CycleState.INDEPENDENT_REFLECTIONS_RECORDED,
        "complete_council",
    ): CycleState.COUNCIL_COMPLETED,
    (CycleState.COUNCIL_COMPLETED, "complete_task_forge"): CycleState.NEXT_TASKS_FORGED,
    (CycleState.NEXT_TASKS_FORGED, "complete_task_validation"): CycleState.TASKS_VALIDATED,
    (CycleState.TASKS_VALIDATED, "lock_attribution"): CycleState.ATTRIBUTION_LOCKED,
    (CycleState.ATTRIBUTION_LOCKED, "qualify_role_candidates"): CycleState.ROLE_CANDIDATES_QUALIFIED,
    (CycleState.ROLE_CANDIDATES_QUALIFIED, "commit_activation_set"): CycleState.ACTIVATION_SET_COMMITTED,
    (CycleState.ACTIVATION_SET_COMMITTED, "complete"): CycleState.COMPLETED,
    (CycleState.STOPPING, "abort"): CycleState.ABORTED,
}
_NEXT = {source: target for source, target in zip(_ORDER, _ORDER[1:])}
_ACTIVE = frozenset(_ORDER[:-1])
_STOPPABLE = _ACTIVE | {CycleState.PAUSED}
_FAILABLE = _STOPPABLE | {CycleState.STOPPING}


def cycle_transition(
    current: CycleState,
    action: str,
    *,
    resume_target: CycleState | None = None,
) -> CycleState:
    """Return the next state without mutating external state."""

    if not isinstance(current, CycleState):
        raise TypeError("current must be a CycleState")
    if not isinstance(action, str) or not action:
        raise ValueError("action must be non-empty text")
    if action == "pause" and current in _ACTIVE:
        return CycleState.PAUSED
    if action == "resume" and current is CycleState.PAUSED and resume_target in _ACTIVE:
        return resume_target
    if action == "stop" and current in _STOPPABLE:
        return CycleState.STOPPING
    if action == "fail" and current in _FAILABLE:
        return CycleState.FAILED
    if action == "retry" and current is CycleState.FAILED:
        return CycleState.CREATED
    if action == "advance" and current in _NEXT:
        return _NEXT[current]
    try:
        return _NAMED_FORWARD[(current, action)]
    except KeyError as exc:
        raise InvalidCycleTransitionError(current, action) from exc


def available_cycle_actions(state: CycleState) -> tuple[str, ...]:
    if not isinstance(state, CycleState):
        raise TypeError("state must be a CycleState")
    actions = {action for (source, action), _ in _NAMED_FORWARD.items() if source is state}
    if state in _NEXT:
        actions.add("advance")
    if state in _ACTIVE:
        actions.add("pause")
    if state in _STOPPABLE:
        actions.add("stop")
    if state in _FAILABLE:
        actions.add("fail")
    if state is CycleState.PAUSED:
        actions.add("resume")
    if state is CycleState.FAILED:
        actions.add("retry")
    return tuple(sorted(actions))


class CycleStateMachine:
    """Thread-safe lifecycle holder that remembers the exact paused stage."""

    def __init__(
        self,
        state: CycleState = CycleState.CREATED,
        *,
        resume_target: CycleState | None = None,
    ) -> None:
        if not isinstance(state, CycleState):
            raise TypeError("state must be a CycleState")
        if state is CycleState.PAUSED:
            if resume_target not in _ACTIVE:
                raise ValueError("a paused curriculum cycle requires an active resume target")
        elif resume_target is not None:
            raise ValueError("resume_target is only valid for a paused curriculum cycle")
        self._state = state
        self._resume_target = resume_target
        self._lock = RLock()

    @property
    def state(self) -> CycleState:
        with self._lock:
            return self._state

    @property
    def resume_target(self) -> CycleState | None:
        with self._lock:
            return self._resume_target

    def apply(self, action: str) -> CycleState:
        with self._lock:
            previous = self._state
            if action == "pause" and previous in _ACTIVE:
                self._resume_target = previous
            target = cycle_transition(previous, action, resume_target=self._resume_target)
            self._state = target
            if action == "resume" or target is not CycleState.PAUSED:
                self._resume_target = None
            return target
