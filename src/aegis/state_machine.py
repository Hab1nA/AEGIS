"""Deterministic campaign lifecycle with resumable pauses."""

from __future__ import annotations

from threading import RLock

from aegis.models import CampaignState


class InvalidTransitionError(ValueError):
    def __init__(self, current: CampaignState, action: str) -> None:
        self.current = current
        self.action = action
        super().__init__(f"cannot {action!r} from {current.value!r}")


_FORWARD: dict[tuple[CampaignState, str], CampaignState] = {
    (CampaignState.CREATED, "start"): CampaignState.PREPARING,
    (CampaignState.PREPARING, "advance"): CampaignState.WARRIOR_RESEARCH,
    (CampaignState.WARRIOR_RESEARCH, "advance"): CampaignState.WARRIOR_EXECUTE,
    (CampaignState.WARRIOR_EXECUTE, "advance"): CampaignState.FROZEN,
    (CampaignState.FROZEN, "advance"): CampaignState.JUDGE_EVALUATE,
    (CampaignState.JUDGE_EVALUATE, "advance"): CampaignState.QUALITY_LOCKED,
    (CampaignState.QUALITY_LOCKED, "advance"): CampaignState.PROSECUTOR_AUDIT,
    (CampaignState.PROSECUTOR_AUDIT, "advance"): CampaignState.PROMOTION_GATE,
    (CampaignState.PROMOTION_GATE, "next_round"): CampaignState.NEXT_ROUND,
    (CampaignState.PROMOTION_GATE, "complete"): CampaignState.COMPLETED,
    (CampaignState.NEXT_ROUND, "advance"): CampaignState.WARRIOR_RESEARCH,
    (CampaignState.STOPPING, "abort"): CampaignState.ABORTED,
}

_PAUSABLE = frozenset(
    {
        CampaignState.PREPARING,
        CampaignState.WARRIOR_RESEARCH,
        CampaignState.WARRIOR_EXECUTE,
        CampaignState.FROZEN,
        CampaignState.JUDGE_EVALUATE,
        CampaignState.QUALITY_LOCKED,
        CampaignState.PROSECUTOR_AUDIT,
        CampaignState.PROMOTION_GATE,
        CampaignState.NEXT_ROUND,
    }
)
_STOPPABLE = _PAUSABLE | {CampaignState.CREATED, CampaignState.PAUSED}
_FAILABLE = _STOPPABLE | {CampaignState.STOPPING}


def transition(
    current: CampaignState,
    action: str,
    *,
    resume_target: CampaignState | None = None,
) -> CampaignState:
    """Return the next state without mutating external state."""
    if not isinstance(current, CampaignState):
        raise TypeError("current must be a CampaignState")
    if action == "pause" and current in _PAUSABLE:
        return CampaignState.PAUSED
    if action == "resume" and current is CampaignState.PAUSED and resume_target in _PAUSABLE:
        return resume_target
    if action == "stop" and current in _STOPPABLE:
        return CampaignState.STOPPING
    if action == "fail" and current in _FAILABLE:
        return CampaignState.FAILED
    try:
        return _FORWARD[(current, action)]
    except KeyError as exc:
        raise InvalidTransitionError(current, action) from exc


def available_actions(state: CampaignState) -> tuple[str, ...]:
    if not isinstance(state, CampaignState):
        raise TypeError("state must be a CampaignState")
    actions = {action for (source, action), _ in _FORWARD.items() if source is state}
    if state in _PAUSABLE:
        actions.add("pause")
    if state in _STOPPABLE:
        actions.add("stop")
    if state in _FAILABLE:
        actions.add("fail")
    if state is CampaignState.PAUSED:
        actions.add("resume")
    return tuple(sorted(actions))


class CampaignStateMachine:
    """Thread-safe lifecycle holder that remembers a paused stage."""

    def __init__(
        self,
        state: CampaignState = CampaignState.CREATED,
        *,
        resume_target: CampaignState | None = None,
    ) -> None:
        if not isinstance(state, CampaignState):
            raise TypeError("state must be a CampaignState")
        if state is CampaignState.PAUSED:
            if resume_target not in _PAUSABLE:
                raise ValueError("a paused campaign requires a pausable resume target")
        elif resume_target is not None:
            raise ValueError("resume_target is only valid for a paused campaign")
        self._state = state
        self._resume_target = resume_target
        self._lock = RLock()

    @property
    def state(self) -> CampaignState:
        with self._lock:
            return self._state

    @property
    def resume_target(self) -> CampaignState | None:
        with self._lock:
            return self._resume_target

    def apply(self, action: str) -> CampaignState:
        with self._lock:
            previous = self._state
            if action == "pause" and previous in _PAUSABLE:
                self._resume_target = previous
            target = transition(previous, action, resume_target=self._resume_target)
            self._state = target
            if action == "resume" or target is not CampaignState.PAUSED:
                self._resume_target = None
            return target
