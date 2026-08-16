from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from aegis.artifacts import ContentAddressedArtifactStore
from aegis.event_store import EventStore
from aegis.gateway.types import (
    GatewayAttempt,
    GatewayAttemptResult,
    GatewayRequest,
    Message,
    TokenUsage,
)
from aegis.models import Role
from aegis.runtime_ledger import (
    AccountingContext,
    GatewayAttemptObserver,
    RuntimeBudgetExceeded,
    RuntimeLedgerIntegrityError,
)
from aegis.runtime_policy import RuntimePolicyRegistry, RuntimeStageBoundary


def _values(**overrides: Any) -> dict[str, Any]:
    values = {
        "max_cost_usd": 10.0,
        "max_total_tokens": 10_000,
        "max_requests": 20,
        "max_rounds": 10,
        "max_runtime_seconds": 3600.0,
        "role_budget_shares": {"warrior": 0.4, "judge": 0.3, "prosecutor": 0.3},
        "role_max_output_tokens": {"warrior": 1000, "judge": 1000, "prosecutor": 1000},
        "max_steps": 20,
        "candidate_max_extra_steps": 12,
        "subagent_max_steps": 8,
        "command_timeout_seconds": 300.0,
        "sealed_timeout_seconds": 1800.0,
        "subagent_timeout_seconds": 180.0,
        "build_timeout_seconds": 3600.0,
        "scan_timeout_seconds": 600.0,
        "council_max_messages": 12,
        "council_max_tokens": 16_384,
    }
    values.update(overrides)
    return values


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 8, 11, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value


def _setup(
    tmp_path: Path,
    *,
    values: dict[str, Any] | None = None,
    context: AccountingContext | None = None,
) -> tuple[EventStore, RuntimePolicyRegistry, GatewayAttemptObserver, GatewayRequest, Clock]:
    store = EventStore(tmp_path / "events.sqlite3")
    registry = RuntimePolicyRegistry(
        store, ContentAddressedArtifactStore(tmp_path / "artifacts"), "campaign-a"
    )
    registry.genesis(values or _values(), {role.value: 2000 for role in Role})
    active = context or AccountingContext(
        "campaign-a", 0, "warrior", Role.WARRIOR, "invocation-1"
    )
    clock = Clock()
    observer = GatewayAttemptObserver(store, registry, lambda _request: active, clock=clock)
    request = GatewayRequest("model", (Message("user", "hello"),), 10)
    return store, registry, observer, request, clock


def _attempt(request: GatewayRequest, number: int = 1, protocol: str = "responses") -> GatewayAttempt:
    return GatewayAttempt(protocol, number, request, TokenUsage(5, 15, 5, 15, False))


def test_reserve_and_settle_are_exactly_once_and_replayable(tmp_path: Path) -> None:
    store, registry, observer, request, clock = _setup(tmp_path)
    attempt = _attempt(request)
    observer.before_attempt(attempt)
    observer.before_attempt(attempt)
    assert observer.consumed().total_tokens == 20
    assert observer.consumed().unsettled_requests == 1

    clock.value += timedelta(seconds=2.5)
    result = GatewayAttemptResult(True, TokenUsage(3, 2), status=200)
    observer.after_attempt(attempt, result)
    observer.after_attempt(attempt, result)

    replayed = GatewayAttemptObserver(store, registry, lambda _request: observer._context(request))
    consumed = replayed.consumed()
    assert consumed.total_tokens == 5
    assert consumed.verified_tokens == 5
    assert consumed.requests == consumed.rounds == 1
    assert consumed.runtime_seconds == 2.5
    assert consumed.unsettled_requests == 0
    assert [event.event_type for event in store.read("campaign-a")].count(
        "gateway_attempt_reserved"
    ) == 1
    assert [event.event_type for event in store.read("campaign-a")].count(
        "gateway_attempt_settled"
    ) == 1
    store.close()


def test_unsettled_replay_keeps_conservative_usage(tmp_path: Path) -> None:
    store, registry, observer, request, _ = _setup(tmp_path)
    observer.before_attempt(_attempt(request))
    replayed = GatewayAttemptObserver(
        store,
        registry,
        lambda _request: AccountingContext(
            "campaign-a", 0, "warrior", Role.WARRIOR, "invocation-1"
        ),
    )
    assert replayed.consumed().unverified_tokens == 20
    assert replayed.consumed().unsettled_requests == 1
    store.close()


@pytest.mark.parametrize(
    ("result", "expected_error"),
    [
        (GatewayAttemptResult(False, TokenUsage(5, 15, verified=False), 429, "GatewayHTTPError"), "GatewayHTTPError"),
        (GatewayAttemptResult(False, TokenUsage(5, 15, verified=False), None, "URLError"), "URLError"),
        (GatewayAttemptResult(False, TokenUsage(5, 15, verified=False), None, "GatewayCancelled"), "GatewayCancelled"),
        (GatewayAttemptResult(False, TokenUsage(5, 15, verified=False), 200, "JSONDecodeError"), "JSONDecodeError"),
    ],
)
def test_every_failure_class_settles_once(
    tmp_path: Path, result: GatewayAttemptResult, expected_error: str
) -> None:
    store, _, observer, request, _ = _setup(tmp_path)
    attempt = _attempt(request)
    observer.before_attempt(attempt)
    observer.after_attempt(attempt, result)
    settlement = [
        event for event in store.read("campaign-a") if event.event_type == "gateway_attempt_settled"
    ][0]
    assert settlement.payload["error_type"] == expected_error
    # Failed attempts are waste: they never consume the normal envelope.
    consumed = observer.consumed()
    assert consumed.total_tokens == 0
    assert consumed.waste_tokens == 20
    store.close()


def test_retries_and_protocol_fallback_are_independent_attempts_in_one_round(tmp_path: Path) -> None:
    store, _, observer, request, _ = _setup(tmp_path)
    attempts = (
        _attempt(request, 1, "responses"),
        _attempt(request, 2, "responses"),
        _attempt(request, 1, "chat"),
    )
    for attempt in attempts:
        observer.before_attempt(attempt)
        observer.after_attempt(
            attempt,
            GatewayAttemptResult(False, attempt.conservative_usage, 503, "GatewayHTTPError"),
        )
    consumed = observer.consumed()
    assert consumed.requests == 0
    assert consumed.rounds == 0
    assert consumed.total_tokens == 0
    assert consumed.waste_requests == 3
    assert consumed.waste_tokens == 60
    store.close()


def test_timeout_storm_does_not_consume_budget_or_trigger_exhaustion(tmp_path: Path) -> None:
    store, _registry, observer, request, _ = _setup(
        tmp_path,
        values=_values(max_requests=2, max_total_tokens=1000, max_runtime_seconds=100.0),
    )
    for number in range(1, 6):
        attempt = _attempt(request, number)
        observer.before_attempt(attempt)
        observer.after_attempt(
            attempt,
            GatewayAttemptResult(False, attempt.conservative_usage, None, "TimeoutError"),
        )
    consumed = observer.consumed()
    assert consumed.requests == 0
    assert consumed.total_tokens == 0
    assert consumed.runtime_seconds == 0.0
    assert consumed.waste_requests == 5
    # A subsequent successful attempt is still allowed: failures never touch
    # the normal envelope (max_requests=2 would otherwise be exhausted).
    observer.before_attempt(_attempt(request, 6))
    assert observer.consumed().requests == 1
    store.close()


def test_effective_budget_is_checked_before_reservation(tmp_path: Path) -> None:
    store, _, observer, request, _ = _setup(
        tmp_path, values=_values(max_total_tokens=39, max_requests=1, max_rounds=1)
    )
    observer.before_attempt(_attempt(request))
    with pytest.raises(RuntimeBudgetExceeded, match="max_total_tokens"):
        observer.before_attempt(_attempt(request, 2))
    assert observer.consumed().requests == 1
    store.close()


def test_request_round_and_runtime_limits_are_each_enforced(tmp_path: Path) -> None:
    store, _, observer, request, _ = _setup(tmp_path / "requests", values=_values(max_requests=1))
    observer.before_attempt(_attempt(request))
    with pytest.raises(RuntimeBudgetExceeded, match="max_requests"):
        observer.before_attempt(_attempt(request, 2))
    store.close()

    active = AccountingContext("campaign-a", 0, "warrior", Role.WARRIOR, "round-1")
    store, registry, _, request, _ = _setup(
        tmp_path / "rounds", values=_values(max_rounds=1), context=active
    )
    observer = GatewayAttemptObserver(store, registry, lambda _request: active)
    observer.before_attempt(_attempt(request))
    active = AccountingContext("campaign-a", 0, "judge", Role.JUDGE, "round-2")
    with pytest.raises(RuntimeBudgetExceeded, match="max_rounds"):
        observer.before_attempt(_attempt(request, 1, "chat"))
    store.close()

    store, _, observer, request, clock = _setup(
        tmp_path / "runtime", values=_values(max_runtime_seconds=1.0)
    )
    first = _attempt(request)
    observer.before_attempt(first)
    clock.value += timedelta(seconds=2)
    observer.after_attempt(first, GatewayAttemptResult(True, TokenUsage(1, 1), 200))
    with pytest.raises(RuntimeBudgetExceeded, match="max_runtime_seconds"):
        observer.before_attempt(_attempt(request, 2))
    store.close()


def test_paired_design_uses_frozen_policy_after_next_cycle_amendment(tmp_path: Path) -> None:
    context = AccountingContext(
        "campaign-a", 1, "sealed", Role.JUDGE, "paired-invocation", "design-a"
    )
    store, registry, _, request, _ = _setup(tmp_path, context=context)
    registry.freeze_for_paired_design("design-a", 0)
    registry.request_patch(
        requested_by=Role.PROSECUTOR,
        current_cycle=0,
        patch={"max_requests": 1},
        consumed={},
        reason="tighten the next cycle",
    )
    observer = GatewayAttemptObserver(store, registry, lambda _request: context)
    observer.before_attempt(_attempt(request, 1))
    observer.before_attempt(_attempt(request, 2))
    assert observer.consumed().requests == 2
    store.close()


def test_ledger_switches_policy_at_stage_boundary_but_paired_context_stays_frozen(
    tmp_path: Path,
) -> None:
    store, registry, _, request, _ = _setup(tmp_path)
    current = RuntimeStageBoundary(0, 2, "prosecutor")
    following = RuntimeStageBoundary(0, 3, "judge")
    design_id = "design-stage-aware"
    registry.freeze_for_paired_design(design_id, 0, boundary=current)
    registry.request_patch_after_stage(
        requested_by=Role.PROSECUTOR,
        requested_at=current,
        effective_at=following,
        patch={"max_requests": 1},
        consumed={},
        reason="limit requests beginning with the judge stage",
    )

    active = AccountingContext(
        "campaign-a", 0, "judge", Role.JUDGE, "judge-normal", stage_ordinal=3
    )
    observer = GatewayAttemptObserver(store, registry, lambda _request: active)
    observer.before_attempt(_attempt(request, 1))
    with pytest.raises(RuntimeBudgetExceeded, match="max_requests"):
        observer.before_attempt(_attempt(request, 2))

    active = AccountingContext(
        "campaign-a",
        0,
        "sealed",
        Role.JUDGE,
        "judge-paired",
        paired_design_id=design_id,
        stage_ordinal=4,
    )
    observer.before_attempt(_attempt(request, 1, "chat"))
    assert observer.consumed().requests == 2
    store.close()


def test_maintenance_only_allows_one_prosecutor_invocation_and_three_attempts(
    tmp_path: Path,
) -> None:
    store = EventStore(tmp_path / "events.sqlite3")
    registry = RuntimePolicyRegistry(
        store, ContentAddressedArtifactStore(tmp_path / "artifacts"), "campaign-a"
    )
    registry.genesis(_values(), {role.value: 2000 for role in Role})
    registry.request_patch(
        requested_by=Role.PROSECUTOR,
        current_cycle=0,
        patch={"max_requests": 1},
        consumed={"max_requests": 2},
        reason="enter maintenance",
    )
    active = AccountingContext(
        "campaign-a", 1, "maintenance", Role.PROSECUTOR, "maintenance-1"
    )
    observer = GatewayAttemptObserver(store, registry, lambda _request: active)
    request = GatewayRequest("model", (Message("user", "repair"),), 10)
    for number in range(1, 4):
        observer.before_attempt(_attempt(request, number))
    with pytest.raises(RuntimeBudgetExceeded, match="three transport attempts"):
        observer.before_attempt(_attempt(request, 4))

    active = AccountingContext(
        "campaign-a", 1, "maintenance", Role.PROSECUTOR, "maintenance-2"
    )
    with pytest.raises(RuntimeBudgetExceeded, match="one invocation"):
        observer.before_attempt(_attempt(request, 1, "chat"))
    active = AccountingContext("campaign-a", 1, "warrior", Role.WARRIOR, "warrior-1")
    with pytest.raises(RuntimeBudgetExceeded, match="prosecutor maintenance"):
        observer.before_attempt(_attempt(request, 1, "chat"))
    store.close()


def test_inconsistent_second_settlement_is_rejected(tmp_path: Path) -> None:
    store, _, observer, request, _ = _setup(tmp_path)
    attempt = _attempt(request)
    observer.before_attempt(attempt)
    observer.after_attempt(attempt, GatewayAttemptResult(True, TokenUsage(1, 1), 200))
    with pytest.raises(RuntimeLedgerIntegrityError, match="settled inconsistently"):
        observer.after_attempt(
            attempt,
            GatewayAttemptResult(False, attempt.conservative_usage, 500, "GatewayHTTPError"),
        )
    store.close()


def test_replay_rejects_malformed_accounting_events(tmp_path: Path) -> None:
    store, _, observer, _, _ = _setup(tmp_path)
    store.append("campaign-a", "gateway_attempt_reserved", {"attempt_id": "forged"})
    with pytest.raises(RuntimeLedgerIntegrityError, match="invalid schema"):
        observer.consumed()
    store.close()
