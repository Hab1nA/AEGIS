"""Durable, exactly-once accounting for model gateway transport attempts.

The ledger deliberately observes transport attempts rather than logical model
calls: retries consume provider resources and therefore must each be reserved
and settled.  Reservations are append-only EventStore records, so an
interrupted process conservatively retains the reserved usage.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock, RLock
from typing import Callable, Mapping, cast

from aegis.event_store import EventStore, EventStoreSequenceConflict
from aegis.gateway.types import GatewayAttempt, GatewayAttemptResult, GatewayRequest, TokenUsage
from aegis.models import JsonValue, Role, canonical_json, thaw_json
from aegis.runtime_policy import (
    RuntimePolicyRegistry,
    RuntimePolicyVersion,
)

_RESERVED = "gateway_attempt_reserved"
_SETTLED = "gateway_attempt_settled"


class RuntimeLedgerError(RuntimeError):
    """Base error for invalid or inconsistent runtime-ledger state."""


class RuntimeBudgetExceeded(RuntimeLedgerError):
    """Raised before transport I/O when the effective policy denies an attempt."""


class RuntimeLedgerIntegrityError(RuntimeLedgerError):
    """Raised when persisted accounting is malformed or contradictory."""


@dataclass(frozen=True, slots=True)
class AccountingContext:
    """Stable ownership of one logical gateway invocation."""

    campaign_id: str
    cycle: int
    stage: str
    role: Role
    invocation_id: str
    paired_design_id: str | None = None
    stage_ordinal: int = 0

    def __post_init__(self) -> None:
        for value, name in (
            (self.campaign_id, "campaign_id"),
            (self.stage, "stage"),
            (self.invocation_id, "invocation_id"),
        ):
            if not isinstance(value, str) or not value.strip() or value != value.strip():
                raise ValueError(f"{name} must be non-empty without surrounding whitespace")
        if isinstance(self.cycle, bool) or not isinstance(self.cycle, int) or self.cycle < 0:
            raise ValueError("cycle must be a non-negative integer")
        if not isinstance(self.role, Role):
            raise TypeError("role must be a Role")
        if self.paired_design_id is not None and (
            not isinstance(self.paired_design_id, str)
            or not self.paired_design_id.strip()
            or self.paired_design_id != self.paired_design_id.strip()
        ):
            raise ValueError("paired_design_id must be null or non-empty text")
        if (
            isinstance(self.stage_ordinal, bool)
            or not isinstance(self.stage_ordinal, int)
            or self.stage_ordinal < 0
        ):
            raise ValueError("stage_ordinal must be a non-negative integer")

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "campaign_id": self.campaign_id,
            "cycle": self.cycle,
            "stage": self.stage,
            "role": self.role.value,
            "invocation_id": self.invocation_id,
            "paired_design_id": self.paired_design_id,
            "stage_ordinal": self.stage_ordinal,
        }

    @classmethod
    def from_mapping(cls, value: object) -> AccountingContext:
        fields = {
            "campaign_id",
            "cycle",
            "stage",
            "role",
            "invocation_id",
            "paired_design_id",
            "stage_ordinal",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise RuntimeLedgerIntegrityError("accounting context has an invalid schema")
        try:
            return cls(
                campaign_id=cast(str, value["campaign_id"]),
                cycle=cast(int, value["cycle"]),
                stage=cast(str, value["stage"]),
                role=Role(cast(str, value["role"])),
                invocation_id=cast(str, value["invocation_id"]),
                paired_design_id=cast(str | None, value["paired_design_id"]),
                stage_ordinal=cast(int, value["stage_ordinal"]),
            )
        except (TypeError, ValueError) as exc:
            raise RuntimeLedgerIntegrityError("accounting context is invalid") from exc


@dataclass(frozen=True, slots=True)
class RuntimeConsumption:
    total_tokens: int = 0
    requests: int = 0
    rounds: int = 0
    runtime_seconds: float = 0.0
    verified_tokens: int = 0
    unverified_tokens: int = 0
    unsettled_requests: int = 0

    def to_policy_mapping(self) -> dict[str, int | float]:
        """Return names accepted by ``RuntimePolicyRegistry.request_patch``."""
        return {
            "max_total_tokens": self.total_tokens,
            "max_requests": self.requests,
            "max_rounds": self.rounds,
            "max_runtime_seconds": self.runtime_seconds,
        }


@dataclass(frozen=True, slots=True)
class _Reservation:
    attempt_id: str
    context: AccountingContext
    policy_id: str
    protocol: str
    attempt_number: int
    request_digest: str
    usage: TokenUsage
    reserved_at: datetime


@dataclass(frozen=True, slots=True)
class _Settlement:
    attempt_id: str
    succeeded: bool
    usage: TokenUsage
    status: int | None
    error_type: str | None
    runtime_seconds: float


_LOCKS_GUARD = Lock()
_LOCKS: dict[tuple[str, str], RLock] = {}


def _ledger_lock(store: EventStore, campaign_id: str) -> RLock:
    key = (str(Path(store.path).resolve()), campaign_id)
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(key, RLock())


def _usage_mapping(usage: TokenUsage) -> dict[str, JsonValue]:
    return {
        "input_tokens": usage.input_tokens,
        "output_tokens": usage.output_tokens,
        "cached_tokens": usage.cached_tokens,
        "reasoning_tokens": usage.reasoning_tokens,
        "verified": usage.verified,
    }


def _usage_from_mapping(value: object) -> TokenUsage:
    fields = {"input_tokens", "output_tokens", "cached_tokens", "reasoning_tokens", "verified"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise RuntimeLedgerIntegrityError("token usage has an invalid schema")
    if any(
        isinstance(value[name], bool) or not isinstance(value[name], int)
        for name in ("input_tokens", "output_tokens", "cached_tokens", "reasoning_tokens")
    ) or not isinstance(value["verified"], bool):
        raise RuntimeLedgerIntegrityError("token usage has invalid field types")
    try:
        return TokenUsage(
            cast(int, value["input_tokens"]),
            cast(int, value["output_tokens"]),
            cast(int, value["cached_tokens"]),
            cast(int, value["reasoning_tokens"]),
            value["verified"],
        )
    except (TypeError, ValueError) as exc:
        raise RuntimeLedgerIntegrityError("token usage is invalid") from exc


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise RuntimeLedgerError("ledger clock must return a timezone-aware datetime")
    return value.astimezone(timezone.utc)


class GatewayAttemptObserver:
    """Event-sourced attempt observer enforcing one campaign's runtime policy.

    ``context_provider`` is the temporary integration seam while
    :class:`GatewayRequest` remains intentionally dependency-free.  The caller
    must return one stable context for every request object in an invocation.
    """

    def __init__(
        self,
        store: EventStore,
        policy_registry: RuntimePolicyRegistry,
        context_provider: Callable[[GatewayRequest], AccountingContext],
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if store.path.resolve() != policy_registry.store.path.resolve():
            raise RuntimeLedgerError("ledger and policy registry must share one EventStore")
        self._store = store
        self._registry = policy_registry
        self._campaign_id = policy_registry.campaign_id
        self._context_provider = context_provider
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = _ledger_lock(store, self._campaign_id)

    def before_attempt(self, attempt: GatewayAttempt) -> None:
        context = self._context(attempt.request)
        policy = self._policy(context)
        candidate = self._reservation(attempt, context, policy, _aware_utc(self._clock()))
        with self._lock:
            reservations, settlements = self._replay()
            existing = reservations.get(candidate.attempt_id)
            if existing is not None:
                if not self._same_reservation_identity(existing, candidate):
                    raise RuntimeLedgerIntegrityError("attempt reservation identity collision")
                return
            self._authorize(candidate, policy, reservations, settlements)
            sequence = self._store.max_sequence(self._campaign_id)
            try:
                self._store.append_if_sequence(
                    self._campaign_id,
                    sequence,
                    _RESERVED,
                    self._reservation_mapping(candidate),
                    created_at=candidate.reserved_at,
                )
            except EventStoreSequenceConflict as exc:
                reservations, _ = self._replay()
                existing = reservations.get(candidate.attempt_id)
                if existing is not None and self._same_reservation_identity(existing, candidate):
                    return
                raise RuntimeLedgerError("gateway reservation raced with another writer") from exc

    def after_attempt(self, attempt: GatewayAttempt, result: GatewayAttemptResult) -> None:
        context = self._context(attempt.request)
        policy = self._policy(context)
        identity = self._reservation(attempt, context, policy, _aware_utc(self._clock()))
        now = _aware_utc(self._clock())
        with self._lock:
            reservations, settlements = self._replay()
            reservation = reservations.get(identity.attempt_id)
            if reservation is None:
                raise RuntimeLedgerIntegrityError("cannot settle an unreserved gateway attempt")
            existing = settlements.get(reservation.attempt_id)
            if existing is not None:
                if (
                    existing.succeeded,
                    existing.usage,
                    existing.status,
                    existing.error_type,
                ) != (
                    result.succeeded,
                    result.usage,
                    result.status,
                    result.error_type,
                ):
                    raise RuntimeLedgerIntegrityError("gateway attempt was settled inconsistently")
                return
            runtime = max(0.0, (now - reservation.reserved_at).total_seconds())
            settlement = _Settlement(
                reservation.attempt_id,
                result.succeeded,
                result.usage,
                result.status,
                result.error_type,
                runtime,
            )
            sequence = self._store.max_sequence(self._campaign_id)
            try:
                self._store.append_if_sequence(
                    self._campaign_id,
                    sequence,
                    _SETTLED,
                    self._settlement_mapping(settlement),
                    created_at=now,
                )
            except EventStoreSequenceConflict as exc:
                _, settlements = self._replay()
                existing = settlements.get(reservation.attempt_id)
                if existing is not None and (
                    existing.succeeded,
                    existing.usage,
                    existing.status,
                    existing.error_type,
                ) == (
                    settlement.succeeded,
                    settlement.usage,
                    settlement.status,
                    settlement.error_type,
                ):
                    return
                raise RuntimeLedgerError("gateway settlement raced with another writer") from exc

    def consumed(self) -> RuntimeConsumption:
        """Return current durable consumption, charging open reservations conservatively."""
        with self._lock:
            reservations, settlements = self._replay()
            return self._consumption(reservations, settlements)

    def _context(self, request: GatewayRequest) -> AccountingContext:
        context = self._context_provider(request)
        if not isinstance(context, AccountingContext):
            raise RuntimeLedgerError("context_provider must return AccountingContext")
        if context.campaign_id != self._campaign_id:
            raise RuntimeLedgerError("accounting context belongs to another campaign")
        return context

    def _policy(self, context: AccountingContext) -> RuntimePolicyVersion:
        if context.paired_design_id is not None:
            return self._registry.policy_for_paired_design(context.paired_design_id)
        boundary = self._registry.stage_boundary(
            context.cycle, context.stage_ordinal, context.stage
        )
        return self._registry.effective_for_stage(boundary)

    def _authorize(
        self,
        candidate: _Reservation,
        policy: RuntimePolicyVersion,
        reservations: Mapping[str, _Reservation],
        settlements: Mapping[str, _Settlement],
    ) -> None:
        consumption = self._consumption(reservations, settlements)
        invocation_ids = {item.context.invocation_id for item in reservations.values()}
        new_round = candidate.context.invocation_id not in invocation_ids
        if policy.maintenance_only:
            self._authorize_maintenance(candidate, policy, reservations)
            return
        projected = {
            "max_total_tokens": consumption.total_tokens + candidate.usage.total_tokens,
            "max_requests": consumption.requests + 1,
            "max_rounds": consumption.rounds + int(new_round),
            "max_runtime_seconds": consumption.runtime_seconds,
        }
        for name, amount in projected.items():
            limit = policy.values[name]
            if not isinstance(limit, (int, float)) or isinstance(limit, bool):
                raise RuntimeLedgerIntegrityError(f"runtime policy {name} is not numeric")
            if amount > float(limit):
                raise RuntimeBudgetExceeded(f"runtime policy {name} exhausted")

    @staticmethod
    def _authorize_maintenance(
        candidate: _Reservation,
        policy: RuntimePolicyVersion,
        reservations: Mapping[str, _Reservation],
    ) -> None:
        context = candidate.context
        if context.role is not Role.PROSECUTOR or context.stage != "maintenance":
            raise RuntimeBudgetExceeded("maintenance-only policy permits only prosecutor maintenance")
        prior = [
            item
            for item in reservations.values()
            if item.policy_id == policy.policy_id
            and item.context.cycle == context.cycle
            and item.context.role is Role.PROSECUTOR
            and item.context.stage == "maintenance"
        ]
        invocation_ids = {item.context.invocation_id for item in prior}
        if invocation_ids and context.invocation_id not in invocation_ids:
            raise RuntimeBudgetExceeded("maintenance-only policy permits one invocation")
        same_invocation = [
            item for item in prior if item.context.invocation_id == context.invocation_id
        ]
        if len(same_invocation) >= 3:
            raise RuntimeBudgetExceeded("maintenance invocation is limited to three transport attempts")

    @staticmethod
    def _consumption(
        reservations: Mapping[str, _Reservation],
        settlements: Mapping[str, _Settlement],
    ) -> RuntimeConsumption:
        total = verified = unverified = unsettled = 0
        runtime = 0.0
        invocation_ids: set[str] = set()
        for attempt_id, reservation in reservations.items():
            settlement = settlements.get(attempt_id)
            usage = reservation.usage if settlement is None else settlement.usage
            tokens = usage.total_tokens
            total += tokens
            if usage.verified:
                verified += tokens
            else:
                unverified += tokens
            if settlement is None:
                unsettled += 1
            else:
                runtime += settlement.runtime_seconds
            invocation_ids.add(reservation.context.invocation_id)
        return RuntimeConsumption(
            total_tokens=total,
            requests=len(reservations),
            rounds=len(invocation_ids),
            runtime_seconds=runtime,
            verified_tokens=verified,
            unverified_tokens=unverified,
            unsettled_requests=unsettled,
        )

    @staticmethod
    def _same_reservation_identity(first: _Reservation, second: _Reservation) -> bool:
        return (
            first.attempt_id,
            first.context,
            first.policy_id,
            first.protocol,
            first.attempt_number,
            first.request_digest,
            first.usage,
        ) == (
            second.attempt_id,
            second.context,
            second.policy_id,
            second.protocol,
            second.attempt_number,
            second.request_digest,
            second.usage,
        )

    @staticmethod
    def _request_digest(request: GatewayRequest) -> str:
        material = {
            "model": request.model,
            "messages": [
                {"role": message.role, "content": message.content} for message in request.messages
            ],
            "max_output_tokens": request.max_output_tokens,
            "temperature": request.temperature,
            "tools": list(request.tools),
            "output_schema": request.output_schema,
            "seed": request.seed,
            "reasoning_effort": request.reasoning_effort,
        }
        return "gateway-request-sha256:" + hashlib.sha256(canonical_json(material).encode()).hexdigest()

    def _reservation(
        self,
        attempt: GatewayAttempt,
        context: AccountingContext,
        policy: RuntimePolicyVersion,
        reserved_at: datetime,
    ) -> _Reservation:
        request_digest = self._request_digest(attempt.request)
        identity = {
            "context": context.to_mapping(),
            "policy_id": policy.policy_id,
            "protocol": attempt.protocol,
            "attempt_number": attempt.attempt_number,
            "request_digest": request_digest,
        }
        attempt_id = "gateway-attempt-sha256:" + hashlib.sha256(
            canonical_json(identity).encode()
        ).hexdigest()
        return _Reservation(
            attempt_id,
            context,
            policy.policy_id,
            attempt.protocol,
            attempt.attempt_number,
            request_digest,
            attempt.conservative_usage,
            reserved_at,
        )

    @staticmethod
    def _reservation_mapping(item: _Reservation) -> dict[str, JsonValue]:
        return {
            "attempt_id": item.attempt_id,
            "context": item.context.to_mapping(),
            "policy_id": item.policy_id,
            "protocol": item.protocol,
            "attempt_number": item.attempt_number,
            "request_digest": item.request_digest,
            "conservative_usage": _usage_mapping(item.usage),
            "reserved_at": item.reserved_at.isoformat(),
        }

    @staticmethod
    def _settlement_mapping(item: _Settlement) -> dict[str, JsonValue]:
        return {
            "attempt_id": item.attempt_id,
            "succeeded": item.succeeded,
            "usage": _usage_mapping(item.usage),
            "status": item.status,
            "error_type": item.error_type,
            "runtime_seconds": item.runtime_seconds,
        }

    def _replay(self) -> tuple[dict[str, _Reservation], dict[str, _Settlement]]:
        reservations: dict[str, _Reservation] = {}
        settlements: dict[str, _Settlement] = {}
        reservation_fields = {
            "attempt_id",
            "context",
            "policy_id",
            "protocol",
            "attempt_number",
            "request_digest",
            "conservative_usage",
            "reserved_at",
        }
        settlement_fields = {
            "attempt_id",
            "succeeded",
            "usage",
            "status",
            "error_type",
            "runtime_seconds",
        }
        for event in self._store.read(self._campaign_id):
            payload = cast(object, thaw_json(event.payload))
            if event.event_type == _RESERVED:
                if not isinstance(payload, Mapping) or set(payload) != reservation_fields:
                    raise RuntimeLedgerIntegrityError("gateway reservation has an invalid schema")
                try:
                    reserved_at = datetime.fromisoformat(cast(str, payload["reserved_at"]))
                    reservation = _Reservation(
                        cast(str, payload["attempt_id"]),
                        AccountingContext.from_mapping(payload["context"]),
                        cast(str, payload["policy_id"]),
                        cast(str, payload["protocol"]),
                        cast(int, payload["attempt_number"]),
                        cast(str, payload["request_digest"]),
                        _usage_from_mapping(payload["conservative_usage"]),
                        _aware_utc(reserved_at),
                    )
                except (TypeError, ValueError) as exc:
                    raise RuntimeLedgerIntegrityError("gateway reservation is invalid") from exc
                identity = {
                    "context": reservation.context.to_mapping(),
                    "policy_id": reservation.policy_id,
                    "protocol": reservation.protocol,
                    "attempt_number": reservation.attempt_number,
                    "request_digest": reservation.request_digest,
                }
                expected_id = "gateway-attempt-sha256:" + hashlib.sha256(
                    canonical_json(identity).encode()
                ).hexdigest()
                if (
                    reservation.context.campaign_id != self._campaign_id
                    or reservation.usage.verified
                    or reservation.protocol not in {"responses", "chat"}
                    or isinstance(reservation.attempt_number, bool)
                    or not isinstance(reservation.attempt_number, int)
                    or reservation.attempt_number < 1
                    or not isinstance(reservation.policy_id, str)
                    or not reservation.policy_id.startswith("runtime-policy-sha256:")
                    or not isinstance(reservation.request_digest, str)
                    or not reservation.request_digest.startswith("gateway-request-sha256:")
                    or reservation.attempt_id != expected_id
                    or reservation.reserved_at != event.created_at.astimezone(timezone.utc)
                ):
                    raise RuntimeLedgerIntegrityError("gateway reservation ownership or usage is invalid")
                existing_reservation = reservations.get(reservation.attempt_id)
                if existing_reservation is not None and existing_reservation != reservation:
                    raise RuntimeLedgerIntegrityError("conflicting gateway reservations exist")
                reservations[reservation.attempt_id] = reservation
            elif event.event_type == _SETTLED:
                if not isinstance(payload, Mapping) or set(payload) != settlement_fields:
                    raise RuntimeLedgerIntegrityError("gateway settlement has an invalid schema")
                runtime = payload["runtime_seconds"]
                if (
                    isinstance(runtime, bool)
                    or not isinstance(runtime, (int, float))
                    or not math.isfinite(float(runtime))
                    or float(runtime) < 0
                ):
                    raise RuntimeLedgerIntegrityError("gateway settlement runtime is invalid")
                if not isinstance(payload["succeeded"], bool):
                    raise RuntimeLedgerIntegrityError("gateway settlement success flag is invalid")
                if payload["error_type"] is not None and not isinstance(
                    payload["error_type"], str
                ):
                    raise RuntimeLedgerIntegrityError("gateway settlement error type is invalid")
                try:
                    settlement = _Settlement(
                        cast(str, payload["attempt_id"]),
                        payload["succeeded"],
                        _usage_from_mapping(payload["usage"]),
                        cast(int | None, payload["status"]),
                        payload["error_type"],
                        float(runtime),
                    )
                    # Reuse the gateway result's strict success/error validation.
                    GatewayAttemptResult(
                        settlement.succeeded,
                        settlement.usage,
                        settlement.status,
                        settlement.error_type,
                    )
                except (TypeError, ValueError) as exc:
                    raise RuntimeLedgerIntegrityError("gateway settlement is invalid") from exc
                if settlement.attempt_id not in reservations:
                    raise RuntimeLedgerIntegrityError("gateway settlement precedes its reservation")
                existing_settlement = settlements.get(settlement.attempt_id)
                if existing_settlement is not None and existing_settlement != settlement:
                    raise RuntimeLedgerIntegrityError("conflicting gateway settlements exist")
                settlements[settlement.attempt_id] = settlement
        return reservations, settlements
