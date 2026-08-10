"""Atomic, thread-safe multi-resource campaign budget accounting."""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from uuid import uuid4

from aegis.models import BudgetLimit, UsageRecord


class BudgetError(RuntimeError):
    pass


class OversubscriptionError(BudgetError):
    pass


class ReservationError(BudgetError):
    pass


@dataclass(frozen=True, slots=True)
class BudgetReservation:
    reservation_id: str
    estimate: UsageRecord


@dataclass(frozen=True, slots=True)
class ResourceTotals:
    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0
    reasoning_tokens: int = 0
    requests: int = 0
    wall_time_seconds: float = 0.0


@dataclass(frozen=True, slots=True)
class BudgetSnapshot:
    limit: BudgetLimit
    committed: ResourceTotals
    reserved: ResourceTotals
    available: ResourceTotals
    usage_verified: bool
    open_reservations: int


_FIELDS = BudgetLimit.resource_names()


def _values(record: UsageRecord | BudgetLimit | ResourceTotals) -> dict[str, int | float]:
    return {name: getattr(record, name) for name in _FIELDS}


def _totals(values: dict[str, int | float]) -> ResourceTotals:
    return ResourceTotals(
        input_tokens=int(values["input_tokens"]),
        output_tokens=int(values["output_tokens"]),
        cached_tokens=int(values["cached_tokens"]),
        reasoning_tokens=int(values["reasoning_tokens"]),
        requests=int(values["requests"]),
        wall_time_seconds=float(values["wall_time_seconds"]),
    )


class BudgetManager:
    """Own one campaign's budget and reject excess before work starts.

    A reservation covers all resource dimensions in one locked operation.  A
    successful commit consumes the actual values and automatically releases
    unused capacity from the estimate.
    """

    def __init__(self, campaign_id: str, limit: BudgetLimit) -> None:
        if not isinstance(campaign_id, str) or not campaign_id.strip():
            raise ValueError("campaign_id must be a non-empty string")
        if not isinstance(limit, BudgetLimit):
            raise TypeError("limit must be a BudgetLimit")
        self._campaign_id = campaign_id
        self._limit = limit
        self._committed = {name: 0 if name != "wall_time_seconds" else 0.0 for name in _FIELDS}
        self._reservations: dict[str, UsageRecord] = {}
        self._records: list[UsageRecord] = []
        self._lock = RLock()

    @property
    def campaign_id(self) -> str:
        return self._campaign_id

    def _validate_usage(self, usage: UsageRecord) -> None:
        if not isinstance(usage, UsageRecord):
            raise TypeError("usage must be a UsageRecord")
        if usage.campaign_id != self._campaign_id:
            raise ValueError("usage belongs to a different campaign")

    def _reserved_totals(self) -> dict[str, int | float]:
        totals = {name: 0 if name != "wall_time_seconds" else 0.0 for name in _FIELDS}
        for estimate in self._reservations.values():
            for name, value in _values(estimate).items():
                totals[name] += value
        return totals

    def reserve(self, estimate: UsageRecord) -> BudgetReservation:
        self._validate_usage(estimate)
        with self._lock:
            reserved = self._reserved_totals()
            exceeded = [
                name
                for name in _FIELDS
                if self._committed[name] + reserved[name] + getattr(estimate, name)
                > getattr(self._limit, name)
            ]
            if exceeded:
                raise OversubscriptionError("reservation exceeds budget for: " + ", ".join(exceeded))
            reservation_id = uuid4().hex
            self._reservations[reservation_id] = estimate
            return BudgetReservation(reservation_id, estimate)

    def commit(
        self,
        reservation: BudgetReservation,
        actual: UsageRecord | None = None,
    ) -> UsageRecord:
        if not isinstance(reservation, BudgetReservation):
            raise TypeError("reservation must be a BudgetReservation")
        actual = reservation.estimate if actual is None else actual
        self._validate_usage(actual)
        with self._lock:
            estimate = self._reservations.get(reservation.reservation_id)
            if estimate is None or estimate != reservation.estimate:
                raise ReservationError("reservation is unknown or already closed")
            exceeded = [name for name in _FIELDS if getattr(actual, name) > getattr(estimate, name)]
            if exceeded:
                raise ReservationError("actual usage exceeds reservation for: " + ", ".join(exceeded))
            del self._reservations[reservation.reservation_id]
            for name, value in _values(actual).items():
                self._committed[name] += value
            self._records.append(actual)
            return actual

    def release(self, reservation: BudgetReservation) -> None:
        if not isinstance(reservation, BudgetReservation):
            raise TypeError("reservation must be a BudgetReservation")
        with self._lock:
            estimate = self._reservations.get(reservation.reservation_id)
            if estimate is None or estimate != reservation.estimate:
                raise ReservationError("reservation is unknown or already closed")
            del self._reservations[reservation.reservation_id]

    def snapshot(self) -> BudgetSnapshot:
        with self._lock:
            reserved = self._reserved_totals()
            available = {
                name: getattr(self._limit, name) - self._committed[name] - reserved[name] for name in _FIELDS
            }
            return BudgetSnapshot(
                self._limit,
                _totals(dict(self._committed)),
                _totals(reserved),
                _totals(available),
                all(record.verified for record in self._records),
                len(self._reservations),
            )

    def committed_records(self) -> tuple[UsageRecord, ...]:
        with self._lock:
            return tuple(self._records)
