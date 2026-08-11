"""Event-sourced runtime registry for MCP bindings, probation, leases, and revocation.

The evolution registry remains authoritative for proposal, validation,
qualification, and activation.  This projection mirrors those decisions and
owns only MCP runtime concerns.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Callable, Mapping

from aegis.event_store import EventStore, EventStoreSequenceConflict
from aegis.models import AuditEvent, thaw_json

from .evolution import McpBinding, McpCandidate, McpEvolutionError

_SCHEMA_VERSION = 1
_CANDIDATE_RECORDED = "mcp_candidate_recorded_v1"
_STATUS_RECORDED = "mcp_candidate_status_recorded_v1"
_PROBATION_STARTED = "mcp_candidate_probation_started_v1"
_PROBATION_OBSERVED = "mcp_candidate_probation_observed_v1"
_LEASE_ACQUIRED = "mcp_registry_lease_acquired_v1"
_LEASE_RENEWED = "mcp_registry_lease_renewed_v1"
_LEASE_RELEASED = "mcp_registry_lease_released_v1"
_KNOWN_EVENTS = frozenset(
    {
        _CANDIDATE_RECORDED,
        _STATUS_RECORDED,
        _PROBATION_STARTED,
        _PROBATION_OBSERVED,
        _LEASE_ACQUIRED,
        _LEASE_RENEWED,
        _LEASE_RELEASED,
    }
)


class McpCandidateStatus(StrEnum):
    PROPOSED = "proposed"
    VALIDATED = "validated"
    QUALIFIED = "qualified"
    PROBATION = "probation"
    ACTIVE = "active"
    REVOKED = "revoked"
    REJECTED = "rejected"


_TRANSITIONS = {
    McpCandidateStatus.PROPOSED: {
        McpCandidateStatus.VALIDATED,
        McpCandidateStatus.REJECTED,
        McpCandidateStatus.REVOKED,
    },
    McpCandidateStatus.VALIDATED: {
        McpCandidateStatus.QUALIFIED,
        McpCandidateStatus.REJECTED,
        McpCandidateStatus.REVOKED,
    },
    McpCandidateStatus.QUALIFIED: {
        McpCandidateStatus.PROBATION,
        McpCandidateStatus.REJECTED,
        McpCandidateStatus.REVOKED,
    },
    McpCandidateStatus.PROBATION: {
        McpCandidateStatus.ACTIVE,
        McpCandidateStatus.REJECTED,
        McpCandidateStatus.REVOKED,
    },
    McpCandidateStatus.ACTIVE: {McpCandidateStatus.REVOKED},
    McpCandidateStatus.REVOKED: set(),
    McpCandidateStatus.REJECTED: set(),
}
_EVOLUTION_DRIVEN = frozenset(
    {
        McpCandidateStatus.PROPOSED,
        McpCandidateStatus.VALIDATED,
        McpCandidateStatus.QUALIFIED,
        McpCandidateStatus.ACTIVE,
        McpCandidateStatus.REJECTED,
    }
)


class McpRegistryError(McpEvolutionError):
    """Persisted MCP runtime state violates its contract."""


class McpRegistryConflictError(McpRegistryError):
    """A compare-and-swap or lease ownership check failed."""


def _text(value: object, name: str, *, limit: int = 2000) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > limit
    ):
        raise McpRegistryError(f"{name} must be bounded non-empty trimmed text")
    return value


def _strict(value: object, fields: set[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise McpRegistryError(f"{name} must be a string-keyed mapping")
    if set(value) != fields or value.get("schema_version") != _SCHEMA_VERSION:
        raise McpRegistryError(f"{name} has missing, unknown, or invalid fields")
    return value


def _timestamp(value: object, name: str) -> datetime:
    if not isinstance(value, str):
        raise McpRegistryError(f"{name} must be an ISO timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise McpRegistryError(f"{name} must be an ISO timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise McpRegistryError(f"{name} must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def mcp_registry_stream_id(campaign_id: str) -> str:
    return f"{_text(campaign_id, 'campaign_id', limit=256)}:mcp-runtime:v1"


@dataclass(frozen=True, slots=True)
class McpRegistryLease:
    owner: str
    token: str
    expires_at: datetime

    def __post_init__(self) -> None:
        _text(self.owner, "lease owner", limit=256)
        if not isinstance(self.token, str) or len(self.token) != 64:
            raise McpRegistryError("lease token must be a 64-character secret")
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise McpRegistryError("lease expiry must be timezone-aware")

    def active_at(self, instant: datetime) -> bool:
        return instant.astimezone(timezone.utc) < self.expires_at.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class McpProbationObservation:
    snapshot_id: str
    evidence_id: str
    passed: bool


@dataclass(frozen=True, slots=True)
class McpCandidateRecord:
    candidate: McpCandidate
    evolution_candidate_id: str
    status: McpCandidateStatus
    evidence_ids: tuple[str, ...]
    reason: str | None = None
    probation_required_observations: int | None = None
    probation_expires_at: datetime | None = None
    probation_observations: tuple[McpProbationObservation, ...] = ()

    def probation_ready(self, instant: datetime) -> bool:
        required = self.probation_required_observations
        expires_at = self.probation_expires_at
        return (
            self.status is McpCandidateStatus.PROBATION
            and required is not None
            and expires_at is not None
            and instant.astimezone(timezone.utc) < expires_at
            and len(self.probation_observations) >= required
            and all(item.passed for item in self.probation_observations)
        )


@dataclass(frozen=True, slots=True)
class McpRegistryProjection:
    campaign_id: str
    stream_id: str
    sequence: int = 0
    candidates: Mapping[str, McpCandidateRecord] = field(default_factory=dict)
    active_bindings: Mapping[str, str] = field(default_factory=dict)
    lease: McpRegistryLease | None = None

    def __post_init__(self) -> None:
        if self.stream_id != mcp_registry_stream_id(self.campaign_id):
            raise McpRegistryError("stream_id does not match the MCP registry contract")
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int) or self.sequence < 0:
            raise McpRegistryError("sequence must be a non-negative integer")
        object.__setattr__(self, "candidates", MappingProxyType(dict(self.candidates)))
        object.__setattr__(self, "active_bindings", MappingProxyType(dict(self.active_bindings)))

    def callable_bindings(self, instant: datetime) -> Mapping[str, McpBinding]:
        """Bindings permitted for active use or a live probation trial."""

        if instant.tzinfo is None or instant.utcoffset() is None:
            raise McpRegistryError("callable binding instant must be timezone-aware")
        now = instant.astimezone(timezone.utc)
        selected: dict[str, McpBinding] = {}
        for record in self.candidates.values():
            expires = record.probation_expires_at
            if record.status is McpCandidateStatus.PROBATION and expires is not None and now < expires:
                selected[record.candidate.binding.server_name] = record.candidate.binding
        for server, candidate_id in self.active_bindings.items():
            selected[server] = self.candidates[candidate_id].candidate.binding
        return MappingProxyType(selected)


class McpRegistry:
    """CAS-guarded durable MCP runtime projection."""

    def __init__(
        self,
        store: EventStore,
        campaign_id: str,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(store, EventStore):
            raise TypeError("store must be an EventStore")
        self._store = store
        self._campaign_id = _text(campaign_id, "campaign_id", limit=256)
        self._stream_id = mcp_registry_stream_id(campaign_id)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._projection = McpRegistryProjection(self._campaign_id, self._stream_id)
        self.refresh()

    @property
    def projection(self) -> McpRegistryProjection:
        return self._projection

    def refresh(self) -> McpRegistryProjection:
        projection = McpRegistryProjection(self._campaign_id, self._stream_id)
        for event in self._store.read(self._stream_id):
            projection = self._apply_event(projection, event)
        self._projection = projection
        return projection

    def acquire_lease(
        self,
        owner: str,
        *,
        duration_seconds: int = 300,
        expected_sequence: int | None = None,
    ) -> McpRegistryLease:
        owner = _text(owner, "lease owner", limit=256)
        if (
            isinstance(duration_seconds, bool)
            or not isinstance(duration_seconds, int)
            or not 1 <= duration_seconds <= 86_400
        ):
            raise McpRegistryError("duration_seconds must be an integer in [1, 86400]")
        now = self._now()
        current = self._projection.lease
        if current is not None and current.active_at(now):
            raise McpRegistryConflictError("MCP registry lease is already held")
        lease = McpRegistryLease(owner, secrets.token_hex(32), now + timedelta(seconds=duration_seconds))
        self._append(
            _LEASE_ACQUIRED,
            {
                "schema_version": _SCHEMA_VERSION,
                "owner": lease.owner,
                "token": lease.token,
                "expires_at": lease.expires_at.isoformat(),
            },
            expected_sequence,
        )
        return lease

    def renew_lease(self, token: str, *, duration_seconds: int = 300) -> McpRegistryLease:
        lease = self._require_lease(token)
        if (
            isinstance(duration_seconds, bool)
            or not isinstance(duration_seconds, int)
            or not 1 <= duration_seconds <= 86_400
        ):
            raise McpRegistryError("duration_seconds must be an integer in [1, 86400]")
        renewed = McpRegistryLease(
            lease.owner, lease.token, self._now() + timedelta(seconds=duration_seconds)
        )
        self._append(
            _LEASE_RENEWED,
            {
                "schema_version": _SCHEMA_VERSION,
                "owner": renewed.owner,
                "token": renewed.token,
                "expires_at": renewed.expires_at.isoformat(),
            },
            None,
        )
        return renewed

    def release_lease(self, token: str) -> None:
        lease = self._require_lease(token)
        self._append(
            _LEASE_RELEASED,
            {"schema_version": _SCHEMA_VERSION, "owner": lease.owner, "token": lease.token},
            None,
        )

    def record_evolution_status(
        self,
        candidate: McpCandidate,
        *,
        evolution_candidate_id: str,
        status: McpCandidateStatus,
        evidence_id: str,
        lease_token: str,
        reason: str | None = None,
    ) -> McpCandidateRecord:
        """Mirror a decision already committed by the authoritative evolution registry."""

        self._require_lease(lease_token)
        if status not in _EVOLUTION_DRIVEN:
            raise McpRegistryError("this status is not evolution-driven")
        if status is McpCandidateStatus.ACTIVE:
            raise McpRegistryError("active status must use activate_from_evolution after probation")
        evolution_candidate_id = _text(evolution_candidate_id, "evolution_candidate_id")
        evidence_id = _text(evidence_id, "evidence_id")
        if reason is not None:
            reason = _text(reason, "reason")
        existing = self._projection.candidates.get(candidate.candidate_id)
        if existing is None:
            if status is not McpCandidateStatus.PROPOSED:
                raise McpRegistryError("the first mirrored status must be proposed")
            self._append(
                _CANDIDATE_RECORDED,
                {
                    "schema_version": _SCHEMA_VERSION,
                    "candidate": candidate.to_mapping(),
                    "evolution_candidate_id": evolution_candidate_id,
                    "evidence_id": evidence_id,
                },
                None,
            )
        else:
            if existing.candidate != candidate or existing.evolution_candidate_id != evolution_candidate_id:
                raise McpRegistryError("candidate identity is already bound to different content")
            self._record_status(candidate.candidate_id, status, evidence_id, reason, lease_token)
        return self._projection.candidates[candidate.candidate_id]

    def begin_probation(
        self,
        candidate_id: str,
        *,
        evidence_id: str,
        required_observations: int,
        expires_at: datetime,
        lease_token: str,
    ) -> McpCandidateRecord:
        self._require_lease(lease_token)
        candidate_id = _text(candidate_id, "candidate_id")
        evidence_id = _text(evidence_id, "evidence_id")
        if (
            isinstance(required_observations, bool)
            or not isinstance(required_observations, int)
            or not 1 <= required_observations <= 10_000
        ):
            raise McpRegistryError("required_observations must be an integer in [1, 10000]")
        if expires_at.tzinfo is None or expires_at.utcoffset() is None:
            raise McpRegistryError("probation expires_at must be timezone-aware")
        expires_at = expires_at.astimezone(timezone.utc)
        if expires_at <= self._now():
            raise McpRegistryError("probation expires_at must be in the future")
        record = self._projection.candidates.get(candidate_id)
        if record is None or record.status is not McpCandidateStatus.QUALIFIED:
            raise McpRegistryError("only a qualified candidate may enter probation")
        self._append(
            _PROBATION_STARTED,
            {
                "schema_version": _SCHEMA_VERSION,
                "candidate_id": candidate_id,
                "evidence_id": evidence_id,
                "required_observations": required_observations,
                "expires_at": expires_at.isoformat(),
            },
            None,
        )
        return self._projection.candidates[candidate_id]

    def observe_probation(
        self,
        candidate_id: str,
        *,
        snapshot_id: str,
        evidence_id: str,
        passed: bool,
        lease_token: str,
    ) -> McpCandidateRecord:
        self._require_lease(lease_token)
        candidate_id = _text(candidate_id, "candidate_id")
        snapshot_id = _text(snapshot_id, "snapshot_id")
        evidence_id = _text(evidence_id, "evidence_id")
        if type(passed) is not bool:
            raise McpRegistryError("passed must be a boolean")
        record = self._projection.candidates.get(candidate_id)
        if record is None or record.status is not McpCandidateStatus.PROBATION:
            raise McpRegistryError("candidate is not in probation")
        if record.probation_expires_at is None or self._now() >= record.probation_expires_at:
            raise McpRegistryError("candidate probation has expired")
        if any(
            item.snapshot_id == snapshot_id or item.evidence_id == evidence_id
            for item in record.probation_observations
        ):
            raise McpRegistryError("probation observation is duplicated")
        self._append(
            _PROBATION_OBSERVED,
            {
                "schema_version": _SCHEMA_VERSION,
                "candidate_id": candidate_id,
                "snapshot_id": snapshot_id,
                "evidence_id": evidence_id,
                "passed": passed,
            },
            None,
        )
        if not passed:
            self._record_status(
                candidate_id,
                McpCandidateStatus.REVOKED,
                evidence_id,
                "probation observation failed",
                lease_token,
            )
        return self._projection.candidates[candidate_id]

    def activate_from_evolution(
        self, candidate_id: str, *, evidence_id: str, lease_token: str
    ) -> str:
        """Mirror evolution activation and return the activated binding receipt id."""

        self._require_lease(lease_token)
        record = self._projection.candidates.get(candidate_id)
        if record is None or not record.probation_ready(self._now()):
            raise McpRegistryError("candidate has not completed a live passing probation")
        self._record_status(candidate_id, McpCandidateStatus.ACTIVE, evidence_id, None, lease_token)
        return self._projection.candidates[candidate_id].candidate.binding.binding_id

    def expire_probation(
        self, candidate_id: str, *, evidence_id: str, lease_token: str
    ) -> McpCandidateRecord:
        self._require_lease(lease_token)
        record = self._projection.candidates.get(candidate_id)
        if (
            record is None
            or record.status is not McpCandidateStatus.PROBATION
            or record.probation_expires_at is None
            or self._now() < record.probation_expires_at
        ):
            raise McpRegistryError("candidate probation has not expired")
        self._record_status(
            candidate_id,
            McpCandidateStatus.REVOKED,
            evidence_id,
            "probation expired",
            lease_token,
        )
        return self._projection.candidates[candidate_id]

    def revoke(
        self, candidate_id: str, *, evidence_id: str, reason: str, lease_token: str
    ) -> McpCandidateRecord:
        self._record_status(
            candidate_id,
            McpCandidateStatus.REVOKED,
            evidence_id,
            _text(reason, "reason"),
            lease_token,
        )
        return self._projection.candidates[candidate_id]

    def binding_for_server(self, server_name: str) -> McpBinding | None:
        candidate_id = self._projection.active_bindings.get(server_name)
        if candidate_id is None:
            return None
        return self._projection.candidates[candidate_id].candidate.binding

    def callable_binding_for_server(self, server_name: str) -> McpBinding | None:
        return self._projection.callable_bindings(self._now()).get(server_name)

    def _record_status(
        self,
        candidate_id: str,
        status: McpCandidateStatus,
        evidence_id: str,
        reason: str | None,
        lease_token: str,
    ) -> None:
        self._require_lease(lease_token)
        candidate_id = _text(candidate_id, "candidate_id")
        evidence_id = _text(evidence_id, "evidence_id")
        record = self._projection.candidates.get(candidate_id)
        if record is None:
            raise McpRegistryError("candidate is not registered")
        if status not in _TRANSITIONS[record.status]:
            raise McpRegistryError(f"invalid MCP status transition {record.status.value}->{status.value}")
        if status in {McpCandidateStatus.REJECTED, McpCandidateStatus.REVOKED} and reason is None:
            raise McpRegistryError("rejection and revocation require a reason")
        self._append(
            _STATUS_RECORDED,
            {
                "schema_version": _SCHEMA_VERSION,
                "candidate_id": candidate_id,
                "from_status": record.status.value,
                "to_status": status.value,
                "evidence_id": evidence_id,
                "reason": reason,
            },
            None,
        )

    def _require_lease(self, token: str) -> McpRegistryLease:
        lease = self._projection.lease
        if lease is None or lease.token != token or not lease.active_at(self._now()):
            raise McpRegistryConflictError("a live matching MCP registry lease is required")
        return lease

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise McpRegistryError("clock must return a timezone-aware datetime")
        return value.astimezone(timezone.utc)

    def _append(
        self, event_type: str, payload: Mapping[str, Any], expected_sequence: int | None
    ) -> None:
        expected = self._projection.sequence if expected_sequence is None else expected_sequence
        try:
            event = self._store.append_if_sequence(
                self._stream_id, expected, event_type, payload
            )
        except EventStoreSequenceConflict as exc:
            raise McpRegistryConflictError("MCP registry sequence changed") from exc
        self._projection = self._apply_event(self._projection, event)

    def _apply_event(
        self, projection: McpRegistryProjection, event: AuditEvent
    ) -> McpRegistryProjection:
        if event.campaign_id != projection.stream_id or event.sequence != projection.sequence + 1:
            raise McpRegistryError("MCP registry event stream is not contiguous")
        if event.event_type not in _KNOWN_EVENTS:
            return replace(projection, sequence=event.sequence)
        raw = thaw_json(event.payload)
        candidates = dict(projection.candidates)
        active = dict(projection.active_bindings)
        lease = projection.lease
        if event.event_type == _CANDIDATE_RECORDED:
            payload = _strict(
                raw,
                {"schema_version", "candidate", "evolution_candidate_id", "evidence_id"},
                "candidate event",
            )
            if not isinstance(payload["candidate"], Mapping):
                raise McpRegistryError("candidate event content must be a mapping")
            candidate = McpCandidate.from_mapping(payload["candidate"])
            if candidate.candidate_id in candidates:
                raise McpRegistryError("duplicate candidate event")
            candidates[candidate.candidate_id] = McpCandidateRecord(
                candidate,
                _text(payload["evolution_candidate_id"], "evolution_candidate_id"),
                McpCandidateStatus.PROPOSED,
                (_text(payload["evidence_id"], "evidence_id"),),
            )
        elif event.event_type == _PROBATION_STARTED:
            payload = _strict(
                raw,
                {
                    "schema_version",
                    "candidate_id",
                    "evidence_id",
                    "required_observations",
                    "expires_at",
                },
                "probation start event",
            )
            candidate_id = _text(payload["candidate_id"], "candidate_id")
            record = candidates.get(candidate_id)
            required = payload["required_observations"]
            if (
                record is None
                or record.status is not McpCandidateStatus.QUALIFIED
                or isinstance(required, bool)
                or not isinstance(required, int)
                or not 1 <= required <= 10_000
            ):
                raise McpRegistryError("probation start event is invalid")
            expiry = _timestamp(payload["expires_at"], "expires_at")
            candidates[candidate_id] = replace(
                record,
                status=McpCandidateStatus.PROBATION,
                evidence_ids=record.evidence_ids + (_text(payload["evidence_id"], "evidence_id"),),
                probation_required_observations=required,
                probation_expires_at=expiry,
            )
        elif event.event_type == _PROBATION_OBSERVED:
            payload = _strict(
                raw,
                {"schema_version", "candidate_id", "snapshot_id", "evidence_id", "passed"},
                "probation observation event",
            )
            candidate_id = _text(payload["candidate_id"], "candidate_id")
            record = candidates.get(candidate_id)
            passed = payload["passed"]
            if record is None or record.status is not McpCandidateStatus.PROBATION or type(passed) is not bool:
                raise McpRegistryError("probation observation event is invalid")
            observation = McpProbationObservation(
                _text(payload["snapshot_id"], "snapshot_id"),
                _text(payload["evidence_id"], "evidence_id"),
                passed,
            )
            if any(
                item.snapshot_id == observation.snapshot_id
                or item.evidence_id == observation.evidence_id
                for item in record.probation_observations
            ):
                raise McpRegistryError("probation observation event is duplicated")
            candidates[candidate_id] = replace(
                record,
                evidence_ids=record.evidence_ids + (observation.evidence_id,),
                probation_observations=record.probation_observations + (observation,),
            )
        elif event.event_type == _STATUS_RECORDED:
            payload = _strict(
                raw,
                {
                    "schema_version",
                    "candidate_id",
                    "from_status",
                    "to_status",
                    "evidence_id",
                    "reason",
                },
                "status event",
            )
            candidate_id = _text(payload["candidate_id"], "candidate_id")
            record = candidates.get(candidate_id)
            if record is None:
                raise McpRegistryError("status event references an unknown candidate")
            try:
                old = McpCandidateStatus(payload["from_status"])
                new = McpCandidateStatus(payload["to_status"])
            except (TypeError, ValueError) as exc:
                raise McpRegistryError("status event has an invalid status") from exc
            if old is not record.status or new not in _TRANSITIONS[old]:
                raise McpRegistryError("status event has an invalid transition")
            reason_raw = payload["reason"]
            reason = None if reason_raw is None else _text(reason_raw, "reason")
            if new in {McpCandidateStatus.REJECTED, McpCandidateStatus.REVOKED} and reason is None:
                raise McpRegistryError("terminal status event requires a reason")
            candidates[candidate_id] = replace(
                record,
                status=new,
                evidence_ids=record.evidence_ids + (_text(payload["evidence_id"], "evidence_id"),),
                reason=reason,
            )
            server = record.candidate.binding.server_name
            if new is McpCandidateStatus.ACTIVE:
                active[server] = candidate_id
            elif new is McpCandidateStatus.REVOKED and active.get(server) == candidate_id:
                del active[server]
        elif event.event_type in {_LEASE_ACQUIRED, _LEASE_RENEWED}:
            payload = _strict(
                raw,
                {"schema_version", "owner", "token", "expires_at"},
                "lease event",
            )
            parsed = McpRegistryLease(
                _text(payload["owner"], "lease owner", limit=256),
                _text(payload["token"], "lease token", limit=64),
                _timestamp(payload["expires_at"], "expires_at"),
            )
            if event.event_type == _LEASE_RENEWED and (
                lease is None or lease.owner != parsed.owner or lease.token != parsed.token
            ):
                raise McpRegistryError("lease renewal does not match the current lease")
            lease = parsed
        else:
            payload = _strict(raw, {"schema_version", "owner", "token"}, "lease release event")
            if lease is None or lease.owner != payload["owner"] or lease.token != payload["token"]:
                raise McpRegistryError("lease release does not match the current lease")
            lease = None
        return replace(
            projection,
            sequence=event.sequence,
            candidates=candidates,
            active_bindings=active,
            lease=lease,
        )


__all__ = [
    "McpCandidateRecord",
    "McpCandidateStatus",
    "McpRegistry",
    "McpRegistryConflictError",
    "McpRegistryError",
    "McpRegistryLease",
    "McpRegistryProjection",
    "McpProbationObservation",
    "mcp_registry_stream_id",
]
