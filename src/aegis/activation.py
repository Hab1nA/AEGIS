"""Durable activation intent/receipt journal and crash reconciler."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any, Mapping

from aegis.event_store import EventStore
from aegis.models import AuditEvent, canonical_json, thaw_json

ACTIVATION_INTENT_RECORDED = "activation_intent_recorded_v1"
ACTIVATION_ROLE_COMMITTED = "activation_role_committed_v1"
ACTIVATION_EVOLUTION_ACTIVATED = "activation_evolution_activated_v1"
ACTIVATION_MCP_ACTIVATED = "activation_mcp_activated_v1"
ACTIVATION_HARNESS_COMMITTED = "activation_harness_committed_v1"
ACTIVATION_COMPLETED = "activation_completed_v1"

_LEGACY_SCHEMA_VERSION = 1
_SCHEMA_VERSION = 2
_HARNESS_SCHEMA_VERSION = 3
_KNOWN_EVENTS = frozenset(
    {
        ACTIVATION_INTENT_RECORDED,
        ACTIVATION_ROLE_COMMITTED,
        ACTIVATION_EVOLUTION_ACTIVATED,
        ACTIVATION_MCP_ACTIVATED,
        ACTIVATION_HARNESS_COMMITTED,
        ACTIVATION_COMPLETED,
    }
)


class ActivationError(RuntimeError):
    """Raised when activation journal state or reconciliation is inconsistent."""


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ActivationError(f"{name} must be non-empty trimmed text")
    return value


def activation_stream_id(campaign_id: str) -> str:
    return f"{_text(campaign_id, 'campaign_id')}:activation:v1"


@dataclass(frozen=True, slots=True)
class ActivationIntent:
    intent_id: str
    evolution_candidate_id: str
    role_candidate_id: str | None
    mcp_candidate_id: str | None
    objective_id: str
    qualification_evidence_id: str
    expected_current_active_set_id: str | None
    harness_candidate_commit: str | None = None
    harness_expected_champion: str | None = None

    @classmethod
    def create(
        cls,
        *,
        evolution_candidate_id: str,
        role_candidate_id: str | None = None,
        mcp_candidate_id: str | None = None,
        objective_id: str,
        qualification_evidence_id: str,
        expected_current_active_set_id: str | None,
        harness_candidate_commit: str | None = None,
        harness_expected_champion: str | None = None,
    ) -> ActivationIntent:
        evolution_candidate_id = _text(evolution_candidate_id, "evolution_candidate_id")
        if role_candidate_id is not None:
            role_candidate_id = _text(role_candidate_id, "role_candidate_id")
        if mcp_candidate_id is not None:
            mcp_candidate_id = _text(mcp_candidate_id, "mcp_candidate_id")
        if role_candidate_id is None and mcp_candidate_id is None:
            raise ActivationError("an activation intent must name a role or MCP candidate")
        objective_id = _text(objective_id, "objective_id")
        qualification_evidence_id = _text(qualification_evidence_id, "qualification_evidence_id")
        if expected_current_active_set_id is not None:
            _text(expected_current_active_set_id, "expected_current_active_set_id")
        if (harness_candidate_commit is None) != (harness_expected_champion is None):
            raise ActivationError("harness activation requires candidate and expected champion")
        if harness_candidate_commit is not None:
            _text(harness_candidate_commit, "harness_candidate_commit")
            _text(harness_expected_champion, "harness_expected_champion")
        payload = {
            "evolution_candidate_id": evolution_candidate_id,
            "role_candidate_id": role_candidate_id,
            "objective_id": objective_id,
            "qualification_evidence_id": qualification_evidence_id,
            "expected_current_active_set_id": expected_current_active_set_id,
        }
        # Preserve the content IDs of pre-MCP role/evolution intents.
        if mcp_candidate_id is not None:
            payload["mcp_candidate_id"] = mcp_candidate_id
        if harness_candidate_commit is not None:
            payload["harness_candidate_commit"] = harness_candidate_commit
            payload["harness_expected_champion"] = harness_expected_champion
        digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        return cls(
            f"activation-intent-sha256:{digest}",
            evolution_candidate_id,
            role_candidate_id,
            mcp_candidate_id,
            objective_id,
            qualification_evidence_id,
            expected_current_active_set_id,
            harness_candidate_commit,
            harness_expected_champion,
        )

    def to_mapping(self) -> dict[str, Any]:
        payload = {
            "intent_id": self.intent_id,
            "evolution_candidate_id": self.evolution_candidate_id,
            "role_candidate_id": self.role_candidate_id,
            "mcp_candidate_id": self.mcp_candidate_id,
            "objective_id": self.objective_id,
            "qualification_evidence_id": self.qualification_evidence_id,
            "expected_current_active_set_id": self.expected_current_active_set_id,
        }
        if self.harness_candidate_commit is not None:
            payload["harness_candidate_commit"] = self.harness_candidate_commit
            payload["harness_expected_champion"] = self.harness_expected_champion
        return payload


@dataclass(frozen=True, slots=True)
class ActivationRecord:
    intent: ActivationIntent
    role_active_set_id: str | None = None
    evolution_activated: bool = False
    mcp_binding_id: str | None = None
    harness_receipt_id: str | None = None
    completed: bool = False

    @property
    def receipts_complete(self) -> bool:
        role_complete = self.intent.role_candidate_id is None or self.role_active_set_id is not None
        mcp_complete = self.intent.mcp_candidate_id is None or self.mcp_binding_id is not None
        harness_complete = (
            self.intent.harness_candidate_commit is None
            or self.harness_receipt_id is not None
        )
        return role_complete and harness_complete and self.evolution_activated and mcp_complete


@dataclass(frozen=True, slots=True)
class ActivationProjection:
    campaign_id: str
    stream_id: str
    sequence: int = 0
    records: Mapping[str, ActivationRecord] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.stream_id != activation_stream_id(self.campaign_id):
            raise ActivationError("stream_id does not match campaign")
        object.__setattr__(self, "records", MappingProxyType(dict(self.records)))

    @property
    def pending(self) -> tuple[ActivationRecord, ...]:
        return tuple(self.records[key] for key in sorted(self.records) if not self.records[key].completed)


class ActivationJournal:
    """CAS-guarded saga journal spanning role, evolution, and MCP registries."""

    def __init__(self, store: EventStore, campaign_id: str) -> None:
        if not isinstance(store, EventStore):
            raise TypeError("store must be an EventStore")
        self._store = store
        self._campaign_id = _text(campaign_id, "campaign_id")
        self._stream_id = activation_stream_id(campaign_id)
        self._projection = ActivationProjection(campaign_id, self._stream_id)
        self.refresh()

    @property
    def projection(self) -> ActivationProjection:
        return self._projection

    def refresh(self) -> ActivationProjection:
        projection = ActivationProjection(self._campaign_id, self._stream_id)
        for event in self._store.read(self._stream_id):
            projection = self._apply_event(projection, event)
        self._projection = projection
        return projection

    def begin(self, intent: ActivationIntent) -> ActivationRecord:
        if not isinstance(intent, ActivationIntent):
            raise TypeError("intent must be an ActivationIntent")
        existing = self._projection.records.get(intent.intent_id)
        if existing is not None:
            if existing.intent != intent:
                raise ActivationError("intent id collision")
            return existing
        return self._append(
            ACTIVATION_INTENT_RECORDED,
            {
                "schema_version": (
                    _HARNESS_SCHEMA_VERSION
                    if intent.harness_candidate_commit is not None
                    else _SCHEMA_VERSION
                ),
                **intent.to_mapping(),
            },
        ).records[intent.intent_id]

    def record_role_commit(self, intent_id: str, active_set_id: str) -> ActivationRecord:
        record = self._record(intent_id)
        if record.intent.role_candidate_id is None:
            raise ActivationError("intent does not declare a role activation")
        if (
            record.intent.harness_candidate_commit is not None
            and record.harness_receipt_id is None
        ):
            raise ActivationError("harness activation must be committed first")
        active_set_id = _text(active_set_id, "active_set_id")
        if record.role_active_set_id is not None:
            if record.role_active_set_id != active_set_id:
                raise ActivationError("intent already names a different active set")
            return record
        return self._append(
            ACTIVATION_ROLE_COMMITTED,
            {
                "schema_version": _SCHEMA_VERSION,
                "intent_id": intent_id,
                "active_set_id": active_set_id,
            },
        ).records[intent_id]

    def record_harness_commit(self, intent_id: str, receipt_id: str) -> ActivationRecord:
        record = self._record(intent_id)
        if record.intent.harness_candidate_commit is None:
            raise ActivationError("intent does not declare harness activation")
        receipt_id = _text(receipt_id, "receipt_id")
        if record.harness_receipt_id is not None:
            if record.harness_receipt_id != receipt_id:
                raise ActivationError("intent already names a different harness receipt")
            return record
        return self._append(
            ACTIVATION_HARNESS_COMMITTED,
            {
                "schema_version": _HARNESS_SCHEMA_VERSION,
                "intent_id": intent_id,
                "receipt_id": receipt_id,
            },
        ).records[intent_id]

    def record_evolution_activation(self, intent_id: str) -> ActivationRecord:
        record = self._record(intent_id)
        if (
            record.intent.harness_candidate_commit is not None
            and record.harness_receipt_id is None
        ):
            raise ActivationError("harness activation must be committed first")
        if record.intent.role_candidate_id is not None and record.role_active_set_id is None:
            raise ActivationError("role activation must be committed first")
        if record.evolution_activated:
            return record
        return self._append(
            ACTIVATION_EVOLUTION_ACTIVATED,
            {"schema_version": _SCHEMA_VERSION, "intent_id": intent_id},
        ).records[intent_id]

    def record_mcp_activation(self, intent_id: str, binding_id: str) -> ActivationRecord:
        record = self._record(intent_id)
        if record.intent.mcp_candidate_id is None:
            raise ActivationError("intent does not declare an MCP activation")
        if not record.evolution_activated:
            raise ActivationError("evolution activation must be committed first")
        binding_id = _text(binding_id, "binding_id")
        if record.mcp_binding_id is not None:
            if record.mcp_binding_id != binding_id:
                raise ActivationError("intent already names a different MCP binding")
            return record
        return self._append(
            ACTIVATION_MCP_ACTIVATED,
            {
                "schema_version": _SCHEMA_VERSION,
                "intent_id": intent_id,
                "binding_id": binding_id,
            },
        ).records[intent_id]

    def complete(self, intent_id: str) -> ActivationRecord:
        record = self._record(intent_id)
        if not record.receipts_complete:
            raise ActivationError("all declared activation receipts are required")
        if record.completed:
            return record
        return self._append(
            ACTIVATION_COMPLETED,
            {"schema_version": _SCHEMA_VERSION, "intent_id": intent_id},
        ).records[intent_id]

    def _record(self, intent_id: str) -> ActivationRecord:
        intent_id = _text(intent_id, "intent_id")
        try:
            return self._projection.records[intent_id]
        except KeyError as exc:
            raise ActivationError("activation intent is not registered") from exc

    def _append(self, event_type: str, payload: Mapping[str, Any]) -> ActivationProjection:
        event = self._store.append_if_sequence(
            self._stream_id, self._projection.sequence, event_type, payload
        )
        self._projection = self._apply_event(self._projection, event)
        return self._projection

    def _apply_event(self, projection: ActivationProjection, event: AuditEvent) -> ActivationProjection:
        if event.campaign_id != projection.stream_id:
            raise ActivationError("event belongs to a different activation stream")
        if event.sequence != projection.sequence + 1:
            raise ActivationError("activation event sequence is not contiguous")
        if event.event_type not in _KNOWN_EVENTS:
            return replace(projection, sequence=event.sequence)
        payload = thaw_json(event.payload)
        if not isinstance(payload, Mapping) or payload.get("schema_version") not in {
            _LEGACY_SCHEMA_VERSION,
            _SCHEMA_VERSION,
            _HARNESS_SCHEMA_VERSION,
        }:
            raise ActivationError("invalid activation event payload")
        schema_version = payload["schema_version"]
        records = dict(projection.records)
        if event.event_type == ACTIVATION_INTENT_RECORDED:
            expected = {
                "schema_version",
                "intent_id",
                "evolution_candidate_id",
                "role_candidate_id",
                "objective_id",
                "qualification_evidence_id",
                "expected_current_active_set_id",
            }
            if schema_version in {_SCHEMA_VERSION, _HARNESS_SCHEMA_VERSION}:
                expected.add("mcp_candidate_id")
            if schema_version == _HARNESS_SCHEMA_VERSION:
                expected.update({"harness_candidate_commit", "harness_expected_champion"})
            if set(payload) != expected:
                raise ActivationError("invalid activation intent payload")
            intent = ActivationIntent.create(
                evolution_candidate_id=payload["evolution_candidate_id"],
                role_candidate_id=payload["role_candidate_id"],
                mcp_candidate_id=payload.get("mcp_candidate_id"),
                objective_id=payload["objective_id"],
                qualification_evidence_id=payload["qualification_evidence_id"],
                expected_current_active_set_id=payload["expected_current_active_set_id"],
                harness_candidate_commit=payload.get("harness_candidate_commit"),
                harness_expected_champion=payload.get("harness_expected_champion"),
            )
            if intent.intent_id != payload["intent_id"] or intent.intent_id in records:
                raise ActivationError("invalid or duplicate activation intent")
            records[intent.intent_id] = ActivationRecord(intent)
        else:
            expected = {"schema_version", "intent_id"}
            if event.event_type == ACTIVATION_ROLE_COMMITTED:
                expected.add("active_set_id")
            elif event.event_type == ACTIVATION_HARNESS_COMMITTED:
                expected.add("receipt_id")
            elif event.event_type == ACTIVATION_MCP_ACTIVATED:
                if schema_version != _SCHEMA_VERSION:
                    raise ActivationError("MCP receipt requires activation schema v2")
                expected.add("binding_id")
            if set(payload) != expected:
                raise ActivationError("invalid activation receipt payload")
            intent_id = _text(payload["intent_id"], "intent_id")
            record = records.get(intent_id)
            if record is None:
                raise ActivationError("receipt references an unknown intent")
            if event.event_type == ACTIVATION_ROLE_COMMITTED:
                if record.intent.role_candidate_id is None or record.role_active_set_id is not None:
                    raise ActivationError("duplicate role receipt")
                records[intent_id] = replace(
                    record, role_active_set_id=_text(payload["active_set_id"], "active_set_id")
                )
            elif event.event_type == ACTIVATION_HARNESS_COMMITTED:
                if (
                    record.intent.harness_candidate_commit is None
                    or record.harness_receipt_id is not None
                ):
                    raise ActivationError("invalid harness receipt")
                records[intent_id] = replace(
                    record,
                    harness_receipt_id=_text(payload["receipt_id"], "receipt_id"),
                )
            elif event.event_type == ACTIVATION_EVOLUTION_ACTIVATED:
                harness_incomplete = (
                    record.intent.harness_candidate_commit is not None
                    and record.harness_receipt_id is None
                )
                role_incomplete = (
                    record.intent.role_candidate_id is not None and record.role_active_set_id is None
                )
                if harness_incomplete or role_incomplete or record.evolution_activated:
                    raise ActivationError("invalid evolution receipt order")
                records[intent_id] = replace(record, evolution_activated=True)
            elif event.event_type == ACTIVATION_MCP_ACTIVATED:
                if (
                    record.intent.mcp_candidate_id is None
                    or not record.evolution_activated
                    or record.mcp_binding_id is not None
                ):
                    raise ActivationError("invalid MCP receipt order")
                records[intent_id] = replace(
                    record,
                    mcp_binding_id=_text(payload["binding_id"], "binding_id"),
                )
            else:
                if not record.receipts_complete or record.completed:
                    raise ActivationError("invalid completion receipt order")
                records[intent_id] = replace(record, completed=True)
        return replace(projection, sequence=event.sequence, records=records)


class ActivationReconciler:
    """Finish journaled activation using idempotent registry state probes."""

    def __init__(
        self,
        journal: ActivationJournal,
        *,
        probe_evolution_activation: Callable[[ActivationIntent], bool],
        activate_evolution: Callable[[ActivationIntent], None],
        probe_role_commit: Callable[[ActivationIntent], str | None] | None = None,
        commit_role: Callable[[ActivationIntent], str] | None = None,
        probe_mcp_activation: Callable[[ActivationIntent], str | None] | None = None,
        activate_mcp: Callable[[ActivationIntent], str] | None = None,
        probe_harness_activation: Callable[[ActivationIntent], str | None] | None = None,
        activate_harness: Callable[[ActivationIntent], str] | None = None,
    ) -> None:
        self._journal = journal
        self._probe_role_commit = probe_role_commit
        self._commit_role = commit_role
        self._probe_evolution_activation = probe_evolution_activation
        self._activate_evolution = activate_evolution
        self._probe_mcp_activation = probe_mcp_activation
        self._activate_mcp = activate_mcp
        self._probe_harness_activation = probe_harness_activation
        self._activate_harness = activate_harness

    def reconcile(self) -> tuple[ActivationRecord, ...]:
        completed: list[ActivationRecord] = []
        for pending in self._journal.refresh().pending:
            intent = pending.intent
            if (
                intent.harness_candidate_commit is not None
                and pending.harness_receipt_id is None
            ):
                if (
                    self._probe_harness_activation is None
                    or self._activate_harness is None
                ):
                    raise ActivationError("harness activation callbacks are not configured")
                receipt_id = self._probe_harness_activation(intent)
                if receipt_id is None:
                    receipt_id = self._activate_harness(intent)
                pending = self._journal.record_harness_commit(
                    intent.intent_id, receipt_id
                )
            if intent.role_candidate_id is not None and pending.role_active_set_id is None:
                if self._probe_role_commit is None or self._commit_role is None:
                    raise ActivationError("role activation callbacks are not configured")
                active_set_id = self._probe_role_commit(intent)
                if active_set_id is None:
                    active_set_id = self._commit_role(intent)
                pending = self._journal.record_role_commit(intent.intent_id, active_set_id)
            if not pending.evolution_activated:
                if not self._probe_evolution_activation(intent):
                    self._activate_evolution(intent)
                pending = self._journal.record_evolution_activation(intent.intent_id)
            if intent.mcp_candidate_id is not None and pending.mcp_binding_id is None:
                if self._probe_mcp_activation is None or self._activate_mcp is None:
                    raise ActivationError("MCP activation callbacks are not configured")
                binding_id = self._probe_mcp_activation(intent)
                if binding_id is None:
                    binding_id = self._activate_mcp(intent)
                pending = self._journal.record_mcp_activation(intent.intent_id, binding_id)
            completed.append(self._journal.complete(intent.intent_id))
        return tuple(completed)
