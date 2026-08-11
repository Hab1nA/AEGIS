"""Append-only evolution candidate registry with per-surface champions."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, replace
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Mapping

from aegis.curriculum.models import SCHEMA_VERSION
from aegis.event_store import EventStore
from aegis.models import AuditEvent, Role, canonical_json, thaw_json

from .surfaces import EvolutionSurface

CANDIDATE_COLLECTED = "evolution_candidate_collected_v2"
CANDIDATE_VALIDATED = "evolution_candidate_validated_v2"
CANDIDATE_REJECTED = "evolution_candidate_rejected_v2"
CANDIDATE_QUALIFIED = "evolution_candidate_qualified_v2"
CANDIDATE_MATERIALIZED = "evolution_candidate_materialized_v2"
SURFACE_ACTIVATED = "evolution_surface_activated_v2"
SURFACE_ROLLED_BACK = "evolution_surface_rolled_back_v2"

_KNOWN_EVENTS = frozenset(
    {
        CANDIDATE_COLLECTED,
        CANDIDATE_VALIDATED,
        CANDIDATE_REJECTED,
        CANDIDATE_QUALIFIED,
        CANDIDATE_MATERIALIZED,
        SURFACE_ACTIVATED,
        SURFACE_ROLLED_BACK,
    }
)

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ARTIFACT = re.compile(r"[a-z][a-z0-9-]{0,63}-sha256:[0-9a-f]{64}\Z")
_CONTENT_ID = re.compile(r"evolution-candidate-sha256:[0-9a-f]{64}\Z")


class EvolutionRegistryError(RuntimeError):
    """Raised when an evolution command or persisted event violates its contract."""


class CandidateState(StrEnum):
    COLLECTED = "collected"
    VALIDATED = "validated"
    REJECTED = "rejected"
    QUALIFIED = "qualified"
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    REVOKED = "revoked"


def evolution_registry_stream_id(campaign_id: str) -> str:
    return f"{_required_text(campaign_id, 'campaign_id')}:evolution:v2"


def _required_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise EvolutionRegistryError(f"{name} must be non-empty text without surrounding whitespace")
    return value


def _strict_payload(
    value: object, expected: set[str], name: str
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise EvolutionRegistryError(f"{name} must be a string-keyed mapping")
    if set(value) != expected:
        raise EvolutionRegistryError(f"{name} has missing or unknown fields")
    if type(value["schema_version"]) is not int or value["schema_version"] != SCHEMA_VERSION:
        raise EvolutionRegistryError(f"{name}.schema_version must be {SCHEMA_VERSION}")
    return value


def _surface(value: object, name: str) -> EvolutionSurface:
    if not isinstance(value, str):
        raise EvolutionRegistryError(f"{name} must be text")
    try:
        return EvolutionSurface(value)
    except ValueError as exc:
        raise EvolutionRegistryError(f"{name} has an invalid value") from exc


def _role(value: object, name: str) -> Role:
    if not isinstance(value, str):
        raise EvolutionRegistryError(f"{name} must be text")
    try:
        return Role(value)
    except ValueError as exc:
        raise EvolutionRegistryError(f"{name} has an invalid value") from exc


def _state(value: object, name: str) -> CandidateState:
    if not isinstance(value, str):
        raise EvolutionRegistryError(f"{name} has an invalid value")
    try:
        return CandidateState(value)
    except ValueError as exc:
        raise EvolutionRegistryError(f"{name} has an invalid value") from exc


def _optional_text(value: object, name: str) -> str | None:
    if value is None:
        return None
    return _required_text(value, name)


def _artifact_id(value: object, name: str, surface: EvolutionSurface) -> str:
    text = _required_text(value, name)
    if _ARTIFACT.fullmatch(text) is None or not text.startswith(f"{surface.value}-sha256:"):
        raise EvolutionRegistryError(f"{name} must be a {surface.value} content address")
    return text


def _artifact_sha256(value: object, name: str) -> str:
    text = _required_text(value, name)
    if _SHA256.fullmatch(text) is None:
        raise EvolutionRegistryError(f"{name} must be a lowercase sha256 digest")
    return text


def _candidate_identity(
    surface: EvolutionSurface,
    target_role: Role,
    version: int,
    parent_candidate_id: str | None,
    artifact_id: str,
) -> str:
    payload = {
        "schema_version": SCHEMA_VERSION,
        "surface": surface.value,
        "target_role": target_role.value,
        "version": version,
        "parent_candidate_id": parent_candidate_id,
        "artifact_id": artifact_id,
    }
    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    return f"evolution-candidate-sha256:{digest}"


@dataclass(frozen=True, slots=True)
class EvolutionCandidateRecord:
    candidate_id: str
    surface: EvolutionSurface
    target_role: Role
    version: int
    parent_candidate_id: str | None
    artifact_id: str
    artifact_sha256: str
    objective_id: str
    state: CandidateState = CandidateState.COLLECTED
    collection_evidence_id: str = ""
    validation_evidence_id: str | None = None
    qualification_evidence_id: str | None = None
    activation_evidence_id: str | None = None
    materialized_artifact_id: str | None = None
    materialized_artifact_sha256: str | None = None
    materialization_evidence_id: str | None = None

    def __post_init__(self) -> None:
        if _CONTENT_ID.fullmatch(self.candidate_id) is None:
            raise EvolutionRegistryError("candidate_id has an invalid value")
        if isinstance(self.version, bool) or not isinstance(self.version, int) or self.version < 1:
            raise EvolutionRegistryError("version must be a positive integer")
        _required_text(self.objective_id, "objective_id")
        _required_text(self.collection_evidence_id, "collection_evidence_id")
        if self.validation_evidence_id is not None:
            _required_text(self.validation_evidence_id, "validation_evidence_id")
        if self.qualification_evidence_id is not None:
            _required_text(self.qualification_evidence_id, "qualification_evidence_id")
        if self.activation_evidence_id is not None:
            _required_text(self.activation_evidence_id, "activation_evidence_id")
        if (self.materialized_artifact_id is None) != (self.materialized_artifact_sha256 is None):
            raise EvolutionRegistryError(
                "materialized artifact id and sha256 must be provided together"
            )
        if self.materialized_artifact_id is not None:
            _artifact_id(
                self.materialized_artifact_id,
                "materialized_artifact_id",
                self.surface,
            )
            if self.materialized_artifact_sha256 is None:
                raise EvolutionRegistryError(
                    "materialized artifact sha256 is required"
                )
            _artifact_sha256(
                self.materialized_artifact_sha256, "materialized_artifact_sha256"
            )
            _required_text(self.materialization_evidence_id, "materialization_evidence_id")
        expected = _candidate_identity(
            self.surface,
            self.target_role,
            self.version,
            self.parent_candidate_id,
            self.artifact_id,
        )
        if self.candidate_id != expected:
            raise EvolutionRegistryError("candidate_id does not match candidate content")
        if self.state is CandidateState.COLLECTED:
            if self.validation_evidence_id is not None or self.qualification_evidence_id is not None:
                raise EvolutionRegistryError("a collected candidate cannot have later-stage evidence")
        elif self.state is CandidateState.VALIDATED:
            if self.validation_evidence_id is None or self.qualification_evidence_id is not None:
                raise EvolutionRegistryError("a validated candidate requires only validation evidence")
        elif self.state in {CandidateState.QUALIFIED, CandidateState.ACTIVE}:
            if self.validation_evidence_id is None or self.qualification_evidence_id is None:
                raise EvolutionRegistryError("qualified and active candidates require both evidence stages")

    @property
    def identity_key(self) -> tuple[EvolutionSurface, Role]:
        return (self.surface, self.target_role)


@dataclass(frozen=True, slots=True)
class EvolutionRegistryProjection:
    campaign_id: str
    stream_id: str
    sequence: int = 0
    candidates: Mapping[str, EvolutionCandidateRecord] = field(default_factory=dict)
    champions: Mapping[tuple[EvolutionSurface, Role], str] = field(default_factory=dict)
    champion_history: Mapping[tuple[EvolutionSurface, Role], tuple[str, ...]] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        _required_text(self.campaign_id, "campaign_id")
        _required_text(self.stream_id, "stream_id")
        if self.stream_id != evolution_registry_stream_id(self.campaign_id):
            raise EvolutionRegistryError("stream_id does not match the evolution registry stream contract")
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int) or self.sequence < 0:
            raise EvolutionRegistryError("sequence must be a non-negative integer")
        object.__setattr__(self, "candidates", MappingProxyType(dict(self.candidates)))
        object.__setattr__(self, "champions", MappingProxyType(dict(self.champions)))
        object.__setattr__(self, "champion_history", MappingProxyType(dict(self.champion_history)))

    def champion(self, surface: EvolutionSurface, role: Role) -> EvolutionCandidateRecord | None:
        candidate_id = self.champions.get((surface, role))
        return self.candidates.get(candidate_id) if candidate_id is not None else None


class EvolutionRegistry:
    """CAS-guarded candidate lifecycle and per-surface champion activation."""

    def __init__(self, store: EventStore, campaign_id: str) -> None:
        if not isinstance(store, EventStore):
            raise TypeError("store must be an EventStore")
        self._store = store
        self._campaign_id = _required_text(campaign_id, "campaign_id")
        self._stream_id = evolution_registry_stream_id(self._campaign_id)
        self._projection = EvolutionRegistryProjection(self._campaign_id, self._stream_id)
        self.refresh()

    @property
    def stream_id(self) -> str:
        return self._stream_id

    @property
    def projection(self) -> EvolutionRegistryProjection:
        return self._projection

    def refresh(self) -> EvolutionRegistryProjection:
        projection = EvolutionRegistryProjection(self._campaign_id, self._stream_id)
        for event in self._store.read(self._stream_id):
            projection = self._apply_event(projection, event)
        self._projection = projection
        return projection

    def champion(self, surface: EvolutionSurface, role: Role) -> EvolutionCandidateRecord | None:
        return self._projection.champion(surface, role)

    def candidates(self) -> tuple[EvolutionCandidateRecord, ...]:
        return tuple(
            sorted(
                self._projection.candidates.values(),
                key=lambda item: (item.surface.value, item.target_role.value, item.version),
            )
        )

    def validated_candidates(self) -> tuple[EvolutionCandidateRecord, ...]:
        """Validated work in append order, providing a deterministic FIFO queue."""
        return tuple(
            item
            for item in self._projection.candidates.values()
            if item.state is CandidateState.VALIDATED
        )

    def collect(
        self,
        surface: EvolutionSurface,
        target_role: Role,
        *,
        artifact_id: str,
        artifact_sha256: str,
        objective_id: str,
        collection_evidence_id: str,
    ) -> EvolutionCandidateRecord:
        artifact_id = _artifact_id(artifact_id, "artifact_id", surface)
        artifact_sha256 = _artifact_sha256(artifact_sha256, "artifact_sha256")
        objective_id = _required_text(objective_id, "objective_id")
        collection_evidence_id = _required_text(collection_evidence_id, "collection_evidence_id")
        current = self._projection.champion(surface, target_role)
        parent = current.candidate_id if current is not None else None
        version = 1 if current is None else current.version + 1
        candidate_id = _candidate_identity(
            surface, target_role, version, parent, artifact_id
        )
        if candidate_id in self._projection.candidates:
            raise EvolutionRegistryError("candidate is already registered")
        record = EvolutionCandidateRecord(
            candidate_id,
            surface,
            target_role,
            version,
            parent,
            artifact_id,
            artifact_sha256,
            objective_id,
            collection_evidence_id=collection_evidence_id,
        )
        return self._append(
            CANDIDATE_COLLECTED,
            {
                "schema_version": SCHEMA_VERSION,
                "candidate_id": record.candidate_id,
                "surface": surface.value,
                "target_role": target_role.value,
                "version": version,
                "parent_candidate_id": parent,
                "artifact_id": artifact_id,
                "artifact_sha256": artifact_sha256,
                "objective_id": objective_id,
                "state": CandidateState.COLLECTED.value,
                "collection_evidence_id": collection_evidence_id,
            },
        ).candidates[candidate_id]

    def validate(self, candidate_id: str, *, validation_evidence_id: str) -> EvolutionCandidateRecord:
        validation_evidence_id = _required_text(
            validation_evidence_id, "validation_evidence_id"
        )
        self._require_state(candidate_id, CandidateState.COLLECTED)
        return self._append(
            CANDIDATE_VALIDATED,
            {
                "schema_version": SCHEMA_VERSION,
                "candidate_id": candidate_id,
                "previous_state": CandidateState.COLLECTED.value,
                "state": CandidateState.VALIDATED.value,
                "validation_evidence_id": validation_evidence_id,
            },
        ).candidates[candidate_id]

    def attach_materialized_artifact(
        self,
        candidate_id: str,
        *,
        materialized_artifact_id: str,
        materialized_artifact_sha256: str,
        materialization_evidence_id: str,
    ) -> EvolutionCandidateRecord:
        """Bind a control-plane-built artifact (e.g. an environment receipt) to
        a collected/validated candidate without changing its identity or
        lineage.  The original proposal artifact remains the candidate's
        content address; consumers resolve the materialized artifact first."""
        record = self._record(candidate_id)
        if record.surface is not EvolutionSurface.ENVIRONMENT:
            raise EvolutionRegistryError(
                "only environment candidates may carry a materialized build artifact"
            )
        if record.state not in {CandidateState.COLLECTED, CandidateState.VALIDATED}:
            raise EvolutionRegistryError(
                "only collected or validated candidates may be materialized"
            )
        materialized_artifact_id = _artifact_id(
            materialized_artifact_id,
            "materialized_artifact_id",
            record.surface,
        )
        materialized_artifact_sha256 = _artifact_sha256(
            materialized_artifact_sha256,
            "materialized_artifact_sha256",
        )
        materialization_evidence_id = _required_text(
            materialization_evidence_id, "materialization_evidence_id"
        )
        return self._append(
            CANDIDATE_MATERIALIZED,
            {
                "schema_version": SCHEMA_VERSION,
                "candidate_id": candidate_id,
                "materialized_artifact_id": materialized_artifact_id,
                "materialized_artifact_sha256": materialized_artifact_sha256,
                "materialization_evidence_id": materialization_evidence_id,
            },
        ).candidates[candidate_id]

    def reject(self, candidate_id: str, *, reason: str) -> EvolutionCandidateRecord:
        reason = _required_text(reason, "reason")
        record = self._record(candidate_id)
        if record.state not in {CandidateState.COLLECTED, CandidateState.VALIDATED}:
            raise EvolutionRegistryError(
                "only collected or validated candidates may be rejected"
            )
        return self._append(
            CANDIDATE_REJECTED,
            {
                "schema_version": SCHEMA_VERSION,
                "candidate_id": candidate_id,
                "previous_state": record.state.value,
                "state": CandidateState.REJECTED.value,
                "reason": reason[:2000],
            },
        ).candidates[candidate_id]

    def qualify(
        self, candidate_id: str, *, qualification_evidence_id: str
    ) -> EvolutionCandidateRecord:
        qualification_evidence_id = _required_text(
            qualification_evidence_id, "qualification_evidence_id"
        )
        self._require_state(candidate_id, CandidateState.VALIDATED)
        return self._append(
            CANDIDATE_QUALIFIED,
            {
                "schema_version": SCHEMA_VERSION,
                "candidate_id": candidate_id,
                "previous_state": CandidateState.VALIDATED.value,
                "state": CandidateState.QUALIFIED.value,
                "qualification_evidence_id": qualification_evidence_id,
            },
        ).candidates[candidate_id]

    def activate(
        self, candidate_id: str, *, activation_evidence_id: str
    ) -> EvolutionCandidateRecord:
        activation_evidence_id = _required_text(
            activation_evidence_id, "activation_evidence_id"
        )
        record = self._record(candidate_id)
        if record.state is not CandidateState.QUALIFIED:
            raise EvolutionRegistryError("only qualified candidates may be activated")
        current = self._projection.champion(record.surface, record.target_role)
        if current is not None and current.candidate_id != record.parent_candidate_id:
            raise EvolutionRegistryError("candidate is stale relative to the current champion")
        return self._append(
            SURFACE_ACTIVATED,
            {
                "schema_version": SCHEMA_VERSION,
                "candidate_id": candidate_id,
                "surface": record.surface.value,
                "target_role": record.target_role.value,
                "previous_champion_id": current.candidate_id if current is not None else None,
                "activation_evidence_id": activation_evidence_id,
            },
        ).candidates[candidate_id]

    def rollback(
        self,
        surface: EvolutionSurface,
        target_role: Role,
        *,
        reason: str,
        expected_champion_id: str,
    ) -> EvolutionCandidateRecord:
        reason = _required_text(reason, "reason")
        current = self._projection.champion(surface, target_role)
        if current is None or current.candidate_id != expected_champion_id:
            raise EvolutionRegistryError("expected champion does not match the current champion")
        history = self._projection.champion_history.get((surface, target_role), ())
        if len(history) < 2:
            raise EvolutionRegistryError("no prior champion exists for rollback")
        target_id = history[-2]
        self._append(
            SURFACE_ROLLED_BACK,
            {
                "schema_version": SCHEMA_VERSION,
                "surface": surface.value,
                "target_role": target_role.value,
                "expected_champion_id": current.candidate_id,
                "target_champion_id": target_id,
                "reason": reason[:2000],
            },
        )
        return self._projection.candidates[target_id]

    def _record(self, candidate_id: str) -> EvolutionCandidateRecord:
        try:
            return self._projection.candidates[candidate_id]
        except KeyError as exc:
            raise EvolutionRegistryError("candidate is not registered") from exc

    def _require_state(self, candidate_id: str, state: CandidateState) -> None:
        record = self._record(candidate_id)
        if record.state is not state:
            raise EvolutionRegistryError(f"candidate must be {state.value}")

    def _append(
        self, event_type: str, payload: Mapping[str, Any]
    ) -> EvolutionRegistryProjection:
        event = self._store.append_if_sequence(
            self._stream_id,
            self._projection.sequence,
            event_type,
            payload,
        )
        projection = self._apply_event(self._projection, event)
        self._projection = projection
        return projection

    def _apply_event(
        self, projection: EvolutionRegistryProjection, event: AuditEvent
    ) -> EvolutionRegistryProjection:
        if event.campaign_id != projection.stream_id:
            raise EvolutionRegistryError("event belongs to a different evolution registry stream")
        if event.sequence != projection.sequence + 1:
            raise EvolutionRegistryError("evolution registry event sequence is not contiguous")
        if event.event_type not in _KNOWN_EVENTS:
            return replace(projection, sequence=event.sequence)
        payload = thaw_json(event.payload)
        try:
            updated = self._apply_known_event(projection, event.event_type, payload)
        except EvolutionRegistryError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise EvolutionRegistryError(
                f"invalid {event.event_type} event at sequence {event.sequence}"
            ) from exc
        return replace(updated, sequence=event.sequence)

    def _apply_known_event(
        self, projection: EvolutionRegistryProjection, event_type: str, payload: object
    ) -> EvolutionRegistryProjection:
        if event_type == CANDIDATE_COLLECTED:
            return self._apply_collected(projection, payload)
        if event_type == CANDIDATE_VALIDATED:
            return self._apply_validated(projection, payload)
        if event_type == CANDIDATE_REJECTED:
            return self._apply_rejected(projection, payload)
        if event_type == CANDIDATE_QUALIFIED:
            return self._apply_qualified(projection, payload)
        if event_type == CANDIDATE_MATERIALIZED:
            return self._apply_materialized(projection, payload)
        if event_type == SURFACE_ACTIVATED:
            return self._apply_activated(projection, payload)
        if event_type == SURFACE_ROLLED_BACK:
            return self._apply_rolled_back(projection, payload)
        raise AssertionError("unreachable")

    @classmethod
    def _apply_collected(
        cls, projection: EvolutionRegistryProjection, payload: object
    ) -> EvolutionRegistryProjection:
        data = _strict_payload(
            payload,
            {
                "schema_version",
                "candidate_id",
                "surface",
                "target_role",
                "version",
                "parent_candidate_id",
                "artifact_id",
                "artifact_sha256",
                "objective_id",
                "state",
                "collection_evidence_id",
            },
            CANDIDATE_COLLECTED,
        )
        surface = _surface(data["surface"], "surface")
        target_role = _role(data["target_role"], "target_role")
        artifact_id = _artifact_id(data["artifact_id"], "artifact_id", surface)
        artifact_sha256 = _artifact_sha256(data["artifact_sha256"], "artifact_sha256")
        if _state(data["state"], "state") is not CandidateState.COLLECTED:
            raise EvolutionRegistryError("new evolution candidates must be collected")
        record = EvolutionCandidateRecord(
            _required_text(data["candidate_id"], "candidate_id"),
            surface,
            target_role,
            data["version"],
            _optional_text(data["parent_candidate_id"], "parent_candidate_id"),
            artifact_id,
            artifact_sha256,
            _required_text(data["objective_id"], "objective_id"),
            collection_evidence_id=_required_text(
                data["collection_evidence_id"], "collection_evidence_id"
            ),
        )
        if record.candidate_id in projection.candidates:
            raise EvolutionRegistryError("duplicate evolution candidate identity")
        current = projection.champion(surface, target_role)
        expected_parent = current.candidate_id if current is not None else None
        if record.parent_candidate_id != expected_parent:
            raise EvolutionRegistryError("candidate parent does not match the current champion")
        expected_version = 1 if current is None else current.version + 1
        if record.version != expected_version:
            raise EvolutionRegistryError("candidate version does not match the champion lineage")
        candidates = dict(projection.candidates)
        candidates[record.candidate_id] = record
        return replace(projection, candidates=candidates)

    @staticmethod
    def _apply_validated(
        projection: EvolutionRegistryProjection, payload: object
    ) -> EvolutionRegistryProjection:
        data = _strict_payload(
            payload,
            {
                "schema_version",
                "candidate_id",
                "previous_state",
                "state",
                "validation_evidence_id",
            },
            CANDIDATE_VALIDATED,
        )
        candidate_id = _required_text(data["candidate_id"], "candidate_id")
        record = projection.candidates.get(candidate_id)
        if record is None or record.state is not CandidateState.COLLECTED:
            raise EvolutionRegistryError("validated candidate must be collected")
        if (
            _state(data["previous_state"], "previous_state") is not CandidateState.COLLECTED
            or _state(data["state"], "state") is not CandidateState.VALIDATED
        ):
            raise EvolutionRegistryError("invalid candidate validation transition")
        candidates = dict(projection.candidates)
        candidates[candidate_id] = replace(
            record,
            state=CandidateState.VALIDATED,
            validation_evidence_id=_required_text(
                data["validation_evidence_id"], "validation_evidence_id"
            ),
        )
        return replace(projection, candidates=candidates)

    @staticmethod
    def _apply_rejected(
        projection: EvolutionRegistryProjection, payload: object
    ) -> EvolutionRegistryProjection:
        data = _strict_payload(
            payload,
            {
                "schema_version",
                "candidate_id",
                "previous_state",
                "state",
                "reason",
            },
            CANDIDATE_REJECTED,
        )
        candidate_id = _required_text(data["candidate_id"], "candidate_id")
        record = projection.candidates.get(candidate_id)
        if record is None or record.state not in {
            CandidateState.COLLECTED,
            CandidateState.VALIDATED,
        }:
            raise EvolutionRegistryError(
                "rejected candidate must be collected or validated"
            )
        if (
            _state(data["previous_state"], "previous_state") is not record.state
            or _state(data["state"], "state") is not CandidateState.REJECTED
        ):
            raise EvolutionRegistryError("invalid candidate rejection transition")
        candidates = dict(projection.candidates)
        candidates[candidate_id] = replace(
            record,
            state=CandidateState.REJECTED,
        )
        return replace(projection, candidates=candidates)

    @staticmethod
    def _apply_materialized(
        projection: EvolutionRegistryProjection, payload: object
    ) -> EvolutionRegistryProjection:
        data = _strict_payload(
            payload,
            {
                "schema_version",
                "candidate_id",
                "materialized_artifact_id",
                "materialized_artifact_sha256",
                "materialization_evidence_id",
            },
            CANDIDATE_MATERIALIZED,
        )
        candidate_id = _required_text(data["candidate_id"], "candidate_id")
        record = projection.candidates.get(candidate_id)
        if record is None or record.state not in {
            CandidateState.COLLECTED,
            CandidateState.VALIDATED,
        }:
            raise EvolutionRegistryError(
                "materialized candidate must be collected or validated"
            )
        if record.surface is not EvolutionSurface.ENVIRONMENT:
            raise EvolutionRegistryError(
                "only environment candidates may be materialized"
            )
        materialized_artifact_id = _artifact_id(
            data["materialized_artifact_id"],
            "materialized_artifact_id",
            record.surface,
        )
        materialized_artifact_sha256 = _artifact_sha256(
            data["materialized_artifact_sha256"],
            "materialized_artifact_sha256",
        )
        candidates = dict(projection.candidates)
        candidates[candidate_id] = replace(
            record,
            materialized_artifact_id=materialized_artifact_id,
            materialized_artifact_sha256=materialized_artifact_sha256,
            materialization_evidence_id=_required_text(
                data["materialization_evidence_id"],
                "materialization_evidence_id",
            ),
        )
        return replace(projection, candidates=candidates)

    @staticmethod
    def _apply_qualified(
        projection: EvolutionRegistryProjection, payload: object
    ) -> EvolutionRegistryProjection:
        data = _strict_payload(
            payload,
            {
                "schema_version",
                "candidate_id",
                "previous_state",
                "state",
                "qualification_evidence_id",
            },
            CANDIDATE_QUALIFIED,
        )
        candidate_id = _required_text(data["candidate_id"], "candidate_id")
        record = projection.candidates.get(candidate_id)
        if record is None or record.state is not CandidateState.VALIDATED:
            raise EvolutionRegistryError("qualified candidate must be validated")
        if (
            _state(data["previous_state"], "previous_state") is not CandidateState.VALIDATED
            or _state(data["state"], "state") is not CandidateState.QUALIFIED
        ):
            raise EvolutionRegistryError("invalid candidate qualification transition")
        candidates = dict(projection.candidates)
        candidates[candidate_id] = replace(
            record,
            state=CandidateState.QUALIFIED,
            qualification_evidence_id=_required_text(
                data["qualification_evidence_id"], "qualification_evidence_id"
            ),
        )
        return replace(projection, candidates=candidates)

    @staticmethod
    def _apply_activated(
        projection: EvolutionRegistryProjection, payload: object
    ) -> EvolutionRegistryProjection:
        data = _strict_payload(
            payload,
            {
                "schema_version",
                "candidate_id",
                "surface",
                "target_role",
                "previous_champion_id",
                "activation_evidence_id",
            },
            SURFACE_ACTIVATED,
        )
        candidate_id = _required_text(data["candidate_id"], "candidate_id")
        surface = _surface(data["surface"], "surface")
        target_role = _role(data["target_role"], "target_role")
        record = projection.candidates.get(candidate_id)
        if (
            record is None
            or record.state is not CandidateState.QUALIFIED
            or record.surface is not surface
            or record.target_role is not target_role
        ):
            raise EvolutionRegistryError("activation candidate is ineligible")
        previous = _optional_text(data["previous_champion_id"], "previous_champion_id")
        current = projection.champion(surface, target_role)
        if (current.candidate_id if current is not None else None) != previous:
            raise EvolutionRegistryError("activation previous champion does not match")
        candidates = dict(projection.candidates)
        champions = dict(projection.champions)
        history = dict(projection.champion_history)
        key = (surface, target_role)
        if current is not None:
            candidates[current.candidate_id] = replace(
                candidates[current.candidate_id], state=CandidateState.SUPERSEDED
            )
        candidates[candidate_id] = replace(
            candidates[candidate_id],
            state=CandidateState.ACTIVE,
            activation_evidence_id=_required_text(
                data["activation_evidence_id"], "activation_evidence_id"
            ),
        )
        champions[key] = candidate_id
        history[key] = tuple(history.get(key, ())) + (candidate_id,)
        return replace(
            projection,
            candidates=candidates,
            champions=champions,
            champion_history=history,
        )

    @staticmethod
    def _apply_rolled_back(
        projection: EvolutionRegistryProjection, payload: object
    ) -> EvolutionRegistryProjection:
        data = _strict_payload(
            payload,
            {
                "schema_version",
                "surface",
                "target_role",
                "expected_champion_id",
                "target_champion_id",
                "reason",
            },
            SURFACE_ROLLED_BACK,
        )
        surface = _surface(data["surface"], "surface")
        target_role = _role(data["target_role"], "target_role")
        expected = _required_text(data["expected_champion_id"], "expected_champion_id")
        target_id = _required_text(data["target_champion_id"], "target_champion_id")
        _required_text(data["reason"], "reason")
        current = projection.champion(surface, target_role)
        if current is None or current.candidate_id != expected:
            raise EvolutionRegistryError("rollback expected champion does not match")
        key = (surface, target_role)
        history = projection.champion_history.get(key, ())
        if len(history) < 2 or history[-2] != target_id or history[-1] != expected:
            raise EvolutionRegistryError("rollback target is not the immediate prior champion")
        candidates = dict(projection.candidates)
        champions = dict(projection.champions)
        candidates[expected] = replace(
            candidates[expected], state=CandidateState.REVOKED
        )
        candidates[target_id] = replace(
            candidates[target_id], state=CandidateState.ACTIVE
        )
        champions[key] = target_id
        return replace(
            projection,
            candidates=candidates,
            champions=champions,
            champion_history=projection.champion_history,
        )


__all__ = [
    "CANDIDATE_COLLECTED",
    "CANDIDATE_QUALIFIED",
    "CANDIDATE_REJECTED",
    "CANDIDATE_VALIDATED",
    "CandidateState",
    "EvolutionCandidateRecord",
    "EvolutionRegistry",
    "EvolutionRegistryError",
    "EvolutionRegistryProjection",
    "SURFACE_ACTIVATED",
    "SURFACE_ROLLED_BACK",
    "evolution_registry_stream_id",
]
