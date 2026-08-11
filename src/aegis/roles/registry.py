"""Append-only per-role candidate and atomic active-set registry for AEGIS v2."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Mapping

from aegis.curriculum.models import (
    SCHEMA_VERSION,
    ActiveRoleSet,
    ObjectiveVersion,
    RoleVersionIdentity,
)
from aegis.event_store import EventStore
from aegis.models import AuditEvent, Role, thaw_json

ROLE_CANDIDATE_COLLECTED_V2 = "role_candidate_collected_v2"
ROLE_CANDIDATE_VALIDATED_V2 = "role_candidate_validated_v2"
ROLE_CANDIDATE_QUALIFIED_V2 = "role_candidate_qualified_v2"
ROLE_ACTIVE_SET_COMMITTED_V2 = "role_active_set_committed_v2"
ROLE_ACTIVE_SET_ROLLED_BACK_V2 = "role_active_set_rolled_back_v2"
ROLE_ACTIVE_SET_OBJECTIVE_REBOUND_V2 = "role_active_set_objective_rebound_v2"

_KNOWN_EVENTS = frozenset(
    {
        ROLE_CANDIDATE_COLLECTED_V2,
        ROLE_CANDIDATE_VALIDATED_V2,
        ROLE_CANDIDATE_QUALIFIED_V2,
        ROLE_ACTIVE_SET_COMMITTED_V2,
        ROLE_ACTIVE_SET_ROLLED_BACK_V2,
        ROLE_ACTIVE_SET_OBJECTIVE_REBOUND_V2,
    }
)


class RoleRegistryError(RuntimeError):
    """Raised when a role command or persisted v2 event violates its contract."""


class RoleCandidateState(StrEnum):
    COLLECTED = "collected"
    VALIDATED = "validated"
    QUALIFIED = "qualified"
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    REVOKED = "revoked"


def _required_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise RoleRegistryError(f"{name} must be non-empty text without surrounding whitespace")
    return value


def role_registry_stream_id(campaign_id: str) -> str:
    """Return the role registry stream, isolated from the curriculum campaign stream."""

    return f"{_required_text(campaign_id, 'campaign_id')}:roles:v2"


def _strict_payload(value: object, expected: set[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise RoleRegistryError(f"{name} must be a string-keyed mapping")
    if set(value) != expected:
        raise RoleRegistryError(f"{name} has missing or unknown fields")
    if type(value["schema_version"]) is not int or value["schema_version"] != SCHEMA_VERSION:
        raise RoleRegistryError(f"{name}.schema_version must be {SCHEMA_VERSION}")
    return value


def _candidate_state(value: object, name: str) -> RoleCandidateState:
    if not isinstance(value, str):
        raise RoleRegistryError(f"{name} has an invalid value")
    try:
        return RoleCandidateState(value)
    except ValueError as exc:
        raise RoleRegistryError(f"{name} has an invalid value") from exc


def _optional_text(value: object, name: str) -> str | None:
    if value is None:
        return None
    return _required_text(value, name)


@dataclass(frozen=True, slots=True)
class RoleCandidateRecord:
    identity: RoleVersionIdentity
    objective_id: str
    state: RoleCandidateState = RoleCandidateState.COLLECTED
    collection_evidence_id: str = ""
    validation_evidence_id: str | None = None
    qualification_evidence_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.identity, RoleVersionIdentity):
            raise TypeError("identity must be a RoleVersionIdentity")
        if not isinstance(self.objective_id, str) or not self.objective_id.startswith(
            ObjectiveVersion.ID_PREFIX
        ):
            raise RoleRegistryError("objective_id must be a content-addressed objective identity")
        _required_text(self.collection_evidence_id, "collection_evidence_id")
        if self.validation_evidence_id is not None:
            _required_text(self.validation_evidence_id, "validation_evidence_id")
        if self.qualification_evidence_id is not None:
            _required_text(self.qualification_evidence_id, "qualification_evidence_id")
        if self.state is RoleCandidateState.COLLECTED:
            if self.validation_evidence_id is not None or self.qualification_evidence_id is not None:
                raise RoleRegistryError("a collected candidate cannot have later-stage evidence")
        elif self.state is RoleCandidateState.VALIDATED:
            if self.validation_evidence_id is None or self.qualification_evidence_id is not None:
                raise RoleRegistryError("a validated candidate requires only validation evidence")
        elif self.validation_evidence_id is None or self.qualification_evidence_id is None:
            raise RoleRegistryError("qualified and later candidate states require both evidence stages")

    @property
    def candidate_id(self) -> str:
        return self.identity.role_version_id


@dataclass(frozen=True, slots=True)
class RoleRegistryProjection:
    campaign_id: str
    stream_id: str
    sequence: int = 0
    candidates: Mapping[str, RoleCandidateRecord] = field(default_factory=dict)
    active_sets: Mapping[str, ActiveRoleSet] = field(default_factory=dict)
    active_set_parents: Mapping[str, str | None] = field(default_factory=dict)
    current_active_set_id: str | None = None

    def __post_init__(self) -> None:
        _required_text(self.campaign_id, "campaign_id")
        _required_text(self.stream_id, "stream_id")
        if self.stream_id != role_registry_stream_id(self.campaign_id):
            raise RoleRegistryError("stream_id does not match the role registry stream contract")
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int) or self.sequence < 0:
            raise RoleRegistryError("sequence must be a non-negative integer")
        object.__setattr__(self, "candidates", MappingProxyType(dict(self.candidates)))
        object.__setattr__(self, "active_sets", MappingProxyType(dict(self.active_sets)))
        object.__setattr__(self, "active_set_parents", MappingProxyType(dict(self.active_set_parents)))
        if self.current_active_set_id is not None and self.current_active_set_id not in self.active_sets:
            raise RoleRegistryError("current active set is not present in active_sets")

    @property
    def current_active_set(self) -> ActiveRoleSet | None:
        if self.current_active_set_id is None:
            return None
        return self.active_sets[self.current_active_set_id]

    def candidate_for_role(self, role: Role) -> RoleCandidateRecord | None:
        if not isinstance(role, Role):
            raise TypeError("role must be a Role")
        active = self.current_active_set
        if active is None:
            return None
        return self.candidates[active.for_role(role).role_version_id]


class RoleRegistry:
    """CAS-guarded role candidate lifecycle and atomic activation-set history."""

    def __init__(self, store: EventStore, campaign_id: str) -> None:
        if not isinstance(store, EventStore):
            raise TypeError("store must be an EventStore")
        self._store = store
        self._campaign_id = _required_text(campaign_id, "campaign_id")
        self._stream_id = role_registry_stream_id(self._campaign_id)
        self._projection = RoleRegistryProjection(self._campaign_id, self._stream_id)
        self.refresh()

    @property
    def stream_id(self) -> str:
        return self._stream_id

    @property
    def projection(self) -> RoleRegistryProjection:
        return self._projection

    def refresh(self) -> RoleRegistryProjection:
        projection = RoleRegistryProjection(self._campaign_id, self._stream_id)
        for event in self._store.read(self._stream_id):
            projection = self._apply_event(projection, event)
        self._projection = projection
        return projection

    def collect_candidate(
        self,
        identity: RoleVersionIdentity,
        *,
        objective_id: str,
        collection_evidence_id: str,
    ) -> RoleRegistryProjection:
        if not isinstance(identity, RoleVersionIdentity):
            raise TypeError("identity must be a RoleVersionIdentity")
        objective_id = _required_text(objective_id, "objective_id")
        collection_evidence_id = _required_text(collection_evidence_id, "collection_evidence_id")
        self._validate_new_identity(self._projection, identity)
        RoleCandidateRecord(identity, objective_id, collection_evidence_id=collection_evidence_id)
        return self._append(
            ROLE_CANDIDATE_COLLECTED_V2,
            {
                "schema_version": SCHEMA_VERSION,
                "identity": identity.to_mapping(),
                "objective_id": objective_id,
                "state": RoleCandidateState.COLLECTED.value,
                "collection_evidence_id": collection_evidence_id,
            },
        )

    def validate_candidate(
        self, candidate_id: str, *, validation_evidence_id: str
    ) -> RoleRegistryProjection:
        candidate_id = _required_text(candidate_id, "candidate_id")
        validation_evidence_id = _required_text(validation_evidence_id, "validation_evidence_id")
        self._require_state(candidate_id, RoleCandidateState.COLLECTED)
        return self._append(
            ROLE_CANDIDATE_VALIDATED_V2,
            {
                "schema_version": SCHEMA_VERSION,
                "candidate_id": candidate_id,
                "previous_state": RoleCandidateState.COLLECTED.value,
                "state": RoleCandidateState.VALIDATED.value,
                "validation_evidence_id": validation_evidence_id,
            },
        )

    def qualify_candidate(
        self, candidate_id: str, *, qualification_evidence_id: str
    ) -> RoleRegistryProjection:
        candidate_id = _required_text(candidate_id, "candidate_id")
        qualification_evidence_id = _required_text(
            qualification_evidence_id, "qualification_evidence_id"
        )
        self._require_state(candidate_id, RoleCandidateState.VALIDATED)
        return self._append(
            ROLE_CANDIDATE_QUALIFIED_V2,
            {
                "schema_version": SCHEMA_VERSION,
                "candidate_id": candidate_id,
                "previous_state": RoleCandidateState.VALIDATED.value,
                "state": RoleCandidateState.QUALIFIED.value,
                "qualification_evidence_id": qualification_evidence_id,
            },
        )

    def commit_active_set(
        self,
        candidates: Mapping[Role, str],
        *,
        objective_id: str,
        joint_evidence_id: str,
        expected_current_active_set_id: str | None,
    ) -> RoleRegistryProjection:
        objective_id = _required_text(objective_id, "objective_id")
        joint_evidence_id = _required_text(joint_evidence_id, "joint_evidence_id")
        expected_current_active_set_id = _optional_text(
            expected_current_active_set_id, "expected_current_active_set_id"
        )
        selected = self._normalize_selection(candidates)
        if expected_current_active_set_id != self._projection.current_active_set_id:
            raise RoleRegistryError("expected current active set does not match")
        for role, candidate_id in selected.items():
            record = self._record(candidate_id)
            if record.identity.role is not role:
                raise RoleRegistryError("candidate is assigned to the wrong role slot")
            if record.state is not RoleCandidateState.QUALIFIED:
                raise RoleRegistryError("all selected candidates must be qualified")
            if record.objective_id != objective_id:
                raise RoleRegistryError("selected candidate is bound to a different objective")
        active_set = self._build_active_set(self._projection, selected, objective_id)
        return self._append(
            ROLE_ACTIVE_SET_COMMITTED_V2,
            {
                "schema_version": SCHEMA_VERSION,
                "objective_id": objective_id,
                "candidate_ids": {
                    role.value: selected[role] for role in Role if role in selected
                },
                "joint_evidence_id": joint_evidence_id,
                "expected_current_active_set_id": expected_current_active_set_id,
                "active_set": active_set.to_mapping(),
            },
        )

    def rollback_active_set(
        self,
        target_active_set_id: str,
        *,
        expected_current_active_set_id: str,
        joint_evidence_id: str,
        reason: str,
    ) -> RoleRegistryProjection:
        target_active_set_id = _required_text(target_active_set_id, "target_active_set_id")
        expected_current_active_set_id = _required_text(
            expected_current_active_set_id, "expected_current_active_set_id"
        )
        joint_evidence_id = _required_text(joint_evidence_id, "joint_evidence_id")
        reason = _required_text(reason, "reason")
        current = self._projection.current_active_set
        target = self._projection.active_sets.get(target_active_set_id)
        if current is None or expected_current_active_set_id != current.active_role_set_id:
            raise RoleRegistryError("expected current active set does not match")
        if target is None or target.active_role_set_id == current.active_role_set_id:
            raise RoleRegistryError("rollback target must be a prior active set")
        if target.objective_id != current.objective_id:
            raise RoleRegistryError("rollback cannot cross an objective boundary")
        return self._append(
            ROLE_ACTIVE_SET_ROLLED_BACK_V2,
            {
                "schema_version": SCHEMA_VERSION,
                "expected_current_active_set_id": expected_current_active_set_id,
                "target_active_set_id": target_active_set_id,
                "joint_evidence_id": joint_evidence_id,
                "reason": reason,
            },
        )

    def rebind_objective(
        self,
        objective_id: str,
        *,
        evidence_id: str,
        expected_current_active_set_id: str,
    ) -> RoleRegistryProjection:
        """Create a new revision with identical role versions bound to another objective."""
        objective_id = _required_text(objective_id, "objective_id")
        evidence_id = _required_text(evidence_id, "evidence_id")
        expected_current_active_set_id = _required_text(
            expected_current_active_set_id, "expected_current_active_set_id"
        )
        current = self._projection.current_active_set
        if current is None or current.active_role_set_id != expected_current_active_set_id:
            raise RoleRegistryError("expected current active set does not match")
        if current.objective_id == objective_id:
            raise RoleRegistryError("active role set is already bound to the objective")
        rebound = ActiveRoleSet(
            revision=current.revision + 1,
            objective_id=objective_id,
            warrior=current.warrior,
            judge=current.judge,
            prosecutor=current.prosecutor,
        )
        return self._append(
            ROLE_ACTIVE_SET_OBJECTIVE_REBOUND_V2,
            {
                "schema_version": SCHEMA_VERSION,
                "objective_id": objective_id,
                "evidence_id": evidence_id,
                "expected_current_active_set_id": expected_current_active_set_id,
                "active_set": rebound.to_mapping(),
            },
        )
    def _record(self, candidate_id: str) -> RoleCandidateRecord:
        try:
            return self._projection.candidates[candidate_id]
        except KeyError as exc:
            raise RoleRegistryError("candidate is not registered") from exc

    def _require_state(self, candidate_id: str, state: RoleCandidateState) -> None:
        if self._record(candidate_id).state is not state:
            raise RoleRegistryError(f"candidate must be {state.value}")

    @staticmethod
    def _normalize_selection(candidates: Mapping[Role, str]) -> dict[Role, str]:
        if not isinstance(candidates, Mapping) or not 1 <= len(candidates) <= len(Role):
            raise RoleRegistryError("active-set commit requires one to three role candidates")
        selected: dict[Role, str] = {}
        for role, candidate_id in candidates.items():
            if not isinstance(role, Role):
                raise TypeError("candidate selection keys must be Role values")
            selected[role] = _required_text(candidate_id, f"{role.value}_candidate_id")
        if len(set(selected.values())) != len(selected):
            raise RoleRegistryError("candidate identities must be distinct")
        return selected

    @staticmethod
    def _build_active_set(
        projection: RoleRegistryProjection,
        selected: Mapping[Role, str],
        objective_id: str,
    ) -> ActiveRoleSet:
        current = projection.current_active_set
        if current is None and set(selected) != set(Role):
            raise RoleRegistryError("the initial active-set commit requires all three roles")
        if (
            current is not None
            and current.objective_id != objective_id
            and set(selected) != set(Role)
        ):
            raise RoleRegistryError(
                "a cross-objective active-set commit requires qualified candidates for all roles"
            )
        identities: dict[Role, RoleVersionIdentity] = {}
        for role in Role:
            if role in selected:
                identities[role] = projection.candidates[selected[role]].identity
            elif current is not None:
                identities[role] = current.for_role(role)
        revision = 0 if current is None else current.revision + 1
        return ActiveRoleSet(
            revision=revision,
            objective_id=objective_id,
            warrior=identities[Role.WARRIOR],
            judge=identities[Role.JUDGE],
            prosecutor=identities[Role.PROSECUTOR],
        )

    @staticmethod
    def _validate_new_identity(
        projection: RoleRegistryProjection, identity: RoleVersionIdentity
    ) -> None:
        if identity.role_version_id in projection.candidates:
            raise RoleRegistryError("candidate is already registered")
        if identity.parent_role_version_id is None:
            if identity.version != 1:
                raise RoleRegistryError("only a version 1 candidate may omit its parent")
            return
        parent = projection.candidates.get(identity.parent_role_version_id)
        if parent is None:
            raise RoleRegistryError("candidate parent is not registered")
        if (
            parent.identity.role is not identity.role
            or parent.identity.constitution_id != identity.constitution_id
            or identity.version != parent.identity.version + 1
        ):
            raise RoleRegistryError("candidate has invalid role-version lineage")

    def _append(self, event_type: str, payload: Mapping[str, Any]) -> RoleRegistryProjection:
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
        self, projection: RoleRegistryProjection, event: AuditEvent
    ) -> RoleRegistryProjection:
        if event.campaign_id != projection.stream_id:
            raise RoleRegistryError("event belongs to a different role registry stream")
        if event.sequence != projection.sequence + 1:
            raise RoleRegistryError("role registry event sequence is not contiguous")
        if event.event_type not in _KNOWN_EVENTS:
            return replace(projection, sequence=event.sequence)
        payload = thaw_json(event.payload)
        try:
            updated = self._apply_known_event(projection, event.event_type, payload)
        except RoleRegistryError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise RoleRegistryError(
                f"invalid {event.event_type} event at sequence {event.sequence}"
            ) from exc
        return replace(updated, sequence=event.sequence)

    def _apply_known_event(
        self, projection: RoleRegistryProjection, event_type: str, payload: object
    ) -> RoleRegistryProjection:
        if event_type == ROLE_CANDIDATE_COLLECTED_V2:
            return self._apply_collected(projection, payload, event_type)
        if event_type == ROLE_CANDIDATE_VALIDATED_V2:
            return self._apply_validated(projection, payload, event_type)
        if event_type == ROLE_CANDIDATE_QUALIFIED_V2:
            return self._apply_qualified(projection, payload, event_type)
        if event_type == ROLE_ACTIVE_SET_COMMITTED_V2:
            return self._apply_commit(projection, payload, event_type)
        if event_type == ROLE_ACTIVE_SET_ROLLED_BACK_V2:
            return self._apply_rollback(projection, payload, event_type)
        if event_type == ROLE_ACTIVE_SET_OBJECTIVE_REBOUND_V2:
            return self._apply_objective_rebind(projection, payload, event_type)
        raise AssertionError("unreachable")

    @classmethod
    def _apply_collected(
        cls, projection: RoleRegistryProjection, payload: object, event_type: str
    ) -> RoleRegistryProjection:
        data = _strict_payload(
            payload,
            {"schema_version", "identity", "objective_id", "state", "collection_evidence_id"},
            event_type,
        )
        identity = RoleVersionIdentity.from_mapping(data["identity"])
        cls._validate_new_identity(projection, identity)
        if _candidate_state(data["state"], "state") is not RoleCandidateState.COLLECTED:
            raise RoleRegistryError("new role candidates must be collected")
        record = RoleCandidateRecord(
            identity=identity,
            objective_id=_required_text(data["objective_id"], "objective_id"),
            collection_evidence_id=_required_text(
                data["collection_evidence_id"], "collection_evidence_id"
            ),
        )
        candidates = dict(projection.candidates)
        candidates[record.candidate_id] = record
        return replace(projection, candidates=candidates)

    @staticmethod
    def _apply_validated(
        projection: RoleRegistryProjection, payload: object, event_type: str
    ) -> RoleRegistryProjection:
        data = _strict_payload(
            payload,
            {
                "schema_version",
                "candidate_id",
                "previous_state",
                "state",
                "validation_evidence_id",
            },
            event_type,
        )
        candidate_id = _required_text(data["candidate_id"], "candidate_id")
        record = projection.candidates.get(candidate_id)
        if record is None or record.state is not RoleCandidateState.COLLECTED:
            raise RoleRegistryError("validated candidate must be collected")
        if (
            _candidate_state(data["previous_state"], "previous_state")
            is not RoleCandidateState.COLLECTED
            or _candidate_state(data["state"], "state") is not RoleCandidateState.VALIDATED
        ):
            raise RoleRegistryError("invalid candidate validation transition")
        candidates = dict(projection.candidates)
        candidates[candidate_id] = replace(
            record,
            state=RoleCandidateState.VALIDATED,
            validation_evidence_id=_required_text(
                data["validation_evidence_id"], "validation_evidence_id"
            ),
        )
        return replace(projection, candidates=candidates)

    @staticmethod
    def _apply_qualified(
        projection: RoleRegistryProjection, payload: object, event_type: str
    ) -> RoleRegistryProjection:
        data = _strict_payload(
            payload,
            {
                "schema_version",
                "candidate_id",
                "previous_state",
                "state",
                "qualification_evidence_id",
            },
            event_type,
        )
        candidate_id = _required_text(data["candidate_id"], "candidate_id")
        record = projection.candidates.get(candidate_id)
        if record is None or record.state is not RoleCandidateState.VALIDATED:
            raise RoleRegistryError("qualified candidate must be validated")
        if (
            _candidate_state(data["previous_state"], "previous_state")
            is not RoleCandidateState.VALIDATED
            or _candidate_state(data["state"], "state") is not RoleCandidateState.QUALIFIED
        ):
            raise RoleRegistryError("invalid candidate qualification transition")
        candidates = dict(projection.candidates)
        candidates[candidate_id] = replace(
            record,
            state=RoleCandidateState.QUALIFIED,
            qualification_evidence_id=_required_text(
                data["qualification_evidence_id"], "qualification_evidence_id"
            ),
        )
        return replace(projection, candidates=candidates)

    @classmethod
    def _apply_commit(
        cls, projection: RoleRegistryProjection, payload: object, event_type: str
    ) -> RoleRegistryProjection:
        data = _strict_payload(
            payload,
            {
                "schema_version",
                "objective_id",
                "candidate_ids",
                "joint_evidence_id",
                "expected_current_active_set_id",
                "active_set",
            },
            event_type,
        )
        objective_id = _required_text(data["objective_id"], "objective_id")
        _required_text(data["joint_evidence_id"], "joint_evidence_id")
        expected = _optional_text(
            data["expected_current_active_set_id"], "expected_current_active_set_id"
        )
        if expected != projection.current_active_set_id:
            raise RoleRegistryError("commit expected current active set does not match")
        raw_selection = data["candidate_ids"]
        if not isinstance(raw_selection, Mapping):
            raise RoleRegistryError("candidate_ids must be a mapping")
        selected: dict[Role, str] = {}
        for raw_role, candidate_id in raw_selection.items():
            if not isinstance(raw_role, str):
                raise RoleRegistryError("candidate_ids keys must be role names")
            try:
                role = Role(raw_role)
            except ValueError as exc:
                raise RoleRegistryError("candidate_ids contains an invalid role") from exc
            selected[role] = _required_text(candidate_id, f"{role.value}_candidate_id")
        selected = cls._normalize_selection(selected)
        for role, candidate_id in selected.items():
            record = projection.candidates.get(candidate_id)
            if (
                record is None
                or record.identity.role is not role
                or record.state is not RoleCandidateState.QUALIFIED
                or record.objective_id != objective_id
            ):
                raise RoleRegistryError("commit contains an ineligible role candidate")
        computed = cls._build_active_set(projection, selected, objective_id)
        stored = ActiveRoleSet.from_mapping(data["active_set"])
        if stored != computed:
            raise RoleRegistryError("committed active set does not match selected candidates")
        return cls._activate(projection, computed, selected, expected)

    @staticmethod
    def _activate(
        projection: RoleRegistryProjection,
        active_set: ActiveRoleSet,
        selected: Mapping[Role, str],
        parent_id: str | None,
    ) -> RoleRegistryProjection:
        candidates = dict(projection.candidates)
        current = projection.current_active_set
        for role, candidate_id in selected.items():
            if current is not None:
                previous_id = current.for_role(role).role_version_id
                if previous_id != candidate_id:
                    candidates[previous_id] = replace(
                        candidates[previous_id], state=RoleCandidateState.SUPERSEDED
                    )
            candidates[candidate_id] = replace(
                candidates[candidate_id], state=RoleCandidateState.ACTIVE
            )
        active_sets = dict(projection.active_sets)
        parents = dict(projection.active_set_parents)
        active_sets[active_set.active_role_set_id] = active_set
        parents[active_set.active_role_set_id] = parent_id
        return replace(
            projection,
            candidates=candidates,
            active_sets=active_sets,
            active_set_parents=parents,
            current_active_set_id=active_set.active_role_set_id,
        )

    @staticmethod
    def _apply_rollback(
        projection: RoleRegistryProjection, payload: object, event_type: str
    ) -> RoleRegistryProjection:
        data = _strict_payload(
            payload,
            {
                "schema_version",
                "expected_current_active_set_id",
                "target_active_set_id",
                "joint_evidence_id",
                "reason",
            },
            event_type,
        )
        expected = _required_text(
            data["expected_current_active_set_id"], "expected_current_active_set_id"
        )
        target_id = _required_text(data["target_active_set_id"], "target_active_set_id")
        _required_text(data["joint_evidence_id"], "joint_evidence_id")
        _required_text(data["reason"], "reason")
        current = projection.current_active_set
        target = projection.active_sets.get(target_id)
        if current is None or current.active_role_set_id != expected:
            raise RoleRegistryError("rollback expected current active set does not match")
        if target is None or target.active_role_set_id == current.active_role_set_id:
            raise RoleRegistryError("rollback target is not a prior active set")
        if target.objective_id != current.objective_id:
            raise RoleRegistryError("rollback cannot cross an objective boundary")
        candidates = dict(projection.candidates)
        for role in Role:
            current_id = current.for_role(role).role_version_id
            target_candidate_id = target.for_role(role).role_version_id
            if current_id != target_candidate_id:
                candidates[current_id] = replace(
                    candidates[current_id], state=RoleCandidateState.REVOKED
                )
                candidates[target_candidate_id] = replace(
                    candidates[target_candidate_id], state=RoleCandidateState.ACTIVE
                )
        return replace(
            projection,
            candidates=candidates,
            current_active_set_id=target.active_role_set_id,
        )

    @staticmethod
    def _apply_objective_rebind(
        projection: RoleRegistryProjection, payload: object, event_type: str
    ) -> RoleRegistryProjection:
        data = _strict_payload(
            payload,
            {"schema_version", "objective_id", "evidence_id", "expected_current_active_set_id", "active_set"},
            event_type,
        )
        objective_id = _required_text(data["objective_id"], "objective_id")
        _required_text(data["evidence_id"], "evidence_id")
        expected = _required_text(
            data["expected_current_active_set_id"], "expected_current_active_set_id"
        )
        current = projection.current_active_set
        if current is None or current.active_role_set_id != expected:
            raise RoleRegistryError("rebind expected current active set does not match")
        if current.objective_id == objective_id:
            raise RoleRegistryError("active role set is already bound to the objective")
        stored = ActiveRoleSet.from_mapping(data["active_set"])
        expected_set = ActiveRoleSet(
            revision=current.revision + 1,
            objective_id=objective_id,
            warrior=current.warrior,
            judge=current.judge,
            prosecutor=current.prosecutor,
        )
        if stored != expected_set:
            raise RoleRegistryError("rebound active set changes role versions or revision")
        active_sets = dict(projection.active_sets)
        parents = dict(projection.active_set_parents)
        active_sets[stored.active_role_set_id] = stored
        parents[stored.active_role_set_id] = current.active_role_set_id
        return replace(
            projection,
            active_sets=active_sets,
            active_set_parents=parents,
            current_active_set_id=stored.active_role_set_id,
        )
