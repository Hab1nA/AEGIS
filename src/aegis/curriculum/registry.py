"""Append-only registry and replay projection for AEGIS v2 curriculum state."""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Mapping

from aegis.event_store import EventStore
from aegis.models import AuditEvent, thaw_json

from .models import SCHEMA_VERSION, Constitution, CurriculumSnapshot, ObjectiveVersion
from .state_machine import CycleState, CycleStateMachine

CONSTITUTION_RECORDED_V2 = "constitution_recorded_v2"
OBJECTIVE_PROVISIONAL_V2 = "objective_provisional_v2"
OBJECTIVE_PROBATION_STARTED_V2 = "objective_probation_started_v2"
OBJECTIVE_ACTIVATED_V2 = "objective_activated_v2"
OBJECTIVE_ROLLED_BACK_V2 = "objective_rolled_back_v2"
CURRICULUM_SNAPSHOT_RECORDED_V2 = "curriculum_snapshot_recorded_v2"
CYCLE_STATE_CHANGED_V2 = "cycle_state_changed_v2"

_CONTENT_ADDRESS = re.compile(r"(?:[a-z0-9-]+-)?sha256:[0-9a-f]{64}\Z")
_EVIDENCE_ACTIONS = frozenset(
    {
        "lock_cohort",
        "collect_solutions",
        "freeze_submission",
        "record_judge_review",
        "lock_quality",
        "record_prosecutor_audit",
        "record_independent_reflections",
        "complete_council",
        "complete_task_forge",
        "complete_task_validation",
        "lock_attribution",
        "qualify_role_candidates",
        "commit_activation_set",
        "complete",
    }
)

_KNOWN_EVENTS = frozenset(
    {
        CONSTITUTION_RECORDED_V2,
        OBJECTIVE_PROVISIONAL_V2,
        OBJECTIVE_PROBATION_STARTED_V2,
        OBJECTIVE_ACTIVATED_V2,
        OBJECTIVE_ROLLED_BACK_V2,
        CURRICULUM_SNAPSHOT_RECORDED_V2,
        CYCLE_STATE_CHANGED_V2,
    }
)


class CurriculumRegistryError(RuntimeError):
    """Raised when a curriculum command or persisted v2 event violates its contract."""


class ObjectiveStatus(StrEnum):
    PROVISIONAL = "provisional"
    PROBATION = "probation"
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    ROLLED_BACK = "rolled_back"


def _required_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise CurriculumRegistryError(f"{name} must be non-empty text without surrounding whitespace")
    return value


def _strict_payload(value: object, expected: set[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise CurriculumRegistryError(f"{name} must be a string-keyed mapping")
    if set(value) != expected:
        raise CurriculumRegistryError(f"{name} has missing or unknown fields")
    if type(value["schema_version"]) is not int or value["schema_version"] != SCHEMA_VERSION:
        raise CurriculumRegistryError(f"{name}.schema_version must be {SCHEMA_VERSION}")
    return value


def _optional_text(value: object, name: str) -> str | None:
    if value is None:
        return None
    return _required_text(value, name)


def _optional_evidence_id(value: object) -> str | None:
    if value is None:
        return None
    text = _required_text(value, "evidence_id")
    if _CONTENT_ADDRESS.fullmatch(text) is None:
        raise CurriculumRegistryError("evidence_id must be a content address")
    return text


def _enum_value(enum_type: type[ObjectiveStatus], value: object, name: str) -> ObjectiveStatus:
    if not isinstance(value, str):
        raise CurriculumRegistryError(f"{name} has an invalid value")
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise CurriculumRegistryError(f"{name} has an invalid value") from exc


def _cycle_state(value: object, name: str) -> CycleState:
    if not isinstance(value, str):
        raise CurriculumRegistryError(f"{name} has an invalid value")
    try:
        return CycleState(value)
    except (TypeError, ValueError) as exc:
        raise CurriculumRegistryError(f"{name} has an invalid value") from exc


@dataclass(frozen=True, slots=True)
class CycleProjection:
    """Immutable state reconstructed exclusively from one campaign event stream."""

    campaign_id: str
    sequence: int = 0
    constitutions: Mapping[str, Constitution] = field(default_factory=dict)
    objectives: Mapping[str, ObjectiveVersion] = field(default_factory=dict)
    objective_statuses: Mapping[str, ObjectiveStatus] = field(default_factory=dict)
    snapshots: Mapping[str, CurriculumSnapshot] = field(default_factory=dict)
    active_objective_id: str | None = None
    probation_objective_id: str | None = None
    current_snapshot_id: str | None = None
    cycle_state: CycleState = CycleState.CREATED
    resume_target: CycleState | None = None

    def __post_init__(self) -> None:
        _required_text(self.campaign_id, "campaign_id")
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int) or self.sequence < 0:
            raise CurriculumRegistryError("sequence must be a non-negative integer")
        object.__setattr__(self, "constitutions", MappingProxyType(dict(self.constitutions)))
        object.__setattr__(self, "objectives", MappingProxyType(dict(self.objectives)))
        object.__setattr__(self, "objective_statuses", MappingProxyType(dict(self.objective_statuses)))
        object.__setattr__(self, "snapshots", MappingProxyType(dict(self.snapshots)))
        CycleStateMachine(self.cycle_state, resume_target=self.resume_target)

    @property
    def current_snapshot(self) -> CurriculumSnapshot | None:
        if self.current_snapshot_id is None:
            return None
        return self.snapshots[self.current_snapshot_id]


class CurriculumRegistry:
    """CAS-guarded command facade over an append-only curriculum event stream."""

    def __init__(self, store: EventStore, campaign_id: str) -> None:
        if not isinstance(store, EventStore):
            raise TypeError("store must be an EventStore")
        self._store = store
        self._campaign_id = _required_text(campaign_id, "campaign_id")
        self._projection = CycleProjection(campaign_id=self._campaign_id)
        self.refresh()

    @property
    def projection(self) -> CycleProjection:
        return self._projection

    def refresh(self) -> CycleProjection:
        projection = CycleProjection(campaign_id=self._campaign_id)
        for event in self._store.read(self._campaign_id):
            projection = self._apply_event(projection, event)
        self._projection = projection
        return projection

    def record_constitution(self, constitution: Constitution) -> CycleProjection:
        if not isinstance(constitution, Constitution):
            raise TypeError("constitution must be a Constitution")
        if constitution.constitution_id in self._projection.constitutions:
            raise CurriculumRegistryError("constitution is already registered")
        parent_id = constitution.parent_constitution_id
        if parent_id is not None:
            parent = self._projection.constitutions.get(parent_id)
            if parent is None:
                raise CurriculumRegistryError("constitution parent is not registered")
            if constitution.version != parent.version + 1:
                raise CurriculumRegistryError("constitution version must directly follow its parent")
        return self._append(
            CONSTITUTION_RECORDED_V2,
            {"schema_version": SCHEMA_VERSION, "constitution": constitution.to_mapping()},
        )

    def provision_objective(self, objective: ObjectiveVersion) -> CycleProjection:
        if not isinstance(objective, ObjectiveVersion):
            raise TypeError("objective must be an ObjectiveVersion")
        if objective.objective_id in self._projection.objectives:
            raise CurriculumRegistryError("objective is already registered")
        if objective.constitution_id not in self._projection.constitutions:
            raise CurriculumRegistryError("objective constitution is not registered")
        parent_id = objective.parent_objective_id
        if parent_id is not None:
            parent = self._projection.objectives.get(parent_id)
            if parent is None:
                raise CurriculumRegistryError("objective parent is not registered")
            if parent.constitution_id != objective.constitution_id:
                raise CurriculumRegistryError("objective lineage crosses a constitution boundary")
            if objective.version != parent.version + 1:
                raise CurriculumRegistryError("objective version must directly follow its parent")
        return self._append(
            OBJECTIVE_PROVISIONAL_V2,
            {
                "schema_version": SCHEMA_VERSION,
                "objective": objective.to_mapping(),
                "status": ObjectiveStatus.PROVISIONAL.value,
            },
        )

    def start_objective_probation(self, objective_id: str) -> CycleProjection:
        objective_id = _required_text(objective_id, "objective_id")
        self._require_status(objective_id, ObjectiveStatus.PROVISIONAL)
        if self._projection.probation_objective_id is not None:
            raise CurriculumRegistryError("another objective is already in probation")
        return self._append(
            OBJECTIVE_PROBATION_STARTED_V2,
            {
                "schema_version": SCHEMA_VERSION,
                "objective_id": objective_id,
                "previous_status": ObjectiveStatus.PROVISIONAL.value,
                "status": ObjectiveStatus.PROBATION.value,
            },
        )

    def activate_objective(self, objective_id: str) -> CycleProjection:
        objective_id = _required_text(objective_id, "objective_id")
        self._require_status(objective_id, ObjectiveStatus.PROBATION)
        if self._projection.probation_objective_id != objective_id:
            raise CurriculumRegistryError("objective is not the registered probation candidate")
        return self._append(
            OBJECTIVE_ACTIVATED_V2,
            {
                "schema_version": SCHEMA_VERSION,
                "objective_id": objective_id,
                "previous_status": ObjectiveStatus.PROBATION.value,
                "status": ObjectiveStatus.ACTIVE.value,
                "previous_active_objective_id": self._projection.active_objective_id,
            },
        )

    def rollback_objective(
        self,
        objective_id: str,
        target_objective_id: str,
        *,
        reason: str,
    ) -> CycleProjection:
        objective_id = _required_text(objective_id, "objective_id")
        target_objective_id = _required_text(target_objective_id, "target_objective_id")
        reason = _required_text(reason, "reason")
        if objective_id == target_objective_id:
            raise CurriculumRegistryError("rollback source and target must differ")
        source_status = self._status(objective_id)
        if source_status not in {ObjectiveStatus.PROBATION, ObjectiveStatus.ACTIVE}:
            raise CurriculumRegistryError("only a probation or active objective can be rolled back")
        target_status = self._status(target_objective_id)
        source = self._projection.objectives[objective_id]
        target = self._projection.objectives[target_objective_id]
        if source.constitution_id != target.constitution_id:
            raise CurriculumRegistryError("rollback cannot cross a constitution boundary")
        if source_status is ObjectiveStatus.PROBATION:
            if target_status is not ObjectiveStatus.ACTIVE:
                raise CurriculumRegistryError("a probation rollback target must be active")
            if self._projection.probation_objective_id != objective_id:
                raise CurriculumRegistryError("objective is not the registered probation candidate")
        else:
            if self._projection.active_objective_id != objective_id:
                raise CurriculumRegistryError("objective is not the active objective")
            if target_status is not ObjectiveStatus.SUPERSEDED:
                raise CurriculumRegistryError("an active rollback target must be superseded")
        return self._append(
            OBJECTIVE_ROLLED_BACK_V2,
            {
                "schema_version": SCHEMA_VERSION,
                "objective_id": objective_id,
                "previous_status": source_status.value,
                "status": ObjectiveStatus.ROLLED_BACK.value,
                "target_objective_id": target_objective_id,
                "target_previous_status": target_status.value,
                "target_status": ObjectiveStatus.ACTIVE.value,
                "reason": reason,
            },
        )

    def record_snapshot(self, snapshot: CurriculumSnapshot) -> CycleProjection:
        if not isinstance(snapshot, CurriculumSnapshot):
            raise TypeError("snapshot must be a CurriculumSnapshot")
        if snapshot.snapshot_id in self._projection.snapshots:
            raise CurriculumRegistryError("curriculum snapshot is already registered")
        if snapshot.campaign_id != self._campaign_id:
            raise CurriculumRegistryError("snapshot belongs to a different campaign")
        constitution = self._projection.constitutions.get(snapshot.constitution.constitution_id)
        if constitution != snapshot.constitution:
            raise CurriculumRegistryError("snapshot constitution is not registered")
        objective = self._projection.objectives.get(snapshot.objective.objective_id)
        if objective != snapshot.objective:
            raise CurriculumRegistryError("snapshot objective is not registered")
        if self._projection.active_objective_id != snapshot.objective.objective_id:
            raise CurriculumRegistryError("snapshot objective is not active")
        previous = self._projection.current_snapshot
        if previous is None:
            if snapshot.cycle_number != 1 or snapshot.parent_snapshot_id is not None:
                raise CurriculumRegistryError("the first registered snapshot must be cycle 1")
            if self._projection.cycle_state is not CycleState.CREATED:
                raise CurriculumRegistryError("first snapshot requires a created cycle")
        else:
            if self._projection.cycle_state is not CycleState.COMPLETED:
                raise CurriculumRegistryError("the previous cycle must complete before a new snapshot")
            if snapshot.cycle_number != previous.cycle_number + 1:
                raise CurriculumRegistryError("snapshot cycle number must increment by one")
            if snapshot.parent_snapshot_id != previous.snapshot_id:
                raise CurriculumRegistryError("snapshot must directly follow the current snapshot")
        return self._append(
            CURRICULUM_SNAPSHOT_RECORDED_V2,
            {
                "schema_version": SCHEMA_VERSION,
                "snapshot": snapshot.to_mapping(),
                "previous_cycle_state": self._projection.cycle_state.value,
                "cycle_state": CycleState.CREATED.value,
            },
        )

    def transition_cycle(
        self,
        action: str,
        *,
        reason: str | None = None,
        evidence_id: str | None = None,
    ) -> CycleProjection:
        action = _required_text(action, "action")
        reason = _optional_text(reason, "reason")
        evidence_id = _optional_evidence_id(evidence_id)
        if action in {"fail", "abort", "stop"} and reason is None:
            raise CurriculumRegistryError(f"{action} requires a reason")
        if action in _EVIDENCE_ACTIONS and evidence_id is None:
            raise CurriculumRegistryError(f"{action} requires evidence_id")
        if action in {"lock_snapshot", "start", "advance"} and (
            self._projection.cycle_state is CycleState.CREATED
            and self._projection.current_snapshot_id is None
        ):
            raise CurriculumRegistryError("a curriculum snapshot must be recorded before the cycle starts")
        machine = CycleStateMachine(
            self._projection.cycle_state,
            resume_target=self._projection.resume_target,
        )
        previous = machine.state
        target = machine.apply(action)
        return self._append(
            CYCLE_STATE_CHANGED_V2,
            {
                "schema_version": SCHEMA_VERSION,
                "previous_state": previous.value,
                "action": action,
                "state": target.value,
                "resume_target": (
                    machine.resume_target.value if machine.resume_target is not None else None
                ),
                "reason": reason,
                "evidence_id": evidence_id,
            },
        )

    def _status(self, objective_id: str) -> ObjectiveStatus:
        try:
            return self._projection.objective_statuses[objective_id]
        except KeyError as exc:
            raise CurriculumRegistryError("objective is not registered") from exc

    def _require_status(self, objective_id: str, expected: ObjectiveStatus) -> None:
        if self._status(objective_id) is not expected:
            raise CurriculumRegistryError(f"objective must be {expected.value}")

    def _append(self, event_type: str, payload: Mapping[str, Any]) -> CycleProjection:
        event = self._store.append_if_sequence(
            self._campaign_id,
            self._projection.sequence,
            event_type,
            payload,
        )
        projection = self._apply_event(self._projection, event)
        self._projection = projection
        return projection

    def _apply_event(self, projection: CycleProjection, event: AuditEvent) -> CycleProjection:
        if event.campaign_id != projection.campaign_id:
            raise CurriculumRegistryError("event belongs to a different campaign")
        if event.sequence != projection.sequence + 1:
            raise CurriculumRegistryError("campaign event sequence is not contiguous")
        if event.event_type not in _KNOWN_EVENTS:
            return replace(projection, sequence=event.sequence)
        payload = thaw_json(event.payload)
        try:
            updated = self._apply_known_event(projection, event.event_type, payload)
        except CurriculumRegistryError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise CurriculumRegistryError(
                f"invalid {event.event_type} event at sequence {event.sequence}"
            ) from exc
        return replace(updated, sequence=event.sequence)

    def _apply_known_event(
        self,
        projection: CycleProjection,
        event_type: str,
        payload: object,
    ) -> CycleProjection:
        if event_type == CONSTITUTION_RECORDED_V2:
            data = _strict_payload(payload, {"schema_version", "constitution"}, event_type)
            constitution = Constitution.from_mapping(data["constitution"])
            self._validate_constitution_event(projection, constitution)
            items = dict(projection.constitutions)
            items[constitution.constitution_id] = constitution
            return replace(projection, constitutions=items)
        if event_type == OBJECTIVE_PROVISIONAL_V2:
            data = _strict_payload(
                payload, {"schema_version", "objective", "status"}, event_type
            )
            if _enum_value(ObjectiveStatus, data["status"], "status") is not ObjectiveStatus.PROVISIONAL:
                raise CurriculumRegistryError("new objectives must be provisional")
            objective = ObjectiveVersion.from_mapping(data["objective"])
            self._validate_objective_event(projection, objective)
            objectives = dict(projection.objectives)
            statuses = dict(projection.objective_statuses)
            objectives[objective.objective_id] = objective
            statuses[objective.objective_id] = ObjectiveStatus.PROVISIONAL
            return replace(projection, objectives=objectives, objective_statuses=statuses)
        if event_type == OBJECTIVE_PROBATION_STARTED_V2:
            return self._apply_probation_event(projection, payload, event_type)
        if event_type == OBJECTIVE_ACTIVATED_V2:
            return self._apply_activation_event(projection, payload, event_type)
        if event_type == OBJECTIVE_ROLLED_BACK_V2:
            return self._apply_rollback_event(projection, payload, event_type)
        if event_type == CURRICULUM_SNAPSHOT_RECORDED_V2:
            return self._apply_snapshot_event(projection, payload, event_type)
        if event_type == CYCLE_STATE_CHANGED_V2:
            return self._apply_cycle_event(projection, payload, event_type)
        raise AssertionError("unreachable")

    @staticmethod
    def _validate_constitution_event(
        projection: CycleProjection, constitution: Constitution
    ) -> None:
        if constitution.constitution_id in projection.constitutions:
            raise CurriculumRegistryError("constitution is already registered")
        if constitution.parent_constitution_id is not None:
            parent = projection.constitutions.get(constitution.parent_constitution_id)
            if parent is None or constitution.version != parent.version + 1:
                raise CurriculumRegistryError("invalid constitution lineage")

    @staticmethod
    def _validate_objective_event(
        projection: CycleProjection, objective: ObjectiveVersion
    ) -> None:
        if objective.objective_id in projection.objectives:
            raise CurriculumRegistryError("objective is already registered")
        if objective.constitution_id not in projection.constitutions:
            raise CurriculumRegistryError("objective constitution is not registered")
        if objective.parent_objective_id is not None:
            parent = projection.objectives.get(objective.parent_objective_id)
            if (
                parent is None
                or parent.constitution_id != objective.constitution_id
                or objective.version != parent.version + 1
            ):
                raise CurriculumRegistryError("invalid objective lineage")

    @staticmethod
    def _apply_probation_event(
        projection: CycleProjection, payload: object, event_type: str
    ) -> CycleProjection:
        data = _strict_payload(
            payload,
            {"schema_version", "objective_id", "previous_status", "status"},
            event_type,
        )
        objective_id = _required_text(data["objective_id"], "objective_id")
        if projection.probation_objective_id is not None:
            raise CurriculumRegistryError("another objective is already in probation")
        if projection.objective_statuses.get(objective_id) is not ObjectiveStatus.PROVISIONAL:
            raise CurriculumRegistryError("probation objective must be provisional")
        if (
            _enum_value(ObjectiveStatus, data["previous_status"], "previous_status")
            is not ObjectiveStatus.PROVISIONAL
            or _enum_value(ObjectiveStatus, data["status"], "status")
            is not ObjectiveStatus.PROBATION
        ):
            raise CurriculumRegistryError("invalid probation status transition")
        statuses = dict(projection.objective_statuses)
        statuses[objective_id] = ObjectiveStatus.PROBATION
        return replace(
            projection,
            objective_statuses=statuses,
            probation_objective_id=objective_id,
        )

    @staticmethod
    def _apply_activation_event(
        projection: CycleProjection, payload: object, event_type: str
    ) -> CycleProjection:
        data = _strict_payload(
            payload,
            {
                "schema_version",
                "objective_id",
                "previous_status",
                "status",
                "previous_active_objective_id",
            },
            event_type,
        )
        objective_id = _required_text(data["objective_id"], "objective_id")
        previous_active_id = _optional_text(
            data["previous_active_objective_id"], "previous_active_objective_id"
        )
        if projection.probation_objective_id != objective_id:
            raise CurriculumRegistryError("activation objective is not in probation")
        if projection.objective_statuses.get(objective_id) is not ObjectiveStatus.PROBATION:
            raise CurriculumRegistryError("activation objective must be in probation")
        if previous_active_id != projection.active_objective_id:
            raise CurriculumRegistryError("activation previous active objective does not match")
        if (
            _enum_value(ObjectiveStatus, data["previous_status"], "previous_status")
            is not ObjectiveStatus.PROBATION
            or _enum_value(ObjectiveStatus, data["status"], "status")
            is not ObjectiveStatus.ACTIVE
        ):
            raise CurriculumRegistryError("invalid activation status transition")
        statuses = dict(projection.objective_statuses)
        statuses[objective_id] = ObjectiveStatus.ACTIVE
        if previous_active_id is not None:
            if statuses.get(previous_active_id) is not ObjectiveStatus.ACTIVE:
                raise CurriculumRegistryError("previous active objective is not active")
            statuses[previous_active_id] = ObjectiveStatus.SUPERSEDED
        return replace(
            projection,
            objective_statuses=statuses,
            active_objective_id=objective_id,
            probation_objective_id=None,
        )

    @staticmethod
    def _apply_rollback_event(
        projection: CycleProjection, payload: object, event_type: str
    ) -> CycleProjection:
        data = _strict_payload(
            payload,
            {
                "schema_version",
                "objective_id",
                "previous_status",
                "status",
                "target_objective_id",
                "target_previous_status",
                "target_status",
                "reason",
            },
            event_type,
        )
        objective_id = _required_text(data["objective_id"], "objective_id")
        target_id = _required_text(data["target_objective_id"], "target_objective_id")
        _required_text(data["reason"], "reason")
        source_status = _enum_value(ObjectiveStatus, data["previous_status"], "previous_status")
        target_status = _enum_value(
            ObjectiveStatus, data["target_previous_status"], "target_previous_status"
        )
        if source_status not in {ObjectiveStatus.PROBATION, ObjectiveStatus.ACTIVE}:
            raise CurriculumRegistryError("invalid rollback source status")
        if projection.objective_statuses.get(objective_id) is not source_status:
            raise CurriculumRegistryError("rollback source status does not match")
        if projection.objective_statuses.get(target_id) is not target_status:
            raise CurriculumRegistryError("rollback target status does not match")
        if (
            _enum_value(ObjectiveStatus, data["status"], "status")
            is not ObjectiveStatus.ROLLED_BACK
            or _enum_value(ObjectiveStatus, data["target_status"], "target_status")
            is not ObjectiveStatus.ACTIVE
        ):
            raise CurriculumRegistryError("invalid rollback target statuses")
        source = projection.objectives.get(objective_id)
        target = projection.objectives.get(target_id)
        if source is None or target is None or source.constitution_id != target.constitution_id:
            raise CurriculumRegistryError("rollback crosses an invalid objective boundary")
        if source_status is ObjectiveStatus.PROBATION:
            if projection.probation_objective_id != objective_id:
                raise CurriculumRegistryError("rollback source is not in probation")
            if target_status is not ObjectiveStatus.ACTIVE or projection.active_objective_id != target_id:
                raise CurriculumRegistryError("probation rollback target is not active")
        else:
            if projection.active_objective_id != objective_id:
                raise CurriculumRegistryError("rollback source is not active")
            if target_status is not ObjectiveStatus.SUPERSEDED:
                raise CurriculumRegistryError("active rollback target is not superseded")
        statuses = dict(projection.objective_statuses)
        statuses[objective_id] = ObjectiveStatus.ROLLED_BACK
        statuses[target_id] = ObjectiveStatus.ACTIVE
        return replace(
            projection,
            objective_statuses=statuses,
            active_objective_id=target_id,
            probation_objective_id=None,
        )

    @staticmethod
    def _apply_snapshot_event(
        projection: CycleProjection, payload: object, event_type: str
    ) -> CycleProjection:
        data = _strict_payload(
            payload,
            {"schema_version", "snapshot", "previous_cycle_state", "cycle_state"},
            event_type,
        )
        snapshot = CurriculumSnapshot.from_mapping(data["snapshot"])
        previous_state = _cycle_state(data["previous_cycle_state"], "previous_cycle_state")
        target_state = _cycle_state(data["cycle_state"], "cycle_state")
        if previous_state is not projection.cycle_state or target_state is not CycleState.CREATED:
            raise CurriculumRegistryError("snapshot cycle state checkpoint does not match")
        if snapshot.campaign_id != projection.campaign_id:
            raise CurriculumRegistryError("snapshot belongs to a different campaign")
        if snapshot.snapshot_id in projection.snapshots:
            raise CurriculumRegistryError("curriculum snapshot is already registered")
        if projection.constitutions.get(snapshot.constitution.constitution_id) != snapshot.constitution:
            raise CurriculumRegistryError("snapshot constitution is not registered")
        if projection.objectives.get(snapshot.objective.objective_id) != snapshot.objective:
            raise CurriculumRegistryError("snapshot objective is not registered")
        if projection.active_objective_id != snapshot.objective.objective_id:
            raise CurriculumRegistryError("snapshot objective is not active")
        previous = projection.current_snapshot
        if previous is None:
            if snapshot.cycle_number != 1 or previous_state is not CycleState.CREATED:
                raise CurriculumRegistryError("invalid first curriculum snapshot")
        elif (
            previous_state is not CycleState.COMPLETED
            or snapshot.cycle_number != previous.cycle_number + 1
            or snapshot.parent_snapshot_id != previous.snapshot_id
        ):
            raise CurriculumRegistryError("invalid curriculum snapshot lineage")
        snapshots = dict(projection.snapshots)
        snapshots[snapshot.snapshot_id] = snapshot
        return replace(
            projection,
            snapshots=snapshots,
            current_snapshot_id=snapshot.snapshot_id,
            cycle_state=CycleState.CREATED,
            resume_target=None,
        )

    @staticmethod
    def _apply_cycle_event(
        projection: CycleProjection, payload: object, event_type: str
    ) -> CycleProjection:
        data = _strict_payload(
            payload,
            {
                "schema_version",
                "previous_state",
                "action",
                "state",
                "resume_target",
                "reason",
                "evidence_id",
            },
            event_type,
        )
        previous = _cycle_state(data["previous_state"], "previous_state")
        if previous is not projection.cycle_state:
            raise CurriculumRegistryError("cycle event previous state does not match")
        action = _required_text(data["action"], "action")
        reason = _optional_text(data["reason"], "reason")
        evidence_id = _optional_evidence_id(data["evidence_id"])
        if action in {"fail", "abort", "stop"} and reason is None:
            raise CurriculumRegistryError(f"{action} event requires a reason")
        if action in _EVIDENCE_ACTIONS and evidence_id is None:
            raise CurriculumRegistryError(f"{action} event requires evidence_id")
        if action in {"lock_snapshot", "start", "advance"} and (
            previous is CycleState.CREATED and projection.current_snapshot_id is None
        ):
            raise CurriculumRegistryError("cycle cannot start without a curriculum snapshot")
        machine = CycleStateMachine(previous, resume_target=projection.resume_target)
        target = machine.apply(action)
        stored_target = _cycle_state(data["state"], "state")
        stored_resume = data["resume_target"]
        resume_target = (
            None if stored_resume is None else _cycle_state(stored_resume, "resume_target")
        )
        if stored_target is not target or resume_target is not machine.resume_target:
            raise CurriculumRegistryError("cycle event transition result does not match")
        return replace(
            projection,
            cycle_state=target,
            resume_target=machine.resume_target,
        )
