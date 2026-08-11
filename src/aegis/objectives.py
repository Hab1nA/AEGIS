"""Immutable human-core objectives and autonomous adaptive governance.

The registry in this module deliberately owns only objective governance.  A
campaign records one operator-authored core at genesis; autonomous roles may
then propose refinements, but cannot replace or weaken that core.  All durable
state is reconstructed from one campaign's append-only event stream and every
domain record is independently persisted in the content-addressed store.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any, ClassVar, Mapping

from aegis.artifacts import ArtifactRef, ArtifactStoreError, ContentAddressedArtifactStore
from aegis.event_store import EventStore
from aegis.models import AuditEvent, Role, canonical_json, thaw_json

SCHEMA_VERSION = 1

CORE_RECORDED = "human_core_objective_recorded_v1"
ADAPTIVE_GENESIS_RECORDED = "adaptive_objective_genesis_recorded_v1"
AMENDMENT_PROPOSED = "adaptive_objective_amendment_proposed_v1"
SHADOW_RECORDED = "adaptive_objective_shadow_recorded_v1"
AMENDMENT_DECIDED = "adaptive_objective_amendment_decided_v1"
PROBATION_STARTED = "adaptive_objective_probation_started_v1"
PROBATION_OBSERVED = "adaptive_objective_probation_observed_v1"

_KNOWN_EVENTS = frozenset(
    {
        CORE_RECORDED,
        ADAPTIVE_GENESIS_RECORDED,
        AMENDMENT_PROPOSED,
        SHADOW_RECORDED,
        AMENDMENT_DECIDED,
        PROBATION_STARTED,
        PROBATION_OBSERVED,
    }
)
_SHA256 = "sha256:"
_ANY_CONTENT_ADDRESS = re.compile(r"(?:[a-z][a-z0-9-]*-)?sha256:[0-9a-f]{64}\Z")


class ObjectiveGovernanceError(RuntimeError):
    """A command or persisted governance event violated the objective contract."""


class ObjectiveStatus(StrEnum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    PROBATION = "probation"
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    ROLLED_BACK = "rolled_back"


class AmendmentDecision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


def _required_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{name} must be non-empty text without surrounding whitespace")
    if any(ord(character) < 32 for character in value):
        raise ValueError(f"{name} must not contain control characters")
    return value


def _positive_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


def _content_address(value: object, name: str, *, prefix: str = _SHA256) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a {prefix} content address")
    if prefix == _SHA256:
        if _ANY_CONTENT_ADDRESS.fullmatch(value) is None:
            raise ValueError(f"{name} must be a sha256 content address")
        digest = value.rsplit(":", 1)[1]
    elif value.startswith(prefix):
        digest = value.removeprefix(prefix)
    else:
        raise ValueError(f"{name} must be a {prefix} content address")
    if len(digest) != 64 or digest.lower() != digest:
        raise ValueError(f"{name} must be a {prefix} content address")
    try:
        bytes.fromhex(digest)
    except ValueError as exc:
        raise ValueError(f"{name} must be a {prefix} content address") from exc
    return value


def _identity(prefix: str, payload: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    return f"{prefix}{digest}"


def _texts(value: object, name: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise TypeError(f"{name} must be a tuple")
    if not allow_empty and not value:
        raise ValueError(f"{name} must not be empty")
    for item in value:
        _required_text(item, f"{name}[]")
    if tuple(sorted(value)) != value or len(set(value)) != len(value):
        raise ValueError(f"{name} must be unique and in canonical order")
    return value


def _strict(value: object, fields: set[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{name} must be a string-keyed mapping")
    if set(value) != fields:
        raise ValueError(f"{name} has missing or unknown fields")
    if type(value["schema_version"]) is not int or value["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"{name}.schema_version must be {SCHEMA_VERSION}")
    return value


@dataclass(frozen=True, slots=True)
class EvaluatorCriterion:
    """A measurable lower bound owned by an immutable evaluator definition."""

    name: str
    evaluator_id: str
    minimum: float

    def __post_init__(self) -> None:
        _required_text(self.name, "name")
        _content_address(self.evaluator_id, "evaluator_id")
        if isinstance(self.minimum, bool) or not isinstance(self.minimum, (int, float)):
            raise TypeError("minimum must be numeric")
        minimum = float(self.minimum)
        if not math.isfinite(minimum):
            raise ValueError("minimum must be finite")
        object.__setattr__(self, "minimum", minimum)

    def to_mapping(self) -> Mapping[str, Any]:
        return {"name": self.name, "evaluator_id": self.evaluator_id, "minimum": self.minimum}

    @classmethod
    def from_mapping(cls, value: object) -> EvaluatorCriterion:
        if not isinstance(value, Mapping) or set(value) != {"name", "evaluator_id", "minimum"}:
            raise ValueError("criterion has missing or unknown fields")
        return cls(name=value["name"], evaluator_id=value["evaluator_id"], minimum=value["minimum"])


def _criteria(value: object) -> tuple[EvaluatorCriterion, ...]:
    if not isinstance(value, tuple) or not value:
        raise TypeError("criteria must be a non-empty tuple")
    if any(not isinstance(item, EvaluatorCriterion) for item in value):
        raise TypeError("criteria must contain EvaluatorCriterion values")
    names = tuple(item.name for item in value)
    if names != tuple(sorted(names)) or len(set(names)) != len(names):
        raise ValueError("criteria names must be unique and in canonical order")
    return value


@dataclass(frozen=True, slots=True)
class HumanCoreObjective:
    """Operator-owned campaign genesis that autonomous roles cannot mutate."""

    ID_PREFIX: ClassVar[str] = "human-core-objective-sha256:"

    statement: str
    criteria: tuple[EvaluatorCriterion, ...]
    forbidden_capabilities: tuple[str, ...]
    constitution_id: str
    core_objective_id: str = field(init=False)

    def __post_init__(self) -> None:
        _required_text(self.statement, "statement")
        _criteria(self.criteria)
        _texts(self.forbidden_capabilities, "forbidden_capabilities")
        _content_address(self.constitution_id, "constitution_id")
        object.__setattr__(self, "core_objective_id", _identity(self.ID_PREFIX, self._payload()))

    def _payload(self) -> Mapping[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "statement": self.statement,
            "criteria": [item.to_mapping() for item in self.criteria],
            "forbidden_capabilities": list(self.forbidden_capabilities),
            "constitution_id": self.constitution_id,
        }

    def to_mapping(self) -> Mapping[str, Any]:
        return {"core_objective_id": self.core_objective_id, **self._payload()}

    @classmethod
    def from_mapping(cls, value: object) -> HumanCoreObjective:
        data = _strict(
            value,
            {
                "schema_version",
                "core_objective_id",
                "statement",
                "criteria",
                "forbidden_capabilities",
                "constitution_id",
            },
            "human core objective",
        )
        raw_criteria = data["criteria"]
        if not isinstance(raw_criteria, (list, tuple)):
            raise ValueError("criteria must be an array")
        raw_forbidden = data["forbidden_capabilities"]
        if not isinstance(raw_forbidden, (list, tuple)):
            raise ValueError("forbidden_capabilities must be an array")
        result = cls(
            statement=data["statement"],
            criteria=tuple(EvaluatorCriterion.from_mapping(item) for item in raw_criteria),
            forbidden_capabilities=tuple(raw_forbidden),
            constitution_id=data["constitution_id"],
        )
        if result.core_objective_id != data["core_objective_id"]:
            raise ValueError("core_objective_id does not match canonical content")
        return result


@dataclass(frozen=True, slots=True)
class AdaptiveObjectiveVersion:
    """A complete, mechanically checkable refinement of a human core."""

    ID_PREFIX: ClassVar[str] = "adaptive-objective-sha256:"

    version: int
    core_objective_id: str
    refinement: str
    criteria: tuple[EvaluatorCriterion, ...]
    weights: Mapping[str, float]
    capability_tags: tuple[str, ...] = ()
    parent_objective_id: str | None = None
    objective_id: str = field(init=False)

    def __post_init__(self) -> None:
        _positive_int(self.version, "version")
        _content_address(self.core_objective_id, "core_objective_id", prefix=HumanCoreObjective.ID_PREFIX)
        _required_text(self.refinement, "refinement")
        criteria = _criteria(self.criteria)
        if not isinstance(self.weights, Mapping) or set(self.weights) != {item.name for item in criteria}:
            raise ValueError("weights must define exactly the objective criteria")
        normalized: dict[str, float] = {}
        for name in sorted(self.weights):
            raw = self.weights[name]
            if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                raise TypeError("weights must be numeric")
            weight = float(raw)
            if not math.isfinite(weight) or weight <= 0:
                raise ValueError("weights must be finite and positive")
            normalized[name] = weight
        object.__setattr__(self, "weights", MappingProxyType(normalized))
        _texts(self.capability_tags, "capability_tags", allow_empty=True)
        if self.version == 1:
            if self.parent_objective_id is not None:
                raise ValueError("version 1 adaptive objective must not have a parent")
        else:
            if self.parent_objective_id is None:
                raise ValueError("versioned adaptive objective requires a parent")
            _content_address(
                self.parent_objective_id,
                "parent_objective_id",
                prefix=self.ID_PREFIX,
            )
        object.__setattr__(self, "objective_id", _identity(self.ID_PREFIX, self._payload()))

    def _payload(self) -> Mapping[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "version": self.version,
            "core_objective_id": self.core_objective_id,
            "parent_objective_id": self.parent_objective_id,
            "refinement": self.refinement,
            "criteria": [item.to_mapping() for item in self.criteria],
            "weights": dict(self.weights),
            "capability_tags": list(self.capability_tags),
        }

    def to_mapping(self) -> Mapping[str, Any]:
        return {"objective_id": self.objective_id, **self._payload()}

    @classmethod
    def from_mapping(cls, value: object) -> AdaptiveObjectiveVersion:
        data = _strict(
            value,
            {
                "schema_version",
                "objective_id",
                "version",
                "core_objective_id",
                "parent_objective_id",
                "refinement",
                "criteria",
                "weights",
                "capability_tags",
            },
            "adaptive objective",
        )
        raw_criteria = data["criteria"]
        raw_tags = data["capability_tags"]
        if not isinstance(raw_criteria, (list, tuple)) or not isinstance(raw_tags, (list, tuple)):
            raise ValueError("criteria and capability_tags must be arrays")
        result = cls(
            version=data["version"],
            core_objective_id=data["core_objective_id"],
            parent_objective_id=data["parent_objective_id"],
            refinement=data["refinement"],
            criteria=tuple(EvaluatorCriterion.from_mapping(item) for item in raw_criteria),
            weights=data["weights"],
            capability_tags=tuple(raw_tags),
        )
        if result.objective_id != data["objective_id"]:
            raise ValueError("objective_id does not match canonical content")
        return result


@dataclass(frozen=True, slots=True)
class ObjectiveAmendment:
    ID_PREFIX: ClassVar[str] = "objective-amendment-sha256:"

    objective: AdaptiveObjectiveVersion
    rationale: str
    council_reflection_ids: tuple[str, ...]
    critique_ids: tuple[str, ...]
    amendment_id: str = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.objective, AdaptiveObjectiveVersion):
            raise TypeError("objective must be an AdaptiveObjectiveVersion")
        _required_text(self.rationale, "rationale")
        _texts(self.council_reflection_ids, "council_reflection_ids")
        _texts(self.critique_ids, "critique_ids")
        for name, values in (
            ("council_reflection_ids", self.council_reflection_ids),
            ("critique_ids", self.critique_ids),
        ):
            for value in values:
                _content_address(value, f"{name}[]")
        object.__setattr__(self, "amendment_id", _identity(self.ID_PREFIX, self._payload()))

    def _payload(self) -> Mapping[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "objective": self.objective.to_mapping(),
            "rationale": self.rationale,
            "council_reflection_ids": list(self.council_reflection_ids),
            "critique_ids": list(self.critique_ids),
        }

    def to_mapping(self) -> Mapping[str, Any]:
        return {"amendment_id": self.amendment_id, **self._payload()}

    @classmethod
    def from_mapping(cls, value: object) -> ObjectiveAmendment:
        data = _strict(
            value,
            {
                "schema_version",
                "amendment_id",
                "objective",
                "rationale",
                "council_reflection_ids",
                "critique_ids",
            },
            "objective amendment",
        )
        reflections = data["council_reflection_ids"]
        critiques = data["critique_ids"]
        if not isinstance(reflections, (list, tuple)) or not isinstance(critiques, (list, tuple)):
            raise ValueError("reflection and critique ids must be arrays")
        result = cls(
            objective=AdaptiveObjectiveVersion.from_mapping(data["objective"]),
            rationale=data["rationale"],
            council_reflection_ids=tuple(reflections),
            critique_ids=tuple(critiques),
        )
        if result.amendment_id != data["amendment_id"]:
            raise ValueError("amendment_id does not match canonical content")
        return result


@dataclass(frozen=True, slots=True)
class ObjectiveEvidence:
    """Sealed shadow or probation evidence bound to one snapshot and objective."""

    ID_PREFIX: ClassVar[str] = "objective-evidence-sha256:"

    objective_id: str
    snapshot_id: str
    cycle_number: int
    quality_passed: bool
    integrity_passed: bool
    regression_detected: bool
    source_evidence_id: str
    evidence_id: str = field(init=False)

    def __post_init__(self) -> None:
        _content_address(self.objective_id, "objective_id", prefix=AdaptiveObjectiveVersion.ID_PREFIX)
        _content_address(self.snapshot_id, "snapshot_id")
        _positive_int(self.cycle_number, "cycle_number")
        for name in ("quality_passed", "integrity_passed", "regression_detected"):
            if not isinstance(getattr(self, name), bool):
                raise TypeError(f"{name} must be a bool")
        _content_address(self.source_evidence_id, "source_evidence_id")
        object.__setattr__(self, "evidence_id", _identity(self.ID_PREFIX, self._payload()))

    @property
    def passed(self) -> bool:
        return self.quality_passed and self.integrity_passed and not self.regression_detected

    def _payload(self) -> Mapping[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "objective_id": self.objective_id,
            "snapshot_id": self.snapshot_id,
            "cycle_number": self.cycle_number,
            "quality_passed": self.quality_passed,
            "integrity_passed": self.integrity_passed,
            "regression_detected": self.regression_detected,
            "source_evidence_id": self.source_evidence_id,
        }

    def to_mapping(self) -> Mapping[str, Any]:
        return {"evidence_id": self.evidence_id, **self._payload()}

    @classmethod
    def from_mapping(cls, value: object) -> ObjectiveEvidence:
        data = _strict(
            value,
            {
                "schema_version",
                "evidence_id",
                "objective_id",
                "snapshot_id",
                "cycle_number",
                "quality_passed",
                "integrity_passed",
                "regression_detected",
                "source_evidence_id",
            },
            "objective evidence",
        )
        result = cls(
            objective_id=data["objective_id"],
            snapshot_id=data["snapshot_id"],
            cycle_number=data["cycle_number"],
            quality_passed=data["quality_passed"],
            integrity_passed=data["integrity_passed"],
            regression_detected=data["regression_detected"],
            source_evidence_id=data["source_evidence_id"],
        )
        if result.evidence_id != data["evidence_id"]:
            raise ValueError("evidence_id does not match canonical content")
        return result


@dataclass(frozen=True, slots=True)
class ImportRecordResult:
    line_number: int
    status: str
    reason: str


@dataclass(frozen=True, slots=True)
class LegacyImportReport:
    records: tuple[ImportRecordResult, ...]

    @property
    def accepted(self) -> int:
        return sum(item.status == "accepted" for item in self.records)

    @property
    def skipped(self) -> int:
        return sum(item.status == "skipped" for item in self.records)

    @property
    def rejected(self) -> int:
        return sum(item.status == "rejected" for item in self.records)


@dataclass(frozen=True, slots=True)
class ObjectiveProjection:
    campaign_id: str
    sequence: int = 0
    core: HumanCoreObjective | None = None
    amendments: Mapping[str, ObjectiveAmendment] = field(default_factory=dict)
    statuses: Mapping[str, ObjectiveStatus] = field(default_factory=dict)
    shadow_evidence: Mapping[str, tuple[ObjectiveEvidence, ...]] = field(default_factory=dict)
    approved_effective_cycles: Mapping[str, int] = field(default_factory=dict)
    active_objective_id: str | None = None
    probation_objective_id: str | None = None
    probation_parent_id: str | None = None
    probation_effective_cycle: int | None = None
    probation_started_cycle: int | None = None
    probation_observations: tuple[ObjectiveEvidence, ...] = ()

    def __post_init__(self) -> None:
        _required_text(self.campaign_id, "campaign_id")
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int) or self.sequence < 0:
            raise ObjectiveGovernanceError("sequence must be a non-negative integer")
        object.__setattr__(self, "amendments", MappingProxyType(dict(self.amendments)))
        object.__setattr__(self, "statuses", MappingProxyType(dict(self.statuses)))
        object.__setattr__(
            self,
            "approved_effective_cycles",
            MappingProxyType(dict(self.approved_effective_cycles)),
        )
        object.__setattr__(
            self,
            "shadow_evidence",
            MappingProxyType({key: tuple(value) for key, value in self.shadow_evidence.items()}),
        )

    @property
    def active_objective(self) -> AdaptiveObjectiveVersion | None:
        if self.active_objective_id is None:
            return None
        return self.amendments[self.active_objective_id].objective

    def effective_objective_id(self, cycle_number: int) -> str | None:
        _positive_int(cycle_number, "cycle_number")
        if (
            self.probation_objective_id is not None
            and self.probation_effective_cycle is not None
            and cycle_number >= self.probation_effective_cycle
        ):
            return self.probation_objective_id
        due = tuple(
            objective_id
            for objective_id, effective_cycle in self.approved_effective_cycles.items()
            if self.statuses.get(objective_id) is ObjectiveStatus.APPROVED
            and cycle_number >= effective_cycle
        )
        if len(due) == 1:
            return due[0]
        if len(due) > 1:
            raise ObjectiveGovernanceError("multiple approved objectives are effective")
        return self.active_objective_id


class ObjectiveGovernanceRegistry:
    """CAS-backed, append-only objective governance for exactly one campaign."""

    def __init__(
        self,
        store: EventStore,
        artifacts: ContentAddressedArtifactStore,
        campaign_id: str,
    ) -> None:
        if not isinstance(store, EventStore):
            raise TypeError("store must be an EventStore")
        if not isinstance(artifacts, ContentAddressedArtifactStore):
            raise TypeError("artifacts must be a ContentAddressedArtifactStore")
        self._store = store
        self._artifacts = artifacts
        self._campaign_id = _required_text(campaign_id, "campaign_id")
        self._projection = ObjectiveProjection(self._campaign_id)
        self.refresh()

    @property
    def projection(self) -> ObjectiveProjection:
        return self._projection

    def refresh(self) -> ObjectiveProjection:
        projection = ObjectiveProjection(self._campaign_id)
        for event in self._store.read(self._campaign_id):
            projection = self._apply_event(projection, event)
        self._projection = projection
        return projection

    def record_genesis(self, core: HumanCoreObjective) -> ObjectiveProjection:
        if not isinstance(core, HumanCoreObjective):
            raise TypeError("core must be a HumanCoreObjective")
        if self._projection.core is not None:
            if self._projection.core == core:
                return self._projection
            raise ObjectiveGovernanceError(
                "campaign genesis core is immutable; create a new campaign to change it"
            )
        ref = self._put("human-core-objective", core.to_mapping())
        return self._append(CORE_RECORDED, {"artifact": _ref_mapping(ref)})

    def record_adaptive_genesis(
        self, objective: AdaptiveObjectiveVersion
    ) -> ObjectiveProjection:
        if self._projection.core is None:
            raise ObjectiveGovernanceError("human core must be recorded first")
        if objective.version != 1 or objective.parent_objective_id is not None:
            raise ObjectiveGovernanceError("adaptive genesis must be an unparented version 1")
        if self._projection.active_objective_id is not None:
            existing = self._projection.active_objective
            if existing == objective:
                return self._projection
            raise ObjectiveGovernanceError("campaign adaptive genesis is immutable")
        self._validate_refinement(self._projection.core, objective)
        ref = self._put("adaptive-objective", objective.to_mapping())
        return self._append(ADAPTIVE_GENESIS_RECORDED, {"artifact": _ref_mapping(ref)})

    def propose_amendment(self, amendment: ObjectiveAmendment) -> ObjectiveProjection:
        if not isinstance(amendment, ObjectiveAmendment):
            raise TypeError("amendment must be an ObjectiveAmendment")
        core = self._projection.core
        if core is None:
            raise ObjectiveGovernanceError("campaign genesis must be recorded first")
        objective = amendment.objective
        existing = self._projection.amendments.get(objective.objective_id)
        if existing is not None:
            if existing == amendment:
                return self._projection
            raise ObjectiveGovernanceError("objective identity already belongs to another amendment")
        self._validate_refinement(core, objective)
        ref = self._put("objective-amendment", amendment.to_mapping())
        return self._append(AMENDMENT_PROPOSED, {"artifact": _ref_mapping(ref)})

    def record_shadow_evidence(self, evidence: ObjectiveEvidence) -> ObjectiveProjection:
        if not isinstance(evidence, ObjectiveEvidence):
            raise TypeError("evidence must be ObjectiveEvidence")
        self._require_status(evidence.objective_id, ObjectiveStatus.PROPOSED)
        existing = self._projection.shadow_evidence.get(evidence.objective_id, ())
        if any(item.evidence_id == evidence.evidence_id for item in existing):
            return self._projection
        if any(item.cycle_number == evidence.cycle_number for item in existing):
            raise ObjectiveGovernanceError("shadow evidence already exists for that cycle")
        ref = self._put("objective-evidence", evidence.to_mapping())
        return self._append(SHADOW_RECORDED, {"artifact": _ref_mapping(ref)})

    def decide_amendment(
        self,
        objective_id: str,
        *,
        actor: Role,
        decision: AmendmentDecision,
        current_cycle: int,
        reason: str,
    ) -> ObjectiveProjection:
        _content_address(objective_id, "objective_id", prefix=AdaptiveObjectiveVersion.ID_PREFIX)
        if actor is not Role.PROSECUTOR:
            raise ObjectiveGovernanceError("only prosecutor may approve or reject an amendment")
        if not isinstance(decision, AmendmentDecision):
            raise TypeError("decision must be an AmendmentDecision")
        _positive_int(current_cycle, "current_cycle")
        _required_text(reason, "reason")
        status = self._projection.statuses.get(objective_id)
        decided = {ObjectiveStatus.APPROVED, ObjectiveStatus.REJECTED}
        if status in decided:
            expected = ObjectiveStatus.APPROVED if decision is AmendmentDecision.APPROVE else ObjectiveStatus.REJECTED
            if status is expected:
                return self._projection
            raise ObjectiveGovernanceError("amendment already has the opposite final decision")
        self._require_status(objective_id, ObjectiveStatus.PROPOSED)
        if decision is AmendmentDecision.APPROVE:
            if any(
                status in {ObjectiveStatus.APPROVED, ObjectiveStatus.PROBATION}
                for candidate_id, status in self._projection.statuses.items()
                if candidate_id != objective_id
            ):
                raise ObjectiveGovernanceError("another objective is already approved or in probation")
            evidence = self._projection.shadow_evidence.get(objective_id, ())
            latest = tuple(sorted(evidence, key=lambda item: item.cycle_number)[-3:])
            if len(latest) != 3:
                raise ObjectiveGovernanceError("approval requires the latest three shadow snapshots")
            cycles = tuple(item.cycle_number for item in latest)
            if cycles != tuple(range(cycles[0], cycles[0] + 3)) or cycles[-1] > current_cycle:
                raise ObjectiveGovernanceError("shadow snapshots must be consecutive and historical")
            if len({item.snapshot_id for item in latest}) != 3:
                raise ObjectiveGovernanceError("shadow evidence must bind three distinct snapshots")
            if not all(item.passed for item in latest):
                raise ObjectiveGovernanceError("all latest three shadow snapshots must pass")
        return self._append(
            AMENDMENT_DECIDED,
            {
                "objective_id": objective_id,
                "actor": actor.value,
                "decision": decision.value,
                "reason": reason,
                "decided_cycle": current_cycle,
                "effective_cycle": current_cycle + 1 if decision is AmendmentDecision.APPROVE else None,
            },
        )

    def begin_cycle(self, cycle_number: int) -> ObjectiveProjection:
        """Make the one due approved objective effective under two-cycle probation."""
        _positive_int(cycle_number, "cycle_number")
        if self._projection.probation_objective_id is not None:
            return self._projection
        overdue = tuple(
            objective_id
            for objective_id, effective in self._projection.approved_effective_cycles.items()
            if self._projection.statuses.get(objective_id) is ObjectiveStatus.APPROVED
            and effective < cycle_number
        )
        if overdue:
            raise ObjectiveGovernanceError("approved objective missed its next-cycle activation boundary")
        due = [
            (objective_id, effective)
            for objective_id, effective in self._projection.approved_effective_cycles.items()
            if self._projection.statuses.get(objective_id) is ObjectiveStatus.APPROVED
            and effective == cycle_number
        ]
        if not due:
            return self._projection
        if len(due) != 1:
            raise ObjectiveGovernanceError("multiple approved objectives are due for probation")
        objective_id, effective_cycle = due[0]
        return self._append(
            PROBATION_STARTED,
            {
                "objective_id": objective_id,
                "parent_objective_id": self._projection.active_objective_id,
                "effective_cycle": effective_cycle,
                "started_cycle": cycle_number,
                "required_clean_cycles": 2,
            },
        )

    def observe_probation(self, evidence: ObjectiveEvidence) -> ObjectiveProjection:
        if not isinstance(evidence, ObjectiveEvidence):
            raise TypeError("evidence must be ObjectiveEvidence")
        duplicate = next(
            (
                item
                for item in self._projection.probation_observations
                if item.cycle_number == evidence.cycle_number
            ),
            None,
        )
        if duplicate is not None:
            if duplicate == evidence:
                return self._projection
            raise ObjectiveGovernanceError("probation evidence already exists for that cycle")
        self._require_status(evidence.objective_id, ObjectiveStatus.PROBATION)
        if evidence.objective_id != self._projection.probation_objective_id:
            raise ObjectiveGovernanceError("evidence does not target the probation objective")
        existing = self._projection.probation_observations
        if existing and evidence.cycle_number != existing[-1].cycle_number + 1:
            raise ObjectiveGovernanceError("probation observations must cover consecutive cycles")
        expected_cycle = self._projection.probation_started_cycle
        if expected_cycle is None:
            raise ObjectiveGovernanceError("probation start cycle is missing")
        expected_cycle += len(existing)
        if evidence.cycle_number != expected_cycle:
            raise ObjectiveGovernanceError("probation evidence does not bind the current probation cycle")
        ref = self._put("objective-evidence", evidence.to_mapping())
        clean_count = len(existing) + 1 if evidence.passed else 0
        outcome = "continue"
        if not evidence.passed:
            outcome = "rollback"
        elif clean_count == 2:
            outcome = "graduate"
        return self._append(
            PROBATION_OBSERVED,
            {
                "artifact": _ref_mapping(ref),
                "outcome": outcome,
                "rollback_objective_id": self._projection.probation_parent_id,
            },
        )

    def import_legacy_jsonl(self, path: Path) -> LegacyImportReport:
        """Import only CAS-verifiable shadow rows and explicitly account for every line.

        Accepted legacy rows have exactly ``campaign_id``, ``snapshot_id`` and
        ``artifact``.  The artifact must already exist in this campaign's CAS
        and contain an ObjectiveEvidence bound to both the row's snapshot and a
        currently proposed objective.  Malformed or foreign rows never mutate
        state and are returned as rejected; exact duplicates are returned as
        skipped.
        """
        if not isinstance(path, Path):
            raise TypeError("path must be a Path")
        results: list[ImportRecordResult] = []
        for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            try:
                value = json.loads(raw)
                if not isinstance(value, Mapping) or set(value) != {
                    "campaign_id",
                    "snapshot_id",
                    "artifact",
                }:
                    raise ValueError("legacy row has missing or unknown fields")
                if value["campaign_id"] != self._campaign_id:
                    raise ValueError("legacy row belongs to another campaign")
                snapshot_id = _content_address(value["snapshot_id"], "snapshot_id")
                ref = _ref_from_mapping(value["artifact"])
                evidence = ObjectiveEvidence.from_mapping(
                    json.loads(self._artifacts.get(ref).decode("utf-8"))
                )
                if evidence.snapshot_id != snapshot_id:
                    raise ValueError("legacy row snapshot does not match CAS evidence")
                before = self._projection.sequence
                self.record_shadow_evidence(evidence)
                if self._projection.sequence == before:
                    results.append(ImportRecordResult(line_number, "skipped", "exact duplicate"))
                else:
                    results.append(ImportRecordResult(line_number, "accepted", "verified and imported"))
            except (
                ArtifactStoreError,
                json.JSONDecodeError,
                UnicodeError,
                TypeError,
                ValueError,
                KeyError,
                ObjectiveGovernanceError,
            ) as exc:
                results.append(ImportRecordResult(line_number, "rejected", str(exc)))
        return LegacyImportReport(tuple(results))

    def _validate_refinement(
        self,
        core: HumanCoreObjective,
        objective: AdaptiveObjectiveVersion,
        amendments: Mapping[str, ObjectiveAmendment] | None = None,
        statuses: Mapping[str, ObjectiveStatus] | None = None,
    ) -> None:
        if objective.core_objective_id != core.core_objective_id:
            raise ObjectiveGovernanceError("adaptive objective is bound to another human core")
        amendment_source = self._projection.amendments if amendments is None else amendments
        status_source = self._projection.statuses if statuses is None else statuses
        baseline_criteria = {item.name: item for item in core.criteria}
        baseline_weights = {item.name: 0.0 for item in core.criteria}
        if objective.parent_objective_id is not None:
            parent = amendment_source.get(objective.parent_objective_id)
            if parent is None:
                raise ObjectiveGovernanceError("adaptive objective parent is not registered")
            if status_source.get(objective.parent_objective_id) is not ObjectiveStatus.ACTIVE:
                raise ObjectiveGovernanceError("adaptive objective parent must be the active objective")
            if objective.version != parent.objective.version + 1:
                raise ObjectiveGovernanceError("adaptive objective version must directly follow its parent")
            baseline_criteria = {item.name: item for item in parent.objective.criteria}
            baseline_weights = dict(parent.objective.weights)
        elif objective.version != 1:
            raise ObjectiveGovernanceError("first adaptive objective must have version 1")
        elif any(status is ObjectiveStatus.ACTIVE for status in status_source.values()):
            raise ObjectiveGovernanceError("a successor must refine the active adaptive objective")
        proposed = {item.name: item for item in objective.criteria}
        for name, baseline in baseline_criteria.items():
            candidate = proposed.get(name)
            if candidate is None:
                raise ObjectiveGovernanceError(f"adaptive objective removes required criterion {name!r}")
            if candidate.evaluator_id != baseline.evaluator_id:
                raise ObjectiveGovernanceError(f"adaptive objective changes evaluator for {name!r}")
            if candidate.minimum < baseline.minimum:
                raise ObjectiveGovernanceError(f"adaptive objective weakens criterion {name!r}")
            if objective.weights[name] < baseline_weights[name]:
                raise ObjectiveGovernanceError(f"adaptive objective reduces weight for {name!r}")

    def _require_status(self, objective_id: str, expected: ObjectiveStatus) -> None:
        if self._projection.statuses.get(objective_id) is not expected:
            raise ObjectiveGovernanceError(f"objective must have status {expected.value}")

    def _put(self, kind: str, value: Mapping[str, Any]) -> ArtifactRef:
        return self._artifacts.put_json(kind, value)

    def _append(self, event_type: str, payload: Mapping[str, Any]) -> ObjectiveProjection:
        event = self._store.append_if_sequence(
            self._campaign_id,
            self._projection.sequence,
            event_type,
            payload,
        )
        self._projection = self._apply_event(self._projection, event)
        return self._projection

    def _load(self, value: object, expected_kind: str) -> Mapping[str, Any]:
        ref = _ref_from_mapping(value)
        if ref.kind != expected_kind:
            raise ObjectiveGovernanceError(f"event artifact must have kind {expected_kind}")
        try:
            decoded = json.loads(self._artifacts.get(ref).decode("utf-8"))
        except (ArtifactStoreError, json.JSONDecodeError, UnicodeError, ValueError) as exc:
            raise ObjectiveGovernanceError("event artifact is not canonical JSON") from exc
        if not isinstance(decoded, Mapping):
            raise ObjectiveGovernanceError("event artifact must contain a mapping")
        return decoded

    def _apply_event(self, projection: ObjectiveProjection, event: AuditEvent) -> ObjectiveProjection:
        if event.event_type not in _KNOWN_EVENTS:
            return replace(projection, sequence=event.sequence)
        data = thaw_json(event.payload)
        if not isinstance(data, Mapping):
            raise ObjectiveGovernanceError("event payload must be a mapping")
        try:
            if event.event_type == CORE_RECORDED:
                core = HumanCoreObjective.from_mapping(
                    self._load(_only_artifact(data, event.event_type), "human-core-objective")
                )
                if projection.core is not None:
                    raise ObjectiveGovernanceError("campaign contains more than one genesis core")
                return replace(projection, sequence=event.sequence, core=core)

            if event.event_type == ADAPTIVE_GENESIS_RECORDED:
                objective = AdaptiveObjectiveVersion.from_mapping(
                    self._load(_only_artifact(data, event.event_type), "adaptive-objective")
                )
                if projection.core is None or projection.active_objective_id is not None:
                    raise ObjectiveGovernanceError("adaptive genesis is out of order or duplicated")
                self._validate_refinement(projection.core, objective)
                if objective.version != 1 or objective.parent_objective_id is not None:
                    raise ObjectiveGovernanceError("adaptive genesis lineage is invalid")
                amendment = ObjectiveAmendment(
                    objective,
                    "operator adaptive genesis",
                    (projection.core.core_objective_id,),
                    (projection.core.constitution_id,),
                )
                return replace(
                    projection,
                    sequence=event.sequence,
                    amendments={objective.objective_id: amendment},
                    statuses={objective.objective_id: ObjectiveStatus.ACTIVE},
                    active_objective_id=objective.objective_id,
                )

            if event.event_type == AMENDMENT_PROPOSED:
                amendment = ObjectiveAmendment.from_mapping(
                    self._load(_only_artifact(data, event.event_type), "objective-amendment")
                )
                if projection.core is None:
                    raise ObjectiveGovernanceError("amendment precedes campaign genesis")
                self._validate_refinement(
                    projection.core,
                    amendment.objective,
                    projection.amendments,
                    projection.statuses,
                )
                objective_id = amendment.objective.objective_id
                amendments = dict(projection.amendments)
                statuses = dict(projection.statuses)
                if objective_id in amendments:
                    raise ObjectiveGovernanceError("duplicate amendment event")
                amendments[objective_id] = amendment
                statuses[objective_id] = ObjectiveStatus.PROPOSED
                return replace(
                    projection,
                    sequence=event.sequence,
                    amendments=amendments,
                    statuses=statuses,
                )

            if event.event_type == SHADOW_RECORDED:
                evidence = ObjectiveEvidence.from_mapping(
                    self._load(_only_artifact(data, event.event_type), "objective-evidence")
                )
                if projection.statuses.get(evidence.objective_id) is not ObjectiveStatus.PROPOSED:
                    raise ObjectiveGovernanceError("shadow evidence targets a non-proposed objective")
                items = dict(projection.shadow_evidence)
                current = items.get(evidence.objective_id, ())
                if any(item.cycle_number == evidence.cycle_number for item in current):
                    raise ObjectiveGovernanceError("duplicate shadow evidence cycle")
                items[evidence.objective_id] = (*current, evidence)
                return replace(projection, sequence=event.sequence, shadow_evidence=items)

            if event.event_type == AMENDMENT_DECIDED:
                expected = {
                    "objective_id",
                    "actor",
                    "decision",
                    "reason",
                    "decided_cycle",
                    "effective_cycle",
                }
                if set(data) != expected or data["actor"] != Role.PROSECUTOR.value:
                    raise ObjectiveGovernanceError("invalid amendment decision event")
                objective_id = str(data["objective_id"])
                _content_address(
                    objective_id,
                    "objective_id",
                    prefix=AdaptiveObjectiveVersion.ID_PREFIX,
                )
                if projection.statuses.get(objective_id) is not ObjectiveStatus.PROPOSED:
                    raise ObjectiveGovernanceError("decision targets a non-proposed objective")
                decision = AmendmentDecision(data["decision"])
                decided_cycle = _positive_int(data["decided_cycle"], "decided_cycle")
                _required_text(data["reason"], "reason")
                effective = data["effective_cycle"]
                if decision is AmendmentDecision.APPROVE:
                    if effective != decided_cycle + 1:
                        raise ObjectiveGovernanceError("approved objective must become effective next cycle")
                    shadow_items = projection.shadow_evidence.get(objective_id, ())
                    latest = tuple(sorted(shadow_items, key=lambda item: item.cycle_number)[-3:])
                    cycles = tuple(item.cycle_number for item in latest)
                    if (
                        len(latest) != 3
                        or cycles != tuple(range(cycles[0], cycles[0] + 3))
                        or cycles[-1] > decided_cycle
                        or len({item.snapshot_id for item in latest}) != 3
                        or not all(item.passed for item in latest)
                    ):
                        raise ObjectiveGovernanceError("approved event lacks three clean shadow snapshots")
                elif effective is not None:
                    raise ObjectiveGovernanceError("rejected objective cannot have an effective cycle")
                statuses = dict(projection.statuses)
                effective_cycles = dict(projection.approved_effective_cycles)
                statuses[objective_id] = (
                    ObjectiveStatus.APPROVED
                    if decision is AmendmentDecision.APPROVE
                    else ObjectiveStatus.REJECTED
                )
                if decision is AmendmentDecision.APPROVE:
                    if any(
                        status in {ObjectiveStatus.APPROVED, ObjectiveStatus.PROBATION}
                        for candidate_id, status in projection.statuses.items()
                        if candidate_id != objective_id
                    ):
                        raise ObjectiveGovernanceError("decision overlaps another approved objective")
                    effective_cycles[objective_id] = decided_cycle + 1
                return replace(
                    projection,
                    sequence=event.sequence,
                    statuses=statuses,
                    approved_effective_cycles=effective_cycles,
                )

            if event.event_type == PROBATION_STARTED:
                expected = {
                    "objective_id",
                    "parent_objective_id",
                    "effective_cycle",
                    "started_cycle",
                    "required_clean_cycles",
                }
                if set(data) != expected or data["required_clean_cycles"] != 2:
                    raise ObjectiveGovernanceError("invalid probation start event")
                objective_id = str(data["objective_id"])
                if projection.statuses.get(objective_id) is not ObjectiveStatus.APPROVED:
                    raise ObjectiveGovernanceError("probation requires an approved objective")
                effective = _positive_int(data["effective_cycle"], "effective_cycle")
                started = _positive_int(data["started_cycle"], "started_cycle")
                if started != effective or projection.probation_objective_id is not None:
                    raise ObjectiveGovernanceError("invalid probation cycle or overlapping probation")
                if projection.approved_effective_cycles.get(objective_id) != effective:
                    raise ObjectiveGovernanceError("probation cycle does not match the approved boundary")
                if data["parent_objective_id"] != projection.active_objective_id:
                    raise ObjectiveGovernanceError("probation parent is not the active objective")
                statuses = dict(projection.statuses)
                statuses[objective_id] = ObjectiveStatus.PROBATION
                return replace(
                    projection,
                    sequence=event.sequence,
                    statuses=statuses,
                    probation_objective_id=objective_id,
                    probation_parent_id=data["parent_objective_id"],
                    probation_effective_cycle=effective,
                    probation_started_cycle=started,
                    probation_observations=(),
                )

            if event.event_type == PROBATION_OBSERVED:
                if set(data) != {"artifact", "outcome", "rollback_objective_id"}:
                    raise ObjectiveGovernanceError("invalid probation observation event")
                evidence = ObjectiveEvidence.from_mapping(
                    self._load(data["artifact"], "objective-evidence")
                )
                probation_id = projection.probation_objective_id
                if probation_id is None or evidence.objective_id != probation_id:
                    raise ObjectiveGovernanceError("probation evidence targets another objective")
                started_cycle = projection.probation_started_cycle
                if (
                    started_cycle is None
                    or evidence.cycle_number
                    != started_cycle + len(projection.probation_observations)
                ):
                    raise ObjectiveGovernanceError("probation evidence has an invalid cycle binding")
                observations = (*projection.probation_observations, evidence)
                outcome = data["outcome"]
                expected_outcome = (
                    "rollback" if not evidence.passed else "graduate" if len(observations) == 2 else "continue"
                )
                if outcome != expected_outcome:
                    raise ObjectiveGovernanceError("probation outcome does not match evidence")
                statuses = dict(projection.statuses)
                if outcome == "continue":
                    return replace(
                        projection,
                        sequence=event.sequence,
                        probation_observations=observations,
                    )
                statuses[probation_id] = (
                    ObjectiveStatus.ROLLED_BACK if outcome == "rollback" else ObjectiveStatus.ACTIVE
                )
                active = projection.active_objective_id
                if outcome == "graduate":
                    if active is not None:
                        statuses[active] = ObjectiveStatus.SUPERSEDED
                    active = probation_id
                elif data["rollback_objective_id"] != projection.probation_parent_id:
                    raise ObjectiveGovernanceError("rollback target does not match probation parent")
                return replace(
                    projection,
                    sequence=event.sequence,
                    statuses=statuses,
                    active_objective_id=active,
                    probation_objective_id=None,
                    probation_parent_id=None,
                    probation_effective_cycle=None,
                    probation_started_cycle=None,
                    probation_observations=observations,
                )
        except (TypeError, ValueError, KeyError) as exc:
            raise ObjectiveGovernanceError(f"invalid {event.event_type} event") from exc
        raise AssertionError("unreachable")


def _ref_mapping(ref: ArtifactRef) -> Mapping[str, Any]:
    return {"kind": ref.kind, "artifact_id": ref.artifact_id, "size_bytes": ref.size_bytes}


def _ref_from_mapping(value: object) -> ArtifactRef:
    if not isinstance(value, Mapping) or set(value) != {"kind", "artifact_id", "size_bytes"}:
        raise ValueError("artifact reference has missing or unknown fields")
    return ArtifactRef(kind=value["kind"], artifact_id=value["artifact_id"], size_bytes=value["size_bytes"])


def _only_artifact(data: Mapping[str, Any], event_type: str) -> object:
    if set(data) != {"artifact"}:
        raise ObjectiveGovernanceError(f"invalid {event_type} event")
    return data["artifact"]


__all__ = [
    "AdaptiveObjectiveVersion",
    "AmendmentDecision",
    "EvaluatorCriterion",
    "HumanCoreObjective",
    "ImportRecordResult",
    "LegacyImportReport",
    "ObjectiveAmendment",
    "ObjectiveEvidence",
    "ObjectiveGovernanceError",
    "ObjectiveGovernanceRegistry",
    "ObjectiveProjection",
    "ObjectiveStatus",
]
