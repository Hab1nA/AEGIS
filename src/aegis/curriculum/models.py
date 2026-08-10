"""Strict immutable identities for AEGIS v2 curriculum cycles.

Objectives are deliberately separated from the constitution.  An objective may
describe desired outcomes and success criteria, but it can only reference (and
never redefine) the constitution that owns safety-critical control boundaries.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, ClassVar, Mapping

from aegis.models import Role, canonical_json

SCHEMA_VERSION = 2
MANDATORY_PROTECTED_CONTROLS = (
    "budget_limits",
    "event_store",
    "promotion_policy",
    "sandbox_policy",
    "scoring_policy",
    "sealed_evaluation",
    "tool_permissions",
)


def _required_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{name} must be non-empty text without surrounding whitespace")
    if any(ord(character) < 32 for character in value):
        raise ValueError(f"{name} must not contain control characters")
    return value


def _positive_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value < 1:
        raise ValueError(f"{name} must be positive")
    return value


def _non_negative_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or value.lower() != value:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be hexadecimal") from exc
    return value


def _identity(value: object, name: str, prefix: str) -> str:
    if not isinstance(value, str) or not value.startswith(prefix):
        raise ValueError(f"{name} must start with {prefix!r}")
    _digest(value.removeprefix(prefix), name)
    return value


def _text_tuple(value: object, name: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise TypeError(f"{name} must be a tuple")
    if not allow_empty and not value:
        raise ValueError(f"{name} must not be empty")
    for item in value:
        _required_text(item, f"{name}[]")
    if len(set(value)) != len(value):
        raise ValueError(f"{name} must not contain duplicates")
    return value


def _lineage(version: int, parent_id: str | None, name: str, prefix: str) -> None:
    if version == 1:
        if parent_id is not None:
            raise ValueError(f"version 1 {name} must not have a parent")
        return
    if parent_id is None:
        raise ValueError(f"versioned {name} requires a parent identity")
    _identity(parent_id, f"parent_{name}_id", prefix)


def _content_id(prefix: str, payload: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    return f"{prefix}{digest}"


def _strict_mapping(value: object, expected: set[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise TypeError(f"{name} must be a string-keyed mapping")
    if set(value) != expected:
        raise ValueError(f"{name} has missing or unknown fields")
    if type(value["schema_version"]) is not int or value["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"{name}.schema_version must be {SCHEMA_VERSION}")
    return value


def _sequence_to_tuple(
    value: object, name: str, *, allow_empty: bool = False
) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise TypeError(f"{name} must be an array")
    return _text_tuple(tuple(value), name, allow_empty=allow_empty)


@dataclass(frozen=True, slots=True)
class Constitution:
    """Operator-owned safety boundary that role objectives cannot redefine."""

    ID_PREFIX: ClassVar[str] = "constitution-sha256:"

    version: int
    safety_rules: tuple[str, ...]
    parent_constitution_id: str | None = None
    protected_controls: tuple[str, ...] = MANDATORY_PROTECTED_CONTROLS
    constitution_id: str = field(init=False)

    def __post_init__(self) -> None:
        version = _positive_int(self.version, "version")
        _text_tuple(self.safety_rules, "safety_rules")
        controls = _text_tuple(self.protected_controls, "protected_controls")
        if controls != tuple(sorted(controls)):
            raise ValueError("protected_controls must be in canonical order")
        missing = set(MANDATORY_PROTECTED_CONTROLS) - set(controls)
        if missing:
            raise ValueError(f"constitution omits mandatory protected controls: {sorted(missing)}")
        _lineage(version, self.parent_constitution_id, "constitution", self.ID_PREFIX)
        object.__setattr__(self, "constitution_id", _content_id(self.ID_PREFIX, self._payload()))

    def _payload(self) -> Mapping[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "version": self.version,
            "parent_constitution_id": self.parent_constitution_id,
            "safety_rules": list(self.safety_rules),
            "protected_controls": list(self.protected_controls),
        }

    def to_mapping(self) -> Mapping[str, Any]:
        return {"constitution_id": self.constitution_id, **self._payload()}

    @classmethod
    def from_mapping(cls, value: object) -> Constitution:
        data = _strict_mapping(
            value,
            {
                "schema_version",
                "constitution_id",
                "version",
                "parent_constitution_id",
                "safety_rules",
                "protected_controls",
            },
            "constitution",
        )
        item = cls(
            version=data["version"],
            safety_rules=_sequence_to_tuple(data["safety_rules"], "safety_rules"),
            parent_constitution_id=data["parent_constitution_id"],
            protected_controls=_sequence_to_tuple(data["protected_controls"], "protected_controls"),
        )
        if data["constitution_id"] != item.constitution_id:
            raise ValueError("constitution_id does not match canonical content")
        return item


@dataclass(frozen=True, slots=True)
class ObjectiveVersion:
    """A versioned desired outcome bound to, but unable to modify, a constitution."""

    ID_PREFIX: ClassVar[str] = "objective-sha256:"

    version: int
    constitution_id: str
    statement: str
    success_criteria: tuple[str, ...]
    capability_tags: tuple[str, ...]
    parent_objective_id: str | None = None
    objective_id: str = field(init=False)

    def __post_init__(self) -> None:
        version = _positive_int(self.version, "version")
        _identity(self.constitution_id, "constitution_id", Constitution.ID_PREFIX)
        _required_text(self.statement, "statement")
        _text_tuple(self.success_criteria, "success_criteria")
        tags = _text_tuple(self.capability_tags, "capability_tags", allow_empty=True)
        if tags != tuple(sorted(tags)):
            raise ValueError("capability_tags must be in canonical order")
        _lineage(version, self.parent_objective_id, "objective", self.ID_PREFIX)
        object.__setattr__(self, "objective_id", _content_id(self.ID_PREFIX, self._payload()))

    def _payload(self) -> Mapping[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "version": self.version,
            "parent_objective_id": self.parent_objective_id,
            "constitution_id": self.constitution_id,
            "statement": self.statement,
            "success_criteria": list(self.success_criteria),
            "capability_tags": list(self.capability_tags),
        }

    def to_mapping(self) -> Mapping[str, Any]:
        return {"objective_id": self.objective_id, **self._payload()}

    @classmethod
    def from_mapping(cls, value: object) -> ObjectiveVersion:
        data = _strict_mapping(
            value,
            {
                "schema_version",
                "objective_id",
                "version",
                "parent_objective_id",
                "constitution_id",
                "statement",
                "success_criteria",
                "capability_tags",
            },
            "objective",
        )
        item = cls(
            version=data["version"],
            parent_objective_id=data["parent_objective_id"],
            constitution_id=data["constitution_id"],
            statement=data["statement"],
            success_criteria=_sequence_to_tuple(data["success_criteria"], "success_criteria"),
            capability_tags=_sequence_to_tuple(
                data["capability_tags"], "capability_tags", allow_empty=True
            ),
        )
        if data["objective_id"] != item.objective_id:
            raise ValueError("objective_id does not match canonical content")
        return item


@dataclass(frozen=True, slots=True)
class RoleVersionIdentity:
    """Content-addressed identity for one independently versioned role artifact."""

    ID_PREFIX: ClassVar[str] = "role-version-sha256:"

    role: Role
    version: int
    artifact_id: str
    artifact_sha256: str
    constitution_id: str
    parent_role_version_id: str | None = None
    role_version_id: str = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.role, Role):
            raise TypeError("role must be a Role")
        version = _positive_int(self.version, "version")
        _required_text(self.artifact_id, "artifact_id")
        _digest(self.artifact_sha256, "artifact_sha256")
        _identity(self.constitution_id, "constitution_id", Constitution.ID_PREFIX)
        _lineage(version, self.parent_role_version_id, "role_version", self.ID_PREFIX)
        object.__setattr__(self, "role_version_id", _content_id(self.ID_PREFIX, self._payload()))

    def _payload(self) -> Mapping[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "role": self.role.value,
            "version": self.version,
            "parent_role_version_id": self.parent_role_version_id,
            "artifact_id": self.artifact_id,
            "artifact_sha256": self.artifact_sha256,
            "constitution_id": self.constitution_id,
        }

    def to_mapping(self) -> Mapping[str, Any]:
        return {"role_version_id": self.role_version_id, **self._payload()}

    @classmethod
    def from_mapping(cls, value: object) -> RoleVersionIdentity:
        data = _strict_mapping(
            value,
            {
                "schema_version",
                "role_version_id",
                "role",
                "version",
                "parent_role_version_id",
                "artifact_id",
                "artifact_sha256",
                "constitution_id",
            },
            "role version identity",
        )
        try:
            role = Role(data["role"])
        except (TypeError, ValueError) as exc:
            raise ValueError("role must be warrior, judge, or prosecutor") from exc
        item = cls(
            role=role,
            version=data["version"],
            parent_role_version_id=data["parent_role_version_id"],
            artifact_id=data["artifact_id"],
            artifact_sha256=data["artifact_sha256"],
            constitution_id=data["constitution_id"],
        )
        if data["role_version_id"] != item.role_version_id:
            raise ValueError("role_version_id does not match canonical content")
        return item


@dataclass(frozen=True, slots=True)
class ActiveRoleSet:
    """One atomically pinned Warrior/Judge/Prosecutor version vector."""

    ID_PREFIX: ClassVar[str] = "active-role-set-sha256:"

    revision: int
    objective_id: str
    warrior: RoleVersionIdentity
    judge: RoleVersionIdentity
    prosecutor: RoleVersionIdentity
    active_role_set_id: str = field(init=False)

    def __post_init__(self) -> None:
        _non_negative_int(self.revision, "revision")
        _identity(self.objective_id, "objective_id", ObjectiveVersion.ID_PREFIX)
        expected = (
            (self.warrior, Role.WARRIOR),
            (self.judge, Role.JUDGE),
            (self.prosecutor, Role.PROSECUTOR),
        )
        if any(not isinstance(item, RoleVersionIdentity) for item, _ in expected):
            raise TypeError("active roles must be RoleVersionIdentity values")
        if any(item.role is not role for item, role in expected):
            raise ValueError("active role identities are assigned to the wrong slots")
        constitutions = {item.constitution_id for item, _ in expected}
        if len(constitutions) != 1:
            raise ValueError("all active roles must share one constitution")
        role_ids = {item.role_version_id for item, _ in expected}
        if len(role_ids) != 3:
            raise ValueError("active role identities must be distinct")
        object.__setattr__(self, "active_role_set_id", _content_id(self.ID_PREFIX, self._payload()))

    @property
    def constitution_id(self) -> str:
        return self.warrior.constitution_id

    def for_role(self, role: Role) -> RoleVersionIdentity:
        if not isinstance(role, Role):
            raise TypeError("role must be a Role")
        return {
            Role.WARRIOR: self.warrior,
            Role.JUDGE: self.judge,
            Role.PROSECUTOR: self.prosecutor,
        }[role]

    def _payload(self) -> Mapping[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "revision": self.revision,
            "objective_id": self.objective_id,
            "warrior": self.warrior.to_mapping(),
            "judge": self.judge.to_mapping(),
            "prosecutor": self.prosecutor.to_mapping(),
        }

    def to_mapping(self) -> Mapping[str, Any]:
        return {"active_role_set_id": self.active_role_set_id, **self._payload()}

    @classmethod
    def from_mapping(cls, value: object) -> ActiveRoleSet:
        data = _strict_mapping(
            value,
            {
                "schema_version",
                "active_role_set_id",
                "revision",
                "objective_id",
                "warrior",
                "judge",
                "prosecutor",
            },
            "active role set",
        )
        item = cls(
            revision=data["revision"],
            objective_id=data["objective_id"],
            warrior=RoleVersionIdentity.from_mapping(data["warrior"]),
            judge=RoleVersionIdentity.from_mapping(data["judge"]),
            prosecutor=RoleVersionIdentity.from_mapping(data["prosecutor"]),
        )
        if data["active_role_set_id"] != item.active_role_set_id:
            raise ValueError("active_role_set_id does not match canonical content")
        return item


@dataclass(frozen=True, slots=True)
class CurriculumSnapshot:
    """Immutable cycle input binding objective, constitution, roles, and cohorts."""

    ID_PREFIX: ClassVar[str] = "curriculum-snapshot-sha256:"

    campaign_id: str
    cycle_number: int
    constitution: Constitution
    objective: ObjectiveVersion
    active_roles: ActiveRoleSet
    task_pool_revision: int
    training_cohort_sha256: str
    lagged_holdout_cohort_sha256: str
    hall_of_fame_revision: int
    external_probe_set_sha256: str
    parent_snapshot_id: str | None = None
    snapshot_id: str = field(init=False)

    def __post_init__(self) -> None:
        _required_text(self.campaign_id, "campaign_id")
        cycle = _positive_int(self.cycle_number, "cycle_number")
        if not isinstance(self.constitution, Constitution):
            raise TypeError("constitution must be a Constitution")
        if not isinstance(self.objective, ObjectiveVersion):
            raise TypeError("objective must be an ObjectiveVersion")
        if not isinstance(self.active_roles, ActiveRoleSet):
            raise TypeError("active_roles must be an ActiveRoleSet")
        if self.objective.constitution_id != self.constitution.constitution_id:
            raise ValueError("objective is bound to a different constitution")
        if self.active_roles.constitution_id != self.constitution.constitution_id:
            raise ValueError("active roles are bound to a different constitution")
        if self.active_roles.objective_id != self.objective.objective_id:
            raise ValueError("active roles are pinned for a different objective")
        _non_negative_int(self.task_pool_revision, "task_pool_revision")
        _digest(self.training_cohort_sha256, "training_cohort_sha256")
        _digest(self.lagged_holdout_cohort_sha256, "lagged_holdout_cohort_sha256")
        _non_negative_int(self.hall_of_fame_revision, "hall_of_fame_revision")
        _digest(self.external_probe_set_sha256, "external_probe_set_sha256")
        if cycle == 1:
            if self.parent_snapshot_id is not None:
                raise ValueError("cycle 1 snapshot must not have a parent")
        elif self.parent_snapshot_id is None:
            raise ValueError("later curriculum snapshots require a parent")
        else:
            _identity(self.parent_snapshot_id, "parent_snapshot_id", self.ID_PREFIX)
        object.__setattr__(self, "snapshot_id", _content_id(self.ID_PREFIX, self._payload()))

    def _payload(self) -> Mapping[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "campaign_id": self.campaign_id,
            "cycle_number": self.cycle_number,
            "parent_snapshot_id": self.parent_snapshot_id,
            "constitution": self.constitution.to_mapping(),
            "objective": self.objective.to_mapping(),
            "active_roles": self.active_roles.to_mapping(),
            "task_pool_revision": self.task_pool_revision,
            "training_cohort_sha256": self.training_cohort_sha256,
            "lagged_holdout_cohort_sha256": self.lagged_holdout_cohort_sha256,
            "hall_of_fame_revision": self.hall_of_fame_revision,
            "external_probe_set_sha256": self.external_probe_set_sha256,
        }

    def to_mapping(self) -> Mapping[str, Any]:
        return {"snapshot_id": self.snapshot_id, **self._payload()}

    @classmethod
    def from_mapping(cls, value: object) -> CurriculumSnapshot:
        data = _strict_mapping(
            value,
            {
                "schema_version",
                "snapshot_id",
                "campaign_id",
                "cycle_number",
                "parent_snapshot_id",
                "constitution",
                "objective",
                "active_roles",
                "task_pool_revision",
                "training_cohort_sha256",
                "lagged_holdout_cohort_sha256",
                "hall_of_fame_revision",
                "external_probe_set_sha256",
            },
            "curriculum snapshot",
        )
        item = cls(
            campaign_id=data["campaign_id"],
            cycle_number=data["cycle_number"],
            parent_snapshot_id=data["parent_snapshot_id"],
            constitution=Constitution.from_mapping(data["constitution"]),
            objective=ObjectiveVersion.from_mapping(data["objective"]),
            active_roles=ActiveRoleSet.from_mapping(data["active_roles"]),
            task_pool_revision=data["task_pool_revision"],
            training_cohort_sha256=data["training_cohort_sha256"],
            lagged_holdout_cohort_sha256=data["lagged_holdout_cohort_sha256"],
            hall_of_fame_revision=data["hall_of_fame_revision"],
            external_probe_set_sha256=data["external_probe_set_sha256"],
        )
        if data["snapshot_id"] != item.snapshot_id:
            raise ValueError("snapshot_id does not match canonical content")
        return item
