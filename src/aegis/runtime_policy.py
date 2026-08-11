"""Immutable, replayable runtime-policy autonomy for AEGIS campaigns.

The prosecutor may tune economic and execution budgets.  Host isolation and
resource-enforcement settings are deliberately absent from the policy schema,
so no amendment can weaken the Windows/WSL safety boundary.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from pathlib import Path
from threading import Lock, RLock
from types import MappingProxyType
from typing import Any, Mapping, cast

from aegis.artifacts import ArtifactRef, ContentAddressedArtifactStore
from aegis.event_store import EventStore, EventStoreSequenceConflict
from aegis.models import JsonValue, Role, canonical_json, freeze_json, thaw_json

_POLICY_KIND = "runtime-policy"
_AMENDMENT_KIND = "runtime-policy-amendment"
_STAGE_AMENDMENT_KIND = "runtime-policy-stage-amendment"
_ROLES = frozenset(role.value for role in Role)
_CUMULATIVE_LIMITS = frozenset(
    {"max_cost_usd", "max_total_tokens", "max_requests", "max_rounds", "max_runtime_seconds"}
)
_INTEGER_LIMITS = frozenset(
    {
        "max_total_tokens",
        "max_requests",
        "max_rounds",
        "max_steps",
        "candidate_max_extra_steps",
        "subagent_max_steps",
        "council_max_messages",
        "council_max_tokens",
    }
)
_TIMEOUT_LIMITS = frozenset(
    {
        "command_timeout_seconds",
        "sealed_timeout_seconds",
        "subagent_timeout_seconds",
        "scan_timeout_seconds",
    }
)
_ALLOWED_FIELDS = frozenset(
    {
        *_CUMULATIVE_LIMITS,
        *_INTEGER_LIMITS,
        *_TIMEOUT_LIMITS,
        "build_timeout_seconds",
        "role_budget_shares",
        "role_max_output_tokens",
    }
)
_HOST_SAFETY_TERMS = (
    "windows",
    "wsl",
    "host",
    "safety",
    "cpu",
    "memory",
    "mem",
    "pid",
    "disk",
    "concurrency",
    "interop",
    "drvfs",
    "mount",
    "broker",
)


class RuntimePolicyError(RuntimeError):
    """Base error for invalid or inconsistent runtime-policy operations."""


class RuntimePolicyConflictError(RuntimePolicyError):
    """Raised when one cycle or paired design receives conflicting bindings."""


class RuntimePolicyIntegrityError(RuntimePolicyError):
    """Raised when replayed event or CAS material is inconsistent."""


def _strict_object(value: object, fields: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise RuntimePolicyIntegrityError(f"{name} has an invalid schema")
    return dict(value)


def _positive_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RuntimePolicyError(f"{name} must be an integer")
    if value <= 0:
        raise RuntimePolicyError(f"{name} must be positive")
    return value


def _positive_number(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RuntimePolicyError(f"{name} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise RuntimePolicyError(f"{name} must be finite and positive")
    return result


def _validate_role_numbers(value: object, name: str, *, shares: bool = False) -> dict[str, float | int]:
    if not isinstance(value, Mapping) or set(value) != _ROLES:
        raise RuntimePolicyError(f"{name} must define exactly warrior, judge, and prosecutor")
    result: dict[str, float | int] = {}
    for role, raw in value.items():
        if shares:
            result[cast(str, role)] = _positive_number(raw, f"{name}.{role}")
        else:
            result[cast(str, role)] = _positive_int(raw, f"{name}.{role}")
    if shares and not math.isclose(sum(cast(float, item) for item in result.values()), 1.0, abs_tol=1e-9):
        raise RuntimePolicyError("role_budget_shares must sum to 1")
    return result


def _validate_provider_limits(value: object) -> dict[str, int]:
    if not isinstance(value, Mapping) or not value:
        raise RuntimePolicyError("provider_output_limits must be a non-empty mapping")
    result: dict[str, int] = {}
    for role, raw in value.items():
        if not isinstance(role, str) or role not in _ROLES:
            raise RuntimePolicyError("provider_output_limits contains an invalid role")
        result[role] = _positive_int(raw, f"provider_output_limits.{role}")
    if set(result) != _ROLES:
        raise RuntimePolicyError("provider_output_limits must define exactly all roles")
    return result


def _validate_values(
    value: object, provider_output_limits: Mapping[str, int]
) -> Mapping[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise RuntimePolicyError("runtime policy values must be a mapping")
    unknown = set(value) - _ALLOWED_FIELDS
    if unknown:
        names = ", ".join(sorted(str(item) for item in unknown))
        if any(term in str(item).lower() for item in unknown for term in _HOST_SAFETY_TERMS):
            raise RuntimePolicyError(f"host safety and resource-envelope fields are immutable: {names}")
        raise RuntimePolicyError(f"runtime policy contains unsupported fields: {names}")
    missing = _ALLOWED_FIELDS - set(value)
    if missing:
        raise RuntimePolicyError(f"runtime policy is missing fields: {', '.join(sorted(missing))}")

    normalized: dict[str, Any] = {}
    for name in _INTEGER_LIMITS:
        normalized[name] = _positive_int(value[name], name)
    for name in _TIMEOUT_LIMITS | {"max_runtime_seconds", "build_timeout_seconds", "max_cost_usd"}:
        normalized[name] = _positive_number(value[name], name)
    if normalized["max_steps"] > 1000:
        raise RuntimePolicyError("max_steps must be at most 1000")
    if normalized["candidate_max_extra_steps"] > 1000:
        raise RuntimePolicyError("candidate_max_extra_steps must be at most 1000")
    if normalized["subagent_max_steps"] > 1000:
        raise RuntimePolicyError("subagent_max_steps must be at most 1000")
    for name in _TIMEOUT_LIMITS:
        if normalized[name] > 3600:
            raise RuntimePolicyError(f"{name} must be at most 3600 seconds")
    if normalized["build_timeout_seconds"] > 86_400:
        raise RuntimePolicyError("build_timeout_seconds must be at most 86400 seconds")

    normalized["role_budget_shares"] = _validate_role_numbers(
        value["role_budget_shares"], "role_budget_shares", shares=True
    )
    outputs = _validate_role_numbers(value["role_max_output_tokens"], "role_max_output_tokens")
    for role, output in outputs.items():
        if cast(int, output) > provider_output_limits[role]:
            raise RuntimePolicyError(
                f"role_max_output_tokens.{role} exceeds the provider output profile"
            )
    normalized["role_max_output_tokens"] = outputs
    return cast(Mapping[str, JsonValue], freeze_json(normalized))


def _validate_consumed(value: Mapping[str, float | int]) -> Mapping[str, float]:
    unknown = set(value) - _CUMULATIVE_LIMITS
    if unknown:
        raise RuntimePolicyError(f"consumed contains unsupported fields: {', '.join(sorted(unknown))}")
    result: dict[str, float] = {}
    for name, raw in value.items():
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            raise RuntimePolicyError(f"consumed.{name} must be numeric")
        number = float(raw)
        if not math.isfinite(number) or number < 0:
            raise RuntimePolicyError(f"consumed.{name} must be finite and non-negative")
        result[name] = number
    return MappingProxyType(result)


def _content_id(kind: str, payload: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    return f"{kind}-sha256:{digest}"


@dataclass(frozen=True, slots=True)
class RuntimePolicyVersion:
    policy_id: str
    parent_policy_id: str | None
    effective_cycle: int
    values: Mapping[str, JsonValue]
    provider_output_limits: Mapping[str, int]
    maintenance_only: bool
    maintenance_reasons: tuple[str, ...]

    @classmethod
    def create(
        cls,
        *,
        parent_policy_id: str | None,
        effective_cycle: int,
        values: Mapping[str, Any],
        provider_output_limits: Mapping[str, int],
        consumed: Mapping[str, float | int] | None = None,
    ) -> RuntimePolicyVersion:
        if isinstance(effective_cycle, bool) or not isinstance(effective_cycle, int) or effective_cycle < 0:
            raise RuntimePolicyError("effective_cycle must be a non-negative integer")
        limits = MappingProxyType(_validate_provider_limits(provider_output_limits))
        normalized = _validate_values(values, limits)
        usage = _validate_consumed(consumed or {})
        reasons = tuple(
            sorted(
                name
                for name, amount in usage.items()
                if name in normalized and float(cast(float | int, normalized[name])) < amount
            )
        )
        material: dict[str, Any] = {
            "parent_policy_id": parent_policy_id,
            "effective_cycle": effective_cycle,
            "values": thaw_json(cast(JsonValue, normalized)),
            "provider_output_limits": dict(limits),
            "maintenance_only": bool(reasons),
            "maintenance_reasons": list(reasons),
        }
        return cls(
            _content_id(_POLICY_KIND, material),
            parent_policy_id,
            effective_cycle,
            normalized,
            limits,
            bool(reasons),
            reasons,
        )

    @classmethod
    def from_artifact_mapping(cls, value: object) -> RuntimePolicyVersion:
        data = _strict_object(
            value,
            {
                "parent_policy_id",
                "effective_cycle",
                "values",
                "provider_output_limits",
                "maintenance_only",
                "maintenance_reasons",
            },
            "runtime policy artifact",
        )
        reasons = data["maintenance_reasons"]
        if not isinstance(reasons, list) or any(not isinstance(item, str) for item in reasons):
            raise RuntimePolicyIntegrityError("maintenance_reasons must be a string list")
        if any(item not in _CUMULATIVE_LIMITS for item in reasons) or reasons != sorted(set(reasons)):
            raise RuntimePolicyIntegrityError("maintenance_reasons contains invalid fields")
        maintenance_only = data["maintenance_only"]
        if not isinstance(maintenance_only, bool) or maintenance_only != bool(reasons):
            raise RuntimePolicyIntegrityError("runtime policy maintenance state is inconsistent")
        effective_cycle = data["effective_cycle"]
        if isinstance(effective_cycle, bool) or not isinstance(effective_cycle, int) or effective_cycle < 0:
            raise RuntimePolicyIntegrityError("effective_cycle must be a non-negative integer")
        parent = data["parent_policy_id"]
        if parent is not None and not isinstance(parent, str):
            raise RuntimePolicyIntegrityError("parent_policy_id must be text or null")
        limits = MappingProxyType(_validate_provider_limits(data["provider_output_limits"]))
        values = _validate_values(data["values"], limits)
        material = {
            "parent_policy_id": parent,
            "effective_cycle": effective_cycle,
            "values": thaw_json(cast(JsonValue, values)),
            "provider_output_limits": dict(limits),
            "maintenance_only": maintenance_only,
            "maintenance_reasons": reasons,
        }
        return cls(
            _content_id(_POLICY_KIND, material),
            parent,
            effective_cycle,
            values,
            limits,
            maintenance_only,
            tuple(reasons),
        )

    def to_artifact_mapping(self) -> dict[str, Any]:
        return {
            "parent_policy_id": self.parent_policy_id,
            "effective_cycle": self.effective_cycle,
            "values": thaw_json(cast(JsonValue, self.values)),
            "provider_output_limits": dict(self.provider_output_limits),
            "maintenance_only": self.maintenance_only,
            "maintenance_reasons": list(self.maintenance_reasons),
        }

    def to_mapping(self) -> dict[str, Any]:
        return {"policy_id": self.policy_id, **self.to_artifact_mapping()}


@dataclass(frozen=True, slots=True)
class RuntimePolicyAmendment:
    amendment_id: str
    base_policy_id: str
    requested_cycle: int
    effective_cycle: int
    requested_by: Role
    kind: str
    patch: Mapping[str, JsonValue]
    rollback_target_policy_id: str | None
    resulting_policy_id: str
    reason: str

    @classmethod
    def create(
        cls,
        *,
        base_policy_id: str,
        requested_cycle: int,
        kind: str,
        patch: Mapping[str, Any],
        rollback_target_policy_id: str | None,
        resulting_policy_id: str,
        reason: str,
    ) -> RuntimePolicyAmendment:
        if kind not in {"patch", "rollback"}:
            raise RuntimePolicyError("amendment kind must be patch or rollback")
        if isinstance(requested_cycle, bool) or not isinstance(requested_cycle, int) or requested_cycle < 0:
            raise RuntimePolicyError("requested_cycle must be a non-negative integer")
        if not isinstance(reason, str) or not reason.strip() or reason != reason.strip():
            raise RuntimePolicyError("amendment reason must be non-empty without surrounding whitespace")
        frozen_patch = cast(Mapping[str, JsonValue], freeze_json(patch))
        material = {
            "base_policy_id": base_policy_id,
            "requested_cycle": requested_cycle,
            "effective_cycle": requested_cycle + 1,
            "requested_by": Role.PROSECUTOR.value,
            "kind": kind,
            "patch": thaw_json(cast(JsonValue, frozen_patch)),
            "rollback_target_policy_id": rollback_target_policy_id,
            "resulting_policy_id": resulting_policy_id,
            "reason": reason,
        }
        return cls(
            _content_id(_AMENDMENT_KIND, material),
            base_policy_id,
            requested_cycle,
            requested_cycle + 1,
            Role.PROSECUTOR,
            kind,
            frozen_patch,
            rollback_target_policy_id,
            resulting_policy_id,
            reason,
        )

    def to_artifact_mapping(self) -> dict[str, Any]:
        return {
            "base_policy_id": self.base_policy_id,
            "requested_cycle": self.requested_cycle,
            "effective_cycle": self.effective_cycle,
            "requested_by": self.requested_by.value,
            "kind": self.kind,
            "patch": thaw_json(cast(JsonValue, self.patch)),
            "rollback_target_policy_id": self.rollback_target_policy_id,
            "resulting_policy_id": self.resulting_policy_id,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class RuntimeStageBoundary:
    """One monotonic execution boundary inside a campaign cycle."""

    cycle: int
    ordinal: int
    name: str

    def __post_init__(self) -> None:
        for value, field_name in ((self.cycle, "cycle"), (self.ordinal, "ordinal")):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise RuntimePolicyError(f"stage boundary {field_name} must be non-negative")
        if not isinstance(self.name, str) or not self.name.strip() or self.name != self.name.strip():
            raise RuntimePolicyError("stage boundary name must be non-empty without surrounding whitespace")

    @property
    def key(self) -> tuple[int, int]:
        return self.cycle, self.ordinal

    def to_mapping(self) -> dict[str, JsonValue]:
        return {"cycle": self.cycle, "ordinal": self.ordinal, "name": self.name}

    @classmethod
    def from_mapping(cls, value: object) -> RuntimeStageBoundary:
        data = _strict_object(value, {"cycle", "ordinal", "name"}, "runtime stage boundary")
        try:
            return cls(data["cycle"], data["ordinal"], data["name"])
        except (TypeError, ValueError) as exc:
            raise RuntimePolicyIntegrityError("runtime stage boundary is invalid") from exc


@dataclass(frozen=True, slots=True)
class StageRuntimePolicyAmendment:
    amendment_id: str
    base_policy_id: str
    requested_at: RuntimeStageBoundary
    effective_at: RuntimeStageBoundary
    requested_by: Role
    kind: str
    patch: Mapping[str, JsonValue]
    rollback_target_policy_id: str | None
    resulting_policy_id: str
    reason: str

    @classmethod
    def create(
        cls,
        *,
        base_policy_id: str,
        requested_at: RuntimeStageBoundary,
        effective_at: RuntimeStageBoundary,
        kind: str,
        patch: Mapping[str, Any],
        rollback_target_policy_id: str | None,
        resulting_policy_id: str,
        reason: str,
    ) -> StageRuntimePolicyAmendment:
        if kind not in {"patch", "rollback"}:
            raise RuntimePolicyError("stage amendment kind must be patch or rollback")
        direct_successor = (
            effective_at.cycle == requested_at.cycle
            and effective_at.ordinal == requested_at.ordinal + 1
        ) or (
            effective_at.cycle == requested_at.cycle + 1 and effective_at.ordinal == 0
        )
        if not direct_successor:
            raise RuntimePolicyError("stage amendment must become effective at the next stage boundary")
        if not isinstance(reason, str) or not reason.strip() or reason != reason.strip():
            raise RuntimePolicyError("stage amendment reason must be non-empty without surrounding whitespace")
        frozen_patch = cast(Mapping[str, JsonValue], freeze_json(patch))
        material = {
            "base_policy_id": base_policy_id,
            "requested_at": requested_at.to_mapping(),
            "effective_at": effective_at.to_mapping(),
            "requested_by": Role.PROSECUTOR.value,
            "kind": kind,
            "patch": thaw_json(cast(JsonValue, frozen_patch)),
            "rollback_target_policy_id": rollback_target_policy_id,
            "resulting_policy_id": resulting_policy_id,
            "reason": reason,
        }
        return cls(
            _content_id(_STAGE_AMENDMENT_KIND, material),
            base_policy_id,
            requested_at,
            effective_at,
            Role.PROSECUTOR,
            kind,
            frozen_patch,
            rollback_target_policy_id,
            resulting_policy_id,
            reason,
        )

    def to_artifact_mapping(self) -> dict[str, Any]:
        return {
            "base_policy_id": self.base_policy_id,
            "requested_at": self.requested_at.to_mapping(),
            "effective_at": self.effective_at.to_mapping(),
            "requested_by": self.requested_by.value,
            "kind": self.kind,
            "patch": thaw_json(cast(JsonValue, self.patch)),
            "rollback_target_policy_id": self.rollback_target_policy_id,
            "resulting_policy_id": self.resulting_policy_id,
            "reason": self.reason,
        }


_LOCKS_GUARD = Lock()
_REGISTRY_LOCKS: dict[tuple[str, str], RLock] = {}


def _registry_lock(store: EventStore, campaign_id: str) -> RLock:
    key = (str(Path(store.path).resolve()), campaign_id)
    with _LOCKS_GUARD:
        return _REGISTRY_LOCKS.setdefault(key, RLock())


class RuntimePolicyRegistry:
    """Event-sourced runtime-policy timeline backed by immutable CAS objects."""

    def __init__(
        self,
        store: EventStore,
        artifacts: ContentAddressedArtifactStore,
        campaign_id: str,
    ) -> None:
        if not isinstance(campaign_id, str) or not campaign_id.strip():
            raise RuntimePolicyError("campaign_id must be non-empty")
        self.store = store
        self.artifacts = artifacts
        self.campaign_id = campaign_id
        self._lock = _registry_lock(store, campaign_id)
        self._versions: dict[str, RuntimePolicyVersion] = {}
        self._schedule: dict[int, str] = {}
        self._amendments: dict[int, RuntimePolicyAmendment] = {}
        self._stage_schedule: dict[tuple[int, int], tuple[RuntimeStageBoundary, str]] = {}
        self._stage_amendments: dict[tuple[int, int], StageRuntimePolicyAmendment] = {}
        self._paired_designs: dict[str, str] = {}
        self._replay()

    @property
    def versions(self) -> tuple[RuntimePolicyVersion, ...]:
        return tuple(self._versions[key] for key in sorted(self._versions))

    def genesis(
        self,
        values: Mapping[str, Any],
        provider_output_limits: Mapping[str, int],
    ) -> RuntimePolicyVersion:
        candidate = RuntimePolicyVersion.create(
            parent_policy_id=None,
            effective_cycle=0,
            values=values,
            provider_output_limits=provider_output_limits,
        )
        with self._lock:
            self._replay()
            existing = self._schedule.get(0)
            if existing is not None:
                if existing == candidate.policy_id:
                    return self._versions[existing]
                raise RuntimePolicyConflictError("campaign already has a different genesis policy")
            self._persist_policy(candidate, "runtime_policy_genesis", None)
            self._replay()
            return self._versions[candidate.policy_id]

    def effective_for_cycle(self, cycle: int) -> RuntimePolicyVersion:
        if isinstance(cycle, bool) or not isinstance(cycle, int) or cycle < 0:
            raise RuntimePolicyError("cycle must be a non-negative integer")
        eligible = [item for item in self._schedule if item <= cycle]
        if not eligible:
            raise RuntimePolicyError("runtime policy genesis has not been initialized")
        return self._versions[self._schedule[max(eligible)]]

    def effective_for_stage(self, boundary: RuntimeStageBoundary) -> RuntimePolicyVersion:
        """Resolve the latest policy at an exact monotonic stage boundary."""
        scheduled = self._stage_schedule.get(boundary.key)
        if scheduled is not None and scheduled[0] != boundary:
            raise RuntimePolicyConflictError(
                "stage ordinal is already bound to another stage name"
            )
        requested = self._stage_amendments.get(boundary.key)
        if requested is not None and requested.requested_at != boundary:
            raise RuntimePolicyConflictError(
                "stage ordinal is already bound to another stage name"
            )
        candidates: list[tuple[tuple[int, int], str]] = [
            ((cycle, 0), policy_id)
            for cycle, policy_id in self._schedule.items()
            if (cycle, 0) <= boundary.key
        ]
        candidates.extend(
            (key, policy_id)
            for key, (_, policy_id) in self._stage_schedule.items()
            if key <= boundary.key
        )
        if not candidates:
            raise RuntimePolicyError("runtime policy genesis has not been initialized")
        return self._versions[max(candidates, key=lambda item: item[0])[1]]

    def resume_stage_boundary(self, cycle: int) -> RuntimeStageBoundary:
        """Return the latest persisted effective boundary for a resumed cycle."""
        if isinstance(cycle, bool) or not isinstance(cycle, int) or cycle < 0:
            raise RuntimePolicyError("cycle must be a non-negative integer")
        matches = [
            boundary
            for (scheduled_cycle, _ordinal), (boundary, _policy_id) in self._stage_schedule.items()
            if scheduled_cycle == cycle
        ]
        if not matches:
            return RuntimeStageBoundary(cycle, 0, "stage:0")
        return max(matches, key=lambda item: item.ordinal)

    def stage_boundary(
        self, cycle: int, ordinal: int, default_name: str
    ) -> RuntimeStageBoundary:
        """Resolve the persisted name for a boundary, or create its first binding."""
        existing = self._stage_schedule.get((cycle, ordinal))
        if existing is not None:
            return existing[0]
        requested = self._stage_amendments.get((cycle, ordinal))
        if requested is not None:
            return requested.requested_at
        return RuntimeStageBoundary(cycle, ordinal, default_name)

    def amendment_for_cycle(self, requested_cycle: int) -> RuntimePolicyAmendment | None:
        return self._amendments.get(requested_cycle)

    def amendment_for_stage(
        self, requested_at: RuntimeStageBoundary
    ) -> StageRuntimePolicyAmendment | None:
        amendment = self._stage_amendments.get(requested_at.key)
        if amendment is not None and amendment.requested_at != requested_at:
            raise RuntimePolicyConflictError("stage ordinal is already bound to another stage name")
        return amendment

    def request_patch_after_stage(
        self,
        *,
        requested_by: Role | str,
        requested_at: RuntimeStageBoundary,
        effective_at: RuntimeStageBoundary,
        patch: Mapping[str, Any],
        consumed: Mapping[str, float | int],
        reason: str,
    ) -> StageRuntimePolicyAmendment:
        role = requested_by if isinstance(requested_by, Role) else Role(requested_by)
        if role is not Role.PROSECUTOR:
            raise RuntimePolicyError("only the prosecutor may amend runtime policy")
        if not isinstance(patch, Mapping) or not patch:
            raise RuntimePolicyError("runtime policy patch must be a non-empty mapping")
        unknown = set(patch) - _ALLOWED_FIELDS
        if unknown:
            names = ", ".join(sorted(str(item) for item in unknown))
            raise RuntimePolicyError(f"runtime policy patch cannot modify fields: {names}")
        with self._lock:
            self._replay()
            base = self.effective_for_stage(requested_at)
            values = cast(dict[str, Any], thaw_json(cast(JsonValue, base.values)))
            values.update(dict(patch))
            result = RuntimePolicyVersion.create(
                parent_policy_id=base.policy_id,
                effective_cycle=effective_at.cycle,
                values=values,
                provider_output_limits=base.provider_output_limits,
                consumed=consumed,
            )
            amendment = StageRuntimePolicyAmendment.create(
                base_policy_id=base.policy_id,
                requested_at=requested_at,
                effective_at=effective_at,
                kind="patch",
                patch=patch,
                rollback_target_policy_id=None,
                resulting_policy_id=result.policy_id,
                reason=reason,
            )
            return self._persist_stage_amendment(result, amendment)

    def request_rollback_after_stage(
        self,
        *,
        requested_by: Role | str,
        requested_at: RuntimeStageBoundary,
        effective_at: RuntimeStageBoundary,
        target_policy_id: str,
        consumed: Mapping[str, float | int],
        reason: str,
    ) -> StageRuntimePolicyAmendment:
        role = requested_by if isinstance(requested_by, Role) else Role(requested_by)
        if role is not Role.PROSECUTOR:
            raise RuntimePolicyError("only the prosecutor may roll back runtime policy")
        with self._lock:
            self._replay()
            base = self.effective_for_stage(requested_at)
            try:
                target = self._versions[target_policy_id]
            except KeyError as exc:
                raise RuntimePolicyError("rollback target policy is unknown") from exc
            result = RuntimePolicyVersion.create(
                parent_policy_id=base.policy_id,
                effective_cycle=effective_at.cycle,
                values=cast(Mapping[str, Any], target.values),
                provider_output_limits=target.provider_output_limits,
                consumed=consumed,
            )
            amendment = StageRuntimePolicyAmendment.create(
                base_policy_id=base.policy_id,
                requested_at=requested_at,
                effective_at=effective_at,
                kind="rollback",
                patch={},
                rollback_target_policy_id=target.policy_id,
                resulting_policy_id=result.policy_id,
                reason=reason,
            )
            return self._persist_stage_amendment(result, amendment)

    def request_patch(
        self,
        *,
        requested_by: Role | str,
        current_cycle: int,
        patch: Mapping[str, Any],
        consumed: Mapping[str, float | int],
        reason: str,
    ) -> RuntimePolicyAmendment:
        role = requested_by if isinstance(requested_by, Role) else Role(requested_by)
        if role is not Role.PROSECUTOR:
            raise RuntimePolicyError("only the prosecutor may amend runtime policy")
        if not isinstance(patch, Mapping) or not patch:
            raise RuntimePolicyError("runtime policy patch must be a non-empty mapping")
        unknown = set(patch) - _ALLOWED_FIELDS
        if unknown:
            names = ", ".join(sorted(str(item) for item in unknown))
            raise RuntimePolicyError(f"runtime policy patch cannot modify fields: {names}")
        with self._lock:
            self._replay()
            base = self.effective_for_cycle(current_cycle)
            values = cast(dict[str, Any], thaw_json(cast(JsonValue, base.values)))
            values.update(dict(patch))
            result = RuntimePolicyVersion.create(
                parent_policy_id=base.policy_id,
                effective_cycle=current_cycle + 1,
                values=values,
                provider_output_limits=base.provider_output_limits,
                consumed=consumed,
            )
            amendment = RuntimePolicyAmendment.create(
                base_policy_id=base.policy_id,
                requested_cycle=current_cycle,
                kind="patch",
                patch=patch,
                rollback_target_policy_id=None,
                resulting_policy_id=result.policy_id,
                reason=reason,
            )
            return self._persist_amendment(result, amendment)

    def request_rollback(
        self,
        *,
        requested_by: Role | str,
        current_cycle: int,
        target_policy_id: str,
        consumed: Mapping[str, float | int],
        reason: str,
    ) -> RuntimePolicyAmendment:
        role = requested_by if isinstance(requested_by, Role) else Role(requested_by)
        if role is not Role.PROSECUTOR:
            raise RuntimePolicyError("only the prosecutor may roll back runtime policy")
        with self._lock:
            self._replay()
            base = self.effective_for_cycle(current_cycle)
            try:
                target = self._versions[target_policy_id]
            except KeyError as exc:
                raise RuntimePolicyError("rollback target policy is unknown") from exc
            result = RuntimePolicyVersion.create(
                parent_policy_id=base.policy_id,
                effective_cycle=current_cycle + 1,
                values=cast(Mapping[str, Any], target.values),
                provider_output_limits=target.provider_output_limits,
                consumed=consumed,
            )
            amendment = RuntimePolicyAmendment.create(
                base_policy_id=base.policy_id,
                requested_cycle=current_cycle,
                kind="rollback",
                patch={},
                rollback_target_policy_id=target.policy_id,
                resulting_policy_id=result.policy_id,
                reason=reason,
            )
            return self._persist_amendment(result, amendment)

    def freeze_for_paired_design(
        self,
        design_id: str,
        cycle: int,
        *,
        boundary: RuntimeStageBoundary | None = None,
    ) -> str:
        if not isinstance(design_id, str) or not design_id.strip():
            raise RuntimePolicyError("design_id must be non-empty")
        if boundary is not None and boundary.cycle != cycle:
            raise RuntimePolicyError("paired design boundary must belong to the requested cycle")
        with self._lock:
            self._replay()
            policy_id = (
                self.effective_for_stage(boundary).policy_id
                if boundary is not None
                else self.effective_for_cycle(cycle).policy_id
            )
            existing = self._paired_designs.get(design_id)
            if existing is not None:
                if existing != policy_id:
                    raise RuntimePolicyConflictError("paired design is already frozen to another policy")
                return existing
            sequence = self.store.max_sequence(self.campaign_id)
            try:
                self.store.append_if_sequence(
                    self.campaign_id,
                    sequence,
                    "runtime_policy_paired_design_frozen",
                    {
                        "design_id": design_id,
                        "policy_id": policy_id,
                        "cycle": cycle,
                        "boundary": boundary.to_mapping() if boundary is not None else None,
                    },
                )
            except EventStoreSequenceConflict as exc:
                self._replay()
                existing = self._paired_designs.get(design_id)
                if existing == policy_id:
                    return existing
                raise RuntimePolicyConflictError("paired design freeze raced with another writer") from exc
            self._replay()
            return policy_id

    def policy_for_paired_design(self, design_id: str) -> RuntimePolicyVersion:
        try:
            return self._versions[self._paired_designs[design_id]]
        except KeyError as exc:
            raise RuntimePolicyError("paired design has no frozen runtime policy") from exc

    def _persist_amendment(
        self, policy: RuntimePolicyVersion, amendment: RuntimePolicyAmendment
    ) -> RuntimePolicyAmendment:
        existing = self._amendments.get(amendment.requested_cycle)
        if existing is not None:
            if existing.amendment_id == amendment.amendment_id:
                return existing
            raise RuntimePolicyConflictError("a different runtime policy amendment already exists for cycle")
        if (policy.effective_cycle, 0) in self._stage_schedule:
            raise RuntimePolicyConflictError(
                "another runtime policy already becomes effective at this cycle boundary"
            )
        policy_ref = self._put_policy(policy)
        amendment_ref = self.artifacts.put_json(_AMENDMENT_KIND, amendment.to_artifact_mapping())
        if amendment_ref.artifact_id != amendment.amendment_id:
            raise RuntimePolicyIntegrityError("amendment CAS identity mismatch")
        sequence = self.store.max_sequence(self.campaign_id)
        payload = {
            "policy_ref": self._ref_mapping(policy_ref),
            "amendment_ref": self._ref_mapping(amendment_ref),
        }
        try:
            self.store.append_if_sequence(
                self.campaign_id, sequence, "runtime_policy_amendment_scheduled", payload
            )
        except EventStoreSequenceConflict as exc:
            self._replay()
            existing = self._amendments.get(amendment.requested_cycle)
            if existing is not None and existing.amendment_id == amendment.amendment_id:
                return existing
            raise RuntimePolicyConflictError("runtime policy amendment raced with another writer") from exc
        self._replay()
        return self._amendments[amendment.requested_cycle]

    def _persist_stage_amendment(
        self,
        policy: RuntimePolicyVersion,
        amendment: StageRuntimePolicyAmendment,
    ) -> StageRuntimePolicyAmendment:
        existing = self._stage_amendments.get(amendment.requested_at.key)
        if existing is not None:
            if existing.amendment_id == amendment.amendment_id:
                return existing
            raise RuntimePolicyConflictError(
                "a different runtime policy amendment already exists for stage"
            )
        if amendment.effective_at.key in self._stage_schedule or (
            amendment.effective_at.ordinal == 0
            and amendment.effective_at.cycle in self._schedule
        ):
            raise RuntimePolicyConflictError(
                "another runtime policy already becomes effective at this stage"
            )
        policy_ref = self._put_policy(policy)
        amendment_ref = self.artifacts.put_json(
            _STAGE_AMENDMENT_KIND, amendment.to_artifact_mapping()
        )
        if amendment_ref.artifact_id != amendment.amendment_id:
            raise RuntimePolicyIntegrityError("stage amendment CAS identity mismatch")
        sequence = self.store.max_sequence(self.campaign_id)
        payload = {
            "policy_ref": self._ref_mapping(policy_ref),
            "amendment_ref": self._ref_mapping(amendment_ref),
        }
        try:
            self.store.append_if_sequence(
                self.campaign_id,
                sequence,
                "runtime_policy_stage_amendment_scheduled",
                payload,
            )
        except EventStoreSequenceConflict as exc:
            self._replay()
            existing = self._stage_amendments.get(amendment.requested_at.key)
            if existing is not None and existing.amendment_id == amendment.amendment_id:
                return existing
            raise RuntimePolicyConflictError(
                "runtime policy stage amendment raced with another writer"
            ) from exc
        self._replay()
        return self._stage_amendments[amendment.requested_at.key]

    def _persist_policy(
        self,
        policy: RuntimePolicyVersion,
        event_type: str,
        amendment_ref: ArtifactRef | None,
    ) -> None:
        ref = self._put_policy(policy)
        payload: dict[str, Any] = {"policy_ref": self._ref_mapping(ref)}
        if amendment_ref is not None:
            payload["amendment_ref"] = self._ref_mapping(amendment_ref)
        sequence = self.store.max_sequence(self.campaign_id)
        try:
            self.store.append_if_sequence(self.campaign_id, sequence, event_type, payload)
        except EventStoreSequenceConflict as exc:
            raise RuntimePolicyConflictError("runtime policy write raced with another writer") from exc

    def _put_policy(self, policy: RuntimePolicyVersion) -> ArtifactRef:
        ref = self.artifacts.put_json(_POLICY_KIND, policy.to_artifact_mapping())
        if ref.artifact_id != policy.policy_id:
            raise RuntimePolicyIntegrityError("runtime policy CAS identity mismatch")
        return ref

    @staticmethod
    def _ref_mapping(ref: ArtifactRef) -> dict[str, Any]:
        return {"kind": ref.kind, "artifact_id": ref.artifact_id, "size_bytes": ref.size_bytes}

    def _load_json(self, value: object, expected_kind: str) -> Mapping[str, Any]:
        data = _strict_object(value, {"kind", "artifact_id", "size_bytes"}, "artifact ref")
        try:
            ref = ArtifactRef(data["kind"], data["artifact_id"], data["size_bytes"])
        except (TypeError, ValueError) as exc:
            raise RuntimePolicyIntegrityError("event contains an invalid artifact ref") from exc
        if ref.kind != expected_kind:
            raise RuntimePolicyIntegrityError("event artifact kind is invalid")
        import json

        try:
            loaded = json.loads(self.artifacts.get(ref))
        except (UnicodeDecodeError, ValueError) as exc:
            raise RuntimePolicyIntegrityError("runtime policy artifact is not valid JSON") from exc
        if not isinstance(loaded, Mapping):
            raise RuntimePolicyIntegrityError("runtime policy artifact must contain a JSON object")
        return loaded

    def _replay(self) -> None:
        versions: dict[str, RuntimePolicyVersion] = {}
        schedule: dict[int, str] = {}
        amendments: dict[int, RuntimePolicyAmendment] = {}
        stage_schedule: dict[
            tuple[int, int], tuple[RuntimeStageBoundary, str]
        ] = {}
        stage_amendments: dict[tuple[int, int], StageRuntimePolicyAmendment] = {}
        paired: dict[str, str] = {}
        for event in self.store.read(self.campaign_id):
            payload = thaw_json(event.payload)
            if event.event_type == "runtime_policy_genesis":
                policy = RuntimePolicyVersion.from_artifact_mapping(
                    self._load_json(payload["policy_ref"], _POLICY_KIND)
                )
                if policy.policy_id != payload["policy_ref"]["artifact_id"] or policy.effective_cycle != 0:
                    raise RuntimePolicyIntegrityError("genesis policy identity or cycle is invalid")
                if 0 in schedule and schedule[0] != policy.policy_id:
                    raise RuntimePolicyIntegrityError("multiple genesis policies exist")
                versions[policy.policy_id] = policy
                schedule[0] = policy.policy_id
            elif event.event_type == "runtime_policy_amendment_scheduled":
                policy = RuntimePolicyVersion.from_artifact_mapping(
                    self._load_json(payload["policy_ref"], _POLICY_KIND)
                )
                amendment_data = self._load_json(payload["amendment_ref"], _AMENDMENT_KIND)
                amendment = RuntimePolicyAmendment.create(
                    base_policy_id=amendment_data["base_policy_id"],
                    requested_cycle=amendment_data["requested_cycle"],
                    kind=amendment_data["kind"],
                    patch=amendment_data["patch"],
                    rollback_target_policy_id=amendment_data["rollback_target_policy_id"],
                    resulting_policy_id=amendment_data["resulting_policy_id"],
                    reason=amendment_data["reason"],
                )
                if amendment_data["requested_by"] != Role.PROSECUTOR.value:
                    raise RuntimePolicyIntegrityError("persisted amendment was not requested by prosecutor")
                if amendment.amendment_id != payload["amendment_ref"]["artifact_id"]:
                    raise RuntimePolicyIntegrityError("amendment content address is invalid")
                if policy.policy_id != payload["policy_ref"]["artifact_id"]:
                    raise RuntimePolicyIntegrityError("policy content address is invalid")
                if policy.policy_id != amendment.resulting_policy_id:
                    raise RuntimePolicyIntegrityError("amendment does not bind the resulting policy")
                if policy.parent_policy_id != amendment.base_policy_id:
                    raise RuntimePolicyIntegrityError("amendment does not bind the base policy")
                if policy.effective_cycle != amendment.effective_cycle:
                    raise RuntimePolicyIntegrityError("amendment and policy effective cycles differ")
                if amendment.requested_cycle in amendments:
                    raise RuntimePolicyIntegrityError("multiple amendments exist for one cycle")
                if policy.effective_cycle in schedule:
                    raise RuntimePolicyIntegrityError("multiple policies become effective in one cycle")
                if (policy.effective_cycle, 0) in stage_schedule:
                    raise RuntimePolicyIntegrityError(
                        "cycle and stage policies collide at one boundary"
                    )
                versions[policy.policy_id] = policy
                schedule[policy.effective_cycle] = policy.policy_id
                amendments[amendment.requested_cycle] = amendment
            elif event.event_type == "runtime_policy_stage_amendment_scheduled":
                policy = RuntimePolicyVersion.from_artifact_mapping(
                    self._load_json(payload["policy_ref"], _POLICY_KIND)
                )
                amendment_data = self._load_json(
                    payload["amendment_ref"], _STAGE_AMENDMENT_KIND
                )
                stage_amendment = StageRuntimePolicyAmendment.create(
                    base_policy_id=amendment_data["base_policy_id"],
                    requested_at=RuntimeStageBoundary.from_mapping(
                        amendment_data["requested_at"]
                    ),
                    effective_at=RuntimeStageBoundary.from_mapping(
                        amendment_data["effective_at"]
                    ),
                    kind=amendment_data["kind"],
                    patch=amendment_data["patch"],
                    rollback_target_policy_id=amendment_data[
                        "rollback_target_policy_id"
                    ],
                    resulting_policy_id=amendment_data["resulting_policy_id"],
                    reason=amendment_data["reason"],
                )
                if amendment_data["requested_by"] != Role.PROSECUTOR.value:
                    raise RuntimePolicyIntegrityError(
                        "persisted stage amendment was not requested by prosecutor"
                    )
                if stage_amendment.amendment_id != payload["amendment_ref"]["artifact_id"]:
                    raise RuntimePolicyIntegrityError(
                        "stage amendment content address is invalid"
                    )
                if policy.policy_id != payload["policy_ref"]["artifact_id"]:
                    raise RuntimePolicyIntegrityError("policy content address is invalid")
                if policy.policy_id != stage_amendment.resulting_policy_id:
                    raise RuntimePolicyIntegrityError(
                        "stage amendment does not bind the resulting policy"
                    )
                if policy.parent_policy_id != stage_amendment.base_policy_id:
                    raise RuntimePolicyIntegrityError(
                        "stage amendment does not bind the base policy"
                    )
                if policy.effective_cycle != stage_amendment.effective_at.cycle:
                    raise RuntimePolicyIntegrityError(
                        "stage amendment and policy effective cycles differ"
                    )
                if stage_amendment.base_policy_id not in versions:
                    raise RuntimePolicyIntegrityError(
                        "stage amendment references an unknown base policy"
                    )
                if stage_amendment.requested_at.key in stage_amendments:
                    raise RuntimePolicyIntegrityError(
                        "multiple amendments exist for one stage"
                    )
                if stage_amendment.effective_at.key in stage_schedule or (
                    stage_amendment.effective_at.ordinal == 0
                    and stage_amendment.effective_at.cycle in schedule
                ):
                    raise RuntimePolicyIntegrityError(
                        "multiple policies become effective at one stage"
                    )
                versions[policy.policy_id] = policy
                stage_schedule[stage_amendment.effective_at.key] = (
                    stage_amendment.effective_at,
                    policy.policy_id,
                )
                stage_amendments[stage_amendment.requested_at.key] = stage_amendment
            elif event.event_type == "runtime_policy_paired_design_frozen":
                if set(payload) not in (
                    {"design_id", "policy_id", "cycle"},
                    {"design_id", "policy_id", "cycle", "boundary"},
                ):
                    raise RuntimePolicyIntegrityError(
                        "paired design freeze has an invalid schema"
                    )
                design_id = payload.get("design_id")
                policy_id = payload.get("policy_id")
                cycle = payload.get("cycle")
                if (
                    not isinstance(design_id, str)
                    or not design_id.strip()
                    or not isinstance(policy_id, str)
                    or isinstance(cycle, bool)
                    or not isinstance(cycle, int)
                    or cycle < 0
                ):
                    raise RuntimePolicyIntegrityError("paired design freeze is malformed")
                if policy_id not in versions:
                    raise RuntimePolicyIntegrityError("paired design references an unknown policy")
                raw_boundary = payload.get("boundary")
                boundary = (
                    RuntimeStageBoundary.from_mapping(raw_boundary)
                    if raw_boundary is not None
                    else RuntimeStageBoundary(cycle, 0, "cycle-start")
                )
                if boundary.cycle != cycle:
                    raise RuntimePolicyIntegrityError(
                        "paired design boundary belongs to another cycle"
                    )
                candidates = [
                    ((item_cycle, 0), item_policy)
                    for item_cycle, item_policy in schedule.items()
                    if (item_cycle, 0) <= boundary.key
                ]
                candidates.extend(
                    (key, item_policy)
                    for key, (_, item_policy) in stage_schedule.items()
                    if key <= boundary.key
                )
                if not candidates or max(candidates, key=lambda item: item[0])[1] != policy_id:
                    raise RuntimePolicyIntegrityError(
                        "paired design did not freeze its effective runtime policy"
                    )
                if design_id in paired and paired[design_id] != policy_id:
                    raise RuntimePolicyIntegrityError("paired design has conflicting policy freezes")
                paired[design_id] = policy_id
        self._versions = versions
        self._schedule = schedule
        self._amendments = amendments
        self._stage_schedule = stage_schedule
        self._stage_amendments = stage_amendments
        self._paired_designs = paired
