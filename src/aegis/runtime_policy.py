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
_IMMEDIATE_AMENDMENT_KIND = "runtime-policy-immediate-amendment"
_COUNCIL_DECISION_KIND = "runtime-policy-council-decision"
_ROLES = frozenset(role.value for role in Role)
_LEGACY_CUMULATIVE_LIMITS = frozenset(
    {"max_cost_usd", "max_total_tokens", "max_requests", "max_rounds", "max_runtime_seconds"}
)
_LEGACY_INTEGER_LIMITS = frozenset(
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
_LEGACY_TIMEOUT_LIMITS = frozenset(
    {
        "command_timeout_seconds",
        "sealed_timeout_seconds",
        "subagent_timeout_seconds",
        "scan_timeout_seconds",
    }
)
_LEGACY_POLICY_FIELDS_V1 = frozenset(
    {
        *_LEGACY_CUMULATIVE_LIMITS,
        *_LEGACY_INTEGER_LIMITS,
        *_LEGACY_TIMEOUT_LIMITS,
        "build_timeout_seconds",
        "role_budget_shares",
        "role_max_output_tokens",
    }
)
_V2_CUMULATIVE_LIMITS = frozenset(
    {"max_total_tokens", "max_requests", "max_model_invocations", "max_active_runtime_seconds"}
)
_V2_ROLE_INTEGER_FIELDS = frozenset(
    {
        "role_max_steps",
        "role_max_output_tokens",
        "role_research_action_budgets",
        "role_max_read_bytes",
        "role_max_write_bytes",
        "role_max_tool_output_bytes",
        "role_max_search_results",
    }
)
_V2_ROLE_NUMBER_FIELDS = frozenset({"role_command_timeout_seconds"})
_V2_INTEGER_LIMITS = frozenset(
    {
        "max_total_tokens", "max_requests", "max_model_invocations",
        "gateway_max_attempts", "subagent_max_spawns_per_run", "subagent_max_steps",
        "subagent_max_result_bytes", "subagent_max_output_tokens", "subagent_max_total_tokens",
        "subagent_max_requests", "max_evolution_requests_per_run", "max_evolution_source_refs",
        "task_authoring_attempts", "task_proposals_per_cycle", "cohort_limit",
        "candidate_evaluations_per_cycle", "candidate_max_steps", "population_max_cells",
        "council_max_messages", "council_max_tokens", "task_holdout_delay_cycles",
        "objective_history_window", "objective_probation_cycles", "dependency_download_max_bytes",
    }
)
_V2_NUMBER_LIMITS = frozenset(
    {
        "max_active_runtime_seconds", "gateway_timeout_seconds", "gateway_base_delay_seconds",
        "gateway_max_delay_seconds", "subagent_timeout_seconds",
        "dependency_download_timeout_seconds", "build_timeout_seconds", "scan_timeout_seconds",
    }
)
_V2_POSITIVE_INTEGER_LIMITS = frozenset(
    {
        "max_total_tokens", "max_requests", "max_model_invocations", "gateway_max_attempts",
        "subagent_max_steps", "subagent_max_result_bytes", "subagent_max_output_tokens",
        "candidate_max_steps", "council_max_messages", "council_max_tokens",
        "task_authoring_attempts", "objective_history_window", "objective_probation_cycles",
        "dependency_download_max_bytes", "task_holdout_delay_cycles", "cohort_limit",
        "population_max_cells",
    }
)
_V2_POSITIVE_ROLE_INTEGER_FIELDS = frozenset(
    {"role_max_steps", "role_max_output_tokens", "role_max_read_bytes", "role_max_write_bytes",
     "role_max_tool_output_bytes", "role_max_search_results"}
)
_POLICY_FIELDS_V2 = frozenset(
    {
        *_V2_CUMULATIVE_LIMITS, *_V2_ROLE_INTEGER_FIELDS, *_V2_ROLE_NUMBER_FIELDS,
        *_V2_INTEGER_LIMITS, *_V2_NUMBER_LIMITS, "role_token_shares", "role_reasoning_effort",
    }
)
# The external cost envelope plus a bounded set of cycle-flow parameters: the
# runtime-policy fields the Prosecutor may adjust (with council ratification).
# Flow bounds keep the adjustments inside sane operating ranges; everything
# else remains a fixed safety constant or inert legacy value.
_ENVELOPE_FIELDS = frozenset(
    {"max_total_tokens", "max_requests", "max_model_invocations", "max_active_runtime_seconds"}
)
_FLOW_FIELD_BOUNDS: Mapping[str, tuple[int, int]] = {
    "cohort_limit": (1, 12),
    "task_authoring_attempts": (1, 4),
    "task_proposals_per_cycle": (1, 8),
    "candidate_max_steps": (4, 128),
    "council_max_messages": (2, 64),
}
# Backwards-compatible name used by the legacy amendment reader.
_ALLOWED_FIELDS = _LEGACY_POLICY_FIELDS_V1
_CUMULATIVE_LIMITS = _LEGACY_CUMULATIVE_LIMITS | _V2_CUMULATIVE_LIMITS
_INTEGER_LIMITS = _LEGACY_INTEGER_LIMITS
_TIMEOUT_LIMITS = _LEGACY_TIMEOUT_LIMITS
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
        raise RuntimePolicyError(f"{name} must sum to 1")
    return result


def _validate_role_nonnegative_integers(value: object, name: str) -> dict[str, int]:
    if not isinstance(value, Mapping) or set(value) != _ROLES:
        raise RuntimePolicyError(f"{name} must define exactly warrior, judge, and prosecutor")
    result: dict[str, int] = {}
    for role, raw in value.items():
        if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
            raise RuntimePolicyError(f"{name}.{role} must be a non-negative integer")
        result[cast(str, role)] = raw
    return result


def _validate_role_positive_numbers(value: object, name: str) -> dict[str, float]:
    if not isinstance(value, Mapping) or set(value) != _ROLES:
        raise RuntimePolicyError(f"{name} must define exactly warrior, judge, and prosecutor")
    return {
        cast(str, role): _positive_number(raw, f"{name}.{role}")
        for role, raw in value.items()
    }


def _validate_role_reasoning(value: object) -> dict[str, str | None]:
    if not isinstance(value, Mapping) or set(value) != _ROLES:
        raise RuntimePolicyError("role_reasoning_effort must define exactly all roles")
    allowed = {None, "none", "low", "medium", "high", "max"}
    result = dict(value)
    if any(item not in allowed for item in result.values()):
        raise RuntimePolicyError("role_reasoning_effort contains an unsupported value")
    return cast(dict[str, str | None], result)


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


def _validate_values_v1(
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


def _validate_values_v2(
    value: object, provider_output_limits: Mapping[str, int]
) -> Mapping[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise RuntimePolicyError("runtime policy values must be a mapping")
    unknown = set(value) - _POLICY_FIELDS_V2
    if unknown:
        names = ", ".join(sorted(str(item) for item in unknown))
        if any(term in str(item).lower() for item in unknown for term in _HOST_SAFETY_TERMS):
            raise RuntimePolicyError(f"host safety and resource-envelope fields are immutable: {names}")
        raise RuntimePolicyError(f"runtime policy contains unsupported fields: {names}")
    missing = _POLICY_FIELDS_V2 - set(value)
    if missing:
        raise RuntimePolicyError(f"runtime policy is missing fields: {', '.join(sorted(missing))}")

    normalized: dict[str, Any] = {}
    # Zero is meaningful for count budgets: it disables the corresponding action.
    for name in _V2_INTEGER_LIMITS:
        raw = value[name]
        if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
            raise RuntimePolicyError(f"{name} must be a non-negative integer")
        if name in _V2_POSITIVE_INTEGER_LIMITS and raw == 0:
            raise RuntimePolicyError(f"{name} must be positive")
        if name == "candidate_evaluations_per_cycle" and raw > 1:
            raise RuntimePolicyError(
                "candidate_evaluations_per_cycle is a bidirectional 0/1 control; "
                "the cycle state machine records one paired evaluation artifact"
            )
        normalized[name] = raw
    for name in _V2_NUMBER_LIMITS:
        normalized[name] = _positive_number(value[name], name)
    for name in _V2_ROLE_INTEGER_FIELDS:
        raw_values = _validate_role_nonnegative_integers(value[name], name)
        if name in _V2_POSITIVE_ROLE_INTEGER_FIELDS and any(raw == 0 for raw in raw_values.values()):
            raise RuntimePolicyError(f"{name} values must be positive")
        if name == "role_max_output_tokens":
            for role, output in raw_values.items():
                if output > provider_output_limits[role]:
                    raise RuntimePolicyError(
                        f"role_max_output_tokens.{role} exceeds the provider output profile"
                    )
        normalized[name] = raw_values
    for name in _V2_ROLE_NUMBER_FIELDS:
        normalized[name] = _validate_role_positive_numbers(value[name], name)
    normalized["role_token_shares"] = _validate_role_numbers(
        value["role_token_shares"], "role_token_shares", shares=True
    )
    normalized["role_reasoning_effort"] = _validate_role_reasoning(
        value["role_reasoning_effort"]
    )
    if normalized["gateway_max_delay_seconds"] < normalized["gateway_base_delay_seconds"]:
        raise RuntimePolicyError("gateway_max_delay_seconds must be at least gateway_base_delay_seconds")
    return cast(Mapping[str, JsonValue], freeze_json(normalized))


def _validate_values(
    value: object, provider_output_limits: Mapping[str, int], *, schema_version: int = 1
) -> Mapping[str, JsonValue]:
    if schema_version == 1:
        return _validate_values_v1(value, provider_output_limits)
    if schema_version == 2:
        return _validate_values_v2(value, provider_output_limits)
    raise RuntimePolicyError(f"unsupported runtime policy schema version: {schema_version}")


def _validate_consumed(value: Mapping[str, Any]) -> Mapping[str, Any]:
    unknown = set(value) - (_CUMULATIVE_LIMITS | {"role_tokens"})
    if unknown:
        raise RuntimePolicyError(f"consumed contains unsupported fields: {', '.join(sorted(unknown))}")
    result: dict[str, Any] = {}
    for name, raw in value.items():
        if name == "role_tokens":
            if not isinstance(raw, Mapping) or set(raw) != _ROLES:
                raise RuntimePolicyError("consumed.role_tokens must define exactly all roles")
            role_tokens: dict[str, float] = {}
            for role, amount in raw.items():
                if isinstance(amount, bool) or not isinstance(amount, (int, float)) or not math.isfinite(float(amount)) or float(amount) < 0:
                    raise RuntimePolicyError(f"consumed.role_tokens.{role} must be finite and non-negative")
                role_tokens[cast(str, role)] = float(amount)
            result["role_tokens"] = MappingProxyType(role_tokens)
            continue
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


def _v2_matches_v1(v2: Mapping[str, JsonValue], v1: Mapping[str, JsonValue]) -> bool:
    """Compare only historical semantics; removed cost/sealed controls are not migrated."""
    role_steps = cast(Mapping[str, Any], v2["role_max_steps"])
    role_timeouts = cast(Mapping[str, Any], v2["role_command_timeout_seconds"])
    if len(set(role_steps.values())) != 1 or len(set(role_timeouts.values())) != 1:
        return False
    projection = {
        "max_total_tokens": v2["max_total_tokens"],
        "max_requests": v2["max_requests"],
        "max_rounds": v2["max_model_invocations"],
        "max_runtime_seconds": v2["max_active_runtime_seconds"],
        "role_budget_shares": v2["role_token_shares"],
        "role_max_output_tokens": v2["role_max_output_tokens"],
        "max_steps": next(iter(role_steps.values())),
        "candidate_max_extra_steps": v2["candidate_max_steps"],
        "subagent_max_steps": v2["subagent_max_steps"],
        "command_timeout_seconds": next(iter(role_timeouts.values())),
        "subagent_timeout_seconds": v2["subagent_timeout_seconds"],
        "build_timeout_seconds": v2["build_timeout_seconds"],
        "scan_timeout_seconds": v2["scan_timeout_seconds"],
        "council_max_messages": v2["council_max_messages"],
        "council_max_tokens": v2["council_max_tokens"],
    }
    return all(v1.get(name) == value for name, value in projection.items())


def _overlay_v1_on_v2(
    v2: Mapping[str, JsonValue], v1: Mapping[str, JsonValue]
) -> dict[str, Any]:
    result = cast(dict[str, Any], thaw_json(cast(JsonValue, v2)))
    result.update(
        {
            "max_total_tokens": v1["max_total_tokens"],
            "max_requests": v1["max_requests"],
            "max_model_invocations": v1["max_rounds"],
            "max_active_runtime_seconds": v1["max_runtime_seconds"],
            "role_token_shares": thaw_json(v1["role_budget_shares"]),
            "role_max_output_tokens": thaw_json(v1["role_max_output_tokens"]),
            "role_max_steps": {role: v1["max_steps"] for role in _ROLES},
            "role_command_timeout_seconds": {
                role: v1["command_timeout_seconds"] for role in _ROLES
            },
            "candidate_max_steps": v1["candidate_max_extra_steps"],
            "subagent_max_steps": v1["subagent_max_steps"],
            "subagent_timeout_seconds": v1["subagent_timeout_seconds"],
            "build_timeout_seconds": v1["build_timeout_seconds"],
            "scan_timeout_seconds": v1["scan_timeout_seconds"],
            "council_max_messages": v1["council_max_messages"],
            "council_max_tokens": v1["council_max_tokens"],
        }
    )
    return result


@dataclass(frozen=True, slots=True)
class RuntimePolicyVersion:
    policy_id: str
    schema_version: int
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
        consumed: Mapping[str, Any] | None = None,
        schema_version: int | None = None,
    ) -> RuntimePolicyVersion:
        if isinstance(effective_cycle, bool) or not isinstance(effective_cycle, int) or effective_cycle < 0:
            raise RuntimePolicyError("effective_cycle must be a non-negative integer")
        limits = MappingProxyType(_validate_provider_limits(provider_output_limits))
        if schema_version is None:
            schema_version = 1 if set(values) == _LEGACY_POLICY_FIELDS_V1 else 2
        if schema_version not in {1, 2}:
            raise RuntimePolicyError("runtime policy schema version must be 1 or 2")
        normalized = _validate_values(values, limits, schema_version=schema_version)
        usage = _validate_consumed(consumed or {})
        reason_items = [
            name for name, amount in usage.items()
            if name in normalized and float(cast(float | int, normalized[name])) < amount
        ]
        # Per-role token shares are inert legacy values: they are neither
        # enforced by the ledger nor a maintenance trigger. Only the single
        # campaign cost envelope can force maintenance mode.
        reasons = tuple(sorted(reason_items))
        material: dict[str, Any] = {
            "parent_policy_id": parent_policy_id,
            "effective_cycle": effective_cycle,
            "values": thaw_json(cast(JsonValue, normalized)),
            "provider_output_limits": dict(limits),
            "maintenance_only": bool(reasons),
            "maintenance_reasons": list(reasons),
        }
        if schema_version == 2:
            material = {"schema_version": 2, **material}
        return cls(
            _content_id(_POLICY_KIND, material),
            schema_version,
            parent_policy_id,
            effective_cycle,
            normalized,
            limits,
            bool(reasons),
            reasons,
        )

    @classmethod
    def from_artifact_mapping(cls, value: object) -> RuntimePolicyVersion:
        if not isinstance(value, Mapping):
            raise RuntimePolicyIntegrityError("runtime policy artifact has an invalid schema")
        schema_version = value.get("schema_version", 1)
        if schema_version not in {1, 2}:
            raise RuntimePolicyIntegrityError("unsupported runtime policy schema version")
        fields = {
            "parent_policy_id", "effective_cycle", "values", "provider_output_limits",
            "maintenance_only", "maintenance_reasons",
        }
        if schema_version == 2:
            fields.add("schema_version")
        data = _strict_object(
            value,
            fields,
            "runtime policy artifact",
        )
        reasons = data["maintenance_reasons"]
        if not isinstance(reasons, list) or any(not isinstance(item, str) for item in reasons):
            raise RuntimePolicyIntegrityError("maintenance_reasons must be a string list")
        if any(
            item not in _CUMULATIVE_LIMITS and not item.startswith("role_token_shares.")
            for item in reasons
        ) or reasons != sorted(set(reasons)):
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
        values = _validate_values(data["values"], limits, schema_version=cast(int, schema_version))
        material = {
            "parent_policy_id": parent,
            "effective_cycle": effective_cycle,
            "values": thaw_json(cast(JsonValue, values)),
            "provider_output_limits": dict(limits),
            "maintenance_only": maintenance_only,
            "maintenance_reasons": reasons,
        }
        if schema_version == 2:
            material = {"schema_version": 2, **material}
        return cls(
            _content_id(_POLICY_KIND, material),
            cast(int, schema_version),
            parent,
            effective_cycle,
            values,
            limits,
            maintenance_only,
            tuple(reasons),
        )

    def to_artifact_mapping(self) -> dict[str, Any]:
        result = {
            "parent_policy_id": self.parent_policy_id,
            "effective_cycle": self.effective_cycle,
            "values": thaw_json(cast(JsonValue, self.values)),
            "provider_output_limits": dict(self.provider_output_limits),
            "maintenance_only": self.maintenance_only,
            "maintenance_reasons": list(self.maintenance_reasons),
        }
        if self.schema_version == 2:
            return {"schema_version": 2, **result}
        return result

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


@dataclass(frozen=True, slots=True)
class ImmediateRuntimePolicyAmendment:
    amendment_id: str
    request_id: str
    base_policy_id: str
    requested_at: RuntimeStageBoundary
    revision: int
    requested_by: Role
    kind: str
    patch: Mapping[str, JsonValue]
    rollback_target_policy_id: str | None
    resulting_policy_id: str
    reason: str
    evidence_refs: tuple[str, ...]

    @classmethod
    def create(cls, *, request_id: str, base_policy_id: str,
               requested_at: RuntimeStageBoundary, revision: int, kind: str,
               patch: Mapping[str, Any], rollback_target_policy_id: str | None,
               resulting_policy_id: str, reason: str,
               evidence_refs: tuple[str, ...] = ()) -> "ImmediateRuntimePolicyAmendment":
        if kind not in {"patch", "rollback"}:
            raise RuntimePolicyError("immediate amendment kind must be patch or rollback")
        if not isinstance(request_id, str) or not request_id.strip():
            raise RuntimePolicyError("request_id must be non-empty")
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
            raise RuntimePolicyError("revision must be a positive integer")
        if not isinstance(reason, str) or not reason.strip() or reason != reason.strip():
            raise RuntimePolicyError("amendment reason must be trimmed non-empty text")
        if any(not isinstance(item, str) or not item.strip() for item in evidence_refs):
            raise RuntimePolicyError("evidence_refs must contain non-empty text")
        frozen_patch = cast(Mapping[str, JsonValue], freeze_json(patch))
        material = {
            "request_id": request_id, "base_policy_id": base_policy_id,
            "requested_at": requested_at.to_mapping(), "revision": revision,
            "requested_by": Role.PROSECUTOR.value, "kind": kind,
            "patch": thaw_json(cast(JsonValue, frozen_patch)),
            "rollback_target_policy_id": rollback_target_policy_id,
            "resulting_policy_id": resulting_policy_id, "reason": reason,
            "evidence_refs": list(evidence_refs),
        }
        return cls(_content_id(_IMMEDIATE_AMENDMENT_KIND, material), request_id,
                   base_policy_id, requested_at, revision, Role.PROSECUTOR, kind,
                   frozen_patch, rollback_target_policy_id, resulting_policy_id,
                   reason, evidence_refs)

    def to_artifact_mapping(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id, "base_policy_id": self.base_policy_id,
            "requested_at": self.requested_at.to_mapping(), "revision": self.revision,
            "requested_by": self.requested_by.value, "kind": self.kind,
            "patch": thaw_json(cast(JsonValue, self.patch)),
            "rollback_target_policy_id": self.rollback_target_policy_id,
            "resulting_policy_id": self.resulting_policy_id, "reason": self.reason,
            "evidence_refs": list(self.evidence_refs),
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
        self._immediate_amendments: list[ImmediateRuntimePolicyAmendment] = []
        self._council_decisions: dict[str, Mapping[str, JsonValue]] = {}
        self._migration_policy_id: str | None = None
        self._paired_designs: dict[str, str] = {}
        self._maintenance_armed: dict[RuntimeStageBoundary, str] = {}
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
                historical = self._versions[existing]
                if historical.schema_version == 1 and candidate.schema_version == 2:
                    if self._migration_policy_id is not None:
                        migrated = self._versions[self._migration_policy_id]
                        base_id = migrated.parent_policy_id
                        if base_id is None:
                            raise RuntimePolicyIntegrityError("v2 migration has no v1 parent")
                        expected_values = freeze_json(
                            _overlay_v1_on_v2(candidate.values, self._versions[base_id].values)
                        )
                        if migrated.values != expected_values:
                            raise RuntimePolicyConflictError("campaign already has another v2 migration")
                        return migrated
                    latest_cycle = max(
                        [*self._schedule, *(key[0] for key in self._stage_schedule)],
                        default=0,
                    )
                    historical = self.latest_for_cycle(latest_cycle)
                    if historical.schema_version != 1:
                        raise RuntimePolicyConflictError(
                            "campaign has an unsupported policy lineage before v2 migration"
                        )
                    migrated_values = _overlay_v1_on_v2(candidate.values, historical.values)
                    migrated = RuntimePolicyVersion.create(
                        parent_policy_id=historical.policy_id,
                        effective_cycle=historical.effective_cycle,
                        values=migrated_values,
                        provider_output_limits=candidate.provider_output_limits,
                        schema_version=2,
                    )
                    if not _v2_matches_v1(migrated.values, historical.values):
                        raise RuntimePolicyConflictError(
                            "v2 migration does not preserve the latest historical v1 semantics"
                        )
                    self._persist_migration(migrated, historical.policy_id)
                    self._replay()
                    return self._versions[migrated.policy_id]
                raise RuntimePolicyConflictError("campaign already has a different genesis policy")
            self._persist_policy(candidate, "runtime_policy_genesis", None)
            self._replay()
            return self._versions[candidate.policy_id]

    def effective_for_cycle(self, cycle: int) -> RuntimePolicyVersion:
        if isinstance(cycle, bool) or not isinstance(cycle, int) or cycle < 0:
            raise RuntimePolicyError("cycle must be a non-negative integer")
        candidates = [
            ((item_cycle, 0, 0), policy_id)
            for item_cycle, policy_id in self._schedule.items()
            if item_cycle <= cycle
        ]
        candidates.extend(
            ((boundary.cycle, boundary.ordinal, 0), policy_id)
            for boundary, policy_id in self._maintenance_armed.items()
            if boundary.cycle <= cycle
        )
        migration = self._migration_candidate()
        if migration is not None and migration[0][0] <= cycle:
            candidates.append(migration)
        if not candidates:
            raise RuntimePolicyError("runtime policy genesis has not been initialized")
        return self._versions[max(candidates, key=lambda item: item[0])[1]]

    def _migration_candidate(self) -> tuple[tuple[int, int, int], str] | None:
        if self._migration_policy_id is None:
            return None
        migrated = self._versions[self._migration_policy_id]
        parent_id = migrated.parent_policy_id
        positions: list[tuple[int, int, int]] = [
            (cycle, 0, 0)
            for cycle, policy_id in self._schedule.items()
            if policy_id == parent_id
        ]
        positions.extend(
            (key[0], key[1], 0)
            for key, (_boundary, policy_id) in self._stage_schedule.items()
            if policy_id == parent_id
        )
        positions.extend(
            (item.requested_at.cycle, item.requested_at.ordinal, item.revision)
            for item in self._immediate_amendments
            if item.resulting_policy_id == parent_id
        )
        if not positions:
            raise RuntimePolicyIntegrityError("v2 migration parent has no execution position")
        cycle, ordinal, revision = max(positions)
        return ((cycle, ordinal, revision + 1), self._migration_policy_id)

    def latest_for_cycle(self, cycle: int) -> RuntimePolicyVersion:
        """Return the latest revision reached in ``cycle`` without inventing a boundary."""
        candidates: list[tuple[tuple[int, int, int], str]] = [
            ((item_cycle, 0, 0), policy_id)
            for item_cycle, policy_id in self._schedule.items()
            if item_cycle <= cycle
        ]
        candidates.extend(
            ((boundary.cycle, boundary.ordinal, 0), policy_id)
            for boundary, policy_id in self._maintenance_armed.items()
            if boundary.cycle <= cycle
        )
        candidates.extend(
            ((key[0], key[1], 0), policy_id)
            for key, (_boundary, policy_id) in self._stage_schedule.items()
            if key[0] <= cycle
        )
        migration = self._migration_candidate()
        if migration is not None:
            candidates.append(migration)
        candidates.extend(
            ((item.requested_at.cycle, item.requested_at.ordinal, item.revision), item.resulting_policy_id)
            for item in self._immediate_amendments
            if item.requested_at.cycle <= cycle
        )
        if not candidates:
            raise RuntimePolicyError("runtime policy genesis has not been initialized")
        return self._versions[max(candidates, key=lambda item: item[0])[1]]

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
        candidates: list[tuple[tuple[int, int, int], str]] = [
            ((cycle, 0, 0), policy_id)
            for cycle, policy_id in self._schedule.items()
            if (cycle, 0) <= boundary.key
        ]
        candidates.extend(
            ((key[0], key[1], 0), policy_id)
            for key, (_, policy_id) in self._stage_schedule.items()
            if key <= boundary.key
        )
        migration = self._migration_candidate()
        if migration is not None and migration[0][:2] <= boundary.key:
            candidates.append(migration)
        candidates.extend(
            (
                (item.requested_at.cycle, item.requested_at.ordinal, item.revision),
                item.resulting_policy_id,
            )
            for item in self._immediate_amendments
            if item.requested_at.key <= boundary.key
        )
        candidates.extend(
            ((armed.cycle, armed.ordinal, 0), policy_id)
            for armed, policy_id in self._maintenance_armed.items()
            if armed.key <= boundary.key
        )
        if not candidates:
            raise RuntimePolicyError("runtime policy genesis has not been initialized")
        return self._versions[max(candidates, key=lambda item: item[0])[1]]

    @property
    def immediate_amendments(self) -> tuple[ImmediateRuntimePolicyAmendment, ...]:
        return tuple(self._immediate_amendments)

    def pending_council_amendments(self) -> tuple[ImmediateRuntimePolicyAmendment, ...]:
        return tuple(
            item for item in self._immediate_amendments
            if item.amendment_id not in self._council_decisions
        )

    def record_council_decision(
        self, *, amendment_id: str, decision: str, reason: str,
        replacement_amendment_id: str | None = None,
    ) -> Mapping[str, JsonValue]:
        if decision not in {"ratify", "revise", "rollback"}:
            raise RuntimePolicyError("council decision must be ratify, revise, or rollback")
        if not isinstance(reason, str) or not reason.strip() or reason != reason.strip():
            raise RuntimePolicyError("council decision reason must be trimmed non-empty text")
        with self._lock:
            self._replay()
            amendment_ids = {item.amendment_id for item in self._immediate_amendments}
            if amendment_id not in amendment_ids:
                raise RuntimePolicyError("council decision references an unknown amendment")
            if decision == "ratify" and replacement_amendment_id is not None:
                raise RuntimePolicyError("ratification cannot name a replacement amendment")
            if decision in {"revise", "rollback"} and replacement_amendment_id not in amendment_ids:
                raise RuntimePolicyError("revision or rollback must name an applied replacement amendment")
            if decision in {"revise", "rollback"}:
                original_index = next(
                    index for index, item in enumerate(self._immediate_amendments)
                    if item.amendment_id == amendment_id
                )
                replacement_index = next(
                    index for index, item in enumerate(self._immediate_amendments)
                    if item.amendment_id == replacement_amendment_id
                )
                if replacement_index <= original_index:
                    raise RuntimePolicyError("replacement amendment must be a later causal revision")
            material: dict[str, Any] = {
                "amendment_id": amendment_id, "decision": decision, "reason": reason,
                "replacement_amendment_id": replacement_amendment_id,
            }
            decision_id = _content_id(_COUNCIL_DECISION_KIND, material)
            record = cast(Mapping[str, JsonValue], freeze_json({"decision_id": decision_id, **material}))
            existing = self._council_decisions.get(amendment_id)
            if existing is not None:
                if existing == record:
                    return existing
                raise RuntimePolicyConflictError("amendment already has another council decision")
            ref = self.artifacts.put_json(_COUNCIL_DECISION_KIND, material)
            if ref.artifact_id != decision_id:
                raise RuntimePolicyIntegrityError("council decision CAS identity mismatch")
            sequence = self.store.max_sequence(self.campaign_id)
            self.store.append_if_sequence(
                self.campaign_id, sequence, "runtime_policy_council_decided",
                {"decision_ref": self._ref_mapping(ref)},
            )
            self._replay()
            return self._council_decisions[amendment_id]

    def arm_maintenance(
        self,
        *,
        requested_at: RuntimeStageBoundary,
        consumed: Mapping[str, Any],
        reason: str,
    ) -> RuntimePolicyVersion:
        """Persist a maintenance-only policy when consumed usage exceeds limits.

        The armed policy keeps the current values but records the already-consumed
        usage, so the runtime ledger switches to maintenance authorization until
        the Prosecutor applies a compensating amendment that restores a viable
        budget.
        """
        if not isinstance(reason, str) or not reason.strip() or reason != reason.strip():
            raise RuntimePolicyError("maintenance reason must be trimmed non-empty text")
        with self._lock:
            self._replay()
            existing = self._maintenance_armed.get(requested_at)
            if existing is not None:
                return self._versions[existing]
            base = self.effective_for_stage(requested_at)
            if base.schema_version != 2:
                raise RuntimePolicyError("maintenance arming requires a v2 runtime policy")
            policy = RuntimePolicyVersion.create(
                parent_policy_id=base.policy_id,
                effective_cycle=requested_at.cycle,
                values=base.values,
                provider_output_limits=base.provider_output_limits,
                consumed=consumed,
                schema_version=2,
            )
            if not policy.maintenance_only:
                raise RuntimePolicyError(
                    "maintenance arming requires consumed usage above policy limits"
                )
            ref = self._put_policy(policy)
            payload = {
                "policy_ref": self._ref_mapping(ref),
                "requested_at": requested_at.to_mapping(),
            }
            sequence = self.store.max_sequence(self.campaign_id)
            try:
                self.store.append_if_sequence(
                    self.campaign_id,
                    sequence,
                    "runtime_policy_maintenance_armed",
                    payload,
                )
            except EventStoreSequenceConflict as exc:
                self._replay()
                existing = self._maintenance_armed.get(requested_at)
                if existing is not None and existing == policy.policy_id:
                    return self._versions[existing]
                raise RuntimePolicyConflictError(
                    "runtime policy maintenance arming raced with another writer"
                ) from exc
            self._replay()
            return self._versions[policy.policy_id]

    def request_patch_immediately(
        self, *, requested_by: Role | str, requested_at: RuntimeStageBoundary,
        request_id: str, patch: Mapping[str, Any], consumed: Mapping[str, Any],
        reason: str, evidence_refs: tuple[str, ...] = (),
        base_policy_id: str | None = None,
    ) -> ImmediateRuntimePolicyAmendment:
        role = requested_by if isinstance(requested_by, Role) else Role(requested_by)
        if role is not Role.PROSECUTOR:
            raise RuntimePolicyError("only the prosecutor may amend runtime policy")
        if not isinstance(patch, Mapping) or not patch:
            raise RuntimePolicyError("runtime policy patch must be a non-empty mapping")
        unknown = set(patch) - _ENVELOPE_FIELDS - set(_FLOW_FIELD_BOUNDS)
        if unknown:
            raise RuntimePolicyError(
                f"runtime policy patch cannot modify fields: {', '.join(sorted(map(str, unknown)))}"
            )
        for name, raw in patch.items():
            if name in _FLOW_FIELD_BOUNDS:
                bounds = _FLOW_FIELD_BOUNDS[name]
                if isinstance(raw, bool) or not isinstance(raw, int) or not bounds[0] <= raw <= bounds[1]:
                    raise RuntimePolicyError(
                        f"{name} must be an integer in [{bounds[0]},{bounds[1]}]"
                    )
        with self._lock:
            self._replay()
            duplicate = next((item for item in self._immediate_amendments if item.request_id == request_id), None)
            if duplicate is not None:
                if (
                    duplicate.kind == "patch"
                    and duplicate.requested_at == requested_at
                    and duplicate.base_policy_id == base_policy_id
                    and thaw_json(cast(JsonValue, duplicate.patch)) == dict(patch)
                    and duplicate.reason == reason
                    and duplicate.evidence_refs == evidence_refs
                ):
                    return duplicate
                raise RuntimePolicyConflictError("request_id already identifies another amendment request")
            base = self.effective_for_stage(requested_at)
            if base_policy_id is not None and base.policy_id != base_policy_id:
                raise RuntimePolicyConflictError("base_policy_id is stale")
            if base.schema_version != 2:
                raise RuntimePolicyError("immediate amendments require a v2 runtime policy")
            values = cast(dict[str, Any], thaw_json(cast(JsonValue, base.values)))
            for name, raw in patch.items():
                if values.get(name) == raw:
                    continue
                values[name] = raw
            if values == thaw_json(cast(JsonValue, base.values)):
                raise RuntimePolicyError("runtime policy patch is a no-op")
            result = RuntimePolicyVersion.create(
                parent_policy_id=base.policy_id, effective_cycle=requested_at.cycle,
                values=values, provider_output_limits=base.provider_output_limits,
                consumed=consumed, schema_version=2,
            )
            revision = 1 + sum(item.requested_at.key == requested_at.key for item in self._immediate_amendments)
            amendment = ImmediateRuntimePolicyAmendment.create(
                request_id=request_id, base_policy_id=base.policy_id,
                requested_at=requested_at, revision=revision, kind="patch", patch=patch,
                rollback_target_policy_id=None, resulting_policy_id=result.policy_id,
                reason=reason, evidence_refs=evidence_refs,
            )
            return self._persist_immediate_amendment(result, amendment)

    def request_rollback_immediately(
        self, *, requested_by: Role | str, requested_at: RuntimeStageBoundary,
        request_id: str, target_policy_id: str, consumed: Mapping[str, Any],
        reason: str, evidence_refs: tuple[str, ...] = (),
        base_policy_id: str | None = None,
    ) -> ImmediateRuntimePolicyAmendment:
        role = requested_by if isinstance(requested_by, Role) else Role(requested_by)
        if role is not Role.PROSECUTOR:
            raise RuntimePolicyError("only the prosecutor may roll back runtime policy")
        with self._lock:
            self._replay()
            duplicate = next((item for item in self._immediate_amendments if item.request_id == request_id), None)
            if duplicate is not None:
                if (
                    duplicate.kind == "rollback"
                    and duplicate.requested_at == requested_at
                    and duplicate.base_policy_id == base_policy_id
                    and duplicate.rollback_target_policy_id == target_policy_id
                    and duplicate.reason == reason
                    and duplicate.evidence_refs == evidence_refs
                ):
                    return duplicate
                raise RuntimePolicyConflictError("request_id already identifies another amendment request")
            base = self.effective_for_stage(requested_at)
            if base_policy_id is not None and base.policy_id != base_policy_id:
                raise RuntimePolicyConflictError("base_policy_id is stale")
            try:
                target = self._versions[target_policy_id]
            except KeyError as exc:
                raise RuntimePolicyError("rollback target policy is unknown") from exc
            if target.schema_version != 2:
                raise RuntimePolicyError("immediate rollback target must use schema v2")
            result = RuntimePolicyVersion.create(
                parent_policy_id=base.policy_id, effective_cycle=requested_at.cycle,
                values=cast(Mapping[str, Any], target.values),
                provider_output_limits=target.provider_output_limits, consumed=consumed,
                schema_version=2,
            )
            revision = 1 + sum(item.requested_at.key == requested_at.key for item in self._immediate_amendments)
            amendment = ImmediateRuntimePolicyAmendment.create(
                request_id=request_id, base_policy_id=base.policy_id,
                requested_at=requested_at, revision=revision, kind="rollback", patch={},
                rollback_target_policy_id=target.policy_id, resulting_policy_id=result.policy_id,
                reason=reason, evidence_refs=evidence_refs,
            )
            return self._persist_immediate_amendment(result, amendment)

    def resume_stage_boundary(self, cycle: int) -> RuntimeStageBoundary:
        """Return a boundary strictly after all persisted policy activity in a cycle."""
        if isinstance(cycle, bool) or not isinstance(cycle, int) or cycle < 0:
            raise RuntimePolicyError("cycle must be a non-negative integer")
        matches = [
            boundary
            for (scheduled_cycle, _ordinal), (boundary, _policy_id) in self._stage_schedule.items()
            if scheduled_cycle == cycle
        ]
        matches.extend(
            item.requested_at
            for item in self._immediate_amendments
            if item.requested_at.cycle == cycle
        )
        matches.extend(
            boundary for boundary in self._maintenance_armed if boundary.cycle == cycle
        )
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
        consumed: Mapping[str, Any],
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
        consumed: Mapping[str, Any],
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
        consumed: Mapping[str, Any],
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
        consumed: Mapping[str, Any],
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

    def _persist_migration(self, policy: RuntimePolicyVersion, base_policy_id: str) -> None:
        ref = self._put_policy(policy)
        sequence = self.store.max_sequence(self.campaign_id)
        try:
            self.store.append_if_sequence(
                self.campaign_id,
                sequence,
                "runtime_policy_migrated_v2",
                {"policy_ref": self._ref_mapping(ref), "base_policy_id": base_policy_id},
            )
        except EventStoreSequenceConflict as exc:
            self._replay()
            if self._migration_policy_id == policy.policy_id:
                return
            raise RuntimePolicyConflictError("runtime policy migration raced with another writer") from exc

    def _persist_immediate_amendment(
        self, policy: RuntimePolicyVersion, amendment: ImmediateRuntimePolicyAmendment
    ) -> ImmediateRuntimePolicyAmendment:
        existing = next(
            (item for item in self._immediate_amendments if item.request_id == amendment.request_id),
            None,
        )
        if existing is not None:
            if existing.amendment_id == amendment.amendment_id:
                return existing
            raise RuntimePolicyConflictError("request_id already identifies another amendment")
        policy_ref = self._put_policy(policy)
        amendment_ref = self.artifacts.put_json(
            _IMMEDIATE_AMENDMENT_KIND, amendment.to_artifact_mapping()
        )
        if amendment_ref.artifact_id != amendment.amendment_id:
            raise RuntimePolicyIntegrityError("immediate amendment CAS identity mismatch")
        sequence = self.store.max_sequence(self.campaign_id)
        try:
            self.store.append_if_sequence(
                self.campaign_id, sequence, "runtime_policy_immediate_amendment_applied",
                {"policy_ref": self._ref_mapping(policy_ref),
                 "amendment_ref": self._ref_mapping(amendment_ref)},
            )
        except EventStoreSequenceConflict as exc:
            self._replay()
            existing = next(
                (item for item in self._immediate_amendments if item.request_id == amendment.request_id),
                None,
            )
            if existing is not None and existing.amendment_id == amendment.amendment_id:
                return existing
            raise RuntimePolicyConflictError("immediate amendment raced with another writer") from exc
        self._replay()
        return next(
            item for item in self._immediate_amendments if item.request_id == amendment.request_id
        )

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
        immediate_amendments: list[ImmediateRuntimePolicyAmendment] = []
        council_decisions: dict[str, Mapping[str, JsonValue]] = {}
        maintenance_armed: dict[RuntimeStageBoundary, str] = {}
        migration_policy_id: str | None = None
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
            elif event.event_type == "runtime_policy_migrated_v2":
                policy = RuntimePolicyVersion.from_artifact_mapping(
                    self._load_json(payload["policy_ref"], _POLICY_KIND)
                )
                base_policy_id = payload.get("base_policy_id")
                if (
                    policy.schema_version != 2
                    or policy.policy_id != payload["policy_ref"]["artifact_id"]
                    or policy.parent_policy_id != base_policy_id
                    or base_policy_id not in versions
                    or versions[cast(str, base_policy_id)].schema_version != 1
                    or migration_policy_id is not None
                ):
                    raise RuntimePolicyIntegrityError("runtime policy v2 migration is invalid")
                base = versions[cast(str, base_policy_id)]
                positions: list[tuple[tuple[int, int, int], str]] = [
                    ((item_cycle, 0, 0), item_policy)
                    for item_cycle, item_policy in schedule.items()
                ]
                positions.extend(
                    ((key[0], key[1], 0), item_policy)
                    for key, (_boundary, item_policy) in stage_schedule.items()
                )
                positions.extend(
                    (
                        (item.requested_at.cycle, item.requested_at.ordinal, item.revision),
                        item.resulting_policy_id,
                    )
                    for item in immediate_amendments
                )
                if (
                    not positions
                    or max(positions, key=lambda item: item[0])[1] != base_policy_id
                    or policy.effective_cycle != base.effective_cycle
                    or not _v2_matches_v1(policy.values, base.values)
                ):
                    raise RuntimePolicyIntegrityError(
                        "runtime policy v2 migration does not preserve the latest v1 policy"
                    )
                versions[policy.policy_id] = policy
                migration_policy_id = policy.policy_id
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
            elif event.event_type == "runtime_policy_immediate_amendment_applied":
                policy = RuntimePolicyVersion.from_artifact_mapping(
                    self._load_json(payload["policy_ref"], _POLICY_KIND)
                )
                data = self._load_json(payload["amendment_ref"], _IMMEDIATE_AMENDMENT_KIND)
                refs = data["evidence_refs"]
                if not isinstance(refs, list):
                    raise RuntimePolicyIntegrityError("immediate amendment evidence_refs is invalid")
                immediate_amendment = ImmediateRuntimePolicyAmendment.create(
                    request_id=data["request_id"], base_policy_id=data["base_policy_id"],
                    requested_at=RuntimeStageBoundary.from_mapping(data["requested_at"]),
                    revision=data["revision"], kind=data["kind"], patch=data["patch"],
                    rollback_target_policy_id=data["rollback_target_policy_id"],
                    resulting_policy_id=data["resulting_policy_id"], reason=data["reason"],
                    evidence_refs=tuple(refs),
                )
                if data["requested_by"] != Role.PROSECUTOR.value:
                    raise RuntimePolicyIntegrityError("immediate amendment was not requested by prosecutor")
                if immediate_amendment.amendment_id != payload["amendment_ref"]["artifact_id"]:
                    raise RuntimePolicyIntegrityError("immediate amendment content address is invalid")
                if policy.policy_id != payload["policy_ref"]["artifact_id"]:
                    raise RuntimePolicyIntegrityError("immediate policy content address is invalid")
                if policy.policy_id != immediate_amendment.resulting_policy_id or policy.parent_policy_id != immediate_amendment.base_policy_id:
                    raise RuntimePolicyIntegrityError("immediate amendment policy lineage is invalid")
                if immediate_amendment.base_policy_id not in versions:
                    raise RuntimePolicyIntegrityError("immediate amendment base policy is unknown")
                prior_candidates: list[tuple[tuple[int, int, int], str]] = [
                    ((item_cycle, 0, 0), item_policy)
                    for item_cycle, item_policy in schedule.items()
                    if (item_cycle, 0) <= immediate_amendment.requested_at.key
                ]
                prior_candidates.extend(
                    ((key[0], key[1], 0), item_policy)
                    for key, (_boundary, item_policy) in stage_schedule.items()
                    if key <= immediate_amendment.requested_at.key
                )
                prior_candidates.extend(
                    ((armed.cycle, armed.ordinal, 0), item_policy)
                    for armed, item_policy in maintenance_armed.items()
                    if armed.key <= immediate_amendment.requested_at.key
                )
                if migration_policy_id is not None:
                    migrated = versions[migration_policy_id]
                    migration_parent = migrated.parent_policy_id
                    migration_positions = [
                        position
                        for position, item_policy in prior_candidates
                        if item_policy == migration_parent
                    ]
                    if migration_positions:
                        cycle, ordinal, revision = max(migration_positions)
                        prior_candidates.append(
                            ((cycle, ordinal, revision + 1), migration_policy_id)
                        )
                prior_candidates.extend(
                    (
                        (item.requested_at.cycle, item.requested_at.ordinal, item.revision),
                        item.resulting_policy_id,
                    )
                    for item in immediate_amendments
                    if item.requested_at.key <= immediate_amendment.requested_at.key
                )
                if (
                    not prior_candidates
                    or max(prior_candidates, key=lambda item: item[0])[1]
                    != immediate_amendment.base_policy_id
                ):
                    raise RuntimePolicyIntegrityError(
                        "immediate amendment does not extend the effective policy"
                    )
                expected_revision = 1 + sum(
                    item.requested_at.key == immediate_amendment.requested_at.key
                    for item in immediate_amendments
                )
                if immediate_amendment.revision != expected_revision or any(
                    item.request_id == immediate_amendment.request_id for item in immediate_amendments
                ):
                    raise RuntimePolicyIntegrityError("immediate amendment revision or request_id is invalid")
                versions[policy.policy_id] = policy
                immediate_amendments.append(immediate_amendment)
            elif event.event_type == "runtime_policy_maintenance_armed":
                if set(payload) != {"policy_ref", "requested_at"}:
                    raise RuntimePolicyIntegrityError(
                        "runtime policy maintenance arming has an invalid schema"
                    )
                policy = RuntimePolicyVersion.from_artifact_mapping(
                    self._load_json(payload["policy_ref"], _POLICY_KIND)
                )
                if (
                    policy.policy_id != payload["policy_ref"]["artifact_id"]
                    or policy.schema_version != 2
                    or not policy.maintenance_only
                    or policy.parent_policy_id not in versions
                ):
                    raise RuntimePolicyIntegrityError(
                        "runtime policy maintenance arming is invalid"
                    )
                boundary = RuntimeStageBoundary.from_mapping(payload["requested_at"])
                if boundary.cycle != policy.effective_cycle:
                    raise RuntimePolicyIntegrityError(
                        "runtime policy maintenance boundary cycle is invalid"
                    )
                prior: list[tuple[tuple[int, int, int], str]] = [
                    ((item_cycle, 0, 0), item_policy)
                    for item_cycle, item_policy in schedule.items()
                    if (item_cycle, 0) <= boundary.key
                ]
                prior.extend(
                    ((key[0], key[1], 0), item_policy)
                    for key, (_boundary, item_policy) in stage_schedule.items()
                    if key <= boundary.key
                )
                prior.extend(
                    (
                        (item.requested_at.cycle, item.requested_at.ordinal, item.revision),
                        item.resulting_policy_id,
                    )
                    for item in immediate_amendments
                    if item.requested_at.key <= boundary.key
                )
                prior.extend(
                    ((armed.cycle, armed.ordinal, 0), item_policy)
                    for armed, item_policy in maintenance_armed.items()
                    if armed.key <= boundary.key
                )
                if (
                    not prior
                    or max(prior, key=lambda item: item[0])[1]
                    != policy.parent_policy_id
                ):
                    raise RuntimePolicyIntegrityError(
                        "runtime policy maintenance arming does not extend the effective policy"
                    )
                versions[policy.policy_id] = policy
                maintenance_armed[boundary] = policy.policy_id
            elif event.event_type == "runtime_policy_council_decided":
                data = self._load_json(payload["decision_ref"], _COUNCIL_DECISION_KIND)
                strict = _strict_object(
                    data,
                    {"amendment_id", "decision", "reason", "replacement_amendment_id"},
                    "runtime policy council decision",
                )
                decision_id = _content_id(_COUNCIL_DECISION_KIND, strict)
                if decision_id != payload["decision_ref"]["artifact_id"]:
                    raise RuntimePolicyIntegrityError("council decision content address is invalid")
                amendment_id = strict["amendment_id"]
                known = {item.amendment_id for item in immediate_amendments}
                if amendment_id not in known or strict["decision"] not in {"ratify", "revise", "rollback"}:
                    raise RuntimePolicyIntegrityError("council decision is invalid")
                replacement = strict["replacement_amendment_id"]
                if (strict["decision"] == "ratify" and replacement is not None) or (
                    strict["decision"] != "ratify" and replacement not in known
                ):
                    raise RuntimePolicyIntegrityError("council replacement amendment is invalid")
                if strict["decision"] != "ratify":
                    original_index = next(
                        index for index, item in enumerate(immediate_amendments)
                        if item.amendment_id == amendment_id
                    )
                    replacement_index = next(
                        index for index, item in enumerate(immediate_amendments)
                        if item.amendment_id == replacement
                    )
                    if replacement_index <= original_index:
                        raise RuntimePolicyIntegrityError(
                            "council replacement amendment is not a later revision"
                        )
                record = cast(Mapping[str, JsonValue], freeze_json({"decision_id": decision_id, **strict}))
                if amendment_id in council_decisions and council_decisions[amendment_id] != record:
                    raise RuntimePolicyIntegrityError("multiple council decisions exist for one amendment")
                council_decisions[amendment_id] = record
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
                    ((item_cycle, 0, 0), item_policy)
                    for item_cycle, item_policy in schedule.items()
                    if (item_cycle, 0) <= boundary.key
                ]
                if migration_policy_id is not None:
                    migrated = versions[migration_policy_id]
                    migration_parent = migrated.parent_policy_id
                    migration_positions = [
                        position
                        for position, item_policy in candidates
                        if item_policy == migration_parent
                    ]
                    if migration_positions:
                        cycle_at, ordinal_at, revision_at = max(migration_positions)
                        candidates.append(
                            ((cycle_at, ordinal_at, revision_at + 1), migration_policy_id)
                        )
                candidates.extend(
                    ((key[0], key[1], 0), item_policy)
                    for key, (_, item_policy) in stage_schedule.items()
                    if key <= boundary.key
                )
                candidates.extend(
                    ((armed.cycle, armed.ordinal, 0), item_policy)
                    for armed, item_policy in maintenance_armed.items()
                    if armed.key <= boundary.key
                )
                candidates.extend(
                    ((item.requested_at.cycle, item.requested_at.ordinal, item.revision), item.resulting_policy_id)
                    for item in immediate_amendments
                    if item.requested_at.key <= boundary.key
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
        self._immediate_amendments = immediate_amendments
        self._council_decisions = council_decisions
        self._maintenance_armed = maintenance_armed
        self._migration_policy_id = migration_policy_id
        self._paired_designs = paired
