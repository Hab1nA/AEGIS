"""Immutable, content-addressed evidence models for causal role attribution."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping, Sequence

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_OBSERVATION_ID = re.compile(r"attribution-observation-sha256:[0-9a-f]{64}\Z")
_REPORT_ID = re.compile(r"attribution-report-sha256:[0-9a-f]{64}\Z")
_ROLE_VERSION_ID = re.compile(r"role-version-sha256:[0-9a-f]{64}\Z")


def canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def content_id(prefix: str, value: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()
    return f"{prefix}{digest}"


def _text(value: object, name: str, *, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or value.strip() != value or len(value) > maximum:
        raise ValueError(f"{name} must be bounded, non-empty, trimmed text")
    return value


def _generation(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _strict_keys(value: Mapping[str, Any], expected: set[str], name: str) -> None:
    if set(value) != expected:
        raise ValueError(f"{name} has missing or unknown fields")


@dataclass(frozen=True, slots=True, order=True)
class RoleGeneration:
    role: str
    generation: int
    generation_id: str

    def __post_init__(self) -> None:
        _text(self.role, "role", maximum=64)
        _generation(self.generation, "generation")
        if _ROLE_VERSION_ID.fullmatch(self.generation_id) is None:
            raise ValueError("generation_id must be an exact role-version content address")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> RoleGeneration:
        _strict_keys(value, {"role", "generation", "generation_id"}, "role generation")
        return cls(value["role"], value["generation"], value["generation_id"])

    def to_mapping(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "generation": self.generation,
            "generation_id": self.generation_id,
        }


@dataclass(frozen=True, slots=True)
class EvaluationArm:
    """One arm with every causal-control coordinate explicitly locked."""

    cycle_id: str
    objective_id: str
    task_id: str
    seed: int
    model_id: str
    environment_id: str
    plugin_ids: tuple[str, ...]
    role_generations: tuple[RoleGeneration, ...]
    quality: float
    cost_units: int
    usage_verified: bool
    safety_passed: bool
    integrity_passed: bool
    runtime_variant: str | None = None
    mcp_binding_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("cycle_id", "objective_id", "task_id", "model_id", "environment_id"):
            _text(getattr(self, name), name)
        if self.runtime_variant is not None:
            _text(self.runtime_variant, "runtime_variant", maximum=512)
        if isinstance(self.seed, bool) or not isinstance(self.seed, int) or self.seed < 0:
            raise ValueError("seed must be a non-negative integer")
        if tuple(sorted(set(self.plugin_ids))) != self.plugin_ids:
            raise ValueError("plugin_ids must be sorted and unique")
        if any(not isinstance(item, str) for item in self.plugin_ids):
            raise TypeError("plugin_ids must contain strings")
        for plugin_id in self.plugin_ids:
            _text(plugin_id, "plugin_id")
        if tuple(sorted(set(self.mcp_binding_ids))) != self.mcp_binding_ids:
            raise ValueError("mcp_binding_ids must be sorted and unique")
        if any(not isinstance(item, str) for item in self.mcp_binding_ids):
            raise TypeError("mcp_binding_ids must contain strings")
        for binding_id in self.mcp_binding_ids:
            _text(binding_id, "mcp_binding_id")
        if tuple(sorted(self.role_generations)) != self.role_generations:
            raise ValueError("role_generations must be sorted by role")
        roles = tuple(item.role for item in self.role_generations)
        if not roles or len(set(roles)) != len(roles):
            raise ValueError("role_generations must contain unique roles")
        if isinstance(self.quality, bool) or not isinstance(self.quality, (int, float)):
            raise TypeError("quality must be numeric")
        if not math.isfinite(float(self.quality)) or not 0.0 <= float(self.quality) <= 1.0:
            raise ValueError("quality must be finite and in [0,1]")
        if isinstance(self.cost_units, bool) or not isinstance(self.cost_units, int) or self.cost_units < 0:
            raise ValueError("cost_units must be a non-negative integer")
        if not all(
            isinstance(value, bool)
            for value in (self.usage_verified, self.safety_passed, self.integrity_passed)
        ):
            raise TypeError("usage, safety, and integrity flags must be bool values")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> EvaluationArm:
        expected = {
            "cycle_id",
            "objective_id",
            "task_id",
            "seed",
            "model_id",
            "environment_id",
            "plugin_ids",
            "role_generations",
            "quality",
            "cost_units",
            "usage_verified",
            "safety_passed",
            "integrity_passed",
            "runtime_variant",
            "mcp_binding_ids",
        }
        if set(value) != expected:
            compatible = (
                expected - {"runtime_variant"},
                expected - {"mcp_binding_ids"},
                expected - {"runtime_variant", "mcp_binding_ids"},
            )
            if set(value) not in compatible:
                raise ValueError("evaluation arm has missing or unknown fields")
        plugins = value["plugin_ids"]
        roles = value["role_generations"]
        if not isinstance(plugins, list) or not all(isinstance(item, str) for item in plugins):
            raise TypeError("plugin_ids must be an array of strings")
        if not isinstance(roles, list) or not all(isinstance(item, Mapping) for item in roles):
            raise TypeError("role_generations must be an array of objects")
        runtime_variant = value.get("runtime_variant")
        if runtime_variant is not None and not isinstance(runtime_variant, str):
            raise TypeError("runtime_variant must be text or null")
        mcp_bindings = value.get("mcp_binding_ids", [])
        if not isinstance(mcp_bindings, list) or not all(
            isinstance(item, str) for item in mcp_bindings
        ):
            raise TypeError("mcp_binding_ids must be an array of strings")
        return cls(
            cycle_id=value["cycle_id"],
            objective_id=value["objective_id"],
            task_id=value["task_id"],
            seed=value["seed"],
            model_id=value["model_id"],
            environment_id=value["environment_id"],
            plugin_ids=tuple(plugins),
            role_generations=tuple(RoleGeneration.from_mapping(item) for item in roles),
            quality=value["quality"],
            cost_units=value["cost_units"],
            usage_verified=value["usage_verified"],
            safety_passed=value["safety_passed"],
            integrity_passed=value["integrity_passed"],
            runtime_variant=runtime_variant,
            mcp_binding_ids=tuple(mcp_bindings),
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "cycle_id": self.cycle_id,
            "objective_id": self.objective_id,
            "task_id": self.task_id,
            "seed": self.seed,
            "model_id": self.model_id,
            "environment_id": self.environment_id,
            "plugin_ids": list(self.plugin_ids),
            "role_generations": [item.to_mapping() for item in self.role_generations],
            "quality": float(self.quality),
            "cost_units": self.cost_units,
            "usage_verified": self.usage_verified,
            "safety_passed": self.safety_passed,
            "integrity_passed": self.integrity_passed,
            "runtime_variant": self.runtime_variant,
            "mcp_binding_ids": list(self.mcp_binding_ids),
        }

    def generation_for(self, role: str) -> RoleGeneration | None:
        return next((item for item in self.role_generations if item.role == role), None)


@dataclass(frozen=True, slots=True)
class PairedObservation:
    observation_id: str
    target_role: str
    baseline: EvaluationArm
    candidate: EvaluationArm

    def __post_init__(self) -> None:
        if _OBSERVATION_ID.fullmatch(self.observation_id) is None:
            raise ValueError("observation_id must be an attribution observation content id")
        _text(self.target_role, "target_role", maximum=64)
        if self.baseline.generation_for(self.target_role) is None:
            raise ValueError("baseline does not contain target_role")
        if self.candidate.generation_for(self.target_role) is None:
            raise ValueError("candidate does not contain target_role")
        expected = content_id(
            "attribution-observation-sha256:", self.to_mapping(include_id=False)
        )
        if self.observation_id != expected:
            raise ValueError("observation_id does not match paired evidence")

    @classmethod
    def create(
        cls, target_role: str, baseline: EvaluationArm, candidate: EvaluationArm
    ) -> PairedObservation:
        payload = {
            "target_role": target_role,
            "baseline": baseline.to_mapping(),
            "candidate": candidate.to_mapping(),
        }
        return cls(
            content_id("attribution-observation-sha256:", payload),
            target_role,
            baseline,
            candidate,
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> PairedObservation:
        _strict_keys(
            value,
            {"observation_id", "target_role", "baseline", "candidate"},
            "paired observation",
        )
        baseline = value["baseline"]
        candidate = value["candidate"]
        if not isinstance(baseline, Mapping) or not isinstance(candidate, Mapping):
            raise TypeError("paired observation arms must be objects")
        return cls(
            value["observation_id"],
            value["target_role"],
            EvaluationArm.from_mapping(baseline),
            EvaluationArm.from_mapping(candidate),
        )

    def to_mapping(self, *, include_id: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "target_role": self.target_role,
            "baseline": self.baseline.to_mapping(),
            "candidate": self.candidate.to_mapping(),
        }
        return {"observation_id": self.observation_id, **payload} if include_id else payload

    def confounded_fields(self) -> tuple[str, ...]:
        left = self.baseline
        right = self.candidate
        fields = (
            "cycle_id",
            "objective_id",
            "task_id",
            "seed",
            "model_id",
            "environment_id",
            "plugin_ids",
            "mcp_binding_ids",
        )
        changed = [name for name in fields if getattr(left, name) != getattr(right, name)]
        left_roles = {
            item.role: (item.generation, item.generation_id) for item in left.role_generations
        }
        right_roles = {
            item.role: (item.generation, item.generation_id) for item in right.role_generations
        }
        if set(left_roles) != set(right_roles):
            changed.append("teammate_roles")
        else:
            for role in sorted(left_roles):
                if role != self.target_role and left_roles[role] != right_roles[role]:
                    changed.append(f"teammate_generation:{role}")
        if left_roles.get(self.target_role) == right_roles.get(self.target_role):
            changed.append("target_role_generation")
        return tuple(changed)

    def intervention_fields(self) -> tuple[str, ...]:
        """Return the causal coordinates that differ between the two arms.

        A valid single-surface intervention changes exactly one coordinate
        (``plugin_ids`` for a plugin candidate, ``mcp_binding_ids`` for MCP,
        ``runtime_variant`` for an
        environment candidate, or none for advisory workflow/subject
        candidates whose effect is carried by the role generation identity).
        """
        changed = list(self.confounded_fields())
        if self.baseline.runtime_variant != self.candidate.runtime_variant:
            changed.append("runtime_variant")
        return tuple(sorted(dict.fromkeys(changed)))


class QualificationPath(StrEnum):
    NONE = "none"
    QUALITY_IMPROVEMENT = "quality-improvement"
    COST_EFFICIENCY = "cost-efficiency"


class AttributionDisposition(StrEnum):
    QUALIFIED = "qualified"
    NOT_QUALIFIED = "not-qualified"
    CONFOUNDED = "confounded"
    UNVERIFIED_USAGE = "unverified-usage"
    SAFETY_REJECTED = "safety-rejected"
    INTEGRITY_REJECTED = "integrity-rejected"
    INVALID_DESIGN = "invalid-design"


@dataclass(frozen=True, slots=True)
class QualificationPolicy:
    quality_improvement: float = 0.02
    max_cost_increase: float = 0.10
    noninferiority_margin: float = 0.01
    minimum_cost_saving: float = 0.10
    minimum_pairs: int = 1

    def __post_init__(self) -> None:
        values = (
            self.quality_improvement,
            self.max_cost_increase,
            self.noninferiority_margin,
            self.minimum_cost_saving,
        )
        if any(isinstance(item, bool) or not isinstance(item, (int, float)) for item in values):
            raise TypeError("qualification thresholds must be numeric")
        if any(not math.isfinite(float(item)) or float(item) < 0.0 for item in values):
            raise ValueError("qualification thresholds must be finite and non-negative")
        if self.max_cost_increase > 1.0 or self.minimum_cost_saving > 1.0:
            raise ValueError("cost ratios must be in [0,1]")
        if isinstance(self.minimum_pairs, bool) or not isinstance(self.minimum_pairs, int):
            raise TypeError("minimum_pairs must be an integer")
        if self.minimum_pairs < 1:
            raise ValueError("minimum_pairs must be positive")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "quality_improvement": float(self.quality_improvement),
            "max_cost_increase": float(self.max_cost_increase),
            "noninferiority_margin": float(self.noninferiority_margin),
            "minimum_cost_saving": float(self.minimum_cost_saving),
            "minimum_pairs": self.minimum_pairs,
        }


@dataclass(frozen=True, slots=True)
class AttributionReport:
    report_id: str
    disposition: AttributionDisposition
    qualification_path: QualificationPath
    reason: str
    observation_ids: tuple[str, ...]
    policy: QualificationPolicy
    quality_delta: float
    cost_change: float

    def __post_init__(self) -> None:
        if _REPORT_ID.fullmatch(self.report_id) is None:
            raise ValueError("report_id must be an attribution report content id")
        _text(self.reason, "reason", maximum=1024)
        if tuple(sorted(set(self.observation_ids))) != self.observation_ids:
            raise ValueError("observation_ids must be sorted and unique")
        if any(_OBSERVATION_ID.fullmatch(item) is None for item in self.observation_ids):
            raise ValueError("report contains an invalid observation id")
        if self.disposition is AttributionDisposition.QUALIFIED:
            if not self.observation_ids:
                raise ValueError("qualified reports require paired observations")
            if self.qualification_path is QualificationPath.NONE:
                raise ValueError("qualified reports require a qualification path")
        elif self.qualification_path is not QualificationPath.NONE:
            raise ValueError("rejected reports cannot carry a qualification path")
        for value in (self.quality_delta, self.cost_change):
            if not math.isfinite(value):
                raise ValueError("report metrics must be finite")
        expected = content_id("attribution-report-sha256:", self.to_mapping(include_id=False))
        if self.report_id != expected:
            raise ValueError("report_id does not match report evidence")

    @property
    def qualified(self) -> bool:
        return self.disposition is AttributionDisposition.QUALIFIED

    @classmethod
    def create(
        cls,
        *,
        disposition: AttributionDisposition,
        qualification_path: QualificationPath,
        reason: str,
        observation_ids: Sequence[str],
        policy: QualificationPolicy,
        quality_delta: float,
        cost_change: float,
    ) -> AttributionReport:
        payload: dict[str, Any] = {
            "disposition": disposition.value,
            "qualification_path": qualification_path.value,
            "reason": reason,
            "observation_ids": sorted(observation_ids),
            "policy": policy.to_mapping(),
            "quality_delta": round(quality_delta, 12),
            "cost_change": round(cost_change, 12),
        }
        return cls.from_mapping(
            {"report_id": content_id("attribution-report-sha256:", payload), **payload}
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> AttributionReport:
        expected = {
            "report_id",
            "disposition",
            "qualification_path",
            "reason",
            "observation_ids",
            "policy",
            "quality_delta",
            "cost_change",
        }
        _strict_keys(value, expected, "attribution report")
        ids = value["observation_ids"]
        policy = value["policy"]
        if not isinstance(ids, list) or not all(isinstance(item, str) for item in ids):
            raise TypeError("observation_ids must be an array of strings")
        if not isinstance(policy, Mapping):
            raise TypeError("policy must be an object")
        _strict_keys(
            policy,
            {
                "quality_improvement",
                "max_cost_increase",
                "noninferiority_margin",
                "minimum_cost_saving",
                "minimum_pairs",
            },
            "qualification policy",
        )
        return cls(
            report_id=value["report_id"],
            disposition=AttributionDisposition(value["disposition"]),
            qualification_path=QualificationPath(value["qualification_path"]),
            reason=value["reason"],
            observation_ids=tuple(ids),
            policy=QualificationPolicy(
                quality_improvement=policy["quality_improvement"],
                max_cost_increase=policy["max_cost_increase"],
                noninferiority_margin=policy["noninferiority_margin"],
                minimum_cost_saving=policy["minimum_cost_saving"],
                minimum_pairs=policy["minimum_pairs"],
            ),
            quality_delta=value["quality_delta"],
            cost_change=value["cost_change"],
        )

    def to_mapping(self, *, include_id: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "disposition": self.disposition.value,
            "qualification_path": self.qualification_path.value,
            "reason": self.reason,
            "observation_ids": list(self.observation_ids),
            "policy": self.policy.to_mapping(),
            "quality_delta": self.quality_delta,
            "cost_change": self.cost_change,
        }
        return {"report_id": self.report_id, **payload} if include_id else payload
