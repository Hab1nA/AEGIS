"""Candidateized policy for the evolvable in-WSL control core.

Only evaluation, promotion, and the *inner* task sandbox policy live here.
Host/Windows safety, credentials, networking boundaries, and the root WSL
supervisor are intentionally absent and rejected when supplied by a candidate.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import Any, Mapping

from aegis.models import canonical_json


class ControlCorePolicyError(ValueError):
    """Raised when a control-core candidate crosses its narrow grant."""


_FORBIDDEN_BOUNDARY_FIELDS = frozenset(
    {
        "credential_broker",
        "credentials",
        "host_broker",
        "host_safety_envelope",
        "network_boundary",
        "root_agent",
        "secret_broker",
        "windows",
        "windows_envelope",
        "wsl_supervisor",
        "wsl_root_supervisor",
    }
)


def _strict(value: object, fields: set[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ControlCorePolicyError(f"{name} must be a string-keyed object")
    forbidden = set(value) & _FORBIDDEN_BOUNDARY_FIELDS
    if forbidden:
        raise ControlCorePolicyError(
            "control-core cannot modify host, Windows, credential, network-boundary, "
            "or WSL-supervisor controls: " + ", ".join(sorted(forbidden))
        )
    if set(value) != fields:
        raise ControlCorePolicyError(f"{name} has missing or unknown fields")
    return value


def _number(value: object, name: str, *, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ControlCorePolicyError(f"{name} must be numeric")
    result = float(value)
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise ControlCorePolicyError(f"{name} must be in [{minimum},{maximum}]")
    return result


def _integer(value: object, name: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ControlCorePolicyError(f"{name} must be an integer in [{minimum},{maximum}]")
    return value


@dataclass(frozen=True, slots=True)
class SealedEvaluatorPolicy:
    public_weight: float
    hidden_weight: float
    timeout_seconds: float

    def __post_init__(self) -> None:
        _number(self.public_weight, "sealed_evaluator.public_weight", minimum=0.0, maximum=1.0)
        _number(self.hidden_weight, "sealed_evaluator.hidden_weight", minimum=0.0, maximum=1.0)
        if abs(self.public_weight + self.hidden_weight - 1.0) > 1e-12:
            raise ControlCorePolicyError("sealed evaluator weights must sum to one")
        _number(self.timeout_seconds, "sealed_evaluator.timeout_seconds", minimum=1.0, maximum=3600.0)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "public_weight": float(self.public_weight),
            "hidden_weight": float(self.hidden_weight),
            "timeout_seconds": float(self.timeout_seconds),
        }


@dataclass(frozen=True, slots=True)
class PromotionGatePolicy:
    required_seeds: int
    fresh_improvement: float
    regression_noninferiority_margin: float
    max_total_cost_increase: float
    enforce_cost_limit: bool
    min_seed_delta_floor: float = -0.10
    cost_savings_path: float = 0.10

    def __post_init__(self) -> None:
        # The sealed design is fixed to the independently replayed seeds [0,1].
        if self.required_seeds != 2 or isinstance(self.required_seeds, bool):
            raise ControlCorePolicyError("promotion_gate.required_seeds must remain exactly 2")
        _number(self.fresh_improvement, "promotion_gate.fresh_improvement", minimum=0.0, maximum=1.0)
        _number(
            self.regression_noninferiority_margin,
            "promotion_gate.regression_noninferiority_margin",
            minimum=0.0,
            maximum=1.0,
        )
        _number(
            self.max_total_cost_increase,
            "promotion_gate.max_total_cost_increase",
            minimum=0.0,
            maximum=1.0,
        )
        if not isinstance(self.enforce_cost_limit, bool):
            raise ControlCorePolicyError("promotion_gate.enforce_cost_limit must be boolean")
        if self.enforce_cost_limit:
            raise ControlCorePolicyError("promotion cost must remain observational")
        _number(
            self.min_seed_delta_floor,
            "promotion_gate.min_seed_delta_floor",
            minimum=-1.0,
            maximum=0.0,
        )
        _number(
            self.cost_savings_path,
            "promotion_gate.cost_savings_path",
            minimum=0.0,
            maximum=1.0,
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "required_seeds": self.required_seeds,
            "fresh_improvement": float(self.fresh_improvement),
            "regression_noninferiority_margin": float(
                self.regression_noninferiority_margin
            ),
            "max_total_cost_increase": float(self.max_total_cost_increase),
            "enforce_cost_limit": self.enforce_cost_limit,
            "min_seed_delta_floor": float(self.min_seed_delta_floor),
            "cost_savings_path": float(self.cost_savings_path),
        }


@dataclass(frozen=True, slots=True)
class InternalTaskSandboxPolicy:
    network: str
    public_hidden_isolation: bool
    max_workspace_bytes: int
    max_task_overlay_bytes: int
    max_task_overlay_files: int

    def __post_init__(self) -> None:
        if self.network != "none":
            raise ControlCorePolicyError("internal task sandbox network must remain none")
        if self.public_hidden_isolation is not True:
            raise ControlCorePolicyError("public and hidden suites must remain independently isolated")
        _integer(
            self.max_workspace_bytes,
            "task_sandbox.max_workspace_bytes",
            minimum=1,
            maximum=32 * 1024 * 1024,
        )
        _integer(
            self.max_task_overlay_bytes,
            "task_sandbox.max_task_overlay_bytes",
            minimum=1,
            maximum=8 * 1024 * 1024,
        )
        _integer(
            self.max_task_overlay_files,
            "task_sandbox.max_task_overlay_files",
            minimum=1,
            maximum=64,
        )
        if self.max_task_overlay_bytes > self.max_workspace_bytes:
            raise ControlCorePolicyError("task overlay cannot exceed the workspace limit")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "network": self.network,
            "public_hidden_isolation": self.public_hidden_isolation,
            "max_workspace_bytes": self.max_workspace_bytes,
            "max_task_overlay_bytes": self.max_task_overlay_bytes,
            "max_task_overlay_files": self.max_task_overlay_files,
        }


@dataclass(frozen=True, slots=True)
class ControlCorePolicy:
    sealed_evaluator: SealedEvaluatorPolicy
    promotion_gate: PromotionGatePolicy
    task_sandbox: InternalTaskSandboxPolicy

    @property
    def policy_id(self) -> str:
        digest = hashlib.sha256(canonical_json(self.to_mapping()).encode("utf-8")).hexdigest()
        return f"control-core-sha256:{digest}"

    def to_mapping(self) -> dict[str, Any]:
        return {
            "sealed_evaluator": self.sealed_evaluator.to_mapping(),
            "promotion_gate": self.promotion_gate.to_mapping(),
            "task_sandbox": self.task_sandbox.to_mapping(),
        }

    @classmethod
    def from_mapping(cls, value: object) -> ControlCorePolicy:
        data = _strict(
            value,
            {"sealed_evaluator", "promotion_gate", "task_sandbox"},
            "control_core",
        )
        evaluator = _strict(
            data["sealed_evaluator"],
            {"public_weight", "hidden_weight", "timeout_seconds"},
            "control_core.sealed_evaluator",
        )
        gate_data = dict(data["promotion_gate"])
        # Legacy candidate payloads predate the per-seed floor; default it.
        gate_data.setdefault("min_seed_delta_floor", -0.10)
        gate_data.setdefault("cost_savings_path", 0.10)
        gate = _strict(
            gate_data,
            {
                "required_seeds",
                "fresh_improvement",
                "regression_noninferiority_margin",
                "max_total_cost_increase",
                "enforce_cost_limit",
                "min_seed_delta_floor",
                "cost_savings_path",
            },
            "control_core.promotion_gate",
        )
        sandbox = _strict(
            data["task_sandbox"],
            {
                "network",
                "public_hidden_isolation",
                "max_workspace_bytes",
                "max_task_overlay_bytes",
                "max_task_overlay_files",
            },
            "control_core.task_sandbox",
        )
        return cls(
            SealedEvaluatorPolicy(**evaluator),
            PromotionGatePolicy(**gate),
            InternalTaskSandboxPolicy(**sandbox),
        )


DEFAULT_CONTROL_CORE_POLICY = ControlCorePolicy(
    SealedEvaluatorPolicy(0.25, 0.75, 120.0),
    PromotionGatePolicy(2, 0.02, 0.01, 0.10, False, -0.10, 0.10),
    InternalTaskSandboxPolicy(
        "none",
        True,
        32 * 1024 * 1024,
        8 * 1024 * 1024,
        64,
    ),
)


__all__ = [
    "ControlCorePolicy",
    "ControlCorePolicyError",
    "DEFAULT_CONTROL_CORE_POLICY",
    "InternalTaskSandboxPolicy",
    "PromotionGatePolicy",
    "SealedEvaluatorPolicy",
]
