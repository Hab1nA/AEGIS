"""Strict, secret-free campaign configuration."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from aegis.autonomy_budget import (
    AUTONOMY_MIN_AGENT_STEPS,
    AUTONOMY_MIN_OUTPUT_TOKENS,
    AUTONOMY_ROLE_SHARES,
)

AUTONOMY_ACCEPTANCE_PROFILES = frozenset({"autonomous_evolution_v1", "autonomous_evolution_v2"})


class ConfigError(ValueError):
    """Raised when a campaign configuration is incomplete or unsafe."""


def _exact(data: Mapping[str, Any], expected: set[str], required: set[str], label: str) -> None:
    unknown = set(data) - expected
    missing = required - set(data)
    if unknown or missing:
        parts = []
        if missing:
            parts.append(f"missing {sorted(missing)}")
        if unknown:
            parts.append(f"unknown {sorted(unknown)}")
        raise ConfigError(f"{label}: " + "; ".join(parts))


def _positive_int(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ConfigError(f"{name} must be a positive integer")
    return value


def _bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{name} must be a boolean")
    return value


def _optional_public_github_url(value: Any, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ConfigError(f"{name} must be null or a non-empty URL")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.strip("/")
    ):
        raise ConfigError(f"{name} must be a credential-free https://github.com URL")
    return value


@dataclass(frozen=True, slots=True)
class AutonomyV2Config:
    """Secret-free deployment policy for the dynamic three-role runtime."""

    enabled: bool = True
    dynamic_only: bool = True
    task_holdout_delay_cycles: int = 1
    council_max_messages: int = 24
    council_max_tokens: int = 32_768
    objective_history_window: int = 3
    objective_probation_cycles: int = 2
    public_repo_url: str | None = None
    public_stable_branch: str = "stable"
    candidate_branch_prefix: str = "candidate"
    builder_public_internet: bool = True
    builder_block_private_networks: bool = True
    runtime_network: str = "none"
    external_writes_via_connectors: bool = True
    role_activation_automatic: bool = True
    immutable_safety_constitution: bool = True

    _FIELDS = frozenset(
        {
            "enabled",
            "dynamic_only",
            "task_holdout_delay_cycles",
            "council_max_messages",
            "council_max_tokens",
            "objective_history_window",
            "objective_probation_cycles",
            "public_repo_url",
            "public_stable_branch",
            "candidate_branch_prefix",
            "builder_public_internet",
            "builder_block_private_networks",
            "runtime_network",
            "external_writes_via_connectors",
            "role_activation_automatic",
            "immutable_safety_constitution",
        }
    )

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "AutonomyV2Config":
        raw = dict(data)
        _exact(raw, set(cls._FIELDS), set(), "autonomy_v2")
        enabled = _bool(raw.get("enabled", True), "autonomy_v2.enabled")
        dynamic_only = _bool(raw.get("dynamic_only", True), "autonomy_v2.dynamic_only")
        if enabled and not dynamic_only:
            raise ConfigError("autonomy_v2.dynamic_only must remain true for the selected v2 design")
        stable = raw.get("public_stable_branch", "stable")
        prefix = raw.get("candidate_branch_prefix", "candidate")
        for name, value in (("public_stable_branch", stable), ("candidate_branch_prefix", prefix)):
            if (
                not isinstance(value, str)
                or not value
                or value != value.strip()
                or any(
                    character
                    not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_/"
                    for character in value
                )
                or ".." in value
                or value.startswith("/")
                or value.endswith("/")
            ):
                raise ConfigError(f"autonomy_v2.{name} is not a safe Git ref component")
        builder_public = _bool(
            raw.get("builder_public_internet", True), "autonomy_v2.builder_public_internet"
        )
        block_private = _bool(
            raw.get("builder_block_private_networks", True),
            "autonomy_v2.builder_block_private_networks",
        )
        if enabled and not block_private:
            raise ConfigError("autonomy_v2 may not allow builder access to private networks")
        runtime_network = raw.get("runtime_network", "none")
        if runtime_network != "none":
            raise ConfigError("autonomy_v2.runtime_network must be 'none'")
        connectors = _bool(
            raw.get("external_writes_via_connectors", True),
            "autonomy_v2.external_writes_via_connectors",
        )
        if enabled and not connectors:
            raise ConfigError("autonomy_v2 external writes must use dedicated connectors")
        automatic = _bool(
            raw.get("role_activation_automatic", True),
            "autonomy_v2.role_activation_automatic",
        )
        immutable = _bool(
            raw.get("immutable_safety_constitution", True),
            "autonomy_v2.immutable_safety_constitution",
        )
        if enabled and not immutable:
            raise ConfigError("autonomy_v2 safety constitution must remain immutable to roles")
        return cls(
            enabled=enabled,
            dynamic_only=dynamic_only,
            task_holdout_delay_cycles=_positive_int(
                raw.get("task_holdout_delay_cycles", 1),
                "autonomy_v2.task_holdout_delay_cycles",
            ),
            council_max_messages=_positive_int(
                raw.get("council_max_messages", 24), "autonomy_v2.council_max_messages"
            ),
            council_max_tokens=_positive_int(
                raw.get("council_max_tokens", 32_768), "autonomy_v2.council_max_tokens"
            ),
            objective_history_window=_positive_int(
                raw.get("objective_history_window", 3),
                "autonomy_v2.objective_history_window",
            ),
            objective_probation_cycles=_positive_int(
                raw.get("objective_probation_cycles", 2),
                "autonomy_v2.objective_probation_cycles",
            ),
            public_repo_url=_optional_public_github_url(
                raw.get("public_repo_url"), "autonomy_v2.public_repo_url"
            ),
            public_stable_branch=stable,
            candidate_branch_prefix=prefix,
            builder_public_internet=builder_public,
            builder_block_private_networks=block_private,
            runtime_network=runtime_network,
            external_writes_via_connectors=connectors,
            role_activation_automatic=automatic,
            immutable_safety_constitution=immutable,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "dynamic_only": self.dynamic_only,
            "task_holdout_delay_cycles": self.task_holdout_delay_cycles,
            "council_max_messages": self.council_max_messages,
            "council_max_tokens": self.council_max_tokens,
            "objective_history_window": self.objective_history_window,
            "objective_probation_cycles": self.objective_probation_cycles,
            "public_repo_url": self.public_repo_url,
            "public_stable_branch": self.public_stable_branch,
            "candidate_branch_prefix": self.candidate_branch_prefix,
            "builder_public_internet": self.builder_public_internet,
            "builder_block_private_networks": self.builder_block_private_networks,
            "runtime_network": self.runtime_network,
            "external_writes_via_connectors": self.external_writes_via_connectors,
            "role_activation_automatic": self.role_activation_automatic,
            "immutable_safety_constitution": self.immutable_safety_constitution,
        }


@dataclass(frozen=True, slots=True)
class RoleConfig:
    model: str
    budget_share: float
    max_output_tokens: int
    reasoning_effort: str | None = None

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any], *, expected_share: float) -> "RoleConfig":
        _exact(
            settable := dict(data),
            {"model", "budget_share", "max_output_tokens", "reasoning_effort"},
            {"model", "budget_share", "max_output_tokens"},
            "role",
        )
        model = settable["model"]
        share = settable["budget_share"]
        if not isinstance(model, str) or not model.strip():
            raise ConfigError("role.model must be a non-empty string")
        if (
            not isinstance(share, (int, float))
            or isinstance(share, bool)
            or abs(float(share) - expected_share) > 1e-9
        ):
            raise ConfigError(f"role.budget_share must be {expected_share}")
        reasoning_effort = settable.get("reasoning_effort")
        if reasoning_effort not in {None, "none", "low", "medium", "high"}:
            raise ConfigError("role.reasoning_effort must be null, 'none', 'low', 'medium', or 'high'")
        return cls(
            model.strip(),
            float(share),
            _positive_int(settable["max_output_tokens"], "role.max_output_tokens"),
            reasoning_effort,
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.model,
            "budget_share": self.budget_share,
            "max_output_tokens": self.max_output_tokens,
        }
        if self.reasoning_effort is not None:
            payload["reasoning_effort"] = self.reasoning_effort
        return payload


@dataclass(frozen=True, slots=True)
class CampaignConfig:
    campaign_id: str
    max_rounds: int
    total_tokens: int
    max_requests: int
    wall_time_seconds: int
    roles: Mapping[str, RoleConfig]
    task_pack_paths: tuple[str, ...]
    max_agent_steps: int = 20
    research_enabled: bool = True
    offline_research: bool = False
    test_mode: bool = False
    demo_mode: bool = False
    sandbox_backend: str = "wsl"
    acceptance_profile: str | None = None
    evolution_promotion_smoke_only: bool = False
    autonomy_v2: AutonomyV2Config | None = None

    _FIELDS = frozenset(
        {
            "campaign_id",
            "max_rounds",
            "total_tokens",
            "max_requests",
            "wall_time_seconds",
            "roles",
            "task_pack_paths",
            "max_agent_steps",
            "research_enabled",
            "offline_research",
            "test_mode",
            "demo_mode",
            "sandbox_backend",
            "acceptance_profile",
            "evolution_promotion_smoke_only",
            "autonomy_v2",
        }
    )
    _REQUIRED = frozenset(
        {
            "campaign_id",
            "max_rounds",
            "total_tokens",
            "max_requests",
            "wall_time_seconds",
            "roles",
            "task_pack_paths",
        }
    )
    _SHARES = {"warrior": 0.60, "judge": 0.25, "prosecutor": 0.15}

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "CampaignConfig":
        raw = dict(data)
        _exact(raw, set(cls._FIELDS), set(cls._REQUIRED), "campaign")
        campaign_id = raw["campaign_id"]
        if (
            not isinstance(campaign_id, str)
            or not campaign_id
            or not all(ch.isalnum() or ch in "-_" for ch in campaign_id)
        ):
            raise ConfigError("campaign_id must contain only letters, digits, '-' and '_'")
        acceptance_profile = raw.get("acceptance_profile")
        if acceptance_profile not in {None, *AUTONOMY_ACCEPTANCE_PROFILES}:
            raise ConfigError(
                "acceptance_profile must be null, 'autonomous_evolution_v1', or "
                "'autonomous_evolution_v2'"
            )
        expected_shares = (
            AUTONOMY_ROLE_SHARES
            if acceptance_profile in AUTONOMY_ACCEPTANCE_PROFILES
            else cls._SHARES
        )
        roles_raw = raw["roles"]
        if not isinstance(roles_raw, Mapping) or set(roles_raw) != set(cls._SHARES):
            raise ConfigError("roles must contain exactly warrior, judge and prosecutor")
        roles: dict[str, RoleConfig] = {}
        for name, share in expected_shares.items():
            value = roles_raw[name]
            if not isinstance(value, Mapping):
                raise ConfigError(f"roles.{name} must be an object")
            roles[name] = RoleConfig.from_mapping(value, expected_share=share)
        if acceptance_profile in AUTONOMY_ACCEPTANCE_PROFILES:
            if _positive_int(raw.get("max_agent_steps", 20), "max_agent_steps") < AUTONOMY_MIN_AGENT_STEPS:
                raise ConfigError(
                    f"acceptance profile requires max_agent_steps >= {AUTONOMY_MIN_AGENT_STEPS}"
                )
            if any(role.max_output_tokens < AUTONOMY_MIN_OUTPUT_TOKENS for role in roles.values()):
                raise ConfigError(
                    f"acceptance profile requires max_output_tokens >= {AUTONOMY_MIN_OUTPUT_TOKENS}"
                )
        pack_paths = raw["task_pack_paths"]
        if not isinstance(pack_paths, list) or not all(
            isinstance(item, str) and item.strip() for item in pack_paths
        ):
            raise ConfigError("task_pack_paths must be an array of paths")
        normalized_paths = tuple(item.strip() for item in pack_paths)
        if len(set(normalized_paths)) != len(normalized_paths):
            raise ConfigError("task_pack_paths must not contain duplicates")
        if not all(Path(item).is_absolute() for item in normalized_paths):
            raise ConfigError("task_pack_paths must contain only absolute paths")
        research_enabled = raw.get("research_enabled", True)
        offline_research = raw.get("offline_research", False)
        test_mode = raw.get("test_mode", False)
        demo_mode = raw.get("demo_mode", False)
        for name, value in (
            ("research_enabled", research_enabled),
            ("offline_research", offline_research),
            ("test_mode", test_mode),
            ("demo_mode", demo_mode),
        ):
            if not isinstance(value, bool):
                raise ConfigError(f"{name} must be a boolean")
        smoke_only = raw.get("evolution_promotion_smoke_only", False)
        if not isinstance(smoke_only, bool):
            raise ConfigError("evolution_promotion_smoke_only must be a boolean")
        if test_mode and demo_mode:
            raise ConfigError("test_mode and demo_mode are mutually exclusive")
        if offline_research and not (test_mode or demo_mode):
            raise ConfigError("offline_research is allowed only in test or explicit demo mode")
        if not research_enabled and not (test_mode or demo_mode):
            raise ConfigError("research may be disabled only in test or explicit demo mode")
        backend = raw.get("sandbox_backend", "wsl")
        if backend not in {"wsl", "fake"}:
            raise ConfigError("sandbox_backend must be 'wsl' or 'fake'")
        if backend == "fake" and not test_mode:
            raise ConfigError("fake sandbox is allowed only with test_mode=true")
        autonomy_v2_raw = raw.get("autonomy_v2")
        if autonomy_v2_raw is not None and not isinstance(autonomy_v2_raw, Mapping):
            raise ConfigError("autonomy_v2 must be an object or null")
        autonomy_v2 = (
            AutonomyV2Config.from_mapping(autonomy_v2_raw)
            if isinstance(autonomy_v2_raw, Mapping)
            else None
        )
        if autonomy_v2 is not None and autonomy_v2.enabled:
            if acceptance_profile != "autonomous_evolution_v2":
                raise ConfigError("enabled autonomy_v2 requires acceptance_profile autonomous_evolution_v2")
            if normalized_paths:
                raise ConfigError("dynamic-only autonomy_v2 must not configure fixed task_pack_paths")
        elif not normalized_paths:
            raise ConfigError("task_pack_paths must be non-empty unless dynamic autonomy_v2 is enabled")
        return cls(
            campaign_id,
            _positive_int(raw["max_rounds"], "max_rounds"),
            _positive_int(raw["total_tokens"], "total_tokens"),
            _positive_int(raw["max_requests"], "max_requests"),
            _positive_int(raw["wall_time_seconds"], "wall_time_seconds"),
            roles,
            normalized_paths,
            _positive_int(raw.get("max_agent_steps", 20), "max_agent_steps"),
            research_enabled,
            offline_research,
            test_mode,
            demo_mode,
            backend,
            acceptance_profile,
            smoke_only,
            autonomy_v2,
        )

    @classmethod
    def load(cls, path: str | Path) -> "CampaignConfig":
        try:
            value = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ConfigError(f"cannot read campaign JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise ConfigError("campaign JSON must be an object")
        return cls.from_mapping(value)

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "campaign_id": self.campaign_id,
            "max_rounds": self.max_rounds,
            "total_tokens": self.total_tokens,
            "max_requests": self.max_requests,
            "wall_time_seconds": self.wall_time_seconds,
            "roles": {name: role.to_dict() for name, role in self.roles.items()},
            "task_pack_paths": list(self.task_pack_paths),
            "max_agent_steps": self.max_agent_steps,
            "research_enabled": self.research_enabled,
            "offline_research": self.offline_research,
            "test_mode": self.test_mode,
            "demo_mode": self.demo_mode,
            "sandbox_backend": self.sandbox_backend,
            "acceptance_profile": self.acceptance_profile,
            "evolution_promotion_smoke_only": self.evolution_promotion_smoke_only,
        }
        if self.autonomy_v2 is not None:
            payload["autonomy_v2"] = self.autonomy_v2.to_dict()
        return payload

    def dump(self, path: str | Path) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
