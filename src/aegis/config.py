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

NETWORK_ALLOWLIST_DOMAINS = (
    "github.com",
    "raw.githubusercontent.com",
    "api.github.com",
    "pypi.org",
    "files.pythonhosted.org",
    "arxiv.org",
    "huggingface.co",
    "cdn-lfs.huggingface.co",
)


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
    network_allowlist_domains: tuple[str, ...] = NETWORK_ALLOWLIST_DOMAINS
    external_writes_via_connectors: bool = True
    role_activation_automatic: bool = True
    immutable_safety_constitution: bool = True
    evolution_surfaces: tuple[str, ...] = (
        "workflow",
        "subject",
        "plugin",
        "environment",
    )
    harness_evolution_enabled: bool = False
    harness_repo_root: str | None = None
    harness_canary_command: tuple[str, ...] | None = None
    harness_activation_automatic: bool = True
    meta_evolution_enabled: bool = False
    subagent_max_steps: int = 8
    subagent_timeout_seconds: float = 180.0
    subagent_max_concurrency: int = 2
    subagent_max_result_bytes: int = 65_536
    environment_output_repository: str | None = None
    scanner_binary: str = "trivy"
    candidate_max_extra_steps: int = 12

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
            "network_allowlist_domains",
            "external_writes_via_connectors",
            "role_activation_automatic",
            "immutable_safety_constitution",
            "evolution_surfaces",
            "harness_evolution_enabled",
            "harness_repo_root",
            "harness_canary_command",
            "harness_activation_automatic",
            "meta_evolution_enabled",
            "subagent_max_steps",
            "subagent_timeout_seconds",
            "subagent_max_concurrency",
            "subagent_max_result_bytes",
            "environment_output_repository",
            "scanner_binary",
            "candidate_max_extra_steps",
        }
    )
    _EVOLUTION_SURFACES = frozenset(
        {"workflow", "subject", "plugin", "environment", "harness-code"}
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
        if runtime_network not in {"none", "allowlist"}:
            raise ConfigError("autonomy_v2.runtime_network must be 'none' or 'allowlist'")
        allowlist = raw.get("network_allowlist_domains", NETWORK_ALLOWLIST_DOMAINS)
        if (
            not isinstance(allowlist, (list, tuple))
            or not allowlist
            or len(allowlist) != len(set(allowlist))
        ):
            raise ConfigError(
                "autonomy_v2.network_allowlist_domains must be a unique non-empty list"
            )
        normalized_allowlist: list[str] = []
        for domain in allowlist:
            if (
                not isinstance(domain, str)
                or not domain
                or domain != domain.strip().lower()
                or any(
                    character
                    not in "abcdefghijklmnopqrstuvwxyz0123456789.-"
                    for character in domain
                )
                or domain.startswith(".")
                or domain.endswith(".")
                or ".." in domain
                or "://" in domain
            ):
                raise ConfigError(
                    "autonomy_v2.network_allowlist_domains entries must be plain domain names"
                )
            normalized_allowlist.append(domain)
        harness_enabled = _bool(
            raw.get("harness_evolution_enabled", False),
            "autonomy_v2.harness_evolution_enabled",
        )
        harness_root = raw.get("harness_repo_root")
        if harness_root is not None and (
            not isinstance(harness_root, str)
            or not harness_root.strip()
            or harness_root != harness_root.strip()
            or "\x00" in harness_root
        ):
            raise ConfigError("autonomy_v2.harness_repo_root must be null or a trimmed path")
        harness_canary = raw.get("harness_canary_command")
        if harness_canary is not None and (
            not isinstance(harness_canary, (list, tuple))
            or not harness_canary
            or len(harness_canary) > 16
            or any(
                not isinstance(item, str) or not item or "\x00" in item
                for item in harness_canary
            )
        ):
            raise ConfigError(
                "autonomy_v2.harness_canary_command must be null or a bounded argv list"
            )
        harness_auto = _bool(
            raw.get("harness_activation_automatic", True),
            "autonomy_v2.harness_activation_automatic",
        )
        meta_evolution = _bool(
            raw.get("meta_evolution_enabled", False),
            "autonomy_v2.meta_evolution_enabled",
        )
        subagent_steps = _positive_int(
            raw.get("subagent_max_steps", 8), "autonomy_v2.subagent_max_steps"
        )
        if subagent_steps > 1000:
            raise ConfigError("autonomy_v2.subagent_max_steps must be at most 1000")
        subagent_timeout = raw.get("subagent_timeout_seconds", 180.0)
        if (
            isinstance(subagent_timeout, bool)
            or not isinstance(subagent_timeout, (int, float))
            or not 1 <= float(subagent_timeout) <= 3600
        ):
            raise ConfigError("autonomy_v2.subagent_timeout_seconds must be in [1, 3600]")
        subagent_concurrency = _positive_int(
            raw.get("subagent_max_concurrency", 2),
            "autonomy_v2.subagent_max_concurrency",
        )
        if subagent_concurrency > 16:
            raise ConfigError("autonomy_v2.subagent_max_concurrency must be at most 16")
        subagent_result_bytes = _positive_int(
            raw.get("subagent_max_result_bytes", 65_536),
            "autonomy_v2.subagent_max_result_bytes",
        )
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
        surfaces = raw.get("evolution_surfaces", ("workflow", "subject", "plugin", "environment"))
        if not isinstance(surfaces, (list, tuple)) or not surfaces or len(surfaces) != len(set(surfaces)):
            raise ConfigError("autonomy_v2.evolution_surfaces must be a unique non-empty list")
        if any(not isinstance(item, str) or item not in cls._EVOLUTION_SURFACES for item in surfaces):
            raise ConfigError("autonomy_v2.evolution_surfaces contains an unknown surface")
        environment_output = raw.get("environment_output_repository")
        if environment_output is not None:
            if (
                not isinstance(environment_output, str)
                or not environment_output
                or environment_output != environment_output.strip()
                or any(
                    character
                    not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/-"
                    for character in environment_output
                )
                or environment_output.startswith("/")
                or ".." in environment_output
            ):
                raise ConfigError("autonomy_v2.environment_output_repository is invalid")
        scanner_binary = raw.get("scanner_binary", "trivy")
        if not isinstance(scanner_binary, str) or not scanner_binary or scanner_binary != scanner_binary.strip():
            raise ConfigError("autonomy_v2.scanner_binary must be a non-empty trimmed string")
        candidate_steps = _positive_int(
            raw.get("candidate_max_extra_steps", 12),
            "autonomy_v2.candidate_max_extra_steps",
        )
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
            network_allowlist_domains=tuple(normalized_allowlist),
            external_writes_via_connectors=connectors,
            role_activation_automatic=automatic,
            immutable_safety_constitution=immutable,
            evolution_surfaces=tuple(surfaces),
            harness_evolution_enabled=harness_enabled,
            harness_repo_root=harness_root,
            harness_canary_command=(
                tuple(harness_canary) if harness_canary is not None else None
            ),
            harness_activation_automatic=harness_auto,
            meta_evolution_enabled=meta_evolution,
            subagent_max_steps=subagent_steps,
            subagent_timeout_seconds=float(subagent_timeout),
            subagent_max_concurrency=subagent_concurrency,
            subagent_max_result_bytes=subagent_result_bytes,
            environment_output_repository=environment_output,
            scanner_binary=scanner_binary,
            candidate_max_extra_steps=candidate_steps,
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
            "network_allowlist_domains": list(self.network_allowlist_domains),
            "external_writes_via_connectors": self.external_writes_via_connectors,
            "role_activation_automatic": self.role_activation_automatic,
            "immutable_safety_constitution": self.immutable_safety_constitution,
            "evolution_surfaces": list(self.evolution_surfaces),
            "harness_evolution_enabled": self.harness_evolution_enabled,
            "harness_repo_root": self.harness_repo_root,
            "harness_canary_command": (
                list(self.harness_canary_command)
                if self.harness_canary_command is not None
                else None
            ),
            "harness_activation_automatic": self.harness_activation_automatic,
            "meta_evolution_enabled": self.meta_evolution_enabled,
            "subagent_max_steps": self.subagent_max_steps,
            "subagent_timeout_seconds": self.subagent_timeout_seconds,
            "subagent_max_concurrency": self.subagent_max_concurrency,
            "subagent_max_result_bytes": self.subagent_max_result_bytes,
            "environment_output_repository": self.environment_output_repository,
            "scanner_binary": self.scanner_binary,
            "candidate_max_extra_steps": self.candidate_max_extra_steps,
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
        if reasoning_effort not in {None, "none", "low", "medium", "high", "max"}:
            raise ConfigError(
                "role.reasoning_effort must be null, 'none', 'low', 'medium', 'high', or 'max'"
            )
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
        }
        if self.autonomy_v2 is not None:
            payload["autonomy_v2"] = self.autonomy_v2.to_dict()
        return payload

    def dump(self, path: str | Path) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
