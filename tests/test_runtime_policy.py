from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from aegis.artifacts import ContentAddressedArtifactStore
from aegis.event_store import EventStore
from aegis.models import Role
from aegis.runtime_policy import (
    RuntimePolicyConflictError,
    RuntimePolicyError,
    RuntimePolicyRegistry,
    RuntimePolicyVersion,
    RuntimeStageBoundary,
)


def _values() -> dict[str, Any]:
    return {
        "max_cost_usd": 10.0,
        "max_total_tokens": 100_000,
        "max_requests": 100,
        "max_rounds": 20,
        "max_runtime_seconds": 7200.0,
        "role_budget_shares": {"warrior": 0.4, "judge": 0.3, "prosecutor": 0.3},
        "role_max_output_tokens": {"warrior": 8192, "judge": 8192, "prosecutor": 8192},
        "max_steps": 20,
        "candidate_max_extra_steps": 12,
        "subagent_max_steps": 8,
        "command_timeout_seconds": 300.0,
        "sealed_timeout_seconds": 1800.0,
        "subagent_timeout_seconds": 180.0,
        "build_timeout_seconds": 3600.0,
        "scan_timeout_seconds": 600.0,
        "council_max_messages": 12,
        "council_max_tokens": 16_384,
    }


def _provider_limits() -> dict[str, int]:
    return {"warrior": 16_384, "judge": 16_384, "prosecutor": 16_384}


def _registry(tmp_path: Path, campaign: str = "campaign-a") -> tuple[EventStore, RuntimePolicyRegistry]:
    store = EventStore(tmp_path / "events.sqlite3")
    artifacts = ContentAddressedArtifactStore(tmp_path / "artifacts")
    return store, RuntimePolicyRegistry(store, artifacts, campaign)


def test_version_is_immutable_content_addressed_and_provider_bounded() -> None:
    first = RuntimePolicyVersion.create(
        parent_policy_id=None,
        effective_cycle=0,
        values=_values(),
        provider_output_limits=_provider_limits(),
    )
    second = RuntimePolicyVersion.create(
        parent_policy_id=None,
        effective_cycle=0,
        values=_values(),
        provider_output_limits=_provider_limits(),
    )
    assert first == second
    assert first.policy_id.startswith("runtime-policy-sha256:")
    with pytest.raises(TypeError):
        first.values["max_steps"] = 21  # type: ignore[index]

    too_large = _values()
    too_large["role_max_output_tokens"] = {
        "warrior": 16_385,
        "judge": 8192,
        "prosecutor": 8192,
    }
    with pytest.raises(RuntimePolicyError, match="provider output profile"):
        RuntimePolicyVersion.create(
            parent_policy_id=None,
            effective_cycle=0,
            values=too_large,
            provider_output_limits=_provider_limits(),
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("max_steps", 1001, "at most 1000"),
        ("command_timeout_seconds", 3601, "at most 3600"),
        ("sealed_timeout_seconds", 3601, "at most 3600"),
        ("build_timeout_seconds", 86_401, "at most 86400"),
    ],
)
def test_technical_caps_are_enforced(field: str, value: int, message: str) -> None:
    values = _values()
    values[field] = value
    with pytest.raises(RuntimePolicyError, match=message):
        RuntimePolicyVersion.create(
            parent_policy_id=None,
            effective_cycle=0,
            values=values,
            provider_output_limits=_provider_limits(),
        )


def test_registry_applies_prosecutor_patch_at_next_cycle_and_replays(tmp_path: Path) -> None:
    store, registry = _registry(tmp_path)
    genesis = registry.genesis(_values(), _provider_limits())
    amendment = registry.request_patch(
        requested_by=Role.PROSECUTOR,
        current_cycle=2,
        patch={"max_steps": 40, "max_total_tokens": 150_000},
        consumed={"max_total_tokens": 20_000},
        reason="allow a longer repair pass",
    )
    assert amendment.effective_cycle == 3
    assert registry.effective_for_cycle(2).policy_id == genesis.policy_id
    assert registry.effective_for_cycle(3).values["max_steps"] == 40

    replayed = RuntimePolicyRegistry(store, registry.artifacts, "campaign-a")
    assert replayed.effective_for_cycle(3).policy_id == amendment.resulting_policy_id
    assert replayed.amendment_for_cycle(2) == amendment
    store.close()


def test_only_prosecutor_may_amend_and_safety_fields_are_not_in_schema(tmp_path: Path) -> None:
    store, registry = _registry(tmp_path)
    registry.genesis(_values(), _provider_limits())
    with pytest.raises(RuntimePolicyError, match="only the prosecutor"):
        registry.request_patch(
            requested_by=Role.WARRIOR,
            current_cycle=0,
            patch={"max_steps": 21},
            consumed={},
            reason="not authorized",
        )
    for forbidden in ("windows_interop", "wsl_mounts", "cpu_limit", "memory_bytes", "pid_limit", "disk_bytes", "sandbox_concurrency"):
        with pytest.raises(RuntimePolicyError, match="cannot modify"):
            registry.request_patch(
                requested_by=Role.PROSECUTOR,
                current_cycle=0,
                patch={forbidden: 1},
                consumed={},
                reason="attempt to weaken the envelope",
            )
    store.close()


def test_same_cycle_is_idempotent_but_conflicting_amendment_is_rejected(tmp_path: Path) -> None:
    store, registry = _registry(tmp_path)
    registry.genesis(_values(), _provider_limits())
    kwargs = {
        "requested_by": Role.PROSECUTOR,
        "current_cycle": 4,
        "patch": {"max_steps": 25},
        "consumed": {},
        "reason": "expand deliberation",
    }
    first = registry.request_patch(**kwargs)
    assert registry.request_patch(**kwargs).amendment_id == first.amendment_id
    with pytest.raises(RuntimePolicyConflictError, match="different runtime policy amendment"):
        registry.request_patch(
            requested_by=Role.PROSECUTOR,
            current_cycle=4,
            patch={"max_steps": 26},
            consumed={},
            reason="a conflicting decision",
        )
    store.close()


def test_lowering_below_consumed_enters_maintenance_only(tmp_path: Path) -> None:
    store, registry = _registry(tmp_path)
    registry.genesis(_values(), _provider_limits())
    amendment = registry.request_patch(
        requested_by=Role.PROSECUTOR,
        current_cycle=0,
        patch={"max_total_tokens": 10_000, "max_requests": 3},
        consumed={"max_total_tokens": 12_000, "max_requests": 4},
        reason="stop new work after the maintenance turn",
    )
    policy = registry.effective_for_cycle(1)
    assert policy.policy_id == amendment.resulting_policy_id
    assert policy.maintenance_only is True
    assert policy.maintenance_reasons == ("max_requests", "max_total_tokens")

    replayed = RuntimePolicyRegistry(store, registry.artifacts, "campaign-a")
    assert replayed.effective_for_cycle(1) == policy
    store.close()


def test_rollback_is_a_new_next_cycle_version_and_observes_current_usage(tmp_path: Path) -> None:
    store, registry = _registry(tmp_path)
    genesis = registry.genesis(_values(), _provider_limits())
    registry.request_patch(
        requested_by=Role.PROSECUTOR,
        current_cycle=0,
        patch={"max_steps": 50},
        consumed={},
        reason="temporary expansion",
    )
    rollback = registry.request_rollback(
        requested_by=Role.PROSECUTOR,
        current_cycle=1,
        target_policy_id=genesis.policy_id,
        consumed={},
        reason="restore the proven settings",
    )
    restored = registry.effective_for_cycle(2)
    assert rollback.rollback_target_policy_id == genesis.policy_id
    assert restored.policy_id != genesis.policy_id
    assert restored.parent_policy_id == registry.effective_for_cycle(1).policy_id
    assert restored.values == genesis.values
    store.close()


def test_paired_design_policy_is_frozen_and_replayable(tmp_path: Path) -> None:
    store, registry = _registry(tmp_path)
    genesis = registry.genesis(_values(), _provider_limits())
    assert registry.freeze_for_paired_design("candidate-design-sha256:" + "a" * 64, 0) == genesis.policy_id
    registry.request_patch(
        requested_by=Role.PROSECUTOR,
        current_cycle=0,
        patch={"max_steps": 30},
        consumed={},
        reason="next cycle gets more steps",
    )
    design_id = "candidate-design-sha256:" + "a" * 64
    assert registry.policy_for_paired_design(design_id).policy_id == genesis.policy_id
    assert registry.freeze_for_paired_design(design_id, 0) == genesis.policy_id
    with pytest.raises(RuntimePolicyConflictError, match="another policy"):
        registry.freeze_for_paired_design(design_id, 1)
    replayed = RuntimePolicyRegistry(store, registry.artifacts, "campaign-a")
    assert replayed.policy_for_paired_design(design_id).policy_id == genesis.policy_id
    store.close()


def test_stage_amendment_activates_only_at_the_next_boundary_and_replays(
    tmp_path: Path,
) -> None:
    store, registry = _registry(tmp_path)
    genesis = registry.genesis(_values(), _provider_limits())
    prosecutor = RuntimeStageBoundary(2, 3, "prosecutor")
    next_stage = RuntimeStageBoundary(2, 4, "attribution")
    amendment = registry.request_patch_after_stage(
        requested_by=Role.PROSECUTOR,
        requested_at=prosecutor,
        effective_at=next_stage,
        patch={"max_steps": 40, "command_timeout_seconds": 600.0},
        consumed={},
        reason="expand the next stage",
    )

    assert registry.effective_for_stage(prosecutor).policy_id == genesis.policy_id
    effective = registry.effective_for_stage(next_stage)
    assert effective.policy_id == amendment.resulting_policy_id
    assert effective.values["max_steps"] == 40
    assert registry.effective_for_stage(RuntimeStageBoundary(2, 5, "sealed")).policy_id == (
        effective.policy_id
    )

    replayed = RuntimePolicyRegistry(store, registry.artifacts, "campaign-a")
    assert replayed.amendment_for_stage(prosecutor) == amendment
    assert replayed.effective_for_stage(next_stage) == effective
    store.close()


def test_stage_amendments_chain_and_conflicts_are_idempotent(tmp_path: Path) -> None:
    store, registry = _registry(tmp_path)
    registry.genesis(_values(), _provider_limits())
    first = RuntimeStageBoundary(0, 1, "prosecutor")
    second = RuntimeStageBoundary(0, 2, "judge")
    third = RuntimeStageBoundary(0, 3, "sealed")
    kwargs = {
        "requested_by": Role.PROSECUTOR,
        "requested_at": first,
        "effective_at": second,
        "patch": {"max_steps": 30},
        "consumed": {},
        "reason": "next stage needs more steps",
    }
    amendment = registry.request_patch_after_stage(**kwargs)
    assert registry.request_patch_after_stage(**kwargs) == amendment
    registry.request_patch_after_stage(
        requested_by=Role.PROSECUTOR,
        requested_at=second,
        effective_at=third,
        patch={"max_steps": 35},
        consumed={},
        reason="sealed stage needs more steps",
    )
    assert registry.effective_for_stage(third).values["max_steps"] == 35
    with pytest.raises(RuntimePolicyConflictError, match="another stage name"):
        registry.effective_for_stage(RuntimeStageBoundary(0, 3, "wrong-name"))
    with pytest.raises(RuntimePolicyConflictError, match="different runtime policy amendment"):
        registry.request_patch_after_stage(
            requested_by=Role.PROSECUTOR,
            requested_at=first,
            effective_at=second,
            patch={"max_steps": 31},
            consumed={},
            reason="conflicting amendment",
        )
    with pytest.raises(RuntimePolicyError, match="next stage boundary"):
        registry.request_patch_after_stage(
            requested_by=Role.PROSECUTOR,
            requested_at=third,
            effective_at=RuntimeStageBoundary(0, 5, "skipped"),
            patch={"max_steps": 36},
            consumed={},
            reason="cannot skip a stage",
        )
    store.close()


def test_paired_design_freeze_precedes_later_stage_amendment(tmp_path: Path) -> None:
    store, registry = _registry(tmp_path)
    genesis = registry.genesis(_values(), _provider_limits())
    design_boundary = RuntimeStageBoundary(1, 4, "sealed-design")
    design_id = "candidate-design-sha256:" + "b" * 64
    assert (
        registry.freeze_for_paired_design(
            design_id, 1, boundary=design_boundary
        )
        == genesis.policy_id
    )
    next_stage = RuntimeStageBoundary(1, 5, "sealed-arms")
    registry.request_patch_after_stage(
        requested_by=Role.PROSECUTOR,
        requested_at=design_boundary,
        effective_at=next_stage,
        patch={"max_total_tokens": 150_000},
        consumed={},
        reason="raise later-stage budget",
    )
    assert registry.effective_for_stage(next_stage).policy_id != genesis.policy_id
    assert registry.policy_for_paired_design(design_id).policy_id == genesis.policy_id

    replayed = RuntimePolicyRegistry(store, registry.artifacts, "campaign-a")
    assert replayed.policy_for_paired_design(design_id).policy_id == genesis.policy_id
    store.close()


def test_stage_lowering_below_consumed_enters_maintenance_only(tmp_path: Path) -> None:
    store, registry = _registry(tmp_path)
    registry.genesis(_values(), _provider_limits())
    current = RuntimeStageBoundary(3, 7, "prosecutor")
    maintenance = RuntimeStageBoundary(3, 8, "maintenance")
    registry.request_patch_after_stage(
        requested_by=Role.PROSECUTOR,
        requested_at=current,
        effective_at=maintenance,
        patch={"max_requests": 2},
        consumed={"max_requests": 3},
        reason="enter bounded maintenance",
    )
    policy = registry.effective_for_stage(maintenance)
    assert policy.maintenance_only is True
    assert policy.maintenance_reasons == ("max_requests",)
    store.close()
