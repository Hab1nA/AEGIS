from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

import pytest

from aegis.agent_runtime import (
    FIXED_ROLE_MAX_STEPS,
    FIXED_ROLE_RESEARCH_ACTION_BUDGET,
    Action,
    RoleAgentRuntime,
    RuntimeLimits,
)
from aegis.artifacts import ContentAddressedArtifactStore
from aegis.cycle_ports import _validate_runtime_policy_council_decisions
from aegis.event_store import EventStore
from aegis.gateway.protocols import Role as GatewayRole
from aegis.gateway.types import (
    GatewayAttempt,
    GatewayAttemptResult,
    GatewayRequest,
    GatewayResponse,
    Message,
    TokenUsage,
)
from aegis.models import Role
from aegis.runtime_ledger import AccountingContext, GatewayAttemptObserver, RuntimeBudgetExceeded
from aegis.runtime_policy import (
    RuntimePolicyConflictError,
    RuntimePolicyError,
    RuntimePolicyRegistry,
    RuntimePolicyVersion,
    RuntimeStageBoundary,
)


def values_v2(**updates: Any) -> dict[str, Any]:
    roles = ("warrior", "judge", "prosecutor")
    def role_int(value: int) -> dict[str, int]:
        return {role: value for role in roles}

    def role_float(value: float) -> dict[str, float]:
        return {role: float(value) for role in roles}
    result: dict[str, Any] = {
        "max_total_tokens": 100_000,
        "max_requests": 100,
        "max_model_invocations": 20,
        "max_active_runtime_seconds": 7200.0,
        "role_token_shares": {"warrior": 0.5, "judge": 0.25, "prosecutor": 0.25},
        "role_max_steps": role_int(20),
        "role_max_output_tokens": role_int(8192),
        "role_reasoning_effort": {role: None for role in roles},
        "role_research_action_budgets": role_int(10),
        "role_command_timeout_seconds": role_float(300),
        "role_max_read_bytes": role_int(262144),
        "role_max_write_bytes": role_int(262144),
        "role_max_tool_output_bytes": role_int(524288),
        "role_max_search_results": role_int(20),
        "gateway_timeout_seconds": 900.0,
        "gateway_max_attempts": 6,
        "gateway_base_delay_seconds": 0.5,
        "gateway_max_delay_seconds": 4.0,
        "subagent_max_spawns_per_run": 8,
        "subagent_max_steps": 8,
        "subagent_timeout_seconds": 180.0,
        "subagent_max_result_bytes": 65536,
        "subagent_max_output_tokens": 8192,
        "subagent_max_total_tokens": 25000,
        "subagent_max_requests": 25,
        "max_evolution_requests_per_run": 1,
        "max_evolution_source_refs": 5,
        "task_authoring_attempts": 2,
        "task_proposals_per_cycle": 1,
        "cohort_limit": 8,
        "candidate_evaluations_per_cycle": 1,
        "candidate_max_steps": 12,
        "population_max_cells": 128,
        "council_max_messages": 24,
        "council_max_tokens": 1048576,
        "task_holdout_delay_cycles": 1,
        "objective_history_window": 3,
        "objective_probation_cycles": 2,
        "dependency_download_timeout_seconds": 600.0,
        "dependency_download_max_bytes": 536870912,
        "build_timeout_seconds": 3600.0,
        "scan_timeout_seconds": 600.0,
    }
    result.update(updates)
    return result


def registry(tmp_path: Path) -> tuple[EventStore, RuntimePolicyRegistry]:
    store = EventStore(tmp_path / "events.sqlite3")
    return store, RuntimePolicyRegistry(
        store, ContentAddressedArtifactStore(tmp_path / "artifacts"), "v2-campaign"
    )


def provider_limits() -> dict[str, int]:
    return {"warrior": 65536, "judge": 65536, "prosecutor": 65536}


def test_v2_has_no_legacy_economic_fields_and_accepts_values_above_old_caps() -> None:
    values = values_v2(
        role_max_steps={"warrior": 2001, "judge": 2001, "prosecutor": 2001},
        build_timeout_seconds=100000.0,
        scan_timeout_seconds=7200.0,
    )
    policy = RuntimePolicyVersion.create(
        parent_policy_id=None,
        effective_cycle=0,
        values=values,
        provider_output_limits=provider_limits(),
    )
    assert policy.schema_version == 2
    assert "max_cost_usd" not in policy.values
    assert policy.values["build_timeout_seconds"] == 100000.0

    with pytest.raises(RuntimePolicyError, match="bidirectional 0/1"):
        RuntimePolicyVersion.create(
            parent_policy_id=None,
            effective_cycle=0,
            values=values_v2(candidate_evaluations_per_cycle=2),
            provider_output_limits=provider_limits(),
        )


def test_v1_genesis_migrates_once_to_content_addressed_v2_child(tmp_path: Path) -> None:
    legacy = {
        "max_cost_usd": 10.0, "max_total_tokens": 100_000, "max_requests": 100,
        "max_rounds": 20, "max_runtime_seconds": 7200.0,
        "role_budget_shares": {"warrior": 0.5, "judge": 0.25, "prosecutor": 0.25},
        "role_max_output_tokens": {"warrior": 8192, "judge": 8192, "prosecutor": 8192},
        "max_steps": 20, "candidate_max_extra_steps": 12, "subagent_max_steps": 8,
        "command_timeout_seconds": 300.0, "sealed_timeout_seconds": 1800.0,
        "subagent_timeout_seconds": 180.0, "build_timeout_seconds": 3600.0,
        "scan_timeout_seconds": 600.0, "council_max_messages": 24,
        "council_max_tokens": 1048576,
    }
    store, policies = registry(tmp_path)
    historical = policies.genesis(legacy, provider_limits())
    migrated = policies.genesis(values_v2(), provider_limits())
    assert historical.schema_version == 1
    assert migrated.schema_version == 2
    assert migrated.parent_policy_id == historical.policy_id
    assert migrated.values["role_research_action_budgets"]["warrior"] == 10
    replayed = RuntimePolicyRegistry(store, policies.artifacts, "v2-campaign")
    assert replayed.genesis(values_v2(), provider_limits()).policy_id == migrated.policy_id
    assert len([event for event in store.read("v2-campaign") if event.event_type == "runtime_policy_migrated_v2"]) == 1
    store.close()


def test_v1_migration_uses_latest_scheduled_policy_and_keeps_cycle_order(tmp_path: Path) -> None:
    legacy = {
        "max_cost_usd": 10.0, "max_total_tokens": 100_000, "max_requests": 100,
        "max_rounds": 20, "max_runtime_seconds": 7200.0,
        "role_budget_shares": {"warrior": 0.5, "judge": 0.25, "prosecutor": 0.25},
        "role_max_output_tokens": {"warrior": 8192, "judge": 8192, "prosecutor": 8192},
        "max_steps": 20, "candidate_max_extra_steps": 12, "subagent_max_steps": 8,
        "command_timeout_seconds": 300.0, "sealed_timeout_seconds": 1800.0,
        "subagent_timeout_seconds": 180.0, "build_timeout_seconds": 3600.0,
        "scan_timeout_seconds": 600.0, "council_max_messages": 24,
        "council_max_tokens": 1048576,
    }
    store, policies = registry(tmp_path)
    genesis = policies.genesis(legacy, provider_limits())
    scheduled = policies.request_patch(
        requested_by=Role.PROSECUTOR,
        current_cycle=0,
        patch={"max_steps": 33},
        consumed={},
        reason="legacy scheduled increase",
    )
    migrated = policies.genesis(values_v2(), provider_limits())
    assert migrated.parent_policy_id == scheduled.resulting_policy_id
    assert migrated.values["role_max_steps"] == {
        "warrior": 33, "judge": 33, "prosecutor": 33,
    }
    assert policies.effective_for_cycle(0).policy_id == genesis.policy_id
    assert policies.effective_for_cycle(1).policy_id == migrated.policy_id
    replayed = RuntimePolicyRegistry(store, policies.artifacts, "v2-campaign")
    assert replayed.effective_for_cycle(1).policy_id == migrated.policy_id
    store.close()


def test_immediate_bidirectional_chain_stale_noop_and_council_replay(tmp_path: Path) -> None:
    store, policies = registry(tmp_path)
    genesis = policies.genesis(values_v2(), provider_limits())
    boundary = RuntimeStageBoundary(1, 3, "stage:3")
    first = policies.request_patch_immediately(
        requested_by=Role.PROSECUTOR,
        requested_at=boundary,
        request_id="raise-research",
        base_policy_id=genesis.policy_id,
        patch={"max_active_runtime_seconds": 9_000.0},
        consumed={},
        reason="warrior supplied evidence that more runtime is useful",
        evidence_refs=("reflection-sha256:" + "1" * 64,),
    )
    raised = policies.effective_for_stage(boundary)
    assert first.revision == 1
    assert raised.values["max_active_runtime_seconds"] == 9_000.0
    second = policies.request_patch_immediately(
        requested_by=Role.PROSECUTOR,
        requested_at=boundary,
        request_id="lower-runtime",
        base_policy_id=raised.policy_id,
        patch={"max_active_runtime_seconds": 5_000.0},
        consumed={},
        reason="later evidence favors convergence",
    )
    assert second.revision == 2
    assert policies.effective_for_stage(boundary).values["max_active_runtime_seconds"] == 5_000.0
    with pytest.raises(RuntimePolicyConflictError, match="stale"):
        policies.request_patch_immediately(
            requested_by=Role.PROSECUTOR,
            requested_at=boundary,
            request_id="stale",
            base_policy_id=genesis.policy_id,
            patch={"max_requests": 150},
            consumed={},
            reason="stale request",
        )
    with pytest.raises(RuntimePolicyError, match="no-op"):
        policies.request_patch_immediately(
            requested_by=Role.PROSECUTOR,
            requested_at=boundary,
            request_id="noop",
            base_policy_id=second.resulting_policy_id,
            patch={"max_active_runtime_seconds": 5_000.0},
            consumed={},
            reason="no change",
        )
    decision = policies.record_council_decision(
        amendment_id=first.amendment_id,
        decision="ratify",
        reason="the amendment was evidence-backed",
    )
    assert decision["decision"] == "ratify"
    replayed = RuntimePolicyRegistry(store, policies.artifacts, "v2-campaign")
    assert replayed.effective_for_stage(boundary).policy_id == second.resulting_policy_id
    assert [item.amendment_id for item in replayed.pending_council_amendments()] == [
        second.amendment_id
    ]
    store.close()


def test_immediate_request_id_reuse_requires_identical_content(tmp_path: Path) -> None:
    store, policies = registry(tmp_path)
    genesis = policies.genesis(values_v2(), provider_limits())
    boundary = RuntimeStageBoundary(0, 1, "audit")
    policies.request_patch_immediately(
        requested_by=Role.PROSECUTOR,
        requested_at=boundary,
        request_id="stable-request",
        base_policy_id=genesis.policy_id,
        patch={"max_active_runtime_seconds": 8_500.0},
        consumed={},
        reason="first request",
    )
    with pytest.raises(RuntimePolicyConflictError, match="request_id"):
        policies.request_patch_immediately(
            requested_by=Role.PROSECUTOR,
            requested_at=boundary,
            request_id="stable-request",
            base_policy_id=genesis.policy_id,
            patch={"max_active_runtime_seconds": 8_600.0},
            consumed={},
            reason="different request",
        )
    store.close()


def test_resume_boundary_keeps_immediate_policy_after_cycle_retry(tmp_path: Path) -> None:
    store, policies = registry(tmp_path)
    genesis = policies.genesis(values_v2(), provider_limits())
    first_boundary = RuntimeStageBoundary(2, 9, "repair")
    amendment = policies.request_patch_immediately(
        requested_by=Role.PROSECUTOR,
        requested_at=first_boundary,
        request_id="repair-share",
        base_policy_id=genesis.policy_id,
        patch={"max_requests": 500},
        consumed={},
        reason="raise request headroom after an exhaustion",
    )
    resumed = policies.resume_stage_boundary(2)
    assert resumed.ordinal == 9
    next_boundary = RuntimeStageBoundary(2, resumed.ordinal + 1, "retry-submission")
    assert policies.effective_for_stage(next_boundary).policy_id == amendment.resulting_policy_id
    store.close()


def test_v2_ledger_does_not_enforce_per_role_token_shares(tmp_path: Path) -> None:
    store, policies = registry(tmp_path)
    values = values_v2(
        max_total_tokens=200,
        role_token_shares={"warrior": 0.1, "judge": 0.45, "prosecutor": 0.45},
    )
    policies.genesis(values, provider_limits())
    context = AccountingContext(
        "v2-campaign", 0, "warrior", Role.WARRIOR, "warrior-invocation"
    )
    observer = GatewayAttemptObserver(store, policies, lambda _request: context)
    request = GatewayRequest("model", (Message("user", "hello"),), 10)
    first = GatewayAttempt("responses", 1, request, TokenUsage(5, 15, 5, 15, False))
    second = GatewayAttempt("responses", 2, request, TokenUsage(5, 15, 5, 15, False))
    # Shares are inert: the single envelope (not per-role shares) bounds cost.
    observer.before_attempt(first)
    observer.before_attempt(second)
    assert observer.consumed().role_tokens["warrior"] == 40
    store.close()


def test_lowering_envelope_below_consumed_enters_maintenance(tmp_path: Path) -> None:
    store, policies = registry(tmp_path)
    genesis = policies.genesis(values_v2(), provider_limits())
    amendment = policies.request_patch_immediately(
        requested_by=Role.PROSECUTOR,
        requested_at=RuntimeStageBoundary(0, 1, "stage:1"),
        request_id="lower-runtime",
        base_policy_id=genesis.policy_id,
        patch={"max_active_runtime_seconds": 100.0},
        consumed={
            "max_total_tokens": 20_000,
            "max_requests": 1,
            "max_model_invocations": 1,
            "max_active_runtime_seconds": 999_999.0,
            "role_tokens": {"warrior": 0, "judge": 0, "prosecutor": 0},
        },
        reason="reduce the future runtime envelope",
    )
    policy = policies.effective_for_stage(amendment.requested_at)
    assert policy.maintenance_only
    assert policy.maintenance_reasons == ("max_active_runtime_seconds",)
    store.close()


class DynamicDispatcher:
    def __init__(self, policy: dict[str, Any]) -> None:
        self.policy = policy
        self.limits = RuntimeLimits(max_steps=2)
        self.research_calls = 0

    def allowed_actions(self, role: GatewayRole) -> frozenset[str]:
        del role
        return frozenset({"research.search", "submit"})

    def update_runtime_limits(self, limits: RuntimeLimits) -> None:
        self.limits = limits

    def dispatch(self, role: GatewayRole, action: Action) -> Mapping[str, Any]:
        del role
        if action.name == "research.search":
            self.research_calls += 1
            if self.research_calls == 1:
                self.policy["role_max_steps"]["warrior"] = 4
                self.policy["role_research_action_budgets"]["warrior"] = 2
            return {"results": []}
        return {"summary": "done", "payload": {"research_calls": self.research_calls}}


class ActionGateway:
    def __init__(self) -> None:
        self.actions = [
            {"action": "research.search", "arguments": {"query": "one"}},
            {"action": "research.search", "arguments": {"query": "two"}},
            {"action": "submit", "arguments": {"summary": "done", "payload": {}}},
        ]

    def complete(self, request: Any, *, cancel: Any = None) -> GatewayResponse:
        del request, cancel
        return GatewayResponse(
            json.dumps(self.actions.pop(0)), TokenUsage(1, 1, 0, 0, True), "responses"
        )


def test_role_runtime_uses_fixed_safety_bounds_not_policy_budgets() -> None:
    policy = values_v2()
    policy["role_max_steps"]["warrior"] = 3
    policy["role_research_action_budgets"]["warrior"] = 1
    dispatcher = DynamicDispatcher(policy)
    runtime = RoleAgentRuntime(
        ActionGateway(),
        dispatcher,  # type: ignore[arg-type]
        "model",
        limits=RuntimeLimits(max_steps=3),
        policy_provider=lambda _role: policy,
    )
    result = runtime.run(GatewayRole.WARRIOR, objective="test", context={})
    assert result.submission == {"research_calls": 2}
    assert dispatcher.research_calls == 2
    assert len(result.observations) == 3
    # Role-level step and research budgets are fixed safety constants, so the
    # policy-provided values (3 steps / 1 research action) are ignored.
    assert runtime.limits.max_steps == FIXED_ROLE_MAX_STEPS
    assert runtime.research_action_budget == FIXED_ROLE_RESEARCH_ACTION_BUDGET


def test_immediate_patch_whitelist_rejects_non_envelope_fields(tmp_path: Path) -> None:
    store, policies = registry(tmp_path)
    genesis = policies.genesis(values_v2(), provider_limits())
    boundary = RuntimeStageBoundary(0, 1, "stage:1")
    blocked = (
        {"role_max_steps": {"warrior": 200, "judge": 200, "prosecutor": 200}},
        {"role_token_shares": {"warrior": 0.4, "judge": 0.3, "prosecutor": 0.3}},
        {"council_max_tokens": 1_000_000},
        {"role_research_action_budgets": {"warrior": 50, "judge": 50, "prosecutor": 50}},
        {"gateway_timeout_seconds": 7_200.0},
    )
    for index, patch in enumerate(blocked):
        with pytest.raises(RuntimePolicyError, match="cannot modify fields"):
            policies.request_patch_immediately(
                requested_by=Role.PROSECUTOR,
                requested_at=boundary,
                request_id=f"blocked-{index}",
                base_policy_id=genesis.policy_id,
                patch=patch,
                consumed={},
                reason="non-envelope fields are not tunable",
            )
    store.close()


def test_arm_maintenance_creates_maintenance_only_policy_and_survives_replay(
    tmp_path: Path,
) -> None:
    store, policies = registry(tmp_path)
    policies.genesis(values_v2(), provider_limits())
    boundary = RuntimeStageBoundary(1, 4, "stage:4")
    consumed = {
        "max_total_tokens": 120_000,
        "max_requests": 1,
        "max_model_invocations": 1,
        "max_active_runtime_seconds": 999_999.0,
        "role_tokens": {"warrior": 0, "judge": 0, "prosecutor": 0},
    }
    armed = policies.arm_maintenance(
        requested_at=boundary, consumed=consumed, reason="cycle budget exhausted"
    )
    assert armed.maintenance_only
    assert "max_total_tokens" in armed.maintenance_reasons
    assert "max_active_runtime_seconds" in armed.maintenance_reasons
    assert (
        policies.effective_for_stage(RuntimeStageBoundary(1, 5, "stage:5")).policy_id
        == armed.policy_id
    )
    assert policies.resume_stage_boundary(1) == boundary
    assert (
        policies.arm_maintenance(
            requested_at=boundary, consumed=consumed, reason="cycle budget exhausted"
        ).policy_id
        == armed.policy_id
    )
    store.close()
    store2 = EventStore(tmp_path / "events.sqlite3")
    policies2 = RuntimePolicyRegistry(
        store2, ContentAddressedArtifactStore(tmp_path / "artifacts"), "v2-campaign"
    )
    assert (
        policies2.effective_for_stage(RuntimeStageBoundary(1, 5, "stage:5")).policy_id
        == armed.policy_id
    )
    store2.close()


def test_maintenance_ledger_permits_prosecutor_amendment_after_arming(
    tmp_path: Path,
) -> None:
    store, policies = registry(tmp_path)
    genesis = policies.genesis(
        values_v2(max_active_runtime_seconds=7200.0), provider_limits()
    )
    boundary = RuntimeStageBoundary(0, 1, "stage:1")
    consumed = {
        "max_total_tokens": 50_000,
        "max_requests": 1,
        "max_model_invocations": 1,
        "max_active_runtime_seconds": 999_999.0,
        "role_tokens": {"warrior": 0, "judge": 0, "prosecutor": 0},
    }
    armed = policies.arm_maintenance(
        requested_at=boundary, consumed=consumed, reason="budget exhausted"
    )
    assert armed.parent_policy_id == genesis.policy_id

    def make_context(stage: str, ordinal: int, role: Role, invocation: str) -> AccountingContext:
        return AccountingContext(
            "v2-campaign", 0, stage, role, invocation, stage_ordinal=ordinal
        )

    calls: list[AccountingContext] = [
        make_context("maintenance", 2, Role.PROSECUTOR, "maintenance-invocation")
    ]
    observer = GatewayAttemptObserver(store, policies, lambda _request: calls.pop(0))
    request = GatewayRequest("model", (Message("user", "hello"),), 10)
    attempt = GatewayAttempt("responses", 1, request, TokenUsage(5, 15, 5, 15, False))
    observer.before_attempt(attempt)
    calls.append(make_context("role:warrior", 3, Role.WARRIOR, "warrior-invocation"))
    with pytest.raises(RuntimeBudgetExceeded, match="maintenance-only"):
        observer.before_attempt(attempt)
    amendment = policies.request_patch_immediately(
        requested_by=Role.PROSECUTOR,
        requested_at=RuntimeStageBoundary(0, 2, "stage:2"),
        request_id="raise-runtime",
        base_policy_id=armed.policy_id,
        patch={"max_active_runtime_seconds": 1_500_000.0},
        consumed=observer.consumed().to_policy_mapping(),
        reason="restore a viable active-runtime budget",
    )
    restored = policies.effective_for_stage(RuntimeStageBoundary(0, 3, "stage:3"))
    assert restored.policy_id == amendment.resulting_policy_id
    assert not restored.maintenance_only
    calls.append(make_context("role:warrior", 4, Role.WARRIOR, "warrior-invocation-2"))
    observer.before_attempt(attempt)
    assert observer.consumed().requests == 2
    store.close()


def _armed_maintenance_ledger(tmp_path: Path):
    store, policies = registry(tmp_path)
    genesis = policies.genesis(
        values_v2(max_active_runtime_seconds=7200.0), provider_limits()
    )
    consumed = {
        "max_total_tokens": 50_000,
        "max_requests": 1,
        "max_model_invocations": 1,
        "max_active_runtime_seconds": 999_999.0,
        "role_tokens": {"warrior": 0, "judge": 0, "prosecutor": 0},
    }
    armed = policies.arm_maintenance(
        requested_at=RuntimeStageBoundary(0, 1, "stage:1"),
        consumed=consumed,
        reason="budget exhausted",
    )
    calls: list[AccountingContext] = []

    def provider(_request: GatewayRequest) -> AccountingContext:
        return calls.pop(0)

    observer = GatewayAttemptObserver(store, policies, provider)
    request = GatewayRequest("model", (Message("user", "hello"),), 10)
    usage = TokenUsage(5, 15, 5, 15, False)
    attempt = GatewayAttempt("responses", 1, request, usage)
    return store, genesis, armed, calls, observer, request, usage, attempt


def test_maintenance_invocation_budget_is_released_after_transport_failure(
    tmp_path: Path,
) -> None:
    store, _genesis, _armed, calls, observer, _request, usage, attempt = (
        _armed_maintenance_ledger(tmp_path)
    )
    first = AccountingContext(
        "v2-campaign", 0, "maintenance", Role.PROSECUTOR,
        "maintenance-invocation-1", stage_ordinal=2,
    )
    calls.append(first)
    observer.before_attempt(attempt)
    calls.append(first)
    observer.after_attempt(
        attempt,
        GatewayAttemptResult(
            succeeded=False, usage=usage, status=401, error_type="GatewayHTTPError"
        ),
    )
    second = AccountingContext(
        "v2-campaign", 0, "maintenance", Role.PROSECUTOR,
        "maintenance-invocation-2", stage_ordinal=3,
    )
    calls.append(second)
    observer.before_attempt(attempt)
    consumed = observer.consumed()
    assert consumed.requests == 1
    assert consumed.waste_requests == 1
    store.close()


def test_maintenance_invocation_budget_is_not_released_after_success(
    tmp_path: Path,
) -> None:
    store, _genesis, _armed, calls, observer, _request, usage, attempt = (
        _armed_maintenance_ledger(tmp_path)
    )
    first = AccountingContext(
        "v2-campaign", 0, "maintenance", Role.PROSECUTOR,
        "maintenance-invocation-1", stage_ordinal=2,
    )
    calls.append(first)
    observer.before_attempt(attempt)
    calls.append(first)
    observer.after_attempt(
        attempt,
        GatewayAttemptResult(succeeded=True, usage=usage, status=200),
    )
    second = AccountingContext(
        "v2-campaign", 0, "maintenance", Role.PROSECUTOR,
        "maintenance-invocation-2", stage_ordinal=3,
    )
    calls.append(second)
    with pytest.raises(RuntimeBudgetExceeded, match="maintenance-only policy permits one invocation"):
        observer.before_attempt(attempt)
    store.close()


def test_runtime_policy_council_decisions_are_fully_validated_before_use() -> None:
    pending = {"amendment-b", "amendment-a"}
    decisions = _validate_runtime_policy_council_decisions(
        [
            {
                "amendment_id": "amendment-b",
                "decision": "rollback",
                "reason": "restore the prior values",
                "replacement_amendment_id": "replacement-b",
            },
            {
                "amendment_id": "amendment-a",
                "decision": "ratify",
                "reason": "evidence supports the change",
                "replacement_amendment_id": None,
            },
        ],
        pending,
    )
    assert [item["amendment_id"] for item in decisions] == [
        "amendment-a",
        "amendment-b",
    ]


@pytest.mark.parametrize(
    "decisions",
    [
        [],
        [
            {
                "amendment_id": "amendment-a",
                "decision": "ratify",
                "reason": "ok",
                "replacement_amendment_id": None,
            },
            {
                "amendment_id": "amendment-a",
                "decision": "ratify",
                "reason": "duplicate",
                "replacement_amendment_id": None,
            },
        ],
        [
            {
                "amendment_id": "amendment-a",
                "decision": "ratify",
                "reason": "replacement is invalid for ratification",
                "replacement_amendment_id": "replacement-a",
            }
        ],
    ],
)
def test_runtime_policy_council_decisions_reject_incomplete_or_duplicate_input(
    decisions: object,
) -> None:
    with pytest.raises(ValueError):
        _validate_runtime_policy_council_decisions(decisions, {"amendment-a"})
