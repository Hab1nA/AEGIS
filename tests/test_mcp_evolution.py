from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from aegis.event_store import EventStore
from aegis.mcp import (
    McpBinding,
    McpCandidate,
    McpCandidateStatus,
    McpEvolutionError,
    McpPermissionStage,
    McpRegistry,
    McpRegistryConflictError,
    McpRegistryError,
    McpRiskLevel,
    McpServerManifest,
    McpToolAuthorization,
    mcp_registry_stream_id,
)


def candidate_fixture() -> McpCandidate:
    manifest = McpServerManifest.create(
        name="issue-tracker",
        endpoint="https://mcp.example.test/rpc",
        tool_names=("issues.list", "issues.update"),
        version="1.0",
        rationale="bounded issue workflow",
    )
    grants = (
        McpToolAuthorization.create(
            tool_name="issues.list",
            input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            schema_summary="List issues without modifying remote state.",
            risk_level=McpRiskLevel.L1,
            permission_stage=McpPermissionStage.OBSERVATION,
        ),
        McpToolAuthorization.create(
            tool_name="issues.update",
            input_schema={
                "type": "object",
                "properties": {"issue_id": {"type": "string"}},
                "required": ["issue_id"],
                "additionalProperties": False,
            },
            schema_summary="Update one explicitly identified issue.",
            risk_level=McpRiskLevel.L2,
            permission_stage=McpPermissionStage.OPERATION,
        ),
    )
    binding = McpBinding.create(
        manifest_id=manifest.manifest_id,
        server_name=manifest.name,
        authorizations=grants,
    )
    return McpCandidate.create(
        manifest=manifest,
        binding=binding,
        proposed_by="judge",
        rationale="Add a schema-pinned issue workflow.",
    )


def test_candidate_is_self_contained_content_addressed_and_strict() -> None:
    candidate = candidate_fixture()
    restored = McpCandidate.from_mapping(candidate.to_mapping())
    assert restored == candidate
    assert restored.manifest.endpoint == "https://mcp.example.test/rpc"
    assert restored.binding.binding_id.startswith("mcp-binding-sha256:")
    assert restored.candidate_id.startswith("mcp-candidate-sha256:")

    unknown = candidate.to_mapping()
    unknown["unexpected"] = True
    with pytest.raises(McpEvolutionError, match="missing or unknown"):
        McpCandidate.from_mapping(unknown)

    tampered = candidate.to_mapping()
    tampered["rationale"] = "different"
    with pytest.raises(McpEvolutionError, match="candidate_id does not match"):
        McpCandidate.from_mapping(tampered)


def test_risk_level_requires_a_sufficient_permission_stage() -> None:
    with pytest.raises(McpEvolutionError, match="does not authorize"):
        McpToolAuthorization.create(
            tool_name="dangerous.delete",
            input_schema={"type": "object"},
            schema_summary="Delete remote state.",
            risk_level=McpRiskLevel.L3,
            permission_stage=McpPermissionStage.OPERATION,
        )


def test_registry_replays_probation_activation_and_revocation(tmp_path) -> None:
    store = EventStore(tmp_path / "events.sqlite3")
    registry = McpRegistry(store, "campaign")
    candidate = candidate_fixture()
    lease = registry.acquire_lease("controller")

    record = registry.record_evolution_status(
        candidate,
        evolution_candidate_id="evolution-candidate-sha256:" + "a" * 64,
        status=McpCandidateStatus.PROPOSED,
        evidence_id="proposal-evidence",
        lease_token=lease.token,
    )
    assert record.status is McpCandidateStatus.PROPOSED
    for status, evidence in (
        (McpCandidateStatus.VALIDATED, "validation-evidence"),
        (McpCandidateStatus.QUALIFIED, "qualification-evidence"),
    ):
        record = registry.record_evolution_status(
            candidate,
            evolution_candidate_id=record.evolution_candidate_id,
            status=status,
            evidence_id=evidence,
            lease_token=lease.token,
        )
    assert registry.begin_probation(
        candidate.candidate_id,
        evidence_id="probation-evidence",
        required_observations=2,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        lease_token=lease.token,
    ).status is McpCandidateStatus.PROBATION
    assert registry.callable_binding_for_server(candidate.manifest.name) == candidate.binding
    with pytest.raises(McpRegistryError, match="has not completed"):
        registry.activate_from_evolution(
            candidate.candidate_id,
            evidence_id="premature-activation",
            lease_token=lease.token,
        )
    for index in range(2):
        registry.observe_probation(
            candidate.candidate_id,
            snapshot_id=f"snapshot-{index}",
            evidence_id=f"observation-{index}",
            passed=True,
            lease_token=lease.token,
        )
    receipt = registry.activate_from_evolution(
        candidate.candidate_id,
        evidence_id="evolution-activation-evidence",
        lease_token=lease.token,
    )
    assert receipt == candidate.binding.binding_id
    assert registry.binding_for_server(candidate.manifest.name) == candidate.binding

    replayed = McpRegistry(store, "campaign")
    assert replayed.projection == registry.projection
    assert replayed.binding_for_server(candidate.manifest.name) == candidate.binding

    revoked = replayed.revoke(
        candidate.candidate_id,
        evidence_id="incident-evidence",
        reason="Tool behavior drifted from its pinned schema.",
        lease_token=lease.token,
    )
    assert revoked.status is McpCandidateStatus.REVOKED
    assert replayed.binding_for_server(candidate.manifest.name) is None
    assert replayed.callable_binding_for_server(candidate.manifest.name) is None


def test_lease_expiry_takeover_and_stale_writer_cas(tmp_path) -> None:
    now = [datetime(2026, 8, 11, tzinfo=timezone.utc)]
    store = EventStore(tmp_path / "events.sqlite3")
    first = McpRegistry(store, "campaign", clock=lambda: now[0])
    stale = McpRegistry(store, "campaign", clock=lambda: now[0])
    lease = first.acquire_lease("first", duration_seconds=10)
    with pytest.raises(McpRegistryConflictError, match="sequence changed"):
        stale.acquire_lease("stale", expected_sequence=0)

    now[0] += timedelta(seconds=11)
    with pytest.raises(McpRegistryConflictError, match="live matching"):
        first.renew_lease(lease.token)
    takeover = first.acquire_lease("second")
    assert takeover.owner == "second"
    first.release_lease(takeover.token)
    assert first.projection.lease is None


def test_probation_observations_are_unique_and_expiry_removes_callability(tmp_path) -> None:
    now = [datetime(2026, 8, 11, tzinfo=timezone.utc)]
    registry = McpRegistry(
        EventStore(tmp_path / "events.sqlite3"), "campaign", clock=lambda: now[0]
    )
    candidate = candidate_fixture()
    lease = registry.acquire_lease("controller")
    evolution_id = "evolution-candidate-sha256:" + "b" * 64
    for status in (
        McpCandidateStatus.PROPOSED,
        McpCandidateStatus.VALIDATED,
        McpCandidateStatus.QUALIFIED,
    ):
        registry.record_evolution_status(
            candidate,
            evolution_candidate_id=evolution_id,
            status=status,
            evidence_id=f"{status.value}-evidence",
            lease_token=lease.token,
        )
    registry.begin_probation(
        candidate.candidate_id,
        evidence_id="probation-evidence",
        required_observations=2,
        expires_at=now[0] + timedelta(seconds=10),
        lease_token=lease.token,
    )
    registry.observe_probation(
        candidate.candidate_id,
        snapshot_id="snapshot-1",
        evidence_id="observation-1",
        passed=True,
        lease_token=lease.token,
    )
    with pytest.raises(McpRegistryError, match="duplicated"):
        registry.observe_probation(
            candidate.candidate_id,
            snapshot_id="snapshot-1",
            evidence_id="different-evidence",
            passed=True,
            lease_token=lease.token,
        )
    assert registry.callable_binding_for_server(candidate.manifest.name) == candidate.binding

    now[0] += timedelta(seconds=11)
    assert registry.callable_binding_for_server(candidate.manifest.name) is None
    with pytest.raises(McpRegistryError, match="expired"):
        registry.observe_probation(
            candidate.candidate_id,
            snapshot_id="snapshot-2",
            evidence_id="observation-2",
            passed=True,
            lease_token=lease.token,
        )
    assert registry.expire_probation(
        candidate.candidate_id,
        evidence_id="expiry-evidence",
        lease_token=lease.token,
    ).status is McpCandidateStatus.REVOKED


def test_failed_probation_observation_revokes_candidate(tmp_path) -> None:
    now = datetime(2026, 8, 11, tzinfo=timezone.utc)
    registry = McpRegistry(EventStore(tmp_path / "events.sqlite3"), "campaign", clock=lambda: now)
    candidate = candidate_fixture()
    lease = registry.acquire_lease("controller")
    evolution_id = "evolution-candidate-sha256:" + "c" * 64
    for status in (
        McpCandidateStatus.PROPOSED,
        McpCandidateStatus.VALIDATED,
        McpCandidateStatus.QUALIFIED,
    ):
        registry.record_evolution_status(
            candidate,
            evolution_candidate_id=evolution_id,
            status=status,
            evidence_id=f"{status.value}-evidence",
            lease_token=lease.token,
        )
    registry.begin_probation(
        candidate.candidate_id,
        evidence_id="probation-evidence",
        required_observations=1,
        expires_at=now + timedelta(hours=1),
        lease_token=lease.token,
    )
    record = registry.observe_probation(
        candidate.candidate_id,
        snapshot_id="snapshot-failed",
        evidence_id="failed-evidence",
        passed=False,
        lease_token=lease.token,
    )
    assert record.status is McpCandidateStatus.REVOKED
    assert registry.callable_binding_for_server(candidate.manifest.name) is None


def test_replay_rejects_malformed_known_event(tmp_path) -> None:
    store = EventStore(tmp_path / "events.sqlite3")
    store.append(
        mcp_registry_stream_id("campaign"),
        "mcp_registry_lease_acquired_v1",
        {
            "schema_version": 1,
            "owner": "controller",
            "token": "a" * 64,
            "expires_at": "2026-08-11T00:00:00+00:00",
            "unexpected": True,
        },
    )
    with pytest.raises(McpRegistryError, match="missing, unknown, or invalid"):
        McpRegistry(store, "campaign")
