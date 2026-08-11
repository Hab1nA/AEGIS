from __future__ import annotations

import pytest

from aegis.artifacts import ContentAddressedArtifactStore
from aegis.config import RoleConfig
from aegis.curriculum.models import RoleVersionIdentity
from aegis.event_store import EventStore
from aegis.evolution.control_core import (
    DEFAULT_CONTROL_CORE_POLICY,
    ControlCorePolicy,
    ControlCorePolicyError,
)
from aegis.evolution.registry import EvolutionRegistry
from aegis.evolution.runtime import (
    candidate_binding,
    candidate_manifest,
    champion_binding_for_role,
    materialize_default_artifacts,
    resolve_role_binding,
    store_composite_manifest,
)
from aegis.evolution.surfaces import EvolutionSurface
from aegis.models import Role


def candidate_policy() -> dict[str, object]:
    value = DEFAULT_CONTROL_CORE_POLICY.to_mapping()
    value["sealed_evaluator"]["timeout_seconds"] = 90.0
    value["promotion_gate"]["fresh_improvement"] = 0.03
    value["task_sandbox"]["max_task_overlay_files"] = 48
    return value


def role_config() -> RoleConfig:
    return RoleConfig("model", 1.0, 4096)


def identity(artifact_id: str, version: int = 1) -> RoleVersionIdentity:
    return RoleVersionIdentity(
        Role.WARRIOR,
        version,
        artifact_id,
        artifact_id.rsplit(":", 1)[1],
        "constitution-sha256:" + "a" * 64,
        parent_role_version_id=(
            None if version == 1 else "role-version-sha256:" + "b" * 64
        ),
    )


def test_policy_is_content_addressed_and_rejects_boundary_fields() -> None:
    first = ControlCorePolicy.from_mapping(candidate_policy())
    second = ControlCorePolicy.from_mapping(candidate_policy())
    assert first.policy_id == second.policy_id
    assert first.policy_id.startswith("control-core-sha256:")

    for forbidden in (
        "host_safety_envelope",
        "windows_envelope",
        "wsl_root_supervisor",
        "credential_broker",
        "network_boundary",
    ):
        value = candidate_policy()
        value[forbidden] = {}
        with pytest.raises(ControlCorePolicyError, match="cannot modify"):
            ControlCorePolicy.from_mapping(value)

    value = candidate_policy()
    value["task_sandbox"]["network"] = "public"
    with pytest.raises(ControlCorePolicyError, match="network must remain none"):
        ControlCorePolicy.from_mapping(value)


def test_candidate_manifest_activation_and_registry_rollback(tmp_path) -> None:
    artifacts = ContentAddressedArtifactStore(tmp_path / "artifacts")
    store = EventStore(tmp_path / "events.sqlite3")
    registry = EvolutionRegistry(store, "campaign")
    workflow, subject = materialize_default_artifacts(artifacts)
    default_ref = artifacts.put_json(
        "control-core", DEFAULT_CONTROL_CORE_POLICY.to_mapping()
    )
    default_record = registry.collect(
        EvolutionSurface.CONTROL_CORE,
        Role.WARRIOR,
        artifact_id=default_ref.artifact_id,
        artifact_sha256=default_ref.artifact_id.rsplit(":", 1)[1],
        objective_id="objective-sha256:" + "c" * 64,
        collection_evidence_id="evidence:default-collect",
    )
    registry.validate(
        default_record.candidate_id, validation_evidence_id="evidence:default-validate"
    )
    registry.qualify(
        default_record.candidate_id, qualification_evidence_id="evidence:default-qualify"
    )
    registry.activate(
        default_record.candidate_id, activation_evidence_id="evidence:default-activate"
    )
    policy = ControlCorePolicy.from_mapping(candidate_policy())
    policy_ref = artifacts.put_json("control-core", policy.to_mapping())
    assert policy_ref.artifact_id == policy.policy_id

    record = registry.collect(
        EvolutionSurface.CONTROL_CORE,
        Role.WARRIOR,
        artifact_id=policy_ref.artifact_id,
        artifact_sha256=policy_ref.artifact_id.rsplit(":", 1)[1],
        objective_id="objective-sha256:" + "c" * 64,
        collection_evidence_id="evidence:collect",
    )
    registry.validate(record.candidate_id, validation_evidence_id="evidence:validate")
    registry.qualify(record.candidate_id, qualification_evidence_id="evidence:qualify")

    champion = champion_binding_for_role(
        artifacts=artifacts,
        evolution=registry,
        role=Role.WARRIOR,
        role_config=role_config(),
        budget_policy_sha256="d" * 64,
        default_image=None,
        default_workflow_ref=workflow,
        default_subject_ref=subject,
    )
    candidate = candidate_binding(
        champion=champion,
        candidate=registry.projection.candidates[record.candidate_id],
        artifacts=artifacts,
        role=Role.WARRIOR,
    )
    assert candidate.control_core == policy
    manifest = candidate_manifest(
        champion=champion,
        candidate=registry.projection.candidates[record.candidate_id],
        artifacts=artifacts,
    )
    assert manifest is not None
    assert manifest.control_core_artifact_id == policy.policy_id

    manifest_ref = store_composite_manifest(artifacts, manifest)
    registry.activate(record.candidate_id, activation_evidence_id="evidence:activate")
    active_binding = resolve_role_binding(
        artifacts=artifacts,
        evolution=registry,
        active_identity=identity(manifest_ref.artifact_id, version=2),
        role=Role.WARRIOR,
        role_config=role_config(),
        budget_policy_sha256="d" * 64,
        default_image=None,
        default_workflow_ref=workflow,
        default_subject_ref=subject,
    )
    assert active_binding.control_core == policy

    assert registry.champion(EvolutionSurface.CONTROL_CORE, Role.WARRIOR) is not None
    registry.rollback(
        EvolutionSurface.CONTROL_CORE,
        Role.WARRIOR,
        reason="probation regression",
        expected_champion_id=record.candidate_id,
    )
    restored = registry.champion(EvolutionSurface.CONTROL_CORE, Role.WARRIOR)
    assert restored is not None
    assert restored.artifact_id == DEFAULT_CONTROL_CORE_POLICY.policy_id
    rolled_back_binding = resolve_role_binding(
        artifacts=artifacts,
        evolution=registry,
        active_identity=identity(manifest_ref.artifact_id, version=2),
        role=Role.WARRIOR,
        role_config=role_config(),
        budget_policy_sha256="d" * 64,
        default_image=None,
        default_workflow_ref=workflow,
        default_subject_ref=subject,
    )
    assert rolled_back_binding.control_core == DEFAULT_CONTROL_CORE_POLICY
    fallback = champion_binding_for_role(
        artifacts=artifacts,
        evolution=registry,
        role=Role.WARRIOR,
        role_config=role_config(),
        budget_policy_sha256="d" * 64,
        default_image=None,
        default_workflow_ref=workflow,
        default_subject_ref=subject,
    )
    assert fallback.control_core == DEFAULT_CONTROL_CORE_POLICY


def test_cost_gate_and_isolation_cannot_be_weakened() -> None:
    value = candidate_policy()
    value["promotion_gate"]["enforce_cost_limit"] = True
    with pytest.raises(ControlCorePolicyError, match="cost must remain observational"):
        ControlCorePolicy.from_mapping(value)
    value = candidate_policy()
    value["task_sandbox"]["public_hidden_isolation"] = False
    with pytest.raises(ControlCorePolicyError, match="independently isolated"):
        ControlCorePolicy.from_mapping(value)
