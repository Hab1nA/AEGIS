from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from aegis.curriculum import Constitution, ObjectiveSuccessCriterion, ObjectiveVersion, RoleVersionIdentity
from aegis.event_store import EventStore, EventStoreSequenceConflict
from aegis.models import Role
from aegis.roles import (
    RoleCandidateState,
    RoleRegistry,
    RoleRegistryError,
    role_registry_stream_id,
)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class RoleRegistryV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.store = EventStore(Path(self.directory.name) / "events.sqlite3")
        self.campaign_id = "role-registry-v2-test"
        self.constitution = Constitution(
            version=1,
            safety_rules=("Only trusted control-plane code may activate role artifacts.",),
        )
        self.objective = ObjectiveVersion(
            version=1,
            constitution_id=self.constitution.constitution_id,
            statement="Improve reliable software-engineering performance.",
            success_criteria=(ObjectiveSuccessCriterion("quality", 0.5),),
            capability_tags=("debugging", "testing"),
            capability_weights={"quality": 1, "generalization": 1, "retention": 1, "efficiency": 1},
        )

    def tearDown(self) -> None:
        self.store.close()
        self.directory.cleanup()

    def identity(
        self,
        role: Role,
        *,
        label: str,
        version: int = 1,
        parent_id: str | None = None,
    ) -> RoleVersionIdentity:
        return RoleVersionIdentity(
            role=role,
            version=version,
            parent_role_version_id=parent_id,
            artifact_id=f"artifact-{label}",
            artifact_sha256=digest(label),
            constitution_id=self.constitution.constitution_id,
        )

    def qualify(self, registry: RoleRegistry, identity: RoleVersionIdentity) -> None:
        registry.collect_candidate(
            identity,
            objective_id=self.objective.objective_id,
            collection_evidence_id=f"collection:{identity.artifact_id}",
        )
        registry.validate_candidate(
            identity.role_version_id,
            validation_evidence_id=f"validation:{identity.artifact_id}",
        )
        registry.qualify_candidate(
            identity.role_version_id,
            qualification_evidence_id=f"qualification:{identity.artifact_id}",
        )

    def genesis(self, registry: RoleRegistry) -> dict[Role, RoleVersionIdentity]:
        identities = {
            role: self.identity(role, label=f"genesis-{role.value}") for role in Role
        }
        for identity in identities.values():
            self.qualify(registry, identity)
        registry.commit_active_set(
            {role: identity.role_version_id for role, identity in identities.items()},
            objective_id=self.objective.objective_id,
            joint_evidence_id="joint:genesis",
            expected_current_active_set_id=None,
        )
        return identities

    def test_candidate_stages_are_separate_and_initial_commit_is_atomic(self) -> None:
        registry = RoleRegistry(self.store, self.campaign_id)
        identities = {
            role: self.identity(role, label=f"genesis-{role.value}") for role in Role
        }
        for identity in identities.values():
            registry.collect_candidate(
                identity,
                objective_id=self.objective.objective_id,
                collection_evidence_id=f"collection:{identity.artifact_id}",
            )
            registry.validate_candidate(
                identity.role_version_id,
                validation_evidence_id=f"validation:{identity.artifact_id}",
            )
        with self.assertRaisesRegex(RoleRegistryError, "qualified"):
            registry.commit_active_set(
                {role: identity.role_version_id for role, identity in identities.items()},
                objective_id=self.objective.objective_id,
                joint_evidence_id="joint:too-early",
                expected_current_active_set_id=None,
            )
        for identity in identities.values():
            registry.qualify_candidate(
                identity.role_version_id,
                qualification_evidence_id=f"qualification:{identity.artifact_id}",
            )
        registry.commit_active_set(
            {role: identity.role_version_id for role, identity in identities.items()},
            objective_id=self.objective.objective_id,
            joint_evidence_id="joint:genesis",
            expected_current_active_set_id=None,
        )
        active = registry.projection.current_active_set
        self.assertIsNotNone(active)
        assert active is not None
        self.assertEqual(active.revision, 0)
        for role, identity in identities.items():
            self.assertEqual(active.for_role(role), identity)
            self.assertIs(
                registry.projection.candidates[identity.role_version_id].state,
                RoleCandidateState.ACTIVE,
            )

    def test_single_role_commit_supersedes_only_that_role_and_cold_replays(self) -> None:
        registry = RoleRegistry(self.store, self.campaign_id)
        genesis = self.genesis(registry)
        baseline_id = registry.projection.current_active_set_id
        assert baseline_id is not None
        successor = self.identity(
            Role.WARRIOR,
            label="warrior-v2",
            version=2,
            parent_id=genesis[Role.WARRIOR].role_version_id,
        )
        self.qualify(registry, successor)
        registry.commit_active_set(
            {Role.WARRIOR: successor.role_version_id},
            objective_id=self.objective.objective_id,
            joint_evidence_id="joint:warrior-v2",
            expected_current_active_set_id=baseline_id,
        )

        recovered = RoleRegistry(self.store, self.campaign_id).projection
        active = recovered.current_active_set
        assert active is not None
        self.assertEqual(active.revision, 1)
        self.assertEqual(active.warrior, successor)
        self.assertEqual(active.judge, genesis[Role.JUDGE])
        self.assertEqual(active.prosecutor, genesis[Role.PROSECUTOR])
        self.assertIs(
            recovered.candidates[genesis[Role.WARRIOR].role_version_id].state,
            RoleCandidateState.SUPERSEDED,
        )
        self.assertIs(
            recovered.candidates[successor.role_version_id].state,
            RoleCandidateState.ACTIVE,
        )

    def test_stale_sibling_is_blocked_by_cas_then_expected_active_set(self) -> None:
        registry = RoleRegistry(self.store, self.campaign_id)
        genesis = self.genesis(registry)
        baseline_id = registry.projection.current_active_set_id
        assert baseline_id is not None
        first = self.identity(
            Role.WARRIOR,
            label="warrior-sibling-a",
            version=2,
            parent_id=genesis[Role.WARRIOR].role_version_id,
        )
        second = self.identity(
            Role.WARRIOR,
            label="warrior-sibling-b",
            version=2,
            parent_id=genesis[Role.WARRIOR].role_version_id,
        )
        self.qualify(registry, first)
        self.qualify(registry, second)
        stale = RoleRegistry(self.store, self.campaign_id)
        registry.commit_active_set(
            {Role.WARRIOR: first.role_version_id},
            objective_id=self.objective.objective_id,
            joint_evidence_id="joint:sibling-a",
            expected_current_active_set_id=baseline_id,
        )
        with self.assertRaises(EventStoreSequenceConflict):
            stale.commit_active_set(
                {Role.WARRIOR: second.role_version_id},
                objective_id=self.objective.objective_id,
                joint_evidence_id="joint:sibling-b",
                expected_current_active_set_id=baseline_id,
            )
        stale.refresh()
        with self.assertRaisesRegex(RoleRegistryError, "expected current"):
            stale.commit_active_set(
                {Role.WARRIOR: second.role_version_id},
                objective_id=self.objective.objective_id,
                joint_evidence_id="joint:sibling-b",
                expected_current_active_set_id=baseline_id,
            )

    def test_rollback_revokes_candidate_and_restores_prior_active_set(self) -> None:
        registry = RoleRegistry(self.store, self.campaign_id)
        genesis = self.genesis(registry)
        baseline_id = registry.projection.current_active_set_id
        assert baseline_id is not None
        successor = self.identity(
            Role.JUDGE,
            label="judge-v2",
            version=2,
            parent_id=genesis[Role.JUDGE].role_version_id,
        )
        self.qualify(registry, successor)
        registry.commit_active_set(
            {Role.JUDGE: successor.role_version_id},
            objective_id=self.objective.objective_id,
            joint_evidence_id="joint:judge-v2",
            expected_current_active_set_id=baseline_id,
        )
        candidate_set_id = registry.projection.current_active_set_id
        assert candidate_set_id is not None
        registry.rollback_active_set(
            baseline_id,
            expected_current_active_set_id=candidate_set_id,
            joint_evidence_id="joint:judge-rollback",
            reason="Sealed external evaluation regressed.",
        )

        recovered = RoleRegistry(self.store, self.campaign_id).projection
        self.assertEqual(recovered.current_active_set_id, baseline_id)
        self.assertIs(
            recovered.candidates[successor.role_version_id].state,
            RoleCandidateState.REVOKED,
        )
        self.assertIs(
            recovered.candidates[genesis[Role.JUDGE].role_version_id].state,
            RoleCandidateState.ACTIVE,
        )
        event = self.store.read(registry.stream_id)[-1]
        self.assertEqual(event.event_type, "role_active_set_rolled_back_v2")
        self.assertEqual(event.payload["reason"], "Sealed external evaluation regressed.")

    def test_objective_binding_joint_evidence_and_independent_stream_fail_closed(self) -> None:
        self.store.append(self.campaign_id, "curriculum_event_v2", {"value": 1})
        registry = RoleRegistry(self.store, self.campaign_id)
        self.assertEqual(registry.projection.sequence, 0)
        self.assertEqual(registry.stream_id, role_registry_stream_id(self.campaign_id))
        identity = self.identity(Role.WARRIOR, label="objective-bound")
        self.qualify(registry, identity)
        other_objective = ObjectiveVersion(
            version=1,
            constitution_id=self.constitution.constitution_id,
            statement="A distinct target.",
            success_criteria=(ObjectiveSuccessCriterion("quality", 0.5),),
            capability_tags=(),
            capability_weights={"quality": 1, "generalization": 1, "retention": 1, "efficiency": 1},
        )
        with self.assertRaisesRegex(RoleRegistryError, "different objective"):
            registry.commit_active_set(
                {Role.WARRIOR: identity.role_version_id},
                objective_id=other_objective.objective_id,
                joint_evidence_id="joint:mismatch",
                expected_current_active_set_id=None,
            )
        with self.assertRaisesRegex(RoleRegistryError, "joint_evidence_id"):
            registry.commit_active_set(
                {Role.WARRIOR: identity.role_version_id},
                objective_id=self.objective.objective_id,
                joint_evidence_id="",
                expected_current_active_set_id=None,
            )

    def test_cross_objective_commit_requires_three_newly_bound_roles(self) -> None:
        registry = RoleRegistry(self.store, self.campaign_id)
        genesis = self.genesis(registry)
        baseline_id = registry.projection.current_active_set_id
        assert baseline_id is not None
        next_objective = ObjectiveVersion(
            version=2,
            parent_objective_id=self.objective.objective_id,
            constitution_id=self.constitution.constitution_id,
            statement="A successor objective requiring fresh joint qualification.",
            success_criteria=(ObjectiveSuccessCriterion("quality", 0.5),),
            capability_tags=("debugging", "testing"),
            capability_weights={"quality": 2, "generalization": 1, "retention": 1, "efficiency": 1},
        )
        warrior = self.identity(
            Role.WARRIOR,
            label="warrior-next-objective",
            version=2,
            parent_id=genesis[Role.WARRIOR].role_version_id,
        )
        registry.collect_candidate(
            warrior,
            objective_id=next_objective.objective_id,
            collection_evidence_id="collection:warrior-next-objective",
        )
        registry.validate_candidate(
            warrior.role_version_id,
            validation_evidence_id="validation:warrior-next-objective",
        )
        registry.qualify_candidate(
            warrior.role_version_id,
            qualification_evidence_id="qualification:warrior-next-objective",
        )
        with self.assertRaisesRegex(RoleRegistryError, "cross-objective"):
            registry.commit_active_set(
                {Role.WARRIOR: warrior.role_version_id},
                objective_id=next_objective.objective_id,
                joint_evidence_id="joint:partial-next-objective",
                expected_current_active_set_id=baseline_id,
            )

    def test_objective_rebind_preserves_role_versions_and_creates_revision(self) -> None:
        registry = RoleRegistry(self.store, self.campaign_id)
        genesis = self.genesis(registry)
        baseline_id = registry.projection.current_active_set_id
        assert baseline_id is not None
        next_objective = ObjectiveVersion(
            version=2,
            parent_objective_id=self.objective.objective_id,
            constitution_id=self.constitution.constitution_id,
            statement="A probation objective using the existing role vector.",
            success_criteria=(ObjectiveSuccessCriterion("quality", 0.5),),
            capability_tags=(),
            capability_weights={"quality": 2, "generalization": 1, "retention": 1, "efficiency": 1},
        )
        registry.rebind_objective(
            next_objective.objective_id,
            evidence_id="objective-rebind:test",
            expected_current_active_set_id=baseline_id,
        )
        recovered = RoleRegistry(self.store, self.campaign_id).projection
        active = recovered.current_active_set
        assert active is not None
        self.assertEqual(active.revision, 1)
        self.assertEqual(active.objective_id, next_objective.objective_id)
        for role in Role:
            self.assertEqual(active.for_role(role), genesis[role])
            self.assertIs(
                recovered.candidates[genesis[role].role_version_id].state,
                RoleCandidateState.ACTIVE,
            )
        self.assertEqual(recovered.active_set_parents[active.active_role_set_id], baseline_id)

    def test_cold_start_rejects_tampered_known_event(self) -> None:
        identity = self.identity(Role.WARRIOR, label="tampered")
        self.store.append(
            role_registry_stream_id(self.campaign_id),
            "role_candidate_collected_v2",
            {
                "schema_version": 3,
                "identity": identity.to_mapping(),
                "objective_id": self.objective.objective_id,
                "state": "active",
                "collection_evidence_id": "collection:tampered",
            },
        )
        with self.assertRaises(RoleRegistryError):
            RoleRegistry(self.store, self.campaign_id)


if __name__ == "__main__":
    unittest.main()
