from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from aegis.artifacts import ContentAddressedArtifactStore
from aegis.config import RoleConfig
from aegis.curriculum import Constitution, ObjectiveSuccessCriterion, ObjectiveVersion, RoleVersionIdentity
from aegis.event_store import EventStore
from aegis.evolution.registry import EvolutionRegistry
from aegis.evolution.runtime import (
    DEFAULT_SUBJECT,
    DEFAULT_WORKFLOW,
    CompositeRoleManifest,
    RuntimeBinding,
    budget_policy_hash,
    build_composite_manifest,
    candidate_binding,
    candidate_manifest,
    champion_binding_for_role,
    materialize_default_artifacts,
    model_profile_hash,
    resolve_role_binding,
    store_composite_manifest,
)
from aegis.evolution.surfaces import EvolutionSurface
from aegis.models import Role


class EvolutionRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self._root = tempfile.TemporaryDirectory(prefix="aegis-runtime-")
        self.root = Path(self._root.name)
        self.artifacts = ContentAddressedArtifactStore(self.root / "artifacts")
        self.store = EventStore(self.root / "events.sqlite3")
        self.evolution = EvolutionRegistry(self.store, "campaign")
        self.cfg = {
            "warrior": RoleConfig("w", 0.60, 1024, "medium"),
            "judge": RoleConfig("j", 0.25, 1024, "medium"),
            "prosecutor": RoleConfig("p", 0.15, 1024, "medium"),
        }
        self.workflow_ref, self.subject_ref = materialize_default_artifacts(
            self.artifacts
        )

    def tearDown(self) -> None:
        self.store.close()
        self._root.cleanup()

    def _identity(self, artifact_id: str, version: int = 1) -> RoleVersionIdentity:
        constitution = Constitution(1, ("never execute on the host",))
        objective = ObjectiveVersion(
            1,
            constitution.constitution_id,
            "improve",
            (ObjectiveSuccessCriterion("quality", 0.5),),
            ("python",),
            {"quality": 1, "generalization": 1, "retention": 1, "efficiency": 1},
        )
        return RoleVersionIdentity(
            Role.WARRIOR,
            version,
            artifact_id,
            hashlib.sha256(artifact_id.encode("utf-8")).hexdigest(),
            objective.constitution_id,
        )

    def test_composite_manifest_round_trip(self) -> None:
        manifest = build_composite_manifest(
            role=Role.WARRIOR,
            model_profile_sha256=model_profile_hash(self.cfg["warrior"]),
            workflow_artifact_id=self.workflow_ref.artifact_id,
            subject_artifact_id=self.subject_ref.artifact_id,
            plugin_artifact_ids=(),
            runtime_image=None,
            budget_policy_sha256="0" * 64,
        )
        ref = store_composite_manifest(self.artifacts, manifest)
        replayed = CompositeRoleManifest.from_mapping(
            self.artifacts.get(ref).decode("utf-8") and __import__("json").loads(
                self.artifacts.get(ref).decode("utf-8")
            )
        )
        self.assertEqual(replayed, manifest)
        self.assertTrue(ref.artifact_id.startswith("role-manifest-sha256:"))

    def test_resolve_role_binding_default_fallback_and_manifest(self) -> None:
        placeholder = self._identity("genesis-warrior-v1")
        binding = resolve_role_binding(
            artifacts=self.artifacts,
            evolution=self.evolution,
            active_identity=placeholder,
            role=Role.WARRIOR,
            role_config=self.cfg["warrior"],
            budget_policy_sha256="0" * 64,
            default_image=None,
            default_workflow_ref=self.workflow_ref,
            default_subject_ref=self.subject_ref,
        )
        self.assertEqual(binding.workflow, dict(DEFAULT_WORKFLOW))
        self.assertEqual(binding.subject, dict(DEFAULT_SUBJECT))
        self.assertEqual(binding.plugins, ())
        self.assertIsNone(binding.runtime_image)

        manifest = build_composite_manifest(
            role=Role.WARRIOR,
            model_profile_sha256=model_profile_hash(self.cfg["warrior"]),
            workflow_artifact_id=self.workflow_ref.artifact_id,
            subject_artifact_id=self.subject_ref.artifact_id,
            plugin_artifact_ids=(),
            runtime_image="localhost/aegis@sha256:" + "c" * 64,
            budget_policy_sha256="0" * 64,
        )
        ref = store_composite_manifest(self.artifacts, manifest)
        bound_identity = self._identity(ref.artifact_id)
        resolved = resolve_role_binding(
            artifacts=self.artifacts,
            evolution=self.evolution,
            active_identity=bound_identity,
            role=Role.WARRIOR,
            role_config=self.cfg["warrior"],
            budget_policy_sha256="0" * 64,
            default_image=None,
            default_workflow_ref=self.workflow_ref,
            default_subject_ref=self.subject_ref,
        )
        self.assertEqual(
            resolved.runtime_image, "localhost/aegis@sha256:" + "c" * 64
        )

    def test_champion_binding_and_candidate_binding(self) -> None:
        champion = champion_binding_for_role(
            artifacts=self.artifacts,
            evolution=self.evolution,
            role=Role.WARRIOR,
            role_config=self.cfg["warrior"],
            budget_policy_sha256="0" * 64,
            default_image=None,
            default_workflow_ref=self.workflow_ref,
            default_subject_ref=self.subject_ref,
        )
        self.assertIsInstance(champion, RuntimeBinding)
        record = self.evolution.collect(
            EvolutionSurface.WORKFLOW,
            Role.WARRIOR,
            artifact_id=self.workflow_ref.artifact_id,
            artifact_sha256=self.workflow_ref.artifact_id.rsplit(":", 1)[1],
            objective_id="objective-sha256:" + "b" * 64,
            collection_evidence_id="evidence:1",
        )
        candidate = candidate_binding(
            champion=champion,
            candidate=record,
            artifacts=self.artifacts,
            role=Role.WARRIOR,
        )
        self.assertEqual(candidate.workflow, dict(DEFAULT_WORKFLOW))
        manifest = candidate_manifest(
            champion=champion, candidate=record, artifacts=self.artifacts
        )
        self.assertIsNotNone(manifest)
        assert manifest is not None
        self.assertEqual(manifest.workflow_artifact_id, self.workflow_ref.artifact_id)

    def test_model_and_budget_hashes_are_deterministic(self) -> None:
        self.assertEqual(
            model_profile_hash(self.cfg["warrior"]),
            model_profile_hash(self.cfg["warrior"]),
        )
        from aegis.config import CampaignConfig

        campaign = CampaignConfig.from_mapping(
            {
                "campaign_id": "x",
                "max_rounds": 1,
                "total_tokens": 10_000,
                "max_requests": 10,
                "wall_time_seconds": 60,
                "task_pack_paths": ["C:/taskpack"],
                "roles": {
                    "warrior": {"model": "w", "budget_share": 0.60, "max_output_tokens": 100},
                    "judge": {"model": "j", "budget_share": 0.25, "max_output_tokens": 100},
                    "prosecutor": {"model": "p", "budget_share": 0.15, "max_output_tokens": 100},
                },
            }
        )
        self.assertEqual(budget_policy_hash(campaign), budget_policy_hash(campaign))
        self.assertEqual(len(budget_policy_hash(campaign)), 64)


if __name__ == "__main__":
    unittest.main()
