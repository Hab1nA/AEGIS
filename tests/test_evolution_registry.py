from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from aegis.event_store import EventStore
from aegis.evolution.registry import (
    CandidateState,
    EvolutionRegistry,
    EvolutionRegistryError,
    evolution_registry_stream_id,
)
from aegis.evolution.surfaces import EvolutionSurface
from aegis.models import Role


class EvolutionRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._root = tempfile.TemporaryDirectory(prefix="aegis-registry-")
        self.root = Path(self._root.name)
        self.store = EventStore(self.root / "events.sqlite3")
        self.registry = EvolutionRegistry(self.store, "campaign")

    def tearDown(self) -> None:
        self.store.close()
        self._root.cleanup()

    def _collect(self, *, surface=EvolutionSurface.WORKFLOW, role=Role.WARRIOR, digest="a") -> str:
        record = self.registry.collect(
            surface,
            role,
            artifact_id=f"{surface.value}-sha256:" + digest * 64,
            artifact_sha256=digest * 64,
            objective_id="objective-sha256:" + "b" * 64,
            collection_evidence_id="evidence:1",
        )
        return record.candidate_id

    def test_lifecycle_collect_validate_qualify_activate(self) -> None:
        candidate_id = self._collect()
        record = self.registry.projection.candidates[candidate_id]
        self.assertEqual(record.state, CandidateState.COLLECTED)
        self.assertEqual(record.version, 1)
        self.assertIsNone(record.parent_candidate_id)

        self.registry.validate(candidate_id, validation_evidence_id="evidence:2")
        self.registry.qualify(candidate_id, qualification_evidence_id="evidence:3")
        self.registry.activate(candidate_id, activation_evidence_id="evidence:4")
        champion = self.registry.champion(EvolutionSurface.WORKFLOW, Role.WARRIOR)
        self.assertIsNotNone(champion)
        assert champion is not None
        self.assertEqual(champion.candidate_id, candidate_id)
        self.assertIs(champion.state, CandidateState.ACTIVE)

        # A new candidate must descend from the champion.
        second = self._collect(digest="c")
        second_record = self.registry.projection.candidates[second]
        self.assertEqual(second_record.version, 2)
        self.assertEqual(second_record.parent_candidate_id, candidate_id)

    def test_attach_materialized_artifact_for_environment_candidate(self) -> None:
        candidate_id = self._collect(
            surface=EvolutionSurface.ENVIRONMENT, digest="e"
        )
        self.registry.validate(candidate_id, validation_evidence_id="evidence:2")
        updated = self.registry.attach_materialized_artifact(
            candidate_id,
            materialized_artifact_id="environment-sha256:" + "f" * 64,
            materialized_artifact_sha256="f" * 64,
            materialization_evidence_id="evidence:build",
        )
        self.assertEqual(updated.materialized_artifact_id, "environment-sha256:" + "f" * 64)
        self.assertEqual(updated.materialized_artifact_sha256, "f" * 64)
        self.assertEqual(updated.state, CandidateState.VALIDATED)
        # Identity and lineage stay bound to the original recipe artifact.
        self.assertEqual(updated.artifact_id, "environment-sha256:" + "e" * 64)
        # The projection serves the record with the materialized id.
        projected = self.registry.projection.candidates[candidate_id]
        self.assertEqual(
            projected.materialized_artifact_id, "environment-sha256:" + "f" * 64
        )
        # Activation still resolves the record carrying the receipt.
        self.registry.qualify(candidate_id, qualification_evidence_id="evidence:3")
        self.registry.activate(candidate_id, activation_evidence_id="evidence:4")
        champion = self.registry.champion(EvolutionSurface.ENVIRONMENT, Role.WARRIOR)
        self.assertIsNotNone(champion)
        assert champion is not None
        self.assertEqual(champion.materialized_artifact_id, "environment-sha256:" + "f" * 64)

    def test_attach_materialized_artifact_rejects_non_environment(self) -> None:
        candidate_id = self._collect()
        with self.assertRaisesRegex(EvolutionRegistryError, "environment"):
            self.registry.attach_materialized_artifact(
                candidate_id,
                materialized_artifact_id="workflow-sha256:" + "f" * 64,
                materialized_artifact_sha256="f" * 64,
                materialization_evidence_id="evidence:build",
            )

    def test_attach_materialized_artifact_rejects_activated_candidate(self) -> None:
        candidate_id = self._collect(surface=EvolutionSurface.ENVIRONMENT, digest="e")
        self.registry.validate(candidate_id, validation_evidence_id="evidence:2")
        self.registry.qualify(candidate_id, qualification_evidence_id="evidence:3")
        self.registry.activate(candidate_id, activation_evidence_id="evidence:4")
        with self.assertRaisesRegex(EvolutionRegistryError, "collected or validated"):
            self.registry.attach_materialized_artifact(
                candidate_id,
                materialized_artifact_id="environment-sha256:" + "f" * 64,
                materialized_artifact_sha256="f" * 64,
                materialization_evidence_id="evidence:build",
            )

    def test_reject_and_rollback(self) -> None:
        first = self._collect(digest="a")
        self.registry.validate(first, validation_evidence_id="e1")
        self.registry.qualify(first, qualification_evidence_id="e2")
        self.registry.activate(first, activation_evidence_id="e3")
        second = self._collect(digest="d")
        self.registry.validate(second, validation_evidence_id="e4")
        self.registry.qualify(second, qualification_evidence_id="e5")
        self.registry.activate(second, activation_evidence_id="e6")
        champion = self.registry.champion(EvolutionSurface.WORKFLOW, Role.WARRIOR)
        assert champion is not None
        self.assertEqual(champion.candidate_id, second)

        rolled_back = self.registry.rollback(
            EvolutionSurface.WORKFLOW,
            Role.WARRIOR,
            reason="shadow regression",
            expected_champion_id=second,
        )
        self.assertEqual(rolled_back.candidate_id, first)
        champion = self.registry.champion(EvolutionSurface.WORKFLOW, Role.WARRIOR)
        assert champion is not None
        self.assertEqual(champion.candidate_id, first)
        self.assertIs(
            self.registry.projection.candidates[second].state,
            CandidateState.REVOKED,
        )

        rejected = self._collect(digest="e")
        self.registry.reject(rejected, reason="does not validate")
        self.assertIs(
            self.registry.projection.candidates[rejected].state,
            CandidateState.REJECTED,
        )
        with self.assertRaises(EvolutionRegistryError):
            self.registry.validate(rejected, validation_evidence_id="e7")

    def test_replay_is_stable_and_strict(self) -> None:
        first = self._collect(digest="a")
        self.registry.validate(first, validation_evidence_id="e1")
        replay = EvolutionRegistry(self.store, "campaign")
        self.assertEqual(
            replay.projection.candidates[first].state, CandidateState.VALIDATED
        )
        self.assertEqual(replay.projection.sequence, self.registry.projection.sequence)
        with self.assertRaises(EvolutionRegistryError):
            replay.collect(
                EvolutionSurface.WORKFLOW,
                Role.WARRIOR,
                artifact_id="workflow-sha256:" + "a" * 64,
                artifact_sha256="a" * 64,
                objective_id="objective-sha256:" + "b" * 64,
                collection_evidence_id="evidence:dup",
            )

    def test_stream_contract(self) -> None:
        self.assertEqual(
            evolution_registry_stream_id("campaign"), "campaign:evolution:v2"
        )
        with self.assertRaises(EvolutionRegistryError):
            evolution_registry_stream_id("  ")

    def test_bad_artifact_address_rejected(self) -> None:
        with self.assertRaises(EvolutionRegistryError):
            self.registry.collect(
                EvolutionSurface.WORKFLOW,
                Role.WARRIOR,
                artifact_id="role-manifest-sha256:" + "a" * 64,
                artifact_sha256="a" * 64,
                objective_id="objective-sha256:" + "b" * 64,
                collection_evidence_id="evidence:1",
            )


if __name__ == "__main__":
    unittest.main()
