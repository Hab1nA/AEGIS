from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from aegis.curriculum import (
    ActiveRoleSet,
    Constitution,
    CurriculumRegistry,
    CurriculumRegistryError,
    CurriculumSnapshot,
    CycleState,
    ObjectiveStatus,
    ObjectiveVersion,
    RoleVersionIdentity,
)
from aegis.event_store import EventStore, EventStoreSequenceConflict
from aegis.models import Role


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class CurriculumRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.store = EventStore(Path(self.directory.name) / "events.sqlite3")
        self.campaign_id = "registry-v2-test"
        self.constitution = Constitution(
            version=1,
            safety_rules=("Execute generated code only in the networkless sandbox.",),
        )
        self.objective = ObjectiveVersion(
            version=1,
            constitution_id=self.constitution.constitution_id,
            statement="Improve robust software-engineering performance.",
            success_criteria=("Improve held-out quality without a safety regression.",),
            capability_tags=("debugging", "testing"),
        )

    def tearDown(self) -> None:
        self.store.close()
        self.directory.cleanup()

    def active_roles(self, objective: ObjectiveVersion) -> ActiveRoleSet:
        identities = {
            role: RoleVersionIdentity(
                role=role,
                version=1,
                artifact_id=f"genesis-{role.value}",
                artifact_sha256=digest(role.value),
                constitution_id=self.constitution.constitution_id,
            )
            for role in Role
        }
        return ActiveRoleSet(
            revision=0,
            objective_id=objective.objective_id,
            warrior=identities[Role.WARRIOR],
            judge=identities[Role.JUDGE],
            prosecutor=identities[Role.PROSECUTOR],
        )

    def snapshot(self, objective: ObjectiveVersion | None = None) -> CurriculumSnapshot:
        selected = objective or self.objective
        return CurriculumSnapshot(
            campaign_id=self.campaign_id,
            cycle_number=1,
            constitution=self.constitution,
            objective=selected,
            active_roles=self.active_roles(selected),
            task_pool_revision=0,
            training_cohort_sha256=digest("training"),
            lagged_holdout_cohort_sha256=digest("lagged-holdout"),
            hall_of_fame_revision=0,
            external_probe_set_sha256=digest("external-probes"),
        )

    def activate_genesis(self, registry: CurriculumRegistry) -> None:
        registry.record_constitution(self.constitution)
        registry.provision_objective(self.objective)
        registry.start_objective_probation(self.objective.objective_id)
        registry.activate_objective(self.objective.objective_id)

    def test_append_only_lifecycle_replays_snapshot_and_pause_target(self) -> None:
        self.store.append(self.campaign_id, "legacy_event", {"ignored": True})
        registry = CurriculumRegistry(self.store, self.campaign_id)
        self.assertEqual(registry.projection.sequence, 1)
        self.activate_genesis(registry)
        snapshot = self.snapshot()
        registry.record_snapshot(snapshot)
        registry.transition_cycle("lock_snapshot")
        registry.transition_cycle("lock_cohort", evidence_id="dynamic-cohort-sha256:" + "a" * 64)
        registry.transition_cycle("pause")

        recovered = CurriculumRegistry(self.store, self.campaign_id).projection
        self.assertEqual(recovered.sequence, self.store.max_sequence(self.campaign_id))
        self.assertEqual(recovered.constitutions[self.constitution.constitution_id], self.constitution)
        self.assertEqual(recovered.objectives[self.objective.objective_id], self.objective)
        self.assertEqual(recovered.snapshots[snapshot.snapshot_id], snapshot)
        self.assertIs(recovered.cycle_state, CycleState.PAUSED)
        self.assertIs(recovered.resume_target, CycleState.COHORT_LOCKED)

        resumed = CurriculumRegistry(self.store, self.campaign_id)
        resumed.transition_cycle("resume")
        self.assertIs(resumed.projection.cycle_state, CycleState.COHORT_LOCKED)
        self.assertIsNone(resumed.projection.resume_target)
        self.assertTrue(
            all(
                event.event_type.endswith("_v2")
                for event in self.store.read(self.campaign_id)
                if event.event_type != "legacy_event"
            )
        )

    def test_objective_probation_activation_and_active_rollback_are_durable(self) -> None:
        registry = CurriculumRegistry(self.store, self.campaign_id)
        self.activate_genesis(registry)
        successor = ObjectiveVersion(
            version=2,
            parent_objective_id=self.objective.objective_id,
            constitution_id=self.constitution.constitution_id,
            statement="Improve debugging performance on unseen repositories.",
            success_criteria=("Pass probation and external probes.",),
            capability_tags=("debugging", "testing"),
        )
        registry.provision_objective(successor)
        self.assertIs(
            registry.projection.objective_statuses[successor.objective_id],
            ObjectiveStatus.PROVISIONAL,
        )
        registry.start_objective_probation(successor.objective_id)
        registry.activate_objective(successor.objective_id)
        self.assertIs(
            registry.projection.objective_statuses[self.objective.objective_id],
            ObjectiveStatus.SUPERSEDED,
        )
        registry.rollback_objective(
            successor.objective_id,
            self.objective.objective_id,
            reason="External probes regressed.",
        )

        recovered = CurriculumRegistry(self.store, self.campaign_id).projection
        self.assertEqual(recovered.active_objective_id, self.objective.objective_id)
        self.assertIs(
            recovered.objective_statuses[successor.objective_id], ObjectiveStatus.ROLLED_BACK
        )
        self.assertIs(
            recovered.objective_statuses[self.objective.objective_id], ObjectiveStatus.ACTIVE
        )
        rollback = self.store.read(self.campaign_id)[-1]
        self.assertEqual(rollback.event_type, "objective_rolled_back_v2")
        self.assertEqual(rollback.payload["reason"], "External probes regressed.")

    def test_probation_candidate_can_roll_back_without_changing_active_objective(self) -> None:
        registry = CurriculumRegistry(self.store, self.campaign_id)
        self.activate_genesis(registry)
        candidate = ObjectiveVersion(
            version=2,
            parent_objective_id=self.objective.objective_id,
            constitution_id=self.constitution.constitution_id,
            statement="A candidate that does not survive probation.",
            success_criteria=("Pass all gates.",),
            capability_tags=(),
        )
        registry.provision_objective(candidate)
        registry.start_objective_probation(candidate.objective_id)
        registry.rollback_objective(
            candidate.objective_id,
            self.objective.objective_id,
            reason="Probation quality gate failed.",
        )
        self.assertEqual(registry.projection.active_objective_id, self.objective.objective_id)
        self.assertIsNone(registry.projection.probation_objective_id)
        self.assertIs(
            registry.projection.objective_statuses[candidate.objective_id],
            ObjectiveStatus.ROLLED_BACK,
        )

    def test_stale_writer_is_rejected_by_campaign_sequence_cas(self) -> None:
        first = CurriculumRegistry(self.store, self.campaign_id)
        stale = CurriculumRegistry(self.store, self.campaign_id)
        first.record_constitution(self.constitution)
        with self.assertRaises(EventStoreSequenceConflict):
            stale.record_constitution(self.constitution)
        stale.refresh()
        self.assertEqual(stale.projection.sequence, 1)

    def test_snapshot_and_cycle_preconditions_fail_closed(self) -> None:
        registry = CurriculumRegistry(self.store, self.campaign_id)
        with self.assertRaisesRegex(CurriculumRegistryError, "snapshot"):
            registry.transition_cycle("lock_snapshot")
        self.activate_genesis(registry)
        foreign = CurriculumSnapshot(
            campaign_id="foreign-campaign",
            cycle_number=1,
            constitution=self.constitution,
            objective=self.objective,
            active_roles=self.active_roles(self.objective),
            task_pool_revision=0,
            training_cohort_sha256=digest("training"),
            lagged_holdout_cohort_sha256=digest("lagged-holdout"),
            hall_of_fame_revision=0,
            external_probe_set_sha256=digest("external-probes"),
        )
        with self.assertRaisesRegex(CurriculumRegistryError, "different campaign"):
            registry.record_snapshot(foreign)

    def test_cold_start_rejects_tampered_known_v2_event(self) -> None:
        self.store.append(
            self.campaign_id,
            "objective_provisional_v2",
            {
                "schema_version": 2,
                "objective": self.objective.to_mapping(),
                "status": "active",
            },
        )
        with self.assertRaises(CurriculumRegistryError):
            CurriculumRegistry(self.store, self.campaign_id)


if __name__ == "__main__":
    unittest.main()
