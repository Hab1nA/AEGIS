from __future__ import annotations

import hashlib
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

from aegis.curriculum import (
    MANDATORY_PROTECTED_CONTROLS,
    ActiveRoleSet,
    Constitution,
    CurriculumSnapshot,
    CycleState,
    CycleStateMachine,
    InvalidCycleTransitionError,
    ObjectiveVersion,
    RoleVersionIdentity,
    available_cycle_actions,
    cycle_transition,
)
from aegis.event_store import EventStore
from aegis.models import Role, thaw_json


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class CurriculumModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.constitution = Constitution(
            version=1,
            safety_rules=(
                "Generated code executes only in the networkless sandbox.",
                "Only the trusted evaluator may lock quality.",
            ),
        )
        self.objective = ObjectiveVersion(
            version=1,
            constitution_id=self.constitution.constitution_id,
            statement="Improve robust software-engineering performance.",
            success_criteria=("Improve held-out quality without a safety regression.",),
            capability_tags=("debugging", "testing"),
        )
        self.roles = {
            role: RoleVersionIdentity(
                role=role,
                version=1,
                artifact_id=f"genesis-{role.value}",
                artifact_sha256=digest(role.value),
                constitution_id=self.constitution.constitution_id,
            )
            for role in Role
        }
        self.active = ActiveRoleSet(
            revision=0,
            objective_id=self.objective.objective_id,
            warrior=self.roles[Role.WARRIOR],
            judge=self.roles[Role.JUDGE],
            prosecutor=self.roles[Role.PROSECUTOR],
        )

    def snapshot(self) -> CurriculumSnapshot:
        return CurriculumSnapshot(
            campaign_id="curriculum-v2-test",
            cycle_number=1,
            constitution=self.constitution,
            objective=self.objective,
            active_roles=self.active,
            task_pool_revision=0,
            training_cohort_sha256=digest("training"),
            lagged_holdout_cohort_sha256=digest("lagged-holdout"),
            hall_of_fame_revision=0,
            external_probe_set_sha256=digest("external-probes"),
        )

    def test_models_are_content_addressed_immutable_and_round_trip(self) -> None:
        snapshot = self.snapshot()

        self.assertTrue(self.constitution.constitution_id.startswith("constitution-sha256:"))
        self.assertTrue(self.objective.objective_id.startswith("objective-sha256:"))
        self.assertTrue(self.active.active_role_set_id.startswith("active-role-set-sha256:"))
        self.assertTrue(snapshot.snapshot_id.startswith("curriculum-snapshot-sha256:"))
        self.assertEqual(Constitution.from_mapping(self.constitution.to_mapping()), self.constitution)
        self.assertEqual(ObjectiveVersion.from_mapping(self.objective.to_mapping()), self.objective)
        self.assertEqual(ActiveRoleSet.from_mapping(self.active.to_mapping()), self.active)
        self.assertEqual(CurriculumSnapshot.from_mapping(snapshot.to_mapping()), snapshot)
        with self.assertRaises(FrozenInstanceError):
            snapshot.task_pool_revision = 2  # type: ignore[misc]

    def test_identity_tampering_and_unknown_fields_fail_closed(self) -> None:
        objective = dict(self.objective.to_mapping())
        objective["statement"] = "A different objective."
        with self.assertRaisesRegex(ValueError, "objective_id"):
            ObjectiveVersion.from_mapping(objective)

        constitution = dict(self.constitution.to_mapping())
        constitution["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "missing or unknown"):
            Constitution.from_mapping(constitution)

    def test_constitution_owns_mandatory_control_boundaries(self) -> None:
        missing = tuple(
            item for item in MANDATORY_PROTECTED_CONTROLS if item != "sealed_evaluation"
        )
        with self.assertRaisesRegex(ValueError, "mandatory protected controls"):
            Constitution(
                version=1,
                safety_rules=("Keep evaluation sealed.",),
                protected_controls=missing,
            )

    def test_objective_and_active_roles_cannot_cross_constitution_boundary(self) -> None:
        other = Constitution(version=1, safety_rules=("A distinct operator policy.",))
        mismatched_objective = ObjectiveVersion(
            version=1,
            constitution_id=other.constitution_id,
            statement="A separately governed objective.",
            success_criteria=("Remain separate.",),
            capability_tags=(),
        )
        with self.assertRaisesRegex(ValueError, "different constitution"):
            CurriculumSnapshot(
                campaign_id="mismatch",
                cycle_number=1,
                constitution=self.constitution,
                objective=mismatched_objective,
                active_roles=self.active,
                task_pool_revision=0,
                training_cohort_sha256=digest("training"),
                lagged_holdout_cohort_sha256=digest("lagged-holdout"),
                hall_of_fame_revision=0,
                external_probe_set_sha256=digest("external-probes"),
            )

    def test_active_role_slots_are_exact_and_queryable(self) -> None:
        self.assertIs(self.active.for_role(Role.JUDGE), self.roles[Role.JUDGE])
        with self.assertRaisesRegex(ValueError, "wrong slots"):
            ActiveRoleSet(
                revision=1,
                objective_id=self.objective.objective_id,
                warrior=self.roles[Role.JUDGE],
                judge=self.roles[Role.WARRIOR],
                prosecutor=self.roles[Role.PROSECUTOR],
            )

    def test_version_lineage_is_explicit(self) -> None:
        with self.assertRaisesRegex(ValueError, "requires a parent"):
            ObjectiveVersion(
                version=2,
                constitution_id=self.constitution.constitution_id,
                statement="Second objective version.",
                success_criteria=("Retain lineage.",),
                capability_tags=(),
            )
        successor = ObjectiveVersion(
            version=2,
            parent_objective_id=self.objective.objective_id,
            constitution_id=self.constitution.constitution_id,
            statement="Second objective version.",
            success_criteria=("Retain lineage.",),
            capability_tags=(),
        )
        self.assertNotEqual(successor.objective_id, self.objective.objective_id)
        self.assertEqual(ObjectiveVersion.from_mapping(successor.to_mapping()), successor)

    def test_snapshot_is_strict_json_and_can_be_persisted_in_event_store(self) -> None:
        snapshot = self.snapshot()
        with tempfile.TemporaryDirectory() as directory:
            store = EventStore(Path(directory) / "events.sqlite3")
            try:
                store.append("curriculum", "curriculum_snapshot_locked_v2", snapshot.to_mapping())
                event = store.read("curriculum")[0]
            finally:
                store.close()
        recovered = CurriculumSnapshot.from_mapping(thaw_json(event.payload))
        self.assertEqual(recovered, snapshot)


class CycleStateMachineTests(unittest.TestCase):
    def test_full_forward_path_supports_named_actions(self) -> None:
        machine = CycleStateMachine()
        actions = (
            "lock_snapshot",
            "lock_cohort",
            "collect_solutions",
            "freeze_submission",
            "record_judge_review",
            "lock_quality",
            "record_prosecutor_audit",
            "record_independent_reflections",
            "complete_council",
            "complete_task_forge",
            "complete_task_validation",
            "lock_attribution",
            "qualify_role_candidates",
            "commit_activation_set",
            "complete",
        )
        for action in actions:
            machine.apply(action)
        self.assertIs(machine.state, CycleState.COMPLETED)
        self.assertTrue(machine.state.terminal)

    def test_advance_alias_covers_the_complete_durable_path(self) -> None:
        machine = CycleStateMachine()
        while not machine.state.terminal:
            machine.apply("advance")
        self.assertIs(machine.state, CycleState.COMPLETED)

    def test_pause_records_exact_resume_target(self) -> None:
        machine = CycleStateMachine(CycleState.COUNCIL_COMPLETED)
        self.assertIs(machine.apply("pause"), CycleState.PAUSED)
        self.assertIs(machine.resume_target, CycleState.COUNCIL_COMPLETED)
        self.assertIs(machine.apply("resume"), CycleState.COUNCIL_COMPLETED)
        self.assertIsNone(machine.resume_target)

    def test_stop_abort_and_failure_are_terminal(self) -> None:
        stopped = CycleStateMachine(CycleState.COHORT_LOCKED)
        self.assertIs(stopped.apply("stop"), CycleState.STOPPING)
        self.assertIs(stopped.apply("abort"), CycleState.ABORTED)
        self.assertTrue(stopped.state.terminal)

        failed = CycleStateMachine(CycleState.QUALITY_LOCKED)
        self.assertIs(failed.apply("fail"), CycleState.FAILED)
        self.assertTrue(failed.state.terminal)

    def test_invalid_transitions_and_resume_targets_are_rejected(self) -> None:
        with self.assertRaises(InvalidCycleTransitionError):
            cycle_transition(CycleState.CREATED, "complete")
        with self.assertRaisesRegex(ValueError, "requires an active resume target"):
            CycleStateMachine(CycleState.PAUSED)
        self.assertIn("lock_snapshot", available_cycle_actions(CycleState.CREATED))
        self.assertNotIn("resume", available_cycle_actions(CycleState.CREATED))

    def test_failed_cycle_can_retry_to_created(self) -> None:
        self.assertIs(
            cycle_transition(CycleState.FAILED, "retry"),
            CycleState.CREATED,
        )
        self.assertIn("retry", available_cycle_actions(CycleState.FAILED))
        self.assertNotIn("retry", available_cycle_actions(CycleState.CREATED))


if __name__ == "__main__":
    unittest.main()
