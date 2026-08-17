from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

import pytest

from aegis.artifacts import ContentAddressedArtifactStore
from aegis.curriculum import (
    ActiveRoleSet,
    Constitution,
    CurriculumRegistry,
    CurriculumSnapshot,
    CycleState,
    ObjectiveSuccessCriterion,
    ObjectiveVersion,
    RoleVersionIdentity,
)
from aegis.cycle_runtime import CyclePorts, CycleRuntimeError, EvolutionCycleController
from aegis.dynamic_tasks import CohortMember, CohortTier, DynamicTaskCohort
from aegis.event_store import EventStore
from aegis.models import Role


def sha(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


class FakeCohorts:
    def __init__(self, cohort: DynamicTaskCohort) -> None:
        self.cohort = cohort

    def select_dynamic_cohort(self, target_generation: int, *, limit: int | None = None):
        assert target_generation == self.cohort.target_generation
        return self.cohort


class Ports:
    def __init__(self) -> None:
        self.order: list[str] = []

    def solve(self, snapshot, cohort):
        self.order.append("warrior")
        return {"artifact": "solution", "cohort": cohort.cohort_id}

    def review(self, snapshot, submission):
        self.order.append("judge")
        return {"findings": ["bounded review"]}

    def calibrate(self, snapshot, judge_review, quality_lock):
        self.order.append("calibrate")
        return {
            "brier": 0.1,
            "ece": 0.05,
            "false_negatives": 0,
            "false_positives": 0,
        }

    def lock_quality(self, snapshot, cohort, submission, judge_review):
        self.order.append("quality")
        return {"score": 0.8, "locked": True}

    def commit_curriculum_evidence(self, snapshot, cohort, quality_lock):
        self.order.append("curriculum-evidence")
        return {
            "cohort": cohort.cohort_id,
            "quality_lock": quality_lock.artifact_id,
            "committed": True,
        }

    def audit(self, snapshot, submission, judge_review, quality_lock):
        self.order.append("prosecutor")
        return {"usage_verified": True, "curriculum": ["test a new hypothesis"]}

    def reflect(self, role, snapshot, submission, judge_review, quality_lock, prosecutor_audit):
        self.order.append(f"reflect:{role.value}")
        return {"role": role.value, "claims": []}

    def reflect_post(
        self,
        role,
        snapshot,
        submission,
        quality_lock,
        prosecutor_audit,
        judge_calibration,
        task_validation,
        candidate_evaluation,
        attribution,
        activation,
    ):
        self.order.append(f"post-reflect:{role.value}")
        return {
            "role": role.value,
            "claims": [],
            "proposals": [],
        }

    def deliberate(
        self, snapshot, reflections, submission, judge_review, prosecutor_audit
    ):
        self.order.append("council")
        return {"proposal": "next experiment", "reflections": [item.artifact_id for item in reflections]}

    def govern_objective(self, snapshot, cohort, submission, council, quality_lock):
        self.order.append("objective-governance")
        return {
            "admitted": False,
            "reason": "insufficient history",
            "council": council.artifact_id,
        }

    def forge_next_tasks(self, snapshot, submission, judge_review, quality_lock, prosecutor_audit, council):
        self.order.append("forge")
        return {"tasks": ["dynamic-next-task"]}

    def validate_forged_tasks(self, snapshot, forged_tasks):
        self.order.append("validate")
        return {"valid": True, "forge": forged_tasks.artifact_id}

    def evaluate_candidates(
        self,
        snapshot,
        cohort,
        submission,
        judge_review,
        prosecutor_audit,
        council,
        quality_lock,
        task_validation,
    ):
        self.order.append("candidate-eval")
        return {"enabled": True, "candidate": None, "report": None}

    def commit_holdout_evidence(self, snapshot, cohort):
        self.order.append("holdout-commit")
        return {"snapshot_id": snapshot.snapshot_id, "transitions": []}

    def lock_attribution(
        self,
        snapshot,
        quality_lock,
        prosecutor_audit,
        council,
        task_validation,
        candidate_evaluation,
    ):
        self.order.append("attribution")
        return {"qualified_coordinates": ["warrior"]}

    def qualify_role_candidates(self, snapshot, candidate_evaluation, attribution):
        del candidate_evaluation
        self.order.append("qualify")
        return {"qualified": ["warrior-v2"]}

    def commit_activation_set(self, snapshot, qualification):
        self.order.append("activate")
        return {"active_set": "next"}


def setup_runtime(root: Path):
    event_store = EventStore(root / "events.sqlite3")
    registry = CurriculumRegistry(event_store, "campaign")
    constitution = Constitution(1, ("Never execute generated code on the host.",))
    objective = ObjectiveVersion(
        1,
        constitution.constitution_id,
        "Improve dynamic software engineering capability.",
        (ObjectiveSuccessCriterion("quality", 0.5),),
        ("python",),
        {"quality": 1, "generalization": 1, "retention": 1, "efficiency": 1},
    )
    identities = {
        role: RoleVersionIdentity(
            role,
            1,
            f"genesis-{role.value}",
            sha(role.value),
            constitution.constitution_id,
        )
        for role in Role
    }
    active = ActiveRoleSet(
        0,
        objective.objective_id,
        identities[Role.WARRIOR],
        identities[Role.JUDGE],
        identities[Role.PROSECUTOR],
    )
    member = CohortMember(
        "dynamic-task-sha256:" + "1" * 64,
        CohortTier.FRESH_HOLDOUT,
        1,
        "2" * 64,
    )
    cohort = DynamicTaskCohort.create(2, (member,))
    snapshot = CurriculumSnapshot(
        "campaign",
        1,
        constitution,
        objective,
        active,
        1,
        cohort.cohort_id.rsplit(":", 1)[1],
        sha("lagged"),
        0,
        sha("probes"),
    )
    registry.record_constitution(constitution)
    registry.provision_objective(objective)
    registry.start_objective_probation(objective.objective_id)
    registry.activate_objective(objective.objective_id)
    ports = Ports()
    controller = EvolutionCycleController(
        registry,
        FakeCohorts(cohort),
        ContentAddressedArtifactStore(root / "artifacts"),
        CyclePorts(ports, ports, ports, ports, ports, ports),
    )
    return event_store, registry, snapshot, ports, controller


def assert_summary_shape(controller, result) -> None:
    import json

    assert result.judge_calibration is not None
    assert result.post_reflection_index is not None
    payload = json.loads(
        controller._artifacts.get(result.cycle_summary).decode("utf-8")
    )
    assert payload["dimensions"]["candidate"] == "pending"
    assert payload["dimensions"]["activation"] == "not_attempted"
    assert "post_reflection_index" in payload
    assert "judge_calibration" in payload


def test_full_cycle_locks_quality_before_audit_and_council_before_next_tasks() -> None:
    with tempfile.TemporaryDirectory() as directory:
        store, registry, snapshot, ports, controller = setup_runtime(Path(directory))
        try:
            result = controller.run(snapshot, target_generation=2)
            assert registry.projection.cycle_state is CycleState.COMPLETED
            assert ports.order == [
                "warrior",
                "judge",
                "quality",
                "calibrate",
                "curriculum-evidence",
                "prosecutor",
                "reflect:warrior",
                "reflect:judge",
                "reflect:prosecutor",
                "council",
                "objective-governance",
                "forge",
                    "validate",
                    "candidate-eval",
                    "holdout-commit",
                    "attribution",
                "qualify",
                "activate",
                "post-reflect:warrior",
                "post-reflect:judge",
                "post-reflect:prosecutor",
            ]
            assert result.cycle_summary.artifact_id.startswith("cycle-summary-sha256:")
            assert_summary_shape(controller, result)
            transition_events = [
                event for event in store.read("campaign") if event.event_type == "cycle_state_changed_v2"
            ]
            assert all(
                event.payload["evidence_id"] is not None
                for event in transition_events
                if event.payload["action"] not in {"lock_snapshot"}
            )
        finally:
            store.close()


def test_forbidden_private_reasoning_fails_closed_and_persists_failed_state() -> None:
    with tempfile.TemporaryDirectory() as directory:
        store, registry, snapshot, ports, controller = setup_runtime(Path(directory))
        ports.solve = lambda snapshot, cohort: {"chain_of_thought": "must never persist"}
        try:
            with pytest.raises(CycleRuntimeError, match="forbidden"):
                controller.run(snapshot, target_generation=2)
            assert registry.projection.cycle_state is CycleState.FAILED
            assert "chain_of_thought" not in str(store.read("campaign"))
        finally:
            store.close()



def test_interrupted_cycle_resumes_without_rerunning_checkpointed_stages() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        store, registry, snapshot, ports, _ = setup_runtime(root)
        try:
            checkpoints: dict[str, ArtifactRef] = {}
            controller = EvolutionCycleController(
                registry,
                FakeCohorts(
                    DynamicTaskCohort.create(
                        2,
                        (
                            CohortMember(
                                "dynamic-task-sha256:" + "1" * 64,
                                CohortTier.FRESH_HOLDOUT,
                                1,
                                "2" * 64,
                            ),
                        ),
                    )
                ),
                ContentAddressedArtifactStore(root / "artifacts"),
                CyclePorts(ports, ports, ports, ports, ports, ports),
                checkpoint=lambda key, ref: checkpoints.update({key: ref}),
            )
            original_eval = ports.evaluate_candidates

            def failing_eval(*args, **kwargs):
                raise RuntimeError("candidate eval failed once")

            ports.evaluate_candidates = failing_eval
            try:
                with pytest.raises(RuntimeError, match="failed once"):
                    controller.run(snapshot, target_generation=2)
                assert registry.projection.cycle_state is CycleState.FAILED
                assert "submission" in checkpoints
                assert "judge-review" in checkpoints
                assert "reflection:judge" in checkpoints
            finally:
                ports.evaluate_candidates = original_eval

            registry.transition_cycle(
                "retry", reason="control-plane restart after interrupted cycle"
            )
            ports.order.clear()
            result = controller.run(
                snapshot,
                target_generation=2,
                retry=True,
                resume_evidence=checkpoints,
            )
            assert registry.projection.cycle_state is CycleState.COMPLETED
            assert "warrior" not in ports.order
            assert "judge" not in ports.order
            assert "quality" not in ports.order
            assert "candidate-eval" in ports.order
            assert "holdout-commit" in ports.order
            assert result.cycle_summary.artifact_id.startswith("cycle-summary-sha256:")
        finally:
            store.close()


def test_snapshot_must_bind_the_exact_dynamic_cohort() -> None:
    with tempfile.TemporaryDirectory() as directory:
        store, registry, snapshot, _, controller = setup_runtime(Path(directory))
        try:
            wrong = CurriculumSnapshot(
                snapshot.campaign_id,
                snapshot.cycle_number,
                snapshot.constitution,
                snapshot.objective,
                snapshot.active_roles,
                snapshot.task_pool_revision,
                sha("wrong"),
                snapshot.lagged_holdout_cohort_sha256,
                snapshot.hall_of_fame_revision,
                snapshot.external_probe_set_sha256,
            )
            with pytest.raises(CycleRuntimeError, match="not bound"):
                controller.run(wrong, target_generation=2)
            assert registry.projection.cycle_state is CycleState.CREATED
        finally:
            store.close()


def test_failed_cycle_can_retry_the_same_snapshot_after_control_plane_retry() -> None:
    with tempfile.TemporaryDirectory() as directory:
        store, registry, snapshot, ports, controller = setup_runtime(Path(directory))
        try:
            ports.solve = lambda snapshot, cohort: (_ for _ in ()).throw(
                RuntimeError("warrior solve failed once")
            )
            with pytest.raises(RuntimeError, match="failed once"):
                controller.run(snapshot, target_generation=2)
            assert registry.projection.cycle_state is CycleState.FAILED

            registry.transition_cycle(
                "retry",
                reason="control-plane restart after a repaired failure",
            )
            ports.solve = lambda snapshot, cohort: {"artifact": "solution"}
            result = controller.run(snapshot, target_generation=2, retry=True)
            assert registry.projection.cycle_state is CycleState.COMPLETED
            assert result.cycle_summary.artifact_id.startswith("cycle-summary-sha256:")
            assert_summary_shape(controller, result)
        finally:
            store.close()
