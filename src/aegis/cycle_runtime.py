"""Evidence-first orchestration for one AEGIS v2 autonomous cycle."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol

from aegis.artifacts import ArtifactRef, ContentAddressedArtifactStore
from aegis.curriculum import CurriculumRegistry, CurriculumSnapshot, CycleState
from aegis.dynamic_tasks import DynamicTaskCohort
from aegis.failure_taxonomy import (
    classify_completed_cycle,
    classify_exception,
    cycle_dimensions,
)
from aegis.models import Role


class CycleRuntimeError(RuntimeError):
    pass


class CohortProvider(Protocol):
    def select_dynamic_cohort(
        self, target_generation: int, *, limit: int | None = None
    ) -> DynamicTaskCohort: ...


class WarriorCyclePort(Protocol):
    def solve(
        self, snapshot: CurriculumSnapshot, cohort: DynamicTaskCohort
    ) -> Mapping[str, Any]: ...


class JudgeCyclePort(Protocol):
    def review(
        self, snapshot: CurriculumSnapshot, submission: ArtifactRef
    ) -> Mapping[str, Any]: ...

    def calibrate(
        self,
        snapshot: CurriculumSnapshot,
        judge_review: ArtifactRef,
        quality_lock: ArtifactRef,
    ) -> Mapping[str, Any]: ...

    def forge_next_tasks(
        self,
        snapshot: CurriculumSnapshot,
        submission: ArtifactRef,
        judge_review: ArtifactRef,
        quality_lock: ArtifactRef,
        prosecutor_audit: ArtifactRef,
        council: ArtifactRef,
    ) -> Mapping[str, Any]: ...


class QualityCyclePort(Protocol):
    def lock_quality(
        self,
        snapshot: CurriculumSnapshot,
        cohort: DynamicTaskCohort,
        submission: ArtifactRef,
        judge_review: ArtifactRef,
    ) -> Mapping[str, Any]: ...


class ProsecutorCyclePort(Protocol):
    def audit(
        self,
        snapshot: CurriculumSnapshot,
        submission: ArtifactRef,
        judge_review: ArtifactRef,
        quality_lock: ArtifactRef,
    ) -> Mapping[str, Any]: ...


class CouncilCyclePort(Protocol):
    def reflect(
        self,
        role: Role,
        snapshot: CurriculumSnapshot,
        submission: ArtifactRef,
        judge_review: ArtifactRef,
        quality_lock: ArtifactRef,
        prosecutor_audit: ArtifactRef,
    ) -> Mapping[str, Any]: ...

    def reflect_post(
        self,
        role: Role,
        snapshot: CurriculumSnapshot,
        submission: ArtifactRef,
        quality_lock: ArtifactRef,
        prosecutor_audit: ArtifactRef,
        judge_calibration: ArtifactRef,
        task_validation: ArtifactRef,
        candidate_evaluation: ArtifactRef,
        attribution: ArtifactRef,
        activation: ArtifactRef,
    ) -> Mapping[str, Any]: ...

    def deliberate(
        self,
        snapshot: CurriculumSnapshot,
        reflections: tuple[ArtifactRef, ...],
        submission: ArtifactRef,
        judge_review: ArtifactRef,
        prosecutor_audit: ArtifactRef,
    ) -> Mapping[str, Any]: ...

    def govern_objective(
        self,
        snapshot: CurriculumSnapshot,
        cohort: DynamicTaskCohort,
        submission: ArtifactRef,
        council: ArtifactRef,
        quality_lock: ArtifactRef,
    ) -> Mapping[str, Any]: ...


class EvolutionCyclePort(Protocol):
    def commit_curriculum_evidence(
        self,
        snapshot: CurriculumSnapshot,
        cohort: DynamicTaskCohort,
        quality_lock: ArtifactRef,
    ) -> Mapping[str, Any]: ...

    def validate_forged_tasks(
        self, snapshot: CurriculumSnapshot, forged_tasks: ArtifactRef
    ) -> Mapping[str, Any]: ...

    def evaluate_candidates(
        self,
        snapshot: CurriculumSnapshot,
        cohort: DynamicTaskCohort,
        submission: ArtifactRef,
        judge_review: ArtifactRef,
        prosecutor_audit: ArtifactRef,
        council: ArtifactRef,
        quality_lock: ArtifactRef,
        task_validation: ArtifactRef,
    ) -> Mapping[str, Any]: ...

    def commit_holdout_evidence(
        self,
        snapshot: CurriculumSnapshot,
        cohort: DynamicTaskCohort,
    ) -> Mapping[str, Any]: ...

    def lock_attribution(
        self,
        snapshot: CurriculumSnapshot,
        quality_lock: ArtifactRef,
        prosecutor_audit: ArtifactRef,
        council: ArtifactRef,
        task_validation: ArtifactRef,
        candidate_evaluation: ArtifactRef,
    ) -> Mapping[str, Any]: ...

    def qualify_role_candidates(
        self,
        snapshot: CurriculumSnapshot,
        candidate_evaluation: ArtifactRef,
        attribution: ArtifactRef,
    ) -> Mapping[str, Any]: ...

    def commit_activation_set(
        self, snapshot: CurriculumSnapshot, qualification: ArtifactRef
    ) -> Mapping[str, Any]: ...


@dataclass(frozen=True, slots=True)
class CyclePorts:
    warrior: WarriorCyclePort
    judge: JudgeCyclePort
    quality: QualityCyclePort
    prosecutor: ProsecutorCyclePort
    council: CouncilCyclePort
    evolution: EvolutionCyclePort


@dataclass(frozen=True, slots=True)
class CycleRunResult:
    snapshot_id: str
    cohort_id: str
    submission: ArtifactRef
    judge_review: ArtifactRef
    quality_lock: ArtifactRef
    curriculum_evidence: ArtifactRef
    prosecutor_audit: ArtifactRef
    council: ArtifactRef
    objective_governance: ArtifactRef
    forged_tasks: ArtifactRef
    task_validation: ArtifactRef
    candidate_evaluation: ArtifactRef
    attribution: ArtifactRef
    qualification: ArtifactRef
    activation: ArtifactRef
    cycle_summary: ArtifactRef
    judge_calibration: ArtifactRef | None = None
    post_reflection_index: ArtifactRef | None = None


_FORBIDDEN_KEYS = frozenset(
    {
        "chain_of_thought",
        "private_reasoning",
        "hidden_tests",
        "hidden_expected",
        "credentials",
        "api_key",
        "access_token",
    }
)


def _validate_evidence(value: object, *, path: str = "evidence") -> None:
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        if value != value or value in {float("inf"), float("-inf")}:
            raise CycleRuntimeError(f"{path} contains a non-finite number")
        return
    if isinstance(value, str):
        if len(value.encode("utf-8")) > 64 * 1024:
            raise CycleRuntimeError(f"{path} contains oversized text")
        return
    if isinstance(value, (tuple, list)):
        if len(value) > 1024:
            raise CycleRuntimeError(f"{path} contains too many items")
        for index, item in enumerate(value):
            _validate_evidence(item, path=f"{path}[{index}]")
        return
    if isinstance(value, Mapping):
        if len(value) > 256:
            raise CycleRuntimeError(f"{path} contains too many fields")
        for key, item in value.items():
            if not isinstance(key, str):
                raise CycleRuntimeError(f"{path} contains a non-string field")
            if key.lower() in _FORBIDDEN_KEYS:
                raise CycleRuntimeError(f"{path} contains forbidden field {key!r}")
            _validate_evidence(item, path=f"{path}.{key}")
        return
    raise CycleRuntimeError(f"{path} contains unsupported value {type(value).__name__}")


class EvolutionCycleController:
    """Run one pinned cycle; all mutable effects remain behind injected ports."""

    def __init__(
        self,
        registry: CurriculumRegistry,
        cohorts: CohortProvider,
        artifacts: ContentAddressedArtifactStore,
        ports: CyclePorts,
        *,
        checkpoint: Callable[[str, ArtifactRef], None] | None = None,
    ) -> None:
        self._registry = registry
        self._cohorts = cohorts
        self._artifacts = artifacts
        self._ports = ports
        self._checkpoint = checkpoint
        self._resume_evidence: Mapping[str, ArtifactRef] = {}

    def run(
        self,
        snapshot: CurriculumSnapshot,
        *,
        target_generation: int,
        cohort_limit: int | None = None,
        retry: bool = False,
        resume_evidence: Mapping[str, ArtifactRef] | None = None,
    ) -> CycleRunResult:
        self._resume_evidence = resume_evidence or {}
        state = self._registry.projection.cycle_state
        if state not in {CycleState.CREATED, CycleState.COMPLETED}:
            raise CycleRuntimeError("a cycle may start only from created or completed state")
        cohort = self._cohorts.select_dynamic_cohort(target_generation, limit=cohort_limit)
        if not cohort.members:
            raise CycleRuntimeError("dynamic cohort is empty; bootstrap tasks before starting the cycle")
        if snapshot.training_cohort_sha256 != cohort.cohort_id.rsplit(":", 1)[1]:
            raise CycleRuntimeError("snapshot is not bound to the selected dynamic cohort")

        # Recording validates the snapshot lineage and transitions the
        # projection back to CREATED (cycle 1: from CREATED; later cycles:
        # from COMPLETED).  A control-plane retry of the same failed cycle
        # already recorded this snapshot, so re-recording is skipped
        # idempotently while still requiring an exact content match.
        current = self._registry.projection.current_snapshot
        interrupted_retry = (
            state is CycleState.CREATED
            and current is not None
            and snapshot.cycle_number == current.cycle_number
            and snapshot.snapshot_id != current.snapshot_id
        )
        if current is None or snapshot.cycle_number > current.cycle_number:
            self._registry.record_snapshot(snapshot, retry=retry)
        elif snapshot.snapshot_id == current.snapshot_id:
            # A control-plane retry replays the exact snapshot that was already
            # recorded for this cycle; skip re-recording (the content-addressed
            # id guarantees identical content).
            pass
        elif interrupted_retry or (retry and snapshot.cycle_number == current.cycle_number):
            self._registry.record_snapshot(snapshot, retry=True)
        else:
            raise CycleRuntimeError("snapshot conflicts with the recorded cycle")
        self._registry.transition_cycle("lock_snapshot")
        self._registry.transition_cycle("lock_cohort", evidence_id=cohort.cohort_id)

        current_stage = "submission"
        try:
            submission = self._stage(
                "submission", lambda: self._ports.warrior.solve(snapshot, cohort)
            )
            self._registry.transition_cycle("collect_solutions", evidence_id=submission.artifact_id)
            self._registry.transition_cycle("freeze_submission", evidence_id=submission.artifact_id)

            judge_review = self._stage(
                "judge-review", lambda: self._ports.judge.review(snapshot, submission)
            )
            self._registry.transition_cycle(
                "record_judge_review", evidence_id=judge_review.artifact_id
            )

            quality_lock = self._stage(
                "quality-lock",
                lambda: self._ports.quality.lock_quality(snapshot, cohort, submission, judge_review),
            )
            self._registry.transition_cycle("lock_quality", evidence_id=quality_lock.artifact_id)

            current_stage = "judge-calibration"
            judge_calibration = self._stage(
                "judge-calibration",
                lambda: self._ports.judge.calibrate(snapshot, judge_review, quality_lock),
            )

            curriculum_evidence = self._stage(
                "curriculum-evidence",
                lambda: self._ports.evolution.commit_curriculum_evidence(
                    snapshot, cohort, quality_lock
                ),
            )
            self._registry.transition_cycle(
                "commit_curriculum_evidence",
                evidence_id=curriculum_evidence.artifact_id,
            )

            prosecutor_audit = self._stage(
                "prosecutor-audit",
                lambda: self._ports.prosecutor.audit(
                    snapshot, submission, judge_review, quality_lock
                ),
            )
            self._registry.transition_cycle(
                "record_prosecutor_audit", evidence_id=prosecutor_audit.artifact_id
            )

            current_stage = "pre-cycle-diagnosis"
            reflections = tuple(
                self._stage(
                    "reflection",
                    lambda role=role: self._ports.council.reflect(
                        role,
                        snapshot,
                        submission,
                        judge_review,
                        quality_lock,
                        prosecutor_audit,
                    ),
                    resume_key=f"reflection:{role.value}",
                )
                for role in Role
            )
            reflection_index = self._record(
                "reflection-index",
                {"reflections": [item.artifact_id for item in reflections]},
            )
            self._registry.transition_cycle(
                "record_independent_reflections", evidence_id=reflection_index.artifact_id
            )

            current_stage = "council"
            council = self._stage(
                "council",
                lambda: self._ports.council.deliberate(
                    snapshot,
                    reflections,
                    submission,
                    judge_review,
                    prosecutor_audit,
                ),
            )
            self._registry.transition_cycle("complete_council", evidence_id=council.artifact_id)

            current_stage = "objective-governance"
            objective_governance = self._stage(
                "objective-governance",
                lambda: self._ports.council.govern_objective(
                    snapshot, cohort, submission, council, quality_lock
                ),
            )
            self._registry.transition_cycle(
                "lock_objective_governance",
                evidence_id=objective_governance.artifact_id,
            )

            current_stage = "task-forge"
            forged_tasks = self._stage(
                "task-forge",
                lambda: self._ports.judge.forge_next_tasks(
                    snapshot,
                    submission,
                    judge_review,
                    quality_lock,
                    prosecutor_audit,
                    council,
                ),
            )
            self._registry.transition_cycle(
                "complete_task_forge", evidence_id=forged_tasks.artifact_id
            )

            current_stage = "task-validation"
            task_validation = self._stage(
                "task-validation",
                lambda: self._ports.evolution.validate_forged_tasks(snapshot, forged_tasks),
            )
            self._registry.transition_cycle(
                "complete_task_validation", evidence_id=task_validation.artifact_id
            )

            current_stage = "candidate-evaluation"
            candidate_evaluation = self._stage(
                "candidate-evaluation",
                lambda: self._ports.evolution.evaluate_candidates(
                    snapshot,
                    cohort,
                    submission,
                    judge_review,
                    prosecutor_audit,
                    council,
                    quality_lock,
                    task_validation,
                ),
            )
            self._registry.transition_cycle(
                "evaluate_candidates", evidence_id=candidate_evaluation.artifact_id
            )

            current_stage = "holdout-commit"
            self._stage(
                "holdout-commit",
                lambda: self._ports.evolution.commit_holdout_evidence(snapshot, cohort),
            )

            current_stage = "attribution"
            attribution = self._stage(
                "attribution",
                lambda: self._ports.evolution.lock_attribution(
                    snapshot,
                    quality_lock,
                    prosecutor_audit,
                    council,
                    task_validation,
                    candidate_evaluation,
                ),
            )
            self._registry.transition_cycle("lock_attribution", evidence_id=attribution.artifact_id)

            current_stage = "qualification"
            qualification = self._stage(
                "qualification",
                lambda: self._ports.evolution.qualify_role_candidates(
                    snapshot, candidate_evaluation, attribution
                ),
            )
            self._registry.transition_cycle(
                "qualify_role_candidates", evidence_id=qualification.artifact_id
            )

            current_stage = "activation"
            activation = self._stage(
                "activation",
                lambda: self._ports.evolution.commit_activation_set(snapshot, qualification),
            )
            self._registry.transition_cycle(
                "commit_activation_set", evidence_id=activation.artifact_id
            )

            current_stage = "post-reflection"
            post_reflections = tuple(
                self._stage(
                    "post-reflection",
                    lambda role=role: self._ports.council.reflect_post(
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
                    ),
                    resume_key=f"post-reflection:{role.value}",
                )
                for role in Role
            )
            post_reflection_index = self._record(
                "post-reflection-index",
                {"reflections": [item.artifact_id for item in post_reflections]},
            )

            current_stage = "summary"
            outcome_class = classify_completed_cycle(
                self._artifact_mapping(candidate_evaluation),
                self._artifact_mapping(qualification),
                self._artifact_mapping(activation),
                self._artifact_mapping(task_validation),
            )
            dimensions = cycle_dimensions(
                task_validation=self._artifact_mapping(task_validation),
                candidate_evaluation=self._artifact_mapping(candidate_evaluation),
                qualification=self._artifact_mapping(qualification),
                activation=self._artifact_mapping(activation),
            )
            summary = self._record(
                "cycle-summary",
                {
                    "snapshot_id": snapshot.snapshot_id,
                    "cohort_id": cohort.cohort_id,
                    "submission": submission.artifact_id,
                    "judge_review": judge_review.artifact_id,
                    "quality_lock": quality_lock.artifact_id,
                    "curriculum_evidence": curriculum_evidence.artifact_id,
                    "prosecutor_audit": prosecutor_audit.artifact_id,
                    "council": council.artifact_id,
                    "objective_governance": objective_governance.artifact_id,
                    "forged_tasks": forged_tasks.artifact_id,
                    "task_validation": task_validation.artifact_id,
                    "candidate_evaluation": candidate_evaluation.artifact_id,
                    "attribution": attribution.artifact_id,
                    "qualification": qualification.artifact_id,
                    "activation": activation.artifact_id,
                    "judge_calibration": judge_calibration.artifact_id,
                    "post_reflections": [item.artifact_id for item in post_reflections],
                    "post_reflection_index": post_reflection_index.artifact_id,
                    "dimensions": dimensions,
                    "outcome_class": outcome_class.value,
                },
            )
            self._registry.transition_cycle("complete", evidence_id=summary.artifact_id)
        except Exception as exc:
            state = self._registry.projection.cycle_state
            if not state.terminal and state not in {CycleState.STOPPING, CycleState.PAUSED}:
                failure = self._record(
                    "cycle-failure",
                    {
                        "outcome_class": classify_exception(current_stage).value,
                        "stage": current_stage,
                        "error_type": type(exc).__name__,
                        "error_message": str(exc)[:2000],
                    },
                )
                self._registry.transition_cycle(
                    "fail",
                    reason=f"v2 cycle stage failed: {failure.artifact_id}",
                )
            raise

        return CycleRunResult(
            snapshot.snapshot_id,
            cohort.cohort_id,
            submission,
            judge_review,
            quality_lock,
            curriculum_evidence,
            prosecutor_audit,
            council,
            objective_governance,
            forged_tasks,
            task_validation,
            candidate_evaluation,
            attribution,
            qualification,
            activation,
            summary,
            judge_calibration,
            post_reflection_index,
        )

    def _record(self, kind: str, evidence: Mapping[str, Any]) -> ArtifactRef:
        if not isinstance(evidence, Mapping):
            raise CycleRuntimeError(f"{kind} port returned non-object evidence")
        _validate_evidence(evidence, path=kind)
        return self._artifacts.put_json(kind, evidence)

    def _stage(
        self,
        kind: str,
        evidence_factory: Callable[[], Mapping[str, Any]],
        *,
        resume_key: str | None = None,
    ) -> ArtifactRef:
        """Record one lifecycle stage, reusing a checkpointed artifact on resume."""
        key = resume_key or kind
        resumed = self._resume_evidence.get(key)
        if resumed is not None:
            return resumed
        ref = self._record(kind, evidence_factory())
        if self._checkpoint is not None:
            self._checkpoint(key, ref)
        return ref

    def _artifact_mapping(self, ref: ArtifactRef) -> Mapping[str, Any]:
        try:
            value = json.loads(self._artifacts.get(ref).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CycleRuntimeError("recorded cycle evidence is not strict JSON") from exc
        if not isinstance(value, Mapping):
            raise CycleRuntimeError("recorded cycle evidence is not an object")
        return value
