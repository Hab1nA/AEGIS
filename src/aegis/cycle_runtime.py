"""Evidence-first orchestration for one AEGIS v2 autonomous cycle."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from aegis.artifacts import ArtifactRef, ContentAddressedArtifactStore
from aegis.curriculum import CurriculumRegistry, CurriculumSnapshot, CycleState
from aegis.dynamic_tasks import DynamicTaskCohort
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

    def deliberate(
        self,
        snapshot: CurriculumSnapshot,
        reflections: tuple[ArtifactRef, ...],
    ) -> Mapping[str, Any]: ...


class EvolutionCyclePort(Protocol):
    def validate_forged_tasks(
        self, snapshot: CurriculumSnapshot, forged_tasks: ArtifactRef
    ) -> Mapping[str, Any]: ...

    def evaluate_candidates(
        self,
        snapshot: CurriculumSnapshot,
        cohort: DynamicTaskCohort,
        submission: ArtifactRef,
        prosecutor_audit: ArtifactRef,
        quality_lock: ArtifactRef,
        task_validation: ArtifactRef,
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
        self, snapshot: CurriculumSnapshot, attribution: ArtifactRef
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
    prosecutor_audit: ArtifactRef
    council: ArtifactRef
    forged_tasks: ArtifactRef
    task_validation: ArtifactRef
    candidate_evaluation: ArtifactRef
    attribution: ArtifactRef
    qualification: ArtifactRef
    activation: ArtifactRef
    cycle_summary: ArtifactRef


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
    ) -> None:
        self._registry = registry
        self._cohorts = cohorts
        self._artifacts = artifacts
        self._ports = ports

    def run(
        self,
        snapshot: CurriculumSnapshot,
        *,
        target_generation: int,
        cohort_limit: int | None = None,
    ) -> CycleRunResult:
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
        if current is None or snapshot.cycle_number > current.cycle_number:
            self._registry.record_snapshot(snapshot)
        elif snapshot.snapshot_id != current.snapshot_id:
            raise CycleRuntimeError("snapshot conflicts with the recorded cycle")
        self._registry.transition_cycle("lock_snapshot")
        self._registry.transition_cycle("lock_cohort", evidence_id=cohort.cohort_id)

        try:
            submission = self._record(
                "submission", self._ports.warrior.solve(snapshot, cohort)
            )
            self._registry.transition_cycle("collect_solutions", evidence_id=submission.artifact_id)
            self._registry.transition_cycle("freeze_submission", evidence_id=submission.artifact_id)

            judge_review = self._record(
                "judge-review", self._ports.judge.review(snapshot, submission)
            )
            self._registry.transition_cycle(
                "record_judge_review", evidence_id=judge_review.artifact_id
            )

            quality_lock = self._record(
                "quality-lock",
                self._ports.quality.lock_quality(snapshot, cohort, submission, judge_review),
            )
            self._registry.transition_cycle("lock_quality", evidence_id=quality_lock.artifact_id)

            prosecutor_audit = self._record(
                "prosecutor-audit",
                self._ports.prosecutor.audit(
                    snapshot, submission, judge_review, quality_lock
                ),
            )
            self._registry.transition_cycle(
                "record_prosecutor_audit", evidence_id=prosecutor_audit.artifact_id
            )

            reflections = tuple(
                self._record(
                    "reflection",
                    self._ports.council.reflect(
                        role,
                        snapshot,
                        submission,
                        judge_review,
                        quality_lock,
                        prosecutor_audit,
                    ),
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

            council = self._record(
                "council", self._ports.council.deliberate(snapshot, reflections)
            )
            self._registry.transition_cycle("complete_council", evidence_id=council.artifact_id)

            forged_tasks = self._record(
                "task-forge",
                self._ports.judge.forge_next_tasks(
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

            task_validation = self._record(
                "task-validation",
                self._ports.evolution.validate_forged_tasks(snapshot, forged_tasks),
            )
            self._registry.transition_cycle(
                "complete_task_validation", evidence_id=task_validation.artifact_id
            )

            candidate_evaluation = self._record(
                "candidate-evaluation",
                self._ports.evolution.evaluate_candidates(
                    snapshot,
                    cohort,
                    submission,
                    prosecutor_audit,
                    quality_lock,
                    task_validation,
                ),
            )
            self._registry.transition_cycle(
                "evaluate_candidates", evidence_id=candidate_evaluation.artifact_id
            )

            attribution = self._record(
                "attribution",
                self._ports.evolution.lock_attribution(
                    snapshot,
                    quality_lock,
                    prosecutor_audit,
                    council,
                    task_validation,
                    candidate_evaluation,
                ),
            )
            self._registry.transition_cycle("lock_attribution", evidence_id=attribution.artifact_id)

            qualification = self._record(
                "qualification",
                self._ports.evolution.qualify_role_candidates(snapshot, attribution),
            )
            self._registry.transition_cycle(
                "qualify_role_candidates", evidence_id=qualification.artifact_id
            )

            activation = self._record(
                "activation",
                self._ports.evolution.commit_activation_set(snapshot, qualification),
            )
            self._registry.transition_cycle(
                "commit_activation_set", evidence_id=activation.artifact_id
            )

            summary = self._record(
                "cycle-summary",
                {
                    "snapshot_id": snapshot.snapshot_id,
                    "cohort_id": cohort.cohort_id,
                    "submission": submission.artifact_id,
                    "judge_review": judge_review.artifact_id,
                    "quality_lock": quality_lock.artifact_id,
                    "prosecutor_audit": prosecutor_audit.artifact_id,
                    "council": council.artifact_id,
                    "forged_tasks": forged_tasks.artifact_id,
                    "task_validation": task_validation.artifact_id,
                    "candidate_evaluation": candidate_evaluation.artifact_id,
                    "attribution": attribution.artifact_id,
                    "qualification": qualification.artifact_id,
                    "activation": activation.artifact_id,
                },
            )
            self._registry.transition_cycle("complete", evidence_id=summary.artifact_id)
        except Exception:
            state = self._registry.projection.cycle_state
            if not state.terminal and state not in {CycleState.STOPPING, CycleState.PAUSED}:
                self._registry.transition_cycle("fail", reason="v2 cycle stage failed")
            raise

        return CycleRunResult(
            snapshot.snapshot_id,
            cohort.cohort_id,
            submission,
            judge_review,
            quality_lock,
            prosecutor_audit,
            council,
            forged_tasks,
            task_validation,
            candidate_evaluation,
            attribution,
            qualification,
            activation,
            summary,
        )

    def _record(self, kind: str, evidence: Mapping[str, Any]) -> ArtifactRef:
        if not isinstance(evidence, Mapping):
            raise CycleRuntimeError(f"{kind} port returned non-object evidence")
        _validate_evidence(evidence, path=kind)
        return self._artifacts.put_json(kind, evidence)
