"""Durable paired evaluation and promotion for quarantined declarative skills."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from statistics import fmean
from typing import Callable, Mapping, Protocol, Sequence, cast

from aegis.evaluation import PairedObservation, PromotionDecision, PromotionPolicy, decide_promotion
from aegis.event_store import EventStore
from aegis.models import canonical_json
from aegis.promotion_runtime import PromotionArmResult, PromotionBudgetUnavailable
from aegis.skill_registry import (
    SkillCandidate,
    SkillCandidateState,
    SkillEvaluationReport,
    SkillFunnelReport,
    SkillRegistry,
)

NO_SKILL_BASELINE_ID = "no-skill-v1"
SMOKE_TASKS = 2
SMOKE_MAX_QUALITY_REGRESSION = 0.05
SMOKE_MAX_TOKEN_INCREASE = 0.50
FULL_POLICY = PromotionPolicy(required_tasks=12, seeds_per_task=2)


class SkillPromotionRuntimeError(RuntimeError):
    """Raised when persisted promotion state or registry state is inconsistent."""


class SkillPromotionArmRunner(Protocol):
    """Execute one independently sandboxed, externally scored evaluation arm."""

    def __call__(
        self,
        *,
        candidate_artifact_id: str,
        baseline_artifact_id: str,
        evaluated_artifact_id: str,
        skill_name: str,
        skill_version: str,
        task_id: str,
        seed: int,
        arm: str,
        experiment_id: str,
    ) -> PromotionArmResult: ...


@dataclass(frozen=True, slots=True)
class SkillPromotionExperiment:
    experiment_id: str
    candidate_artifact_id: str
    baseline_artifact_id: str
    baseline_revision: str
    skill_name: str
    skill_version: str
    task_ids: tuple[str, ...]
    policy_sha256: str


@dataclass(frozen=True, slots=True)
class SkillPromotionOutcome:
    candidate_artifact_id: str
    experiment_id: str
    state: str
    reason: str
    decision: PromotionDecision | None = None


@dataclass(frozen=True, slots=True)
class SkillPromotionRunSummary:
    candidates_seen: int
    arms_added: int
    outcomes: tuple[SkillPromotionOutcome, ...]
    pending_for_budget: bool = False


def _digest(value: Mapping[str, object]) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _policy_payload(policy: PromotionPolicy) -> dict[str, object]:
    return asdict(policy)


def _result_payload(result: PromotionArmResult) -> dict[str, object]:
    return {
        "quality": result.quality,
        "tokens": result.tokens,
        "usage_verified": result.usage_verified,
        "safety_violations": list(result.safety_violations),
    }


def _parse_result(value: object) -> PromotionArmResult:
    if not isinstance(value, Mapping) or set(value) != {
        "quality",
        "tokens",
        "usage_verified",
        "safety_violations",
    }:
        raise SkillPromotionRuntimeError("persisted skill promotion arm result is invalid")
    violations = value["safety_violations"]
    if not isinstance(violations, (list, tuple)) or any(
        not isinstance(item, str) for item in violations
    ):
        raise SkillPromotionRuntimeError("persisted skill promotion safety evidence is invalid")
    try:
        return PromotionArmResult(
            quality=cast(float, value["quality"]),
            tokens=cast(int, value["tokens"]),
            usage_verified=cast(bool, value["usage_verified"]),
            safety_violations=tuple(violations),
        )
    except (TypeError, ValueError) as exc:
        raise SkillPromotionRuntimeError("persisted skill promotion arm result is invalid") from exc


class SkillPromotionScheduler:
    """Run a resumable 2-task smoke gate followed by an exact 12x2 paired design.

    The first two task/seed-zero pairs are both the smoke sample and part of the
    final 12x2 design. Each arm is persisted immediately, so a crash between
    paired arms does not spend tokens rerunning the completed arm.
    """

    def __init__(
        self,
        registry: SkillRegistry,
        event_store: EventStore,
        campaign_id: str,
        task_ids: Sequence[str],
        runner: SkillPromotionArmRunner,
        *,
        policy: PromotionPolicy | None = None,
        can_start_arm: Callable[[], bool] | None = None,
    ) -> None:
        self.registry = registry
        self.event_store = event_store
        self.campaign_id = campaign_id
        self.task_ids = tuple(task_ids)
        self.runner = runner
        self.policy = policy or FULL_POLICY
        self.can_start_arm = can_start_arm or (lambda: True)
        if not isinstance(campaign_id, str) or not campaign_id.strip():
            raise ValueError("campaign_id must be non-empty")
        if self.policy.required_tasks != 12 or self.policy.seeds_per_task != 2:
            raise ValueError("skill promotion requires an exact 12-task x 2-seed policy")
        if len(self.task_ids) != 12 or len(set(self.task_ids)) != 12:
            raise ValueError("skill promotion requires exactly 12 unique sealed tasks")
        if any(not isinstance(task, str) or not task.strip() for task in self.task_ids):
            raise ValueError("skill promotion task ids must be non-empty strings")

    def run_pending(self) -> SkillPromotionRunSummary:
        outcomes: list[SkillPromotionOutcome] = []
        arms_added = 0
        candidates = tuple(
            candidate
            for candidate in self.registry.candidates()
            if candidate.state is SkillCandidateState.VALIDATED_PENDING
        )
        for candidate in candidates:
            experiment = self._experiment(candidate)
            terminal = self._terminal_outcome(experiment)
            if terminal is not None:
                outcomes.append(terminal)
                continue
            if not self._baseline_is_current(experiment):
                outcome = self._finish(experiment, "stale", "locked baseline is no longer champion")
                outcomes.append(outcome)
                continue
            results = self._arm_results(experiment)
            try:
                for task_id, seed in self._evaluation_order():
                    for arm in self._arm_order(task_id, seed):
                        key = (task_id, seed, arm)
                        if key in results:
                            continue
                        if not self.can_start_arm():
                            return SkillPromotionRunSummary(
                                len(candidates), arms_added, tuple(outcomes), True
                            )
                        result = self._run_arm(experiment, task_id, seed, arm)
                        self._append_arm(experiment, task_id, seed, arm, result)
                        results[key] = result
                        arms_added += 1
                    if self._smoke_complete(results) and not self._full_started(results):
                        reason = self._smoke_failure(results)
                        if reason is not None:
                            outcomes.append(self._finish(experiment, "rejected", reason))
                            break
                else:
                    outcome = self._finalize(experiment, results)
                    outcomes.append(outcome)
            except PromotionBudgetUnavailable:
                return SkillPromotionRunSummary(len(candidates), arms_added, tuple(outcomes), True)
        return SkillPromotionRunSummary(len(candidates), arms_added, tuple(outcomes))

    def _experiment(self, candidate: SkillCandidate) -> SkillPromotionExperiment:
        champion = self.registry.champion(candidate.name)
        baseline_id = NO_SKILL_BASELINE_ID if champion is None else champion.artifact.artifact_id
        baseline_revision = self.registry.champion_revision(candidate.name)
        policy_sha256 = _digest(_policy_payload(self.policy))
        identity = _digest(
            {
                "candidate_artifact_id": candidate.artifact.artifact_id,
                "baseline_artifact_id": baseline_id,
                "baseline_revision": baseline_revision,
                "skill_name": candidate.name,
                "skill_version": candidate.version,
                "task_ids": list(self.task_ids),
                "policy_sha256": policy_sha256,
            }
        )
        proposed = SkillPromotionExperiment(
            f"skill-experiment-sha256:{identity}",
            candidate.artifact.artifact_id,
            baseline_id,
            baseline_revision,
            candidate.name,
            candidate.version,
            self.task_ids,
            policy_sha256,
        )
        persisted = self._persisted_start(candidate.artifact.artifact_id)
        if persisted is not None:
            return persisted
        self.event_store.append(
            self.campaign_id,
            "skill_promotion_started",
            self._experiment_payload(proposed),
        )
        return proposed

    @staticmethod
    def _experiment_payload(experiment: SkillPromotionExperiment) -> dict[str, object]:
        return {
            "experiment_id": experiment.experiment_id,
            "candidate_artifact_id": experiment.candidate_artifact_id,
            "baseline_artifact_id": experiment.baseline_artifact_id,
            "baseline_revision": experiment.baseline_revision,
            "skill_name": experiment.skill_name,
            "skill_version": experiment.skill_version,
            "task_ids": list(experiment.task_ids),
            "policy_sha256": experiment.policy_sha256,
        }

    def _persisted_start(self, artifact_id: str) -> SkillPromotionExperiment | None:
        matches = [
            event.payload
            for event in self.event_store.read(self.campaign_id)
            if event.event_type == "skill_promotion_started"
            and event.payload.get("candidate_artifact_id") == artifact_id
        ]
        if len(matches) > 1:
            raise SkillPromotionRuntimeError("skill candidate has multiple promotion experiments")
        if not matches:
            return None
        payload = matches[0]
        if set(payload) != {
            "experiment_id",
            "candidate_artifact_id",
            "baseline_artifact_id",
            "baseline_revision",
            "skill_name",
            "skill_version",
            "task_ids",
            "policy_sha256",
        }:
            raise SkillPromotionRuntimeError("persisted skill promotion experiment is invalid")
        task_ids = payload["task_ids"]
        if not isinstance(task_ids, (list, tuple)) or any(
            not isinstance(item, str) for item in task_ids
        ):
            raise SkillPromotionRuntimeError("persisted skill promotion task design is invalid")
        experiment = SkillPromotionExperiment(
            cast(str, payload["experiment_id"]),
            cast(str, payload["candidate_artifact_id"]),
            cast(str, payload["baseline_artifact_id"]),
            cast(str, payload["baseline_revision"]),
            cast(str, payload["skill_name"]),
            cast(str, payload["skill_version"]),
            tuple(cast(Sequence[str], task_ids)),
            cast(str, payload["policy_sha256"]),
        )
        expected_id = "skill-experiment-sha256:" + _digest(
            {
                key: value
                for key, value in self._experiment_payload(experiment).items()
                if key != "experiment_id"
            }
        )
        if (
            experiment.experiment_id != expected_id
            or experiment.task_ids != self.task_ids
            or experiment.policy_sha256 != _digest(_policy_payload(self.policy))
        ):
            raise SkillPromotionRuntimeError("persisted skill promotion experiment identity drifted")
        return experiment

    def _arm_results(
        self, experiment: SkillPromotionExperiment
    ) -> dict[tuple[str, int, str], PromotionArmResult]:
        results: dict[tuple[str, int, str], PromotionArmResult] = {}
        valid_keys = {
            (task_id, seed, arm)
            for task_id in self.task_ids
            for seed in range(2)
            for arm in ("candidate", "baseline")
        }
        for event in self.event_store.read(self.campaign_id):
            if event.event_type != "skill_promotion_arm_completed":
                continue
            payload = event.payload
            if payload.get("experiment_id") != experiment.experiment_id:
                continue
            if set(payload) != {
                "experiment_id",
                "candidate_artifact_id",
                "baseline_artifact_id",
                "task_id",
                "seed",
                "arm",
                "evaluated_artifact_id",
                "result",
            }:
                raise SkillPromotionRuntimeError("persisted skill promotion arm event is invalid")
            key = (cast(str, payload["task_id"]), cast(int, payload["seed"]), cast(str, payload["arm"]))
            expected_target = (
                experiment.candidate_artifact_id if key[2] == "candidate" else experiment.baseline_artifact_id
            )
            if (
                key not in valid_keys
                or key in results
                or payload["candidate_artifact_id"] != experiment.candidate_artifact_id
                or payload["baseline_artifact_id"] != experiment.baseline_artifact_id
                or payload["evaluated_artifact_id"] != expected_target
            ):
                raise SkillPromotionRuntimeError("persisted skill promotion arm identity is invalid")
            results[key] = _parse_result(payload["result"])
        return results

    def _run_arm(
        self, experiment: SkillPromotionExperiment, task_id: str, seed: int, arm: str
    ) -> PromotionArmResult:
        evaluated_id = (
            experiment.candidate_artifact_id if arm == "candidate" else experiment.baseline_artifact_id
        )
        result = self.runner(
            candidate_artifact_id=experiment.candidate_artifact_id,
            baseline_artifact_id=experiment.baseline_artifact_id,
            evaluated_artifact_id=evaluated_id,
            skill_name=experiment.skill_name,
            skill_version=experiment.skill_version,
            task_id=task_id,
            seed=seed,
            arm=arm,
            experiment_id=experiment.experiment_id,
        )
        if not isinstance(result, PromotionArmResult):
            raise TypeError("skill promotion runner returned an invalid result")
        return result

    def _append_arm(
        self,
        experiment: SkillPromotionExperiment,
        task_id: str,
        seed: int,
        arm: str,
        result: PromotionArmResult,
    ) -> None:
        target = (
            experiment.candidate_artifact_id if arm == "candidate" else experiment.baseline_artifact_id
        )
        self.event_store.append(
            self.campaign_id,
            "skill_promotion_arm_completed",
            {
                "experiment_id": experiment.experiment_id,
                "candidate_artifact_id": experiment.candidate_artifact_id,
                "baseline_artifact_id": experiment.baseline_artifact_id,
                "task_id": task_id,
                "seed": seed,
                "arm": arm,
                "evaluated_artifact_id": target,
                "result": _result_payload(result),
            },
        )

    def _evaluation_order(self) -> tuple[tuple[str, int], ...]:
        smoke = ((self.task_ids[0], 0), (self.task_ids[1], 0))
        rest = tuple(
            (task_id, seed)
            for task_id in self.task_ids
            for seed in range(2)
            if (task_id, seed) not in smoke
        )
        return smoke + rest

    def _arm_order(self, task_id: str, seed: int) -> tuple[str, str]:
        task_index = self.task_ids.index(task_id)
        return ("baseline", "candidate") if (task_index + seed) % 2 else ("candidate", "baseline")

    def _smoke_complete(self, results: Mapping[tuple[str, int, str], PromotionArmResult]) -> bool:
        return all(
            (task_id, 0, arm) in results
            for task_id in self.task_ids[:SMOKE_TASKS]
            for arm in ("candidate", "baseline")
        )

    def _full_started(self, results: Mapping[tuple[str, int, str], PromotionArmResult]) -> bool:
        smoke_keys = {
            (task_id, 0, arm)
            for task_id in self.task_ids[:SMOKE_TASKS]
            for arm in ("candidate", "baseline")
        }
        return any(key not in smoke_keys for key in results)

    def _smoke_failure(
        self, results: Mapping[tuple[str, int, str], PromotionArmResult]
    ) -> str | None:
        pairs = [self._observation(results, task_id, 0) for task_id in self.task_ids[:2]]
        if any(row.safety_violation for row in pairs):
            return "safety violation in smoke evaluation"
        if any(not row.candidate_usage_verified or not row.champion_usage_verified for row in pairs):
            return "unverified token usage in smoke evaluation"
        if fmean(row.candidate_quality - row.champion_quality for row in pairs) < -SMOKE_MAX_QUALITY_REGRESSION:
            return "candidate was eliminated by smoke quality regression"
        candidate_tokens = sum(row.candidate_tokens for row in pairs)
        baseline_tokens = sum(row.champion_tokens for row in pairs)
        if candidate_tokens > baseline_tokens * (1.0 + SMOKE_MAX_TOKEN_INCREASE):
            return "candidate was eliminated by smoke token regression"
        return None

    @staticmethod
    def _observation(
        results: Mapping[tuple[str, int, str], PromotionArmResult], task_id: str, seed: int
    ) -> PairedObservation:
        candidate = results[(task_id, seed, "candidate")]
        baseline = results[(task_id, seed, "baseline")]
        return PairedObservation(
            task_id=task_id,
            seed=seed,
            candidate_quality=candidate.quality,
            champion_quality=baseline.quality,
            candidate_tokens=candidate.tokens,
            champion_tokens=baseline.tokens,
            candidate_usage_verified=candidate.usage_verified,
            champion_usage_verified=baseline.usage_verified,
            safety_violation=bool(candidate.safety_violations or baseline.safety_violations),
        )

    def _finalize(
        self,
        experiment: SkillPromotionExperiment,
        results: Mapping[tuple[str, int, str], PromotionArmResult],
    ) -> SkillPromotionOutcome:
        observations = tuple(
            self._observation(results, task_id, seed)
            for task_id in self.task_ids
            for seed in range(2)
        )
        decision = decide_promotion(observations, self.policy)
        report_payload: dict[str, object] = {
            "experiment": self._experiment_payload(experiment),
            "observations": [asdict(row) for row in observations],
            "decision": asdict(decision),
        }
        report_sha256 = _digest(report_payload)
        baseline_id = (
            None
            if experiment.baseline_artifact_id == NO_SKILL_BASELINE_ID
            else experiment.baseline_artifact_id
        )
        smoke_observations = tuple(
            self._observation(results, task_id, 0) for task_id in self.task_ids[:2]
        )
        smoke_report = SkillEvaluationReport.create(
            artifact_id=experiment.candidate_artifact_id,
            baseline_artifact_id=baseline_id,
            phase="smoke",
            observations_sha256=_digest(
                {"observations": [asdict(row) for row in smoke_observations]}
            ),
            safety_verified=True,
            quality_verified=True,
            usage_verified=True,
            candidate_tokens=sum(row.candidate_tokens for row in smoke_observations),
            baseline_tokens=sum(row.champion_tokens for row in smoke_observations),
        )
        full_report = SkillEvaluationReport.create(
            artifact_id=experiment.candidate_artifact_id,
            baseline_artifact_id=baseline_id,
            phase="full",
            observations_sha256=report_sha256,
            safety_verified=not any(row.safety_violation for row in observations),
            quality_verified=decision.promoted,
            usage_verified=all(
                row.candidate_usage_verified and row.champion_usage_verified for row in observations
            ),
            candidate_tokens=sum(row.candidate_tokens for row in observations),
            baseline_tokens=sum(row.champion_tokens for row in observations),
        )
        self._record_evaluation(smoke_report)
        self._record_evaluation(full_report)
        funnel = SkillFunnelReport.create(
            artifact_id=experiment.candidate_artifact_id,
            baseline_artifact_id=baseline_id,
            baseline_revision=experiment.baseline_revision,
            static_evidence_id=self._static_evidence_id(experiment.candidate_artifact_id),
            smoke_report_id=smoke_report.report_id,
            full_report_id=full_report.report_id,
            promotable=decision.promoted,
        )
        self._record_funnel(funnel)
        if decision.promoted:
            self._promote_cas(experiment, funnel.report_id)
            state = "promoted"
        else:
            state = "rejected"
        return self._finish(experiment, state, decision.reason, decision)

    def _promote_cas(
        self,
        experiment: SkillPromotionExperiment,
        report_id: str,
    ) -> None:
        if not self._baseline_is_current(experiment):
            raise SkillPromotionRuntimeError("skill champion changed before promotion CAS")
        self.registry.promote_evaluated(
            artifact_id=experiment.candidate_artifact_id,
            funnel_report_id=report_id,
            expected_champion_id=(
                None
                if experiment.baseline_artifact_id == NO_SKILL_BASELINE_ID
                else experiment.baseline_artifact_id
            ),
            expected_champion_revision=experiment.baseline_revision,
        )

    def _baseline_is_current(self, experiment: SkillPromotionExperiment) -> bool:
        champion = self.registry.champion(experiment.skill_name)
        current = NO_SKILL_BASELINE_ID if champion is None else champion.artifact.artifact_id
        return (
            current == experiment.baseline_artifact_id
            and self.registry.champion_revision(experiment.skill_name) == experiment.baseline_revision
        )

    def _verified_registry_reports(
        self,
    ) -> tuple[dict[str, object], dict[str, SkillEvaluationReport], dict[str, SkillFunnelReport]]:
        known = {candidate.artifact.artifact_id for candidate in self.registry.candidates()}
        return self.registry._verified_reports(known)

    def _static_evidence_id(self, artifact_id: str) -> str:
        static, _, _ = self._verified_registry_reports()
        evidence_id = getattr(static.get(artifact_id), "evidence_id", None)
        if not isinstance(evidence_id, str):
            raise SkillPromotionRuntimeError("validated candidate lacks durable static evidence")
        return evidence_id

    def _record_evaluation(self, report: SkillEvaluationReport) -> None:
        _, evaluations, _ = self._verified_registry_reports()
        existing = evaluations.get(report.report_id)
        if existing is None:
            self.registry.record_evaluation_report(report)
        elif existing != report:
            raise SkillPromotionRuntimeError("evaluation report identity collision")

    def _record_funnel(self, report: SkillFunnelReport) -> None:
        _, _, funnels = self._verified_registry_reports()
        existing = funnels.get(report.report_id)
        if existing is None:
            self.registry.record_funnel_report(report)
        elif existing != report:
            raise SkillPromotionRuntimeError("funnel report identity collision")

    def _terminal_outcome(self, experiment: SkillPromotionExperiment) -> SkillPromotionOutcome | None:
        matches = [
            event.payload
            for event in self.event_store.read(self.campaign_id)
            if event.event_type == "skill_promotion_finished"
            and event.payload.get("experiment_id") == experiment.experiment_id
        ]
        if len(matches) > 1:
            raise SkillPromotionRuntimeError("skill promotion experiment has multiple terminal events")
        if not matches:
            return None
        payload = matches[0]
        if set(payload) != {
            "experiment_id",
            "candidate_artifact_id",
            "state",
            "reason",
            "decision",
        }:
            raise SkillPromotionRuntimeError("persisted skill promotion outcome is invalid")
        decision_payload = payload["decision"]
        decision = None
        if decision_payload is not None:
            if not isinstance(decision_payload, Mapping) or set(decision_payload) != {
                "promoted",
                "reason",
                "quality_delta",
                "quality_lower_bound",
                "token_change",
                "token_saving_lower_bound",
                "pairs",
            }:
                raise SkillPromotionRuntimeError("persisted skill promotion decision is invalid")
            try:
                decision = PromotionDecision(
                    promoted=cast(bool, decision_payload["promoted"]),
                    reason=cast(str, decision_payload["reason"]),
                    quality_delta=cast(float, decision_payload["quality_delta"]),
                    quality_lower_bound=cast(float, decision_payload["quality_lower_bound"]),
                    token_change=cast(float, decision_payload["token_change"]),
                    token_saving_lower_bound=cast(
                        float, decision_payload["token_saving_lower_bound"]
                    ),
                    pairs=cast(int, decision_payload["pairs"]),
                )
            except (TypeError, ValueError) as exc:
                raise SkillPromotionRuntimeError("persisted skill promotion decision is invalid") from exc
        return SkillPromotionOutcome(
            cast(str, payload["candidate_artifact_id"]),
            experiment.experiment_id,
            cast(str, payload["state"]),
            cast(str, payload["reason"]),
            decision,
        )

    def _finish(
        self,
        experiment: SkillPromotionExperiment,
        state: str,
        reason: str,
        decision: PromotionDecision | None = None,
    ) -> SkillPromotionOutcome:
        if state not in {"promoted", "rejected", "stale"}:
            raise ValueError("invalid skill promotion terminal state")
        outcome = SkillPromotionOutcome(
            experiment.candidate_artifact_id,
            experiment.experiment_id,
            state,
            reason,
            decision,
        )
        self.event_store.append(
            self.campaign_id,
            "skill_promotion_finished",
            {
                "experiment_id": experiment.experiment_id,
                "candidate_artifact_id": experiment.candidate_artifact_id,
                "state": state,
                "reason": reason,
                "decision": None if decision is None else asdict(decision),
            },
        )
        return outcome


__all__ = [
    "FULL_POLICY",
    "NO_SKILL_BASELINE_ID",
    "SkillPromotionArmRunner",
    "SkillPromotionExperiment",
    "SkillPromotionOutcome",
    "SkillPromotionRunSummary",
    "SkillPromotionRuntimeError",
    "SkillPromotionScheduler",
]
