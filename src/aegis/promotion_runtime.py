"""Real paired-arm execution for event-sourced strategy promotion."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol, Sequence

from aegis.evaluation import PairedObservation, PromotionDecision, PromotionPolicy
from aegis.strategy import StrategyRegistry, StrategyVersion


@dataclass(frozen=True, slots=True)
class PromotionArmResult:
    """Locked evidence produced by one independently sandboxed strategy arm."""

    quality: float
    tokens: int
    usage_verified: bool
    safety_violations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not 0.0 <= self.quality <= 1.0:
            raise ValueError("promotion arm quality must be in [0,1]")
        if self.tokens <= 0:
            raise ValueError("promotion arm must contain real positive token usage")
        if not all(isinstance(item, str) and item for item in self.safety_violations):
            raise ValueError("safety violations must be non-empty strings")


class PromotionBudgetUnavailable(RuntimeError):
    """Raised before or during a pair when the campaign cannot fund it."""


class PromotionArmRunner(Protocol):
    def __call__(
        self,
        *,
        strategy: StrategyVersion,
        task_id: str,
        seed: int,
        arm: str,
        experiment_id: str,
    ) -> PromotionArmResult: ...


@dataclass(frozen=True, slots=True)
class PromotionRunSummary:
    candidates_seen: int
    pairs_added: int
    decisions: tuple[PromotionDecision, ...]
    pending_for_budget: bool = False


class StrategyPromotionScheduler:
    """Run champion/candidate arms against the same sealed 12x2 design.

    The scheduler owns no scoring shortcut.  Its runner must return evidence
    from a real model/tool loop and hidden-test evaluation.  An observation is
    appended only after both independent arms complete.
    """

    def __init__(
        self,
        registry: StrategyRegistry,
        task_ids: Sequence[str],
        runner: PromotionArmRunner,
        *,
        policy: PromotionPolicy | None = None,
        can_start_pair: Callable[[], bool] | None = None,
    ) -> None:
        self.registry = registry
        self.task_ids = tuple(task_ids)
        self.runner = runner
        self.policy = policy or PromotionPolicy()
        self.can_start_pair = can_start_pair or (lambda: True)
        if len(self.task_ids) != self.policy.required_tasks:
            raise ValueError(f"promotion scheduler requires exactly {self.policy.required_tasks} tasks")
        if len(set(self.task_ids)) != len(self.task_ids):
            raise ValueError("promotion task identities must be unique")

    def run_pending(self) -> PromotionRunSummary:
        decisions: list[PromotionDecision] = []
        pairs_added = 0
        candidates = self.registry.pending_candidates()
        for candidate in candidates:
            current = self.registry.champion(candidate.target_role)
            if current is None or candidate.parent_version_id != current.version_id:
                self.registry.supersede_stale_candidate(
                    candidate.version_id,
                    "candidate parent is no longer the active champion",
                )
                continue
            experiment = self.registry.experiment_for_candidate(candidate.version_id)
            if experiment is None:
                experiment = self.registry.start_experiment(
                    candidate.version_id,
                    self.task_ids,
                    policy=self.policy,
                )
            champion = self.registry.version(experiment.snapshot.champion_id)
            for task_index, task_id in enumerate(self.task_ids):
                for seed in range(self.policy.seeds_per_task):
                    if experiment.has_observation(task_id, seed):
                        continue
                    if not self.can_start_pair():
                        return PromotionRunSummary(len(candidates), pairs_added, tuple(decisions), True)
                    try:
                        # Alternate order to avoid giving either arm a systematic
                        # first-run cache or relay-position advantage.
                        if (task_index + seed) % 2:
                            champion_result = self._run(
                                champion, task_id, seed, "champion", experiment.experiment_id
                            )
                            candidate_result = self._run(
                                candidate, task_id, seed, "candidate", experiment.experiment_id
                            )
                        else:
                            candidate_result = self._run(
                                candidate, task_id, seed, "candidate", experiment.experiment_id
                            )
                            champion_result = self._run(
                                champion, task_id, seed, "champion", experiment.experiment_id
                            )
                    except PromotionBudgetUnavailable:
                        return PromotionRunSummary(len(candidates), pairs_added, tuple(decisions), True)
                    decision = experiment.add_observation(
                        PairedObservation(
                            task_id=task_id,
                            seed=seed,
                            candidate_quality=candidate_result.quality,
                            champion_quality=champion_result.quality,
                            candidate_tokens=candidate_result.tokens,
                            champion_tokens=champion_result.tokens,
                            candidate_usage_verified=candidate_result.usage_verified,
                            champion_usage_verified=champion_result.usage_verified,
                            safety_violation=bool(
                                candidate_result.safety_violations or champion_result.safety_violations
                            ),
                        )
                    )
                    pairs_added += 1
                    if decision is not None:
                        decisions.append(decision)
            # A recovered fully observed experiment may not yet have its final
            # event if the process stopped between append and finalization.
            if experiment.snapshot.state == "pending" and (
                len(experiment.snapshot.observations)
                == self.policy.required_tasks * self.policy.seeds_per_task
            ):
                decisions.append(experiment.finalize())
        return PromotionRunSummary(len(candidates), pairs_added, tuple(decisions))

    def _run(
        self, strategy: StrategyVersion, task_id: str, seed: int, arm: str, experiment_id: str
    ) -> PromotionArmResult:
        result = self.runner(
            strategy=strategy, task_id=task_id, seed=seed, arm=arm, experiment_id=experiment_id
        )
        if not isinstance(result, PromotionArmResult):
            raise TypeError("promotion runner returned an invalid result")
        return result
