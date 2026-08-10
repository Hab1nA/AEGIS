"""Durable paired promotion scheduler for isolated self-evolution candidates."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Callable, Mapping, Protocol, Sequence

from aegis.evaluation import PairedObservation
from aegis.event_store import EventStore
from aegis.evolution_funnel import (
    FunnelStage,
    VerifiedTokenEvidence,
    evaluate_evolution_candidate,
    evaluate_smoke_only_candidate,
)
from aegis.evolution_registry import EvolutionRegistry, EvolutionRegistryError
from aegis.models import canonical_json
from aegis.promotion_runtime import PromotionArmResult, PromotionBudgetUnavailable


class EvolutionPromotionArmRunner(Protocol):
    def __call__(
        self,
        *,
        candidate_artifact_id: str,
        parent_champion_id: str | None,
        task_id: str,
        seed: int,
        arm: str,
        experiment_id: str,
    ) -> PromotionArmResult: ...


@dataclass(frozen=True, slots=True)
class EvolutionPromotionSummary:
    candidates_seen: int
    pairs_added: int
    promoted: tuple[str, ...]
    rejected: tuple[str, ...]
    pending_for_budget: bool = False


class EvolutionPromotionScheduler:
    """Resume exact paired experiments from immutable campaign events."""

    def __init__(
        self,
        registry: EvolutionRegistry,
        store: EventStore,
        campaign_id: str,
        task_ids: Sequence[str],
        runner: EvolutionPromotionArmRunner,
        *,
        can_start_pair: Callable[[], bool] | None = None,
        smoke_only: bool = False,
    ) -> None:
        self.registry = registry
        self.store = store
        self.campaign_id = campaign_id
        self.task_ids = tuple(task_ids)
        self.runner = runner
        self.can_start_pair = can_start_pair or (lambda: True)
        self.smoke_only = smoke_only
        if len(self.task_ids) != 12 or len(set(self.task_ids)) != 12:
            raise ValueError("evolution promotion requires exactly 12 unique sealed tasks")

    def _events(self) -> tuple[tuple[str, Mapping[str, object]], ...]:
        return tuple((event.event_type, event.payload) for event in self.store.read(self.campaign_id))

    def _append(self, event_type: str, payload: Mapping[str, object]) -> None:
        self.store.append(self.campaign_id, event_type, payload)

    def _experiment_id(self, artifact_id: str, parent_id: str | None) -> str:
        digest = hashlib.sha256(
            canonical_json(
                {
                    "schema_version": 1,
                    "candidate_artifact_id": artifact_id,
                    "parent_champion_id": parent_id,
                    "task_ids": list(self.task_ids),
                    "seeds": [0, 1],
                }
            ).encode("utf-8")
        ).hexdigest()
        return f"evolution-experiment-sha256:{digest}"

    @staticmethod
    def _arm_result(payload: Mapping[str, object]) -> PromotionArmResult:
        violations = payload.get("safety_violations", [])
        if not isinstance(violations, (list, tuple)):
            raise ValueError("durable evolution arm safety evidence is invalid")
        quality = payload.get("quality")
        tokens = payload.get("tokens")
        usage_verified = payload.get("usage_verified")
        if isinstance(quality, bool) or not isinstance(quality, (int, float)):
            raise ValueError("durable evolution arm quality is invalid")
        if isinstance(tokens, bool) or not isinstance(tokens, int):
            raise ValueError("durable evolution arm token evidence is invalid")
        if not isinstance(usage_verified, bool):
            raise ValueError("durable evolution arm usage evidence is invalid")
        return PromotionArmResult(
            float(quality),
            tokens,
            usage_verified,
            tuple(str(item) for item in violations),
        )

    def _stored_arm(
        self, experiment_id: str, task_id: str, seed: int, arm: str
    ) -> PromotionArmResult | None:
        matches = [
            payload
            for event_type, payload in self._events()
            if event_type == "evolution_promotion_arm_completed"
            and payload.get("experiment_id") == experiment_id
            and payload.get("task_id") == task_id
            and payload.get("seed") == seed
            and payload.get("arm") == arm
        ]
        if len(matches) > 1:
            first = canonical_json(matches[0])
            if any(canonical_json(item) != first for item in matches[1:]):
                raise RuntimeError("conflicting durable evolution arm evidence")
        return None if not matches else self._arm_result(matches[0])

    def _run_arm(
        self,
        *,
        artifact_id: str,
        parent_id: str | None,
        task_id: str,
        seed: int,
        arm: str,
        experiment_id: str,
    ) -> PromotionArmResult:
        stored = self._stored_arm(experiment_id, task_id, seed, arm)
        if stored is not None:
            return stored
        result = self.runner(
            candidate_artifact_id=artifact_id,
            parent_champion_id=parent_id,
            task_id=task_id,
            seed=seed,
            arm=arm,
            experiment_id=experiment_id,
        )
        if not isinstance(result, PromotionArmResult):
            raise TypeError("evolution promotion runner returned invalid arm evidence")
        self._append(
            "evolution_promotion_arm_completed",
            {
                "experiment_id": experiment_id,
                "candidate_artifact_id": artifact_id,
                "parent_champion_id": parent_id,
                "task_id": task_id,
                "seed": seed,
                "arm": arm,
                "quality": result.quality,
                "tokens": result.tokens,
                "usage_verified": result.usage_verified,
                "safety_violations": list(result.safety_violations),
            },
        )
        return result

    def _observation(
        self, experiment_id: str, task_id: str, seed: int
    ) -> PairedObservation | None:
        matches = [
            payload
            for event_type, payload in self._events()
            if event_type == "evolution_promotion_observation_recorded"
            and payload.get("experiment_id") == experiment_id
            and payload.get("task_id") == task_id
            and payload.get("seed") == seed
        ]
        if not matches:
            return None
        if len(matches) > 1 and any(
            canonical_json(item) != canonical_json(matches[0]) for item in matches[1:]
        ):
            raise RuntimeError("conflicting durable evolution paired observations")
        item = matches[0]
        numeric_names = (
            "candidate_quality",
            "champion_quality",
            "candidate_tokens",
            "champion_tokens",
        )
        if any(
            isinstance(item.get(name), bool) or not isinstance(item.get(name), (int, float))
            for name in numeric_names
        ):
            raise ValueError("durable evolution observation numeric evidence is invalid")
        candidate_quality = item["candidate_quality"]
        champion_quality = item["champion_quality"]
        candidate_tokens = item["candidate_tokens"]
        champion_tokens = item["champion_tokens"]
        if not isinstance(candidate_quality, (int, float)) or not isinstance(
            champion_quality, (int, float)
        ):
            raise AssertionError("validated quality evidence changed type")
        if not isinstance(candidate_tokens, int) or not isinstance(champion_tokens, int):
            raise AssertionError("validated token evidence changed type")
        for name in (
            "candidate_usage_verified",
            "champion_usage_verified",
            "safety_violation",
        ):
            if not isinstance(item.get(name), bool):
                raise ValueError("durable evolution observation boolean evidence is invalid")
        return PairedObservation(
            task_id,
            seed,
            float(candidate_quality),
            float(champion_quality),
            candidate_tokens,
            champion_tokens,
            bool(item["candidate_usage_verified"]),
            bool(item["champion_usage_verified"]),
            bool(item["safety_violation"]),
        )

    def _run_pair(
        self, artifact_id: str, parent_id: str | None, experiment_id: str, task_id: str, seed: int
    ) -> PairedObservation:
        stored = self._observation(experiment_id, task_id, seed)
        if stored is not None:
            return stored
        results: dict[str, PromotionArmResult] = {}
        order = ("candidate", "baseline") if (self.task_ids.index(task_id) + seed) % 2 == 0 else ("baseline", "candidate")
        for arm in order:
            results[arm] = self._run_arm(
                artifact_id=artifact_id,
                parent_id=parent_id,
                task_id=task_id,
                seed=seed,
                arm=arm,
                experiment_id=experiment_id,
            )
        candidate = results["candidate"]
        baseline = results["baseline"]
        observation = PairedObservation(
            task_id,
            seed,
            candidate.quality,
            baseline.quality,
            candidate.tokens,
            baseline.tokens,
            candidate.usage_verified,
            baseline.usage_verified,
            bool(candidate.safety_violations or baseline.safety_violations),
        )
        self._append(
            "evolution_promotion_observation_recorded",
            {
                "experiment_id": experiment_id,
                "candidate_artifact_id": artifact_id,
                "task_id": task_id,
                "seed": seed,
                "candidate_quality": observation.candidate_quality,
                "champion_quality": observation.champion_quality,
                "candidate_tokens": observation.candidate_tokens,
                "champion_tokens": observation.champion_tokens,
                "candidate_usage_verified": observation.candidate_usage_verified,
                "champion_usage_verified": observation.champion_usage_verified,
                "safety_violation": observation.safety_violation,
            },
        )
        return observation

    def _record_report(self, experiment_id: str, report: Mapping[str, object]) -> None:
        report_id = report["report_id"]
        if any(
            event_type == "evolution_promotion_funnel_recorded"
            and payload.get("experiment_id") == experiment_id
            and payload.get("report_id") == report_id
            for event_type, payload in self._events()
        ):
            return
        self._append(
            "evolution_promotion_funnel_recorded",
            {"experiment_id": experiment_id, "report_id": report_id, "report": report},
        )

    def run_pending(self) -> EvolutionPromotionSummary:
        candidates = self.registry.pending_candidates()
        promoted: list[str] = []
        rejected: list[str] = []
        pairs_added = 0
        for record in candidates:
            champion = self.registry.champion_archive()
            current_id = None if champion is None else champion.artifact_id
            current_version = 0 if champion is None else champion.version
            if record.parent_champion_id != current_id:
                self.registry.supersede(record.artifact_id, "candidate parent is no longer champion")
                rejected.append(record.artifact_id)
                continue
            experiment_id = self._experiment_id(record.artifact_id, current_id)
            if not any(
                event_type == "evolution_promotion_experiment_started"
                and payload.get("experiment_id") == experiment_id
                for event_type, payload in self._events()
            ):
                self._append(
                    "evolution_promotion_experiment_started",
                    {
                        "experiment_id": experiment_id,
                        "candidate_artifact_id": record.artifact_id,
                        "parent_champion_id": current_id,
                        "parent_promotion_version": current_version,
                        "task_ids": list(self.task_ids),
                        "seeds": [0, 1],
                        "smoke_pairs": [[self.task_ids[0], 0], [self.task_ids[1], 0]],
                    },
                )
            observations: dict[tuple[str, int], PairedObservation] = {}
            try:
                for task_id in self.task_ids[:2]:
                    existing = self._observation(experiment_id, task_id, 0)
                    if existing is None:
                        if not self.can_start_pair():
                            return EvolutionPromotionSummary(len(candidates), pairs_added, tuple(promoted), tuple(rejected), True)
                        existing = self._run_pair(record.artifact_id, current_id, experiment_id, task_id, 0)
                        pairs_added += 1
                    observations[(task_id, 0)] = existing
            except PromotionBudgetUnavailable:
                return EvolutionPromotionSummary(len(candidates), pairs_added, tuple(promoted), tuple(rejected), True)
            artifact = self.registry.candidate_artifact(record.artifact_id)
            validation = self.registry.validation(record.artifact_id)
            smoke = tuple(observations.values())
            token_evidence = VerifiedTokenEvidence.create(
                candidate_artifact_id=artifact.artifact_id,
                baseline_archive_sha256=artifact.baseline_archive_sha256,
                observations=tuple(observations.values()),
                usage_verified=all(row.candidate_usage_verified and row.champion_usage_verified for row in observations.values()),
                source_report_sha256=hashlib.sha256(
                    canonical_json(
                        {
                            "smoke_observations": [
                                [row.task_id, row.seed] for row in observations.values()
                            ]
                        }
                    ).encode()
                ).hexdigest(),
            )
            smoke_result = evaluate_evolution_candidate(artifact, validation, smoke, tuple(observations.values()), token_evidence)
            if smoke_result.report.stage is not FunnelStage.FULL_REJECTED:
                self._record_report(experiment_id, smoke_result.report.to_dict())
                self.registry.supersede(record.artifact_id, smoke_result.report.reason)
                rejected.append(record.artifact_id)
                continue
            if self.smoke_only:
                # Operator-authorized loop feasibility run: promote from the
                # bounded smoke design instead of waiting for the full 12x2.
                smoke_promotion = evaluate_smoke_only_candidate(
                    artifact,
                    validation,
                    tuple(observations.values()),
                    token_evidence,
                )
                self._record_report(experiment_id, smoke_promotion.report.to_dict())
                if smoke_promotion.promotion_evidence is None:
                    self.registry.supersede(record.artifact_id, smoke_promotion.report.reason)
                    rejected.append(record.artifact_id)
                    continue
                try:
                    self.registry.promote_if_current(
                        record.artifact_id,
                        smoke_promotion.promotion_evidence,
                        expected_champion_id=current_id,
                        expected_promotion_version=current_version,
                    )
                except EvolutionRegistryError:
                    self.registry.supersede(record.artifact_id, "champion changed before promotion")
                    rejected.append(record.artifact_id)
                    continue
                self._append(
                    "evolution_candidate_promoted",
                    {"experiment_id": experiment_id, "candidate_artifact_id": record.artifact_id},
                )
                promoted.append(record.artifact_id)
                continue
            try:
                for task_id in self.task_ids:
                    for seed in (0, 1):
                        key = (task_id, seed)
                        existing = observations.get(key) or self._observation(experiment_id, task_id, seed)
                        if existing is None:
                            if not self.can_start_pair():
                                return EvolutionPromotionSummary(len(candidates), pairs_added, tuple(promoted), tuple(rejected), True)
                            existing = self._run_pair(record.artifact_id, current_id, experiment_id, task_id, seed)
                            pairs_added += 1
                        observations[key] = existing
            except PromotionBudgetUnavailable:
                return EvolutionPromotionSummary(len(candidates), pairs_added, tuple(promoted), tuple(rejected), True)
            full = tuple(observations[key] for key in sorted(observations))
            token_evidence = VerifiedTokenEvidence.create(
                candidate_artifact_id=artifact.artifact_id,
                baseline_archive_sha256=artifact.baseline_archive_sha256,
                observations=full,
                usage_verified=all(row.candidate_usage_verified and row.champion_usage_verified for row in full),
                source_report_sha256=hashlib.sha256(
                    canonical_json(
                        {
                            "full_observations": [
                                [
                                    row.task_id,
                                    row.seed,
                                    row.candidate_tokens,
                                    row.champion_tokens,
                                ]
                                for row in full
                            ]
                        }
                    ).encode()
                ).hexdigest(),
            )
            result = evaluate_evolution_candidate(artifact, validation, smoke, full, token_evidence)
            self._record_report(experiment_id, result.report.to_dict())
            if result.promotion_evidence is None:
                self.registry.supersede(record.artifact_id, result.report.reason)
                rejected.append(record.artifact_id)
                continue
            try:
                self.registry.promote_if_current(
                    record.artifact_id,
                    result.promotion_evidence,
                    expected_champion_id=current_id,
                    expected_promotion_version=current_version,
                )
            except EvolutionRegistryError:
                self.registry.supersede(record.artifact_id, "champion changed before promotion")
                rejected.append(record.artifact_id)
                continue
            self._append(
                "evolution_candidate_promoted",
                {"experiment_id": experiment_id, "candidate_artifact_id": record.artifact_id},
            )
            promoted.append(record.artifact_id)
        return EvolutionPromotionSummary(len(candidates), pairs_added, tuple(promoted), tuple(rejected))
