"""Paired bootstrap promotion gate with fixed-seed reproducibility."""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from statistics import fmean
from typing import Iterable, Sequence


@dataclass(frozen=True, slots=True)
class PairedObservation:
    task_id: str
    seed: int
    candidate_quality: float
    champion_quality: float
    candidate_tokens: int
    champion_tokens: int
    candidate_usage_verified: bool = True
    champion_usage_verified: bool = True
    safety_violation: bool = False

    def __post_init__(self) -> None:
        if not 0 <= self.candidate_quality <= 1 or not 0 <= self.champion_quality <= 1:
            raise ValueError("quality must be in [0,1]")
        if self.candidate_tokens < 0 or self.champion_tokens <= 0:
            raise ValueError("token counts are invalid")


@dataclass(frozen=True, slots=True)
class PromotionPolicy:
    required_tasks: int = 12
    seeds_per_task: int = 2
    bootstrap_samples: int = 10_000
    bootstrap_seed: int = 0xAE615
    confidence: float = 0.95
    quality_improvement: float = 0.02
    max_token_increase: float = 0.10
    noninferiority_margin: float = -0.01
    token_saving: float = 0.10


@dataclass(frozen=True, slots=True)
class PromotionDecision:
    promoted: bool
    reason: str
    quality_delta: float
    quality_lower_bound: float
    token_change: float
    token_saving_lower_bound: float
    pairs: int


def _percentile(samples: Sequence[float], probability: float) -> float:
    if not samples:
        raise ValueError("samples must not be empty")
    ordered = sorted(samples)
    position = probability * (len(ordered) - 1)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def _validate_design(rows: Sequence[PairedObservation], policy: PromotionPolicy) -> str | None:
    expected_pairs = policy.required_tasks * policy.seeds_per_task
    if len(rows) != expected_pairs:
        return f"requires exactly {expected_pairs} paired observations"
    keys = {(row.task_id, row.seed) for row in rows}
    if len(keys) != len(rows):
        return "paired observations contain duplicate task/seed keys"
    tasks: dict[str, set[int]] = {}
    for row in rows:
        tasks.setdefault(row.task_id, set()).add(row.seed)
    if len(tasks) != policy.required_tasks or any(
        len(seeds) != policy.seeds_per_task for seeds in tasks.values()
    ):
        return f"requires {policy.required_tasks} tasks with {policy.seeds_per_task} seeds each"
    seed_sets = {frozenset(seeds) for seeds in tasks.values()}
    if len(seed_sets) != 1:
        return "every task must use the same seed set"
    return None


def decide_promotion(
    observations: Iterable[PairedObservation], policy: PromotionPolicy | None = None
) -> PromotionDecision:
    policy = policy or PromotionPolicy()
    rows = tuple(sorted(observations, key=lambda row: (row.task_id, row.seed)))
    invalid = _validate_design(rows, policy)
    if invalid:
        return PromotionDecision(False, invalid, 0.0, 0.0, 0.0, 0.0, len(rows))
    if any(row.safety_violation for row in rows):
        return PromotionDecision(False, "safety violation in paired arm", 0.0, 0.0, 0.0, 0.0, len(rows))
    if any(not row.candidate_usage_verified or not row.champion_usage_verified for row in rows):
        return PromotionDecision(False, "verified token usage is required", 0.0, 0.0, 0.0, 0.0, len(rows))
    # Seeds are repeated measurements within a task, not independent tasks.
    # Aggregate within each task and bootstrap task clusters so duplicated or
    # highly correlated seeds cannot manufacture a narrower confidence bound.
    by_task: dict[str, list[PairedObservation]] = {}
    for row in rows:
        by_task.setdefault(row.task_id, []).append(row)
    task_deltas = [
        fmean(item.candidate_quality - item.champion_quality for item in task_rows)
        for task_rows in by_task.values()
    ]
    task_savings = [
        1.0
        - sum(item.candidate_tokens for item in task_rows) / sum(item.champion_tokens for item in task_rows)
        for task_rows in by_task.values()
    ]
    quality_delta = fmean(task_deltas)
    candidate_total = sum(row.candidate_tokens for row in rows)
    champion_total = sum(row.champion_tokens for row in rows)
    token_change = round(candidate_total / champion_total - 1.0, 12)
    rng = random.Random(policy.bootstrap_seed)
    boot_quality: list[float] = []
    boot_saving: list[float] = []
    size = len(task_deltas)
    for _ in range(policy.bootstrap_samples):
        indices = [rng.randrange(size) for _ in range(size)]
        boot_quality.append(fmean(task_deltas[index] for index in indices))
        boot_saving.append(fmean(task_savings[index] for index in indices))
    alpha = (1.0 - policy.confidence) / 2.0
    quality_lower = _percentile(boot_quality, alpha)
    saving_lower = _percentile(boot_saving, alpha)
    quality_win = quality_lower > policy.quality_improvement and candidate_total <= champion_total * (
        1.0 + policy.max_token_increase
    )
    efficiency_win = quality_lower >= policy.noninferiority_margin and saving_lower >= policy.token_saving
    if quality_win:
        reason = "quality improvement gate passed"
    elif efficiency_win:
        reason = "token-efficiency noninferiority gate passed"
    else:
        reason = "candidate did not meet a promotion gate"
    return PromotionDecision(
        quality_win or efficiency_win,
        reason,
        quality_delta,
        quality_lower,
        token_change,
        saving_lower,
        len(rows),
    )
