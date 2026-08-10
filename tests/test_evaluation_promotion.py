from __future__ import annotations

import unittest

from aegis.evaluation.promotion import PairedObservation, PromotionPolicy, decide_promotion
from aegis.evaluation.scoring import EvaluationEvidence, TamperEvidence, detect_tampering, score_quality


def rows(*, candidate_quality=0.9, champion_quality=0.8, candidate_tokens=100, champion_tokens=100, **kwargs):
    return [
        PairedObservation(
            f"task-{task:02d}",
            seed,
            candidate_quality,
            champion_quality,
            candidate_tokens,
            champion_tokens,
            **kwargs,
        )
        for task in range(12)
        for seed in range(2)
    ]


class ScoringTests(unittest.TestCase):
    def test_quality_score_is_deterministic(self) -> None:
        evidence = EvaluationEvidence(8, 10, 9, 10, 3, 4, True)
        first = score_quality(evidence)
        second = score_quality(evidence)
        self.assertEqual(first, second)
        self.assertAlmostEqual(first.score, 0.80 * (0.25 * 0.8 + 0.75 * 0.9) + 0.15 * 0.75 + 0.05)
        self.assertTrue(first.accepted)

    def test_tamper_or_safety_violation_is_non_compensable(self) -> None:
        tamper = TamperEvidence("a", "b", ("hidden/test_secret.py",))
        reasons = detect_tampering(tamper)
        self.assertEqual(len(reasons), 2)
        result = score_quality(EvaluationEvidence(10, 10, 10, 10, 4, 4, True, ("network",), tamper))
        self.assertFalse(result.accepted)
        self.assertEqual(result.score, 0)
        self.assertEqual(len(result.reasons), 3)

    def test_invalid_counts_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            score_quality(EvaluationEvidence(2, 1, 1, 1, 1, 1, True))


class PromotionTests(unittest.TestCase):
    policy = PromotionPolicy(bootstrap_samples=1000)

    def test_quality_improvement_promotes_with_fixed_seed(self) -> None:
        observations = rows(
            candidate_quality=0.86, champion_quality=0.80, candidate_tokens=110, champion_tokens=100
        )
        first = decide_promotion(observations, self.policy)
        second = decide_promotion(reversed(observations), self.policy)
        self.assertTrue(first.promoted)
        self.assertEqual(first, second)
        self.assertGreater(first.quality_lower_bound, 0.02)
        self.assertLessEqual(first.token_change, 0.10)

    def test_noninferior_token_saving_promotes(self) -> None:
        decision = decide_promotion(
            rows(candidate_quality=0.795, champion_quality=0.80, candidate_tokens=80, champion_tokens=100),
            self.policy,
        )
        self.assertTrue(decision.promoted)
        self.assertGreaterEqual(decision.quality_lower_bound, -0.01)
        self.assertGreaterEqual(decision.token_saving_lower_bound, 0.10)

    def test_safety_and_unverified_usage_reject(self) -> None:
        unsafe = decide_promotion(rows(safety_violation=True), self.policy)
        self.assertFalse(unsafe.promoted)
        self.assertIn("safety", unsafe.reason)
        unverified = decide_promotion(rows(candidate_usage_verified=False), self.policy)
        self.assertFalse(unverified.promoted)
        self.assertIn("verified", unverified.reason)

    def test_incomplete_or_duplicate_design_rejects(self) -> None:
        incomplete = rows()[:-1]
        self.assertFalse(decide_promotion(incomplete, self.policy).promoted)
        duplicate = rows()
        duplicate[-1] = duplicate[0]
        decision = decide_promotion(duplicate, self.policy)
        self.assertFalse(decision.promoted)
        self.assertIn("duplicate", decision.reason)

    def test_inconsistent_seed_sets_reject(self) -> None:
        observations = rows()
        observations[-1] = PairedObservation("task-11", 9, 0.9, 0.8, 100, 100)
        decision = decide_promotion(observations, self.policy)
        self.assertFalse(decision.promoted)
        self.assertIn("same seed", decision.reason)

    def test_quality_win_rejects_token_increase_above_ten_percent(self) -> None:
        decision = decide_promotion(
            rows(candidate_quality=0.9, champion_quality=0.8, candidate_tokens=111, champion_tokens=100),
            self.policy,
        )
        self.assertFalse(decision.promoted)

    def test_correlated_seed_duplicates_do_not_inflate_bootstrap_sample_size(self) -> None:
        paired: list[PairedObservation] = []
        single: list[PairedObservation] = []
        for task in range(12):
            delta = 0.08 if task < 6 else -0.02
            for seed in range(2):
                paired.append(PairedObservation(f"task-{task:02d}", seed, 0.8 + delta, 0.8, 90, 100))
            single.append(PairedObservation(f"task-{task:02d}", 0, 0.8 + delta, 0.8, 90, 100))
        paired_result = decide_promotion(paired, PromotionPolicy(bootstrap_samples=2000))
        single_result = decide_promotion(
            single,
            PromotionPolicy(seeds_per_task=1, bootstrap_samples=2000),
        )
        self.assertEqual(paired_result.quality_lower_bound, single_result.quality_lower_bound)
        self.assertEqual(paired_result.token_saving_lower_bound, single_result.token_saving_lower_bound)


if __name__ == "__main__":
    unittest.main()
