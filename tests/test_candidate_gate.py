from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError

from aegis.attribution import (
    CandidateGateDisposition,
    CandidateGatePolicy,
    SealedCandidateArm,
    SealedCandidatePair,
    evaluate_candidate_gate,
)


def arm(
    *,
    overall: float = 0.7,
    fresh: float | None = 0.6,
    regression: float | None = 0.8,
    cost: int = 100,
    integrity: bool = True,
) -> SealedCandidateArm:
    return SealedCandidateArm(overall, fresh, regression, cost, integrity)


def pair(
    seed: int,
    *,
    fresh_delta: float = 0.03,
    regression_delta: float = -0.005,
    candidate_cost: int = 110,
    baseline_fresh: float | None = 0.6,
    candidate_fresh: float | None = None,
    baseline_regression: float | None = 0.8,
    candidate_regression: float | None = None,
    candidate_integrity: bool = True,
) -> SealedCandidatePair:
    resolved_candidate_fresh = (
        None
        if baseline_fresh is None
        else baseline_fresh + fresh_delta
        if candidate_fresh is None
        else candidate_fresh
    )
    resolved_candidate_regression = (
        None
        if baseline_regression is None
        else baseline_regression + regression_delta
        if candidate_regression is None
        else candidate_regression
    )
    return SealedCandidatePair(
        seed,
        arm(fresh=baseline_fresh, regression=baseline_regression),
        arm(
            overall=0.73,
            fresh=resolved_candidate_fresh,
            regression=resolved_candidate_regression,
            cost=candidate_cost,
            integrity=candidate_integrity,
        ),
    )


class CandidateGateTests(unittest.TestCase):
    def test_two_seeds_must_each_pass_all_quality_gates(self) -> None:
        report = evaluate_candidate_gate((pair(11), pair(22)))

        self.assertTrue(report.qualified)
        self.assertEqual(report.disposition, CandidateGateDisposition.QUALIFIED)
        self.assertAlmostEqual(report.total_cost_change or 0.0, 0.10)
        self.assertEqual(tuple(item.seed for item in report.seed_results), (11, 22))
        self.assertTrue(report.report_id.startswith("candidate-gate-report-sha256:"))
        self.assertEqual(type(report).from_mapping(report.to_mapping()), report)
        with self.assertRaises(FrozenInstanceError):
            report.reason = "tampered"  # type: ignore[misc]
        tampered = report.to_mapping()
        tampered["total_cost_change"] = 0.0
        with self.assertRaisesRegex(ValueError, "does not match"):
            type(report).from_mapping(tampered)

    def test_missing_or_duplicate_seed_evidence_fails_design(self) -> None:
        missing = evaluate_candidate_gate((pair(11),))
        duplicate = evaluate_candidate_gate((pair(11), pair(11)))

        self.assertEqual(missing.disposition, CandidateGateDisposition.INVALID_DESIGN)
        self.assertEqual(duplicate.disposition, CandidateGateDisposition.INVALID_DESIGN)

    def test_no_fresh_evidence_is_an_explicit_rejection(self) -> None:
        report = evaluate_candidate_gate(
            (pair(11, baseline_fresh=None), pair(22, baseline_fresh=None))
        )

        self.assertEqual(report.disposition, CandidateGateDisposition.NO_FRESH_EVIDENCE)

    def test_integrity_is_a_non_compensable_hard_gate(self) -> None:
        report = evaluate_candidate_gate(
            (
                pair(11, fresh_delta=0.3, candidate_integrity=False),
                pair(22, fresh_delta=0.3),
            )
        )

        self.assertEqual(report.disposition, CandidateGateDisposition.INTEGRITY_REJECTED)

    def test_fresh_threshold_applies_to_every_seed(self) -> None:
        report = evaluate_candidate_gate((pair(11), pair(22, fresh_delta=0.019)))

        self.assertEqual(report.disposition, CandidateGateDisposition.FRESH_REJECTED)
        self.assertIn("22", report.reason)

    def test_regression_noninferiority_applies_to_every_seed(self) -> None:
        report = evaluate_candidate_gate(
            (pair(11), pair(22, regression_delta=-0.011))
        )

        self.assertEqual(report.disposition, CandidateGateDisposition.REGRESSION_REJECTED)

    def test_total_cost_is_aggregated_across_both_seeds(self) -> None:
        passing = evaluate_candidate_gate(
            (pair(11, candidate_cost=120), pair(22, candidate_cost=100))
        )
        observed = evaluate_candidate_gate(
            (pair(11, candidate_cost=121), pair(22, candidate_cost=100))
        )
        failing = evaluate_candidate_gate(
            (pair(11, candidate_cost=121), pair(22, candidate_cost=100)),
            CandidateGatePolicy(enforce_cost_limit=True),
        )

        self.assertTrue(passing.qualified)
        self.assertTrue(observed.qualified)
        self.assertGreater(observed.total_cost_change or 0.0, 0.10)
        self.assertEqual(failing.disposition, CandidateGateDisposition.COST_REJECTED)
        self.assertAlmostEqual(failing.total_cost_change or 0.0, 0.105)

    def test_missing_regression_group_and_zero_baseline_cost_fail_closed(self) -> None:
        missing_regression = evaluate_candidate_gate(
            (
                pair(11, baseline_regression=None),
                pair(22, baseline_regression=None),
            )
        )
        zero_cost = evaluate_candidate_gate(
            (
                SealedCandidatePair(11, arm(cost=0), arm(cost=0, fresh=0.63, regression=0.8)),
                SealedCandidatePair(22, arm(cost=0), arm(cost=0, fresh=0.63, regression=0.8)),
            )
        )

        self.assertEqual(missing_regression.disposition, CandidateGateDisposition.INVALID_DESIGN)
        self.assertTrue(zero_cost.qualified)
        self.assertIsNone(zero_cost.total_cost_change)

    def test_policy_is_explicit_and_reordering_is_replay_stable(self) -> None:
        first = pair(11, fresh_delta=0.015)
        second = pair(22, fresh_delta=0.015)
        policy = CandidateGatePolicy(fresh_improvement=0.01)

        forward = evaluate_candidate_gate((first, second), policy)
        reverse = evaluate_candidate_gate((second, first), policy)

        self.assertEqual(forward, reverse)
        self.assertTrue(forward.qualified)


if __name__ == "__main__":
    unittest.main()
