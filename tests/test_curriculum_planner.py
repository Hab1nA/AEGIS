from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError

from aegis.curriculum import (
    CapabilityGap,
    CurriculumHypothesis,
    CurriculumPlan,
    CurriculumPlanner,
    CurriculumPlanningError,
    TaskCapabilityProfile,
)


def gap(
    capability: str,
    *,
    evidence_cycle: int = 4,
    priority: float = 0.5,
    uncertainty: float = 0.4,
    failures: int = 0,
    last_targeted_cycle: int | None = 3,
) -> CapabilityGap:
    return CapabilityGap(
        capability=capability,
        evidence_cycle=evidence_cycle,
        evidence_ids=(f"evidence:{capability}",),
        counter_evidence_ids=(f"counter:{capability}",),
        severity=0.7,
        expected_gain=0.1,
        estimated_cost_units=10,
        stop_conditions=(f"Stop when {capability} reaches its quality threshold.",),
        priority=priority,
        uncertainty=uncertainty,
        consecutive_failures=failures,
        last_targeted_cycle=last_targeted_cycle,
    )


def profile(
    task_id: str,
    capability: str,
    *,
    evidence_cycle: int = 4,
    available_since_cycle: int = 4,
    difficulty: int = 3,
    hall_of_fame_age: int | None = None,
    lagged_holdout: bool = False,
    exploration: bool = False,
    cost: int = 10,
    last_selected_cycle: int | None = 4,
) -> TaskCapabilityProfile:
    return TaskCapabilityProfile(
        task_id=task_id,
        evidence_cycle=evidence_cycle,
        available_since_cycle=available_since_cycle,
        capabilities=(capability,),
        difficulty=difficulty,
        hall_of_fame_age=hall_of_fame_age,
        lagged_holdout=lagged_holdout,
        exploration=exploration,
        estimated_cost_units=cost,
        last_selected_cycle=last_selected_cycle,
    )


class CurriculumPlannerModelTests(unittest.TestCase):
    def test_all_structured_artifacts_are_immutable_content_addressed_and_round_trip(self) -> None:
        source_gap = gap("debugging")
        hypothesis = CurriculumHypothesis(
            gap_id=source_gap.gap_id,
            evidence_ids=source_gap.evidence_ids,
            counter_evidence_ids=source_gap.counter_evidence_ids,
            target_capabilities=("debugging",),
            task_attributes=("difficulty:adaptive", "source:dynamic"),
            expected_gain=0.1,
            estimated_cost_units=10,
            stop_conditions=source_gap.stop_conditions,
            priority=0.5,
            uncertainty=0.4,
        )
        task = profile("dynamic-task-a", "debugging", exploration=True)
        plan = CurriculumPlan(
            target_cycle=5,
            evidence_cutoff_cycle=4,
            source_gap_ids=(source_gap.gap_id,),
            source_profile_ids=(task.profile_id,),
            hypotheses=(hypothesis,),
            cohort=(task,),
            cohort_strata=("debugging|difficulty:3|hof-age:fresh|training",),
            exploration_quota=1,
            total_cost_units=10,
            max_total_cost_units=10,
            stop_conditions=source_gap.stop_conditions,
        )

        self.assertEqual(CapabilityGap.from_mapping(source_gap.to_mapping()), source_gap)
        self.assertEqual(CurriculumHypothesis.from_mapping(hypothesis.to_mapping()), hypothesis)
        self.assertEqual(TaskCapabilityProfile.from_mapping(task.to_mapping()), task)
        self.assertEqual(CurriculumPlan.from_mapping(plan.to_mapping()), plan)
        self.assertTrue(plan.plan_id.startswith("curriculum-plan-sha256:"))
        with self.assertRaises(FrozenInstanceError):
            task.difficulty = 9  # type: ignore[misc]

        tampered = plan.to_mapping()
        tampered["total_cost_units"] = 9
        with self.assertRaises(ValueError):
            CurriculumPlan.from_mapping(tampered)


class CurriculumPlannerTests(unittest.TestCase):
    def test_plan_meets_exploration_cost_and_multiaxis_stratification(self) -> None:
        planner = CurriculumPlanner(
            cohort_size=4,
            max_total_cost_units=45,
            exploration_quota=2,
            starvation_window=4,
        )
        gaps = (gap("debugging", priority=0.8), gap("testing", priority=0.6))
        profiles = (
            profile(
                "dynamic-debug-fresh",
                "debugging",
                difficulty=2,
                exploration=True,
                cost=9,
            ),
            profile(
                "dynamic-debug-hof",
                "debugging",
                difficulty=5,
                hall_of_fame_age=3,
                cost=11,
            ),
            profile(
                "dynamic-test-lagged",
                "testing",
                difficulty=4,
                lagged_holdout=True,
                exploration=True,
                cost=10,
            ),
            profile(
                "dynamic-test-hof",
                "testing",
                difficulty=7,
                hall_of_fame_age=8,
                cost=12,
            ),
            profile("dynamic-spare", "debugging", difficulty=2, cost=20),
        )

        first = planner.plan(5, gaps, profiles)
        second = planner.plan(5, tuple(gaps), tuple(profiles))
        self.assertEqual(first, second)
        self.assertEqual(len(first.cohort), 4)
        self.assertGreaterEqual(sum(item.exploration for item in first.cohort), 2)
        self.assertLessEqual(first.total_cost_units, 45)
        self.assertEqual(len(set(first.cohort_strata)), 4)
        self.assertTrue(any("|lagged" in value for value in first.cohort_strata))
        self.assertTrue(any("hof-age:8" in value for value in first.cohort_strata))
        self.assertEqual(first.evidence_cutoff_cycle, 4)
        self.assertEqual(
            first.source_profile_ids, tuple(sorted(item.profile_id for item in profiles))
        )

    def test_anti_starvation_task_is_mandatory_even_with_low_gap_score(self) -> None:
        planner = CurriculumPlanner(
            cohort_size=2,
            max_total_cost_units=20,
            exploration_quota=0,
            starvation_window=3,
        )
        gaps = (gap("debugging", priority=0.9), gap("documentation", priority=0.01))
        starved = profile(
            "dynamic-starved",
            "documentation",
            available_since_cycle=1,
            last_selected_cycle=1,
            cost=10,
        )
        profiles = (
            profile("dynamic-high-a", "debugging", cost=10),
            profile("dynamic-high-b", "debugging", difficulty=4, cost=10),
            starved,
        )
        plan = planner.plan(5, gaps, profiles)
        self.assertIn(starved, plan.cohort)

    def test_repeated_failure_weight_is_capped(self) -> None:
        planner = CurriculumPlanner(
            cohort_size=1,
            max_total_cost_units=10,
            exploration_quota=0,
            starvation_window=10,
            repeated_failure_weight_cap=2,
        )
        profiles = (
            profile("dynamic-debug", "debugging"),
            profile("dynamic-test", "testing"),
        )
        capped = planner.plan(
            5,
            (gap("debugging", priority=0.2, failures=2), gap("testing", priority=0.1)),
            profiles,
        )
        extreme = planner.plan(
            5,
            (gap("debugging", priority=0.2, failures=100), gap("testing", priority=0.1)),
            profiles,
        )
        self.assertEqual(capped.cohort, extreme.cohort)
        capped_priority = next(
            item.priority
            for item in capped.hypotheses
            if item.target_capabilities == ("debugging",)
        )
        extreme_priority = next(
            item.priority
            for item in extreme.hypotheses
            if item.target_capabilities == ("debugging",)
        )
        self.assertEqual(capped_priority, extreme_priority)

    def test_current_and_future_evidence_are_rejected(self) -> None:
        planner = CurriculumPlanner(1, 10, 0, 3)
        with self.assertRaisesRegex(CurriculumPlanningError, "current or future"):
            planner.plan(5, (gap("debugging", evidence_cycle=5),), (profile("task", "debugging"),))
        with self.assertRaisesRegex(CurriculumPlanningError, "current or future"):
            planner.plan(
                5,
                (gap("debugging"),),
                (profile("task", "debugging", evidence_cycle=6),),
            )

    def test_infeasible_exploration_starvation_or_cost_fails_closed(self) -> None:
        tasks = (
            profile(
                "dynamic-old-a",
                "debugging",
                available_since_cycle=1,
                last_selected_cycle=1,
                cost=6,
            ),
            profile(
                "dynamic-old-b",
                "debugging",
                available_since_cycle=1,
                last_selected_cycle=1,
                cost=6,
            ),
        )
        with self.assertRaisesRegex(CurriculumPlanningError, "anti-starvation"):
            CurriculumPlanner(1, 20, 0, 3).plan(5, (gap("debugging"),), tasks)
        with self.assertRaisesRegex(CurriculumPlanningError, "exploration"):
            CurriculumPlanner(1, 20, 1, 10).plan(5, (gap("debugging"),), tasks)
        with self.assertRaisesRegex(CurriculumPlanningError, "total cost"):
            CurriculumPlanner(2, 10, 0, 10).plan(5, (gap("debugging"),), tasks)


if __name__ == "__main__":
    unittest.main()
