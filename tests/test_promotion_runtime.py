import tempfile
import unittest
from pathlib import Path

from aegis.event_store import EventStore
from aegis.models import Role
from aegis.promotion_runtime import (
    PromotionArmResult,
    PromotionBudgetUnavailable,
    StrategyPromotionScheduler,
)
from aegis.strategy import StrategyContent, StrategyProposal, StrategyRegistry


class PromotionRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = EventStore(Path(self.temp.name) / "events.db")
        self.registry = StrategyRegistry(self.store, "campaign")
        self.registry.initialize_defaults()
        proposal = StrategyProposal(
            "candidate-1",
            Role.WARRIOR,
            StrategyContent(role_guidance=("Prefer small verified edits.",)),
            "reduce avoidable changes",
        )
        self.candidate = self.registry.submit_payload(
            Role.WARRIOR,
            {
                "strategy_proposals": [
                    {
                        "proposal_id": proposal.proposal_id,
                        "target_role": proposal.target_role.value,
                        "content": proposal.content.to_dict(),
                        "rationale": proposal.rationale,
                    }
                ]
            },
        )[0]
        self.tasks = tuple(f"task-{index}" for index in range(12))

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def test_runs_real_independent_arms_and_promotes_after_24_pairs(self):
        calls = []

        def runner(**kwargs):
            calls.append(kwargs)
            candidate = kwargs["arm"] == "candidate"
            return PromotionArmResult(0.9 if candidate else 0.8, 90 if candidate else 100, True)

        summary = StrategyPromotionScheduler(self.registry, self.tasks, runner).run_pending()
        self.assertEqual(summary.pairs_added, 24)
        self.assertEqual(len(calls), 48)
        self.assertEqual(len({(item["task_id"], item["seed"]) for item in calls}), 24)
        self.assertEqual({item["arm"] for item in calls}, {"candidate", "champion"})
        self.assertTrue(summary.decisions[0].promoted)
        self.assertEqual(self.registry.champion(Role.WARRIOR).version_id, self.candidate.version_id)

    def test_budget_stop_keeps_candidate_and_partial_experiment_pending(self):
        calls = 0

        def runner(**kwargs):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise PromotionBudgetUnavailable("budget")
            return PromotionArmResult(0.8, 100, True)

        summary = StrategyPromotionScheduler(self.registry, self.tasks, runner).run_pending()
        self.assertTrue(summary.pending_for_budget)
        self.assertEqual(summary.pairs_added, 1)
        experiment = self.registry.experiment_for_candidate(self.candidate.version_id)
        self.assertIsNotNone(experiment)
        self.assertEqual(len(experiment.snapshot.observations), 1)
        self.assertEqual(experiment.snapshot.state, "pending")
        self.assertEqual(self.registry.champion(Role.WARRIOR).version, 1)

    def test_resume_skips_durable_pairs(self):
        first_calls = 0

        def first(**kwargs):
            nonlocal first_calls
            first_calls += 1
            if first_calls == 5:
                raise PromotionBudgetUnavailable("budget")
            return PromotionArmResult(0.85, 100, True)

        first_summary = StrategyPromotionScheduler(self.registry, self.tasks, first).run_pending()
        self.assertEqual(first_summary.pairs_added, 2)
        resumed_calls = []

        def resumed(**kwargs):
            resumed_calls.append(kwargs)
            return PromotionArmResult(0.85, 100, True)

        second = StrategyPromotionScheduler(self.registry, self.tasks, resumed).run_pending()
        self.assertEqual(second.pairs_added, 22)
        self.assertEqual(len(resumed_calls), 44)
        self.assertFalse(any(item["task_id"] == "task-0" for item in resumed_calls))

    def test_candidate_safety_violation_hard_rejects(self):
        def runner(**kwargs):
            return PromotionArmResult(0.95, 100, True, ("tamper",) if kwargs["arm"] == "candidate" else ())

        summary = StrategyPromotionScheduler(self.registry, self.tasks, runner).run_pending()
        self.assertFalse(summary.decisions[0].promoted)
        self.assertEqual(summary.decisions[0].reason, "safety violation in paired arm")

    def test_champion_arm_safety_violation_also_invalidates_pair(self):
        def runner(**kwargs):
            return PromotionArmResult(
                0.9, 100, True, ("unsafe evaluation",) if kwargs["arm"] == "champion" else ()
            )

        summary = StrategyPromotionScheduler(self.registry, self.tasks, runner).run_pending()
        self.assertFalse(summary.decisions[0].promoted)
        self.assertEqual(summary.decisions[0].reason, "safety violation in paired arm")

    def test_later_candidate_against_replaced_parent_is_durably_superseded(self):
        second = self.registry.submit_payload(
            Role.WARRIOR,
            {
                "strategy_proposals": [
                    {
                        "proposal_id": "candidate-2",
                        "target_role": "warrior",
                        "content": {
                            "role_guidance": ["Prefer explicit invariants."],
                            "prompt_fragments": [],
                            "tool_preferences": [],
                            "max_steps": None,
                        },
                        "rationale": "make checks explicit",
                    }
                ]
            },
        )[0]

        def runner(**kwargs):
            return PromotionArmResult(
                0.9 if kwargs["arm"] == "candidate" else 0.8,
                90 if kwargs["arm"] == "candidate" else 100,
                True,
            )

        StrategyPromotionScheduler(self.registry, self.tasks, runner).run_pending()
        self.assertEqual(self.registry.candidate_state(second.version_id), "rejected")
        reopened = StrategyRegistry(self.store, "campaign")
        self.assertEqual(reopened.candidate_state(second.version_id), "rejected")


if __name__ == "__main__":
    unittest.main()
