from __future__ import annotations

import unittest

from aegis.models import CampaignState
from aegis.state_machine import (
    CampaignStateMachine,
    InvalidTransitionError,
    available_actions,
    transition,
)


class StateMachineTests(unittest.TestCase):
    def test_complete_lifecycle_and_next_round_branch(self) -> None:
        machine = CampaignStateMachine()
        self.assertEqual(machine.apply("start"), CampaignState.PREPARING)
        for expected in (
            CampaignState.WARRIOR_RESEARCH,
            CampaignState.WARRIOR_EXECUTE,
            CampaignState.FROZEN,
            CampaignState.JUDGE_EVALUATE,
            CampaignState.QUALITY_LOCKED,
            CampaignState.PROSECUTOR_AUDIT,
            CampaignState.PROMOTION_GATE,
        ):
            self.assertEqual(machine.apply("advance"), expected)
        self.assertEqual(machine.apply("next_round"), CampaignState.NEXT_ROUND)
        self.assertEqual(machine.apply("advance"), CampaignState.WARRIOR_RESEARCH)

    def test_pause_records_exact_resume_target(self) -> None:
        machine = CampaignStateMachine(CampaignState.JUDGE_EVALUATE)
        self.assertEqual(machine.apply("pause"), CampaignState.PAUSED)
        self.assertEqual(machine.resume_target, CampaignState.JUDGE_EVALUATE)
        self.assertEqual(machine.apply("resume"), CampaignState.JUDGE_EVALUATE)
        self.assertIsNone(machine.resume_target)
        with self.assertRaises(ValueError):
            CampaignStateMachine(CampaignState.PAUSED)

    def test_stop_abort_fail_and_terminal_states(self) -> None:
        machine = CampaignStateMachine(CampaignState.WARRIOR_EXECUTE)
        self.assertEqual(machine.apply("stop"), CampaignState.STOPPING)
        self.assertEqual(machine.apply("abort"), CampaignState.ABORTED)
        self.assertEqual(available_actions(CampaignState.ABORTED), ())
        with self.assertRaises(InvalidTransitionError):
            machine.apply("start")
        self.assertEqual(transition(CampaignState.QUALITY_LOCKED, "fail"), CampaignState.FAILED)

    def test_pure_resume_requires_valid_target(self) -> None:
        with self.assertRaises(InvalidTransitionError):
            transition(CampaignState.PAUSED, "resume")
        self.assertEqual(
            transition(CampaignState.PAUSED, "resume", resume_target=CampaignState.FROZEN),
            CampaignState.FROZEN,
        )


if __name__ == "__main__":
    unittest.main()
