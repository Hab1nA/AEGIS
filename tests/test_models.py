from __future__ import annotations

import math
import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone

from aegis.models import (
    AuditEvent,
    BudgetLimit,
    CampaignState,
    EvaluationResult,
    ImprovementProposal,
    PromotionDecision,
    Role,
    TaskBundle,
    UsageRecord,
    canonical_json,
)


class ModelTests(unittest.TestCase):
    def test_lifecycle_and_roles_are_stable_string_enums(self) -> None:
        self.assertEqual(Role.WARRIOR.value, "warrior")
        self.assertEqual(CampaignState.WARRIOR_EXECUTE.value, "warrior_execute")
        self.assertTrue(CampaignState.COMPLETED.terminal)
        self.assertFalse(CampaignState.PAUSED.terminal)

    def test_budget_and_usage_are_strict(self) -> None:
        limit = BudgetLimit(10, 10, 5, 5, 2, 3.5)
        usage = UsageRecord("c1", 2, 3, 1, 1, 1, 0.25, verified=False)
        self.assertEqual(limit.requests, 2)
        self.assertEqual(usage.total_tokens, 5)
        self.assertFalse(usage.verified)
        with self.assertRaises(TypeError):
            BudgetLimit(True, 1, 0, 0, 1, 1)
        with self.assertRaises(ValueError):
            UsageRecord("c1", wall_time_seconds=math.inf)
        with self.assertRaises(ValueError):
            UsageRecord("c1", recorded_at=datetime.now())

    def test_audit_payload_is_deeply_immutable_and_canonical(self) -> None:
        source = {"z": [1, {"b": True}], "a": "x"}
        event = AuditEvent("c", 1, "started", source, datetime.now(timezone.utc))
        source["z"].append(2)
        self.assertEqual(event.payload["z"], (1, {"b": True}))
        with self.assertRaises(TypeError):
            event.payload["new"] = 1  # type: ignore[index]
        self.assertEqual(canonical_json({"z": 1, "a": 2}), '{"a":2,"z":1}')
        with self.assertRaises(ValueError):
            canonical_json({"bad": float("nan")})

    def test_domain_models_are_frozen_and_validate_shapes(self) -> None:
        task = TaskBundle("t", "fix it", Role.WARRIOR, ("tests pass",))
        with self.assertRaises(FrozenInstanceError):
            task.version = 2  # type: ignore[misc]
        result = EvaluationResult("t", 0.8, "good", (True, False), True)
        self.assertEqual(result.score, 0.8)
        proposal = ImprovementProposal("p", Role.JUDGE, "add mutants", "find gaps", "mutation score")
        decision = PromotionDecision("p", False, "not enough evidence", -0.01, -0.2)
        self.assertEqual(proposal.target, Role.JUDGE)
        self.assertFalse(decision.promoted)
        with self.assertRaises(TypeError):
            EvaluationResult("t", 1, "x", [True], True)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
