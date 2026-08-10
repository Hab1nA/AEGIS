import unittest

from aegis.autonomy_budget import (
    AUTONOMY_MIN_REQUESTS,
    V2_MIN_REQUESTS,
    autonomy_budget_check,
    autonomy_v2_budget_check,
)


class AutonomyBudgetTests(unittest.TestCase):
    def check(self, *, total_tokens=14_000_000, max_requests=800, max_output=4096):
        return autonomy_budget_check(
            total_tokens=total_tokens,
            max_requests=max_requests,
            role_shares={"warrior": 0.55, "judge": 0.225, "prosecutor": 0.225},
            max_output_tokens={role: max_output for role in ("warrior", "judge", "prosecutor")},
        )

    def test_recommended_capacity_covers_shortest_complete_chain(self):
        result = self.check()
        self.assertTrue(result.passed)
        self.assertEqual(result.minimum_requests, 663)
        self.assertEqual(AUTONOMY_MIN_REQUESTS, 663)
        self.assertEqual(result.global_tokens_required, 13_578_240)

    def test_old_smoke_capacity_is_rejected(self):
        result = self.check(total_tokens=1_200_000, max_requests=600)
        self.assertFalse(result.passed)
        self.assertTrue(any("requests" in failure for failure in result.failures))
        self.assertTrue(any("global token" in failure for failure in result.failures))

    def test_insufficient_prosecutor_share_is_rejected(self):
        result = autonomy_budget_check(
            total_tokens=14_000_000,
            max_requests=800,
            role_shares={"warrior": 0.60, "judge": 0.25, "prosecutor": 0.15},
            max_output_tokens={role: 4096 for role in ("warrior", "judge", "prosecutor")},
        )
        self.assertFalse(result.passed)
        self.assertTrue(any("prosecutor" in failure for failure in result.failures))

    def test_larger_output_limit_requires_more_token_capacity(self):
        result = self.check(max_output=8192)
        self.assertFalse(result.passed)
        self.assertGreater(result.global_tokens_required, 14_000_000)

    def test_output_below_acceptance_minimum_is_rejected(self):
        result = self.check(max_output=4095)
        self.assertFalse(result.passed)
        self.assertTrue(any("max_output_tokens" in failure for failure in result.failures))

    def v2_check(self, *, total_tokens=20_000_000, max_requests=120, max_output=16384):
        return autonomy_v2_budget_check(
            total_tokens=total_tokens,
            max_requests=max_requests,
            role_shares={"warrior": 0.55, "judge": 0.225, "prosecutor": 0.225},
            max_output_tokens={role: max_output for role in ("warrior", "judge", "prosecutor")},
        )

    def test_v2_dynamic_capacity_covers_two_cycles(self):
        result = self.v2_check()
        self.assertTrue(result.passed)
        self.assertEqual(result.minimum_requests, 48)
        self.assertEqual(V2_MIN_REQUESTS, 48)

    def test_v2_capacity_rejects_insufficient_requests(self):
        result = self.v2_check(max_requests=40)
        self.assertFalse(result.passed)
        self.assertTrue(any("requests" in failure for failure in result.failures))


if __name__ == "__main__":
    unittest.main()
