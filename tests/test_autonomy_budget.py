import unittest

from aegis.autonomy_budget import V2_MIN_REQUESTS, autonomy_v2_budget_check


class AutonomyV2BudgetTests(unittest.TestCase):
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

    def test_v2_capacity_rejects_low_output_limit(self):
        result = self.v2_check(max_output=4095)
        self.assertFalse(result.passed)
        self.assertTrue(any("max_output_tokens" in failure for failure in result.failures))

    def test_v2_roles_must_include_all_three_roles(self):
        with self.assertRaises(ValueError):
            autonomy_v2_budget_check(
                total_tokens=20_000_000,
                max_requests=120,
                role_shares={"warrior": 0.55, "judge": 0.45},
                max_output_tokens={"warrior": 8192, "judge": 8192},
            )


if __name__ == "__main__":
    unittest.main()
