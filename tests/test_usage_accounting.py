"""Frozen usage accounting: extraction semantics and tamper detection."""

from __future__ import annotations

import unittest

from aegis.gateway.types import GatewayRequest, Message, TokenUsage
from aegis.usage_accounting import extract_usage


def _request(max_output_tokens: int = 1000) -> GatewayRequest:
    return GatewayRequest(
        "model",
        (Message("system", "sys"), Message("user", "hello")),
        max_output_tokens,
    )


class TokenUsageIdentityTests(unittest.TestCase):
    def test_gateway_types_reexport_is_the_frozen_class(self) -> None:
        # The editable transport must not be able to shadow the accounting
        # type with a lookalike: gateway.types re-exports the frozen class.
        import aegis.gateway.types as gt
        from aegis import usage_accounting

        self.assertIs(gt.TokenUsage, usage_accounting.TokenUsage)


class ExtractUsageTests(unittest.TestCase):
    def test_responses_shape_is_verified(self) -> None:
        usage = extract_usage(
            {
                "usage": {
                    "input_tokens": 120,
                    "output_tokens": 40,
                    "input_tokens_details": {"cached_tokens": 60},
                    "output_tokens_details": {"reasoning_tokens": 30},
                }
            },
            _request(),
            "text",
        )
        self.assertEqual((usage.input_tokens, usage.output_tokens), (120, 40))
        self.assertEqual((usage.cached_tokens, usage.reasoning_tokens), (60, 30))
        self.assertTrue(usage.verified)
        self.assertEqual(usage.anomalies, ())

    def test_chat_completions_shape_is_verified(self) -> None:
        usage = extract_usage(
            {
                "usage": {
                    "prompt_tokens": 90,
                    "completion_tokens": 25,
                    "prompt_tokens_details": {"cached_tokens": 10},
                    "reasoning_tokens": 15,
                }
            },
            _request(),
            "text",
        )
        self.assertEqual((usage.input_tokens, usage.output_tokens), (90, 25))
        self.assertEqual((usage.cached_tokens, usage.reasoning_tokens), (10, 15))
        self.assertTrue(usage.verified)
        self.assertEqual(usage.anomalies, ())

    def test_missing_usage_falls_back_to_unverified_estimate(self) -> None:
        usage = extract_usage({}, _request(), "abcdef")
        self.assertFalse(usage.verified)
        self.assertGreater(usage.input_tokens, 0)
        self.assertGreater(usage.output_tokens, 0)

    def test_output_beyond_reserved_budget_is_flagged_unverified(self) -> None:
        usage = extract_usage(
            {"usage": {"input_tokens": 120, "output_tokens": 4001}},
            _request(max_output_tokens=4000),
            "text",
        )
        self.assertEqual(usage.output_tokens, 4001)
        self.assertFalse(usage.verified)
        self.assertIn("output_tokens_exceed_reserved_budget", usage.anomalies)

    def test_reasoning_exceeding_output_is_flagged(self) -> None:
        usage = extract_usage(
            {
                "usage": {
                    "input_tokens": 120,
                    "output_tokens": 40,
                    "output_tokens_details": {"reasoning_tokens": 41},
                }
            },
            _request(),
            "text",
        )
        self.assertFalse(usage.verified)
        self.assertIn("reasoning_tokens_exceed_output_tokens", usage.anomalies)

    def test_cached_exceeding_input_is_flagged(self) -> None:
        usage = extract_usage(
            {
                "usage": {
                    "input_tokens": 50,
                    "output_tokens": 40,
                    "input_tokens_details": {"cached_tokens": 51},
                }
            },
            _request(),
            "text",
        )
        self.assertFalse(usage.verified)
        self.assertIn("cached_tokens_exceed_input_tokens", usage.anomalies)

    def test_anomaly_summary_is_exposable(self) -> None:
        from aegis.cycle_ports import _usage_summary

        usages = [
            TokenUsage(10, 5, verified=True),
            TokenUsage(8, 4, verified=False, anomalies=("output_tokens_exceed_reserved_budget",)),
        ]
        summary = _usage_summary(usages)
        self.assertEqual(summary["usage_anomalies"], 1)
        self.assertEqual(summary["requests"], 2)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
