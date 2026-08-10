import unittest
from datetime import datetime, timezone

from aegis.models import AuditEvent, PromotionDecision, Role, canonical_json


class ModelTests(unittest.TestCase):
    def test_roles_are_stable_string_enum(self) -> None:
        self.assertEqual(Role.WARRIOR.value, "warrior")
        self.assertEqual(
            list(Role),
            [Role.WARRIOR, Role.JUDGE, Role.PROSECUTOR],
        )

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

    def test_promotion_decision_is_frozen_and_validates(self) -> None:
        decision = PromotionDecision("p", False, "not enough evidence", -0.01, -0.2)
        self.assertFalse(decision.promoted)
        self.assertEqual(decision.reason, "not enough evidence")


if __name__ == "__main__":
    unittest.main()
