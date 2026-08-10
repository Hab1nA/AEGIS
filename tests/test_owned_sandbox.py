import unittest

from aegis.sandbox.fake import FakeSandboxBackend
from aegis.sandbox.owned import OwnedSandboxBackend


class OwnedSandboxTests(unittest.TestCase):
    def test_prepare_intent_precedes_backend_and_partial_failure_remains_owned(self) -> None:
        class PartialPrepare(FakeSandboxBackend):
            def prepare(self, sandbox_id):
                super().prepare(sandbox_id)
                raise RuntimeError("crashed after resource creation")

        raw = PartialPrepare()
        events = []
        owned = OwnedSandboxBackend(raw, lambda kind, payload: events.append((kind, payload)))

        with self.assertRaisesRegex(RuntimeError, "crashed"):
            owned.prepare("box")

        self.assertIn("box", raw.prepared)
        self.assertEqual([kind for kind, _ in events], ["sandbox_prepare_intent", "sandbox_prepare_failed"])
        owned.kill("box")
        self.assertEqual(events[-1], ("sandbox_killed", {"sandbox_id": "box"}))

    def test_cleanup_failure_never_emits_false_success(self) -> None:
        class FailedCleanup(FakeSandboxBackend):
            def kill(self, sandbox_id):
                raise RuntimeError("podman unavailable")

        events = []
        owned = OwnedSandboxBackend(FailedCleanup(), lambda kind, payload: events.append((kind, payload)))

        with self.assertRaisesRegex(RuntimeError, "podman"):
            owned.kill("box")

        self.assertEqual([kind for kind, _ in events], ["sandbox_cleanup_failed"])
        self.assertEqual(events[0][1]["action"], "kill")


if __name__ == "__main__":
    unittest.main()
