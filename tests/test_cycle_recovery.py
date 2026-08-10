from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path

from aegis.agent_runtime import RuntimeLimits
from aegis.artifacts import ContentAddressedArtifactStore
from aegis.config import RoleConfig
from aegis.curriculum import CurriculumRegistry
from aegis.cycle_ports import run_v2_cycle
from aegis.dynamic_tasks import (
    DynamicTaskRegistry,
    GenesisSeeder,
    TaskForge,
)
from aegis.event_store import EventStore
from aegis.gateway.types import GatewayResponse, TokenUsage
from aegis.models import Role
from aegis.roles import RoleRegistry
from aegis.sandbox.fake import FakeSandboxBackend
from aegis.taskpacks.validation import ExecutionResult


class AnchorRunner:
    def run(self, pack, implementation_dir: str, suite: str) -> ExecutionResult:
        passed = implementation_dir == pack.manifest.reference_dir
        return ExecutionResult(
            passed=passed,
            tests_run=1,
            exit_code=0 if passed else 1,
            timed_out=False,
            output_digest="recovery-anchor",
        )


class FailingThenPatchGateway:
    """First model call bricks the cycle; second call supplies the repair patch."""

    def __init__(self, *, empty_patch: bool = False) -> None:
        self.calls = 0
        self.empty_patch = empty_patch

    def complete(self, request, *, cancel=None):
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("simulated cycle failure in warrior solve")
        payload = (
            {"summary": "no safe patch", "changes": []}
            if self.empty_patch
            else {
                "summary": "repair warrior role",
                "changes": [
                    {
                        "path": "warrior/fix.py",
                        "content_base64": base64.b64encode(b"FIXED = True\n").decode("ascii"),
                        "executable": False,
                    }
                ],
            }
        )
        return GatewayResponse(
            json.dumps({"action": "submit", "arguments": {"summary": "repair", "payload": payload}}),
            TokenUsage(5, 3, verified=True),
            "fake",
        )


class CycleRecoveryTests(unittest.TestCase):
    def test_failed_cycle_is_repaired_and_activates_repaired_role(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = EventStore(root / "events.sqlite3")
            dynamic = DynamicTaskRegistry(root / "tasks.sqlite3")
            runner = AnchorRunner()
            GenesisSeeder(dynamic, TaskForge(dynamic)).seed(runner)
            curriculum = CurriculumRegistry(store, "cli")
            roles = RoleRegistry(store, "cli")
            try:
                result = run_v2_cycle(
                    gateway=FailingThenPatchGateway(),
                    sandbox=FakeSandboxBackend(),
                    research=None,
                    knowledge=None,
                    skills=None,
                    pdf_extractor=None,
                    role_configs={
                        "warrior": RoleConfig("w", 0.60, 1024),
                        "judge": RoleConfig("j", 0.25, 1024),
                        "prosecutor": RoleConfig("p", 0.15, 1024),
                    },
                    limits=RuntimeLimits(max_steps=20),
                    artifacts=ContentAddressedArtifactStore(root / "artifacts"),
                    dynamic=dynamic,
                    forge=TaskForge(dynamic),
                    runner=runner,
                    curriculum=curriculum,
                    roles=roles,
                    data_dir=root,
                    campaign_id="cli",
                    repair_on_failure=True,
                    event_store=store,
                )
                self.assertEqual(result.status.value, "repaired")
                active = roles.projection.current_active_set
                self.assertIsNotNone(active)
                assert active is not None
                self.assertEqual(active.for_role(Role.WARRIOR).version, 2)
                repair_events = [
                    event
                    for event in store.read(f"repair:{result.incident_id}")
                    if event.event_type.startswith("repair_runtime_")
                ]
                self.assertTrue(repair_events)
                self.assertTrue(
                    any(event.event_type == "repair_runtime_terminal_v1" for event in repair_events)
                )
            finally:
                dynamic.close()
                store.close()

    def test_failed_cycle_without_patch_rolls_back_to_last_known_good(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = EventStore(root / "events.sqlite3")
            dynamic = DynamicTaskRegistry(root / "tasks.sqlite3")
            runner = AnchorRunner()
            GenesisSeeder(dynamic, TaskForge(dynamic)).seed(runner)
            curriculum = CurriculumRegistry(store, "cli")
            roles = RoleRegistry(store, "cli")
            try:
                result = run_v2_cycle(
                    gateway=FailingThenPatchGateway(empty_patch=True),
                    sandbox=FakeSandboxBackend(),
                    research=None,
                    knowledge=None,
                    skills=None,
                    pdf_extractor=None,
                    role_configs={
                        "warrior": RoleConfig("w", 0.60, 1024),
                        "judge": RoleConfig("j", 0.25, 1024),
                        "prosecutor": RoleConfig("p", 0.15, 1024),
                    },
                    limits=RuntimeLimits(max_steps=20),
                    artifacts=ContentAddressedArtifactStore(root / "artifacts"),
                    dynamic=dynamic,
                    forge=TaskForge(dynamic),
                    runner=runner,
                    curriculum=curriculum,
                    roles=roles,
                    data_dir=root,
                    campaign_id="cli",
                    repair_on_failure=True,
                    event_store=store,
                )
                self.assertEqual(result.status.value, "rolled-back")
                started = [
                    event
                    for event in store.read("cli")
                    if event.event_type == "cycle_failed_recovery_started"
                ]
                self.assertEqual(len(started), 1)
                self.assertIn("simulated cycle failure", started[0].payload["error"])
            finally:
                dynamic.close()
                store.close()


if __name__ == "__main__":
    unittest.main()
