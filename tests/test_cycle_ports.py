from __future__ import annotations

import base64
import hashlib
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from aegis.agent_runtime import RuntimeLimits
from aegis.artifacts import ContentAddressedArtifactStore
from aegis.cli import main
from aegis.config import RoleConfig
from aegis.curriculum import CurriculumRegistry, CycleState
from aegis.cycle_ports import run_v2_cycle
from aegis.dynamic_tasks import (
    DynamicTaskOrigin,
    DynamicTaskRegistry,
    DynamicTaskStatus,
    GenesisSeeder,
    TaskForge,
)
from aegis.dynamic_tasks.forge import canonical_taskpack_archive
from aegis.event_store import EventStore
from aegis.gateway.types import GatewayResponse, TokenUsage
from aegis.models import Role
from aegis.research.types import Provenance, ResearchArtifact, SearchHit
from aegis.roles import RoleRegistry
from aegis.sandbox.fake import FakeSandboxBackend
from aegis.taskpacks.builtin import load_builtin_python_taskpacks
from aegis.taskpacks.manifest import TaskPack
from aegis.taskpacks.validation import ExecutionResult


class AnchorRunner:
    """Deterministic validation runner: reference passes, defect/mutants fail."""

    def run(self, pack, implementation_dir: str, suite: str) -> ExecutionResult:
        passed = implementation_dir == pack.manifest.reference_dir
        return ExecutionResult(
            passed=passed,
            tests_run=1,
            exit_code=0 if passed else 1,
            timed_out=False,
            output_digest="cycle-anchor",
        )


class FakeGateway:
    def __init__(self, actions: list[dict[str, object]]) -> None:
        self.actions = list(actions)
        self.requests = []

    def complete(self, request, *, cancel=None):
        self.requests.append(request)
        action = self.actions.pop(0)
        return GatewayResponse(json.dumps(action), TokenUsage(5, 3, verified=True), "fake")


class FakeResearch:
    def search(self, query: str, *, limit: int = 10):
        return [SearchHit("https://example.test/paper", "Paper", "abstract")]

    def fetch(self, url: str, *, validate_as_archive: bool = False):
        content = b"research"
        return ResearchArtifact(
            content,
            Provenance(
                url,
                url,
                "2026-01-01T00:00:00+00:00",
                hashlib.sha256(content).hexdigest(),
                len(content),
                "text/plain",
                (),
            ),
        )


def submit(summary: str, payload: dict[str, object]) -> dict[str, object]:
    return {"action": "submit", "arguments": {"summary": summary, "payload": payload}}


def forge_archive(root: Path, *, task_id: str = "dynamic-next") -> bytes:
    source = sorted(
        load_builtin_python_taskpacks(), key=lambda item: item.manifest.task_id
    )[0]
    copied = root / "forge-pack"
    shutil.copytree(source.root, copied)
    manifest_path = copied / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["task_id"] = task_id
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return canonical_taskpack_archive(TaskPack.load(copied))


def gateway_actions(
    archive: bytes, *, propose_candidate: bool = True
) -> list[dict[str, object]]:
    audit_payload: dict[str, object] = {
        "usage_verified": True,
        "safety_passed": True,
        "integrity_passed": True,
        "curriculum": [{"capability": "debugging", "hypothesis": "next probe"}],
    }
    if propose_candidate:
        audit_payload["role_candidates"] = {
            "warrior": {
                "artifact_id": "role-bundle-warrior-v2",
                "artifact_sha256": "a" * 64,
            }
        }
    return [
        submit(
            "solved",
            {"task_ids": ["dynamic-task-sha256:" + "1" * 64], "results": [{"passed": True}]},
        ),
        submit("reviewed", {"findings": ["bounded review"], "quality_score": 0.8}),
        submit("audited", audit_payload),
        submit("reflect-warrior", {"claims": ["keep workspace autonomy"]}),
        submit("reflect-judge", {"claims": ["forge harder tasks"]}),
        submit("reflect-prosecutor", {"claims": ["watch token drift"]}),
        submit("council", {"proposal": "test the next hypothesis", "agenda": ["x"]}),
        submit(
            "forged",
            {
                "proposals": [
                    {
                        "task_id": "dynamic-next",
                        "difficulty": 2,
                        "capability_tags": ["python"],
                        "cost_units": 10,
                        "stop_conditions": ["pass the sealed suite"],
                    }
                ],
                "archives": [
                    {
                        "task_id": "dynamic-next",
                        "archive_base64": base64.b64encode(archive).decode("ascii"),
                    }
                ],
            },
        ),
    ]


def role_configs() -> dict[str, RoleConfig]:
    return {
        "warrior": RoleConfig("w", 0.60, 1024),
        "judge": RoleConfig("j", 0.25, 1024),
        "prosecutor": RoleConfig("p", 0.15, 1024),
    }


class CyclePortsTests(unittest.TestCase):
    def test_full_model_driven_cycle_forges_and_registers_dynamic_task(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = EventStore(root / "events.sqlite3")
            dynamic = DynamicTaskRegistry(root / "tasks.sqlite3")
            runner = AnchorRunner()
            seeder = GenesisSeeder(dynamic, TaskForge(dynamic))
            seeder.seed(runner)
            curriculum = CurriculumRegistry(store, "cli")
            roles = RoleRegistry(store, "cli")
            archive = forge_archive(root)
            gateway = FakeGateway(gateway_actions(archive))
            try:
                result = run_v2_cycle(
                    gateway=gateway,
                    sandbox=FakeSandboxBackend(),
                    research=FakeResearch(),
                    knowledge=None,
                    skills=None,
                    pdf_extractor=None,
                    role_configs=role_configs(),
                    limits=RuntimeLimits(max_steps=20),
                    artifacts=ContentAddressedArtifactStore(root / "artifacts"),
                    dynamic=dynamic,
                    forge=TaskForge(dynamic),
                    runner=runner,
                    curriculum=curriculum,
                    roles=roles,
                    data_dir=root,
                    campaign_id="cli",
                )
                self.assertIs(curriculum.projection.cycle_state, CycleState.COMPLETED)
                self.assertTrue(result.cycle_summary.artifact_id.startswith("cycle-summary-sha256:"))
                self.assertTrue(
                    result.task_validation.artifact_id.startswith("task-validation-sha256:")
                )
                dynamic_records = [
                    record
                    for record in dynamic.records()
                    if record.origin is DynamicTaskOrigin.DYNAMIC
                ]
                self.assertEqual(len(dynamic_records), 1)
                self.assertIs(dynamic_records[0].status, DynamicTaskStatus.QUARANTINED)
                self.assertEqual(dynamic_records[0].creator_generation, 2)
                active = roles.projection.current_active_set
                self.assertIsNotNone(active)
                assert active is not None
                self.assertEqual(active.for_role(Role.WARRIOR).version, 2)
                ledger = root / "attribution_arms.jsonl"
                self.assertTrue(ledger.exists())
                self.assertEqual(len(ledger.read_text(encoding="utf-8").splitlines()), 1)
                self.assertEqual(gateway.requests[0].messages[0].role, "system")
            finally:
                dynamic.close()
                store.close()

    def test_second_cycle_records_paired_attribution_and_keeps_provisional_roles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = EventStore(root / "events.sqlite3")
            dynamic = DynamicTaskRegistry(root / "tasks.sqlite3")
            runner = AnchorRunner()
            GenesisSeeder(dynamic, TaskForge(dynamic)).seed(runner)
            curriculum = CurriculumRegistry(store, "cli")
            roles = RoleRegistry(store, "cli")
            archive = forge_archive(root)
            artifacts = ContentAddressedArtifactStore(root / "artifacts")
            first = FakeGateway(gateway_actions(archive, propose_candidate=True))
            second = FakeGateway(gateway_actions(archive, propose_candidate=False))
            common = dict(
                sandbox=FakeSandboxBackend(),
                research=FakeResearch(),
                knowledge=None,
                skills=None,
                pdf_extractor=None,
                role_configs=role_configs(),
                limits=RuntimeLimits(max_steps=20),
                artifacts=artifacts,
                dynamic=dynamic,
                forge=TaskForge(dynamic),
                runner=runner,
                curriculum=curriculum,
                roles=roles,
                data_dir=root,
                campaign_id="cli",
            )
            try:
                result1 = run_v2_cycle(gateway=first, **common)
                active_after_first = roles.projection.current_active_set
                self.assertIsNotNone(active_after_first)
                assert active_after_first is not None
                self.assertEqual(active_after_first.for_role(Role.WARRIOR).version, 2)
                result2 = run_v2_cycle(gateway=second, **common)
                self.assertIs(curriculum.projection.cycle_state, CycleState.COMPLETED)
                self.assertEqual(curriculum.projection.current_snapshot.cycle_number, 2)
                active_after_second = roles.projection.current_active_set
                self.assertIsNotNone(active_after_second)
                assert active_after_second is not None
                self.assertEqual(active_after_second.for_role(Role.WARRIOR).version, 2)
                ledger = root / "attribution_arms.jsonl"
                self.assertEqual(len(ledger.read_text(encoding="utf-8").splitlines()), 2)
                attribution = json.loads(artifacts.get(result2.attribution).decode("utf-8"))
                self.assertEqual(attribution["report"]["disposition"], "confounded")
                self.assertTrue(
                    result2.snapshot_id != result1.snapshot_id
                )
            finally:
                dynamic.close()
                store.close()

    def test_cli_evolution_cycle_run_executes_one_full_cycle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "v2.json"
            configured = {
                "campaign_id": "cli",
                "max_rounds": 2,
                "total_tokens": 14_000_000,
                "max_requests": 800,
                "wall_time_seconds": 28_800,
                "sandbox_backend": "fake",
                "test_mode": True,
                "offline_research": True,
                "research_enabled": False,
                "acceptance_profile": "autonomous_evolution_v2",
                "task_pack_paths": [],
                "autonomy_v2": {"enabled": True},
                "roles": {
                    "warrior": {"model": "w", "budget_share": 0.55, "max_output_tokens": 4096},
                    "judge": {"model": "j", "budget_share": 0.225, "max_output_tokens": 4096},
                    "prosecutor": {
                        "model": "p",
                        "budget_share": 0.225,
                        "max_output_tokens": 4096,
                    },
                },
            }
            source.write_text(json.dumps(configured))
            argv = ["--data-dir", str(root / "isolated")]
            self.assertEqual(main([*argv, "campaign-create", str(source)]), 0)
            archive = forge_archive(root)
            gateway = FakeGateway(gateway_actions(archive))
            output = StringIO()
            with (
                redirect_stdout(output),
                patch("aegis.cli.ModelGateway", return_value=gateway),
                patch("aegis.cli.SandboxTaskPackRunner", return_value=AnchorRunner()),
            ):
                self.assertEqual(main([*argv, "evolution-cycle", "cli", "--run"]), 0)
            report = json.loads(output.getvalue())
            self.assertEqual(report["plan"]["registry"]["anchors"], 12)
            self.assertEqual(report["cycle"]["state"], "completed")
            self.assertTrue(
                report["cycle"]["artifacts"]["task_validation"].startswith(
                    "task-validation-sha256:"
                )
            )


if __name__ == "__main__":
    unittest.main()
