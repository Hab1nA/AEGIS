"""Deterministic end-to-end evidence-chain test for the Judge/evolution cycle.

Runs the full v2 cycle through the real control-plane wiring with a scripted
gateway and asserts the complete Judge evidence chain: frozen workspace
binding, forecast artifact, post-seal calibration, clause traceability on
registered tasks, reflection proposals entering the evolution queue, four
dimensional outcome summary, post-cycle postmortem, and stage checkpoints.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from aegis.artifacts import ArtifactRef, ContentAddressedArtifactStore
from aegis.curriculum import CurriculumRegistry
from aegis.agent_runtime import RuntimeLimits
from aegis.cycle_ports import run_v2_cycle
from aegis.dynamic_tasks import DynamicTaskRegistry, TaskForge
from aegis.dynamic_tasks.seed import GenesisSeeder
from aegis.event_store import EventStore
from aegis.evolution.registry import EvolutionRegistry
from aegis.roles import RoleRegistry
from aegis.taskpacks.validation import ExecutionResult

from tests.test_cycle_ports import (
    FakeGateway,
    FakeResearch,
    WritingFakeSandboxBackend,
    role_configs,
    submit,
    task_spec_from_pack,
)


class AnchorRunner:
    """Deterministic validation runner: reference passes, defect/mutants fail."""

    def run(self, pack, implementation_dir: str, suite: str) -> ExecutionResult:
        passed = implementation_dir == pack.manifest.reference_dir
        return ExecutionResult(
            passed=passed,
            tests_run=1,
            exit_code=0 if passed else 1,
            timed_out=False,
            output_digest="chain-anchor",
        )


def workflow_content() -> dict[str, object]:
    return {
        "stage_plan": ["read contract", "implement", "verify"],
        "research_query_templates": ["search the sealed public contract for boundary semantics"],
        "tool_selection_rules": ["workspace.read before submit"],
        "stop_conditions": ["submit when public tests pass"],
        "verification_checklist": ["public tests pass"],
        "skill_references": ["python-basic"],
        "max_steps": 10,
    }


def reflection_proposals(role: str, proposal_id: str) -> list[dict[str, object]]:
    return [
        {
            "proposal_id": proposal_id,
            "target_role": "warrior",
            "content": workflow_content(),
            "rationale": f"{role} reflection proposal",
            "expected_metric": "quality>=0.6",
            "falsifier": "next sealed evaluation contradicts the hypothesis",
        }
    ]


def actions_for_chain() -> list[dict[str, object]]:
    return [
        {
            "action": "strategy.propose",
            "arguments": {
                "proposal_id": "strategy-chain-1",
                "target_role": "warrior",
                "workflow": workflow_content(),
                "rationale": "deterministic workflow candidate",
            },
        },
        submit("solved", {"task_ids": [], "results": []}),
        submit(
            "reviewed",
            {
                "findings": ["bounded review"],
                "quality_score": 0.8,
                "forecast": {
                    "per_task_failure_probability": {},
                    "confidence": 0.7,
                    "evidence_coverage": 1.0,
                    "probes": ["workspace.read"],
                },
            },
        ),
        submit(
            "audited",
            {
                "usage_verified": True,
                "safety_passed": True,
                "integrity_passed": True,
                "curriculum": [],
            },
        ),
        submit("reflect-warrior", {"claims": [], "proposals": reflection_proposals("warrior", "reflection-chain-1")}),
        submit("reflect-judge", {"claims": [], "proposals": reflection_proposals("judge", "reflection-chain-2")}),
        submit("reflect-prosecutor", {"claims": [], "proposals": reflection_proposals("prosecutor", "reflection-chain-3")}),
        submit("council", {"proposal": None, "agenda": []}),
        submit("forged", {"task_specs": [task_spec_from_pack("dynamic-chain-task")]}),
    ]


def test_full_judge_evidence_chain_with_scripted_gateway() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        store = EventStore(root / "events.sqlite3")
        dynamic = DynamicTaskRegistry(root / "tasks.sqlite3")
        runner = AnchorRunner()
        GenesisSeeder(dynamic, TaskForge(dynamic)).seed(runner)
        curriculum = CurriculumRegistry(store, "cli")
        roles = RoleRegistry(store, "cli")
        evolution = EvolutionRegistry(store, "cli")
        artifacts = ContentAddressedArtifactStore(root / "artifacts")
        try:
            gateway = FakeGateway(actions_for_chain())
            result = run_v2_cycle(
                gateway=gateway,
                sandbox=WritingFakeSandboxBackend(),
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
                evolution=evolution,
                event_store=store,
                evaluate_candidates_enabled=True,
            )

            # 1. Frozen workspace binding on the Warrior submission.
            submission = json.loads(artifacts.get(result.submission).decode("utf-8"))
            assert submission["workspace_artifact_id"].startswith("arm-workspace-sha256:")
            assert submission["workspace_digest"]
            assert submission["workspace_staged"] is True

            # 2. Judge review carries a forecast and the mounted workspace digest.
            review = json.loads(artifacts.get(result.judge_review).decode("utf-8"))
            assert review["forecast"]["workspace_digest"] == submission["workspace_digest"]
            assert "per_task_failure_probability" in review["forecast"]
            assert isinstance(review["forecast"]["verified_workspace_binding"], bool)

            # 3. Quality lock separates advisory score from sealed evaluation truth.
            lock = json.loads(artifacts.get(result.quality_lock).decode("utf-8"))
            assert "judge_advisory_score" in lock
            assert lock["evaluation"]["integrity_passed"] is True
            assert lock["evaluation"]["safety_violations"] == []

            # 4. Post-seal calibration artifact exists with a bounded report.
            calibration = json.loads(artifacts.get(result.judge_calibration).decode("utf-8"))
            assert "sample_count" in calibration and calibration["sample_count"] >= 0
            assert "workspace_verified" in calibration
            assert "brier_score" in calibration and "ece" in calibration
            assert "forecast_count" in calibration

            # 5. Clause traceability on the registered task.
            validation = json.loads(artifacts.get(result.task_validation).decode("utf-8"))
            assert validation["valid"] is True
            assert validation["registered"][0]["clause_coverage"]["coverage"]["defect"] is True
            assert validation["registered"][0]["clause_coverage"]["coverage"]["hidden_cases"] > 0

            # 6. Reflection proposals enter the evolution queue and candidate
            #    evaluation runs enabled with the collected candidate.
            candidates = json.loads(artifacts.get(result.candidate_evaluation).decode("utf-8"))
            assert candidates["enabled"] is True
            assert candidates["validated"], "reflection/strategy proposals must be collected"
            assert candidates["activation"]["reason"].startswith("candidate retained")

            # 7. Attribution reads integrity/safety from the sealed quality lock.
            attribution = json.loads(artifacts.get(result.attribution).decode("utf-8"))
            assert attribution["arm"]["integrity_passed"] is True
            assert attribution["arm"]["safety_passed"] is True

            # 8. Post-cycle postmortem exists for all roles.
            post_index = json.loads(artifacts.get(result.post_reflection_index).decode("utf-8"))
            assert len(post_index["reflections"]) == 3
            post_id = post_index["reflections"][0]
            post_ref = json.loads(
                artifacts.get(
                    ArtifactRef(
                        "post-reflection",
                        post_id,
                        (artifacts.root / "post-reflection" / post_id.rsplit(":", 1)[1]).stat().st_size,
                    )
                ).decode("utf-8")
            )
            assert "failed_stage_or_obligation" in post_ref
            assert post_ref["evidence_kind"] == "observed"

            # 9. Summary reports four outcome dimensions instead of one label.
            summary = json.loads(artifacts.get(result.cycle_summary).decode("utf-8"))
            assert set(summary["dimensions"]) == {
                "execution",
                "learning",
                "candidate",
                "activation",
            }
            assert summary["dimensions"]["learning"] == "progressed"
            assert summary["dimensions"]["candidate"] == "pending"
            assert "judge_calibration" in summary and "post_reflections" in summary

            # 10. Stage checkpoints are persisted for a resumable lifecycle.
            checkpoints = [
                event
                for event in store.read("cli/stage-checkpoints")
                if event.event_type == "stage_checkpoint_v2"
            ]
            assert checkpoints, "stage checkpoints must be persisted"
            assert {event.payload["stage"] for event in checkpoints} >= {
                "submission",
                "judge-review",
                "quality-lock",
                "task-forge",
                "candidate-evaluation",
            }
        finally:
            dynamic.close()
            store.close()
