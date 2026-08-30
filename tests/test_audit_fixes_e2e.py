"""Full-cycle E2E for the third-audit fixes.

Every test drives the real ``run_v2_cycle`` path (control plane, sandbox,
sealed evaluation, registries) with a scripted gateway and asserts that a
previously-broken link now works end to end:

1. cost-path activation  — a zero-quality-delta candidate that saves cost now
   activates (previously the gate could only reject);
2. prosecutor policy amendment — the Prosecutor can construct a legal
   ``aegis.adjust_runtime_policy`` call from the envelope and the amendment
   takes effect on later stages of the same cycle (previously unconstructible);
3. objective-amendment coverage pre-check — a chair proposal with insufficient
   history is rejected without sinking shadow solve cost;
4. reflect ``strategy_proposals`` reach candidate collection (previously a
   dead-end key mismatch);
5. chair envelope carries ``runtime_policy_requests`` and ``objective_history``
   (previously invisible);
6. ``resolve_role_binding`` fails loud on a corrupt active manifest
   (previously a silent default fallback).
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from aegis.agent_runtime import RuntimeLimits
from aegis.config import CampaignConfig
from aegis.artifacts import ContentAddressedArtifactStore
from aegis.curriculum.models import ObjectiveSuccessCriterion, ObjectiveVersion
from aegis.curriculum import CurriculumRegistry
from aegis.roles import RoleRegistry
from aegis.cycle_ports import ModelCyclePorts, run_v2_cycle
from aegis.dynamic_tasks import DynamicTaskRegistry, GenesisSeeder, TaskForge
from aegis.event_store import EventStore
from aegis.evolution.runtime import (
    EvolutionRuntimeError,
    materialize_default_artifacts,
    resolve_role_binding,
)
from aegis.evolution.registry import EvolutionRegistry
from aegis.evolution.surfaces import EvolutionSurface
from aegis.gateway.types import GatewayResponse, TokenUsage
from aegis.models import Role

from tests.test_cycle_ports import (
    AnchorRunner,
    FakeResearch,
    WritingFakeSandboxBackend,
    role_configs,
    run_candidate_cycle,
    seed_fresh_candidate_probe,
    submit,
    task_spec_from_pack,
)


class AuditAwareGateway:
    """Scripted gateway with dynamic branches for the audited stages."""

    def __init__(
        self,
        actions: list[dict[str, object]],
        *,
        audit_patch: dict[str, object] | None = None,
        chair_proposal_builder=None,
        baseline_cost: int = 100,
        candidate_cost: int = 8,
    ) -> None:
        self.actions = list(actions)
        self.requests = []
        self.audit_patch = audit_patch
        self.audit_handled = False
        self.chair_proposal_builder = chair_proposal_builder
        self.chair_handled = False
        self.chair_envelopes: list[dict] = []
        self.baseline_cost = baseline_cost
        self.candidate_cost = candidate_cost

    def _usage(self, context: dict) -> TokenUsage:
        arm = str(context.get("arm", ""))
        if "baseline" in arm:
            return TokenUsage(self.baseline_cost, self.baseline_cost, verified=True)
        return TokenUsage(5, 3, verified=True)

    def complete(self, request, *, cancel=None):
        self.requests.append(request)
        envelope = json.loads(request.messages[1].content)
        context = envelope.get("context", {})
        if (
            self.audit_patch is not None
            and not self.audit_handled
            and envelope.get("role") == "prosecutor"
            and "workspace_digest" in context
        ):
            self.audit_handled = True
            values = envelope["active_runtime_policy_values"]
            action = {
                "action": "aegis.adjust_runtime_policy",
                "arguments": {
                    "request_id": "e2e-audit-amend-1",
                    "base_policy_id": values["runtime_policy_id"],
                    "patch": dict(self.audit_patch),
                    "rollback_target_policy_id": None,
                    "reason": "widen cohort for a harder curriculum",
                    "evidence_refs": [],
                },
            }
            return GatewayResponse(
                json.dumps(action), self._usage(context), "fake"
            )
        if (
            self.chair_proposal_builder is not None
            and not self.chair_handled
            and str(envelope.get("objective", "")).startswith("Act as council chair")
        ):
            self.chair_handled = True
            self.chair_envelopes.append(envelope)
            payload = self.chair_proposal_builder(envelope)
            action = submit(
                "chaired",
                {
                    "proposal": payload.get("proposal"),
                    "agenda": payload.get("agenda", []),
                    "mcp_decisions": payload.get("mcp_decisions", []),
                    "runtime_policy_decisions": payload.get(
                        "runtime_policy_decisions", []
                    ),
                },
            )
            return GatewayResponse(
                json.dumps(action), self._usage(context), "fake"
            )
        action = self.actions.pop(0)
        return GatewayResponse(json.dumps(action), self._usage(context), "fake")


def fixed_write(path: str, solution: bytes) -> dict[str, object]:
    return {
        "action": "workspace.write",
        "arguments": {
            "path": path,
            "content_base64": base64.b64encode(solution).decode("ascii"),
        },
    }


def workflow_propose_action(
    target: str = "warrior", proposal_id: str = "wf-e2e-1"
) -> dict[str, object]:
    return {
        "action": "strategy.propose",
        "arguments": {
            "proposal_id": proposal_id,
            "target_role": target,
            "workflow": {
                "stage_plan": [
                    "read every task brief",
                    "write one solution per task",
                    "run the public tests",
                    "submit the payload",
                ],
                "research_query_templates": ["python {feature}"],
                "tool_selection_rules": [
                    "use workspace.write with explicit content_base64 arguments"
                ],
                "stop_conditions": ["all tasks submitted"],
                "verification_checklist": ["public tests pass"],
                "skill_references": ["none"],
                "max_steps": None,
            },
            "rationale": "explicit write arguments prevent ActionError misuse",
        },
    }


def build_cycle(root: Path, *, sandbox):
    store = EventStore(root / "events.sqlite3")
    dynamic = DynamicTaskRegistry(root / "tasks.sqlite3")
    runner = AnchorRunner()
    GenesisSeeder(dynamic, TaskForge(dynamic)).seed(runner)
    seed_fresh_candidate_probe(dynamic, runner, root)
    curriculum = CurriculumRegistry(store, "cli")
    roles = RoleRegistry(store, "cli")
    evolution = EvolutionRegistry(store, "cli")
    artifacts = ContentAddressedArtifactStore(root / "artifacts")
    common = dict(
        sandbox=sandbox,
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
    )
    return common, store, artifacts, roles, evolution


def _fixed_sealed_evaluator(sandbox):
    def sealed_evaluator(sandbox_id: str, payload: bytes, timeout: float):
        del payload, timeout
        files = sandbox._files.get(sandbox_id, {})
        fixed = any(
            isinstance(content, bytes) and b"FIXED" in content
            for content in files.values()
        )
        from aegis.sandbox.types import SealedEvaluationResult

        return SealedEvaluationResult(1 if fixed else 0, 1)

    return sealed_evaluator


class _RecordingExecutor:
    def __init__(self) -> None:
        self.sandbox = None

    def __call__(self, sandbox_id: str, spec):
        argv = spec.argv
        if (
            len(argv) == 5
            and argv[0] == "python3"
            and argv[1] == "-c"
            and "base64" in argv[2]
        ):
            path = argv[3]
            payload = base64.b64decode(argv[4], validate=True)
            assert self.sandbox is not None
            self.sandbox._files.setdefault(sandbox_id, {})[path] = payload
            from aegis.sandbox.types import CommandResult

            return CommandResult(0, str(len(payload)), "", 0.0)
        from aegis.sandbox.types import CommandResult

        return CommandResult(0, "", "", 0.0)


def _envelopes(gateway: AuditAwareGateway):
    return [json.loads(r.messages[1].content) for r in gateway.requests]


def test_cost_path_activates_zero_delta_candidate(tmp_path: Path) -> None:
    """Before the fix this exact scenario could only end in fresh-rejected."""
    solution = (
        b"def clamp(value, lower, upper):\n"
        b"    if lower > upper:\n"
        b"        raise ValueError()\n"
        b"    return min(max(value, lower), upper)  # FIXED\n"
    )
    path = "tasks/candidate-fresh-probe/solution.py"
    solved = submit("solved", {"task_ids": [], "results": []})
    write = fixed_write(path, solution)
    actions = [
        workflow_propose_action(),
        submit(
            "solved",
            {
                "task_ids": ["dynamic-task-sha256:" + "1" * 64],
                "results": [{"passed": True}],
            },
        ),
        submit("reviewed", {"findings": ["bounded review"], "quality_score": 0.8}),
        submit(
            "audited",
            {"usage_verified": True, "safety_passed": True, "integrity_passed": True},
        ),
        submit("reflect-warrior", {"claims": ["keep workspace autonomy"]}),
        submit("reflect-judge", {"claims": ["forge harder tasks"]}),
        submit("reflect-prosecutor", {"claims": ["watch token drift"]}),
        submit("council", {"proposal": None, "agenda": ["x"]}),
        submit("forged", {"task_specs": [task_spec_from_pack()]}),
        # seed 0: baseline + candidate both write FIXED (fresh saturated),
        write,
        solved,
        write,
        solved,
        # seed 1: same, so quality delta is exactly zero and only the cost
        # path can qualify the candidate.
        write,
        solved,
        write,
        solved,
    ]
    recorder = _RecordingExecutor()
    sandbox = WritingFakeSandboxBackend(
        executor=recorder, sealed_evaluator=None
    )
    sandbox.sealed_evaluator = _fixed_sealed_evaluator(sandbox)
    recorder.sandbox = sandbox
    common, store, artifacts, roles, evolution = build_cycle(tmp_path, sandbox=sandbox)
    gateway = AuditAwareGateway(actions)
    try:
        result = run_candidate_cycle(gateway=gateway, **common)
        assert roles.projection.current_active_set is not None
        candidate_evidence = json.loads(
            artifacts.get(result.candidate_evaluation).decode("utf-8")
        )
        gate = candidate_evidence["candidate_gate"]
        assert gate["disposition"] == "qualified"
        assert "cost path" in gate["reason"]
        assert candidate_evidence["arms"]["pairs"][0]["baseline_source"] in {
            "main-solve",
            "dedicated-arm",
        }
        assert roles.projection.current_active_set.for_role(Role.WARRIOR).version == 2
        champion = evolution.champion(__import__("aegis").evolution.surfaces.EvolutionSurface.WORKFLOW, Role.WARRIOR)
        assert champion is not None
    finally:
        store.close()


def test_prosecutor_constructs_policy_amendment_from_envelope(tmp_path: Path) -> None:
    """The audit stage can now build a legal adjust call and it takes effect
    on later stages of the same cycle (previously unconstructible)."""
    audit_payload = {
        "usage_verified": True,
        "safety_passed": True,
        "integrity_passed": True,
        "curriculum_hypotheses": [
            {"hypothesis_id": "hyp-1", "summary": "concurrency stress next", "confidence": 0.7}
        ],
    }
    actions = [
        submit("solved", {"task_ids": [], "results": []}),
        submit("reviewed", {"findings": [], "quality_score": 0.5}),
        submit("audited", audit_payload),
        submit("reflect-warrior", {"claims": []}),
        submit("reflect-judge", {"claims": []}),
        submit("reflect-prosecutor", {"claims": []}),
        submit("council", {"proposal": None, "agenda": []}),
        submit("forged", {"task_specs": [task_spec_from_pack()]}),
    ]
    sandbox = WritingFakeSandboxBackend()
    common, store, artifacts, roles, evolution = build_cycle(tmp_path, sandbox=sandbox)
    campaign_config = CampaignConfig.from_mapping(
        {
            "campaign_id": "cli",
            "acceptance_profile": "autonomous_evolution_v2",
            "max_rounds": 64,
            "total_tokens": 60_000_000,
            "max_requests": 500,
            "wall_time_seconds": 28_800,
            "roles": {
                "warrior": {"model": "w", "budget_share": 0.55, "max_output_tokens": 4096, "reasoning_effort": "max"},
                "judge": {"model": "j", "budget_share": 0.225, "max_output_tokens": 4096, "reasoning_effort": "max"},
                "prosecutor": {"model": "p", "budget_share": 0.225, "max_output_tokens": 4096, "reasoning_effort": "max"},
            },
            "task_pack_paths": [],
            "autonomy_v2": {"enabled": True},
        }
    )
    def chair_responder(envelope: dict) -> dict:
        pending = envelope["context"]["pending_runtime_policy_amendments"]
        return {
            "proposal": None,
            "agenda": ["ratified the cohort widening"],
            "mcp_decisions": [],
            "runtime_policy_decisions": [
                {
                    "amendment_id": pending[0]["amendment_id"],
                    "decision": "ratify",
                    "reason": "cohort widening accepted",
                    "replacement_amendment_id": None,
                }
            ],
        }

    gateway = AuditAwareGateway(
        actions, audit_patch={"cohort_limit": 4}, chair_proposal_builder=chair_responder
    )
    try:
        result = run_v2_cycle(
            gateway=gateway, campaign_config=campaign_config, event_store=store, **common
        )
        assert curriculum_completed(store)
        # The amendment was applied and persisted.
        events = store.read("cli/runtime-policy")
        applied = [
            e for e in events if "amendment" in e.event_type
        ]
        assert applied, "no runtime-policy amendment event was recorded"
        policy_values = [
            json.loads(p.read_text(encoding="utf-8")).get("values") or {}
            for p in (artifacts.root / "runtime-policy").iterdir()
        ]
        assert any(v.get("cohort_limit") == 4 for v in policy_values)
        # It took effect on later stages of the same cycle: reflect/chair
        # envelopes advertise the patched value.
        envelopes = _envelopes(gateway)
        audit_index = next(
            i
            for i, env in enumerate(envelopes)
            if env.get("role") == "prosecutor"
            and "workspace_digest" in env.get("context", {})
        )
        post_audit = [
            env
            for env in envelopes[audit_index + 1 :]
            if "cohort_limit" in env.get("active_runtime_policy_values", {})
        ]
        assert post_audit, "no post-audit stage advertised policy values"
        assert all(
            env["active_runtime_policy_values"]["cohort_limit"] == 4
            for env in post_audit
        )
        # The dual-key curriculum contract: the artifact carries the hypotheses.
        newest = sorted(
            (artifacts.root / "prosecutor-audit").iterdir(),
            key=lambda p: p.stat().st_mtime,
        )[-1]
        audit_artifact = json.loads(newest.read_text(encoding="utf-8"))
        assert len(audit_artifact["curriculum"]) == 1
        assert audit_artifact["curriculum"][0]["hypothesis_id"] == "hyp-1"
    finally:
        store.close()


def curriculum_completed(store: EventStore) -> bool:
    events = store.read("cli")
    from aegis.curriculum import CycleState

    return any(
        e.event_type == "cycle_state_changed_v2"
        and e.payload.get("state") == CycleState.COMPLETED.value
        for e in events
    )


def test_chair_amendment_with_insufficient_history_skips_shadow_solves(
    tmp_path: Path,
) -> None:
    """The pre-check rejects early instead of sinking full solve cost."""
    def chair_proposal(envelope: dict) -> dict:
        obj = envelope["context"]["snapshot"]["objective"]
        # The chair proposes the flat structured schema; the control plane
        # builds the successor ObjectiveVersion itself.
        return {
            "proposal": {
                "statement": str(obj["statement"]) + " with a sharper quality bar",
                "success_criteria": [
                    {"metric": "quality", "minimum": 0.6},
                    {"metric": "generalization", "minimum": 0.5},
                ],
                "capability_tags": list(obj["capability_tags"]),
                "capability_weights": dict(obj["capability_weights"]),
                "rationale": "raise the quality bar",
            },
            "agenda": ["x"],
            "mcp_decisions": [],
            "runtime_policy_decisions": [],
        }

    actions = [
        submit("solved", {"task_ids": [], "results": []}),
        submit("reviewed", {"findings": [], "quality_score": 0.5}),
        submit(
            "audited",
            {"usage_verified": True, "safety_passed": True, "integrity_passed": True},
        ),
        submit("reflect-warrior", {"claims": []}),
        submit("reflect-judge", {"claims": []}),
        submit("reflect-prosecutor", {"claims": []}),
        # No static council entry: the dynamic branch supplies the proposal.
        # A proposing chair also triggers two critiques and three votes.
        submit("critique", {}),
        submit("critique", {}),
        submit("voted", {"decision": "support"}),
        submit("voted", {"decision": "support"}),
        submit("voted", {"decision": "support"}),
        submit("forged", {"task_specs": [task_spec_from_pack()]}),
    ]
    sandbox = WritingFakeSandboxBackend()
    common, store, artifacts, roles, evolution = build_cycle(tmp_path, sandbox=sandbox)
    gateway = AuditAwareGateway(actions, chair_proposal_builder=chair_proposal)
    try:
        with __import__("unittest").mock.patch.object(
            ModelCyclePorts,
            "_shadow_objective_on_history",
            side_effect=AssertionError("shadow solves must not run"),
        ):
            run_v2_cycle(gateway=gateway, **common)
        governed = sorted(
            (artifacts.root / "objective-governance").iterdir(),
            key=lambda p: p.stat().st_mtime,
        )[-1]
        evidence = json.loads(governed.read_text(encoding="utf-8"))
        dumped = json.dumps(evidence, ensure_ascii=False)
        assert "insufficient historical objective shadow coverage" in dumped
        # No shadow arm ever ran.
        assert all(
            "objective-history" not in json.loads(r.messages[1].content).get("context", {})
            for r in gateway.requests
        )
        # The chair envelope now carries the audit-fix context data.
        assert gateway.chair_envelopes
        chair_context = gateway.chair_envelopes[0]["context"]
        assert "runtime_policy_requests" in chair_context
        assert chair_context["objective_history"]["required"] >= 1
    finally:
        store.close()


def test_reflect_strategy_proposals_reach_collection(tmp_path: Path) -> None:
    """Previously the reflect stage read the wrong submit key and the
    prosecutor's proposals were silently dropped."""
    actions = [
        submit("solved", {"task_ids": [], "results": []}),
        submit("reviewed", {"findings": [], "quality_score": 0.5}),
        submit(
            "audited",
            {"usage_verified": True, "safety_passed": True, "integrity_passed": True},
        ),
        submit("reflect-warrior", {"claims": []}),
        submit("reflect-judge", {"claims": []}),
        workflow_propose_action(target="prosecutor", proposal_id="sp-1"),
        submit("reflect-prosecutor", {"claims": []}),
        submit("council", {"proposal": None, "agenda": []}),
        submit("forged", {"task_specs": [task_spec_from_pack()]}),
    ]
    sandbox = WritingFakeSandboxBackend()
    common, store, artifacts, roles, evolution = build_cycle(tmp_path, sandbox=sandbox)
    gateway = AuditAwareGateway(actions)
    try:
        result = run_candidate_cycle(gateway=gateway, **common)
        candidate_evidence = json.loads(
            artifacts.get(result.candidate_evaluation).decode("utf-8")
        )
        rejected = candidate_evidence["rejected"]
        assert any(
            item.get("error", "").startswith("only Warrior-target")
            and item.get("target_role") == "prosecutor"
            for item in rejected
        ), rejected
    finally:
        store.close()


def test_difficulty_signal_rows_flag_fully_solved_tasks() -> None:
    from aegis.cycle_ports import _difficulty_signal_rows

    data = {
        "evaluation": {
            "tasks": [
                {
                    "artifact_id": "task-easy",
                    "public": {"passed": 4, "total": 4},
                    "hidden": {"passed": 6, "total": 6},
                },
                {
                    "artifact_id": "task-hard",
                    "public": {"passed": 4, "total": 4},
                    "hidden": {"passed": 4, "total": 6},
                },
            ]
        }
    }
    rows = _difficulty_signal_rows(data)
    assert len(rows) == 2
    easy = next(r for r in rows if r["task_id"] == "task-easy")
    hard = next(r for r in rows if r["task_id"] == "task-hard")
    assert easy["fully_solved"] is True and easy["quality"] == 1.0
    assert hard["fully_solved"] is False
    assert abs(hard["quality"] - (0.25 * 1.0 + 0.75 * (4 / 6))) < 1e-9


def test_resolve_role_binding_fails_loud_on_missing_manifest(tmp_path: Path) -> None:
    artifacts = ContentAddressedArtifactStore(tmp_path / "artifacts")
    default_workflow_ref, default_subject_ref = materialize_default_artifacts(artifacts)
    identity = __import__("aegis").curriculum.models.RoleVersionIdentity(
        role=Role.WARRIOR,
        version=1,
        artifact_id="role-manifest-sha256:" + "0" * 64,
        artifact_sha256="0" * 64,
        constitution_id="constitution-sha256:" + "0" * 64,
    )
    with pytest.raises(EvolutionRuntimeError, match="failed to resolve"):
        resolve_role_binding(
            artifacts=artifacts,
            evolution=None,
            active_identity=identity,
            role=Role.WARRIOR,
            role_config=role_configs()["warrior"],
            budget_policy_sha256="0" * 64,
            default_image="aegis-inprocess@sha256:" + "0" * 64,
            default_workflow_ref=default_workflow_ref,
            default_subject_ref=default_subject_ref,
        )
