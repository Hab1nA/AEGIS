import base64
import hashlib
import io
import json
import tarfile
import tempfile
import time
import unittest
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from aegis.agent_runtime import Action, ActionError, RoleRunResult, StepLimitExceeded
from aegis.config import CampaignConfig
from aegis.event_store import EventStore
from aegis.evolution_registry import EvolutionCandidateState, EvolutionRegistry
from aegis.evolution_workspace import EvolutionWorkspace
from aegis.gateway.client import GatewayConfig, ModelGateway, RetryPolicy
from aegis.gateway.protocols import Role as GatewayRole
from aegis.gateway.transport import HTTPResponse
from aegis.gateway.types import GatewayResponse, TokenUsage
from aegis.knowledge import KnowledgeStore
from aegis.models import CampaignState, Role
from aegis.orchestrator import (
    CampaignController,
    CampaignHalted,
    SandboxCleanupError,
    _source_consumption_action_guard,
    apply_persisted_control,
    prepare_retryable_failure,
)
from aegis.research.imports import validate_skill_import
from aegis.research.types import Provenance, ResearchArtifact, SearchHit
from aegis.sandbox.fake import FakeSandboxBackend
from aegis.sandbox.types import CommandResult, DoctorCheck, DoctorReport
from aegis.skill_promotion_runtime import NO_SKILL_BASELINE_ID
from aegis.skill_registry import SkillRegistry
from aegis.skill_validation import SkillStaticValidator
from aegis.state_machine import CampaignStateMachine
from aegis.strategy import WorkflowArtifact
from aegis.taskpacks import PythonTaskProvider
from tests.test_taskpack_runtime import make_validated_pack


def config(pack_path: Path, **updates):
    raw = {
        "campaign_id": "toy",
        "max_rounds": 1,
        "total_tokens": 1_000_000,
        "max_requests": 20,
        "wall_time_seconds": 60,
        "sandbox_backend": "fake",
        "test_mode": True,
        "offline_research": True,
        "task_pack_paths": [str(pack_path.resolve())],
        "max_agent_steps": 5,
        "roles": {
            "warrior": {"model": "w", "budget_share": 0.60, "max_output_tokens": 100},
            "judge": {"model": "j", "budget_share": 0.25, "max_output_tokens": 100},
            "prosecutor": {"model": "p", "budget_share": 0.15, "max_output_tokens": 100},
        },
    }
    raw.update(updates)
    if raw.get("acceptance_profile") == "autonomous_evolution_v1" and "roles" not in updates:
        raw["roles"] = {
            "warrior": {"model": "w", "budget_share": 0.55, "max_output_tokens": 4096},
            "judge": {"model": "j", "budget_share": 0.225, "max_output_tokens": 4096},
            "prosecutor": {"model": "p", "budget_share": 0.225, "max_output_tokens": 4096},
        }
    if raw.get("acceptance_profile") == "autonomous_evolution_v1" and "max_agent_steps" not in updates:
        raw["max_agent_steps"] = 20
    return CampaignConfig.from_mapping(raw)


class FakeResearch:
    def __init__(self):
        self.searches = []

    def search(self, query, *, limit=10):
        self.searches.append((query, limit))
        return [SearchHit("https://example.com/advice", "advice", "current practice")]

    def fetch(self, url, *, validate_as_archive=False):
        raise AssertionError("not used")


class FetchResearch(FakeResearch):
    def fetch(self, url, *, validate_as_archive=False):
        content = b"verified reusable research"
        return ResearchArtifact(
            content,
            Provenance(
                requested_url=url,
                final_url=url,
                retrieved_at="2026-01-01T00:00:00+00:00",
                sha256=hashlib.sha256(content).hexdigest(),
                size_bytes=len(content),
                media_type="text/plain",
                redirect_chain=(),
            ),
        )


class ActionGateway:
    def __init__(self, hook=None):
        self.hook, self.calls = hook, []

    def complete(self, request, *, cancel=None):
        envelope = json.loads(request.messages[-1].content)
        role, objective, step = envelope["role"], envelope["objective"], envelope["step"]
        phase = (
            "research"
            if role == "warrior" and objective.startswith("Research")
            else ("warrior" if role == "warrior" else role)
        )
        self.calls.append((phase, step))
        if self.hook:
            self.hook(len(self.calls), phase, step)
        if phase == "research" and step == 1:
            action = {
                "action": "research.search",
                "arguments": {"query": "python repair practices", "limit": 2},
            }
        elif phase == "warrior" and step == 1:
            action = {
                "action": "workspace.write",
                "arguments": {
                    "path": "solution.py",
                    "content_base64": base64.b64encode(b"VALUE = 2\n").decode(),
                },
            }
        elif phase == "warrior" and step == 2:
            action = {
                "action": "sandbox.exec",
                "arguments": {"argv": ["python", "-m", "pytest", "-q", "tests/public"]},
            }
        else:
            action = {
                "action": "submit",
                "arguments": {"summary": f"{phase} complete", "payload": {"strategy_proposals": []}},
            }
        return GatewayResponse(json.dumps(action), TokenUsage(5, 5, 1, 2, True), "fake")


class AttemptTransport:
    """OpenAI transport that can fail attempts before returning role actions."""

    def __init__(self, initial=()):
        self.initial = list(initial)
        self.calls = []

    def post(self, url, *, headers, body, timeout, cancel):
        cancel.raise_if_cancelled()
        payload = json.loads(body)
        self.calls.append((url, payload))
        if self.initial:
            outcome = self.initial.pop(0)
            if isinstance(outcome, BaseException):
                raise outcome
            if isinstance(outcome, int):
                return HTTPResponse(outcome, b'{"error":"planned"}', {})
        messages = payload.get("input", payload.get("messages"))
        envelope = json.loads(messages[-1]["content"])
        role, objective, step = envelope["role"], envelope["objective"], envelope["step"]
        phase = (
            "research"
            if role == "warrior" and objective.startswith("Research")
            else ("warrior" if role == "warrior" else role)
        )
        if phase == "research" and step == 1:
            action = {
                "action": "research.search",
                "arguments": {"query": "python repair practices", "limit": 2},
            }
        elif phase == "warrior" and step == 1:
            action = {
                "action": "workspace.write",
                "arguments": {
                    "path": "solution.py",
                    "content_base64": base64.b64encode(b"VALUE = 2\n").decode(),
                },
            }
        elif phase == "warrior" and step == 2:
            action = {
                "action": "sandbox.exec",
                "arguments": {"argv": ["python", "-m", "pytest", "-q", "tests/public"]},
            }
        else:
            action = {
                "action": "submit",
                "arguments": {"summary": f"{phase} complete", "payload": {"strategy_proposals": []}},
            }
        usage = {
            "input_tokens": 5,
            "output_tokens": 5,
            "input_tokens_details": {"cached_tokens": 1},
            "output_tokens_details": {"reasoning_tokens": 2},
        }
        if url.endswith("/responses"):
            data = {"output_text": json.dumps(action), "usage": usage}
        else:
            data = {
                "choices": [{"message": {"content": json.dumps(action)}}],
                "usage": {
                    "prompt_tokens": 5,
                    "completion_tokens": 5,
                    "prompt_tokens_details": {"cached_tokens": 1},
                    "completion_tokens_details": {"reasoning_tokens": 2},
                },
            }
        return HTTPResponse(200, json.dumps(data).encode(), {"x-request-id": "attempt"})


class InflatedCompatibilityUsageTransport(AttemptTransport):
    def post(self, url, *, headers, body, timeout, cancel):
        response = super().post(
            url,
            headers=headers,
            body=body,
            timeout=timeout,
            cancel=cancel,
        )
        data = json.loads(response.body)
        usage = data["usage"]
        output_key = "output_tokens" if url.endswith("/responses") else "completion_tokens"
        details_key = (
            "output_tokens_details" if url.endswith("/responses") else "completion_tokens_details"
        )
        usage[output_key] = 150
        usage[details_key] = {"reasoning_tokens": 150}
        return HTTPResponse(response.status, json.dumps(data).encode(), response.headers)


def attempt_gateway(transport, *, attempts=2):
    return ModelGateway(
        GatewayConfig("https://relay.invalid/v1", "secret"),
        transport=transport,
        retry=RetryPolicy(attempts, 0, 0),
        sleeper=lambda _: None,
    )


class InspectingJudgeGateway(ActionGateway):
    def complete(self, request, *, cancel=None):
        envelope = json.loads(request.messages[-1].content)
        if envelope["role"] == "judge":
            step = envelope["step"]
            self.calls.append(("judge", step))
            if step == 1:
                action = {"action": "workspace.read", "arguments": {"path": "answer.py"}}
            elif step == 2:
                action = {
                    "action": "sandbox.exec",
                    "arguments": {"argv": ["python", "-m", "pytest", "-q", "tests/public"]},
                }
            else:
                action = {
                    "action": "submit",
                    "arguments": {
                        "summary": "judge inspected submission",
                        "payload": {"strategy_proposals": []},
                    },
                }
            return GatewayResponse(json.dumps(action), TokenUsage(5, 5, 1, 2, True), "fake")
        return super().complete(request, cancel=cancel)


class InvalidJudgeGateway(ActionGateway):
    def complete(self, request, *, cancel=None):
        envelope = json.loads(request.messages[-1].content)
        if envelope["role"] == "judge":
            action = {
                "action": "workspace.write",
                "arguments": {"path": "forbidden.py", "content_base64": ""},
            }
            return GatewayResponse(json.dumps(action), TokenUsage(5, 5, verified=True), "fake")
        return super().complete(request, cancel=cancel)


class InspectingProsecutorGateway(ActionGateway):
    def complete(self, request, *, cancel=None):
        envelope = json.loads(request.messages[-1].content)
        if envelope["role"] == "prosecutor":
            step = envelope["step"]
            self.calls.append(("prosecutor", step))
            if step == 1:
                action = {"action": "workspace.read", "arguments": {"path": "answer.py"}}
            else:
                action = {
                    "action": "submit",
                    "arguments": {
                        "summary": "prosecutor inspected submission",
                        "payload": {"strategy_proposals": []},
                    },
                }
            return GatewayResponse(json.dumps(action), TokenUsage(5, 5, verified=True), "fake")
        return super().complete(request, cancel=cancel)


class InvalidProsecutorGateway(ActionGateway):
    def complete(self, request, *, cancel=None):
        envelope = json.loads(request.messages[-1].content)
        if envelope["role"] == "prosecutor":
            action = {
                "action": "workspace.write",
                "arguments": {"path": "forbidden.py", "content_base64": ""},
            }
            return GatewayResponse(json.dumps(action), TokenUsage(5, 5, verified=True), "fake")
        return super().complete(request, cancel=cancel)


class EvidenceGateway(ActionGateway):
    def __init__(self):
        super().__init__()
        self.prosecutor_context = None

    def complete(self, request, *, cancel=None):
        envelope = json.loads(request.messages[-1].content)
        if envelope["role"] == "prosecutor":
            self.prosecutor_context = envelope["context"]
        return super().complete(request, cancel=cancel)


class CrossRoundKnowledgeGateway(ActionGateway):
    def __init__(self):
        super().__init__()
        self.search_result = None

    def complete(self, request, *, cancel=None):
        envelope = json.loads(request.messages[-1].content)
        if envelope["role"] == "warrior" and envelope["objective"].startswith("Research"):
            seed = envelope["context"]["seed"]
            step = envelope["step"]
            self.calls.append(("research", step))
            if seed == 0 and step == 1:
                action = {
                    "action": "research.fetch",
                    "arguments": {"url": "https://example.test/research"},
                }
            elif seed == 0 and step == 2:
                digest = envelope["observations"][0]["result"]["provenance"]["sha256"]
                action = {
                    "action": "knowledge.remember",
                    "arguments": {
                        "sha256": digest,
                        "summary": "State machine verification prevents regressions.",
                        "tags": ["testing"],
                        "applicable_roles": ["warrior"],
                        "experiment_result": "Verified in round one.",
                    },
                }
            elif seed == 1 and step == 1:
                action = {
                    "action": "knowledge.search",
                    "arguments": {"query": "state machine", "limit": 5},
                }
            else:
                if seed == 1:
                    self.search_result = envelope["observations"][0]["result"]
                action = {
                    "action": "submit",
                    "arguments": {
                        "summary": "research complete",
                        "payload": {"strategy_proposals": []},
                    },
                }
            return GatewayResponse(json.dumps(action), TokenUsage(5, 5, verified=True), "fake")
        return super().complete(request, cancel=cancel)


class EvolutionRequestGateway(ActionGateway):
    def complete(self, request, *, cancel=None):
        envelope = json.loads(request.messages[-1].content)
        objective = envelope["objective"]
        if envelope["role"] == "warrior" and objective.startswith("Implement"):
            self.calls.append(("warrior", envelope["step"]))
            if envelope["step"] == 1:
                action = {
                    "action": "evolution.request",
                    "arguments": {
                        "objective": "Improve the sandboxed workflow verification checklist.",
                        "rationale": "The current checklist misses a focused regression step.",
                    },
                }
            else:
                action = {
                    "action": "submit",
                    "arguments": {"summary": "warrior complete", "payload": {}},
                }
            return GatewayResponse(json.dumps(action), TokenUsage(5, 5, verified=True), "fake")
        if envelope["role"] == "warrior" and objective.startswith(
            "Create and verify one isolated self-improvement candidate"
        ):
            self.calls.append(("evolution", envelope["step"]))
            if envelope["step"] == 1:
                content = b"WORKFLOW_VERSION = 'candidate'\n"
                action = {
                    "action": "workspace.write",
                    "arguments": {
                        "path": "src/aegis/evolvable/workflow.py",
                        "content_base64": base64.b64encode(content).decode(),
                    },
                }
            else:
                action = {
                    "action": "submit",
                    "arguments": {"summary": "candidate complete", "payload": {}},
                }
            return GatewayResponse(json.dumps(action), TokenUsage(5, 5, verified=True), "fake")
        return super().complete(request, cancel=cancel)


class AdvisoryGateway(ActionGateway):
    def __init__(self):
        super().__init__()
        self.objectives = []

    def complete(self, request, *, cancel=None):
        envelope = json.loads(request.messages[-1].content)
        self.objectives.append((envelope["role"], envelope["objective"]))
        return super().complete(request, cancel=cancel)


class FakeChampionRegistry:
    def __init__(self):
        self.archive = SimpleNamespace(version=3, artifact_id="candidate-sha256:" + "a" * 64)
        self.closed = False

    def champion_archive(self):
        return self.archive

    def close(self):
        self.closed = True


class FakeEvolutionCanary:
    def __init__(self):
        self.calls = []

    def run(self, candidate, *, role, context, run_id):
        self.calls.append((candidate, role, context, run_id))
        workflow = WorkflowArtifact(
            stage_plan=("Inspect", "Verify"),
            research_query_templates=("{task} exact source",),
            tool_selection_rules=("Prefer the focused regression test.",),
            stop_conditions=("Stop after verified completion.",),
            verification_checklist=("Run the focused regression test.",),
            skill_references=("registry:promoted-champions-only",),
            max_steps=4,
        )
        return SimpleNamespace(
            passed=True,
            workflow=workflow,
            failure_reason=None,
            to_mapping=lambda: {"passed": True, "workflow": workflow.to_dict()},
        )


class RecordingSandbox(FakeSandboxBackend):
    def __init__(self):
        super().__init__(executor=self._execute)
        self.staged_members = []
        self.prepare_calls = []

    def prepare(self, sandbox_id):
        self.prepare_calls.append(sandbox_id)
        return super().prepare(sandbox_id)

    def _execute(self, sandbox_id, command):
        if command.argv[0] == "python3" and command.argv[-2] == "answer.py":
            content = self._files[sandbox_id]["answer.py"]
            assert isinstance(content, bytes)
            return CommandResult(0, base64.b64encode(content).decode("ascii"), "", 0.01)
        if "pytest" in command.argv:
            return CommandResult(0, "1 passed in 0.01s", "", 0.01)
        return CommandResult(0, "", "", 0.01)

    def stage_archive(self, sandbox_id, archive_base64, expected_digest):
        payload = base64.b64decode(archive_base64)
        with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
            self.staged_members.append((sandbox_id, tuple(item.name for item in archive.getmembers())))
        return super().stage_archive(sandbox_id, archive_base64, expected_digest)

    def evaluate_sealed(self, sandbox_id, archive_base64, expected_digest, timeout_seconds):
        payload = base64.b64decode(archive_base64)
        with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
            self.staged_members.append(
                (sandbox_id, tuple(f"tests/hidden/{item.name}" for item in archive.getmembers()))
            )
        return super().evaluate_sealed(sandbox_id, archive_base64, expected_digest, timeout_seconds)


class EvolutionRecordingSandbox(RecordingSandbox):
    def doctor(self):
        return DoctorReport((DoctorCheck("network_none", True, "test isolation"),))

    def _execute(self, sandbox_id, command):
        if command.argv[:2] == ("python3", "-c") and "target.write_bytes" in command.argv[2]:
            path, encoded = command.argv[3], command.argv[4]
            self._files[sandbox_id][path] = base64.b64decode(encoded)
            return CommandResult(0, str(len(self._files[sandbox_id][path])), "", 0.01)
        if "pytest" in command.argv:
            return CommandResult(0, "300 passed", "", 0.01)
        return super()._execute(sandbox_id, command)


class FailingEvolutionSandbox(EvolutionRecordingSandbox):
    def _execute(self, sandbox_id, command):
        if "pytest" in command.argv:
            return CommandResult(1, "1 failed", "candidate regression", 0.01)
        return super()._execute(sandbox_id, command)


class OrchestratorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.pack, self.validation = make_validated_pack(self.root / "pack")
        self.controllers = []

    def tearDown(self):
        for controller in self.controllers:
            controller.close()
        self.temp.cleanup()

    def controller(
        self,
        *,
        cfg=None,
        gateway=None,
        sandbox=None,
        research=None,
        knowledge=None,
        skills=None,
        evolution_workspace=None,
        evolution_registry=None,
        clock=None,
    ):
        backend = sandbox or RecordingSandbox()
        provider = PythonTaskProvider(((self.pack, self.validation),), backend)
        value = CampaignController(
            cfg or config(self.pack.root),
            EventStore(self.root / "events.db"),
            gateway or ActionGateway(),
            backend,
            provider,
            research or FakeResearch(),
            knowledge=knowledge,
            skills=skills,
            evolution_workspace=evolution_workspace,
            evolution_registry=evolution_registry,
            **({} if clock is None else {"clock": clock}),
        )
        self.controllers.append(value)
        return value

    def test_real_tool_loop_evaluates_hidden_and_locks_quality_before_prosecutor(self):
        research = FakeResearch()
        sandbox = RecordingSandbox()
        gateway = ActionGateway()
        ctrl = self.controller(gateway=gateway, sandbox=sandbox, research=research)
        status = ctrl.start()
        self.assertEqual(status.state, "completed")
        self.assertTrue(research.searches)
        self.assertTrue(any("solution.py" in command.argv for _, command in sandbox.commands))
        events = ctrl._events()
        quality_index = next(i for i, event in enumerate(events) if event["event_type"] == "quality_locked")
        prosecutor_index = next(
            i
            for i, event in enumerate(events)
            if event["event_type"] == "role_output" and event["payload"]["phase"] == "prosecutor"
        )
        self.assertLess(quality_index, prosecutor_index)
        hidden_stages = [
            (box, members)
            for box, members in sandbox.staged_members
            if any(name.startswith("tests/hidden") for name in members)
        ]
        self.assertTrue(hidden_stages)
        self.assertTrue(all(box.startswith("judge-") for box, _ in hidden_stages))
        evaluator_ids = {
            event["payload"]["sandbox_id"]
            for event in events
            if event["event_type"] == "sandbox_prepare_intent"
            and str(event["payload"]["sandbox_id"]).startswith("judge-")
        }
        self.assertTrue(evaluator_ids)
        self.assertTrue(
            evaluator_ids
            <= {
                event["payload"]["sandbox_id"]
                for event in events
                if event["event_type"] == "sandbox_prepared"
            }
        )
        decision = next(
            event["payload"]["decision"] for event in events if event["event_type"] == "promotion_decided"
        )
        self.assertTrue(decision["pending"])
        self.assertEqual(decision["required_pairs"], 24)

    def test_prosecutor_receives_bounded_warrior_and_judge_evidence(self):
        gateway = EvidenceGateway()
        ctrl = self.controller(gateway=gateway)
        self.assertEqual(ctrl.start().state, "completed")
        context = gateway.prosecutor_context
        self.assertIsNotNone(context)
        self.assertEqual(context["warrior_evidence"]["role"], "warrior")
        self.assertEqual(context["judge_evidence"]["role"], "judge")
        actions = [item["action"] for item in context["warrior_evidence"]["observations"]]
        self.assertEqual(actions, ["workspace.write", "sandbox.exec", "submit"])
        execution = context["warrior_evidence"]["observations"][1]["result"]
        self.assertNotIn("stdout", execution)
        self.assertNotIn("stderr", execution)
        self.assertIn("stdout_sha256", execution)
        self.assertIn("stderr_sha256", execution)

    def test_promoted_workflow_max_steps_applies_to_normal_role_phase(self):
        gateway = ActionGateway()
        ctrl = self.controller(gateway=gateway)
        ctrl._strategies.initialize(
            Role.WARRIOR,
            WorkflowArtifact(
                stage_plan=("Inspect",),
                research_query_templates=("{task} current practice",),
                tool_selection_rules=("Use verified tools.",),
                stop_conditions=("Stop after the bounded attempt.",),
                verification_checklist=("Run the relevant check.",),
                skill_references=("builtin:none",),
                max_steps=1,
            ),
        )
        with self.assertRaisesRegex(StepLimitExceeded, "within 1 model steps"):
            ctrl.start()
        self.assertEqual(gateway.calls, [("research", 1)])

    def test_autonomous_research_alone_enables_eager_required_convergence(self):
        output = RoleRunResult(GatewayRole.WARRIOR, "done", {}, (), ())

        for acceptance_profile, expected, expected_required in (
            (
                "autonomous_evolution_v1",
                True,
                (
                    frozenset({"research.search"}),
                    frozenset({"github.resolve"}),
                    frozenset({"github.collect"}),
                    frozenset({"github.file_read"}),
                    frozenset({"github.skill_bundle"}),
                    frozenset({"knowledge.remember"}),
                    frozenset({"strategy.propose"}),
                ),
            ),
            (None, False, (frozenset({"knowledge.search", "research.recall", "research.search"}),)),
        ):
            ctrl = self.controller(
                cfg=config(
                    self.pack.root,
                    acceptance_profile=acceptance_profile,
                    test_mode=False,
                    offline_research=False,
                    sandbox_backend="wsl",
                )
            )
            ctrl._sandbox_id = "box"
            ctrl._phase_start = Mock()
            ctrl._phase_complete = Mock()
            ctrl._append = Mock()
            with patch("aegis.orchestrator.RoleAgentRuntime") as runtime_class:
                runtime_class.return_value.run.return_value = output
                ctrl._role_phase(1, "research", GatewayRole.WARRIOR, "research", {})

            self.assertEqual(
                ctrl._required_actions(1, "research", GatewayRole.WARRIOR), expected_required
            )
            self.assertIs(
                runtime_class.call_args.kwargs["eager_required_convergence"], expected
            )
            self.assertEqual(
                runtime_class.return_value.run.call_args.kwargs["required_action_groups"],
                expected_required,
            )

            self.assertFalse(runtime_class.call_args.kwargs["ordered_required_action_gate"])

        self.assertEqual(
            ctrl._required_actions(1, "judge", GatewayRole.JUDGE),
            (frozenset({"knowledge.search", "research.recall", "research.search"}),),
        )

    def test_round_feedback_is_durable_and_available_to_the_next_warrior_round(self):
        ctrl = self.controller()
        payload = ctrl._round_feedback_payload(
            1,
            {"score": 0.4, "accepted": False, "safety_violations": ["hidden failure"]},
            {"summary": "Probe boundary values.", "submission": {}, "observations": (), "tokens": 10},
            {"summary": "Reduce repeated calls.", "submission": {}, "observations": (), "tokens": 12},
        )
        ctrl._append("round_feedback_recorded", payload)

        observed = ctrl._prior_round_feedback(2)

        self.assertIsNotNone(observed)
        assert observed is not None
        self.assertEqual(observed["feedback_id"], payload["feedback_id"])
        self.assertEqual([item["feedback_id"] for item in observed["items"]], ["quality", "judge", "prosecutor"])

    def test_formal_warrior_requires_source_bound_evolution_request(self):
        registry = Mock()
        registry.champion_archive.return_value = None
        ctrl = self.controller(
            cfg=config(
                self.pack.root,
                test_mode=False,
                offline_research=False,
                sandbox_backend="wsl",
            ),
            evolution_workspace=EvolutionWorkspace(Path(__file__).resolve().parents[1]),
            evolution_registry=registry,
        )
        ctrl._append(
            "role_output",
            {"round": 1, "phase": "warrior", "output": {"submission": {"evolution_requests": [{}]}}},
        )
        ctrl._state = CampaignState.PROMOTION_GATE
        ctrl._machine = CampaignStateMachine(CampaignState.PROMOTION_GATE)

        with patch.object(
            ctrl,
            "_evolution_request",
            return_value=("evolution-request-sha256:" + "1" * 64, "improve workflow", ()),
        ):
            with self.assertRaisesRegex(RuntimeError, "GitHub and paper evidence"):
                ctrl._run_evolution_request(1)

        self.assertEqual(
            ctrl._required_actions(1, "warrior", GatewayRole.WARRIOR),
            (frozenset({"evolution.request"}),),
        )

    def test_formal_warrior_cannot_skip_evolution_request(self):
        registry = Mock()
        ctrl = self.controller(
            cfg=config(
                self.pack.root,
                test_mode=False,
                offline_research=False,
                sandbox_backend="wsl",
            ),
            evolution_workspace=EvolutionWorkspace(Path(__file__).resolve().parents[1]),
            evolution_registry=registry,
        )
        ctrl._append("role_output", {"round": 1, "phase": "warrior", "output": {"submission": {}}})
        ctrl._state = CampaignState.PROMOTION_GATE
        ctrl._machine = CampaignStateMachine(CampaignState.PROMOTION_GATE)

        with self.assertRaisesRegex(RuntimeError, "must contain one source-bound evolution request"):
            ctrl._run_evolution_request(1)

        registry.champion_archive.assert_not_called()

    def test_candidate_source_gate_blocks_workspace_before_bound_sources_are_read(self):
        guard = _source_consumption_action_guard(
            (
                {
                    "artifact_id": "sha256:" + "1" * 64,
                    "kind": "github",
                    "content_sha256": "2" * 64,
                    "locator": "path:src/example.py",
                    "blob_sha256": "3" * 64,
                },
            )
        )

        with self.assertRaises(ActionError):
            guard(Action("workspace.read", {"path": "src/aegis/evolvable/workflow.py"}), ())

    def test_candidate_source_gate_requires_recall_before_bound_artifact_read(self):
        source = {
            "artifact_id": "sha256:" + "1" * 64,
            "kind": "github",
            "content_sha256": "2" * 64,
            "locator": "path:src/example.py",
            "blob_sha256": "3" * 64,
        }
        guard = _source_consumption_action_guard((source,))
        read = Action(
            "research.artifact_read",
            {"artifact_id": source["artifact_id"], "locator": source["locator"]},
        )

        with self.assertRaisesRegex(ActionError, "must be recalled before artifact read"):
            guard(read, ())

        guard(
            read,
            (
                SimpleNamespace(
                    action="research.recall",
                    result={"sha256": source["content_sha256"]},
                    step=1,
                ),
            ),
        )

    def test_formal_candidate_uses_identity_bound_source_ordering(self):
        source_refs = (
            {
                "artifact_id": "a" * 64,
                "kind": "github",
                "content_sha256": "b" * 64,
                "blob_sha256": "c" * 64,
                "locator": "path:src/example.py",
            },
            {
                "artifact_id": "d" * 64,
                "kind": "paper",
                "content_sha256": "e" * 64,
                "blob_sha256": "f" * 64,
                "locator": "page:1",
            },
        )
        registry = Mock()
        registry.champion_archive.return_value = None
        registry.candidate_for_request.return_value = None
        ctrl = self.controller(
            cfg=config(
                self.pack.root,
                acceptance_profile="autonomous_evolution_v1",
                test_mode=False,
                offline_research=False,
                sandbox_backend="wsl",
            ),
            evolution_workspace=EvolutionWorkspace(Path(__file__).resolve().parents[1]),
            evolution_registry=registry,
        )
        ctrl._append(
            "role_output",
            {"round": 1, "phase": "warrior", "output": {"submission": {"evolution_requests": [{}]}}},
        )
        ctrl._state = CampaignState.PROMOTION_GATE
        ctrl._machine = CampaignStateMachine(CampaignState.PROMOTION_GATE)

        with (
            patch.object(
                ctrl,
                "_evolution_request",
                return_value=("evolution-request-sha256:" + "1" * 64, "improve workflow", source_refs),
            ),
            patch("aegis.orchestrator.RoleAgentRuntime") as runtime_class,
        ):
            runtime_class.return_value.run.side_effect = RuntimeError("stop after construction")
            with self.assertRaisesRegex(RuntimeError, "stop after construction"):
                ctrl._run_evolution_request(1)

        self.assertFalse(runtime_class.call_args.kwargs["ordered_required_action_gate"])

    def test_paused_campaign_does_not_start_evolution_candidate_work(self):
        ctrl = self.controller(
            evolution_workspace=EvolutionWorkspace(Path(__file__).resolve().parents[1]),
            evolution_registry=Mock(),
        )
        ctrl._state = CampaignState.PAUSED
        ctrl._resume_target = CampaignState.PROMOTION_GATE
        ctrl._machine = CampaignStateMachine(
            CampaignState.PAUSED, resume_target=CampaignState.PROMOTION_GATE
        )

        ctrl._run_evolution_request(1)

        self.assertFalse(
            any(event["event_type"] == "evolution_request_started" for event in ctrl._events())
        )

    def test_evolution_promotion_budget_shortage_pauses_for_resume(self):
        ctrl = self.controller(
            evolution_workspace=EvolutionWorkspace(Path(__file__).resolve().parents[1]),
            evolution_registry=Mock(),
        )
        ctrl.evolution_canary = Mock()
        ctrl._state = CampaignState.PROMOTION_GATE
        ctrl._machine = CampaignStateMachine(CampaignState.PROMOTION_GATE)
        ctrl.tasks.promotion_task_ids = Mock(return_value=tuple(f"task-{index}" for index in range(12)))
        summary = SimpleNamespace(
            candidates_seen=1,
            pairs_added=0,
            promoted=(),
            rejected=(),
            pending_for_budget=True,
        )

        with patch("aegis.orchestrator.EvolutionPromotionScheduler") as scheduler:
            scheduler.return_value.run_pending.return_value = summary
            ctrl._run_evolution_promotions()

        self.assertEqual(ctrl.status().state, "paused")
        self.assertEqual(ctrl.status().stop_reason, None)
        self.assertTrue(
            any(
                event["event_type"] == "evolution_promotion_paused_for_budget"
                for event in ctrl._events()
            )
        )

    def test_autonomous_warrior_phase_uses_ordered_actions_without_eager_submit(self):
        output = RoleRunResult(GatewayRole.WARRIOR, "done", {}, (), ())
        ctrl = self.controller(
            cfg=config(
                self.pack.root,
                acceptance_profile="autonomous_evolution_v1",
                test_mode=False,
                offline_research=False,
                sandbox_backend="wsl",
            )
        )
        ctrl._sandbox_id = "box"
        ctrl._phase_start = Mock()
        ctrl._phase_complete = Mock()
        ctrl._append = Mock()
        expected_required = tuple(
            frozenset({action})
            for action in (
                "research.search",
                "paper.collect",
                "paper.excerpt_read",
                "research.recall",
                "github.file_read",
                "workspace.read",
                "workspace.write",
                "sandbox.exec",
                "evolution.request",
            )
        )
        with patch("aegis.orchestrator.RoleAgentRuntime") as runtime_class:
            runtime_class.return_value.run.return_value = output
            ctrl._role_phase(1, "warrior", GatewayRole.WARRIOR, "implement", {})

        self.assertEqual(ctrl._required_actions(1, "warrior", GatewayRole.WARRIOR), expected_required)
        self.assertFalse(runtime_class.call_args.kwargs["eager_required_convergence"])
        self.assertTrue(runtime_class.call_args.kwargs["ordered_required_action_gate"])
        self.assertEqual(
            runtime_class.return_value.run.call_args.kwargs["required_action_groups"], expected_required
        )
        self.assertEqual(
            ctrl._required_actions(2, "warrior", GatewayRole.WARRIOR),
            tuple(
                frozenset({action})
                for action in ("workspace.read", "workspace.write", "sandbox.exec", "evolution.request")
            ),
        )

    def test_verified_knowledge_is_reused_by_warrior_in_a_later_round(self):
        gateway = CrossRoundKnowledgeGateway()
        knowledge = KnowledgeStore(self.root / "knowledge.sqlite3")
        ctrl = self.controller(
            cfg=config(self.pack.root, max_rounds=2),
            gateway=gateway,
            research=FetchResearch(),
            knowledge=knowledge,
        )
        self.assertEqual(ctrl.start().state, "completed")
        self.assertIsNotNone(gateway.search_result)
        self.assertEqual(len(gateway.search_result["artifacts"]), 1)
        self.assertEqual(
            gateway.search_result["artifacts"][0]["summary"],
            "State machine verification prevents regressions.",
        )

    def test_warrior_evolution_request_creates_validated_pending_candidate_once(self):
        sandbox = EvolutionRecordingSandbox()
        registry = EvolutionRegistry(self.root / "evolution.sqlite3")
        workspace = EvolutionWorkspace(Path(__file__).resolve().parents[1])
        ctrl = self.controller(
            gateway=EvolutionRequestGateway(),
            sandbox=sandbox,
            evolution_workspace=workspace,
            evolution_registry=registry,
        )
        self.assertEqual(ctrl.start().state, "completed")
        events = ctrl._events()
        completed = [event for event in events if event["event_type"] == "evolution_request_completed"]
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0]["payload"]["status"], "pending")
        registered = [event for event in events if event["event_type"] == "evolution_candidate_registered"]
        self.assertEqual(len(registered), 1)
        record = registry.candidate(registered[0]["payload"]["artifact_id"])
        self.assertIs(record.state, EvolutionCandidateState.CANDIDATE)
        self.assertEqual(ctrl.run().state, "completed")
        self.assertEqual(
            len(
                [
                    event
                    for event in ctrl._events()
                    if event["event_type"] == "evolution_candidate_registered"
                ]
            ),
            1,
        )
        evolution_usage = [
            event
            for event in events
            if event["event_type"] == "usage_committed"
            and event["payload"].get("phase") == "evolution"
        ]
        self.assertEqual(len(evolution_usage), 2)
        self.assertTrue(all(event["payload"]["verified"] for event in evolution_usage))
        self.assertFalse(any("-evo-" in sandbox_id for sandbox_id in sandbox.prepared))

    def test_acceptance_pauses_once_after_second_generation_inherits_champion(self):
        registry = Mock()
        registry.candidate.return_value = SimpleNamespace(
            artifact_id="candidate-sha256:" + "2" * 64,
            parent_champion_id="candidate-sha256:" + "1" * 64,
            baseline_archive_digest="a" * 64,
            state=EvolutionCandidateState.CANDIDATE,
        )
        registry.validation.return_value = SimpleNamespace(passed=True, evidence_id="validation-sha256:" + "3" * 64)
        ctrl = self.controller(
            cfg=config(
                self.pack.root,
                max_rounds=2,
                acceptance_profile="autonomous_evolution_v1",
            ),
            evolution_workspace=EvolutionWorkspace(Path(__file__).resolve().parents[1]),
            evolution_registry=registry,
        )
        ctrl._append(
            "evolution_candidate_collected",
            {
                "round": 2,
                "request_id": "evolution-request-sha256:" + "4" * 64,
                "artifact_id": "candidate-sha256:" + "2" * 64,
            },
        )
        ctrl._append(
            "evolution_candidate_registered",
            {
                "round": 2,
                "request_id": "evolution-request-sha256:" + "4" * 64,
                "artifact_id": "candidate-sha256:" + "2" * 64,
                "state": "candidate",
                "evidence_id": "validation-sha256:" + "3" * 64,
            },
        )
        ctrl._append(
            "evolution_request_completed",
            {
                "round": 2,
                "request_id": "evolution-request-sha256:" + "4" * 64,
                "status": "pending",
            },
        )
        ctrl._state = CampaignState.PROMOTION_GATE
        ctrl._machine = CampaignStateMachine(CampaignState.PROMOTION_GATE)

        ctrl._pause_after_acceptance_inheritance(2)
        ctrl._pause_after_acceptance_inheritance(2)

        self.assertEqual(ctrl.status().state, "paused")
        observed = [
            event
            for event in ctrl._events()
            if event["event_type"] == "autonomy_acceptance_inheritance_observed"
        ]
        self.assertEqual(len(observed), 1)
        self.assertEqual(
            observed[0]["payload"]["parent_champion_id"],
            "candidate-sha256:" + "1" * 64,
        )

    def test_acceptance_inheritance_does_not_pause_after_failed_validation(self):
        registry = Mock()
        registry.candidate.return_value = SimpleNamespace(
            artifact_id="candidate-sha256:" + "2" * 64,
            parent_champion_id="candidate-sha256:" + "1" * 64,
            baseline_archive_digest="a" * 64,
            state=EvolutionCandidateState.VALIDATION_FAILED,
        )
        registry.validation.return_value = SimpleNamespace(passed=False, evidence_id="validation-sha256:" + "3" * 64)
        ctrl = self.controller(
            cfg=config(
                self.pack.root,
                max_rounds=2,
                acceptance_profile="autonomous_evolution_v1",
            ),
            evolution_workspace=EvolutionWorkspace(Path(__file__).resolve().parents[1]),
            evolution_registry=registry,
        )
        ctrl._append(
            "evolution_candidate_collected",
            {
                "round": 2,
                "request_id": "evolution-request-sha256:" + "4" * 64,
                "artifact_id": "candidate-sha256:" + "2" * 64,
            },
        )
        ctrl._state = CampaignState.PROMOTION_GATE
        ctrl._machine = CampaignStateMachine(CampaignState.PROMOTION_GATE)

        ctrl._pause_after_acceptance_inheritance(2)

        self.assertEqual(ctrl.status().state, "promotion_gate")
        self.assertFalse(
            any(
                event["event_type"] == "autonomy_acceptance_inheritance_observed"
                for event in ctrl._events()
            )
        )

    def test_evolution_request_recovers_registry_commit_without_regenerating_candidate(self):
        class CrashAfterOriginCommit(EvolutionRegistry):
            crashed = False

            def register_collected(self, *args, **kwargs):
                record = super().register_collected(*args, **kwargs)
                if not self.crashed:
                    self.crashed = True
                    raise KeyboardInterrupt("simulated crash after registry commit")
                return record

        sandbox = EvolutionRecordingSandbox()
        gateway = EvolutionRequestGateway()
        db = self.root / "recover-evolution.sqlite3"
        first_registry = CrashAfterOriginCommit(db)
        first = self.controller(
            gateway=gateway,
            sandbox=sandbox,
            evolution_workspace=EvolutionWorkspace(Path(__file__).resolve().parents[1]),
            evolution_registry=first_registry,
        )
        with self.assertRaisesRegex(KeyboardInterrupt, "registry commit"):
            first.start()
        request_event = next(
            event for event in first._events() if event["event_type"] == "evolution_request_started"
        )
        request_id = request_event["payload"]["request_id"]
        durable_artifact = first_registry.candidate_for_request(request_id)
        self.assertIsNotNone(durable_artifact)
        self.assertFalse(
            any(event["event_type"] == "evolution_candidate_collected" for event in first._events())
        )
        evolution_calls = len([call for call in gateway.calls if call[0] == "evolution"])
        first.close()
        self.controllers.remove(first)

        resumed_registry = EvolutionRegistry(db)
        resumed = self.controller(
            gateway=gateway,
            sandbox=sandbox,
            evolution_workspace=EvolutionWorkspace(Path(__file__).resolve().parents[1]),
            evolution_registry=resumed_registry,
        )
        self.assertEqual(resumed.resume().state, "completed")
        self.assertEqual(
            len([call for call in gateway.calls if call[0] == "evolution"]), evolution_calls
        )
        collected = [
            event
            for event in resumed._events()
            if event["event_type"] == "evolution_candidate_collected"
        ]
        self.assertEqual(len(collected), 1)
        self.assertTrue(collected[0]["payload"]["recovered"])
        self.assertEqual(collected[0]["payload"]["artifact_id"], durable_artifact.artifact_id)
        self.assertEqual(resumed.run().state, "completed")
        self.assertEqual(
            len(
                [
                    event
                    for event in resumed._events()
                    if event["event_type"] == "evolution_candidate_collected"
                ]
            ),
            1,
        )

    def test_failed_evolution_validation_is_not_registered_and_cleans_sandboxes(self):
        sandbox = FailingEvolutionSandbox()
        registry = EvolutionRegistry(self.root / "failed-evolution.sqlite3")
        ctrl = self.controller(
            gateway=EvolutionRequestGateway(),
            sandbox=sandbox,
            evolution_workspace=EvolutionWorkspace(Path(__file__).resolve().parents[1]),
            evolution_registry=registry,
        )
        self.assertEqual(ctrl.start().state, "completed")
        completed = [
            event
            for event in ctrl._events()
            if event["event_type"] == "evolution_request_completed"
        ]
        self.assertEqual(completed[0]["payload"]["status"], "validation-failed")
        self.assertEqual(registry.champion(), None)
        self.assertFalse(
            any(event["event_type"] == "evolution_candidate_registered" for event in ctrl._events())
        )
        self.assertFalse(sandbox.prepared)

    def test_promoted_evolution_code_only_influences_roles_through_canary_advisory(self):
        gateway = AdvisoryGateway()
        registry = FakeChampionRegistry()
        canary = FakeEvolutionCanary()
        backend = EvolutionRecordingSandbox()
        provider = PythonTaskProvider(((self.pack, self.validation),), backend)
        ctrl = CampaignController(
            config(self.pack.root),
            EventStore(self.root / "canary-events.db"),
            gateway,
            backend,
            provider,
            FakeResearch(),
            evolution_workspace=object(),  # type: ignore[arg-type]
            evolution_registry=registry,  # type: ignore[arg-type]
            evolution_canary=canary,  # type: ignore[arg-type]
        )
        self.controllers.append(ctrl)
        self.assertEqual(ctrl.start().state, "completed")
        self.assertEqual([call[1] for call in canary.calls], ["warrior", "warrior", "judge", "prosecutor"])
        self.assertTrue(
            all(
                "promoted-evolution-advisory" in objective
                for _role, objective in gateway.objectives
            )
        )
        events = [
            event for event in ctrl._events() if event["event_type"] == "evolution_canary_evaluated"
        ]
        self.assertEqual(len(events), 4)
        self.assertTrue(all(event["payload"]["result"]["passed"] for event in events))

    def test_judge_reads_and_executes_only_in_fresh_public_review_sandbox(self):
        sandbox = RecordingSandbox()
        ctrl = self.controller(gateway=InspectingJudgeGateway(), sandbox=sandbox)
        self.assertEqual(ctrl.start().state, "completed")
        review_commands = [(box, command) for box, command in sandbox.commands if "-review-r" in box]
        self.assertTrue(any(command.argv[0] == "python3" for _, command in review_commands))
        self.assertTrue(any("pytest" in command.argv for _, command in review_commands))
        review_stages = [members for box, members in sandbox.staged_members if "-review-r" in box]
        self.assertEqual(len(review_stages), 1)
        self.assertFalse(
            any("hidden" in name or "reference" in name or "mutants" in name for name in review_stages[0])
        )
        self.assertFalse(any("-review-r" in box for box in sandbox.prepared))

    def test_judge_failure_cleans_review_and_warrior_sandboxes(self):
        sandbox = RecordingSandbox()
        ctrl = self.controller(gateway=InvalidJudgeGateway(), sandbox=sandbox)
        with self.assertRaisesRegex(StepLimitExceeded, "judge did not submit within 5 model steps"):
            ctrl.start()
        self.assertEqual(ctrl.status().state, "failed")
        self.assertFalse(sandbox.prepared)
        self.assertTrue(
            any(
                item["event_type"] == "sandbox_destroyed" and "-review-r" in item["payload"]["sandbox_id"]
                for item in ctrl._events()
            )
        )

    def test_campaign_error_records_bounded_traceback_detail(self):
        sandbox = RecordingSandbox()
        ctrl = self.controller(gateway=InvalidJudgeGateway(), sandbox=sandbox)
        with self.assertRaisesRegex(StepLimitExceeded, "judge did not submit"):
            ctrl.start()
        error = next(
            event["payload"]
            for event in ctrl._events()
            if event["event_type"] == "campaign_error"
        )
        self.assertEqual(error["type"], "StepLimitExceeded")
        self.assertIn("Traceback (most recent call last)", error["detail"])
        self.assertLessEqual(len(error["detail"]), 8192)

    def test_prosecutor_reads_frozen_artifact_only_in_fresh_audit_sandbox(self):
        sandbox = RecordingSandbox()
        ctrl = self.controller(gateway=InspectingProsecutorGateway(), sandbox=sandbox)
        self.assertEqual(ctrl.start().state, "completed")
        audit_commands = [
            (box, command) for box, command in sandbox.commands if box.startswith("prosecutor-")
        ]
        self.assertTrue(any(command.argv[0] == "python3" for _, command in audit_commands))
        self.assertFalse(any(box == "toy-r1" for box, _ in audit_commands))
        audit_stages = [
            members for box, members in sandbox.staged_members if box.startswith("prosecutor-")
        ]
        self.assertEqual(len(audit_stages), 1)
        self.assertIn("answer.py", audit_stages[0])
        self.assertFalse(any(box.startswith("prosecutor-") for box in sandbox.prepared))

    def test_frozen_archive_is_persisted_and_staged_without_source_container(self):
        sandbox = RecordingSandbox()
        ctrl = self.controller(sandbox=sandbox)
        sandbox.prepare("toy-r1")
        archive_buffer = io.BytesIO()
        with tarfile.open(fileobj=archive_buffer, mode="w") as archive:
            content = b"print('solution')\n"
            info = tarfile.TarInfo("solution.py")
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
        archive = archive_buffer.getvalue()
        digest = hashlib.sha256(archive).hexdigest()
        sandbox.stage_archive("toy-r1", base64.b64encode(archive).decode("ascii"), digest)
        artifact = sandbox.freeze("toy-r1")
        ctrl._persist_frozen_archive("toy-r1", 1, artifact.digest)

        persisted = ctrl.store.path.parent / "frozen" / "toy-r1.tar"
        self.assertTrue(persisted.is_file())
        self.assertEqual(hashlib.sha256(persisted.read_bytes()).hexdigest(), artifact.digest)

        ctrl._round = 1
        sandbox.prepare("toy-review-r1")
        with patch.object(sandbox, "export", side_effect=RuntimeError("source container missing")):
            ctrl._stage_frozen_for_review("toy-r1", "toy-review-r1", artifact.digest)
        staged = {
            name
            for box, members in sandbox.staged_members
            if box == "toy-review-r1"
            for name in members
        }
        self.assertIn("solution.py", staged)

    def test_prosecutor_failure_cleans_audit_and_warrior_sandboxes(self):
        sandbox = RecordingSandbox()
        ctrl = self.controller(gateway=InvalidProsecutorGateway(), sandbox=sandbox)
        with self.assertRaisesRegex(StepLimitExceeded, "prosecutor did not submit within 5 model steps"):
            ctrl.start()
        self.assertEqual(ctrl.status().state, "failed")
        self.assertFalse(sandbox.prepared)
        self.assertTrue(
            any(
                item["event_type"] == "sandbox_destroyed"
                and item["payload"]["sandbox_id"].startswith("prosecutor-")
                for item in ctrl._events()
            )
        )

    def test_budget_stops_before_second_request(self):
        status = self.controller(cfg=config(self.pack.root, max_requests=1)).start()
        self.assertEqual(status.state, "aborted")
        self.assertEqual(status.requests_used, 1)
        self.assertIn("budget", status.stop_reason)

    def test_doctor_gate_refuses_all_execution(self):
        sandbox = FakeSandboxBackend(healthy=False)
        ctrl = self.controller(sandbox=sandbox)
        with self.assertRaisesRegex(RuntimeError, "doctor"):
            ctrl.start()
        self.assertFalse(sandbox.prepared)
        self.assertEqual(ctrl.status().state, "created")

    def test_usage_records_all_dimensions_and_role_caps(self):
        ctrl = self.controller()
        ctrl.start()
        usages = [event["payload"] for event in ctrl._events() if event["event_type"] == "usage_committed"]
        self.assertTrue(usages)
        self.assertTrue(
            all(
                set(("input_tokens", "output_tokens", "cached_tokens", "reasoning_tokens", "verified"))
                <= set(item)
                for item in usages
            )
        )
        self.assertEqual({item["role"] for item in usages}, {"warrior", "judge", "prosecutor"})

    def test_attempt_aware_retry_charges_failure_and_success(self):
        transport = AttemptTransport((urllib.error.URLError("offline"),))
        ctrl = self.controller(gateway=attempt_gateway(transport))
        self.assertEqual(ctrl.start().state, "completed")
        usages = [event["payload"] for event in ctrl._events() if event["event_type"] == "usage_committed"]
        self.assertEqual(len(usages), len(transport.calls))
        self.assertFalse(usages[0]["succeeded"])
        self.assertFalse(usages[0]["verified"])
        self.assertEqual(usages[0]["error_type"], "URLError")
        self.assertTrue(usages[1]["succeeded"])
        self.assertTrue(usages[1]["verified"])
        self.assertEqual(ctrl.status().requests_used, len(transport.calls))

    def test_attempt_reservation_covers_compatibility_usage_above_requested_output(self):
        transport = InflatedCompatibilityUsageTransport()
        ctrl = self.controller(gateway=attempt_gateway(transport))

        self.assertEqual(ctrl.start().state, "completed")
        usages = [event["payload"] for event in ctrl._events() if event["event_type"] == "usage_committed"]
        self.assertTrue(usages)
        self.assertTrue(all(item["output_tokens"] == 150 for item in usages))
        self.assertTrue(all(item["reasoning_tokens"] == 150 for item in usages))

    def test_attempt_aware_final_network_failure_is_still_committed(self):
        transport = AttemptTransport((urllib.error.URLError("one"), urllib.error.URLError("two")))
        ctrl = self.controller(gateway=attempt_gateway(transport))
        with self.assertRaisesRegex(RuntimeError, "unavailable"):
            ctrl.start()
        usages = [event["payload"] for event in ctrl._events() if event["event_type"] == "usage_committed"]
        self.assertEqual(len(usages), 2)
        self.assertEqual(ctrl.status().requests_used, 2)
        self.assertTrue(all(not item["succeeded"] and not item["verified"] for item in usages))

        recovered = self.controller(gateway=attempt_gateway(AttemptTransport()))
        snapshot = recovered._budget.snapshot().committed
        self.assertEqual(recovered.status().requests_used, 2)
        self.assertEqual(snapshot.requests, 2)
        self.assertEqual(snapshot.input_tokens, sum(item["input_tokens"] for item in usages))
        self.assertEqual(snapshot.output_tokens, sum(item["output_tokens"] for item in usages))
        self.assertEqual(snapshot.cached_tokens, sum(item["cached_tokens"] for item in usages))
        self.assertEqual(snapshot.reasoning_tokens, sum(item["reasoning_tokens"] for item in usages))

    def test_attempt_aware_protocol_fallback_commits_both_attempts(self):
        transport = AttemptTransport((404,))
        ctrl = self.controller(gateway=attempt_gateway(transport))
        self.assertEqual(ctrl.start().state, "completed")
        usages = [event["payload"] for event in ctrl._events() if event["event_type"] == "usage_committed"]
        self.assertEqual(
            [(item["protocol"], item["status"], item["succeeded"]) for item in usages[:2]],
            [("responses", 404, False), ("chat", 200, True)],
        )

    def test_attempt_budget_denies_retry_before_second_transport_call(self):
        transport = AttemptTransport((429,))
        ctrl = self.controller(cfg=config(self.pack.root, max_requests=1), gateway=attempt_gateway(transport))
        status = ctrl.start()
        self.assertEqual(status.state, "aborted")
        self.assertEqual(status.requests_used, 1)
        self.assertEqual(len(transport.calls), 1)

    def test_promotion_arm_counts_failed_attempt_but_keeps_verified_success_usage(self):
        transport = AttemptTransport((urllib.error.URLError("retry"),))
        ctrl = self.controller(gateway=attempt_gateway(transport))
        ctrl._strategies.initialize_defaults()
        champion = ctrl._strategies.champion(Role.WARRIOR)
        self.assertIsNotNone(champion)
        result = ctrl._run_promotion_arm(
            strategy=champion,
            task_id=ctrl.tasks.promotion_task_ids()[0],
            seed=0,
            arm="champion",
            experiment_id="attempt-arm",
        )
        events = [event["payload"] for event in ctrl._events() if event["event_type"] == "usage_committed"]
        self.assertEqual(result.tokens, sum(item["input_tokens"] + item["output_tokens"] for item in events))
        self.assertTrue(any(not item["succeeded"] for item in events))
        # A conservatively accounted transient failure does not make the
        # successful, API-verified responses' quality evidence unverifiable.
        self.assertTrue(result.usage_verified)

    def test_pause_before_preparation_resumes_through_real_tool_loop(self):
        ctrl = self.controller()
        ctrl.store.append("toy", "control_requested", {"action": "pause"})
        self.assertEqual(ctrl.start().state, "paused")
        self.assertEqual(ctrl.resume().state, "completed")

    def test_external_pause_checkpoint_does_not_repeat_completed_role_or_prepare(self):
        sandbox = RecordingSandbox()
        control_fired = False

        def pause_after_research(_call, phase, step):
            nonlocal control_fired
            if not control_fired and phase == "research" and step == 2:
                control_fired = True
                control_store = EventStore(self.root / "events.db")
                try:
                    apply_persisted_control("toy", control_store, sandbox, "pause")
                finally:
                    control_store.close()

        gateway = ActionGateway(hook=pause_after_research)
        ctrl = self.controller(gateway=gateway, sandbox=sandbox)
        self.assertEqual(ctrl.start().state, "paused")
        research_calls = [call for call in gateway.calls if call[0] == "research"]
        self.assertEqual(len(research_calls), 2)
        self.assertEqual(sandbox.prepare_calls.count("toy-r1"), 1)
        self.assertEqual(ctrl.resume().state, "completed")
        self.assertEqual(len([call for call in gateway.calls if call[0] == "research"]), 2)
        self.assertEqual(sandbox.prepare_calls.count("toy-r1"), 1)

    def test_external_pause_stops_before_the_next_model_request(self):
        sandbox = RecordingSandbox()
        control_fired = False

        def pause_after_first_research(_call, phase, step):
            nonlocal control_fired
            if not control_fired and phase == "research" and step == 1:
                control_fired = True
                control_store = EventStore(self.root / "events.db")
                try:
                    apply_persisted_control("toy", control_store, sandbox, "pause")
                finally:
                    control_store.close()

        gateway = ActionGateway(hook=pause_after_first_research)
        ctrl = self.controller(gateway=gateway, sandbox=sandbox)

        self.assertEqual(ctrl.start().state, "paused")
        self.assertEqual([call for call in gateway.calls if call[0] == "research"], [("research", 1)])

    def test_external_pause_wins_a_stale_phase_transition(self):
        sandbox = RecordingSandbox()
        ctrl = self.controller(sandbox=sandbox)
        ctrl._state = CampaignState.PREPARING
        ctrl._machine = CampaignStateMachine(CampaignState.PREPARING)
        ctrl._append("state_changed", {"state": "preparing"})
        control_store = EventStore(self.root / "events.db")
        try:
            self.assertEqual(apply_persisted_control("toy", control_store, sandbox, "pause").state, "paused")
        finally:
            control_store.close()

        with self.assertRaises(CampaignHalted):
            ctrl._phase_start(1, "research")

        self.assertEqual(ctrl.status().state, "paused")
        self.assertFalse(any(event["event_type"] == "phase_started" for event in ctrl._events()))

    def test_new_controller_and_provider_resume_attaches_existing_workspace(self):
        sandbox = RecordingSandbox()
        fired = False

        def pause_after_research(_call, phase, step):
            nonlocal fired
            if not fired and phase == "research" and step == 2:
                fired = True
                control_store = EventStore(self.root / "events.db")
                try:
                    apply_persisted_control("toy", control_store, sandbox, "pause")
                finally:
                    control_store.close()

        gateway = ActionGateway(hook=pause_after_research)
        first = self.controller(gateway=gateway, sandbox=sandbox)
        self.assertEqual(first.start().state, "paused")
        first.close()
        self.controllers.remove(first)

        provider = PythonTaskProvider(((self.pack, self.validation),), sandbox)
        resumed = CampaignController(
            config(self.pack.root),
            EventStore(self.root / "events.db"),
            gateway,
            sandbox,
            provider,
            FakeResearch(),
        )
        self.controllers.append(resumed)
        self.assertEqual(resumed.resume().state, "completed")
        self.assertEqual(len([call for call in gateway.calls if call[0] == "research"]), 2)
        self.assertEqual(sandbox.prepare_calls.count("toy-r1"), 1)

    def test_cold_recovery_preserves_wall_time_budget(self):
        store = EventStore(self.root / "events.db")
        try:
            store.append(
                "toy",
                "campaign_started",
                {"elapsed_seconds": 0.0, "active_started_at_unix": time.time() - 120.0},
            )
            store.append("toy", "state_changed", {"state": "preparing"})
        finally:
            store.close()
        ctrl = self.controller(clock=lambda: 100.0)

        self.assertGreaterEqual(ctrl._elapsed_seconds(), 120.0)
        self.assertFalse(ctrl._boundary())
        self.assertEqual(ctrl.status().state, "aborted")

    def test_resume_closes_round_when_destroy_crossed_crash_boundary(self):
        class CrashAfterMainDestroy(RecordingSandbox):
            crashed = False

            def destroy(self, sandbox_id):
                super().destroy(sandbox_id)
                if sandbox_id == "toy-r1" and not self.crashed:
                    self.crashed = True
                    raise KeyboardInterrupt("simulated process death")

        sandbox = CrashAfterMainDestroy()
        first = self.controller(sandbox=sandbox)
        with self.assertRaisesRegex(KeyboardInterrupt, "simulated process death"):
            first.start()
        self.assertIn("round_completed", [event["event_type"] for event in first._events()])
        first.close()
        self.controllers.remove(first)

        resumed = CampaignController(
            config(self.pack.root),
            EventStore(self.root / "events.db"),
            ActionGateway(),
            sandbox,
            PythonTaskProvider(((self.pack, self.validation),), sandbox),
            FakeResearch(),
        )
        self.controllers.append(resumed)
        self.assertEqual(resumed.resume().state, "completed")
        events = resumed._events()
        self.assertTrue(
            any(
                event["event_type"] == "sandbox_destroyed"
                and event["payload"]["sandbox_id"] == "toy-r1"
                for event in events
            )
        )

    def test_persisted_kill_without_controller_kills_owned_sandbox_and_aborts(self):
        sandbox = RecordingSandbox()
        sandbox.prepare("toy-r1")
        store = EventStore(self.root / "offline.db")
        try:
            store.append("toy", "state_changed", {"state": "warrior_execute"})
            store.append("toy", "sandbox_prepared", {"round": 1, "sandbox_id": "toy-r1"})
            status = apply_persisted_control("toy", store, sandbox, "kill")
            events = [event.event_type for event in store.read("toy", limit=100)]
        finally:
            store.close()
        self.assertEqual(status.state, "aborted")
        self.assertIn("toy-r1", sandbox.killed)
        self.assertIn("sandbox_killed", events)
        self.assertIn("control_applied", events)

    def test_prepare_intent_crash_window_is_owned_and_reconciled(self):
        sandbox = RecordingSandbox()
        sandbox.prepare("orphan-review")
        store = EventStore(self.root / "intent-crash.db")
        try:
            store.append("toy", "state_changed", {"state": "judge_evaluate"})
            store.append("toy", "sandbox_prepare_intent", {"sandbox_id": "orphan-review"})
            status = apply_persisted_control("toy", store, sandbox, "kill")
        finally:
            store.close()
        self.assertEqual(status.state, "aborted")
        self.assertIn("orphan-review", sandbox.killed)

    def test_persisted_stop_without_controller_destroys_owned_sandbox(self):
        sandbox = RecordingSandbox()
        sandbox.prepare("toy-r1")
        store = EventStore(self.root / "stop.db")
        try:
            store.append("toy", "state_changed", {"state": "judge_evaluate"})
            store.append("toy", "sandbox_prepared", {"round": 1, "sandbox_id": "toy-r1"})
            status = apply_persisted_control("toy", store, sandbox, "stop")
            events = [event.event_type for event in store.read("toy", limit=100)]
        finally:
            store.close()
        self.assertEqual(status.state, "aborted")
        self.assertNotIn("toy-r1", sandbox.prepared)
        self.assertIn("sandbox_destroyed", events)

    def test_persisted_kill_continues_after_first_sandbox_cleanup_failure(self):
        class FirstKillFails(RecordingSandbox):
            def kill(self, sandbox_id):
                if sandbox_id == "a-main":
                    raise RuntimeError("injected first failure")
                return super().kill(sandbox_id)

        sandbox = FirstKillFails()
        sandbox.prepare("a-main")
        sandbox.prepare("b-review")
        store = EventStore(self.root / "partial-kill.db")
        try:
            store.append("toy", "state_changed", {"state": "judge_evaluate"})
            store.append("toy", "sandbox_prepared", {"round": 1, "sandbox_id": "a-main"})
            store.append(
                "toy",
                "review_sandbox_prepared",
                {"round": 1, "sandbox_id": "b-review", "artifact_digest": "a" * 64},
            )
            with self.assertRaises(SandboxCleanupError):
                apply_persisted_control("toy", store, sandbox, "kill")
            events = [(event.event_type, dict(event.payload)) for event in store.read("toy", limit=100)]
        finally:
            store.close()
        self.assertIn("b-review", sandbox.killed)
        self.assertIn("a-main", sandbox.prepared)
        self.assertTrue(
            any(
                kind == "sandbox_cleanup_failed"
                and payload["sandbox_id"] == "a-main"
                and payload["action"] == "kill"
                for kind, payload in events
            )
        )
        self.assertFalse(
            any(kind == "sandbox_killed" and payload["sandbox_id"] == "a-main" for kind, payload in events)
        )
        self.assertTrue(
            any(kind == "sandbox_killed" and payload["sandbox_id"] == "b-review" for kind, payload in events)
        )
        self.assertEqual(
            [payload["state"] for kind, payload in events if kind == "state_changed"][-1], "failed"
        )

    def test_controller_cleanup_continues_after_first_owned_sandbox_failure(self):
        class FirstDestroyFails(RecordingSandbox):
            def destroy(self, sandbox_id):
                if sandbox_id == "a-main":
                    raise RuntimeError("injected first failure")
                return super().destroy(sandbox_id)

        sandbox = FirstDestroyFails()
        ctrl = self.controller(sandbox=sandbox)
        sandbox.prepare("a-main")
        sandbox.prepare("b-review")
        ctrl.store.append("toy", "sandbox_prepared", {"round": 1, "sandbox_id": "a-main"})
        ctrl.store.append(
            "toy",
            "review_sandbox_prepared",
            {"round": 1, "sandbox_id": "b-review", "artifact_digest": "b" * 64},
        )
        ctrl._sandbox_id = "a-main"

        with self.assertRaises(SandboxCleanupError):
            ctrl._cleanup(kill=False)

        self.assertIn("a-main", sandbox.prepared)
        self.assertNotIn("b-review", sandbox.prepared)
        events = ctrl._events()
        self.assertTrue(
            any(
                event["event_type"] == "sandbox_cleanup_failed" and event["payload"]["sandbox_id"] == "a-main"
                for event in events
            )
        )
        self.assertFalse(
            any(
                event["event_type"] == "sandbox_destroyed" and event["payload"]["sandbox_id"] == "a-main"
                for event in events
            )
        )
        self.assertTrue(
            any(
                event["event_type"] == "sandbox_destroyed" and event["payload"]["sandbox_id"] == "b-review"
                for event in events
            )
        )

    def test_pause_during_promotion_resumes_completed_round_without_replaying_gate(self):
        sandbox = RecordingSandbox()
        base = PythonTaskProvider(((self.pack, self.validation),), sandbox)

        class PausingProvider:
            def __init__(self, delegate, root):
                self.delegate, self.root, self.promotions = delegate, root, 0

            def __getattr__(self, name):
                return getattr(self.delegate, name)

            def promote(self, task, quality, prosecutor_output):
                self.promotions += 1
                control_store = EventStore(self.root / "events.db")
                try:
                    apply_persisted_control("toy", control_store, sandbox, "pause")
                finally:
                    control_store.close()
                return self.delegate.promote(task, quality, prosecutor_output)

        provider = PausingProvider(base, self.root)
        ctrl = CampaignController(
            config(self.pack.root),
            EventStore(self.root / "events.db"),
            ActionGateway(),
            sandbox,
            provider,
            FakeResearch(),
        )
        self.controllers.append(ctrl)
        self.assertEqual(ctrl.start().state, "paused")
        self.assertEqual(provider.promotions, 1)
        self.assertEqual(ctrl.resume().state, "completed")
        self.assertEqual(provider.promotions, 1)

    def test_promotion_arm_runs_model_loop_and_hidden_score_in_fresh_sandbox(self):
        sandbox = RecordingSandbox()
        ctrl = self.controller(gateway=ActionGateway(), sandbox=sandbox)
        ctrl._strategies.initialize_defaults()
        candidate = ctrl._strategies.submit_payload(
            Role.WARRIOR,
            {
                "strategy_proposals": [
                    {
                        "proposal_id": "arm-candidate",
                        "target_role": "warrior",
                        "content": {
                            "role_guidance": ["Prefer a minimal repair."],
                            "prompt_fragments": [],
                            "tool_preferences": [],
                            "max_steps": None,
                        },
                        "rationale": "reduce unnecessary edits",
                    }
                ]
            },
        )[0]
        task_id = ctrl.tasks.promotion_task_ids()[0]
        result = ctrl._run_promotion_arm(
            strategy=candidate,
            task_id=task_id,
            seed=0,
            arm="candidate",
            experiment_id="exp-arm",
        )
        self.assertGreater(result.tokens, 0)
        self.assertTrue(result.usage_verified)
        self.assertEqual(result.quality, 1.0)
        arm_events = [
            item for item in ctrl._events() if item["event_type"] == "strategy_promotion_arm_completed"
        ]
        self.assertEqual(arm_events[0]["payload"]["strategy_id"], candidate.version_id)
        promotion_boxes = {box for box in sandbox.prepared if box.startswith("promo-")}
        self.assertFalse(promotion_boxes)  # the independent arm was destroyed
        self.assertTrue(any(box.startswith("judge-") for box, _ in sandbox.staged_members))

    def test_promotion_prosecutor_reads_only_from_fresh_audit_sandbox(self):
        sandbox = RecordingSandbox()
        ctrl = self.controller(gateway=InspectingProsecutorGateway(), sandbox=sandbox)
        ctrl._strategies.initialize_defaults()
        strategy = ctrl._strategies.champion(Role.WARRIOR.value)
        self.assertIsNotNone(strategy)
        ctrl._run_promotion_arm(
            strategy=strategy,
            task_id=ctrl.tasks.promotion_task_ids()[0],
            seed=0,
            arm="baseline",
            experiment_id="exp-prosecutor-audit",
        )
        audit_commands = [
            (box, command) for box, command in sandbox.commands if box.startswith("promo-prosecutor-")
        ]
        self.assertTrue(any(command.argv[0] == "python3" for _, command in audit_commands))
        audit_stages = [
            members
            for box, members in sandbox.staged_members
            if box.startswith("promo-prosecutor-")
        ]
        self.assertEqual(len(audit_stages), 1)
        self.assertIn("answer.py", audit_stages[0])
        self.assertFalse(any(box.startswith("promo-") for box in sandbox.prepared))

    def test_skill_promotion_arm_stages_only_selected_declarative_skill(self):
        sandbox = RecordingSandbox()
        skills = SkillRegistry(self.root / "skills.sqlite3")
        content = b"# Focused review\nRead the task and run the focused tests.\n"
        artifact = validate_skill_import(
            {
                "schema_version": 1,
                "kind": "skill",
                "source_url": "https://example.test/skill.md",
                "content_sha256": hashlib.sha256(content).hexdigest(),
                "size_bytes": len(content),
                "metadata": {
                    "name": "focused-review",
                    "version": "1.0.0",
                    "permissions": ["workspace.read"],
                    "dependencies": [],
                },
            }
        )
        skills.register_candidate(artifact, content)
        skills.record_static_evidence(SkillStaticValidator().validate(artifact, content))
        ctrl = self.controller(gateway=ActionGateway(), sandbox=sandbox, skills=skills)
        ctrl._strategies.initialize_defaults()

        result = ctrl._run_skill_promotion_arm(
            candidate_artifact_id=artifact.artifact_id,
            baseline_artifact_id=NO_SKILL_BASELINE_ID,
            evaluated_artifact_id=artifact.artifact_id,
            skill_name="focused-review",
            skill_version="1.0.0",
            task_id=ctrl.tasks.promotion_task_ids()[0],
            seed=0,
            arm="candidate",
            experiment_id="skill-exp",
        )

        self.assertTrue(result.usage_verified)
        skill_members = [
            name
            for _, members in sandbox.staged_members
            for name in members
            if name.startswith(".aegis/skills/")
        ]
        self.assertTrue(skill_members)
        self.assertTrue(
            all(name.startswith(".aegis/skills/focused-review/active/") for name in skill_members)
        )

        baseline_start = len(sandbox.staged_members)
        ctrl._run_skill_promotion_arm(
            candidate_artifact_id=artifact.artifact_id,
            baseline_artifact_id=NO_SKILL_BASELINE_ID,
            evaluated_artifact_id=NO_SKILL_BASELINE_ID,
            skill_name="focused-review",
            skill_version="1.0.0",
            task_id=ctrl.tasks.promotion_task_ids()[0],
            seed=0,
            arm="baseline",
            experiment_id="skill-exp",
        )
        self.assertFalse(
            any(
                name.startswith(".aegis/skills/")
                for _, members in sandbox.staged_members[baseline_start:]
                for name in members
            )
        )

class RetryableFailureTests(unittest.TestCase):
    def test_step_limit_failure_becomes_paused_retry_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = EventStore(Path(directory) / "events.sqlite3")
            try:
                store.append("retry", "state_changed", {"state": "warrior_research"})
                store.append("retry", "phase_started", {"round": 1, "phase": "research"})
                store.append(
                    "retry",
                    "usage_committed",
                    {"input_tokens": 7, "output_tokens": 5},
                )
                store.append(
                    "retry",
                    "campaign_error",
                    {"type": "StepLimitExceeded", "message": "bounded failure"},
                )
                store.append("retry", "state_changed", {"state": "failed"})

                status = prepare_retryable_failure("retry", store)
                events = store.read("retry", limit=20)
            finally:
                store.close()

        self.assertEqual(status.state, "paused")
        self.assertEqual(status.tokens_used, 12)
        self.assertEqual(status.requests_used, 1)
        self.assertEqual(events[-2].event_type, "campaign_retry_requested")
        self.assertEqual(events[-2].payload["resume_target"], "warrior_research")
        self.assertEqual(events[-1].payload["state"], "paused")
        self.assertEqual(events[-1].payload["resume_target"], "warrior_research")

    def test_non_step_limit_failure_is_not_retryable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = EventStore(Path(directory) / "events.sqlite3")
            try:
                store.append("retry", "state_changed", {"state": "warrior_research"})
                store.append("retry", "phase_started", {"round": 1, "phase": "research"})
                store.append(
                    "retry",
                    "campaign_error",
                    {"type": "RuntimeError", "message": "integrity failure"},
                )
                store.append("retry", "state_changed", {"state": "failed"})
                with self.assertRaisesRegex(
                    RuntimeError, "only a StepLimitExceeded or automatic sandbox cleanup failure"
                ):
                    prepare_retryable_failure("retry", store)
            finally:
                store.close()

    def test_automatic_cleanup_failure_becomes_paused_retry_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = EventStore(Path(directory) / "events.sqlite3")
            try:
                store.append("retry", "state_changed", {"state": "judge_evaluate"})
                store.append("retry", "phase_completed", {"round": 1, "phase": "judge"})
                store.append(
                    "retry",
                    "sandbox_cleanup_failed",
                    {
                        "sandbox_id": "retry-review-r1",
                        "action": "destroy",
                        "type": "RuntimeError",
                        "message": "sandbox agent failed with exit code 3221225794",
                    },
                )
                store.append(
                    "retry",
                    "state_changed",
                    {
                        "state": "failed",
                        "reason": "sandbox destroy failed for 2 target(s): retry-r1, retry-review-r1",
                    },
                )

                status = prepare_retryable_failure("retry", store)
                events = store.read("retry", limit=20)
            finally:
                store.close()

        self.assertEqual(status.state, "paused")
        self.assertEqual(status.round_number, 1)
        self.assertEqual(status.phase, "judge")
        self.assertEqual(events[-2].event_type, "campaign_retry_requested")
        self.assertEqual(events[-2].payload["failure_type"], "SandboxCleanup")
        self.assertEqual(events[-2].payload["resume_target"], "judge_evaluate")
        self.assertEqual(events[-1].payload["state"], "paused")
        self.assertEqual(events[-1].payload["resume_target"], "judge_evaluate")

    def test_operator_stop_cleanup_failure_is_not_retryable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = EventStore(Path(directory) / "events.sqlite3")
            try:
                store.append("retry", "state_changed", {"state": "judge_evaluate"})
                store.append("retry", "phase_completed", {"round": 1, "phase": "judge"})
                store.append(
                    "retry",
                    "state_changed",
                    {"state": "stopping", "reason": "graceful stop requested"},
                )
                store.append(
                    "retry",
                    "sandbox_cleanup_failed",
                    {
                        "sandbox_id": "retry-r1",
                        "action": "destroy",
                        "type": "RuntimeError",
                        "message": "sandbox agent failed with exit code 3221225794",
                    },
                )
                store.append(
                    "retry",
                    "state_changed",
                    {
                        "state": "failed",
                        "reason": "sandbox destroy failed for 1 target(s): retry-r1",
                    },
                )
                with self.assertRaisesRegex(
                    RuntimeError, "only a StepLimitExceeded or automatic sandbox cleanup failure"
                ):
                    prepare_retryable_failure("retry", store)
            finally:
                store.close()

    def test_after_fix_retry_resumes_any_failed_phase(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = EventStore(Path(directory) / "events.sqlite3")
            try:
                store.append("retry", "state_changed", {"state": "next_round"})
                store.append("retry", "phase_started", {"round": 1, "phase": "evolution"})
                store.append(
                    "retry",
                    "campaign_error",
                    {"type": "RuntimeError", "message": "transient transport flap"},
                )
                store.append(
                    "retry",
                    "state_changed",
                    {"state": "failed", "reason": "transient transport flap"},
                )

                status = prepare_retryable_failure("retry", store, after_fix=True)
                events = store.read("retry", limit=20)
            finally:
                store.close()

        self.assertEqual(status.state, "paused")
        self.assertEqual(status.round_number, 1)
        self.assertEqual(status.phase, "evolution")
        self.assertEqual(events[-2].event_type, "campaign_retry_requested")
        self.assertEqual(events[-2].payload["failure_type"], "OperatorAfterFix")
        self.assertEqual(events[-2].payload["resume_target"], "next_round")
        self.assertEqual(events[-1].payload["state"], "paused")
        self.assertEqual(events[-1].payload["resume_target"], "next_round")

    def test_after_fix_retry_rejects_operator_stop(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = EventStore(Path(directory) / "events.sqlite3")
            try:
                store.append("retry", "state_changed", {"state": "next_round"})
                store.append("retry", "phase_started", {"round": 1, "phase": "evolution"})
                store.append(
                    "retry",
                    "state_changed",
                    {"state": "stopping", "reason": "graceful stop requested"},
                )
                store.append(
                    "retry",
                    "campaign_error",
                    {"type": "RuntimeError", "message": "transient transport flap"},
                )
                store.append(
                    "retry",
                    "state_changed",
                    {"state": "failed", "reason": "transient transport flap"},
                )
                with self.assertRaisesRegex(
                    RuntimeError, "only a StepLimitExceeded or automatic sandbox cleanup failure"
                ):
                    prepare_retryable_failure("retry", store, after_fix=True)
            finally:
                store.close()

    def test_after_fix_retry_requires_failed_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = EventStore(Path(directory) / "events.sqlite3")
            try:
                store.append("retry", "state_changed", {"state": "next_round"})
                store.append("retry", "phase_started", {"round": 1, "phase": "evolution"})
                with self.assertRaisesRegex(RuntimeError, "cannot retry campaign from next_round"):
                    prepare_retryable_failure("retry", store, after_fix=True)
            finally:
                store.close()

    def test_evolution_step_limit_failure_becomes_next_round_retry_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = EventStore(Path(directory) / "events.sqlite3")
            try:
                store.append("retry", "phase_completed", {"round": 1, "phase": "promotion"})
                store.append("retry", "state_changed", {"state": "next_round"})
                store.append(
                    "retry",
                    "campaign_error",
                    {"type": "StepLimitExceeded", "message": "warrior evolution bounded failure"},
                )
                store.append("retry", "state_changed", {"state": "failed"})

                status = prepare_retryable_failure("retry", store)
                events = store.read("retry", limit=20)
            finally:
                store.close()

        self.assertEqual(status.state, "paused")
        self.assertEqual(events[-2].event_type, "campaign_retry_requested")
        self.assertEqual(events[-2].payload["resume_target"], "next_round")
        self.assertEqual(events[-1].payload["resume_target"], "next_round")


if __name__ == "__main__":
    unittest.main()
