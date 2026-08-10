import hashlib
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

from aegis.cli import (
    _controller,
    _probe_evolution_workspace,
    _run_local_evolution_acceptance,
    build_parser,
    main,
)
from aegis.config import CampaignConfig
from aegis.event_store import EventStore
from aegis.evolution_workspace import (
    EvolutionPath,
    EvolutionPolicy,
    EvolutionWorkspace,
    ValidationCommand,
)
from aegis.gateway.types import GatewayResponse, TokenUsage
from aegis.knowledge import KnowledgeStore
from aegis.research.types import Provenance, ResearchArtifact, SearchHit
from aegis.sandbox.fake import FakeSandboxBackend
from aegis.sandbox.types import (
    CommandResult,
    DoctorCheck,
    DoctorReport,
    PreparedSandbox,
    StagedArtifact,
    validate_staging_archive,
)
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
            output_digest="cli-anchor",
        )


def config_data():
    return {
        "campaign_id": "cli",
        "max_rounds": 1,
        "total_tokens": 1000,
        "max_requests": 10,
        "wall_time_seconds": 60,
        "sandbox_backend": "fake",
        "task_pack_paths": [str((Path.cwd() / "unused-taskpack").resolve())],
        "test_mode": True,
        "offline_research": True,
        "research_enabled": False,
        "roles": {
            "warrior": {"model": "w", "budget_share": 0.60, "max_output_tokens": 10},
            "judge": {"model": "j", "budget_share": 0.25, "max_output_tokens": 10},
            "prosecutor": {"model": "p", "budget_share": 0.15, "max_output_tokens": 10},
        },
    }


def acceptance_config_data():
    configured = config_data()
    configured.update(
        {
            "max_rounds": 2,
            "total_tokens": 14_000_000,
            "max_requests": 800,
            "wall_time_seconds": 28_800,
            "task_pack_paths": [
                str((Path.cwd() / f"unused-taskpack-{index}").resolve())
                for index in range(12)
            ],
            "acceptance_profile": "autonomous_evolution_v1",
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
    )
    return configured


class CliTests(unittest.TestCase):
    def test_all_required_commands_parse(self):
        parser = build_parser()
        self.assertEqual(parser.parse_args(["doctor"]).command, "doctor")
        self.assertEqual(
            parser.parse_args(["autonomy-local-acceptance"]).command,
            "autonomy-local-acceptance",
        )
        for name in (
            "start",
            "pause",
            "resume",
            "retry",
            "stop",
            "kill",
            "status",
            "report",
            "replay",
            "strategy-history",
            "autonomy-preflight",
            "autonomy-smoke-verify",
        ):
            self.assertEqual(parser.parse_args([name, "c"]).command, name)
        self.assertEqual(parser.parse_args(["campaign-create", "c.json"]).command, "campaign-create")
        self.assertEqual(
            parser.parse_args(["knowledge-search", "testing", "--role", "warrior"]).command,
            "knowledge-search",
        )
        args = parser.parse_args(["sandbox-bootstrap", "--image", "x@sha256:" + "0" * 64])
        self.assertFalse(args.apply)

    def test_acceptance_campaign_requires_and_uses_explicit_isolated_data_dir(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"AEGIS_DATA_DIR": str(Path(directory) / "default")}),
        ):
            root = Path(directory)
            source = root / "acceptance.json"
            configured = acceptance_config_data()
            source.write_text(json.dumps(configured))

            self.assertEqual(main(["campaign-create", str(source)]), 2)
            isolated = root / "isolated"
            self.assertEqual(
                main(["--data-dir", str(isolated), "campaign-create", str(source)]),
                0,
            )
            self.assertTrue((isolated / "campaigns" / "cli.json").is_file())
            self.assertFalse((root / "default" / "campaigns" / "cli.json").exists())

    def test_autonomy_smoke_verify_reads_isolated_campaign_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "acceptance.json"
            configured = acceptance_config_data()
            source.write_text(json.dumps(configured))
            argv = ["--data-dir", str(root / "isolated")]
            self.assertEqual(main([*argv, "campaign-create", str(source)]), 0)

            output = StringIO()
            with redirect_stdout(output):
                exit_code = main([*argv, "autonomy-smoke-verify", "cli"])
            report = json.loads(output.getvalue())
            self.assertEqual(exit_code, 2)
            self.assertFalse(report["passed"])
            self.assertTrue(any(not item["passed"] for item in report["checks"]))

    def test_evolution_cycle_dry_run_then_cold_start_seeds_anchors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "v2.json"
            configured = acceptance_config_data()
            configured["acceptance_profile"] = "autonomous_evolution_v2"
            configured["task_pack_paths"] = []
            configured["autonomy_v2"] = {"enabled": True}
            source.write_text(json.dumps(configured))
            argv = ["--data-dir", str(root / "isolated")]
            self.assertEqual(main([*argv, "campaign-create", str(source)]), 0)

            dry = StringIO()
            with redirect_stdout(dry):
                self.assertEqual(
                    main([*argv, "evolution-cycle", "cli", "--dry-run"]),
                    0,
                )
            dry_report = json.loads(dry.getvalue())
            self.assertEqual(dry_report["mode"], "dry-run")
            self.assertEqual(dry_report["registry"]["records"], 0)
            self.assertEqual(dry_report["cohort"]["members"], [])

            seeded = StringIO()
            with (
                redirect_stdout(seeded),
                patch("aegis.cli.SandboxTaskPackRunner", return_value=AnchorRunner()),
            ):
                self.assertEqual(main([*argv, "evolution-cycle", "cli"]), 0)
            seed_report = json.loads(seeded.getvalue())
            self.assertEqual(len(seed_report["seeded_anchors"]), 12)
            self.assertEqual(seed_report["registry"]["anchors"], 12)
            self.assertEqual(len(seed_report["cohort"]["members"]), 12)

    def test_create_status_control_and_report(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"AEGIS_DATA_DIR": str(Path(directory) / "data")}),
        ):
            root = Path(directory)
            source = root / "input.json"
            source.write_text(json.dumps(config_data()))
            self.assertEqual(main(["campaign-create", str(source)]), 0)
            self.assertEqual(main(["status", "cli"]), 0)
            self.assertEqual(main(["pause", "cli"]), 0)
            output = root / "report.json"
            self.assertEqual(main(["report", "cli", "--output", str(output)]), 0)
            self.assertEqual(json.loads(output.read_text())["campaign_id"], "cli")

    def test_controller_tracks_runtime_sandbox_events_for_cas_transitions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = EventStore(root / "events.sqlite3")
            config = CampaignConfig.from_mapping(config_data())
            with (
                patch("aegis.cli._load", return_value=config),
                patch("aegis.cli._store", return_value=store),
                patch("aegis.cli._data_dir", return_value=root),
                patch("aegis.cli._validate_packs", return_value=[]),
                patch("aegis.cli.PythonTaskProvider", return_value=MagicMock()),
                patch("aegis.cli._knowledge", return_value=None),
                patch("aegis.cli._skills", return_value=None),
                patch("aegis.cli._research", return_value=MagicMock()),
                patch("aegis.cli.GatewayConfig.from_env", return_value=MagicMock()),
                patch("aegis.cli.ModelGateway", return_value=MagicMock()),
            ):
                controller = _controller("cli")
            try:
                controller.sandbox.prepare("cli-r1")
                controller._transition("start")
                self.assertEqual(controller.status().state, "preparing")
            finally:
                controller.close()

    def test_campaign_commands_reject_configuration_drift(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"AEGIS_DATA_DIR": str(Path(directory) / "data")}),
        ):
            source = Path(directory) / "input.json"
            source.write_text(json.dumps(config_data()))
            self.assertEqual(main(["campaign-create", str(source)]), 0)
            campaign = Path(directory) / "data" / "campaigns" / "cli.json"
            changed = json.loads(campaign.read_text())
            changed["total_tokens"] = 9_999_999
            campaign.write_text(json.dumps(changed))

            self.assertEqual(main(["status", "cli"]), 2)

    def test_start_refuses_fake_test_campaign_before_gateway_or_task_loading(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"AEGIS_DATA_DIR": str(Path(directory) / "data")}),
        ):
            source = Path(directory) / "input.json"
            source.write_text(json.dumps(config_data()))
            self.assertEqual(main(["campaign-create", str(source)]), 0)
            self.assertEqual(main(["start", "cli"]), 2)

    def test_autonomy_preflight_is_structured_and_fails_closed(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"AEGIS_DATA_DIR": str(Path(directory) / "data")}),
        ):
            source = Path(directory) / "input.json"
            source.write_text(json.dumps(config_data()))
            self.assertEqual(main(["campaign-create", str(source)]), 0)
            output = StringIO()
            with redirect_stdout(output):
                exit_code = main(["autonomy-preflight", "cli"])
            report = json.loads(output.getvalue())
            checks = {item["name"]: item for item in report["checks"]}
            self.assertEqual(exit_code, 2)
            self.assertFalse(report["passed"])
            self.assertFalse(checks["auto_evolution_promotion"]["passed"])
            self.assertFalse(checks["auto_skill_promotion"]["passed"])
            self.assertFalse(checks["taskpacks_live_validated"]["passed"])
            self.assertFalse(checks["gateway_live_probe"]["passed"])
            self.assertFalse(checks["research_search_live"]["passed"])
            self.assertFalse(checks["research_fetch_live"]["passed"])
            self.assertFalse(checks["evolution_workspace_access_live"]["passed"])
            self.assertFalse(checks["evolution_host_integrity"]["passed"])
            self.assertFalse(checks["evolution_sandbox_cleanup"]["passed"])

    def test_evolution_workspace_probe_checks_access_host_integrity_and_cleanup(self):
        class ProbeBackend:
            def __init__(self):
                self.prepared = []
                self.destroyed = []
                self.writable_paths = ()

            def prepare(self, sandbox_id):
                self.prepared.append(sandbox_id)
                return PreparedSandbox(sandbox_id)

            @staticmethod
            def stage_archive(sandbox_id, archive_base64, expected_digest):
                payload, members = validate_staging_archive(archive_base64, expected_digest)
                return StagedArtifact(sandbox_id, expected_digest, len(payload), len(members))

            def configure_workspace_access(self, sandbox_id, writable_paths):
                self.writable_paths = writable_paths

            @staticmethod
            def exec(sandbox_id, command):
                del sandbox_id
                manifest = json.loads(command.stdin)
                writable = manifest["writable_paths"]

                def permits(path):
                    return any(
                        path == rule["path"]
                        or (rule["recursive"] and path.startswith(rule["path"] + "/"))
                        for rule in writable
                    )

                result = {
                    "passed": True,
                    "files_verified": len(manifest["files"]),
                    "readonly_files_checked": sum(
                        not permits(item["path"]) for item in manifest["files"]
                    ),
                    "readonly_directories_checked": 2,
                    "writable_rules_checked": len(writable),
                    "failures": [],
                }
                return CommandResult(0, json.dumps(result), "", 0.1)

            def destroy(self, sandbox_id):
                self.destroyed.append(sandbox_id)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src" / "adaptive").mkdir(parents=True)
            (root / "src" / "adaptive" / "logic.py").write_text("VALUE = 1\n")
            (root / "control.py").write_text("TRUSTED = True\n")
            policy = EvolutionPolicy(
                evolvable_paths=(EvolutionPath("src/adaptive", recursive=True),),
                required_effective_paths=(),
                read_only_context_paths=(EvolutionPath("control.py"),),
                protected_paths=("control.py",),
                include_repository_context=True,
                context_excluded_paths=(),
            )
            backend = ProbeBackend()
            checks = _probe_evolution_workspace(backend, EvolutionWorkspace(root, policy))

        by_name = {item["name"]: item for item in checks}
        self.assertTrue(by_name["evolution_workspace_access_live"]["passed"])
        self.assertTrue(by_name["evolution_host_integrity"]["passed"])
        self.assertTrue(by_name["evolution_sandbox_cleanup"]["passed"])
        self.assertEqual(len(backend.prepared), 2)
        self.assertEqual(backend.prepared[0], backend.prepared[1])
        self.assertEqual(backend.destroyed, backend.prepared)
        self.assertEqual(
            [(rule.path, rule.recursive) for rule in backend.writable_paths],
            [("src/adaptive", True)],
        )

    def test_evolution_workspace_probe_fails_closed_but_still_cleans_up(self):
        class FailingBackend:
            def __init__(self):
                self.prepared = []
                self.destroyed = []

            def prepare(self, sandbox_id):
                self.prepared.append(sandbox_id)
                return PreparedSandbox(sandbox_id)

            @staticmethod
            def stage_archive(sandbox_id, archive_base64, expected_digest):
                del sandbox_id, archive_base64, expected_digest
                raise RuntimeError("staging failed")

            @staticmethod
            def configure_workspace_access(sandbox_id, writable_paths):
                raise AssertionError((sandbox_id, writable_paths))

            @staticmethod
            def exec(sandbox_id, command):
                raise AssertionError((sandbox_id, command))

            def destroy(self, sandbox_id):
                self.destroyed.append(sandbox_id)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "adaptive").mkdir()
            (root / "adaptive" / "logic.py").write_text("VALUE = 1\n")
            policy = EvolutionPolicy(
                evolvable_paths=(EvolutionPath("adaptive", recursive=True),),
                required_effective_paths=(),
                read_only_context_paths=(),
                protected_paths=(),
                include_repository_context=True,
                context_excluded_paths=(),
            )
            backend = FailingBackend()
            checks = _probe_evolution_workspace(backend, EvolutionWorkspace(root, policy))

        by_name = {item["name"]: item for item in checks}
        self.assertFalse(by_name["evolution_workspace_access_live"]["passed"])
        self.assertIn("staging failed", by_name["evolution_workspace_access_live"]["detail"])
        self.assertTrue(by_name["evolution_host_integrity"]["passed"])
        self.assertTrue(by_name["evolution_sandbox_cleanup"]["passed"])
        self.assertEqual(len(backend.prepared), 2)
        self.assertEqual(backend.destroyed, backend.prepared)

    def test_autonomy_preflight_runs_live_gateway_and_research_probes(self):
        class ProbeGateway:
            @staticmethod
            def complete(request):
                self.assertEqual(request.model, "w")
                self.assertIsNotNone(request.output_schema)
                self.assertEqual(request.max_output_tokens, 10)
                return GatewayResponse(
                    json.dumps(
                        {
                            "action": "submit",
                            "arguments": {"summary": "AEGIS_OK", "payload": {}},
                        }
                    ),
                    TokenUsage(5, 2, verified=True),
                    "responses",
                    "probe-request",
                    {},
                    200,
                )

        class ProbeResearch:
            @staticmethod
            def search(query, *, limit):
                self.assertEqual(limit, 1)
                return [SearchHit("https://example.com/result", "result", query)]

            @staticmethod
            def fetch(url):
                content = b"probe"
                return ResearchArtifact(
                    content,
                    Provenance.now(
                        requested_url=url,
                        final_url=url,
                        sha256=hashlib.sha256(content).hexdigest(),
                        size_bytes=len(content),
                        media_type="text/plain",
                        redirect_chain=(),
                    ),
                )

        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(
                os.environ,
                {
                    "AEGIS_DATA_DIR": str(Path(directory) / "data"),
                    "AEGIS_OPENAI_BASE_URL": "https://relay.example.test/v1",
                    "AEGIS_OPENAI_API_KEY": "test-key",
                },
            ),
            patch("aegis.cli.ModelGateway", return_value=ProbeGateway()),
            patch("aegis.cli._research", return_value=ProbeResearch()),
        ):
            source = Path(directory) / "input.json"
            configured = config_data()
            configured["research_enabled"] = True
            configured["offline_research"] = False
            source.write_text(json.dumps(configured))
            self.assertEqual(main(["campaign-create", str(source)]), 0)
            output = StringIO()
            with redirect_stdout(output):
                exit_code = main(["autonomy-preflight", "cli"])
            report = json.loads(output.getvalue())
            checks = {item["name"]: item for item in report["checks"]}
            self.assertEqual(exit_code, 2)
            self.assertTrue(checks["gateway_live_probe"]["passed"])
            self.assertTrue(checks["research_search_live"]["passed"])
            self.assertTrue(checks["research_fetch_live"]["passed"])

    def test_local_evolution_acceptance_runs_validation_canary_and_host_check(self):
        class NetworklessBackend(FakeSandboxBackend):
            def doctor(self):
                return DoctorReport((DoctorCheck("network_none", True, "test isolation"),))

        workflow = {
            "stage_plan": ["Inspect"],
            "research_query_templates": ["{task} evidence"],
            "tool_selection_rules": ["Use verified sources"],
            "stop_conditions": ["Stop after verification"],
            "verification_checklist": ["Run tests"],
            "skill_references": ["registry:champions"],
            "max_steps": 10,
        }

        def execute(_sandbox_id, command):
            if any("orchestrator.py" in argument for argument in command.argv):
                return CommandResult(1, "", "read-only", 0.1)
            stdout = json.dumps(workflow) if "aegis.evolvable.workflow" in command.argv else ""
            return CommandResult(0, stdout, "", 0.1)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "src" / "aegis" / "evolvable"
            target.mkdir(parents=True)
            (root / "src" / "aegis" / "__init__.py").write_text("", encoding="utf-8")
            (target / "__init__.py").write_text("", encoding="utf-8")
            (target / "workflow.py").write_text("VALUE = 1\n", encoding="utf-8")
            policy = EvolutionPolicy(
                evolvable_paths=(EvolutionPath("src/aegis/evolvable", recursive=True),),
                protected_paths=(),
                validation_commands=(ValidationCommand(("python", "-m", "pytest", "-q")),),
            )
            result = _run_local_evolution_acceptance(
                NetworklessBackend(executor=execute),
                EvolutionWorkspace(root, policy),
            )
        self.assertTrue(result["passed"])
        self.assertTrue(result["validation"]["passed"])
        self.assertIsNone(result["validation"]["failure_reason"])
        self.assertEqual(result["validation"]["exit_codes"], [0])
        self.assertTrue(result["protected_write_probe"]["rejected"])
        self.assertTrue(result["canary"]["passed"])
        self.assertTrue(result["host_unchanged"])

    def test_knowledge_search_reads_persistent_role_scoped_artifacts(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"AEGIS_DATA_DIR": str(Path(directory) / "data")}),
        ):
            data = Path(directory) / "data"
            data.mkdir()
            with KnowledgeStore(data / "knowledge.sqlite3") as knowledge:
                knowledge.add(
                    source_url="https://example.test/paper",
                    sha256="a" * 64,
                    media_type="text/plain",
                    summary="State machine testing lesson.",
                    tags=["testing"],
                    applicable_roles=["warrior"],
                    experiment_result="Caught a seeded defect.",
                )
            self.assertEqual(
                main(["knowledge-search", "state machine", "--role", "warrior", "--limit", "5"]),
                0,
            )


if __name__ == "__main__":
    unittest.main()
