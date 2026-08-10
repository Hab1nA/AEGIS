import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from aegis.cli import build_parser, main
from aegis.taskpacks.validation import ExecutionResult


def v2_config_data():
    return {
        "campaign_id": "cli",
        "max_rounds": 2,
        "total_tokens": 20_000_000,
        "max_requests": 120,
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
            "prosecutor": {"model": "p", "budget_share": 0.225, "max_output_tokens": 4096},
        },
    }


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


class CliTests(unittest.TestCase):
    def test_all_required_commands_parse(self):
        parser = build_parser()
        self.assertEqual(parser.parse_args(["doctor"]).command, "doctor")
        for name in (
            "status",
            "replay",
            "report",
            "autonomy-preflight",
            "evolution-cycle",
        ):
            self.assertEqual(parser.parse_args([name, "c"]).command, name)
        self.assertEqual(parser.parse_args(["campaign-create", "c.json"]).command, "campaign-create")
        self.assertEqual(
            parser.parse_args(["knowledge-search", "testing", "--role", "warrior"]).command,
            "knowledge-search",
        )
        args = parser.parse_args(["sandbox-bootstrap", "--image", "x@sha256:" + "0" * 64])
        self.assertFalse(args.apply)
        cycle = parser.parse_args(["evolution-cycle", "c", "--run", "--repair"])
        self.assertTrue(cycle.run)
        self.assertTrue(cycle.repair)

    def test_acceptance_campaign_requires_and_uses_explicit_isolated_data_dir(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "v2.json"
            source.write_text(json.dumps(v2_config_data()))
            self.assertEqual(main(["campaign-create", str(source)]), 2)
            isolated = root / "isolated"
            self.assertEqual(
                main(["--data-dir", str(isolated), "campaign-create", str(source)]),
                0,
            )
            self.assertTrue((isolated / "campaigns" / "cli.json").is_file())

    def test_create_status_and_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "v2.json"
            source.write_text(json.dumps(v2_config_data()))
            argv = ["--data-dir", str(root / "isolated")]
            self.assertEqual(main([*argv, "campaign-create", str(source)]), 0)
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(main([*argv, "status", "cli"]), 0)
            status = json.loads(output.getvalue())
            self.assertEqual(status["campaign_id"], "cli")
            self.assertIsNone(status["state"])
            destination = root / "report.json"
            self.assertEqual(main([*argv, "report", "cli", "--output", str(destination)]), 0)
            report = json.loads(destination.read_text(encoding="utf-8"))
            self.assertEqual(report["campaign_id"], "cli")
            self.assertIn("campaign_created", report["event_type_counts"])

    def test_evolution_cycle_dry_run_then_cold_start_seeds_anchors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "v2.json"
            source.write_text(json.dumps(v2_config_data()))
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

    def test_preflight_rejects_campaign_without_autonomy_v2(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "v1.json"
            configured = v2_config_data()
            configured["campaign_id"] = "cli-legacy"
            configured["acceptance_profile"] = None
            configured["autonomy_v2"] = None
            configured["task_pack_paths"] = [
                str((root / "unused-taskpack").resolve())
            ]
            configured["roles"] = {
                "warrior": {"model": "w", "budget_share": 0.60, "max_output_tokens": 10},
                "judge": {"model": "j", "budget_share": 0.25, "max_output_tokens": 10},
                "prosecutor": {"model": "p", "budget_share": 0.15, "max_output_tokens": 10},
            }
            source.write_text(json.dumps(configured))
            argv = ["--data-dir", str(root / "isolated")]
            self.assertEqual(main([*argv, "campaign-create", str(source)]), 0)
            output = StringIO()
            with redirect_stdout(output):
                exit_code = main([*argv, "autonomy-preflight", "cli-legacy"])
            report = json.loads(output.getvalue())
            self.assertEqual(exit_code, 2)
            self.assertFalse(report["passed"])
            self.assertFalse(report["checks"][0]["passed"])


if __name__ == "__main__":
    unittest.main()
