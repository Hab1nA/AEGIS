from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from aegis.cli import main
from aegis.sandbox.types import DoctorCheck, DoctorReport


def valid_v2_config(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "campaign_id": "gates",
        "max_rounds": 2,
        "total_tokens": 20_000_000,
        "max_requests": 120,
        "wall_time_seconds": 28_800,
        "task_pack_paths": [],
        "acceptance_profile": "autonomous_evolution_v2",
        "autonomy_v2": {
            "enabled": True,
            "task_holdout_delay_cycles": 1,
            "public_repo_url": "https://github.com/example/aegis",
            "evolution_surfaces": ["workflow", "subject", "plugin", "environment"],
            "environment_output_repository": None,
            "scanner_binary": "trivy",
            "candidate_max_extra_steps": 12,
        },
        "sandbox_backend": "fake",
        "test_mode": True,
        "demo_mode": False,
        "offline_research": True,
        "research_enabled": False,
        "max_agent_steps": 24,
        "roles": {
            "warrior": {"model": "w", "budget_share": 0.55, "max_output_tokens": 4096},
            "judge": {"model": "j", "budget_share": 0.225, "max_output_tokens": 4096},
            "prosecutor": {"model": "p", "budget_share": 0.225, "max_output_tokens": 4096},
        },
    }
    value.update(updates)
    return value


class _FakeGateway:
    """Stand-in for the live model relay so preflight gate tests stay hermetic."""

    def complete(self, request: object, *, cancel: object = None) -> object:
        from aegis.gateway.types import GatewayResponse, TokenUsage

        return GatewayResponse(
            '{"action":"submit","arguments":{"summary":"AEGIS_OK","payload":{}}}',
            TokenUsage(10, 5, verified=True),
            "chat",
        )


class EvolutionPreflightGateTests(unittest.TestCase):
    def _preflight(self, config: dict[str, object]) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "campaign.json"
            source.write_text(json.dumps(config), encoding="utf-8")
            argv = ["--data-dir", str(root / "data")]
            self.assertEqual(main([*argv, "campaign-create", str(source)]), 0)
            output = StringIO()
            with redirect_stdout(output):
                with patch("aegis.cli.ModelGateway", return_value=_FakeGateway()):
                    main([*argv, "autonomy-preflight", "gates"])
            report = json.loads(output.getvalue())
            self.assertEqual(report["campaign_id"], "gates")
            checks = {check["name"]: check for check in report["checks"]}
            checks["passed"] = report["passed"]
            return checks

    def test_environment_surface_requires_real_builder(self) -> None:
        gates = self._preflight(valid_v2_config())
        self.assertFalse(gates["environment_builder_configured"]["passed"])
        self.assertIn("environment_output_repository", gates["environment_builder_configured"]["detail"])
        self.assertFalse(gates["passed"])

    def test_env_surface_configured_for_real_backend_passes_gates(self) -> None:
        config = valid_v2_config(sandbox_backend="wsl")
        autonomy = config["autonomy_v2"]
        assert isinstance(autonomy, dict)
        autonomy["environment_output_repository"] = "localhost/aegis-evolution"
        class HealthyBackend:
            def doctor(self) -> DoctorReport:
                return DoctorReport((DoctorCheck("healthy", True, "ok"),))

            def scanner_available(self) -> bool:
                return True

        with patch("aegis.cli.WslSandboxBackend", return_value=HealthyBackend()):
            gates = self._preflight(config)
        self.assertTrue(gates["evolution_surfaces_valid"]["passed"])
        self.assertTrue(gates["environment_builder_configured"]["passed"])
        self.assertTrue(gates["candidate_shadow_budget_reachable"]["passed"])

    def test_workflow_only_surfaces_skip_environment_gate(self) -> None:
        config = valid_v2_config()
        autonomy = config["autonomy_v2"]
        assert isinstance(autonomy, dict)
        autonomy["evolution_surfaces"] = ["workflow", "subject"]
        gates = self._preflight(config)
        self.assertTrue(gates["environment_builder_configured"]["passed"])

    def test_unknown_surface_is_rejected(self) -> None:
        config = valid_v2_config()
        autonomy = config["autonomy_v2"]
        assert isinstance(autonomy, dict)
        autonomy["evolution_surfaces"] = ["workflow", "harness"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "campaign.json"
            source.write_text(json.dumps(config), encoding="utf-8")
            self.assertEqual(
                main(["--data-dir", str(root / "data"), "campaign-create", str(source)]),
                2,
            )


if __name__ == "__main__":
    unittest.main()
