from __future__ import annotations

import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from aegis.cli import _run_v2_cycle_wsl_first, main
from aegis.config import CampaignConfig
from aegis.dynamic_tasks import DynamicTaskRegistry
from aegis.evolution.wsl_deployment import (
    WslEvolutionDeployment,
    WslEvolutionDeploymentError,
)
from aegis.sandbox.bootstrap import (
    HARNESS_VOLUME_BYTES,
    BootstrapSpec,
    render_files,
)
from aegis.sandbox.types import DoctorCheck, DoctorReport

SOURCE_REF = "a" * 40


def _doctor_response(*, failed: str | None = None) -> dict[str, Any]:
    names = (
        "fixed_agents",
        "source_mirror",
        "campaign_volume_ext4",
        "campaign_volume_bounded",
        "windows_mounts_disabled",
        "interop_disabled",
    )
    return {
        "ok": True,
        "checks": [
            {"name": name, "passed": name != failed, "detail": "ok"}
            for name in names
        ],
    }


def test_deployment_doctor_uses_fixed_transport_and_exact_checks() -> None:
    observed: list[float] = []

    def transport(timeout: float) -> dict[str, Any]:
        observed.append(timeout)
        return _doctor_response()

    deployment = WslEvolutionDeployment(transport=transport, timeout_seconds=12)
    report = deployment.doctor()

    assert report.passed
    assert observed == [12]
    assert deployment.transport_argv() == (
        "wsl.exe",
        "--distribution",
        "AEGIS-Sandbox",
        "--",
        "/usr/local/bin/aegis-evolution-doctor",
    )


def test_deployment_doctor_rejects_incomplete_checks() -> None:
    response = _doctor_response()
    response["checks"].pop()
    with pytest.raises(WslEvolutionDeploymentError, match="incomplete"):
        WslEvolutionDeployment(transport=lambda timeout: response).doctor()


def test_bootstrap_contains_fixed_agents_and_bounded_ext4_harness_volume() -> None:
    rendered = render_files(
        BootstrapSpec(image="example.invalid/aegis@sha256:" + "b" * 64)
    )

    assert "/usr/local/bin/aegis-harness-agent" in rendered
    assert "/usr/local/bin/aegis-supervisor-agent" in rendered
    assert "/usr/local/bin/aegis-gateway-sidecar" in rendered
    assert "/usr/local/bin/aegis-evolution-doctor" in rendered
    helper = rendered["/usr/local/libexec/aegis-evolution-volume-setup"]
    assert f"SIZE={HARNESS_VOLUME_BYTES}" in helper
    assert "loop,nosuid,nodev" in helper
    assert "harness volume capacity is not bounded" in helper
    assert "enabled=false" in rendered["/etc/wsl.conf"]
    assert "appendWindowsPath=false" in rendered["/etc/wsl.conf"]


class _Backend:
    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []

    def ensure_campaign(self, *args: Any) -> SimpleNamespace:
        self.calls.append(("ensure", *args))
        return SimpleNamespace()

    def sync_mirror(self, *args: Any) -> SimpleNamespace:
        self.calls.append(("sync", *args))
        return SimpleNamespace()

    def status(self, *args: Any) -> SimpleNamespace:
        self.calls.append(("status", *args))
        return SimpleNamespace(champion_commit=SOURCE_REF)

    def rollback(self, *args: Any) -> SimpleNamespace:
        self.calls.append(("rollback", *args))
        return SimpleNamespace()


def _thin_client_env() -> dict[str, str]:
    return {
        "AEGIS_OPENAI_BASE_URL": "https://relay.example.invalid/v1",
        "AEGIS_OPENAI_API_KEY": "sk-test",
    }


def test_production_cycle_prepares_and_launches_pinned_champion() -> None:
    config = _production_config()
    backend = _Backend()
    launch = SimpleNamespace(
        status="launched",
        failure_kind=None,
        executed_commit=SOURCE_REF,
        last_known_good=SOURCE_REF,
        import_ok=True,
        heartbeat_ok=True,
        cycle_generation=1,
        cycle_pid=4242,
        to_mapping=lambda: {"status": "launched"},
    )
    status_payloads = iter(
        [
            {"status": "running", "metering": {"requests": 3}},
            {
                "status": "completed",
                "metering": {"requests": 3},
                "cycle_result": {
                    "campaign_id": "production",
                    "state": "completed",
                    "artifacts": {"submission": "artifact-sha256:" + "a" * 64},
                },
            },
        ]
    )
    supervisor = SimpleNamespace(
        launch_cycle=lambda *args, **kwargs: launch,
        cycle_status=lambda *args, **kwargs: next(status_payloads),
    )
    healthy = SimpleNamespace(
        doctor=lambda: DoctorReport((DoctorCheck("healthy", True, "ok"),))
    )
    launch_calls: list[tuple] = []

    def record_launch(*args: Any, **kwargs: Any) -> Any:
        launch_calls.append((args, kwargs))
        return launch

    supervisor.launch_cycle = record_launch
    with patch.dict(
        os.environ,
        {key: value for key, value in _thin_client_env().items()},
    ):
        with (
            patch("aegis.cli.WslHarnessBackend", return_value=backend),
            patch("aegis.cli.WslSupervisor", return_value=supervisor),
            patch(
                "aegis.evolution.wsl_deployment.WslEvolutionDeployment",
                return_value=healthy,
            ),
            patch("time.sleep", lambda *_: None),
        ):
            response = _run_v2_cycle_wsl_first(config)

    assert response["state"] == "completed"
    assert response["cycle_generation"] == 1
    assert response["gateway_metering"] == {"requests": 3}
    assert backend.calls[0] == (
        "ensure",
        "production",
        "https://github.com/example/aegis",
        SOURCE_REF,
        "ensure-" + SOURCE_REF[:24],
    )
    assert backend.calls[1][0] == "sync"
    args, kwargs = launch_calls[0]
    assert kwargs["gateway_credentials"]["api_key"] == "sk-test"
    assert kwargs["gateway_credentials"]["base_url"].startswith("https://")
    assert all(call[0] != "rollback" for call in backend.calls)


def test_boot_failure_automatically_rolls_back_lkg() -> None:
    config = _production_config()
    backend = _Backend()
    failed = "b" * 40
    launch = SimpleNamespace(
        status="boot_failed",
        failure_kind="import_failed",
        executed_commit=failed,
        last_known_good=SOURCE_REF,
        import_ok=False,
        heartbeat_ok=False,
        cycle_generation=None,
        cycle_pid=None,
    )
    healthy = SimpleNamespace(
        doctor=lambda: DoctorReport((DoctorCheck("healthy", True, "ok"),))
    )
    with patch.dict(os.environ, _thin_client_env()):
        with (
            patch("aegis.cli.WslHarnessBackend", return_value=backend),
            patch(
                "aegis.cli.WslSupervisor",
                return_value=SimpleNamespace(launch_cycle=lambda *args, **kwargs: launch),
            ),
            patch(
                "aegis.evolution.wsl_deployment.WslEvolutionDeployment",
                return_value=healthy,
            ),
            pytest.raises(RuntimeError, match="failed to boot"),
        ):
            _run_v2_cycle_wsl_first(config)

    rollback = [call for call in backend.calls if call[0] == "rollback"]
    assert rollback
    assert rollback[0][1:4] == ("production", failed, SOURCE_REF)


def test_evolution_cycle_holds_campaign_execution_lock() -> None:
    entered: list[str] = []

    class Lock:
        def __init__(self, data_path: Path, campaign_id: str) -> None:
            del data_path
            self.campaign_id = campaign_id

        def __enter__(self) -> None:
            entered.append(self.campaign_id)

        def __exit__(self, *args: object) -> None:
            entered.append("released")

    with tempfile.TemporaryDirectory() as directory:
        with (
            patch("aegis.cli.CampaignExecutionLock", Lock),
            patch("aegis.cli._evolution_cycle", return_value={"mode": "plan"}),
        ):
            assert main(
                ["--data-dir", directory, "evolution-cycle", "locked-campaign"]
            ) == 0

    assert entered == ["locked-campaign", "released"]


def _production_config() -> CampaignConfig:
    return CampaignConfig.from_mapping(
        {
            "campaign_id": "production",
            "max_rounds": 2,
            "total_tokens": 20_000_000,
            "max_requests": 120,
            "wall_time_seconds": 28_800,
            "task_pack_paths": [],
            "acceptance_profile": "autonomous_evolution_v2",
            "autonomy_v2": {
                "enabled": True,
                "public_repo_url": "https://github.com/example/aegis",
                "evolution_surfaces": ["workflow", "harness-code"],
                "harness_evolution_enabled": True,
                "harness_source_ref": SOURCE_REF,
            },
            "sandbox_backend": "wsl",
            "test_mode": False,
            "demo_mode": False,
            "offline_research": False,
            "research_enabled": True,
            "max_agent_steps": 24,
            "roles": {
                "warrior": {
                    "model": "w",
                    "budget_share": 0.55,
                    "max_output_tokens": 4096,
                },
                "judge": {
                    "model": "j",
                    "budget_share": 0.225,
                    "max_output_tokens": 4096,
                },
                "prosecutor": {
                    "model": "p",
                    "budget_share": 0.225,
                    "max_output_tokens": 4096,
                },
            },
        }
    )
