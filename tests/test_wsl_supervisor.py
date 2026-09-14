from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from aegis.evolution.wsl_supervisor import (
    WslSupervisor,
    WslSupervisorError,
)
from aegis.models import canonical_json

COMMIT_A = "a" * 40
COMMIT_B = "b" * 40

_TEST_CREDENTIALS = {
    "base_url": "https://relay.example.invalid/v1",
    "api_key": "sk-test",
}


def _receipt(request: Mapping[str, Any]) -> dict[str, Any]:
    payload = {
        "operation_id": request["operation_id"],
        "campaign_id": request["campaign_id"],
        "campaign_key": hashlib.sha256(str(request["campaign_id"]).encode()).hexdigest(),
        "status": "completed",
        "failure_kind": None,
        "executed_commit": request["expected_commit"],
        "tree_hash": "c" * 40,
        "previous_champion": None,
        "last_known_good": request["expected_commit"],
        "import_ok": True,
        "heartbeat_ok": True,
        "exit_code": 0,
        "output_sha256": hashlib.sha256(b"").hexdigest(),
        "output_summary": "",
        "request_sha256": hashlib.sha256(
            canonical_json(
                {key: value for key, value in request.items() if key != "gateway_credentials"}
            ).encode()
        ).hexdigest(),
    }
    return {
        **payload,
        "receipt_sha256": hashlib.sha256(canonical_json(payload).encode()).hexdigest(),
    }


def test_supervisor_uses_fixed_bounded_data_protocol() -> None:
    requests: list[Mapping[str, Any]] = []

    def transport(request: Mapping[str, Any], timeout: float) -> Mapping[str, Any]:
        assert timeout == 60
        requests.append(request)
        return {"ok": True, "receipt": _receipt(request)}

    supervisor = WslSupervisor(transport=transport, timeout_seconds=60)
    receipt = supervisor.launch_cycle("campaign/one", COMMIT_A, "launch-1", {"cycle": 2})

    assert receipt.executed_commit == COMMIT_A
    assert requests == [
        {
            "version": 1,
            "operation": "launch_cycle",
            "operation_id": "launch-1",
            "campaign_id": "campaign/one",
            "expected_commit": COMMIT_A,
            "request_payload": {"cycle": 2},
            "gateway_credentials": None,
        }
    ]
    assert supervisor.transport_argv() == (
        "wsl.exe",
        "--distribution",
        "AEGIS-Sandbox",
        "--",
        "/usr/local/bin/aegis-supervisor-agent",
    )


def test_supervisor_validates_gateway_credentials() -> None:
    supervisor = WslSupervisor(transport=lambda request, timeout: {})
    with pytest.raises(ValueError, match="HTTPS"):
        supervisor.launch_cycle(
            "campaign",
            COMMIT_A,
            "launch-1",
            {},
            gateway_credentials={"base_url": "http://relay/v1", "api_key": "sk"},
        )
    with pytest.raises(ValueError, match="unknown fields"):
        supervisor.launch_cycle(
            "campaign",
            COMMIT_A,
            "launch-2",
            {},
            gateway_credentials={"base_url": "https://r/v1", "api_key": "k", "shell": "/bin/sh"},
        )
    with pytest.raises(ValueError, match="unknown fields"):
        supervisor.launch_cycle(
            "campaign",
            COMMIT_A,
            "launch-3",
            {},
            gateway_credentials={"upstream": "https://r/v1"},
        )


@pytest.mark.parametrize("key", ["command", "argv", "cwd", "path", "module", "executable"])
def test_supervisor_rejects_candidate_selected_execution_fields(key: str) -> None:
    supervisor = WslSupervisor(transport=lambda request, timeout: {})
    with pytest.raises(ValueError, match="may not select"):
        supervisor.launch_cycle("campaign", COMMIT_A, "launch-1", {key: "anything"})


def test_supervisor_rejects_cross_request_receipt() -> None:
    def transport(request: Mapping[str, Any], timeout: float) -> Mapping[str, Any]:
        del timeout
        receipt = _receipt(request)
        receipt["executed_commit"] = "d" * 40
        return {"ok": True, "receipt": receipt}

    with pytest.raises(WslSupervisorError, match="digest mismatch"):
        WslSupervisor(transport=transport).launch_cycle(
            "campaign", COMMIT_A, "launch-1", {}
        )


def test_launched_receipt_requires_probe_handshake_and_pid() -> None:
    def transport(request: Mapping[str, Any], timeout: float) -> Mapping[str, Any]:
        del timeout
        receipt = _receipt(request)
        receipt["status"] = "launched"
        receipt["cycle_generation"] = 3
        receipt["cycle_pid"] = 4242
        receipt["receipt_sha256"] = hashlib.sha256(
            canonical_json(
                {key: value for key, value in receipt.items() if key != "receipt_sha256"}
            ).encode()
        ).hexdigest()
        return {"ok": True, "receipt": receipt}

    supervisor = WslSupervisor(transport=transport, timeout_seconds=60)
    receipt = supervisor.launch_cycle("campaign/one", COMMIT_A, "launch-2", {"generation": 3})
    assert receipt.status == "launched"
    assert receipt.cycle_pid == 4242
    assert receipt.cycle_generation == 3

    def broken_transport(request: Mapping[str, Any], timeout: float) -> Mapping[str, Any]:
        del timeout
        receipt = _receipt(request)
        receipt["status"] = "launched"
        receipt["cycle_generation"] = 3
        receipt["cycle_pid"] = None  # A launched receipt without a pid is invalid.
        receipt["receipt_sha256"] = hashlib.sha256(
            canonical_json(
                {key: value for key, value in receipt.items() if key != "receipt_sha256"}
            ).encode()
        ).hexdigest()
        return {"ok": True, "receipt": receipt}

    broken = WslSupervisor(transport=broken_transport, timeout_seconds=60)
    with pytest.raises(WslSupervisorError, match="probe handshake"):
        broken.launch_cycle("campaign/one", COMMIT_A, "launch-3", {"generation": 3})


def test_legacy_sixteen_field_receipts_still_replay() -> None:
    legacy = _receipt(
        {
            "operation_id": "op",
            "campaign_id": "campaign",
            "expected_commit": COMMIT_A,
        }
    )
    from aegis.evolution.wsl_supervisor import CycleLaunchReceipt

    receipt = CycleLaunchReceipt.from_mapping(legacy)
    assert receipt.cycle_generation is None
    assert receipt.cycle_pid is None
    assert receipt.to_mapping() == legacy


def test_cycle_status_and_cancel_ops_flow_through_transport() -> None:
    seen: list[Mapping[str, Any]] = []

    def transport(request: Mapping[str, Any], timeout: float) -> Mapping[str, Any]:
        seen.append(request)
        return {
            "ok": True,
            "status": "running",
            "metering": {"requests": 2, "request_bytes": 10, "response_bytes": 20, "errors": 0},
        }

    supervisor = WslSupervisor(transport=transport, timeout_seconds=60)
    status = supervisor.cycle_status("campaign/one", 3, "status-1")
    assert status["status"] == "running"
    assert status["metering"]["requests"] == 2
    supervisor.cancel_cycle("campaign/one", 3, "cancel-1")
    assert seen[0]["operation"] == "cycle_status"
    assert seen[1]["operation"] == "cancel_cycle"
    assert seen[0]["generation"] == 3
    with pytest.raises(ValueError, match="positive integer"):
        supervisor.cycle_status("campaign/one", 0, "status-2")


@pytest.mark.skipif(os.name != "posix", reason="real supervisor agent requires Linux")
def test_linux_agent_launches_newly_activated_commit_and_is_idempotent(tmp_path: Path) -> None:
    from aegis.evolution.wsl_supervisor_agent import SupervisorAgent

    root, campaign, repo, commit_a, commit_b = _campaign(tmp_path, broken_b=False)
    agent = SupervisorAgent(
        root,
        use_mount_namespace=False,
        timeout_seconds=30,
        sidecar_launcher=_fake_sidecar,
    )

    first_request = _request("integration", commit_a, "launch-a", {"generation": 1})
    first = agent.handle(first_request)["receipt"]
    assert first["status"] == "launched"
    assert first["executed_commit"] == commit_a
    assert first["import_ok"] is True
    assert first["cycle_generation"] == 1
    assert first["cycle_pid"] > 1
    assert agent.handle(first_request)["receipt"] == first
    _await_terminal(agent, "integration", 1)

    _activate(campaign, repo, commit_a, commit_b)
    second = agent.handle(_request("integration", commit_b, "launch-b", {"generation": 2}))[
        "receipt"
    ]
    assert second["status"] == "launched"
    assert second["executed_commit"] == commit_b
    assert second["previous_champion"] == commit_a
    assert second["output_sha256"] != first["output_sha256"]
    _await_terminal(agent, "integration", 2)

    with pytest.raises(Exception, match="does not match"):
        agent.handle(_request("integration", commit_a, "stale-launch", {"generation": 3}))


@pytest.mark.skipif(os.name != "posix", reason="real supervisor agent requires Linux")
def test_linux_agent_returns_typed_boot_failure_with_lkg(tmp_path: Path) -> None:
    from aegis.evolution.wsl_supervisor_agent import SupervisorAgent

    root, campaign, repo, commit_a, commit_b = _campaign(tmp_path, broken_b=True)
    _activate(campaign, repo, commit_a, commit_b)
    receipt = SupervisorAgent(root, use_mount_namespace=False, timeout_seconds=30).handle(
        _request("integration", commit_b, "launch-b-broken", {"generation": 1})
    )["receipt"]

    assert receipt["status"] == "boot_failed"
    assert receipt["failure_kind"] == "import_failed"
    assert receipt["executed_commit"] == commit_b
    assert receipt["last_known_good"] == commit_a
    assert receipt["previous_champion"] == commit_a
    assert receipt["import_ok"] is False
    assert receipt["heartbeat_ok"] is False
    # A broken champion never reaches the cycle executor.
    assert "cycle_pid" not in receipt


@pytest.mark.skipif(os.name != "posix", reason="mount namespace requires Linux")
def test_linux_agent_probe_survives_private_mount_namespace(tmp_path: Path) -> None:
    from aegis.evolution.wsl_supervisor_agent import SupervisorAgent

    root, _campaign_path, _repo, commit_a, _commit_b = _campaign(tmp_path, broken_b=False)
    receipt = SupervisorAgent(
        root,
        use_mount_namespace=True,
        timeout_seconds=30,
        sidecar_launcher=_fake_sidecar,
    ).handle(_request("integration", commit_a, "launch-isolated", {"generation": 1}))["receipt"]

    assert receipt["status"] == "launched"
    summary = json.loads(receipt["output_summary"])
    events = [
        json.loads(line)
        for line in summary["stdout"].splitlines()
        if line.startswith("{")
    ]
    assert any(event.get("event") == "import" for event in events)
    assert any(event.get("event") == "heartbeat" for event in events)


@pytest.mark.skipif(os.name != "posix", reason="real supervisor agent requires Linux")
def test_linux_agent_cycle_status_reports_completion_and_metering(tmp_path: Path) -> None:
    from aegis.evolution.wsl_supervisor_agent import SupervisorAgent

    root, _campaign, _repo, commit_a, _commit_b = _campaign(tmp_path, broken_b=False)
    agent = SupervisorAgent(
        root,
        use_mount_namespace=False,
        timeout_seconds=30,
        sidecar_launcher=_fake_sidecar,
    )
    receipt = agent.handle(
        _request("integration", commit_a, "launch-a", {"generation": 99})
    )["receipt"]
    generation = receipt["cycle_generation"]
    assert generation == 1  # agent-side launch ordinal, not the payload hint
    status = _await_terminal(agent, "integration", generation)
    assert status["status"] == "completed"
    assert status["metering"]["requests"] == 2
    result = status["cycle_result"]
    assert result["version"] == "A"

    unknown = agent.handle(_request_status("integration", 99))["status"]
    assert unknown == "unknown"


def _await_terminal(agent: Any, campaign_id: str, generation: int, attempts: int = 200) -> Mapping:
    for _ in range(attempts):
        status = agent.handle(_request_status(campaign_id, generation))
        if status["status"] in {"completed", "failed", "cancelled"}:
            return status
        time.sleep(0.05)
    raise AssertionError("cycle did not reach a terminal status")


def _fake_sidecar(credentials: Mapping[str, Any], metering_path: Path) -> dict[str, Any]:
    class _FakeStdin:
        def close(self) -> None:
            return None

    class _FakeProcess:
        stdin = _FakeStdin()

    assert str(credentials.get("base_url", "")).startswith("https://")
    metering_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    metering_path.write_text(
        '{"outcome": "forwarded", "request_bytes": 10, "response_bytes": 20}\n'
        '{"outcome": "forwarded", "request_bytes": 30, "response_bytes": 40}\n',
        encoding="utf-8",
    )
    return {"process": _FakeProcess(), "port": 45678}


def _request(
    campaign_id: str, commit: str, operation_id: str, payload: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        "version": 1,
        "operation": "launch_cycle",
        "operation_id": operation_id,
        "campaign_id": campaign_id,
        "expected_commit": commit,
        "request_payload": dict(payload),
        "gateway_credentials": dict(_TEST_CREDENTIALS),
    }


def _request_status(campaign_id: str, generation: int) -> dict[str, Any]:
    return {
        "version": 1,
        "operation": "cycle_status",
        "operation_id": f"status-{generation}",
        "campaign_id": campaign_id,
        "generation": generation,
    }


def _campaign(tmp_path: Path, *, broken_b: bool) -> tuple[Path, Path, Path, str, str]:
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init", "--initial-branch=main")
    _git(source, "config", "user.name", "Test")
    _git(source, "config", "user.email", "test@invalid")
    _write_candidate(source, "A", broken=False)
    _git(source, "add", ".")
    _git(source, "commit", "-m", "commit A")
    commit_a = _git(source, "rev-parse", "HEAD").stdout.strip()
    _write_candidate(source, "B", broken=broken_b)
    _git(source, "add", ".")
    _git(source, "commit", "-m", "commit B")
    commit_b = _git(source, "rev-parse", "HEAD").stdout.strip()

    root = tmp_path / "campaigns"
    campaign_id = "integration"
    campaign = root / hashlib.sha256(campaign_id.encode()).hexdigest()
    repo = campaign / "repo.git"
    (campaign / "worktrees").mkdir(parents=True)
    (campaign / "operations").mkdir()
    _git(None, "clone", "--bare", str(source), str(repo))
    _git(repo, "update-ref", "refs/aegis/champion", commit_a)
    _git(
        repo,
        "worktree",
        "add",
        "--detach",
        str(campaign / "worktrees" / f"champion-{commit_a[:12]}"),
        commit_a,
    )
    (campaign / "state.json").write_text(
        canonical_json(
            {
                "campaign_id": campaign_id,
                "champion_commit": commit_a,
                "last_known_good": commit_a,
            }
        ),
        encoding="utf-8",
    )
    return root, campaign, repo, commit_a, commit_b


def _activate(campaign: Path, repo: Path, old: str, new: str) -> None:
    _git(repo, "update-ref", "refs/aegis/champion", new, old)
    _git(
        repo,
        "worktree",
        "add",
        "--detach",
        str(campaign / "worktrees" / f"champion-{new[:12]}"),
        new,
    )
    (campaign / "state.json").write_text(
        canonical_json(
            {
                "campaign_id": "integration",
                "champion_commit": new,
                "last_known_good": old,
            }
        ),
        encoding="utf-8",
    )


def _write_candidate(root: Path, version: str, *, broken: bool) -> None:
    package = root / "src" / "aegis" / "evolution"
    package.mkdir(parents=True, exist_ok=True)
    (root / "src" / "aegis" / "__init__.py").write_text("", encoding="utf-8")
    (package / "__init__.py").write_text("", encoding="utf-8")
    content = (
        "def run_cycle(payload):\n"
        f"    return {{'version': '{version}', 'generation': payload.get('generation')}}\n"
    )
    if broken:
        content = "def run_cycle(:\n"
    (package / "cycle_entrypoint.py").write_text(content, encoding="utf-8")


def _git(cwd: Path | None, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("git", *args), cwd=cwd, capture_output=True, text=True, check=True
    )
