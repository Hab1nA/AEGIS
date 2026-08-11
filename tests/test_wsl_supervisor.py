from __future__ import annotations

import hashlib
import json
import os
import subprocess
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


def _receipt(request: Mapping[str, Any]) -> dict[str, Any]:
    payload = {
        "operation_id": request["operation_id"],
        "campaign_id": request["campaign_id"],
        "campaign_key": hashlib.sha256(str(request["campaign_id"]).encode()).hexdigest(),
        "status": "completed",
        "failure_kind": None,
        "executed_commit": request["expected_commit"],
        "tree_hash": "b" * 40,
        "previous_champion": None,
        "last_known_good": request["expected_commit"],
        "import_ok": True,
        "heartbeat_ok": True,
        "exit_code": 0,
        "output_sha256": hashlib.sha256(b"").hexdigest(),
        "output_summary": "",
        "request_sha256": hashlib.sha256(canonical_json(request).encode()).hexdigest(),
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
        }
    ]
    assert supervisor.transport_argv() == (
        "wsl.exe",
        "--distribution",
        "AEGIS-Sandbox",
        "--",
        "/usr/local/bin/aegis-supervisor-agent",
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
        receipt["executed_commit"] = "c" * 40
        return {"ok": True, "receipt": receipt}

    with pytest.raises(WslSupervisorError, match="digest mismatch"):
        WslSupervisor(transport=transport).launch_cycle(
            "campaign", COMMIT_A, "launch-1", {}
        )


@pytest.mark.skipif(os.name != "posix", reason="real supervisor agent requires Linux")
def test_linux_agent_launches_newly_activated_commit_and_is_idempotent(tmp_path: Path) -> None:
    from aegis.evolution.wsl_supervisor_agent import SupervisorAgent

    root, campaign, repo, commit_a, commit_b = _campaign(tmp_path, broken_b=False)
    agent = SupervisorAgent(root, use_mount_namespace=False, timeout_seconds=30)

    first_request = _request("integration", commit_a, "launch-a", {"cycle": 1})
    first = agent.handle(first_request)["receipt"]
    assert first["status"] == "completed"
    assert first["executed_commit"] == commit_a
    assert first["import_ok"] is True
    assert agent.handle(first_request)["receipt"] == first

    _activate(campaign, repo, commit_a, commit_b)
    second = agent.handle(_request("integration", commit_b, "launch-b", {"cycle": 2}))[
        "receipt"
    ]
    assert second["status"] == "completed"
    assert second["executed_commit"] == commit_b
    assert second["previous_champion"] == commit_a
    assert second["output_sha256"] != first["output_sha256"]

    with pytest.raises(Exception, match="does not match"):
        agent.handle(_request("integration", commit_a, "stale-launch", {}))


@pytest.mark.skipif(os.name != "posix", reason="real supervisor agent requires Linux")
def test_linux_agent_returns_typed_boot_failure_with_lkg(tmp_path: Path) -> None:
    from aegis.evolution.wsl_supervisor_agent import SupervisorAgent

    root, campaign, repo, commit_a, commit_b = _campaign(tmp_path, broken_b=True)
    _activate(campaign, repo, commit_a, commit_b)
    receipt = SupervisorAgent(root, use_mount_namespace=False, timeout_seconds=30).handle(
        _request("integration", commit_b, "launch-b-broken", {})
    )["receipt"]

    assert receipt["status"] == "boot_failed"
    assert receipt["failure_kind"] == "import_failed"
    assert receipt["executed_commit"] == commit_b
    assert receipt["last_known_good"] == commit_a
    assert receipt["previous_champion"] == commit_a
    assert receipt["import_ok"] is False
    assert receipt["heartbeat_ok"] is False


@pytest.mark.skipif(os.name != "posix", reason="mount namespace requires Linux")
def test_linux_agent_launches_inside_private_mount_namespace(tmp_path: Path) -> None:
    from aegis.evolution.wsl_supervisor_agent import SupervisorAgent

    root, _campaign_path, _repo, commit_a, _commit_b = _campaign(
        tmp_path, broken_b=False
    )
    receipt = SupervisorAgent(root, use_mount_namespace=True, timeout_seconds=30).handle(
        _request("integration", commit_a, "launch-isolated", {})
    )["receipt"]

    assert receipt["status"] == "completed"
    summary = json.loads(receipt["output_summary"])
    complete = [
        json.loads(line)
        for line in summary["stdout"].splitlines()
        if '"event": "complete"' in line
    ][0]
    assert complete["result"]["mnt_entries"] == []


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
        "from pathlib import Path\n"
        "def run_cycle(payload):\n"
        f"    return {{'version': '{version}', 'payload': payload, "
        "'mnt_entries': sorted(p.name for p in Path('/mnt').iterdir())}\n"
    )
    if broken:
        content = "def run_cycle(:\n"
    (package / "cycle_entrypoint.py").write_text(content, encoding="utf-8")


def _git(cwd: Path | None, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("git", *args), cwd=cwd, capture_output=True, text=True, check=True
    )
