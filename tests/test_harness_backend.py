from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from aegis.evolution.harness_backend import (
    HarnessBackendError,
    WslHarnessBackend,
)
from aegis.models import canonical_json

CAMPAIGN = "research/campaign-1"
COMMIT_A = "a" * 40
COMMIT_B = "b" * 40


def _receipt(
    request: Mapping[str, Any],
    *,
    champion: str = COMMIT_A,
    candidate: str | None = None,
) -> dict[str, Any]:
    payload = {
        "operation": request["operation"],
        "operation_id": request["operation_id"],
        "campaign_id": request["campaign_id"],
        "campaign_key": hashlib.sha256(str(request["campaign_id"]).encode()).hexdigest(),
        "status": "ok",
        "champion_commit": champion,
        "candidate_commit": candidate,
        "previous_champion": None,
        "detail": "",
        "request_sha256": hashlib.sha256(canonical_json(request).encode()).hexdigest(),
    }
    return {
        **payload,
        "receipt_sha256": hashlib.sha256(
            canonical_json(payload).encode()
        ).hexdigest(),
    }


def test_backend_uses_typed_bounded_requests() -> None:
    requests: list[Mapping[str, Any]] = []

    def transport(request: Mapping[str, Any], timeout: float) -> Mapping[str, Any]:
        assert timeout == 60
        requests.append(request)
        return {"ok": True, "receipt": _receipt(request, candidate=COMMIT_B)}

    backend = WslHarnessBackend(transport=transport, timeout_seconds=60)
    receipt = backend.checkpoint(
        CAMPAIGN,
        "candidate-1",
        COMMIT_A,
        [
            {
                "path": "src/aegis/evolution/example.py",
                "content_base64": base64.b64encode(b"VALUE = 1\n").decode(),
                "delete": False,
                "executable": False,
            }
        ],
        "cycle-1-checkpoint",
    )

    assert receipt.candidate_commit == COMMIT_B
    assert requests == [
        {
            "version": 1,
            "operation": "checkpoint",
            "operation_id": "cycle-1-checkpoint",
            "campaign_id": CAMPAIGN,
            "candidate_id": "candidate-1",
            "base_commit": COMMIT_A,
            "changes": [
                {
                    "path": "src/aegis/evolution/example.py",
                    "content_base64": "VkFMVUUgPSAxCg==",
                    "delete": False,
                    "executable": False,
                }
            ],
        }
    ]


@pytest.mark.parametrize(
    "source",
    [
        r"C:\repo",
        r"\\server\repo",
        "file:///mnt/c/repo",
        "https://user:secret@example.test/repo.git",
        "https://example.test/repo.git?token=secret",
        "http://example.test/repo.git",
        "https://127.0.0.1/repo.git",
        "https://localhost/repo.git",
    ],
)
def test_backend_rejects_host_paths_and_credentialed_sources(source: str) -> None:
    backend = WslHarnessBackend(transport=lambda request, timeout: {})
    with pytest.raises(ValueError):
        backend.ensure_campaign(CAMPAIGN, source, COMMIT_A, "ensure-1")


def test_backend_requires_pinned_source_ref() -> None:
    backend = WslHarnessBackend(transport=lambda request, timeout: {})
    with pytest.raises(ValueError, match="pinned"):
        backend.ensure_campaign(
            CAMPAIGN, "https://example.test/repo.git", "main", "ensure-1"
        )


def test_backend_rejects_tampered_or_cross_request_receipt() -> None:
    def tampered(request: Mapping[str, Any], timeout: float) -> Mapping[str, Any]:
        del timeout
        receipt = _receipt(request)
        receipt["campaign_id"] = "another-campaign"
        return {"ok": True, "receipt": receipt}

    with pytest.raises(HarnessBackendError, match="digest mismatch"):
        WslHarnessBackend(transport=tampered).status(CAMPAIGN, "status-1")


def test_transport_command_is_fixed_and_shell_free(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: dict[str, Any] = {}

    def run(argv: object, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        observed["argv"] = argv
        observed.update(kwargs)
        request = json.loads(kwargs["input"].decode("utf-8"))
        return subprocess.CompletedProcess(
            argv,
            0,
            json.dumps({"ok": True, "receipt": _receipt(request)}).encode("utf-8"),
            b"",
        )

    monkeypatch.setattr(subprocess, "run", run)
    backend = WslHarnessBackend(distribution="AEGIS-Sandbox")
    backend.status(CAMPAIGN, "status-1")

    assert observed["argv"] == (
        "wsl.exe",
        "--distribution",
        "AEGIS-Sandbox",
        "--",
        "/usr/local/bin/aegis-harness-agent",
    )
    assert observed["shell"] is False
    assert "candidate" not in " ".join(observed["argv"])


@pytest.mark.skipif(os.name != "posix", reason="real Git harness agent requires Linux flock")
def test_linux_agent_real_git_checkpoint_activate_and_rollback(tmp_path: Path) -> None:
    from aegis.evolution.wsl_harness_agent import HarnessAgent

    source = tmp_path / "source"
    source.mkdir()
    _run_git(source, "init", "--initial-branch=main")
    _run_git(source, "config", "user.name", "Test")
    _run_git(source, "config", "user.email", "test@invalid")
    (source / "README.md").write_text("base\n", encoding="utf-8")
    _run_git(source, "add", "README.md")
    _run_git(source, "commit", "-m", "base")
    base = _run_git(source, "rev-parse", "HEAD").stdout.strip()

    root = tmp_path / "campaigns"
    campaign_id = "linux-integration"
    key = hashlib.sha256(campaign_id.encode()).hexdigest()
    campaign = root / key
    repo = campaign / "repo.git"
    worktrees = campaign / "worktrees"
    worktrees.mkdir(parents=True)
    for name in ("events", "artifacts", "operations"):
        (campaign / name).mkdir()
    _run_git(None, "clone", "--bare", str(source), str(repo))
    _run_git(repo, "update-ref", "refs/aegis/champion", base)
    _run_git(repo, "worktree", "add", "--detach", str(worktrees / f"champion-{base[:12]}"), base)
    (campaign / "state.json").write_text(
        json.dumps(
            {
                "campaign_id": campaign_id,
                "source_url": "https://example.invalid/repo.git",
                "source_ref": base,
                "champion_commit": base,
                "last_known_good": base,
            }
        ),
        encoding="utf-8",
    )
    agent = HarnessAgent(root)
    change = {
        "path": "src/aegis/evolution/value.py",
        "content_base64": base64.b64encode(b"VALUE = 2\n").decode(),
        "delete": False,
        "executable": False,
    }
    checkpoint_request = {
        "version": 1,
        "operation": "checkpoint",
        "operation_id": "checkpoint-1",
        "campaign_id": campaign_id,
        "candidate_id": "candidate-1",
        "base_commit": base,
        "changes": [change],
    }
    first = agent.handle(checkpoint_request)["receipt"]
    second = agent.handle(checkpoint_request)["receipt"]
    assert first == second
    candidate = first["candidate_commit"]
    assert candidate != base

    activated = agent.handle(
        {
            "version": 1,
            "operation": "activate",
            "operation_id": "activate-1",
            "campaign_id": campaign_id,
            "candidate_id": "candidate-1",
            "candidate_commit": candidate,
            "expected_champion": base,
        }
    )["receipt"]
    assert activated["champion_commit"] == candidate
    (campaign / "operations" / "activate-1.json").unlink()
    assert agent.handle(
        {
            "version": 1,
            "operation": "activate",
            "operation_id": "activate-1",
            "campaign_id": campaign_id,
            "candidate_id": "candidate-1",
            "candidate_commit": candidate,
            "expected_champion": base,
        }
    )["receipt"]["champion_commit"] == candidate
    rolled_back = agent.handle(
        {
            "version": 1,
            "operation": "rollback",
            "operation_id": "rollback-1",
            "campaign_id": campaign_id,
            "failed_commit": candidate,
            "target_commit": base,
        }
    )["receipt"]
    assert rolled_back["champion_commit"] == base
    (campaign / "operations" / "rollback-1.json").unlink()
    assert agent.handle(
        {
            "version": 1,
            "operation": "rollback",
            "operation_id": "rollback-1",
            "campaign_id": campaign_id,
            "failed_commit": candidate,
            "target_commit": base,
        }
    )["receipt"]["champion_commit"] == base
    assert not _contains_reset_hard()


def _run_git(cwd: Path | None, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("git", *args), cwd=cwd, capture_output=True, text=True, check=True
    )


def _contains_reset_hard() -> bool:
    source = Path(__file__).parents[1] / "src" / "aegis" / "evolution" / "wsl_harness_agent.py"
    return "reset --hard" in source.read_text(encoding="utf-8")
