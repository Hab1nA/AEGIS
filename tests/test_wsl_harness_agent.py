"""Linux-agent tests for the frozen-path byte-comparison trust anchor.

The harness agent must reject any candidate commit whose diff against the
campaign's pinned ``source_ref`` touches a path outside the evolvable
harness grant — even when the whole champion tree is what executes.
"""

from __future__ import annotations

import base64
import hashlib
import os
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.name != "posix", reason="harness agent requires Linux")


COMMIT_A = "a" * 40


def _git(cwd: Path | None, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("git", *args), cwd=cwd, capture_output=True, text=True, check=True
    )


def _campaign(tmp_path: Path) -> tuple[Path, Any, str, str]:
    """Campaign with champion == pinned source_ref == commit_a."""
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init", "--initial-branch=main")
    _git(source, "config", "user.name", "Test")
    _git(source, "config", "user.email", "test@invalid")
    (source / "src" / "aegis" / "gateway").mkdir(parents=True)
    (source / "src" / "aegis" / "__init__.py").write_text("", encoding="utf-8")
    (source / "src" / "aegis" / "gateway" / "__init__.py").write_text("", encoding="utf-8")
    (source / "src" / "aegis" / "gateway" / "client.py").write_text(
        "VALUE = 1\n", encoding="utf-8"
    )
    (source / "src" / "aegis" / "cycle_ports.py").write_text("FROZEN = 1\n", encoding="utf-8")
    (source / "src" / "aegis" / "evolution").mkdir()
    (source / "src" / "aegis" / "evolution" / "__init__.py").write_text("", encoding="utf-8")
    (source / "src" / "aegis" / "evolution" / "surfaces.py").write_text(
        "RULES = 1\n", encoding="utf-8"
    )
    (source / "README.md").write_text("doc\n", encoding="utf-8")
    _git(source, "add", ".")
    _git(source, "commit", "-m", "source")
    commit_a = _git(source, "rev-parse", "HEAD").stdout.strip()

    from typing import Any

    from aegis.evolution.wsl_harness_agent import HarnessAgent

    root = tmp_path / "campaigns"
    campaign_id = "anchor"
    campaign = root / hashlib.sha256(campaign_id.encode()).hexdigest()
    agent = HarnessAgent(root)
    agent.handle(
        {
            "version": 1,
            "operation": "ensure_campaign",
            "operation_id": "ensure-1",
            "campaign_id": campaign_id,
            "source_url": str(source),
            "source_ref": commit_a,
        }
    )
    return campaign, agent, commit_a, campaign_id


def _checkpoint_request(
    campaign_id: str, candidate_id: str, base: str, changes: list[dict], *, meta: bool = False
) -> dict:
    return {
        "version": 1,
        "operation": "checkpoint",
        "operation_id": f"checkpoint-{candidate_id[:16]}",
        "campaign_id": campaign_id,
        "candidate_id": candidate_id,
        "base_commit": base,
        "changes": changes,
        "meta_evolution_enabled": meta,
    }


def test_checkpoint_rejects_frozen_path_modification(tmp_path: Path) -> None:
    campaign, agent, commit_a, campaign_id = _campaign(tmp_path)
    request = _checkpoint_request(
        campaign_id,
        "evolution-candidate-sha256:" + "1" * 64,
        commit_a,
        [
            {
                "path": "src/aegis/cycle_ports.py",
                "content_base64": __import__("base64").b64encode(b"FROZEN = 2\n").decode(),
                "delete": False,
                "executable": False,
            }
        ],
    )
    with pytest.raises(Exception, match="frozen path"):
        agent.handle(request)


def test_checkpoint_rejects_out_of_tree_paths(tmp_path: Path) -> None:
    campaign, agent, commit_a, campaign_id = _campaign(tmp_path)
    request = _checkpoint_request(
        campaign_id,
        "evolution-candidate-sha256:" + "2" * 64,
        commit_a,
        [
            {
                "path": "README.md",
                "content_base64": __import__("base64").b64encode(b"hacked\n").decode(),
                "delete": False,
                "executable": False,
            }
        ],
    )
    with pytest.raises(Exception, match="frozen path"):
        agent.handle(request)


def test_checkpoint_accepts_allowed_root_and_blocks_meta_without_flag(tmp_path: Path) -> None:
    campaign, agent, commit_a, campaign_id = _campaign(tmp_path)
    allowed = _checkpoint_request(
        campaign_id,
        "evolution-candidate-sha256:" + "3" * 64,
        commit_a,
        [
            {
                "path": "src/aegis/gateway/client.py",
                "content_base64": base64.b64encode(b"VALUE = 2\n").decode(),
                "delete": False,
                "executable": False,
            }
        ],
    )
    receipt = agent.handle(allowed)["receipt"]
    assert receipt["status"] == "checkpointed"

    meta_without_flag = _checkpoint_request(
        campaign_id,
        "evolution-candidate-sha256:" + "4" * 64,
        commit_a,
        [
            {
                "path": "src/aegis/evolution/surfaces.py",
                "content_base64": base64.b64encode(b"RULES = 2\n").decode(),
                "delete": False,
                "executable": False,
            }
        ],
    )
    with pytest.raises(Exception, match="frozen path"):
        agent.handle(meta_without_flag)

    meta_with_flag = _checkpoint_request(
        campaign_id,
        "evolution-candidate-sha256:" + "5" * 64,
        commit_a,
        [
            {
                "path": "src/aegis/evolution/surfaces.py",
                "content_base64": base64.b64encode(b"RULES = 2\n").decode(),
                "delete": False,
                "executable": False,
            }
        ],
        meta=True,
    )
    receipt = agent.handle(meta_with_flag)["receipt"]
    assert receipt["status"] == "checkpointed"
