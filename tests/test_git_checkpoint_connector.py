from __future__ import annotations

import base64
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from aegis.connectors import (
    CHECKPOINT_ACTION,
    ConnectorJournalError,
    GitCheckpointConnector,
    SqliteConnectorJournal,
    build_checkpoint_plugin,
    checkpoint_generation,
)
from aegis.models import Role
from aegis.plugins import (
    EffectClass,
    ExternalIntent,
    PluginExecutionError,
    PluginPolicy,
    ToolBroker,
)
from aegis.publishing import GitPublisher


def git(cwd: Path, *args: str) -> str:
    result = None
    last_error: OSError | None = None
    for attempt in range(4):
        try:
            result = subprocess.run(
                ("git", *args),
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=30,
            )
            break
        except OSError as exc:
            # Windows can transiently fail to duplicate a pipe handle when git
            # processes are spawned in quick succession (WinError 6).
            last_error = exc
            if os.name != "nt":
                raise
            time.sleep(0.25 * (attempt + 1))
    if result is None:
        assert last_error is not None
        raise last_error
    if result.returncode != 0:
        raise AssertionError(result.stderr.decode("utf-8", errors="replace"))
    return result.stdout.decode("utf-8", errors="strict").strip()


class DenyAllExecutor:
    def execute(self, manifest, grant, request):
        raise RuntimeError("external actions must never reach an executor")


class GitCheckpointConnectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.worktree = self.root / "worktree"
        self.remote = self.root / "public.git"
        self.worktree.mkdir()
        git(self.worktree, "init", "-b", "stable")
        git(self.worktree, "config", "user.name", "Test Operator")
        git(self.worktree, "config", "user.email", "operator@example.invalid")
        (self.worktree / "roles" / "warrior").mkdir(parents=True)
        (self.worktree / "roles" / "warrior" / "base.py").write_text("VALUE = 1\n", encoding="utf-8")
        git(self.worktree, "add", ".")
        git(self.worktree, "commit", "-m", "initial stable")
        self.base = git(self.worktree, "rev-parse", "HEAD")
        git(self.root, "init", "--bare", str(self.remote))
        git(self.worktree, "remote", "add", "origin", str(self.remote))
        git(self.worktree, "push", "-u", "origin", "stable")
        self.publisher = GitPublisher(
            str(self.remote),
            remote_id="public-test-origin",
            allowed_role_paths={"warrior": ("roles/warrior",)},
        )
        self.journal_path = self.root / "journal.sqlite3"
        self.journal = SqliteConnectorJournal(self.journal_path)
        self.connector = GitCheckpointConnector(self.publisher)
        self.manifest = build_checkpoint_plugin()
        self.generation = checkpoint_generation(source_commit=self.base)
        policy = PluginPolicy(
            allowed_effects=frozenset(
                {
                    EffectClass.PURE,
                    EffectClass.WORKSPACE_READ,
                    EffectClass.WORKSPACE_WRITE,
                    EffectClass.EXTERNAL,
                }
            ),
            allow_brokered_public_network=True,
        )
        self.broker = ToolBroker(
            self.generation,
            (self.manifest,),
            DenyAllExecutor(),
            policy=policy,
            external_connector=self.connector,
            external_journal=self.journal,
        )

    def tearDown(self) -> None:
        self.journal.close()
        self.temporary.cleanup()

    def arguments(self, *, path: str = "roles/warrior/strategy.py") -> dict[str, object]:
        return {
            "base_commit": self.base,
            "message": "candidate: warrior generation 2",
            "changes": (
                {
                    "path": path,
                    "delete": False,
                    "content_base64": base64.b64encode(b"QUALITY = 2\n").decode("ascii"),
                    "executable": False,
                },
            ),
        }

    def remote_head(self, ref: str) -> str | None:
        output = git(self.root, "ls-remote", "--heads", str(self.remote), ref)
        return output.partition("\t")[0] if output else None

    def execute(self, arguments: dict[str, object]):
        grant = self.broker.issue_grant(
            Role.WARRIOR, self.manifest.artifact_id, CHECKPOINT_ACTION, operation_id="op-1"
        )
        request = self.broker.create_request(grant, arguments)
        return self.broker.execute(request)

    def test_checkpoint_is_journaled_intent_first_and_published_to_candidate_ref(self) -> None:
        receipt = self.execute(self.arguments())
        output = dict(receipt.output)
        digest = self.generation.generation_id.removeprefix("sha256:")
        candidate_ref = f"refs/heads/candidate/warrior/gen-{digest[:40]}"
        self.assertEqual(output["ref"], candidate_ref)
        self.assertEqual(self.remote_head(candidate_ref), output["new_commit"])
        self.assertIsNotNone(receipt.intent_id)
        self.assertIsNotNone(receipt.external_receipt_id)
        self.assertEqual(len(self.journal.intents()), 1)
        self.assertEqual(len(self.journal.receipts()), 1)

    def test_candidate_ref_cannot_be_rewritten(self) -> None:
        self.execute(self.arguments())
        with self.assertRaises(PluginExecutionError):
            self.execute(self.arguments())

    def test_path_outside_role_grant_is_rejected_fail_closed(self) -> None:
        with self.assertRaises(PluginExecutionError):
            self.execute(self.arguments(path="README.md"))
        self.assertEqual(len(self.journal.receipts()), 0)

    def test_journal_rejects_replayed_intent_conflicts(self) -> None:
        intent = ExternalIntent.create(
            request_id="sha256:" + "1" * 64,
            connector_id=self.connector.connector_id,
            operation_id="op-1",
        )
        self.journal.record_intent(intent)
        conflict = ExternalIntent.create(
            request_id=intent.request_id,
            connector_id=self.connector.connector_id,
            operation_id="op-2",
        )
        with self.assertRaises(ConnectorJournalError):
            self.journal.record_intent(conflict)

    def test_journal_replay_is_idempotent(self) -> None:
        intent = ExternalIntent.create(
            request_id="sha256:" + "2" * 64,
            connector_id=self.connector.connector_id,
            operation_id="op-1",
        )
        self.journal.record_intent(intent)
        self.journal.record_intent(intent)
        self.assertEqual(len(self.journal.intents()), 1)
