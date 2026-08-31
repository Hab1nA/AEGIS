from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from aegis.agent_runtime import (
    WORKFLOW_ARTIFACT_SCHEMA,
    Action,
    ActionError,
    RoleAgentRuntime,
    RuntimeLimits,
    StepLimitExceeded,
    ToolDispatcher,
    ToolObservation,
)
from aegis.challenges import SealedTaskMetadata
from aegis.gateway.protocols import Role
from aegis.gateway.types import GatewayResponse, GatewayTruncationError, TokenUsage
from aegis.knowledge import KnowledgeStore
from aegis.research.imports import validate_skill_import
from aegis.research.paper_collector import PaperCollectionError
from aegis.research.types import Provenance, ResearchArtifact, SearchHit
from aegis.sandbox.fake import FakeSandboxBackend
from aegis.sandbox.types import CommandResult
from aegis.skill_registry import SkillPromotionEvidence, SkillRegistry


def git_blob_sha(content: bytes) -> str:
    return hashlib.sha1(
        f"blob {len(content)}\0".encode("ascii") + content,
        usedforsecurity=False,
    ).hexdigest()


def github_file(repository: str, commit: str, path: str, content: bytes) -> SimpleNamespace:
    url = repository.replace("https://github.com/", "https://raw.githubusercontent.com/")
    url += f"/{commit}/{path}"
    sha256 = hashlib.sha256(content).hexdigest()
    provenance = Provenance(
        url, url, "2026-01-01T00:00:00+00:00", sha256, len(content), "text/markdown", ()
    )
    return SimpleNamespace(
        path=path,
        content=content,
        size_bytes=len(content),
        sha256=sha256,
        git_blob_sha=git_blob_sha(content),
        media_type="text/markdown",
        provenance=provenance,
    )


class FakeGateway:
    def __init__(self, actions: list[dict[str, object]]) -> None:
        self.actions = list(actions)
        self.requests = []

    def complete(self, request, *, cancel=None):
        self.requests.append(request)
        action = self.actions.pop(0)
        return GatewayResponse(json.dumps(action), TokenUsage(5, 3, verified=True), "fake")


class MemorySandbox:
    """Emulates only the sandbox boundary used by workspace helpers."""

    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}
        self.commands = []

    def exec(self, sandbox_id, command):
        self.commands.append((sandbox_id, command))
        if command.argv[:2] == ("python3", "-c") and "target.write_bytes" in command.argv[2]:
            path, encoded = command.argv[3], command.argv[4]
            self.files[path] = base64.b64decode(encoded)
            return CommandResult(0, str(len(self.files[path])) + "\n", "", 0.01)
        if command.argv[:2] == ("python3", "-c") and "target.read_bytes" in command.argv[2]:
            path = command.argv[3]
            if path not in self.files:
                return CommandResult(1, "", "not found", 0.01)
            return CommandResult(0, base64.b64encode(self.files[path]).decode(), "", 0.01)
        return CommandResult(0, "ran", "", 0.01)


class FakeResearch:
    def __init__(self) -> None:
        self.searches = []
        self.fetches = []

    def search(self, query: str, *, limit: int = 10):
        self.searches.append((query, limit))
        return [SearchHit("https://example.test/paper", "Paper", "abstract")]

    def fetch(self, url: str, *, validate_as_archive: bool = False):
        self.fetches.append(url)
        content = b"research"
        return ResearchArtifact(
            content,
            Provenance(
                url,
                url,
                "2026-01-01T00:00:00+00:00",
                hashlib.sha256(content).hexdigest(),
                len(content),
                "text/plain",
                (),
            ),
        )


def call(name: str, **arguments: object) -> dict[str, object]:
    return {"action": name, "arguments": arguments}


def workflow(proposal_id: str = "workflow-1", target_role: str = "warrior") -> dict[str, object]:
    return {
        "proposal_id": proposal_id,
        "target_role": target_role,
        "workflow": {
            "stage_plan": ["Inspect", "Research", "Implement", "Verify"],
            "research_query_templates": ["{language} {failure} property testing"],
            "tool_selection_rules": ["Search before relying on an uncertain API."],
            "stop_conditions": ["Stop when regression tests pass."],
            "verification_checklist": ["Run focused tests and the relevant suite."],
            "skill_references": ["github.com/example/testing-skill@abc123"],
            "max_steps": 30,
        },
        "rationale": "The staged workflow should reduce avoidable rework.",
    }


class ActionTests(unittest.TestCase):
    def test_action_envelope_is_exact(self) -> None:
        parsed = Action.parse(json.dumps(call("submit", summary="ok", payload={})))
        self.assertEqual(parsed.name, "submit")
        with self.assertRaisesRegex(ActionError, "exactly"):
            Action.parse('{"action":"submit","arguments":{},"extra":1}')
        with self.assertRaisesRegex(ActionError, "valid JSON"):
            Action.parse("not-json")


class DispatcherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sandbox = MemorySandbox()
        self.research = FakeResearch()
        self.dispatcher = ToolDispatcher(self.sandbox, self.research, "box")

    def test_workspace_io_is_base64_and_only_uses_sandbox_exec(self) -> None:
        encoded = base64.b64encode(b"print('ok')\n").decode()
        written = self.dispatcher.dispatch(
            Role.WARRIOR, Action("workspace.write", {"path": "src/main.py", "content_base64": encoded})
        )
        read = self.dispatcher.dispatch(Role.JUDGE, Action("workspace.read", {"path": "src/main.py"}))
        self.assertEqual(written["size_bytes"], 12)
        self.assertEqual(base64.b64decode(read["content_base64"]), b"print('ok')\n")
        self.assertEqual([item[1].argv[0] for item in self.sandbox.commands], ["python3", "python3"])
        self.assertTrue(all(item[1].cwd == "." for item in self.sandbox.commands))

    def test_role_permissions_enforce_judge_no_write_and_prosecutor_read_only(self) -> None:
        encoded = base64.b64encode(b"x").decode()
        with self.assertRaisesRegex(ActionError, "judge is not allowed"):
            self.dispatcher.dispatch(
                Role.JUDGE, Action("workspace.write", {"path": "x", "content_base64": encoded})
            )
        with self.assertRaisesRegex(ActionError, "prosecutor is not allowed"):
            self.dispatcher.dispatch(Role.PROSECUTOR, Action("sandbox.exec", {"argv": ["true"]}))
        with self.assertRaisesRegex(ActionError, "prosecutor is not allowed"):
            self.dispatcher.dispatch(
                Role.PROSECUTOR, Action("workspace.write", {"path": "x", "content_base64": encoded})
            )

    def test_schema_path_size_and_output_limits(self) -> None:
        with self.assertRaisesRegex(ActionError, "arguments"):
            self.dispatcher.dispatch(Role.WARRIOR, Action("workspace.read", {"path": "x", "extra": 1}))
        with self.assertRaisesRegex(ActionError, "safe POSIX"):
            self.dispatcher.dispatch(Role.WARRIOR, Action("workspace.read", {"path": "../secret"}))
        tiny = ToolDispatcher(
            self.sandbox,
            self.research,
            "box",
            limits=RuntimeLimits(max_write_bytes=1),
        )
        with self.assertRaisesRegex(ActionError, "size limit"):
            tiny.dispatch(
                Role.WARRIOR,
                Action(
                    "workspace.write",
                    {"path": "x", "content_base64": base64.b64encode(b"xx").decode()},
                ),
            )
        noisy = ToolDispatcher(
            self.sandbox,
            self.research,
            "box",
            limits=RuntimeLimits(max_tool_output_bytes=2),
        )
        with self.assertRaisesRegex(ActionError, "output"):
            noisy.dispatch(Role.WARRIOR, Action("sandbox.exec", {"argv": ["true"]}))

    def test_research_calls_real_interface_and_returns_provenance(self) -> None:
        result = self.dispatcher.dispatch(
            Role.WARRIOR, Action("research.search", {"query": "agent tests", "limit": 1})
        )
        artifact = self.dispatcher.dispatch(
            Role.JUDGE, Action("research.fetch", {"url": result["hits"][0]["url"]})
        )
        self.assertEqual(self.research.searches, [("agent tests", 1)])
        self.assertEqual(self.research.fetches, ["https://example.test/paper"])
        self.assertEqual(artifact["provenance"]["sha256"], hashlib.sha256(b"research").hexdigest())
        self.assertEqual(base64.b64decode(artifact["content_base64"]), b"research")

    def test_research_import_binds_only_current_fetched_content_without_execution(self) -> None:
        fetched = self.dispatcher.dispatch(
            Role.WARRIOR, Action("research.fetch", {"url": "https://example.test/paper"})
        )
        digest = fetched["provenance"]["sha256"]
        manifest = {
            "schema_version": 1,
            "kind": "paper",
            "source_url": "https://example.test/paper",
            "content_sha256": digest,
            "size_bytes": len(b"research"),
            "metadata": {
                "title": "Verified testing research",
                "authors": ["Ada Example"],
                "identifier": "doi:10.1234/example.1",
                "provenance": [
                    {
                        "source_url": "https://example.test/paper",
                        "locator_type": "paragraph",
                        "locator": "3",
                        "content_sha256": "1" * 64,
                    }
                ],
            },
        }
        result = self.dispatcher.dispatch(
            Role.WARRIOR,
            Action("research.import", {"sha256": digest, "manifest": manifest}),
        )
        self.assertEqual(result["candidate"]["kind"], "paper")
        self.assertFalse(result["execution_granted"])
        with self.assertRaisesRegex(ActionError, "fetched in this role run"):
            self.dispatcher.dispatch(
                Role.WARRIOR,
                Action("research.import", {"sha256": "0" * 64, "manifest": manifest}),
            )

    def test_validated_skill_import_is_quarantined_in_registry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with SkillRegistry(Path(directory) / "skills.sqlite3") as skills:
                dispatcher = ToolDispatcher(
                    self.sandbox, self.research, "box", skills=skills
                )
                fetched = dispatcher.dispatch(
                    Role.WARRIOR,
                    Action("research.fetch", {"url": "https://example.test/paper"}),
                )
                digest = fetched["provenance"]["sha256"]
                manifest = {
                    "schema_version": 1,
                    "kind": "skill",
                    "source_url": "https://example.test/paper",
                    "content_sha256": digest,
                    "size_bytes": len(b"research"),
                    "metadata": {
                        "name": "testing-helper",
                        "version": "1.0.0",
                        "permissions": ["workspace.read"],
                        "dependencies": [],
                    },
                }
                result = dispatcher.dispatch(
                    Role.WARRIOR,
                    Action("research.import", {"sha256": digest, "manifest": manifest}),
                )
                self.assertEqual(result["skill_registry_state"], "validated_pending")
                candidate = skills.candidate("testing-helper", "1.0.0")
                self.assertEqual(candidate.artifact.artifact_id, result["candidate"]["artifact_id"])
                self.assertFalse(result["execution_granted"])

    def test_github_actions_collect_pinned_snapshot_then_read_only_listed_file(self) -> None:
        artifact = Mock()
        artifact.artifact_id = "snapshot-id"
        artifact.source_url = "https://github.com/example/project/tree/" + "a" * 40
        artifact.to_dict.return_value = {"artifact_id": "snapshot-id", "kind": "github"}
        snapshot = SimpleNamespace(
            artifact=artifact,
            snapshot_sha256="c" * 64,
            tree_sha="b" * 40,
            license_spdx="MIT",
            files=(
                SimpleNamespace(
                    path="src/main.py",
                    content=b"print('safe reference')\n",
                    size_bytes=24,
                    sha256=hashlib.sha256(b"print('safe reference')\n").hexdigest(),
                ),
            ),
        )
        with patch("aegis.agent_runtime.GitHubCollector") as collector_type:
            collector_type.return_value.collect.return_value = snapshot
            collected = self.dispatcher.dispatch(
                Role.WARRIOR,
                Action(
                    "github.collect",
                    {
                        "repository_url": "https://github.com/example/project",
                        "commit_sha": "a" * 40,
                    },
                ),
            )
        self.assertFalse(collected["execution_granted"])
        self.assertEqual(collected["files"][0]["path"], "src/main.py")
        self.assertEqual(collected["next_action"]["action"], "github.file_read")
        self.assertEqual(collected["next_action"]["arguments"]["path"], "src/main.py")
        read = self.dispatcher.dispatch(
            Role.WARRIOR,
            Action("github.file_read", {"artifact_id": "snapshot-id", "path": "src/main.py"}),
        )
        self.assertEqual(base64.b64decode(read["content_base64"]), b"print('safe reference')\n")
        with self.assertRaisesRegex(ActionError, "not present"):
            self.dispatcher.dispatch(
                Role.WARRIOR,
                Action("github.file_read", {"artifact_id": "snapshot-id", "path": "secrets.env"}),
            )

    def test_github_resolve_returns_exact_commit_and_collect_action(self) -> None:
        resolved = SimpleNamespace(
            repository_url="https://github.com/example/project",
            requested_ref="HEAD",
            commit_sha="a" * 40,
            provenance=Provenance(
                "https://api.github.com/repos/example/project/commits/HEAD",
                "https://api.github.com/repos/example/project/commits/HEAD",
                "2026-01-01T00:00:00+00:00",
                "b" * 64,
                52,
                "application/json",
                (),
            ),
        )
        with patch("aegis.agent_runtime.GitHubCollector") as collector_type:
            collector_type.return_value.resolve.return_value = resolved
            result = self.dispatcher.dispatch(
                Role.WARRIOR,
                Action(
                    "github.resolve",
                    {"repository_url": "https://github.com/example/project"},
                ),
            )
        self.assertEqual(result["commit_sha"], "a" * 40)
        self.assertFalse(result["execution_granted"])
        self.assertEqual(result["next_action"]["action"], "github.collect")
        self.assertEqual(result["next_action"]["arguments"]["commit_sha"], "a" * 40)

    def test_github_network_failures_are_recoverable_action_errors(self) -> None:
        with patch("aegis.agent_runtime.GitHubCollector") as collector_type:
            collector_type.return_value.resolve.side_effect = OSError("approved addresses failed")
            with self.assertRaisesRegex(ActionError, "approved addresses failed"):
                self.dispatcher.dispatch(
                    Role.WARRIOR,
                    Action("github.resolve", {"repository_url": "https://github.com/example/project"}),
                )
            collector_type.return_value.collect.side_effect = OSError("approved addresses failed")
            with self.assertRaisesRegex(ActionError, "approved addresses failed"):
                self.dispatcher.dispatch(
                    Role.WARRIOR,
                    Action(
                        "github.collect",
                        {
                            "repository_url": "https://github.com/example/project",
                            "commit_sha": "a" * 40,
                        },
                    ),
                )

    def test_github_snapshot_is_recalled_and_sources_an_evolution_request_across_runs(self) -> None:
        content = b"def bounded_retry():\n    return 3\n"
        snapshot_digest = "c" * 64
        artifact_id = "sha256:" + "d" * 64
        artifact = Mock()
        artifact.artifact_id = artifact_id
        artifact.source_url = "https://github.com/example/project/tree/" + "a" * 40
        artifact.to_dict.return_value = {"artifact_id": artifact_id, "kind": "github"}
        snapshot = SimpleNamespace(
            repository_url="https://github.com/example/project",
            commit_sha="a" * 40,
            artifact=artifact,
            snapshot_sha256=snapshot_digest,
            tree_sha="b" * 40,
            license_spdx="MIT",
            files=(
                github_file(
                    "https://github.com/example/project", "a" * 40, "src/retry.py", content
                ),
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            with KnowledgeStore(Path(directory) / "knowledge.sqlite3") as knowledge:
                first = ToolDispatcher(self.sandbox, self.research, "box", knowledge=knowledge)
                with patch("aegis.agent_runtime.GitHubCollector") as collector_type:
                    collector_type.return_value.collect.return_value = snapshot
                    first.dispatch(
                        Role.WARRIOR,
                        Action(
                            "github.collect",
                            {
                                "repository_url": "https://github.com/example/project",
                                "commit_sha": "a" * 40,
                            },
                        ),
                    )

                second = ToolDispatcher(self.sandbox, self.research, "box", knowledge=knowledge)
                recalled = second.dispatch(
                    Role.WARRIOR, Action("research.recall", {"sha256": snapshot_digest})
                )
                self.assertEqual(recalled["artifacts"][0]["artifact_id"], artifact_id)
                read = second.dispatch(
                    Role.WARRIOR,
                    Action("github.file_read", {"artifact_id": artifact_id, "path": "src/retry.py"}),
                )
                self.assertEqual(base64.b64decode(read["content_base64"]), content)
                requested = second.dispatch(
                    Role.WARRIOR,
                    Action(
                        "evolution.request",
                        {
                            "objective": "Improve bounded retry selection.",
                            "rationale": "Pinned reference demonstrates a simpler bounded policy.",
                            "source_refs": [
                                {"artifact_id": artifact_id, "locator": "path:src/retry.py"}
                            ],
                        },
                    ),
                )
                self.assertEqual(
                    requested["rationale"],
                    "Pinned reference demonstrates a simpler bounded policy.",
                )
                self.assertEqual(requested["source_refs"][0]["artifact_id"], artifact_id)
                self.assertEqual(requested["source_refs"][0]["content_sha256"], snapshot_digest)
                self.assertEqual(requested["source_refs"][0]["blob_sha256"], hashlib.sha256(content).hexdigest())
                self.assertFalse(requested["host_write_allowed"])

    def test_exact_commit_github_skill_bundle_is_recallable_and_auto_queued(self) -> None:
        repository = "https://github.com/example/skills"
        commit = "a" * 40
        skill_md = b"# Retry reviewer\n\nReview retry bounds before editing.\n"
        reference = b"# Checklist\n\n- Verify a finite attempt limit.\n"
        executable = b"print('must never be bundled')\n"
        artifact = Mock()
        artifact.artifact_id = "e" * 64
        artifact.source_url = f"{repository}/tree/{commit}"
        artifact.to_dict.return_value = {"artifact_id": artifact.artifact_id, "kind": "github"}
        snapshot = SimpleNamespace(
            artifact=artifact,
            repository_url=repository,
            commit_sha=commit,
            snapshot_sha256="c" * 64,
            tree_sha="b" * 40,
            license_spdx="MIT",
            files=(
                github_file(repository, commit, "skills/retry/SKILL.md", skill_md),
                github_file(repository, commit, "skills/retry/references/checklist.md", reference),
                github_file(repository, commit, "skills/retry/scripts/install.py", executable),
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            with (
                KnowledgeStore(Path(directory) / "knowledge.sqlite3") as knowledge,
                SkillRegistry(Path(directory) / "skills.sqlite3") as skills,
            ):
                first = ToolDispatcher(
                    self.sandbox, self.research, "box", knowledge=knowledge, skills=skills
                )
                with patch("aegis.agent_runtime.GitHubCollector") as collector_type:
                    collector_type.return_value.collect.return_value = snapshot
                    first.dispatch(
                        Role.WARRIOR,
                        Action(
                            "github.collect",
                            {"repository_url": repository, "commit_sha": commit},
                        ),
                    )
                recalled = ToolDispatcher(
                    self.sandbox, self.research, "box", knowledge=knowledge, skills=skills
                )
                listing = recalled.dispatch(
                    Role.WARRIOR, Action("research.recall", {"sha256": "c" * 64})
                )
                result = recalled.dispatch(
                    Role.WARRIOR,
                    Action(
                        "github.skill_bundle",
                        {
                            "artifact_id": listing["artifacts"][0]["artifact_id"],
                            "root": "skills/retry",
                            "name": "retry-reviewer",
                            "version": "1.0.0",
                        },
                    ),
                )
                self.assertEqual(result["skill_registry_state"], "validated_pending")
                self.assertTrue(result["automatic_promotion_eligible"])
                self.assertEqual(
                    [item["path"] for item in result["files"]],
                    ["SKILL.md", "references/checklist.md"],
                )
                self.assertTrue(result["persistent_archive"]["archived"])
                candidate = skills.candidate("retry-reviewer", "1.0.0")
                self.assertEqual(candidate.state.value, "validated_pending")
                archived = knowledge.research_by_hash(result["bundle_sha256"])[0]
                self.assertEqual(archived.descriptor["commit_sha"], commit)
                self.assertEqual(archived.descriptor["files"][0]["git_blob_sha"], git_blob_sha(skill_md))
                self.assertEqual(
                    [blob.locator for blob in archived.blobs],
                    ["skill:SKILL.md", "skill:references/checklist.md"],
                )
                self.assertEqual(archived.blobs[1].content, reference)
                with self.assertRaisesRegex(ActionError, "judge is not allowed"):
                    recalled.dispatch(
                        Role.JUDGE,
                        Action(
                            "github.skill_bundle",
                            {
                                "artifact_id": artifact.artifact_id,
                                "root": "skills/retry",
                                "name": "retry-reviewer",
                                "version": "1.0.1",
                            },
                        ),
                    )

    def test_only_promoted_skill_is_staged_into_current_sandbox(self) -> None:
        content = b"promoted skill payload"
        artifact = validate_skill_import(
            {
                "schema_version": 1,
                "kind": "skill",
                "source_url": "https://skills.example.test/testing-helper/1.0.0",
                "content_sha256": hashlib.sha256(content).hexdigest(),
                "size_bytes": len(content),
                "metadata": {
                    "name": "testing-helper",
                    "version": "1.0.0",
                    "permissions": ["workspace.read"],
                    "dependencies": [],
                },
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            with SkillRegistry(Path(directory) / "skills.sqlite3") as skills:
                skills.register_candidate(artifact, content)
                skills.promote(
                    "testing-helper",
                    "1.0.0",
                    SkillPromotionEvidence(
                        artifact.artifact_id,
                        True,
                        True,
                        "a" * 64,
                        "b" * 64,
                    ),
                )
                sandbox = FakeSandboxBackend()
                sandbox.prepare("box")
                dispatcher = ToolDispatcher(
                    sandbox, self.research, "box", skills=skills
                )
                listed = dispatcher.dispatch(Role.WARRIOR, Action("skill.list", {}))
                self.assertEqual(listed["champions"][0]["name"], "testing-helper")
                staged = dispatcher.dispatch(
                    Role.WARRIOR, Action("skill.stage", {"name": "testing-helper"})
                )
                self.assertTrue(staged["sandbox_only"])
                self.assertIn(
                    ".aegis/skills/testing-helper/active/SKILL.md", sandbox._files["box"]
                )
                with self.assertRaisesRegex(ActionError, "prosecutor is not allowed"):
                    dispatcher.dispatch(
                        Role.PROSECUTOR,
                        Action("skill.stage", {"name": "testing-helper"}),
                    )

    def test_paper_actions_collect_exact_identifier_then_read_citable_excerpt(self) -> None:
        artifact = Mock()
        artifact.artifact_id = "paper-id"
        artifact.content_sha256 = "d" * 64
        artifact.source_url = "https://papers.example.org/paper.txt"
        artifact.to_dict.return_value = {"artifact_id": "paper-id", "kind": "paper"}
        excerpt = SimpleNamespace(
            locator_type="paragraph",
            locator="p2",
            text="Bounded verification improves reliability.",
            sha256=hashlib.sha256(b"Bounded verification improves reliability.").hexdigest(),
        )
        snapshot = SimpleNamespace(
            artifact=artifact,
            identifier="doi:10.1234/example.1",
            title="Verified Agents",
            authors=("Ada Example",),
            excerpts=(excerpt,),
            content_provenance=SimpleNamespace(media_type="text/plain"),
        )
        with patch("aegis.agent_runtime.PaperCollector") as collector_type:
            collector_type.return_value.collect.return_value = snapshot
            collected = self.dispatcher.dispatch(
                Role.WARRIOR,
                Action("paper.collect", {"identifier": "doi:10.1234/example.1"}),
            )
        self.assertFalse(collected["execution_granted"])
        self.assertEqual(collected["excerpts"][0]["locator"], "p2")
        read = self.dispatcher.dispatch(
            Role.WARRIOR,
            Action(
                "paper.excerpt_read",
                {"artifact_id": "paper-id", "locator_type": "paragraph", "locator": "p2"},
            ),
        )
        self.assertEqual(read["text"], excerpt.text)
        with self.assertRaisesRegex(ActionError, "not present"):
            self.dispatcher.dispatch(
                Role.WARRIOR,
                Action(
                    "paper.excerpt_read",
                    {"artifact_id": "paper-id", "locator_type": "page", "locator": "99"},
                ),
            )

    def test_paper_excerpt_is_persisted_and_read_across_role_runs(self) -> None:
        text = "Bounded verification improves reliability."
        content = text.encode("utf-8")
        digest = hashlib.sha256(content).hexdigest()
        artifact_id = "sha256:" + "e" * 64
        artifact = Mock()
        artifact.artifact_id = artifact_id
        artifact.content_sha256 = digest
        artifact.source_url = "https://papers.example.org/paper.txt"
        artifact.to_dict.return_value = {"artifact_id": artifact_id, "kind": "paper"}
        excerpt = SimpleNamespace(
            locator_type="paragraph",
            locator="p1",
            text=text,
            sha256=digest,
        )
        snapshot = SimpleNamespace(
            artifact=artifact,
            identifier="doi:10.1234/example.1",
            title="Verified Agents",
            authors=("Ada Example",),
            content=content,
            excerpts=(excerpt,),
            content_provenance=SimpleNamespace(
                media_type="text/plain", sha256=digest, size_bytes=len(content)
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            with KnowledgeStore(Path(directory) / "knowledge.sqlite3") as knowledge:
                first = ToolDispatcher(self.sandbox, self.research, "box", knowledge=knowledge)
                with patch("aegis.agent_runtime.PaperCollector") as collector_type:
                    collector_type.return_value.collect.return_value = snapshot
                    first.dispatch(
                        Role.WARRIOR,
                        Action("paper.collect", {"identifier": "doi:10.1234/example.1"}),
                    )
                second = ToolDispatcher(self.sandbox, self.research, "box", knowledge=knowledge)
                read = second.dispatch(
                    Role.WARRIOR,
                    Action(
                        "paper.excerpt_read",
                        {
                            "artifact_id": artifact_id,
                            "locator_type": "paragraph",
                            "locator": "p1",
                        },
                    ),
                )
                self.assertEqual(read["text"], text)

    def test_skill_import_is_archived_as_inert_cross_round_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with KnowledgeStore(Path(directory) / "knowledge.sqlite3") as knowledge:
                first = ToolDispatcher(self.sandbox, self.research, "box", knowledge=knowledge)
                fetched = first.dispatch(
                    Role.WARRIOR,
                    Action("research.fetch", {"url": "https://example.test/paper"}),
                )
                digest = fetched["provenance"]["sha256"]
                imported = first.dispatch(
                    Role.WARRIOR,
                    Action(
                        "research.import",
                        {
                            "sha256": digest,
                            "manifest": {
                                "schema_version": 1,
                                "kind": "skill",
                                "source_url": "https://example.test/paper",
                                "content_sha256": digest,
                                "size_bytes": len(b"research"),
                                "metadata": {
                                    "name": "testing-helper",
                                    "version": "1.0.0",
                                    "permissions": ["workspace.read"],
                                    "dependencies": [],
                                },
                            },
                        },
                    ),
                )
                artifact_id = imported["candidate"]["artifact_id"]
                second = ToolDispatcher(self.sandbox, self.research, "box", knowledge=knowledge)
                recalled = second.dispatch(
                    Role.WARRIOR, Action("research.recall", {"sha256": digest})
                )
                self.assertEqual(recalled["artifacts"][0]["kind"], "skill")
                read = second.dispatch(
                    Role.WARRIOR,
                    Action(
                        "research.artifact_read",
                        {"artifact_id": artifact_id, "locator": "skill:SKILL.md"},
                    ),
                )
                self.assertEqual(base64.b64decode(read["content_base64"]), b"research")
                self.assertFalse(read["execution_granted"])

    def test_paper_collect_forwards_verified_pdf_extractor_and_fails_closed(self) -> None:
        extractor = Mock()
        dispatcher = ToolDispatcher(
            self.sandbox,
            self.research,
            "box",
            pdf_extractor=extractor,
        )
        with patch("aegis.agent_runtime.PaperCollector") as collector_type:
            collector_type.return_value.collect.side_effect = PaperCollectionError("invalid PDF")
            with self.assertRaisesRegex(ActionError, "invalid PDF"):
                dispatcher.dispatch(
                    Role.WARRIOR,
                    Action("paper.collect", {"identifier": "arxiv:2501.00001"}),
                )
        self.assertIs(collector_type.call_args.kwargs["pdf_extractor"], extractor)

    def test_paper_network_failure_is_a_recoverable_action_error(self) -> None:
        with patch("aegis.agent_runtime.PaperCollector") as collector_type:
            collector_type.return_value.collect.side_effect = OSError("approved addresses failed")
            with self.assertRaisesRegex(ActionError, "approved addresses failed"):
                self.dispatcher.dispatch(
                    Role.WARRIOR,
                    Action("paper.collect", {"identifier": "arxiv:2501.00001"}),
                )

    def test_cross_round_knowledge_requires_verified_fetch_and_respects_roles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with KnowledgeStore(Path(directory) / "knowledge.sqlite3") as knowledge:
                dispatcher = ToolDispatcher(
                    self.sandbox, self.research, "box", knowledge=knowledge
                )
                with self.assertRaisesRegex(ActionError, "fetched or collected and verified"):
                    dispatcher.dispatch(
                        Role.WARRIOR,
                        Action(
                            "knowledge.remember",
                            {
                                "sha256": "0" * 64,
                                "summary": "unverified",
                                "tags": ["testing"],
                                "applicable_roles": ["warrior"],
                            },
                        ),
                    )

                fetched = dispatcher.dispatch(
                    Role.WARRIOR,
                    Action("research.fetch", {"url": "https://example.test/paper"}),
                )
                digest = fetched["provenance"]["sha256"]
                stored = dispatcher.dispatch(
                    Role.WARRIOR,
                    Action(
                        "knowledge.remember",
                        {
                            "sha256": digest,
                            "summary": "Property testing exposes state-machine defects.",
                            "tags": ["testing"],
                            "applicable_roles": ["warrior"],
                            "experiment_result": "Caught the seeded defect.",
                        },
                    ),
                )
                self.assertEqual(stored["sha256"], digest)
                result = dispatcher.dispatch(
                    Role.WARRIOR,
                    Action("knowledge.search", {"query": "state-machine", "limit": 5}),
                )
                self.assertEqual(result["artifacts"][0]["sha256"], digest)
                judge_result = dispatcher.dispatch(
                    Role.JUDGE,
                    Action("knowledge.search", {"query": "state-machine", "limit": 5}),
                )
                self.assertEqual(judge_result["artifacts"], [])

    def test_only_prosecutor_may_share_verified_knowledge_across_roles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with KnowledgeStore(Path(directory) / "knowledge.sqlite3") as knowledge:
                warrior = ToolDispatcher(
                    self.sandbox, self.research, "box", knowledge=knowledge
                )
                fetched = warrior.dispatch(
                    Role.WARRIOR,
                    Action("research.fetch", {"url": "https://example.test/paper"}),
                )
                remember = {
                    "sha256": fetched["provenance"]["sha256"],
                    "summary": "Shared testing evidence.",
                    "tags": ["testing"],
                    "applicable_roles": ["judge"],
                }
                with self.assertRaisesRegex(ActionError, "only store knowledge for itself"):
                    warrior.dispatch(Role.WARRIOR, Action("knowledge.remember", remember))

                prosecutor = ToolDispatcher(
                    self.sandbox, self.research, "box", knowledge=knowledge
                )
                prosecutor.dispatch(
                    Role.PROSECUTOR,
                    Action("research.fetch", {"url": "https://example.test/paper"}),
                )
                prosecutor.dispatch(Role.PROSECUTOR, Action("knowledge.remember", remember))
                judge_result = prosecutor.dispatch(
                    Role.JUDGE, Action("knowledge.search", {"query": "testing", "limit": 5})
                )
                self.assertEqual(len(judge_result["artifacts"]), 1)

    def test_strategy_propose_validates_structured_workflow_and_role_boundary(self) -> None:
        result = self.dispatcher.dispatch(Role.WARRIOR, Action("strategy.propose", workflow()))
        self.assertEqual(result["content"]["stage_plan"][0], "Inspect")
        with self.assertRaisesRegex(ActionError, "only propose its own"):
            self.dispatcher.dispatch(
                Role.WARRIOR, Action("strategy.propose", workflow(target_role="judge"))
            )
        incomplete = workflow()
        del incomplete["workflow"]["verification_checklist"]
        with self.assertRaises(ActionError):
            self.dispatcher.dispatch(Role.WARRIOR, Action("strategy.propose", incomplete))
        self.assertFalse(WORKFLOW_ARTIFACT_SCHEMA["additionalProperties"])

    def test_only_judge_can_propose_bounded_declarative_challenges(self) -> None:
        metadata = SealedTaskMetadata(
            task_id="python-cache",
            version=1,
            language="python",
            content_hash="a" * 64,
            base_difficulty=2,
            base_cost_units=100,
            capability_tags=("python",),
        )
        dispatcher = ToolDispatcher(
            self.sandbox,
            self.research,
            "box",
            challenge_metadata=metadata,
            challenge_seed=7,
        )
        result = dispatcher.dispatch(
            Role.JUDGE,
            Action(
                "challenge.propose",
                {"failure_categories": ["boundary", "state-management"], "count": 2},
            ),
        )
        self.assertTrue(result["declarative_only"])
        self.assertEqual(len(result["challenges"]), 2)
        self.assertEqual(result["challenges"][0]["seed"], 7)
        with self.assertRaisesRegex(ActionError, "warrior is not allowed"):
            dispatcher.dispatch(
                Role.WARRIOR,
                Action("challenge.propose", {"failure_categories": [], "count": 1}),
            )
        with self.assertRaises(ActionError):
            dispatcher.dispatch(
                Role.JUDGE,
                Action("challenge.propose", {"failure_categories": ["shell-command"], "count": 1}),
            )


class RuntimeTests(unittest.TestCase):
    def test_historical_observations_keep_receipts_without_replaying_large_payloads(self) -> None:
        observations = [
            ToolObservation(
                1,
                "github.file_read",
                {
                    "artifact_id": "sha256:source",
                    "path": "src/example.py",
                    "sha256": "a" * 64,
                    "content_base64": "A" * 100_000,
                },
            ),
            ToolObservation(
                2,
                "paper.excerpt_read",
                {
                    "artifact_id": "sha256:paper",
                    "locator_type": "section",
                    "locator": "methods",
                    "sha256": "b" * 64,
                    "text": "current excerpt",
                },
            ),
        ]

        serialized = RoleAgentRuntime._request_observations(observations)

        self.assertEqual(serialized[0]["result"]["artifact_id"], "sha256:source")
        self.assertEqual(
            serialized[0]["result"]["content_base64"],
            {"omitted_from_history": True, "encoded_characters": 100_000},
        )
        self.assertEqual(serialized[1]["result"]["text"], "current excerpt")
        self.assertEqual(observations[0].result["content_base64"], "A" * 100_000)

    def test_tool_results_feed_next_call_until_submit_and_usage_is_returned(self) -> None:
        gateway = FakeGateway(
            [
                call("research.search", query="property testing", limit=1),
                call("submit", summary="done", payload={"score": 1}),
            ]
        )
        seen_usage = []
        runtime = RoleAgentRuntime(
            gateway,
            ToolDispatcher(MemorySandbox(), FakeResearch(), "box"),
            "model",
            usage_sink=seen_usage.append,
        )
        result = runtime.run(Role.JUDGE, objective="evaluate", context={"submission": "abc"})
        self.assertEqual(result.summary, "done")
        self.assertEqual(result.total_tokens, 16)
        self.assertTrue(result.usage_verified)
        self.assertEqual(len(seen_usage), 2)
        next_envelope = json.loads(gateway.requests[1].messages[1].content)
        self.assertEqual(next_envelope["observations"][0]["action"], "research.search")
        self.assertEqual(next_envelope["observations"][0]["result"]["hits"][0]["title"], "Paper")

    def test_dispatch_action_error_is_observed_and_model_can_recover(self) -> None:
        gateway = FakeGateway(
            [
                call("github.collect", repository_url="https://github.com/large/project", commit_sha="a" * 40),
                call("github.collect", repository_url="https://github.com/small/project", commit_sha="b" * 40),
                call("submit", summary="recovered", payload={"repository": "small/project"}),
            ]
        )
        dispatcher = ToolDispatcher(MemorySandbox(), FakeResearch(), "box")
        original_dispatch = dispatcher.dispatch
        collect_calls = 0

        def recoverable_dispatch(role, action):
            nonlocal collect_calls
            if action.name == "github.collect":
                collect_calls += 1
                if collect_calls == 1:
                    raise ActionError("tree response is empty or too large")
                return {"artifact": {"artifact_id": "sha256:small"}}
            return original_dispatch(role, action)

        with patch.object(dispatcher, "dispatch", side_effect=recoverable_dispatch):
            result = RoleAgentRuntime(gateway, dispatcher, "model").run(
                Role.WARRIOR,
                objective="find a bounded repository",
                context={},
            )

        self.assertEqual(result.summary, "recovered")
        self.assertEqual(len(result.observations), 3)
        failure = result.observations[0].result
        self.assertFalse(failure["accepted"])
        self.assertEqual(failure["error"]["type"], "ActionError")
        self.assertIn("too large", failure["error"]["message"])
        second_request = json.loads(gateway.requests[1].messages[1].content)
        self.assertEqual(second_request["observations"][0]["result"], failure)

    def test_research_provider_failure_is_observed_and_model_can_choose_another_action(self) -> None:
        class FailingResearch(FakeResearch):
            def fetch(self, url, *, validate_as_archive=False):
                raise OSError("all approved HTTPS addresses failed")

        gateway = FakeGateway(
            [
                call("research.fetch", url="https://unavailable.example/source"),
                call("research.search", query="alternative source", limit=1),
                call("submit", summary="recovered", payload={}),
            ]
        )
        result = RoleAgentRuntime(
            gateway,
            ToolDispatcher(MemorySandbox(), FailingResearch(), "box"),
            "model",
        ).run(Role.WARRIOR, objective="research", context={})

        self.assertEqual(result.summary, "recovered")
        self.assertEqual(result.observations[0].action, "research.fetch")
        self.assertFalse(result.observations[0].result["accepted"])
        self.assertIn("approved HTTPS", result.observations[0].result["error"]["message"])
        self.assertEqual(result.observations[1].action, "research.search")

    def test_malformed_model_action_is_rejected_then_can_be_corrected(self) -> None:
        gateway = FakeGateway(
            [
                {"unexpected": "shape"},
                call("submit", summary="corrected", payload={}),
            ]
        )
        runtime = RoleAgentRuntime(
            gateway,
            ToolDispatcher(MemorySandbox(), FakeResearch(), "box"),
            "model",
        )
        result = runtime.run(Role.WARRIOR, objective="work", context={})
        self.assertEqual(result.summary, "corrected")
        self.assertEqual(result.observations[0].action, "model.response")
        self.assertFalse(result.observations[0].result["accepted"])
        self.assertIn(
            "exactly action and arguments",
            result.observations[0].result["error"]["message"],
        )
        correction = json.loads(gateway.requests[1].messages[1].content)
        self.assertEqual(correction["observations"][0]["action"], "model.response")

    def test_non_json_model_text_is_not_interpreted_as_an_action(self) -> None:
        class RawGateway:
            def __init__(self):
                self.requests = []
                self.responses = [
                    "I will call a tool next.",
                    json.dumps(call("submit", summary="corrected", payload={})),
                ]

            def complete(self, request, *, cancel=None):
                self.requests.append(request)
                return GatewayResponse(
                    self.responses.pop(0),
                    TokenUsage(5, 3, verified=True),
                    "fake",
                )

        gateway = RawGateway()
        result = RoleAgentRuntime(
            gateway,
            ToolDispatcher(MemorySandbox(), FakeResearch(), "box"),
            "model",
        ).run(Role.WARRIOR, objective="work", context={})

        self.assertEqual(result.summary, "corrected")
        self.assertEqual(result.observations[0].action, "model.response")
        self.assertEqual(
            result.observations[0].result["error"]["message"],
            "model response is not valid JSON",
        )

    def test_gateway_truncation_is_an_actionable_rejection_and_usage_is_accounted(self) -> None:
        class TruncatingGateway:
            def __init__(self) -> None:
                self.requests = []
                self.responses = [
                    GatewayTruncationError(
                        "truncated before a complete JSON action",
                        usage=TokenUsage(5, 200, verified=True),
                    ),
                    GatewayResponse(
                        json.dumps(call("submit", summary="corrected", payload={})),
                        TokenUsage(5, 3, verified=True),
                        "fake",
                    ),
                ]

            def complete(self, request, *, cancel=None):
                self.requests.append(request)
                outcome = self.responses.pop(0)
                if isinstance(outcome, BaseException):
                    raise outcome
                return outcome

        gateway = TruncatingGateway()
        seen_usage = []
        result = RoleAgentRuntime(
            gateway,
            ToolDispatcher(MemorySandbox(), FakeResearch(), "box"),
            "model",
            usage_sink=seen_usage.append,
        ).run(Role.WARRIOR, objective="work", context={})

        self.assertEqual(result.summary, "corrected")
        self.assertEqual(result.observations[0].action, "model.response")
        self.assertEqual(
            result.observations[0].result["error"]["type"],
            "GatewayTruncationError",
        )
        self.assertIn("truncated", result.observations[0].result["error"]["message"])
        self.assertEqual([usage.output_tokens for usage in seen_usage], [200, 3])

    def test_judge_context_strips_warrior_reasoning_recursively(self) -> None:
        gateway = FakeGateway([call("submit", summary="review", payload={})])
        runtime = RoleAgentRuntime(gateway, ToolDispatcher(MemorySandbox(), FakeResearch(), "box"), "model")
        runtime.run(
            Role.JUDGE,
            objective="review",
            context={
                "submission": {"patch": "x", "warrior_reasoning": "secret"},
                "thoughts": "also secret",
            },
        )
        envelope = json.loads(gateway.requests[0].messages[1].content)
        self.assertEqual(envelope["context"], {"submission": {"patch": "x"}})
        self.assertNotIn("secret", gateway.requests[0].messages[1].content)

    def test_step_limit_fails_and_every_response_is_accounted(self) -> None:
        gateway = FakeGateway([call("research.search", query="x") for _ in range(2)])
        seen_usage = []
        runtime = RoleAgentRuntime(
            gateway,
            ToolDispatcher(MemorySandbox(), FakeResearch(), "box"),
            "model",
            limits=RuntimeLimits(max_steps=2),
            usage_sink=seen_usage.append,
        )
        with self.assertRaisesRegex(StepLimitExceeded, "did not submit"):
            runtime.run(Role.WARRIOR, objective="work", context={})
        self.assertEqual(len(seen_usage), 2)

    def test_research_budget_is_bounded_and_submission_can_recover(self) -> None:
        gateway = FakeGateway(
            [call("research.search", query="x") for _ in range(11)]
            + [call("submit", summary="done", payload={})]
        )
        runtime = RoleAgentRuntime(
            gateway,
            ToolDispatcher(MemorySandbox(), FakeResearch(), "box"),
            "model",
            limits=RuntimeLimits(max_steps=12),
            research_action_budget=10,
        )
        result = runtime.run(Role.WARRIOR, objective="work", context={})
        self.assertEqual(result.summary, "done")
        self.assertEqual(result.observations[10].result["accepted"], False)
        self.assertIn("no longer available", result.observations[10].result["error"]["message"])
        envelope = json.loads(gateway.requests[0].messages[1].content)
        self.assertEqual(envelope["research_action_budget"], 10)
        self.assertEqual(envelope["submission_deadline_step"], 9)
        exhausted = json.loads(gateway.requests[10].messages[1].content)
        self.assertNotIn("research.search", exhausted["allowed_actions"])
        self.assertEqual(exhausted["allowed_actions"], ["submit"])

    def test_deadline_forces_missing_required_action_then_submit(self) -> None:
        gateway = FakeGateway(
            [
                call("workspace.read", path="solution.py"),
                call("workspace.read", path="solution.py"),
                call("research.search", query="bounded", limit=1),
                call("submit", summary="done", payload={}),
            ]
        )
        runtime = RoleAgentRuntime(
            gateway,
            ToolDispatcher(MemorySandbox(), FakeResearch(), "box"),
            "model",
            limits=RuntimeLimits(max_steps=4),
        )
        result = runtime.run(
            Role.WARRIOR,
            objective="research then finish",
            context={},
            required_action_groups=(frozenset({"research.search"}),),
        )
        self.assertEqual(result.summary, "done")
        forced = json.loads(gateway.requests[2].messages[1].content)
        self.assertTrue(forced["forced_convergence"])
        self.assertEqual(forced["allowed_actions"], ["research.search"])
        self.assertEqual(
            gateway.requests[2].output_schema["properties"]["action"]["enum"],
            ["research.search"],
        )
        submit = json.loads(gateway.requests[3].messages[1].content)
        self.assertTrue(submit["forced_convergence"])
        self.assertEqual(submit["allowed_actions"], ["submit"])

    def test_eager_required_actions_focus_in_order_then_submit(self) -> None:
        class SequentialDispatcher:
            def allowed_actions(self, role):
                return frozenset(
                    {
                        "research.search",
                        "github.resolve",
                        "github.collect",
                        "github.file_read",
                        "workspace.read",
                        "submit",
                    }
                )

            def dispatch(self, role, action):
                if action.name == "submit":
                    return {
                        "summary": action.arguments["summary"],
                        "payload": action.arguments["payload"],
                    }
                if action.name == "sandbox.exec":
                    return {"accepted": True, "exit_code": 0, "timed_out": False}
                return {"accepted": True}

        gateway = FakeGateway(
            [
                call("research.search", query="bounded", limit=1),
                call("github.resolve", repository_url="https://github.com/example/project"),
                call("github.collect", repository_url="https://github.com/example/project", commit_sha="a" * 40),
                call("github.file_read", artifact_sha256="b" * 64, path="README.md"),
                call("submit", summary="done", payload={}),
            ]
        )
        result = RoleAgentRuntime(
            gateway,
            SequentialDispatcher(),
            "model",
            limits=RuntimeLimits(max_steps=10),
            eager_required_convergence=True,
        ).run(
            Role.WARRIOR,
            objective="collect bounded evidence",
            context={},
            required_action_groups=tuple(
                frozenset({action})
                for action in (
                    "research.search",
                    "github.resolve",
                    "github.collect",
                    "github.file_read",
                )
            ),
        )

        self.assertEqual(result.summary, "done")
        self.assertEqual(len(gateway.requests), 5)
        self.assertEqual(
            [json.loads(request.messages[1].content)["allowed_actions"] for request in gateway.requests],
            [
                ["research.search"],
                ["github.resolve"],
                ["github.collect"],
                ["github.file_read"],
                ["submit"],
            ],
        )

    def test_ordered_required_action_gate_releases_normal_actions_after_completion(self) -> None:
        class OrderedDispatcher:
            def allowed_actions(self, role):
                return frozenset({"workspace.read", "workspace.write", "sandbox.exec", "submit"})

            def dispatch(self, role, action):
                if action.name == "submit":
                    return {
                        "summary": action.arguments["summary"],
                        "payload": action.arguments["payload"],
                    }
                if action.name == "sandbox.exec":
                    return {"accepted": True, "exit_code": 0, "timed_out": False}
                return {"accepted": True}

        gateway = FakeGateway(
            [
                call("workspace.write", path="solution.py", content_base64=""),
                call("workspace.read", path="solution.py"),
                call("workspace.write", path="solution.py", content_base64=""),
                call("sandbox.exec", argv=["python", "-m", "pytest"]),
                call("workspace.read", path="solution.py"),
                call("submit", summary="done", payload={}),
            ]
        )
        result = RoleAgentRuntime(
            gateway,
            OrderedDispatcher(),
            "model",
            limits=RuntimeLimits(max_steps=8),
            ordered_required_action_gate=True,
        ).run(
            Role.WARRIOR,
            objective="inspect, write, and verify",
            context={},
            required_action_groups=tuple(
                frozenset({action})
                for action in ("workspace.read", "workspace.write", "sandbox.exec")
            ),
        )

        self.assertEqual(result.summary, "done")
        self.assertFalse(result.observations[0].result["accepted"])
        self.assertEqual(
            [json.loads(request.messages[1].content)["allowed_actions"] for request in gateway.requests],
            [
                ["workspace.read"],
                ["workspace.read"],
                ["workspace.write"],
                ["sandbox.exec"],
                ["sandbox.exec", "submit", "workspace.read", "workspace.write"],
                ["submit"],
            ],
        )

    def test_forced_action_recovers_only_from_trusted_tool_receipt(self) -> None:
        canonical = {
            "repository_url": "https://github.com/example/project",
            "commit_sha": "a" * 40,
        }

        class ReceiptDispatcher:
            def allowed_actions(self, role):
                return frozenset({"github.resolve", "github.collect", "submit"})

            def dispatch(self, role, action):
                if action.name == "github.resolve":
                    return {"next_action": {"action": "github.collect", "arguments": canonical}}
                if action.name == "github.collect":
                    self.collect_arguments = dict(action.arguments)
                    return {"files": []}
                return {"summary": action.arguments["summary"], "payload": action.arguments["payload"]}

        dispatcher = ReceiptDispatcher()
        gateway = FakeGateway(
            [
                call("github.resolve", repository_url="https://github.com/example/project"),
                {"malformed": True},
                call("submit", summary="done", payload={}),
            ]
        )
        result = RoleAgentRuntime(
            gateway,
            dispatcher,
            "model",
            limits=RuntimeLimits(max_steps=3),
        ).run(
            Role.WARRIOR,
            objective="collect exact commit",
            context={},
            required_action_groups=(
                frozenset({"github.resolve"}),
                frozenset({"github.collect"}),
            ),
        )
        self.assertEqual(result.summary, "done")
        self.assertEqual(dispatcher.collect_arguments, canonical)
        self.assertTrue(result.observations[1].result["argument_recovery"]["used"])

    def test_failed_collect_allows_bounded_reresolve_and_uses_new_receipt(self) -> None:
        old = {
            "repository_url": "https://github.com/example/old",
            "commit_sha": "a" * 40,
        }
        new = {
            "repository_url": "https://github.com/example/new",
            "commit_sha": "b" * 40,
        }

        class RecoveryDispatcher:
            def __init__(self) -> None:
                self.collect_arguments = []

            def allowed_actions(self, role):
                return frozenset(
                    {
                        "research.search",
                        "github.resolve",
                        "github.collect",
                        "workspace.read",
                        "submit",
                    }
                )

            def dispatch(self, role, action):
                if action.name == "github.resolve":
                    canonical = old if action.arguments["repository_url"].endswith("/old") else new
                    return {"next_action": {"action": "github.collect", "arguments": canonical}}
                if action.name == "github.collect":
                    arguments = dict(action.arguments)
                    self.collect_arguments.append(arguments)
                    if arguments == old:
                        raise ActionError("old repository cannot be collected")
                    return {"files": []}
                if action.name == "workspace.read":
                    return {"content": "ok"}
                return {"summary": action.arguments["summary"], "payload": action.arguments["payload"]}

        dispatcher = RecoveryDispatcher()
        gateway = FakeGateway(
            [
                call("github.resolve", repository_url="https://github.com/example/old"),
                call("github.collect", repository_url="https://github.com/wrong/repo", commit_sha="c" * 40),
                {"malformed": True},
                call("workspace.read", path="solution.py"),
                call("workspace.read", path="solution.py"),
                call("github.resolve", repository_url="https://github.com/example/new"),
                {"malformed": True},
                call("submit", summary="done", payload={}),
            ]
        )
        result = RoleAgentRuntime(
            gateway,
            dispatcher,
            "model",
            limits=RuntimeLimits(max_steps=8),
            eager_required_convergence=True,
        ).run(
            Role.WARRIOR,
            objective="recover from an unavailable repository",
            context={},
            required_action_groups=(
                frozenset({"github.resolve"}),
                frozenset({"github.collect"}),
            ),
        )

        self.assertEqual(result.summary, "done")
        self.assertEqual(dispatcher.collect_arguments, [old, new])
        self.assertEqual(result.observations[2].action, "model.response")
        recovery = json.loads(gateway.requests[5].messages[1].content)
        self.assertEqual(
            recovery["allowed_actions"],
            ["github.collect", "github.resolve", "research.search"],
        )
        narrowed = json.loads(gateway.requests[6].messages[1].content)
        self.assertEqual(narrowed["allowed_actions"], ["github.collect"])
        self.assertTrue(result.observations[6].result["argument_recovery"]["used"])

    def test_failed_file_read_recovery_is_limited_to_collect_and_read(self) -> None:
        observations = [
            ToolObservation(1, "github.file_read", {"accepted": False}),
        ]
        runtime = RoleAgentRuntime(
            FakeGateway([]),
            ToolDispatcher(MemorySandbox(), FakeResearch(), "box"),
            "model",
            limits=RuntimeLimits(max_steps=8),
            eager_required_convergence=True,
        )
        actions = runtime._convergence_actions(
            Role.WARRIOR,
            1,
            observations,
            1,
            (frozenset({"github.file_read"}),),
        )
        self.assertEqual(actions, frozenset({"github.collect", "github.file_read"}))

    def test_rejected_required_action_does_not_satisfy_gate(self) -> None:
        gateway = FakeGateway(
            [
                call("research.search", query="", limit=1),
                call("submit", summary="too early", payload={}),
                call("research.search", query="valid", limit=1),
                call("submit", summary="done", payload={}),
            ]
        )
        runtime = RoleAgentRuntime(
            gateway,
            ToolDispatcher(MemorySandbox(), FakeResearch(), "box"),
            "model",
        )
        result = runtime.run(
            Role.WARRIOR,
            objective="research",
            context={},
            required_action_groups=(frozenset({"research.search"}),),
        )
        self.assertEqual(result.summary, "done")
        self.assertFalse(result.observations[1].result["accepted"])

    def test_warrior_must_disposition_each_prior_feedback_item_before_submit(self) -> None:
        feedback = {
            "round": 1,
            "feedback_id": "round-1-evidence",
            "items": [
                {"feedback_id": "quality"},
                {"feedback_id": "judge"},
                {"feedback_id": "prosecutor"},
            ],
        }
        valid_payload = {
            "feedback_round": 1,
            "feedback_id": "round-1-evidence",
            "feedback_dispositions": [
                {"feedback_id": "quality", "decision": "adopt", "rationale": "Fix the measured gap."},
                {"feedback_id": "judge", "decision": "defer", "rationale": "Needs a focused reproduction."},
                {"feedback_id": "prosecutor", "decision": "reject", "rationale": "The evidence is stale."},
            ],
        }
        gateway = FakeGateway(
            [
                call("submit", summary="missing feedback", payload={}),
                call("submit", summary="accounted", payload=valid_payload),
            ]
        )
        result = RoleAgentRuntime(
            gateway,
            ToolDispatcher(MemorySandbox(), FakeResearch(), "box"),
            "model",
        ).run(Role.WARRIOR, objective="respond to feedback", context={"prior_round_feedback": feedback})

        self.assertEqual(result.summary, "accounted")
        self.assertFalse(result.observations[0].result["accepted"])
        self.assertEqual(result.submission["feedback_dispositions"], valid_payload["feedback_dispositions"])

    def test_non_warrior_does_not_need_feedback_dispositions(self) -> None:
        feedback = {
            "round": 1,
            "feedback_id": "round-1-evidence",
            "items": [{"feedback_id": "quality"}],
        }
        result = RoleAgentRuntime(
            FakeGateway([call("submit", summary="review complete", payload={})]),
            ToolDispatcher(MemorySandbox(), FakeResearch(), "box"),
            "model",
        ).run(Role.JUDGE, objective="review", context={"prior_round_feedback": feedback})

        self.assertEqual(result.summary, "review complete")
        self.assertEqual(len(result.observations), 1)

    def test_failed_or_timed_out_exec_does_not_satisfy_required_action_gate(self) -> None:
        runtime = RoleAgentRuntime(
            FakeGateway([]),
            ToolDispatcher(MemorySandbox(), FakeResearch(), "box"),
            "model",
            ordered_required_action_gate=True,
        )
        required = (frozenset({"sandbox.exec"}),)
        for result in (
            {"exit_code": 1, "timed_out": False},
            {"exit_code": 0, "timed_out": True},
        ):
            with self.subTest(result=result):
                observations = [ToolObservation(1, "sandbox.exec", result)]
                self.assertEqual(
                    runtime._convergence_actions(Role.WARRIOR, 0, observations, 2, required),
                    frozenset({"sandbox.exec"}),
                )

    def test_forced_submit_recovers_malformed_response_after_required_actions(self) -> None:
        gateway = FakeGateway(
            [
                call("research.search", query="bounded", limit=1),
                {"malformed": True},
            ]
        )
        result = RoleAgentRuntime(
            gateway,
            ToolDispatcher(MemorySandbox(), FakeResearch(), "box"),
            "model",
            limits=RuntimeLimits(max_steps=8),
            eager_required_convergence=True,
        ).run(
            Role.WARRIOR,
            objective="research then submit",
            context={},
            required_action_groups=(frozenset({"research.search"}),),
        )

        self.assertEqual(result.summary, "Required actions completed under forced convergence.")
        self.assertEqual(result.submission, {})
        self.assertEqual(
            result.observations[-1].result["argument_recovery"]["source"],
            "deterministic_forced_submit",
        )
        self.assertTrue(result.observations[-1].result["forced_convergence_submission"])
        self.assertEqual(len(gateway.requests), 2)

    def test_forced_submit_recovers_invalid_submit_arguments(self) -> None:
        gateway = FakeGateway(
            [
                call("research.search", query="bounded", limit=1),
                call("submit", summary="missing payload"),
            ]
        )
        result = RoleAgentRuntime(
            gateway,
            ToolDispatcher(MemorySandbox(), FakeResearch(), "box"),
            "model",
            limits=RuntimeLimits(max_steps=8),
            eager_required_convergence=True,
        ).run(
            Role.WARRIOR,
            objective="research then submit",
            context={},
            required_action_groups=(frozenset({"research.search"}),),
        )

        self.assertEqual(result.submission, {})
        self.assertEqual(result.observations[-1].action, "submit")
        self.assertTrue(result.observations[-1].result["argument_recovery"]["used"])
        self.assertEqual(len(gateway.requests), 2)

    def test_eager_forced_submit_recovers_unavailable_action(self) -> None:
        gateway = FakeGateway(
            [
                call("research.search", query="bounded", limit=1),
                call("workspace.read", path="solution.py"),
            ]
        )
        result = RoleAgentRuntime(
            gateway,
            ToolDispatcher(MemorySandbox(), FakeResearch(), "box"),
            "model",
            limits=RuntimeLimits(max_steps=8),
            eager_required_convergence=True,
        ).run(
            Role.WARRIOR,
            objective="research then submit",
            context={},
            required_action_groups=(frozenset({"research.search"}),),
        )

        self.assertEqual(result.observations[-1].action, "submit")
        self.assertTrue(result.observations[-1].result["forced_convergence_submission"])
        self.assertEqual(len(gateway.requests), 2)

    def test_eager_required_research_cap_never_forces_submit(self) -> None:
        class ResearchOnlyDispatcher:
            def allowed_actions(self, role):
                return frozenset({"research.search", "submit"})

            def dispatch(self, role, action):
                raise AssertionError("dispatch is not used by this state-machine test")

        runtime = RoleAgentRuntime(
            FakeGateway([]),
            ResearchOnlyDispatcher(),
            "model",
            eager_required_convergence=True,
            research_action_budget=10,
        )
        observations = [
            ToolObservation(step, "research.search", {"accepted": False})
            for step in range(1, 11)
        ]
        required = (frozenset({"research.search"}),)
        available = runtime._convergence_actions(
            Role.WARRIOR, 10, observations, 11, required
        )

        self.assertNotIn("research.search", available)
        self.assertEqual(available, frozenset({"submit"}))
        self.assertIsNone(runtime._forced_submit_action(available, required, observations, 11))

    def test_eager_mode_does_not_auto_submit_without_required_groups(self) -> None:
        gateway = FakeGateway([{"malformed": True}])
        runtime = RoleAgentRuntime(
            gateway,
            ToolDispatcher(MemorySandbox(), FakeResearch(), "box"),
            "model",
            limits=RuntimeLimits(max_steps=1),
            eager_required_convergence=True,
        )
        with self.assertRaises(StepLimitExceeded):
            runtime.run(Role.PROSECUTOR, objective="audit", context={})
        self.assertEqual(len(gateway.requests), 1)

    def test_eager_alternative_required_action_satisfies_group(self) -> None:
        gateway = FakeGateway(
            [
                call("research.search", query="bounded", limit=1),
                call("submit", summary="done", payload={}),
            ]
        )
        result = RoleAgentRuntime(
            gateway,
            ToolDispatcher(MemorySandbox(), FakeResearch(), "box"),
            "model",
            limits=RuntimeLimits(max_steps=5),
            eager_required_convergence=True,
        ).run(
            Role.WARRIOR,
            objective="use either research source",
            context={},
            required_action_groups=(
                frozenset({"knowledge.search", "research.recall", "research.search"}),
            ),
        )

        self.assertEqual(result.summary, "done")
        second = json.loads(gateway.requests[1].messages[1].content)
        self.assertEqual(second["allowed_actions"], ["submit"])

    def test_submit_is_not_recovered_before_required_actions_complete(self) -> None:
        gateway = FakeGateway([{"malformed": True}])
        runtime = RoleAgentRuntime(
            gateway,
            ToolDispatcher(MemorySandbox(), FakeResearch(), "box"),
            "model",
            limits=RuntimeLimits(max_steps=1),
        )
        with self.assertRaises(StepLimitExceeded):
            runtime.run(
                Role.WARRIOR,
                objective="must research first",
                context={},
                required_action_groups=(frozenset({"research.search"}),),
            )
        self.assertEqual(gateway.requests[0].output_schema["properties"]["action"]["enum"], ["research.search"])

    def test_request_budget_gate_runs_before_transport_and_can_deny(self) -> None:
        gateway = FakeGateway([call("submit", summary="unreachable", payload={})])
        calls = []

        def deny(role, step, request):
            calls.append((role, step, request))
            raise RuntimeError("budget denied")

        runtime = RoleAgentRuntime(
            gateway,
            ToolDispatcher(MemorySandbox(), FakeResearch(), "box"),
            "model",
            before_request=deny,
        )
        with self.assertRaisesRegex(RuntimeError, "budget denied"):
            runtime.run(Role.WARRIOR, objective="work", context={})
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][:2], (Role.WARRIOR, 1))
        self.assertEqual(gateway.requests, [])

    def test_prosecutor_request_advertises_only_read_actions(self) -> None:
        gateway = FakeGateway([call("submit", summary="audit", payload={})])
        runtime = RoleAgentRuntime(gateway, ToolDispatcher(MemorySandbox(), FakeResearch(), "box"), "model")
        runtime.run(Role.PROSECUTOR, objective="audit", context={})
        envelope = json.loads(gateway.requests[0].messages[1].content)
        self.assertNotIn("workspace.write", envelope["allowed_actions"])
        self.assertNotIn("sandbox.exec", envelope["allowed_actions"])
        self.assertIn("workspace.read", envelope["allowed_actions"])

    def test_disabled_evolution_action_is_not_advertised_or_dispatchable(self) -> None:
        dispatcher = ToolDispatcher(
            MemorySandbox(),
            FakeResearch(),
            "box",
            disabled_actions=frozenset({"evolution.request"}),
        )
        gateway = FakeGateway([call("submit", summary="done", payload={})])
        RoleAgentRuntime(gateway, dispatcher, "model").run(
            Role.WARRIOR, objective="research only", context={}
        )
        envelope = json.loads(gateway.requests[0].messages[1].content)
        self.assertNotIn("evolution.request", envelope["allowed_actions"])
        self.assertNotIn("If a code change", gateway.requests[0].messages[0].content)
        with self.assertRaisesRegex(ActionError, "not allowed"):
            dispatcher.dispatch(
                Role.WARRIOR,
                Action("evolution.request", {"objective": "x", "rationale": "y"}),
            )

    def test_required_action_gate_rejects_early_submit_then_allows_completion(self) -> None:
        gateway = FakeGateway(
            [
                call("submit", summary="too early", payload={}),
                call("research.search", query="bounded retry", limit=1),
                call("submit", summary="done", payload={}),
            ]
        )
        runtime = RoleAgentRuntime(
            gateway,
            ToolDispatcher(MemorySandbox(), FakeResearch(), "box"),
            "model",
        )
        result = runtime.run(
            Role.WARRIOR,
            objective="research",
            context={},
            required_action_groups=(frozenset({"research.search"}),),
        )
        self.assertEqual(result.summary, "done")
        self.assertFalse(result.observations[0].result["accepted"])
        second_envelope = json.loads(gateway.requests[1].messages[1].content)
        self.assertEqual(
            second_envelope["required_action_groups_before_submit"],
            [["research.search"]],
        )

    def test_explicit_strategy_proposal_is_attached_for_legacy_registry_ingestion(self) -> None:
        gateway = FakeGateway(
            [
                call("strategy.propose", **workflow()),
                call("submit", summary="done", payload={"score": 1}),
            ]
        )
        runtime = RoleAgentRuntime(
            gateway, ToolDispatcher(MemorySandbox(), FakeResearch(), "box"), "model"
        )
        result = runtime.run(Role.WARRIOR, objective="improve", context={})
        proposals = result.submission["strategy_proposals"]
        self.assertEqual(proposals[0]["content"]["stage_plan"][0], "Inspect")
        first = json.loads(gateway.requests[0].messages[1].content)
        self.assertIn("strategy.propose", first["allowed_actions"])
        self.assertEqual(
            first["strategy_propose_arguments_schema"]["required"],
            ["proposal_id", "target_role", "workflow", "rationale"],
        )
        self.assertIn("strategy.propose", gateway.requests[0].messages[0].content)

    def test_duplicate_strategy_proposal_is_rejected_without_killing_the_run(self) -> None:
        gateway = FakeGateway(
            [
                call("strategy.propose", **workflow()),
                call("strategy.propose", **workflow()),
                call("submit", summary="done", payload={"score": 1}),
            ]
        )
        runtime = RoleAgentRuntime(
            gateway, ToolDispatcher(MemorySandbox(), FakeResearch(), "box"), "model"
        )
        result = runtime.run(Role.WARRIOR, objective="improve", context={})
        self.assertEqual(result.summary, "done")
        proposals = result.submission["strategy_proposals"]
        self.assertEqual(len(proposals), 1)
        rejected = [
            observation
            for observation in result.observations
            if observation.action == "strategy.propose" and observation.result.get("accepted") is False
        ]
        self.assertEqual(len(rejected), 1)
        self.assertIn("duplicate proposal_id", rejected[0].result["error"]["message"])

    def test_submit_rejects_hidden_strategy_proposals(self) -> None:
        gateway = FakeGateway(
            [
                call("submit", summary="bad", payload={"strategy_proposals": ["hidden"]}),
                call("submit", summary="corrected", payload={}),
            ]
        )
        runtime = RoleAgentRuntime(
            gateway, ToolDispatcher(MemorySandbox(), FakeResearch(), "box"), "model"
        )
        result = runtime.run(Role.WARRIOR, objective="improve", context={})
        self.assertEqual(result.summary, "corrected")
        self.assertNotIn("strategy_proposals", result.submission)
        self.assertFalse(result.observations[0].result["accepted"])
        self.assertIn("explicit strategy.propose", result.observations[0].result["error"]["message"])

    def test_warrior_can_explicitly_schedule_one_isolated_evolution_candidate(self) -> None:
        gateway = FakeGateway(
            [
                call(
                    "evolution.request",
                    objective="Improve evidence-based tool selection in the evolvable workflow.",
                    rationale="Repeated searches consumed tokens without improving quality.",
                ),
                {"malformed": True},
            ]
        )
        runtime = RoleAgentRuntime(
            gateway,
            ToolDispatcher(MemorySandbox(), FakeResearch(), "box"),
            "model",
            limits=RuntimeLimits(max_steps=8),
            eager_required_convergence=True,
        )
        result = runtime.run(
            Role.WARRIOR,
            objective="improve",
            context={},
            required_action_groups=(frozenset({"evolution.request"}),),
        )
        request = result.submission["evolution_requests"][0]
        self.assertTrue(request["candidate_only"])
        self.assertFalse(request["host_write_allowed"])
        self.assertTrue(result.observations[-1].result["forced_convergence_submission"])
        self.assertEqual(len(gateway.requests), 2)
        with self.assertRaisesRegex(ActionError, "judge is not allowed"):
            ToolDispatcher(MemorySandbox(), FakeResearch(), "box").dispatch(
                Role.JUDGE,
                Action(
                    "evolution.request",
                    {"objective": "change", "rationale": "not judge authority"},
                ),
            )

    def test_system_prompt_is_byte_stable_across_steps_and_seed_is_fixed(self) -> None:
        """Prompt-cache preservation: the system message must not drift between
        steps and the request seed must be deterministic, so the provider can
        reuse the leading input block across requests of one run."""
        runtime = RoleAgentRuntime(
            FakeGateway([call("submit", summary="done", payload={})]),
            ToolDispatcher(MemorySandbox(), FakeResearch(), "box"),
            "model",
            limits=RuntimeLimits(max_steps=4),
        )
        requests = [
            runtime._request(Role.WARRIOR, "objective-x", {"k": "v"}, [], step=step)
            for step in (1, 2, 3)
        ]
        systems = {request.messages[0].content for request in requests}
        self.assertEqual(len(systems), 1)
        self.assertTrue(all(request.seed == 0 for request in requests))
        for request in requests:
            envelope = json.loads(request.messages[1].content)
            self.assertIn("allowed_actions", envelope)
            self.assertNotIn("allowed_actions", request.messages[0].content)


if __name__ == "__main__":
    unittest.main()
