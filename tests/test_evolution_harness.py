from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from aegis.agent_runtime import ACTION_SCHEMA, Action, RuntimeLimits, ToolDispatcher
from aegis.artifacts import ContentAddressedArtifactStore
from aegis.config import RoleConfig
from aegis.curriculum import CurriculumRegistry, CycleState
from aegis.cycle_ports import run_v2_cycle
from aegis.dynamic_tasks import (
    DynamicTaskRegistry,
    GenesisSeeder,
    TaskForge,
)
from aegis.dynamic_tasks.forge import canonical_taskpack_archive
from aegis.event_store import EventStore
from aegis.evolution.consumer import consume_rollback_orders
from aegis.evolution.harness import (
    CanaryVerdict,
    HarnessCanaryRunner,
    HarnessEvolutionError,
    HarnessRepo,
    HarnessRollbackExecutor,
    RollbackOrder,
    changes_to_git_file_changes,
)
from aegis.evolution.population import (
    PopulationArchive,
    behavior_descriptor,
    behavior_roots,
    harness_changed_roots,
)
from aegis.evolution.registry import EvolutionRegistry
from aegis.evolution.surfaces import (
    META_ALLOWED_ROOTS,
    META_FORBIDDEN_FILES,
    EvolutionSurface,
    EvolutionSurfaceError,
    validate_harness_code_content,
    validate_harness_path,
)
from aegis.gateway.types import GatewayResponse, TokenUsage
from aegis.models import Role
from aegis.research.types import Provenance, ResearchArtifact, SearchHit
from aegis.roles import RoleRegistry
from aegis.sandbox.fake import FakeSandboxBackend
from aegis.sandbox.types import CommandResult, CommandSpec
from aegis.taskpacks.builtin import load_builtin_python_taskpacks
from aegis.taskpacks.manifest import TaskPack
from aegis.taskpacks.validation import ExecutionResult


def _git(repo: Path, *argv: str) -> str:
    result = subprocess.run(
        ("git", *argv),
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {argv}: {result.stdout} {result.stderr}")
    return result.stdout


def _checkpoint_ref(label: str) -> str:
    return (
        "refs/heads/candidate/warrior/gen-"
        + hashlib.sha256(label.encode("utf-8")).hexdigest()[:40]
    )


def _init_harness_repo(root: Path) -> Path:
    repo = root / "harness"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "config", "user.email", "test@aegis.invalid")
    source = repo / "src" / "aegis"
    source.mkdir(parents=True)
    (source / "__init__.py").write_text('MARKER = "baseline"\n', encoding="utf-8")
    (source / "plugins").mkdir()
    (source / "plugins" / "__init__.py").write_text(
        'MARKER = "baseline"\n', encoding="utf-8"
    )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "baseline harness")
    return repo


def _init_phase4_repo(root: Path) -> Path:
    repo = _init_harness_repo(root)
    source = repo / "src" / "aegis"
    (source / "research").mkdir()
    (source / "research" / "__init__.py").write_text(
        'RESEARCH_MARKER = "baseline"\n', encoding="utf-8"
    )
    (source / "evolution").mkdir()
    (source / "evolution" / "registry.py").write_text(
        "# evolution registry control file\n", encoding="utf-8"
    )
    (repo / "src" / "aegis" / "cycle_recovery.py").write_text(
        "# cycle recovery control file\n", encoding="utf-8"
    )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "phase4 harness baseline")
    return repo


def _commit_on(
    repo: Path, base: str, path: str, content: bytes, ref: str
) -> str:
    _git(repo, "checkout", "-q", "--detach", base)
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    _git(repo, "add", "--", path)
    _git(repo, "commit", "-q", "-m", f"checkpoint {ref}")
    commit = _git(repo, "rev-parse", "HEAD").strip()
    branch = ref.removeprefix("refs/heads/")
    _git(repo, "branch", "-f", branch, commit)
    _git(repo, "checkout", "-q", "--force", "--detach", base)
    return commit


def _change(path: str, content: bytes) -> dict[str, object]:
    return {
        "path": path,
        "delete": False,
        "content_base64": base64.b64encode(content).decode("ascii"),
        "executable": False,
    }


class AnchorRunner:
    def run(self, pack: object, implementation_dir: str, suite: str) -> ExecutionResult:
        passed = implementation_dir == getattr(pack, "manifest").reference_dir
        return ExecutionResult(
            passed=passed,
            tests_run=1,
            exit_code=0 if passed else 1,
            timed_out=False,
            output_digest="cycle-anchor",
        )


class FakeGateway:
    def __init__(self, actions: list[dict[str, object]]) -> None:
        self.actions = list(actions)

    def complete(self, request: object, *, cancel: object = None) -> object:
        action = self.actions.pop(0)
        return GatewayResponse(
            json.dumps(action), TokenUsage(5, 3, verified=True), "fake"
        )


class WritingFakeSandboxBackend(FakeSandboxBackend):
    def exec(self, sandbox_id: str, command: CommandSpec) -> CommandResult:
        argv = command.argv
        if len(argv) == 5 and argv[:2] == ("python3", "-c") and "base64" in argv[2]:
            self._require_runnable(sandbox_id)
            payload = base64.b64decode(argv[4], validate=True)
            self.commands.append((sandbox_id, command))
            self._files.setdefault(sandbox_id, {})[argv[3]] = payload
            return CommandResult(0, str(len(payload)), "", 0.0)
        return super().exec(sandbox_id, command)


class FakeResearch:
    def search(self, query: str, *, limit: int = 10):
        return [SearchHit("https://example.test/paper", "Paper", "abstract")]

    def fetch(self, url: str, *, validate_as_archive: bool = False):
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


def submit(summary: str, payload: dict[str, object]) -> dict[str, object]:
    return {"action": "submit", "arguments": {"summary": summary, "payload": payload}}


def forge_archive(root: Path, *, task_id: str = "dynamic-next") -> bytes:
    source = sorted(
        load_builtin_python_taskpacks(), key=lambda item: item.manifest.task_id
    )[0]
    copied = root / "forge-pack"
    shutil.copytree(source.root, copied)
    manifest_path = copied / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["task_id"] = task_id
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return canonical_taskpack_archive(TaskPack.load(copied))


def task_spec_from_pack(task_id: str = "dynamic-next") -> dict[str, object]:
    """Translate the first built-in pack into a declarative Judge task spec."""
    source = sorted(
        load_builtin_python_taskpacks(), key=lambda item: item.manifest.task_id
    )[0]
    return {
        "task_id": task_id,
        "prompt": (source.root / "prompt.md").read_text(encoding="utf-8"),
        "public_cases": json.loads(
            (source.root / "public" / "cases.json").read_text(encoding="utf-8")
        ),
        "public_test": (source.root / "public" / "test_solution.py").read_text(
            encoding="utf-8"
        ),
        "hidden_cases": json.loads(
            (source.root / "hidden" / "cases.json").read_text(encoding="utf-8")
        ),
        "reference_solution": (source.root / "reference" / "solution.py").read_text(
            encoding="utf-8"
        ),
        "defect_solution": (source.root / "defect" / "solution.py").read_text(
            encoding="utf-8"
        ),
        "mutants": [
            {"name": path.parent.name, "solution": path.read_text(encoding="utf-8")}
            for path in sorted((source.root / "mutants").glob("*/solution.py"))
        ],
    }


def role_configs() -> dict[str, RoleConfig]:
    return {
        "warrior": RoleConfig("w", 0.60, 1024),
        "judge": RoleConfig("j", 0.25, 1024),
        "prosecutor": RoleConfig("p", 0.15, 1024),
    }


def plain_actions(archive: bytes | None = None) -> list[dict[str, object]]:
    actions = [
        submit(
            "solved",
            {
                "task_ids": ["dynamic-task-sha256:" + "1" * 64],
                "results": [{"passed": True}],
            },
        ),
        submit("reviewed", {"findings": ["bounded review"], "quality_score": 0.8}),
        submit(
            "audited",
            {
                "usage_verified": True,
                "safety_passed": True,
                "integrity_passed": True,
                "curriculum": [{"capability": "debugging", "hypothesis": "next probe"}],
            },
        ),
        submit("reflect-warrior", {"claims": ["keep workspace autonomy"]}),
        submit("reflect-judge", {"claims": ["forge harder tasks"]}),
        submit("reflect-prosecutor", {"claims": ["watch token drift"]}),
        submit("council", {"proposal": None, "agenda": ["x"]}),
    ]
    actions.append(submit("forged", {"task_specs": [task_spec_from_pack()]}))
    return actions


def warrior_proposal_action(
    base_commit: str,
    checkpoint_ref: str,
    content: bytes,
    *,
    path: str = "src/aegis/plugins/__init__.py",
) -> dict[str, object]:
    return {
        "action": "aegis.propose_harness_change",
        "arguments": {
            "objective": "add a marker constant",
            "rationale": "prove the Warrior can evolve real harness code",
            "base_commit": base_commit,
            "checkpoint_ref": checkpoint_ref,
            "changes": [_change(path, content)],
            "expected_fix": ["constant present"],
            "regression_risk": ["plugins import stays intact"],
        },
    }


class HarnessSurfaceTests(unittest.TestCase):
    def test_valid_harness_proposal_normalizes(self) -> None:
        content = {
            "base_commit": "a" * 40,
            "checkpoint_ref": _checkpoint_ref("one"),
            "changes": [_change("src/aegis/plugins/demo.py", b"VALUE = 1\n")],
            "objective": "add tool",
            "rationale": "make it faster",
            "failure_mode_targeted": None,
            "expected_fix": ["tool works"],
            "regression_risk": ["import stays"],
            "evidence_ref": None,
        }
        validated = validate_harness_code_content(content)
        self.assertEqual(validated["changes"][0]["path"], "src/aegis/plugins/demo.py")
        self.assertIsNone(validated["evidence_ref"])

    def test_forbidden_harness_paths_are_rejected(self) -> None:
        for path in (
            "tests/test_evolution_harness.py",
            "src/aegis/sandbox/agent.py",
            "src/aegis/publishing/publisher.py",
            "src/aegis/connectors/git_checkpoint.py",
            "src/aegis/config.py",
            "src/aegis/evolution/registry.py",
            "src/aegis/evolution/consumer.py",
            "src/aegis/taskpacks/manifest.py",
            "src/aegis/evaluation/sealed.py",
            "docs/architecture.md",
            ".env",
            "warrior/prompt.md",
        ):
            with self.subTest(path=path):
                with self.assertRaises(EvolutionSurfaceError):
                    validate_harness_path(path)

    def test_allowed_harness_paths_are_accepted(self) -> None:
        for path in (
            "src/aegis/agent_runtime.py",
            "src/aegis/plugins/demo.py",
            "src/aegis/gateway/transport.py",
            "src/aegis/roles/prompts.py",
            "src/aegis/research/github_collector.py",
            "src/aegis/evolution/surfaces.py",
        ):
            with self.subTest(path=path):
                self.assertEqual(validate_harness_path(path), path)

    def test_bad_manifest_fields_are_rejected(self) -> None:
        base = {
            "base_commit": "a" * 40,
            "checkpoint_ref": _checkpoint_ref("one"),
            "changes": [_change("src/aegis/plugins/demo.py", b"VALUE = 1\n")],
            "objective": "add tool",
            "rationale": "make it faster",
            "failure_mode_targeted": None,
            "expected_fix": ["tool works"],
            "regression_risk": ["import stays"],
            "evidence_ref": None,
        }
        for field, value in (
            ("base_commit", "short"),
            ("checkpoint_ref", "refs/heads/main"),
            ("checkpoint_ref", "refs/heads/candidate/judge/gen-abcdef"),
            ("changes", []),
            ("expected_fix", []),
            ("regression_risk", []),
        ):
            with self.subTest(field=field, value=value):
                with self.assertRaises(EvolutionSurfaceError):
                    validate_harness_code_content({**base, field: value})


class HarnessRepoTests(unittest.TestCase):
    def test_verify_activate_rollback_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = _init_harness_repo(root)
            base = _git(repo, "rev-parse", "HEAD").strip()
            patch = b'MARKER = "patched"\n'
            ref = _checkpoint_ref("round-trip")
            checkpoint = _commit_on(
                repo, base, "src/aegis/plugins/__init__.py", patch, ref
            )
            harness = HarnessRepo(repo)
            changes = changes_to_git_file_changes(
                [_change("src/aegis/plugins/__init__.py", patch)]
            )
            self.assertEqual(
                harness.verify_checkpoint(
                    base_commit=base, checkpoint_ref=ref, changes=changes
                ),
                checkpoint,
            )
            activation_commit = harness.activate(
                changes, message="evolution: round-trip"
            )
            self.assertNotEqual(activation_commit, base)
            self.assertEqual(
                (repo / "src/aegis/plugins/__init__.py").read_text(encoding="utf-8"),
                "MARKER = \"patched\"\n",
            )
            restored = harness.rollback(base)
            self.assertEqual(restored, base)
            self.assertEqual(
                (repo / "src/aegis/plugins/__init__.py").read_text(encoding="utf-8"),
                'MARKER = "baseline"\n',
            )

    def test_checkpoint_tree_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = _init_harness_repo(root)
            base = _git(repo, "rev-parse", "HEAD").strip()
            ref = _checkpoint_ref("mismatch")
            _commit_on(repo, base, "src/aegis/plugins/__init__.py", b"OTHER\n", ref)
            harness = HarnessRepo(repo)
            changes = changes_to_git_file_changes(
                [_change("src/aegis/plugins/__init__.py", b"DIFFERENT\n")]
            )
            with self.assertRaises(HarnessEvolutionError):
                harness.verify_checkpoint(
                    base_commit=base, checkpoint_ref=ref, changes=changes
                )

    def test_rollback_rejects_non_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = _init_harness_repo(root)
            harness = HarnessRepo(repo)
            unrelated = _commit_on(
                repo,
                _git(repo, "rev-parse", "HEAD").strip(),
                "src/aegis/plugins/__init__.py",
                b"FUTURE\n",
                _checkpoint_ref("unrelated"),
            )
            _git(repo, "checkout", "-q", "-b", "main2", "main")
            with self.assertRaises(HarnessEvolutionError):
                harness.rollback(unrelated)


class HarnessCanaryTests(unittest.TestCase):
    def test_good_patch_passes_zero_regression(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = _init_harness_repo(Path(directory))
            base = _git(repo, "rev-parse", "HEAD").strip()
            patch = b'MARKER = "patched"\n'
            ref = _checkpoint_ref("good")
            _commit_on(repo, base, "src/aegis/plugins/__init__.py", patch, ref)
            harness = HarnessRepo(repo)
            runner = HarnessCanaryRunner(
                harness,
                canary_argv=(
                    "{python}",
                    "-c",
                    "import aegis.plugins; "
                    "assert aegis.plugins.MARKER in ('baseline', 'patched')",
                ),
            )
            content = {
                "base_commit": base,
                "checkpoint_ref": ref,
                "changes": [_change("src/aegis/plugins/__init__.py", patch)],
                "objective": "x",
                "rationale": "y",
                "failure_mode_targeted": None,
                "expected_fix": ["a"],
                "regression_risk": ["b"],
                "evidence_ref": None,
            }
            verdict = runner.run(content, changes_to_git_file_changes(content["changes"]))
            self.assertIsInstance(verdict, CanaryVerdict)
            self.assertTrue(verdict.passed, verdict.reason)
            self.assertTrue(verdict.evidence_id.startswith("harness-canary-sha256:"))

    def test_broken_patch_fails_smoke(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = _init_harness_repo(Path(directory))
            base = _git(repo, "rev-parse", "HEAD").strip()
            patch = b"def broken(:\n"
            ref = _checkpoint_ref("broken")
            _commit_on(repo, base, "src/aegis/plugins/__init__.py", patch, ref)
            runner = HarnessCanaryRunner(
                HarnessRepo(repo),
                canary_argv=("{python}", "-c", "import aegis.plugins"),
            )
            content = {
                "base_commit": base,
                "checkpoint_ref": ref,
                "changes": [_change("src/aegis/plugins/__init__.py", patch)],
                "objective": "x",
                "rationale": "y",
                "failure_mode_targeted": None,
                "expected_fix": ["a"],
                "regression_risk": ["b"],
                "evidence_ref": None,
            }
            verdict = runner.run(content, changes_to_git_file_changes(content["changes"]))
            self.assertFalse(verdict.passed)
            self.assertIn("compile", verdict.reason.lower())


class RollbackOrderTests(unittest.TestCase):
    def test_consume_rollback_orders_from_submission(self) -> None:
        order = RollbackOrder.create(
            candidate_id="evolution-candidate-sha256:" + "a" * 64,
            reason="bricked the harness",
            analysis="import error in the patch",
        )
        submission = {
            "role": "prosecutor",
            "submission": {"summary": "audit", "rollback_orders": [order.to_mapping()]},
        }
        orders = consume_rollback_orders(submission)
        self.assertEqual(len(orders), 1)
        self.assertEqual(orders[0].candidate_id, order.candidate_id)

    def test_rollback_executor_resets_live_repo(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = _init_harness_repo(Path(directory))
            base = _git(repo, "rev-parse", "HEAD").strip()
            patch = b'MARKER = "patched"\n'
            harness = HarnessRepo(repo)
            changes = changes_to_git_file_changes(
                [_change("src/aegis/plugins/__init__.py", patch)]
            )
            harness.activate(changes, message="activation")
            order = RollbackOrder.create(
                candidate_id="evolution-candidate-sha256:" + "b" * 64,
                reason="failed",
                analysis="crash",
            )
            outcome = HarnessRollbackExecutor(harness).execute(order, base_commit=base)
            self.assertEqual(
                (repo / "src/aegis/plugins/__init__.py").read_text(encoding="utf-8"),
                'MARKER = "baseline"\n',
            )
            self.assertTrue(outcome["evidence_id"].startswith("harness-rollback-sha256:"))


class RuntimeActionTests(unittest.TestCase):
    def test_runtime_action_permissions(self) -> None:
        dispatcher = ToolDispatcher(
            FakeSandboxBackend(), FakeResearch(), "rt-1"
        )
        warrior = dispatcher.allowed_actions(Role.WARRIOR)
        prosecutor = dispatcher.allowed_actions(Role.PROSECUTOR)
        judge = dispatcher.allowed_actions(Role.JUDGE)
        self.assertIn("aegis.propose_harness_change", warrior)
        self.assertNotIn("aegis.propose_harness_change", prosecutor)
        self.assertNotIn("aegis.propose_harness_change", judge)
        self.assertIn("aegis.order_rollback", prosecutor)
        self.assertNotIn("aegis.order_rollback", warrior)
        self.assertNotIn("aegis.order_rollback", judge)
        enum = ACTION_SCHEMA["properties"]["action"]["enum"]
        self.assertIn("aegis.propose_harness_change", enum)
        self.assertIn("aegis.order_rollback", enum)

    def test_deploy_dependency_produces_environment_proposal(self) -> None:
        dispatcher = ToolDispatcher(FakeSandboxBackend(), FakeResearch(), "dep-1")
        parent = "registry.example/base@sha256:" + "a" * 64
        result = dispatcher.dispatch(
            Role.WARRIOR,
            Action.parse(
                json.dumps(
                    {
                        "action": "aegis.deploy_dependency",
                        "arguments": {
                            "parent_image": parent,
                            "dependency": {
                                "name": "requests",
                                "version": "2.31.0",
                                "kind": "python_wheel",
                                "source_url": "https://files.pythonhosted.org/packages/x/requests.whl",
                                "sha256": "c" * 64,
                            },
                            "objective": "install requests",
                            "rationale": "needed for network tooling",
                        },
                    }
                )
            ),
        )
        self.assertEqual(result["proposal"]["surface"], "environment")
        content = result["proposal"]["content"]
        self.assertEqual(content["parent_image"], parent)
        self.assertEqual(content["dependencies"][0]["name"], "requests")
        self.assertEqual(content["network_policy"], "brokered_public")


class HarnessEvolutionCycleTests(unittest.TestCase):
    def test_harness_candidate_waits_for_fresh_full_cycle_evidence(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            root = Path(directory)
            store = EventStore(root / "events.sqlite3")
            dynamic = DynamicTaskRegistry(root / "tasks.sqlite3")
            runner = AnchorRunner()
            seeder = GenesisSeeder(dynamic, TaskForge(dynamic))
            seeder.seed(runner)
            curriculum = CurriculumRegistry(store, "cli")
            roles = RoleRegistry(store, "cli")
            evolution = EvolutionRegistry(store, "cli")
            artifacts = ContentAddressedArtifactStore(root / "artifacts")
            archive = forge_archive(root)
            harness_repo_root = root / "harness"
            harness_repo = _init_harness_repo(root)
            base = _git(harness_repo, "rev-parse", "HEAD").strip()
            patch_a = b'MARKER = "patched"\nCONST = 1\n'
            ref_a = _checkpoint_ref("gen-a")
            _commit_on(
                harness_repo,
                base,
                "src/aegis/plugins/__init__.py",
                patch_a,
                ref_a,
            )
            canary = (
                "{python}",
                "-c",
                "import aegis.plugins; "
                "assert aegis.plugins.MARKER in ('baseline', 'patched')",
            )

            def cycle_actions(
                *,
                warrior_proposal: dict[str, object] | None,
                prosecutor_actions: list[dict[str, object]] | None = None,
            ) -> list[dict[str, object]]:
                actions = []
                if warrior_proposal is not None:
                    actions.append(warrior_proposal)
                actions.extend(plain_actions(archive))
                if prosecutor_actions is not None:
                    actions[2] = prosecutor_actions[0]
                    actions.insert(3, prosecutor_actions[1])
                return actions

            def run_cycle(
                actions: list[dict[str, object]],
            ) -> object:
                return run_v2_cycle(
                    gateway=FakeGateway(actions),
                    sandbox=WritingFakeSandboxBackend(),
                    research=FakeResearch(),
                    knowledge=None,
                    skills=None,
                    pdf_extractor=None,
                    role_configs=role_configs(),
                    limits=RuntimeLimits(max_steps=20),
                    artifacts=artifacts,
                    dynamic=dynamic,
                    forge=TaskForge(dynamic),
                    runner=runner,
                    curriculum=curriculum,
                    roles=roles,
                    data_dir=root,
                    campaign_id="cli",
                    evolution=evolution,
                    harness_repo=HarnessRepo(harness_repo_root),
                    harness_canary_command=canary,
                    harness_activation_automatic=True,
                )

            try:
                result = run_cycle(
                    cycle_actions(
                        warrior_proposal=warrior_proposal_action(base, ref_a, patch_a)
                    )
                )
                self.assertIs(curriculum.projection.cycle_state, CycleState.COMPLETED)
                self.assertIsNone(
                    evolution.champion(EvolutionSurface.HARNESS_CODE, Role.WARRIOR)
                )
                pending = evolution.validated_candidates()
                self.assertEqual(len(pending), 1)
                self.assertIs(pending[0].surface, EvolutionSurface.HARNESS_CODE)
                self.assertEqual(_git(harness_repo, "rev-parse", "HEAD").strip(), base)
                candidate = json.loads(
                    artifacts.get(result.candidate_evaluation).decode("utf-8")
                )
                self.assertNotIn("harness_canary", candidate)
                self.assertIn("Fresh holdout", candidate["activation"]["reason"])
            finally:
                dynamic.close()
                store.close()


class PopulationArchiveTests(unittest.TestCase):
    def test_register_and_diversity_report(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            root = Path(directory)
            store = EventStore(root / "events.sqlite3")
            archive = PopulationArchive(store, "pop")
            try:
                cell_a = ("harness-code", "plugins", "", "")
                cell_b = ("harness-code", "research", "", "")
                archive.register(
                    candidate_id="evolution-candidate-sha256:" + "a" * 64,
                    cell=cell_a,
                    fitness=1.0,
                    evidence_id="e1",
                    descriptor=cell_a,
                )
                archive.register(
                    candidate_id="evolution-candidate-sha256:" + "b" * 64,
                    cell=cell_b,
                    fitness=1.0,
                    evidence_id="e2",
                    descriptor=cell_b,
                )
                self.assertEqual(len(archive.cells()), 2)
                report = archive.diversity_report()
                self.assertEqual(report["cell_count"], 2)
                self.assertEqual(report["harness_roots"]["plugins"], 1)
                self.assertEqual(report["harness_roots"]["research"], 1)
                replayed = PopulationArchive(store, "pop")
                self.assertEqual(len(replayed.cells()), 2)
            finally:
                store.close()

    def test_equal_fitness_does_not_replace(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            store = EventStore(Path(directory) / "events.sqlite3")
            archive = PopulationArchive(store, "pop2")
            try:
                cell = ("harness-code", "plugins", "", "")
                archive.register(
                    candidate_id="evolution-candidate-sha256:" + "a" * 64,
                    cell=cell,
                    fitness=1.0,
                    evidence_id="e1",
                    descriptor=cell,
                )
                entry = archive.register(
                    candidate_id="evolution-candidate-sha256:" + "b" * 64,
                    cell=cell,
                    fitness=1.0,
                    evidence_id="e2",
                    descriptor=cell,
                )
                self.assertEqual(entry.candidate_id, "evolution-candidate-sha256:" + "a" * 64)
            finally:
                store.close()

    def test_behavior_descriptors(self) -> None:
        content = {
            "changes": [
                {"path": "src/aegis/plugins/demo.py"},
                {"path": "src/aegis/research/x.py"},
            ]
        }
        self.assertEqual(
            harness_changed_roots(content),
            ("plugins", "research"),
        )
        workflow = {"stage_plan": ["search", "solve"]}
        self.assertEqual(
            behavior_roots(workflow, surface=EvolutionSurface.WORKFLOW),
            ("workflow:search",),
        )
        cell = behavior_descriptor(
            surface=EvolutionSurface.HARNESS_CODE,
            changed_roots=("plugins",),
            failure_mode="import error",
            objective="fix imports",
        )
        self.assertEqual(cell[0], "harness-code")
        self.assertEqual(cell[1], "plugins")


class MetaEvolutionTests(unittest.TestCase):
    def test_control_files_require_explicit_authorization(self) -> None:
        for path in META_FORBIDDEN_FILES:
            with self.subTest(path=path):
                with self.assertRaises(EvolutionSurfaceError):
                    validate_harness_path(path)
                self.assertEqual(
                    validate_harness_path(path, meta_evolution_enabled=True),
                    path,
                )
        for path in META_ALLOWED_ROOTS:
            with self.subTest(path=path):
                with self.assertRaises(EvolutionSurfaceError):
                    validate_harness_path(path)
                self.assertEqual(
                    validate_harness_path(path, meta_evolution_enabled=True),
                    path,
                )

    def test_safety_boundaries_never_open(self) -> None:
        for path in (
            "src/aegis/sandbox/agent.py",
            "src/aegis/publishing/publisher.py",
            "src/aegis/config.py",
            "src/aegis/attribution/models.py",
            "tests/test_evolution_harness.py",
        ):
            with self.subTest(path=path):
                with self.assertRaises(EvolutionSurfaceError):
                    validate_harness_path(path, meta_evolution_enabled=True)

    def test_harness_repo_enforces_meta_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = _init_phase4_repo(Path(directory))
            base = _git(repo, "rev-parse", "HEAD").strip()
            patch = b"# evolution registry control file\n# meta-evolved\n"
            ref = _checkpoint_ref("meta-a")
            checkpoint = _commit_on(
                repo, base, "src/aegis/evolution/registry.py", patch, ref
            )
            changes = changes_to_git_file_changes(
                [_change("src/aegis/evolution/registry.py", patch)]
            )
            closed = HarnessRepo(repo)
            with self.assertRaises(HarnessEvolutionError):
                closed.verify_checkpoint(
                    base_commit=base, checkpoint_ref=ref, changes=changes
                )
            opened = HarnessRepo(repo, meta_evolution_enabled=True)
            self.assertEqual(
                opened.verify_checkpoint(
                    base_commit=base, checkpoint_ref=ref, changes=changes
                ),
                checkpoint,
            )
            activated = opened.activate(changes, message="meta evolution")
            self.assertIsInstance(activated, str)


class HarnessPhase4EndToEndTests(unittest.TestCase):
    def test_meta_harness_candidate_remains_pending_after_canary(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            root = Path(directory)
            store = EventStore(root / "events.sqlite3")
            dynamic = DynamicTaskRegistry(root / "tasks.sqlite3")
            runner = AnchorRunner()
            seeder = GenesisSeeder(dynamic, TaskForge(dynamic))
            seeder.seed(runner)
            curriculum = CurriculumRegistry(store, "cli")
            roles = RoleRegistry(store, "cli")
            evolution = EvolutionRegistry(store, "cli")
            population = PopulationArchive(store, "cli")
            artifacts = ContentAddressedArtifactStore(root / "artifacts")
            archive = forge_archive(root)
            harness_repo_root = root / "harness"
            harness_repo = _init_phase4_repo(root)
            canary = (
                "{python}",
                "-c",
                "import aegis.plugins; "
                "assert aegis.plugins.MARKER in ('baseline', 'patched')",
            )

            def run_cycle(
                actions: list[dict[str, object]],
                *,
                meta: bool = False,
            ) -> object:
                return run_v2_cycle(
                    gateway=FakeGateway(actions),
                    sandbox=WritingFakeSandboxBackend(),
                    research=FakeResearch(),
                    knowledge=None,
                    skills=None,
                    pdf_extractor=None,
                    role_configs=role_configs(),
                    limits=RuntimeLimits(max_steps=20),
                    artifacts=artifacts,
                    dynamic=dynamic,
                    forge=TaskForge(dynamic),
                    runner=runner,
                    curriculum=curriculum,
                    roles=roles,
                    data_dir=root,
                    campaign_id="cli",
                    evolution=evolution,
                    harness_repo=HarnessRepo(
                        harness_repo_root, meta_evolution_enabled=meta
                    ),
                    harness_canary_command=canary,
                    harness_activation_automatic=True,
                    population=population,
                    meta_evolution_enabled=meta,
                )

            def actions_for(
                *,
                warrior_proposal: dict[str, object] | None,
                prosecutor_actions: list[dict[str, object]] | None = None,
            ) -> list[dict[str, object]]:
                actions = []
                if warrior_proposal is not None:
                    actions.append(warrior_proposal)
                actions.extend(plain_actions(archive))
                if prosecutor_actions is not None:
                    actions[2] = prosecutor_actions[0]
                    actions.insert(3, prosecutor_actions[1])
                return actions

            def propose(
                base: str,
                ref: str,
                content: bytes,
                *,
                path: str = "src/aegis/plugins/__init__.py",
            ) -> dict[str, object]:
                return warrior_proposal_action(base, ref, content, path=path)

            try:
                base = _git(harness_repo, "rev-parse", "HEAD").strip()

                patch_plugins = b"# evolution registry control file\n# meta-evolved\n"
                ref_plugins = _checkpoint_ref("gen-meta")
                _commit_on(
                    harness_repo,
                    base,
                    "src/aegis/evolution/registry.py",
                    patch_plugins,
                    ref_plugins,
                )
                run_cycle(
                    actions_for(
                        warrior_proposal=propose(
                            base,
                            ref_plugins,
                            patch_plugins,
                            path="src/aegis/evolution/registry.py",
                        )
                    ),
                    meta=True,
                )
                self.assertIsNone(
                    evolution.champion(EvolutionSurface.HARNESS_CODE, Role.WARRIOR)
                )
                pending = evolution.validated_candidates()
                self.assertEqual(len(pending), 1)
                self.assertIs(pending[0].surface, EvolutionSurface.HARNESS_CODE)
                self.assertEqual(_git(harness_repo, "rev-parse", "HEAD").strip(), base)
                self.assertEqual(population.diversity_report()["cell_count"], 0)
            finally:
                dynamic.close()
                store.close()


if __name__ == "__main__":
    unittest.main()
