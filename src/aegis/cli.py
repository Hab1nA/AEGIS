"""Zero-dependency command line interface for AEGIS."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
from dataclasses import asdict, is_dataclass, replace
from pathlib import Path
from typing import Any, Mapping, Sequence, cast

from aegis.agent_runtime import ACTION_SCHEMA, Action, ActionError, RuntimeLimits
from aegis.artifacts import ContentAddressedArtifactStore
from aegis.autonomy_acceptance import verify_autonomy_campaign
from aegis.autonomy_budget import (
    AUTONOMY_MIN_AGENT_STEPS,
    AUTONOMY_ROLE_SHARES,
    autonomy_budget_check,
    autonomy_v2_budget_check,
)
from aegis.config import AUTONOMY_ACCEPTANCE_PROFILES, CampaignConfig
from aegis.curriculum import CurriculumRegistry
from aegis.cycle_ports import _git_head, run_v2_cycle
from aegis.dynamic_tasks import (
    DynamicTaskOrigin,
    DynamicTaskRegistry,
    GenesisSeeder,
    TaskForge,
)
from aegis.event_store import EventStore
from aegis.evolution_canary import EvolutionCanary
from aegis.evolution_registry import EvolutionRegistry
from aegis.evolution_validation import EvolutionValidator
from aegis.evolution_workspace import EvolutionWorkspace, ValidationCommand
from aegis.gateway.client import GatewayConfig, ModelGateway
from aegis.gateway.types import GatewayRequest, Message
from aegis.knowledge import KnowledgeStore
from aegis.models import Role, canonical_json, thaw_json
from aegis.orchestrator import (
    CampaignController,
    apply_persisted_control,
    prepare_retryable_failure,
)
from aegis.publishing import GitPublisher
from aegis.reporting import build_report, replay_events, write_report
from aegis.research import (
    LoopbackProxyTLSTransport,
    PinnedHTTPSFetcher,
    ResearchBroker,
    SearxNGSearchProvider,
    WslLoopbackHTTPFetcher,
)
from aegis.research.pdf_extractor import SandboxPDFExtractor
from aegis.roles import RoleRegistry
from aegis.sandbox.backend import SandboxBackend
from aegis.sandbox.fake import FakeSandboxBackend
from aegis.sandbox.owned import OwnedSandboxBackend
from aegis.sandbox.types import CommandSpec
from aegis.sandbox.wsl import WslSandboxBackend
from aegis.skill_registry import SkillRegistry
from aegis.strategy import StrategyRegistry
from aegis.taskpacks import (
    ExecutionResult,
    PythonTaskProvider,
    SandboxTaskPackRunner,
    TaskPack,
    TaskPackValidation,
    validate_taskpack,
)
from aegis.taskpacks.builtin import builtin_python_root

_DATA_DIR_OVERRIDE: Path | None = None


def _data_dir() -> Path:
    if _DATA_DIR_OVERRIDE is not None:
        return _DATA_DIR_OVERRIDE
    configured = os.environ.get("AEGIS_DATA_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    local = os.environ.get("LOCALAPPDATA")
    return (Path(local) / "AEGIS" if local else Path.cwd() / ".aegis").resolve()


def _config_path(campaign_id: str) -> Path:
    return _data_dir() / "campaigns" / f"{campaign_id}.json"


def _store() -> EventStore:
    root = _data_dir()
    root.mkdir(parents=True, exist_ok=True)
    return EventStore(root / "events.sqlite3")


def _knowledge() -> KnowledgeStore:
    root = _data_dir()
    root.mkdir(parents=True, exist_ok=True)
    return KnowledgeStore(root / "knowledge.sqlite3")


def _skills() -> SkillRegistry:
    root = _data_dir()
    root.mkdir(parents=True, exist_ok=True)
    return SkillRegistry(root / "skills.sqlite3")


def _load(campaign_id: str) -> CampaignConfig:
    config = CampaignConfig.load(_config_path(campaign_id))
    database = _data_dir() / "events.sqlite3"
    if not database.exists():
        return config
    store = EventStore(database)
    try:
        created = [
            event.payload
            for event in store.read(campaign_id, limit=1000)
            if event.event_type == "campaign_created"
        ]
    finally:
        store.close()
    if not created:
        return config
    if len(created) != 1 or not isinstance(created[0].get("config"), Mapping):
        raise RuntimeError("campaign configuration binding is missing or ambiguous")
    bound = CampaignConfig.from_mapping(thaw_json(created[0]["config"]))
    if canonical_json(bound.to_dict()) != canonical_json(config.to_dict()):
        raise RuntimeError("campaign configuration differs from its immutable creation snapshot")
    return config


def _execution_result(value: object, label: str) -> ExecutionResult:
    if not isinstance(value, dict) or set(value) != {
        "passed",
        "tests_run",
        "exit_code",
        "timed_out",
        "output_digest",
    }:
        raise ValueError(f"validation evidence {label} has missing or unknown fields")
    if (
        not isinstance(value["passed"], bool)
        or isinstance(value["tests_run"], bool)
        or not isinstance(value["tests_run"], int)
        or isinstance(value["exit_code"], bool)
        or not isinstance(value["exit_code"], int)
        or not isinstance(value["timed_out"], bool)
        or not isinstance(value["output_digest"], str)
    ):
        raise ValueError(f"validation evidence {label} has invalid field types")
    return ExecutionResult(**value)


def _load_validated_pack(path: str) -> tuple[TaskPack, TaskPackValidation]:
    pack = TaskPack.load(Path(path))
    # Evidence is deliberately adjacent to the integrity-hashed pack.  Keeping
    # it inside the pack would make its embedded content_hash self-referential.
    evidence_path = pack.root.parent / f"{pack.root.name}.validation.json"
    try:
        raw = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read task-pack validation evidence: {evidence_path}") from exc
    expected = {
        "content_hash",
        "valid",
        "reasons",
        "reference_public",
        "reference_hidden",
        "defect_public",
        "defect_hidden",
        "mutant_hidden",
    }
    if not isinstance(raw, dict) or set(raw) != expected:
        raise ValueError("validation evidence has missing or unknown fields")
    if raw["content_hash"] != pack.manifest.content_hash:
        raise ValueError("validation evidence content hash does not match task pack")
    if (
        not isinstance(raw["valid"], bool)
        or not isinstance(raw["reasons"], list)
        or not all(isinstance(item, str) for item in raw["reasons"])
    ):
        raise ValueError("validation evidence summary is invalid")
    mutants = raw["mutant_hidden"]
    if not isinstance(mutants, list):
        raise ValueError("validation evidence mutant_hidden must be an array")
    report = TaskPackValidation(
        raw["valid"],
        tuple(raw["reasons"]),
        _execution_result(raw["reference_public"], "reference_public"),
        _execution_result(raw["reference_hidden"], "reference_hidden"),
        _execution_result(raw["defect_public"], "defect_public"),
        _execution_result(raw["defect_hidden"], "defect_hidden"),
        tuple(_execution_result(item, "mutant_hidden") for item in mutants),
    )
    if not report.valid or report.reasons:
        raise ValueError("task-pack validation evidence is not a successful validation")
    if len(report.mutant_hidden) != len(pack.manifest.mutant_dirs):
        raise ValueError("validation evidence mutant count does not match task pack")
    return pack, report


def _validate_packs(
    paths: tuple[str, ...], sandbox: SandboxBackend, *, campaign_id: str = ""
) -> tuple[tuple[TaskPack, TaskPackValidation], ...]:
    runner = SandboxTaskPackRunner(sandbox, id_namespace=campaign_id)
    validated: list[tuple[TaskPack, TaskPackValidation]] = []
    for path in paths:
        pack, sealed = _load_validated_pack(path)
        try:
            live = validate_taskpack(pack, runner)
        except (OSError, RuntimeError, ValueError) as exc:
            raise RuntimeError(
                f"live sandbox validation crashed for {pack.manifest.task_id}: {exc}"
            ) from exc
        if not live.valid:
            raise ValueError(
                f"live sandbox validation failed for {pack.manifest.task_id}: {', '.join(live.reasons)}"
            )
        # The checked evidence must describe the same suite cardinalities and
        # outcomes. Output digests may vary because pytest timing is not stable.
        sealed_rows = (
            sealed.reference_public,
            sealed.reference_hidden,
            sealed.defect_public,
            sealed.defect_hidden,
            *sealed.mutant_hidden,
        )
        live_rows = (
            live.reference_public,
            live.reference_hidden,
            live.defect_public,
            live.defect_hidden,
            *live.mutant_hidden,
        )
        if len(sealed_rows) != len(live_rows) or any(
            (a.passed, a.tests_run) != (b.passed, b.tests_run) for a, b in zip(sealed_rows, live_rows)
        ):
            raise ValueError(f"live validation contradicts sealed evidence for {pack.manifest.task_id}")
        validated.append((pack, live))
    return tuple(validated)


def _research(config: CampaignConfig) -> ResearchBroker:
    if not config.research_enabled or config.offline_research:
        return ResearchBroker()
    proxy_url = os.environ.get("AEGIS_HTTPS_PROXY")
    public_fetcher = PinnedHTTPSFetcher(
        transport=(LoopbackProxyTLSTransport(proxy_url).connect if proxy_url else None)
    )
    loopback = os.environ.get("AEGIS_ALLOW_INSECURE_SEARCH_LOOPBACK", "false").strip().lower()
    search_fetcher = WslLoopbackHTTPFetcher() if loopback == "true" else public_fetcher
    provider = SearxNGSearchProvider.from_environment(fetcher=search_fetcher)
    return ResearchBroker(search_provider=provider, fetcher=public_fetcher)


def _controller(campaign_id: str) -> CampaignController:
    config = _load(campaign_id)
    sandbox = FakeSandboxBackend() if config.sandbox_backend == "fake" else WslSandboxBackend()
    gateway = ModelGateway(GatewayConfig.from_env())
    store = _store()
    knowledge: KnowledgeStore | None = None
    skills: SkillRegistry | None = None
    evolution_registry: EvolutionRegistry | None = None

    def append_sandbox_event(kind: str, payload: dict[str, Any]) -> None:
        store.append(config.campaign_id, kind, payload)

    preflight_sandbox = OwnedSandboxBackend(sandbox, append_sandbox_event)
    try:
        knowledge = _knowledge()
        skills = _skills()
        root = _data_dir()
        evolution_registry = EvolutionRegistry(root / "evolution.sqlite3")
        evolution_workspace = EvolutionWorkspace(Path(__file__).resolve().parents[2])
        packs = _validate_packs(config.task_pack_paths, preflight_sandbox, campaign_id=config.campaign_id)
        controller = CampaignController(
            config,
            store,
            gateway,
            sandbox,
            PythonTaskProvider(packs, sandbox),
            _research(config),
            knowledge=knowledge,
            skills=skills,
            evolution_workspace=evolution_workspace,
            evolution_registry=evolution_registry,
        )
        controller.evolution_canary = EvolutionCanary(controller.sandbox)
        controller.pdf_extractor = SandboxPDFExtractor(controller.sandbox)
        return controller
    except Exception:
        try:
            store.close()
        finally:
            try:
                if knowledge is not None:
                    knowledge.close()
            finally:
                try:
                    if skills is not None:
                        skills.close()
                finally:
                    if evolution_registry is not None:
                        evolution_registry.close()
        raise


def _next_v2_generation(registry: DynamicTaskRegistry) -> int:
    records = registry.records()
    if not records:
        return 2
    latest = max(record.creator_generation for record in records)
    return max(2, latest + 1)


def _evolution_cycle(args: argparse.Namespace) -> Mapping[str, Any]:
    """Cold-start and plan one dynamic v2 cycle without running model ports."""
    config = _load(args.campaign_id)
    if config.autonomy_v2 is None or not config.autonomy_v2.enabled:
        raise RuntimeError(
            "campaign does not enable autonomy_v2; evolution-cycle requires the dynamic-only design"
        )
    root = _data_dir()
    root.mkdir(parents=True, exist_ok=True)
    registry = DynamicTaskRegistry(root / "dynamic_tasks.sqlite3")
    try:
        seeded: list[str] = []
        if not args.dry_run and not args.no_seed_anchors and not registry.records():
            sandbox: SandboxBackend = (
                FakeSandboxBackend() if config.sandbox_backend == "fake" else WslSandboxBackend()
            )
            doctor_report = sandbox.doctor()
            if not doctor_report.passed:
                raise RuntimeError(
                    "sandbox doctor failed before cold-start validation: "
                    + "; ".join(
                        f"{check.name}: {check.detail}"
                        for check in doctor_report.checks
                        if not check.passed
                    )
                )
            runner = SandboxTaskPackRunner(sandbox, id_namespace=config.campaign_id)
            records = GenesisSeeder(registry, TaskForge(registry)).seed(runner)
            seeded = [record.artifact.task_id for record in records]
        target = _next_v2_generation(registry)
        cohort = registry.select_dynamic_cohort(target, limit=args.cohort_limit)
        records = registry.records()
        return {
            "campaign_id": config.campaign_id,
            "mode": "dry-run" if args.dry_run else "plan",
            "seeded_anchors": seeded,
            "registry": {
                "records": len(records),
                "anchors": sum(
                    1 for record in records if record.origin is DynamicTaskOrigin.FIXED_ANCHOR
                ),
                "dynamic": sum(
                    1 for record in records if record.origin is DynamicTaskOrigin.DYNAMIC
                ),
            },
            "target_generation": target,
            "cohort": cohort.to_mapping(),
        }
    finally:
        registry.close()


def _run_v2_cycle_cli(
    config: CampaignConfig, root: Path, *, repair: bool = False
) -> Mapping[str, Any]:
    """Execute one full model-driven v2 cycle through the real runtime wiring."""
    store = _store()
    knowledge = _knowledge()
    skills = _skills()
    dynamic = DynamicTaskRegistry(root / "dynamic_tasks.sqlite3")
    try:
        sandbox: SandboxBackend = (
            FakeSandboxBackend() if config.sandbox_backend == "fake" else WslSandboxBackend()
        )
        doctor_report = sandbox.doctor()
        if not doctor_report.passed:
            raise RuntimeError(
                "sandbox doctor failed before the v2 cycle run: "
                + "; ".join(
                    f"{check.name}: {check.detail}"
                    for check in doctor_report.checks
                    if not check.passed
                )
            )
        curriculum = CurriculumRegistry(store, config.campaign_id)
        roles = RoleRegistry(store, config.campaign_id)
        artifacts = ContentAddressedArtifactStore(root / "artifacts")
        runner = SandboxTaskPackRunner(sandbox, id_namespace=config.campaign_id)
        forge = TaskForge(dynamic)
        gateway = ModelGateway(GatewayConfig.from_env())
        autonomy = config.autonomy_v2
        source_commit = None
        if autonomy is not None and autonomy.public_repo_url is not None:
            source_commit = _git_head(Path(__file__).resolve().parents[2])
        result = run_v2_cycle(
            gateway=gateway,
            sandbox=sandbox,
            research=_research(config),
            knowledge=knowledge,
            skills=skills,
            pdf_extractor=(
                None if config.sandbox_backend == "fake" else SandboxPDFExtractor(sandbox)
            ),
            role_configs=dict(config.roles),
            limits=RuntimeLimits(max_steps=config.max_agent_steps),
            artifacts=artifacts,
            dynamic=dynamic,
            forge=forge,
            runner=runner,
            curriculum=curriculum,
            roles=roles,
            data_dir=root,
            campaign_id=config.campaign_id,
            holdout_delay=(
                autonomy.task_holdout_delay_cycles if autonomy is not None else 1
            ),
            public_repo_url=autonomy.public_repo_url if autonomy is not None else None,
            source_commit=source_commit,
            repair_on_failure=repair,
            event_store=store,
            repair_git_publisher=(
                GitPublisher(
                    autonomy.public_repo_url,
                    remote_id="aegis-public",
                    allowed_role_paths={"warrior": ("warrior",)},
                )
                if autonomy is not None and autonomy.public_repo_url is not None
                else None
            ),
        )
        if hasattr(result, "status"):
            return {
                "campaign_id": config.campaign_id,
                "repaired": True,
                "incident_id": result.incident_id,
                "repair_plan_id": result.repair_plan_id,
                "status": result.status.value,
                "completed_steps": [item.value for item in result.completed_steps],
            }
        return {
            "campaign_id": config.campaign_id,
            "state": curriculum.projection.cycle_state.value,
            "snapshot_id": result.snapshot_id,
            "cohort_id": result.cohort_id,
            "cycle_summary": result.cycle_summary.artifact_id,
            "artifacts": {
                name: getattr(result, name).artifact_id
                for name in (
                    "submission",
                    "judge_review",
                    "quality_lock",
                    "prosecutor_audit",
                    "council",
                    "forged_tasks",
                    "task_validation",
                    "attribution",
                    "qualification",
                    "activation",
                )
            },
        }
    finally:
        dynamic.close()
        knowledge.close()
        skills.close()
        store.close()


def _print(value: object) -> None:
    print(
        json.dumps(
            value,
            indent=2,
            ensure_ascii=False,
            default=lambda item: asdict(cast(Any, item)) if is_dataclass(item) else str(item),
        )
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegis", description="Adversarial AI engineering campaigns")
    parser.add_argument(
        "--data-dir",
        type=Path,
        help="explicit isolated runtime state directory; place before the subcommand",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor")
    boot = sub.add_parser("sandbox-bootstrap", help="render a bootstrap plan; dry-run by default")
    boot.add_argument("--image", required=True)
    boot.add_argument("--apply", action="store_true")
    boot.add_argument("--root", type=Path)
    create = sub.add_parser("campaign-create")
    create.add_argument("config", type=Path)
    for name in (
        "start",
        "pause",
        "resume",
        "retry",
        "stop",
        "kill",
        "status",
        "replay",
        "strategy-history",
    ):
        command = sub.add_parser(name)
        command.add_argument("campaign_id")
        if name == "retry":
            command.add_argument(
                "--after-fix",
                action="store_true",
                help="resume a failed campaign from its durable boundary after an operator-applied fix",
            )
    report = sub.add_parser("report")
    report.add_argument("campaign_id")
    report.add_argument("--format", choices=("json", "markdown"), default="json")
    report.add_argument("--output", type=Path)
    knowledge = sub.add_parser("knowledge-search")
    knowledge.add_argument("query")
    knowledge.add_argument("--role", choices=[role.value for role in Role])
    knowledge.add_argument("--limit", type=int, default=20)
    preflight = sub.add_parser(
        "autonomy-preflight",
        help="fail-closed report on whether full autonomous evolution may start",
    )
    preflight.add_argument("campaign_id")
    smoke_verify = sub.add_parser(
        "autonomy-smoke-verify",
        help="verify the real research-to-candidate-to-inheritance acceptance event chain",
    )
    smoke_verify.add_argument("campaign_id")
    sub.add_parser(
        "autonomy-local-acceptance",
        help="run the no-network candidate validation and canary chain in real WSL/Podman",
    )
    cycle = sub.add_parser(
        "evolution-cycle",
        help="cold-start and plan one dynamic v2 cycle; --dry-run never validates or mutates",
    )
    cycle.add_argument("campaign_id")
    cycle.add_argument("--dry-run", action="store_true")
    cycle.add_argument(
        "--run",
        action="store_true",
        help="execute one full model-driven v2 cycle after cold-start planning",
    )
    cycle.add_argument(
        "--repair",
        action="store_true",
        help="on cycle failure, run the Prosecutor repair pipeline (requires --run)",
    )
    cycle.add_argument(
        "--no-seed-anchors",
        action="store_true",
        help="do not register built-in anchor tasks into an empty dynamic task bank",
    )
    cycle.add_argument("--cohort-limit", type=int)
    return parser


def _apply_control(campaign_id: str, action: str) -> object:
    config = _load(campaign_id)
    sandbox: SandboxBackend = (
        FakeSandboxBackend() if config.sandbox_backend == "fake" else WslSandboxBackend()
    )
    store = _store()
    try:
        return apply_persisted_control(campaign_id, store, sandbox, action)
    finally:
        store.close()


_EVOLUTION_WORKSPACE_PROBE = r"""
import errno
import hashlib
import json
import os
import sys

manifest = json.loads(sys.stdin.read())
root = "/workspace"
files = manifest["files"]
rules = manifest["writable_paths"]
failures = []
permission_errors = {errno.EACCES, errno.EPERM, errno.EROFS}


def target(path):
    return os.path.join(root, *path.split("/"))


def writable(path):
    return any(
        path == rule["path"]
        or (rule["recursive"] and path.startswith(rule["path"] + "/"))
        for rule in rules
    )


for item in files:
    try:
        with open(target(item["path"]), "rb") as source:
            digest = hashlib.sha256(source.read()).hexdigest()
    except OSError as exc:
        failures.append("unreadable:" + item["path"] + ":" + str(exc.errno))
    else:
        if digest != item["sha256"]:
            failures.append("digest:" + item["path"])

readonly_files = [item["path"] for item in files if not writable(item["path"])]
for path in readonly_files:
    try:
        descriptor = os.open(target(path), os.O_WRONLY | os.O_APPEND)
    except OSError as exc:
        if exc.errno not in permission_errors:
            failures.append("readonly-file-error:" + path + ":" + str(exc.errno))
    else:
        os.close(descriptor)
        failures.append("writable-file:" + path)

directories = {"."}
for item in files:
    parts = item["path"].split("/")[:-1]
    for index in range(1, len(parts) + 1):
        directories.add("/".join(parts[:index]))
readonly_directories = sorted(path for path in directories if path == "." or not writable(path))
for path in readonly_directories:
    marker = os.path.join(root if path == "." else target(path), ".aegis-readonly-probe")
    try:
        descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        if exc.errno not in permission_errors:
            failures.append("readonly-dir-error:" + path + ":" + str(exc.errno))
    else:
        os.close(descriptor)
        os.unlink(marker)
        failures.append("writable-dir:" + path)

for rule in rules:
    path = rule["path"]
    if rule["recursive"]:
        marker = os.path.join(target(path), ".aegis-writable-probe")
        try:
            descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(b"AEGIS")
            os.unlink(marker)
        except OSError as exc:
            failures.append("unwritable-rule:" + path + ":" + str(exc.errno))
    else:
        destination = target(path)
        try:
            with open(destination, "rb") as source:
                original = source.read()
            with open(destination, "ab") as output:
                output.write(b"\n# AEGIS writable probe\n")
            with open(destination, "wb") as output:
                output.write(original)
        except OSError as exc:
            failures.append("unwritable-rule:" + path + ":" + str(exc.errno))

result = {
    "passed": not failures,
    "files_verified": len(files),
    "readonly_files_checked": len(readonly_files),
    "readonly_directories_checked": len(readonly_directories),
    "writable_rules_checked": len(rules),
    "failures": failures[:20],
}
sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")))
sys.exit(0 if result["passed"] else 1)
"""


def _probe_evolution_workspace(
    backend: SandboxBackend,
    workspace: EvolutionWorkspace,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Exercise the real candidate mount boundary and prove host isolation and cleanup."""
    access_passed = False
    access_detail = "evolution workspace access probe did not run"
    cleanup_passed = False
    cleanup_detail = "sandbox cleanup did not run"
    host_passed = False
    host_detail = "host repository integrity was not verified"
    sandbox_id = f"evolution-preflight-{secrets.token_hex(8)}"
    baseline = None
    initial_cleanup_succeeded = False

    try:
        baseline = workspace.create_snapshot()
        manifest = {
            "files": [
                {"path": item.path, "sha256": item.sha256}
                for item in baseline.files
            ],
            "writable_paths": [
                {"path": item.path, "recursive": item.recursive}
                for item in workspace.policy.evolvable_paths
            ],
        }
        backend.prepare(sandbox_id)
        workspace.stage_snapshot(backend, sandbox_id, baseline)
        command = CommandSpec(
            ("python", "-B", "-I", "-c", _EVOLUTION_WORKSPACE_PROBE),
            stdin=json.dumps(manifest, sort_keys=True, separators=(",", ":")),
            timeout_seconds=120.0,
        )
        execution = backend.exec(sandbox_id, command)
        if execution.timed_out:
            raise RuntimeError("workspace access probe timed out")
        if execution.exit_code != 0:
            raise RuntimeError(
                f"workspace access probe exited {execution.exit_code}: "
                f"{execution.stderr.strip() or execution.stdout.strip()}"
            )
        try:
            result = json.loads(execution.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("workspace access probe returned invalid JSON") from exc
        expected_readonly_files = sum(
            not workspace.policy.permits(item.path) for item in baseline.files
        )
        if not isinstance(result, dict) or result != {
            "passed": True,
            "files_verified": len(baseline.files),
            "readonly_files_checked": expected_readonly_files,
            "readonly_directories_checked": result.get("readonly_directories_checked"),
            "writable_rules_checked": len(workspace.policy.evolvable_paths),
            "failures": [],
        }:
            raise RuntimeError("workspace access probe returned inconsistent evidence")
        if not isinstance(result["readonly_directories_checked"], int) or result[
            "readonly_directories_checked"
        ] < 1:
            raise RuntimeError("workspace access probe did not check read-only directories")
        access_passed = True
        access_detail = (
            f"verified {result['files_verified']} context file hash(es), "
            f"{result['readonly_files_checked']} read-only file(s), "
            f"{result['readonly_directories_checked']} read-only directorie(s), and "
            f"{result['writable_rules_checked']} evolvable write rule(s) in network-none Podman"
        )
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        access_detail = f"workspace access probe failed closed: {type(exc).__name__}: {exc}"
    finally:
        try:
            backend.destroy(sandbox_id)
        except Exception as exc:
            cleanup_detail = f"initial sandbox destroy failed: {type(exc).__name__}: {exc}"
        else:
            initial_cleanup_succeeded = True

        if initial_cleanup_succeeded:
            try:
                backend.prepare(sandbox_id)
                backend.destroy(sandbox_id)
            except Exception as exc:
                cleanup_detail = (
                    "sandbox residue/reuse probe failed closed: "
                    f"{type(exc).__name__}: {exc}"
                )
                try:
                    backend.destroy(sandbox_id)
                except Exception as cleanup_exc:
                    cleanup_detail += (
                        "; final cleanup failed: "
                        f"{type(cleanup_exc).__name__}: {cleanup_exc}"
                    )
            else:
                cleanup_passed = True
                cleanup_detail = "destroyed sandbox, reused the same ID, and destroyed it again without residue"

        if baseline is not None:
            try:
                current = workspace.create_snapshot()
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                host_detail = f"host repository resnapshot failed: {type(exc).__name__}: {exc}"
            else:
                host_passed = current.archive_sha256 == baseline.archive_sha256
                host_detail = (
                    f"host repository snapshot unchanged at sha256={baseline.archive_sha256}"
                    if host_passed
                    else (
                        "host repository changed during sandbox probe: "
                        f"before={baseline.archive_sha256}, after={current.archive_sha256}"
                    )
                )

    return (
        {"name": "evolution_workspace_access_live", "passed": access_passed, "detail": access_detail},
        {"name": "evolution_host_integrity", "passed": host_passed, "detail": host_detail},
        {"name": "evolution_sandbox_cleanup", "passed": cleanup_passed, "detail": cleanup_detail},
    )


def _held_out_context_check(workspace: EvolutionWorkspace) -> tuple[bool, str]:
    snapshot = workspace.create_snapshot()
    forbidden = {"defect", "hidden", "mutants", "reference"}
    leaked = [
        item.path
        for item in snapshot.files
        if item.path.endswith(".validation.json")
        or forbidden.intersection(item.path.split("/"))
    ]
    public_files = [
        item.path
        for item in snapshot.files
        if item.path.startswith("taskpacks/") and "/public/" in item.path
    ]
    taskpacks_present = (workspace.root / "taskpacks").exists()
    passed = not leaked and (bool(public_files) or not taskpacks_present)
    return (
        passed,
        (
            f"excluded held-out taskpack assets while retaining {len(public_files)} public file(s)"
            if passed
            else f"held-out leak count={len(leaked)}, retained public files={len(public_files)}"
        ),
    )


def _run_autonomy_preflight(campaign_id: str) -> dict[str, Any]:
    """Fail-closed preflight: report every gate that must pass before full autonomous evolution."""
    checks: list[dict[str, Any]] = []
    config = _load(campaign_id)

    def _check(name: str, passed: bool, detail: str) -> None:
        checks.append({"name": name, "passed": passed, "detail": detail})

    # 1. Sandbox doctor
    doctor_passed = False
    sandbox: SandboxBackend = (
        FakeSandboxBackend() if config.sandbox_backend == "fake" else WslSandboxBackend()
    )
    try:
        doctor_report = sandbox.doctor()
        doctor_passed = doctor_report.passed
        _check("sandbox_doctor", doctor_report.passed, "; ".join(
            f"{c.name}: {'ok' if c.passed else c.detail}" for c in doctor_report.checks
        ))
    except Exception as exc:
        _check("sandbox_doctor", False, f"doctor raised: {exc}")

    # 2. Real backend and test-mode safety
    _check(
        "real_backend",
        config.sandbox_backend != "fake",
        f"sandbox_backend={config.sandbox_backend}",
    )
    _check(
        "test_mode_off",
        not config.test_mode,
        f"test_mode={config.test_mode}",
    )
    _check(
        "demo_mode_off",
        not config.demo_mode,
        f"demo_mode={config.demo_mode}",
    )
    v2_dynamic = config.autonomy_v2 is not None and config.autonomy_v2.enabled
    budget = (autonomy_v2_budget_check if v2_dynamic else autonomy_budget_check)(
        total_tokens=config.total_tokens,
        max_requests=config.max_requests,
        role_shares={role: cfg.budget_share for role, cfg in config.roles.items()},
        max_output_tokens={role: cfg.max_output_tokens for role, cfg in config.roles.items()},
    )
    shares_match = all(
        config.roles[role].budget_share == share
        for role, share in AUTONOMY_ROLE_SHARES.items()
    )
    dedicated_smoke = config.acceptance_profile in AUTONOMY_ACCEPTANCE_PROFILES
    _check(
        "autonomy_smoke_budget_reachable",
        not dedicated_smoke
        or (
            config.max_rounds == 2
            and config.max_agent_steps >= AUTONOMY_MIN_AGENT_STEPS
            and shares_match
            and config.wall_time_seconds >= 28_800
            and budget.passed
        ),
        (
            "not a dedicated autonomy smoke profile"
            if not dedicated_smoke
            else (
                f"minimum_requests={budget.minimum_requests}, "
                f"global_tokens_required={budget.global_tokens_required}, "
                f"failures={list(budget.failures)}"
            )
        ),
    )

    # 3. Research config
    _check(
        "research_enabled",
        config.research_enabled,
        f"research_enabled={config.research_enabled}",
    )
    _check(
        "online_research",
        not config.offline_research,
        f"offline_research={config.offline_research}",
    )
    gateway_config: GatewayConfig | None = None
    try:
        gateway_config = GatewayConfig.from_env()
    except (ValueError, OSError) as exc:
        _check("gateway_config", False, f"gateway configuration is incomplete: {exc}")
    else:
        _check("gateway_config", True, "OpenAI-compatible gateway configuration loaded")
    if gateway_config is None:
        _check("gateway_live_probe", False, "skipped because gateway configuration is incomplete")
    else:
        try:
            probe = ModelGateway(gateway_config).complete(
                GatewayRequest(
                    config.roles[Role.WARRIOR.value].model,
                    (
                        Message(
                            "user",
                            (
                                "Return exactly this JSON action and nothing else: "
                                '{"action":"submit","arguments":{"summary":"AEGIS_OK","payload":{}}}'
                            ),
                        ),
                    ),
                    min(1_024, config.roles[Role.WARRIOR.value].max_output_tokens),
                    temperature=0.0,
                    output_schema=ACTION_SCHEMA,
                    seed=0,
                    reasoning_effort=config.roles[Role.WARRIOR.value].reasoning_effort,
                )
            )
        except Exception as exc:
            _check("gateway_live_probe", False, f"live model probe failed: {type(exc).__name__}: {exc}")
        else:
            usage = probe.usage
            try:
                action = Action.parse(probe.text)
            except (ActionError, TypeError, ValueError):
                action = None
            passed = (
                action is not None
                and action.name == "submit"
                and action.arguments == {"summary": "AEGIS_OK", "payload": {}}
                and usage.verified
            )
            failure_detail = ""
            if not passed:
                if action is None:
                    action_status = "invalid-action"
                elif action.name != "submit" or action.arguments != {
                    "summary": "AEGIS_OK",
                    "payload": {},
                }:
                    action_status = "unexpected-action"
                else:
                    action_status = "exact-action"
                encoded_text = probe.text.encode("utf-8")
                failure_detail = (
                    f"action={action_status}, usage_verified={usage.verified}, "
                    f"input={usage.input_tokens}, output={usage.output_tokens}, "
                    f"reasoning={usage.reasoning_tokens}, protocol={probe.protocol}, "
                    f"text_bytes={len(encoded_text)}, text_sha256={hashlib.sha256(encoded_text).hexdigest()}"
                )
            _check(
                "gateway_live_probe",
                passed,
                (
                    f"model responded with verified usage: input={usage.input_tokens}, "
                    f"output={usage.output_tokens}, protocol={probe.protocol}"
                    if passed
                    else failure_detail
                ),
            )
    research: ResearchBroker | None = None
    try:
        research = _research(config)
    except (ValueError, OSError) as exc:
        _check("research_provider", False, f"research provider configuration failed: {exc}")
    else:
        _check("research_provider", True, "brokered research provider configuration loaded")
    if research is None or not config.research_enabled or config.offline_research:
        _check("research_search_live", False, "skipped because online research is unavailable")
        _check("research_fetch_live", False, "skipped because online research is unavailable")
    else:
        try:
            hits = research.search("Python software engineering testing", limit=1)
        except Exception as exc:
            _check("research_search_live", False, f"live search probe failed: {type(exc).__name__}: {exc}")
        else:
            _check(
                "research_search_live",
                bool(hits),
                "brokered search returned a validated HTTPS result" if hits else "search returned no results",
            )
        try:
            artifact = research.fetch("https://example.com/")
        except Exception as exc:
            _check("research_fetch_live", False, f"live fetch probe failed: {type(exc).__name__}: {exc}")
        else:
            provenance = artifact.provenance
            passed = bool(artifact.content) and provenance.size_bytes == len(artifact.content)
            _check(
                "research_fetch_live",
                passed,
                (
                    f"brokered HTTPS fetch verified {provenance.size_bytes} bytes with sha256="
                    f"{provenance.sha256}"
                    if passed
                    else "brokered fetch returned empty or inconsistent provenance"
                ),
            )

    # 4. Taskpack cardinality, sealed integrity, and unique task identity
    packs_ok = True
    packs_detail_parts: list[str] = []
    task_ids: list[str] = []
    sealed_valid = True
    sealed_detail_parts: list[str] = []
    if v2_dynamic:
        builtin_root_path = builtin_python_root()
        anchor_manifests = sorted(builtin_root_path.glob("*/manifest.json"))
        anchor_ready = len(anchor_manifests) == 12
        _check(
            "taskpacks_present",
            anchor_ready,
            (
                f"{len(anchor_manifests)} built-in anchor pack(s) available for dynamic cold start"
                if anchor_ready
                else "expected 12 built-in anchor packs for cold start"
            ),
        )
        validation_files = sorted(builtin_root_path.glob("*.validation.json"))
        sealed_ok = anchor_ready and len(validation_files) == 12
        _check(
            "taskpacks_sealed_integrity",
            sealed_ok,
            (
                f"{len(validation_files)} sealed anchor validation file(s)"
                if sealed_ok
                else "anchor validation evidence is incomplete"
            ),
        )
        try:
            from aegis.cycle_ports import run_v2_cycle as _v2_run  # noqa: F401
            from aegis.dynamic_tasks import GenesisSeeder, TaskForge  # noqa: F401

            wiring_ok = callable(_v2_run)
        except Exception as exc:
            wiring_ok = False
            wiring_detail = f"cycle wiring import failed: {type(exc).__name__}: {exc}"
        else:
            wiring_detail = (
                "dynamic cold-start and cycle wiring importable; "
                "live anchor validation runs at cold start"
            )
        _check("taskpacks_live_validated", wiring_ok, wiring_detail)
        packs_ok = anchor_ready
        sealed_valid = sealed_ok
    elif not config.task_pack_paths:
        packs_ok = False
        packs_detail_parts.append("no task packs configured")
    else:
        unique_paths = set(config.task_pack_paths)
        if len(config.task_pack_paths) != 12:
            packs_ok = False
            packs_detail_parts.append(
                f"expected exactly 12 packs, got {len(config.task_pack_paths)}"
            )
        if len(unique_paths) != len(config.task_pack_paths):
            packs_ok = False
            packs_detail_parts.append("duplicate task pack paths")
        missing = [p for p in config.task_pack_paths if not Path(p).exists()]
        if missing:
            packs_ok = False
            packs_detail_parts.append(f"{len(missing)} missing pack(s)")
        packs_detail_parts.append(f"{len(config.task_pack_paths)} pack(s) configured")
        if packs_ok:
            for path in config.task_pack_paths:
                try:
                    pack, _sealed = _load_validated_pack(path)
                    task_ids.append(pack.manifest.task_id)
                except (ValueError, OSError) as exc:
                    sealed_valid = False
                    sealed_detail_parts.append(f"sealed validation failed: {path}: {exc}")
            if task_ids:
                duplicates = [tid for tid in task_ids if task_ids.count(tid) > 1]
                if duplicates:
                    sealed_valid = False
                    sealed_detail_parts.append(
                        f"duplicate task identities: {', '.join(sorted(set(duplicates)))}"
                    )
                else:
                    sealed_detail_parts.append(f"{len(task_ids)} unique task identities verified")
    if not v2_dynamic:
        _check("taskpacks_present", packs_ok, "; ".join(packs_detail_parts))
        _check("taskpacks_sealed_integrity", packs_ok and sealed_valid, "; ".join(
            sealed_detail_parts if sealed_detail_parts else ["skipped: packs not present"]
        ))
    if not v2_dynamic and doctor_passed and packs_ok and sealed_valid:
        try:
            live_packs = _validate_packs(
                config.task_pack_paths,
                sandbox,
                campaign_id=f"{campaign_id}-preflight",
            )
        except (ValueError, RuntimeError, OSError) as exc:
            _check("taskpacks_live_validated", False, f"live validation failed: {exc}")
        else:
            _check(
                "taskpacks_live_validated",
                len(live_packs) == 12,
                f"{len(live_packs)} task packs passed live sealed validation",
            )
    elif not v2_dynamic:
        _check(
            "taskpacks_live_validated",
            False,
            "skipped because sandbox doctor or sealed task-pack integrity failed",
        )

    # 5. PDF runtime wiring
    pdf_wired = True
    pdf_detail = "SandboxPDFExtractor available via CampaignController"
    # In production wiring, the controller creates SandboxPDFExtractor(owned).
    # We verify the owned backend is the real one (not fake) and the class is importable.
    if config.sandbox_backend == "fake":
        pdf_wired = False
        pdf_detail = "fake sandbox backend; SandboxPDFExtractor requires real network-isolated backend"
    _check("pdf_runtime_wiring", pdf_wired, pdf_detail)

    # 6. Evolution workspace / registry / canary wiring
    evo_wired = True
    evo_detail_parts: list[str] = []
    root = _data_dir()
    evo_db = root / "evolution.sqlite3"
    try:
        with EvolutionRegistry(evo_db):
            pass
    except (ValueError, RuntimeError, OSError) as exc:
        evo_wired = False
        evo_detail_parts.append(f"evolution registry integrity failed: {exc}")
    else:
        evo_detail_parts.append("evolution registry initialized and integrity-checked")
    try:
        with SkillRegistry(root / "skills.sqlite3"):
            pass
        with KnowledgeStore(root / "knowledge.sqlite3"):
            pass
    except (ValueError, RuntimeError, OSError) as exc:
        evo_wired = False
        evo_detail_parts.append(f"knowledge or Skill registry integrity failed: {exc}")
    else:
        evo_detail_parts.append("knowledge and Skill registries initialized and integrity-checked")
    repo_root = Path(__file__).resolve().parents[2]
    evolution_workspace = EvolutionWorkspace(repo_root)
    try:
        held_out_passed, held_out_detail = _held_out_context_check(evolution_workspace)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        held_out_passed = False
        held_out_detail = f"held-out context check failed closed: {type(exc).__name__}: {exc}"
    _check("evolution_held_out_assets_excluded", held_out_passed, held_out_detail)
    evo_init = repo_root / "src" / "aegis" / "evolvable" / "__init__.py"
    if not evo_init.exists():
        evo_wired = False
        evo_detail_parts.append("evolvable/__init__.py missing")
    else:
        evo_detail_parts.append("evolvable module present")
    _check("evolution_infrastructure", evo_wired, "; ".join(evo_detail_parts))

    evolution_runtime_passed = False
    if not doctor_passed or config.sandbox_backend == "fake":
        reason = (
            "requires a passing real WSL/Podman sandbox doctor"
            if config.sandbox_backend != "fake"
            else "requires the real WSL/Podman sandbox backend"
        )
        for name in (
            "evolution_workspace_access_live",
            "evolution_host_integrity",
            "evolution_sandbox_cleanup",
        ):
            _check(name, False, reason)
    else:
        probe_checks = _probe_evolution_workspace(sandbox, evolution_workspace)
        checks.extend(probe_checks)
        evolution_runtime_passed = all(item["passed"] for item in probe_checks)

    # 7. Automatic evolution promotion production wiring
    auto_evolution = evo_wired and packs_ok and sealed_valid and evolution_runtime_passed
    _check(
        "auto_evolution_promotion",
        auto_evolution,
        (
            "durable collection, validation, paired scheduler, funnel, and CAS promotion are wired"
            if auto_evolution
            else "automatic evolution promotion prerequisites are incomplete"
        ),
    )

    # 8. Automatic declarative Skill v1 promotion wiring
    auto_skill = packs_ok and sealed_valid and all(
        callable(getattr(SkillRegistry, name, None))
        for name in (
            "pending_validated",
            "record_static_evidence",
            "record_evaluation_report",
            "record_funnel_report",
            "promote_evaluated",
            "sandbox_package_by_artifact_id",
        )
    )
    _check(
        "auto_skill_promotion",
        auto_skill,
        (
            "declarative Skill v1 static validation, durable paired scheduler, CAS promotion, "
            "and sandbox-only active-path staging are wired"
            if auto_skill
            else "automatic Skill v1 promotion prerequisites are incomplete"
        ),
    )

    overall_passed = all(c["passed"] for c in checks)
    return {
        "campaign_id": campaign_id,
        "passed": overall_passed,
        "checks": checks,
    }


def _run_local_evolution_acceptance(
    backend: SandboxBackend | None = None,
    workspace: EvolutionWorkspace | None = None,
) -> dict[str, Any]:
    active_backend = WslSandboxBackend() if backend is None else backend
    active_workspace = (
        EvolutionWorkspace(Path(__file__).resolve().parents[2])
        if workspace is None
        else workspace
    )
    baseline = active_workspace.create_snapshot()
    held_out_passed, held_out_detail = _held_out_context_check(active_workspace)
    try:
        candidate_files = dict(active_workspace._candidate_files(baseline.archive))
        for path in active_workspace.policy.required_effective_paths:
            content = candidate_files.get(path)
            if content is None:
                raise RuntimeError(f"local acceptance baseline lacks effective path: {path}")
            candidate_files[path] = content + b"\n# AEGIS local acceptance candidate\n"
        candidate_archive = active_workspace._archive(candidate_files)
        candidate = active_workspace.candidate_from_archive(baseline, candidate_archive)
        validation = EvolutionValidator(
            active_backend,
            policy=active_workspace.policy,
        ).validate(candidate, validation_id="local-accept")
        tamper_policy = replace(
            active_workspace.policy,
            validation_commands=(
                ValidationCommand(
                    (
                        "python",
                        "-B",
                        "-I",
                        "-c",
                        (
                            "from pathlib import Path; "
                            "Path('src/aegis/orchestrator.py').write_bytes(b'tampered')"
                        ),
                    ),
                    timeout_seconds=30.0,
                ),
            ),
        )
        tamper_workspace = EvolutionWorkspace(active_workspace.root, tamper_policy)
        tamper_baseline = tamper_workspace.create_snapshot()
        if tamper_baseline.archive_sha256 != baseline.archive_sha256:
            raise RuntimeError("tamper probe baseline drifted from acceptance baseline")
        tamper_candidate = tamper_workspace.candidate_from_archive(
            tamper_baseline,
            candidate_archive,
        )
        tamper_validation = EvolutionValidator(
            active_backend,
            policy=tamper_policy,
        ).validate(tamper_candidate, validation_id="tamper-denied")
        protected_write_rejected = (
            not tamper_validation.passed
            and tamper_validation.failure_reason == "nonzero-exit"
        )
        canary = EvolutionCanary(active_backend).run_candidate(
            candidate,
            role=Role.WARRIOR,
            context={"schema_version": 1, "purpose": "local-autonomy-acceptance"},
            run_id="local-accept",
        )
        current = active_workspace.create_snapshot()
    except Exception as exc:
        return {
            "passed": False,
            "baseline_archive_sha256": baseline.archive_sha256,
            "error": f"{type(exc).__name__}: {exc}",
        }
    host_unchanged = current.archive_sha256 == baseline.archive_sha256
    passed = (
        validation.passed
        and protected_write_rejected
        and canary.passed
        and host_unchanged
        and held_out_passed
    )
    return {
        "passed": passed,
        "baseline_archive_sha256": baseline.archive_sha256,
        "candidate_artifact_id": candidate.artifact_id,
        "held_out_assets": {"excluded": held_out_passed, "detail": held_out_detail},
        "validation": {
            "passed": validation.passed,
            "evidence_id": validation.evidence_id,
            "failure_reason": validation.failure_reason,
            "workspace_mutated": validation.workspace_mutated,
            "commands": len(validation.commands),
            "exit_codes": [item.exit_code for item in validation.commands],
        },
        "protected_write_probe": {
            "rejected": protected_write_rejected,
            "evidence_id": tamper_validation.evidence_id,
            "failure_reason": tamper_validation.failure_reason,
        },
        "canary": {
            "passed": canary.passed,
            "result_id": canary.result_id,
            "workflow_sha256": (
                None
                if canary.workflow is None
                else hashlib.sha256(
                    json.dumps(
                        canary.workflow.to_dict(),
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest()
            ),
        },
        "host_unchanged": host_unchanged,
    }


def main(argv: Sequence[str] | None = None) -> int:
    global _DATA_DIR_OVERRIDE
    args = build_parser().parse_args(argv)
    _DATA_DIR_OVERRIDE = args.data_dir.expanduser().resolve() if args.data_dir is not None else None
    try:
        if args.command == "sandbox-bootstrap":
            from aegis.sandbox.bootstrap import BootstrapSpec, apply_plan, installation_plan

            spec = BootstrapSpec(image=args.image)
            if args.apply:
                if args.root is None:
                    raise ValueError("--apply requires --root")
                _print(
                    {
                        "mode": "applied",
                        "files": [str(path) for path in apply_plan(spec, args.root.resolve())],
                    }
                )
            else:
                _print(installation_plan(spec))
        elif args.command == "campaign-create":
            config = CampaignConfig.load(args.config)
            if config.acceptance_profile is not None and args.data_dir is None:
                raise ValueError("acceptance-profile campaigns require an explicit isolated --data-dir")
            target = _config_path(config.campaign_id)
            if target.exists():
                raise FileExistsError(f"campaign already exists: {config.campaign_id}")
            store = _store()
            try:
                if any(
                    event.event_type == "campaign_created"
                    for event in store.read(config.campaign_id, limit=1_000)
                ):
                    raise FileExistsError(f"campaign already exists: {config.campaign_id}")
                config.dump(target)
                store.append(config.campaign_id, "campaign_created", {"config": config.to_dict()})
                StrategyRegistry(store, config.campaign_id).initialize_defaults()
            finally:
                store.close()
            _print({"campaign_id": config.campaign_id, "config": str(target)})
        elif args.command == "doctor":
            doctor_report = WslSandboxBackend().doctor()
            _print(
                {
                    "passed": doctor_report.passed,
                    "checks": [
                        {"name": c.name, "passed": c.passed, "detail": c.detail} for c in doctor_report.checks
                    ],
                }
            )
            return 0 if doctor_report.passed else 2
        elif args.command == "start":
            config = _load(args.campaign_id)
            if config.test_mode or config.sandbox_backend == "fake":
                raise RuntimeError("CLI start refuses test-mode or fake-sandbox campaigns")
            preflight_report = _run_autonomy_preflight(args.campaign_id)
            if not preflight_report["passed"]:
                failed = [item["name"] for item in preflight_report["checks"] if not item["passed"]]
                raise RuntimeError(f"full-autonomy preflight failed: {', '.join(failed)}")
            controller = _controller(args.campaign_id)
            try:
                _print(controller.start())
            finally:
                controller.close()
        elif args.command == "resume":
            preflight_report = _run_autonomy_preflight(args.campaign_id)
            if not preflight_report["passed"]:
                failed = [item["name"] for item in preflight_report["checks"] if not item["passed"]]
                raise RuntimeError(f"full-autonomy preflight failed: {', '.join(failed)}")
            controller = _controller(args.campaign_id)
            try:
                _print(controller.resume())
            finally:
                controller.close()
        elif args.command == "retry":
            preflight_report = _run_autonomy_preflight(args.campaign_id)
            if not preflight_report["passed"]:
                failed = [item["name"] for item in preflight_report["checks"] if not item["passed"]]
                raise RuntimeError(f"full-autonomy preflight failed: {', '.join(failed)}")
            store = _store()
            try:
                prepare_retryable_failure(args.campaign_id, store, after_fix=args.after_fix)
            finally:
                store.close()
            controller = _controller(args.campaign_id)
            try:
                _print(controller.resume())
            finally:
                controller.close()
        elif args.command in {"pause", "stop", "kill"}:
            _print(_apply_control(args.campaign_id, args.command))
        elif args.command == "status":
            config = _load(args.campaign_id)
            store = _store()
            try:
                campaign_report = build_report(store, config.campaign_id)
            finally:
                store.close()
            _print(
                {
                    key: campaign_report[key]
                    for key in ("campaign_id", "state", "rounds_completed", "tokens_used", "requests_used")
                }
            )
        elif args.command == "report":
            destination = args.output or (
                _data_dir() / "reports" / f"{args.campaign_id}.{'json' if args.format == 'json' else 'md'}"
            )
            store = _store()
            try:
                write_report(store, args.campaign_id, destination, format=args.format)
            finally:
                store.close()
            _print({"campaign_id": args.campaign_id, "report": str(destination)})
        elif args.command == "replay":
            store = _store()
            try:
                _print(replay_events(store, args.campaign_id))
            finally:
                store.close()
        elif args.command == "strategy-history":
            store = _store()
            try:
                history = [
                    e
                    for e in replay_events(store, args.campaign_id)
                    if e["event_type"].startswith("strategy_")
                ]
            finally:
                store.close()
            _print(history)
        elif args.command == "knowledge-search":
            knowledge = _knowledge()
            try:
                role = Role(args.role) if args.role else None
                artifacts = knowledge.query(args.query, role=role, limit=args.limit)
                _print(
                    [
                        {
                            "artifact_id": item.artifact_id,
                            "source_url": item.source_url,
                            "sha256": item.sha256,
                            "media_type": item.media_type,
                            "summary": item.summary,
                            "tags": list(item.tags),
                            "applicable_roles": [value.value for value in item.applicable_roles],
                            "experiment_result": item.experiment_result,
                            "failure_reason": item.failure_reason,
                            "created_at": item.created_at.isoformat(),
                        }
                        for item in artifacts
                    ]
                )
            finally:
                knowledge.close()
        elif args.command == "autonomy-preflight":
            preflight_report = _run_autonomy_preflight(args.campaign_id)
            _print(preflight_report)
            return 0 if preflight_report["passed"] else 2
        elif args.command == "autonomy-local-acceptance":
            acceptance = _run_local_evolution_acceptance()
            _print(acceptance)
            return 0 if acceptance["passed"] else 2
        elif args.command == "autonomy-smoke-verify":
            config = _load(args.campaign_id)
            store = _store()
            try:
                events = replay_events(store, args.campaign_id)
            finally:
                store.close()
            with EvolutionRegistry(_data_dir() / "evolution.sqlite3") as registry:
                acceptance = verify_autonomy_campaign(config, events, registry)
            _print(acceptance)
            return 0 if acceptance["passed"] else 2
        elif args.command == "evolution-cycle":
            plan = _evolution_cycle(args)
            if args.run:
                _print(
                    {
                        "plan": plan,
                        "cycle": _run_v2_cycle_cli(
                            _load(args.campaign_id), _data_dir(), repair=args.repair
                        ),
                    }
                )
            else:
                _print(plan)
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"error: {exc}", file=__import__("sys").stderr)
        return 2
    return 0
