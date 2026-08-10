"""Zero-dependency command line interface for the AEGIS v2 evolution system."""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence, cast

from aegis.agent_runtime import ACTION_SCHEMA, Action, ActionError, RuntimeLimits
from aegis.artifacts import ContentAddressedArtifactStore
from aegis.autonomy_budget import (
    AUTONOMY_MIN_AGENT_STEPS,
    AUTONOMY_ROLE_SHARES,
    autonomy_v2_budget_check,
)
from aegis.config import CampaignConfig
from aegis.curriculum import CurriculumRegistry
from aegis.cycle_ports import _git_head, run_v2_cycle
from aegis.dynamic_tasks import (
    DynamicTaskOrigin,
    DynamicTaskRegistry,
    GenesisSeeder,
    TaskForge,
)
from aegis.event_store import EventStore
from aegis.gateway.client import GatewayConfig, ModelGateway
from aegis.gateway.types import GatewayRequest, Message
from aegis.knowledge import KnowledgeStore
from aegis.models import Role, canonical_json, thaw_json
from aegis.publishing import GitPublisher
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
from aegis.sandbox.wsl import WslSandboxBackend
from aegis.taskpacks import SandboxTaskPackRunner
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
    if (
        len(created) != 1
        or not isinstance(created[0], Mapping)
        or not isinstance(created[0].get("config"), Mapping)
    ):
        raise RuntimeError("campaign configuration binding is missing or ambiguous")
    bound = CampaignConfig.from_mapping(thaw_json(created[0]["config"]))
    if canonical_json(bound.to_dict()) != canonical_json(config.to_dict()):
        raise RuntimeError("campaign configuration differs from its immutable creation snapshot")
    return config


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


def _print(value: object) -> None:
    print(
        json.dumps(
            value,
            indent=2,
            ensure_ascii=False,
            default=lambda item: asdict(cast(Any, item)) if is_dataclass(item) else str(item),
        )
    )


def _next_v2_generation(registry: DynamicTaskRegistry) -> int:
    records = registry.records()
    if not records:
        return 2
    latest = max(record.creator_generation for record in records)
    return max(2, latest + 1)


def _require_healthy_sandbox(sandbox: SandboxBackend) -> None:
    doctor_report = sandbox.doctor()
    if not doctor_report.passed:
        raise RuntimeError(
            "sandbox doctor failed: "
            + "; ".join(
                f"{check.name}: {check.detail}"
                for check in doctor_report.checks
                if not check.passed
            )
        )


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
            _require_healthy_sandbox(sandbox)
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
    dynamic = DynamicTaskRegistry(root / "dynamic_tasks.sqlite3")
    try:
        sandbox: SandboxBackend = (
            FakeSandboxBackend() if config.sandbox_backend == "fake" else WslSandboxBackend()
        )
        _require_healthy_sandbox(sandbox)
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
            skills=None,
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
        store.close()


def _campaign_events(campaign_id: str) -> list[Any]:
    store = _store()
    try:
        return list(store.read(campaign_id))
    finally:
        store.close()


def _event_payload(event: Any) -> Mapping[str, Any]:
    payload = event.payload
    if not isinstance(payload, Mapping):
        return {}
    return cast(Mapping[str, Any], thaw_json(payload))


def _v2_status(campaign_id: str) -> Mapping[str, Any]:
    events = _campaign_events(campaign_id)
    cycle_states = [e for e in events if e.event_type == "cycle_state_changed_v2"]
    snapshots = [e for e in events if e.event_type == "curriculum_snapshot_recorded_v2"]
    summaries = [e for e in events if e.event_type.startswith("cycle-summary-")]
    repaired = [e for e in events if e.event_type == "cycle_failed_recovery_started"]
    latest_state = (
        _event_payload(cycle_states[-1]).get("state")
        if cycle_states
        else None
    )
    latest_cycle = (
        _event_payload(snapshots[-1]).get("snapshot", {}).get("cycle_number")
        if snapshots
        else None
    )
    return {
        "campaign_id": campaign_id,
        "state": latest_state,
        "cycle_number": latest_cycle,
        "cycle_summaries": len(summaries),
        "recovery_incidents": len(repaired),
        "event_count": len(events),
    }


def _v2_report(campaign_id: str) -> Mapping[str, Any]:
    events = _campaign_events(campaign_id)
    grouped: dict[str, int] = {}
    for event in events:
        grouped[event.event_type] = grouped.get(event.event_type, 0) + 1
    return {
        "campaign_id": campaign_id,
        "status": _v2_status(campaign_id),
        "event_type_counts": dict(sorted(grouped.items())),
    }


def _v2_replay(campaign_id: str) -> list[Mapping[str, Any]]:
    events = _campaign_events(campaign_id)
    return [
        {
            "sequence": event.sequence,
            "event_type": event.event_type,
            "payload": _event_payload(event),
            "created_at": str(event.created_at),
        }
        for event in events
    ]


def _run_autonomy_preflight(campaign_id: str) -> dict[str, Any]:
    """Fail-closed v2 preflight: report every gate required before a dynamic cycle."""
    checks: list[dict[str, Any]] = []
    config = _load(campaign_id)

    def _check(name: str, passed: bool, detail: str) -> None:
        checks.append({"name": name, "passed": passed, "detail": detail})

    if config.autonomy_v2 is None or not config.autonomy_v2.enabled:
        _check("autonomy_v2_enabled", False, "campaign must enable autonomy_v2")
        return {"campaign_id": campaign_id, "passed": False, "checks": checks}

    doctor_passed = False
    sandbox: SandboxBackend = (
        FakeSandboxBackend() if config.sandbox_backend == "fake" else WslSandboxBackend()
    )
    try:
        doctor_report = sandbox.doctor()
        doctor_passed = doctor_report.passed
        _check(
            "sandbox_doctor",
            doctor_report.passed,
            "; ".join(
                f"{c.name}: {'ok' if c.passed else c.detail}" for c in doctor_report.checks
            ),
        )
    except Exception as exc:
        _check("sandbox_doctor", False, f"doctor raised: {exc}")
    _check(
        "real_backend",
        config.sandbox_backend != "fake",
        f"sandbox_backend={config.sandbox_backend}",
    )
    _check("test_mode_off", not config.test_mode, f"test_mode={config.test_mode}")
    _check("demo_mode_off", not config.demo_mode, f"demo_mode={config.demo_mode}")

    budget = autonomy_v2_budget_check(
        total_tokens=config.total_tokens,
        max_requests=config.max_requests,
        role_shares={role: cfg.budget_share for role, cfg in config.roles.items()},
        max_output_tokens={role: cfg.max_output_tokens for role, cfg in config.roles.items()},
    )
    shares_match = all(
        config.roles[role].budget_share == share
        for role, share in AUTONOMY_ROLE_SHARES.items()
    )
    _check(
        "autonomy_smoke_budget_reachable",
        (
            config.max_agent_steps >= AUTONOMY_MIN_AGENT_STEPS
            and shares_match
            and config.wall_time_seconds >= 28_800
            and budget.passed
        ),
        (
            f"minimum_requests={budget.minimum_requests}, "
            f"global_tokens_required={budget.global_tokens_required}, "
            f"failures={list(budget.failures)}"
        ),
    )
    _check("research_enabled", config.research_enabled, f"research_enabled={config.research_enabled}")
    _check("online_research", not config.offline_research, f"offline_research={config.offline_research}")

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
            _check(
                "gateway_live_probe",
                passed,
                (
                    f"model responded with verified usage: input={usage.input_tokens}, "
                    f"output={usage.output_tokens}, protocol={probe.protocol}"
                    if passed
                    else "live model probe did not return the exact verified action"
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
                    f"brokered HTTPS fetch verified {provenance.size_bytes} bytes with sha256={provenance.sha256}"
                    if passed
                    else "brokered fetch returned empty or inconsistent provenance"
                ),
            )

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
        from aegis.dynamic_tasks import GenesisSeeder as _Seeder  # noqa: F401
        from aegis.dynamic_tasks import TaskForge as _Forge  # noqa: F401

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

    pdf_wired = config.sandbox_backend != "fake"
    _check(
        "pdf_runtime_wiring",
        pdf_wired,
        "SandboxPDFExtractor available via the v2 cycle runtime"
        if pdf_wired
        else "fake sandbox backend; SandboxPDFExtractor requires real network-isolated backend",
    )
    try:
        registry = DynamicTaskRegistry(_data_dir() / "dynamic_tasks.sqlite3")
        registry.close()
        bank_ok = True
        bank_detail = "dynamic task bank initialized and integrity-checked"
    except Exception as exc:
        bank_ok = False
        bank_detail = f"dynamic task bank failed: {type(exc).__name__}: {exc}"
    _check("dynamic_task_bank_ready", bank_ok, bank_detail)
    _check(
        "v2_role_evolution_wiring",
        callable(RoleRegistry) and callable(CurriculumRegistry),
        "RoleRegistry and CurriculumRegistry wiring importable",
    )
    _check(
        "evolution_cycle_wiring",
        wiring_ok and doctor_passed,
        "evolution-cycle command and real sandbox doctor are ready",
    )
    overall_passed = all(c["passed"] for c in checks)
    return {"campaign_id": campaign_id, "passed": overall_passed, "checks": checks}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegis", description="AEGIS v2 autonomous evolution")
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
    for name in ("status", "replay"):
        command = sub.add_parser(name)
        command.add_argument("campaign_id")
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
        help="fail-closed report on whether a dynamic v2 campaign may start",
    )
    preflight.add_argument("campaign_id")
    cycle = sub.add_parser(
        "evolution-cycle",
        help="cold-start and run dynamic v2 cycles; --dry-run never validates or mutates",
    )
    cycle.add_argument("campaign_id")
    cycle.add_argument("--dry-run", action="store_true")
    cycle.add_argument(
        "--no-seed-anchors",
        action="store_true",
        help="do not register built-in anchor tasks into an empty dynamic task bank",
    )
    cycle.add_argument("--cohort-limit", type=int)
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
    return parser


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
            finally:
                store.close()
            _print({"campaign_id": config.campaign_id, "config": str(target)})
        elif args.command == "doctor":
            doctor_report = WslSandboxBackend().doctor()
            _print(
                {
                    "passed": doctor_report.passed,
                    "checks": [
                        {"name": c.name, "passed": c.passed, "detail": c.detail}
                        for c in doctor_report.checks
                    ],
                }
            )
            return 0 if doctor_report.passed else 2
        elif args.command == "status":
            _print(_v2_status(args.campaign_id))
        elif args.command == "report":
            destination = args.output or (
                _data_dir() / "reports" / f"{args.campaign_id}.{'json' if args.format == 'json' else 'md'}"
            )
            report = _v2_report(args.campaign_id)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if args.format == "markdown":
                lines = [
                    f"# AEGIS v2 report: {report['campaign_id']}",
                    "",
                    f"- state: {report['status']['state']}",
                    f"- cycle_number: {report['status']['cycle_number']}",
                    f"- cycle_summaries: {report['status']['cycle_summaries']}",
                    f"- recovery_incidents: {report['status']['recovery_incidents']}",
                    f"- events: {report['status']['event_count']}",
                    "",
                    "## Event type counts",
                    "",
                ]
                lines.extend(f"- {key}: {value}" for key, value in report["event_type_counts"].items())
                destination.write_text("\n".join(lines) + "\n", encoding="utf-8")
            else:
                destination.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            _print({"campaign_id": args.campaign_id, "report": str(destination)})
        elif args.command == "replay":
            _print(_v2_replay(args.campaign_id))
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


if __name__ == "__main__":
    raise SystemExit(main())
