"""In-distro standard cycle executor for the WSL-first evolution runtime.

This module is the trusted-default wiring used by the champion entrypoint
(``aegis.evolution.cycle_entrypoint.run_cycle``) when a production cycle runs
inside the dedicated distribution.  It mirrors the host CLI construction but:

- the campaign data root lives on the campaign volume under
  ``/var/lib/aegis/campaigns/<key>/data`` and is validated against that prefix;
- the sandbox backend invokes the fixed ``aegis-sandbox-agent`` directly
  instead of through ``wsl.exe``;
- harness operations go through the fixed ``aegis-harness-agent`` locally;
- the model gateway talks to the loopback credential sidecar (``AEGIS_OPENAI_*``
  env is supplied by the trusted supervisor pointing at the sidecar — relay
  credentials never enter champion code).

The champion tree may evolve how a cycle is run (this file ships inside the
champion worktree), but the frozen-path byte comparison against the pinned
source ref plus the supervisor/sidecar trust anchors bound what that authority
can reach.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping

from aegis.artifacts import ContentAddressedArtifactStore
from aegis.config import CampaignConfig
from aegis.curriculum import CurriculumRegistry
from aegis.cycle_ports import run_v2_cycle
from aegis.dynamic_tasks import DynamicTaskRegistry, TaskForge
from aegis.event_store import EventStore
from aegis.evolution.harness_backend import LocalHarnessBackend
from aegis.evolution.registry import EvolutionRegistry
from aegis.gateway.client import GatewayConfig, ModelGateway
from aegis.knowledge import KnowledgeStore
from aegis.agent_runtime import RuntimeLimits
from aegis.models import Role
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
from aegis.sandbox.wsl import LocalAgentSandboxBackend
from aegis.taskpacks import SandboxTaskPackRunner

CAMPAIGNS_ROOT = Path("/var/lib/aegis/campaigns")
_CYCLE_RESULT_LIMIT = 240_000


class WslCycleRuntimeError(RuntimeError):
    pass


def _validated_data_root(data_root: object) -> Path:
    if not isinstance(data_root, str) or not data_root:
        raise WslCycleRuntimeError("data_root must be non-empty text")
    root = Path(data_root)
    if not root.is_absolute() or ".." in root.parts:
        raise WslCycleRuntimeError("data_root must be an absolute traversal-free path")
    resolved = root.resolve()
    campaigns = CAMPAIGNS_ROOT.resolve()
    if campaigns not in resolved.parents:
        raise WslCycleRuntimeError("data_root must live under the campaign volume")
    return resolved


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


def _require_healthy_sandbox(sandbox: LocalAgentSandboxBackend) -> None:
    report = sandbox.doctor()
    if not report.passed:
        raise WslCycleRuntimeError(
            "sandbox doctor failed: "
            + "; ".join(
                f"{check.name}: {check.detail}" for check in report.checks if not check.passed
            )
        )


def execute_standard_cycle(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    """Run one full v2 cycle in-distro and return a bounded result mapping."""
    if payload.get("action") != "evolution_cycle":
        raise WslCycleRuntimeError("unsupported cycle action")
    campaign_id = payload.get("campaign_id")
    if not isinstance(campaign_id, str) or not campaign_id or len(campaign_id) > 512:
        raise WslCycleRuntimeError("campaign_id is missing or invalid")
    generation = payload.get("generation")
    if generation is not None and (
        isinstance(generation, bool) or not isinstance(generation, int) or generation < 1
    ):
        raise WslCycleRuntimeError("generation must be a positive integer when present")
    raw_config = payload.get("config")
    if not isinstance(raw_config, Mapping):
        raise WslCycleRuntimeError("campaign config snapshot is missing")
    config = CampaignConfig.from_mapping(dict(raw_config))
    if config.campaign_id != campaign_id:
        raise WslCycleRuntimeError("config campaign identity does not match the launch")
    if config.test_mode:
        raise WslCycleRuntimeError("test-mode campaigns run on the host path, not in-distro")
    data_root = _validated_data_root(payload.get("data_root"))
    source_commit = payload.get("source_commit")
    if not isinstance(source_commit, str) or len(source_commit) < 40:
        raise WslCycleRuntimeError("source_commit must be a full Git commit id")
    data_root.mkdir(mode=0o700, parents=True, exist_ok=True)

    autonomy = config.autonomy_v2
    store = EventStore(data_root / "events.sqlite3")
    knowledge = KnowledgeStore(data_root / "knowledge.sqlite3")
    skills = None
    dynamic: DynamicTaskRegistry | None = None
    try:
        from aegis.skill_registry import SkillRegistry

        skills = SkillRegistry(data_root / "skills.sqlite3")
        dynamic = DynamicTaskRegistry(data_root / "dynamic_tasks.sqlite3")
        sandbox = LocalAgentSandboxBackend()
        _require_healthy_sandbox(sandbox)
        curriculum = CurriculumRegistry(store, config.campaign_id)
        roles = RoleRegistry(store, config.campaign_id)
        evolution = EvolutionRegistry(store, config.campaign_id)
        from aegis.evolution.population import PopulationArchive

        population = PopulationArchive(store, config.campaign_id)
        artifacts = ContentAddressedArtifactStore(data_root / "artifacts")
        runner = SandboxTaskPackRunner(sandbox, id_namespace=config.campaign_id)
        forge = TaskForge(dynamic)
        gateway = ModelGateway(GatewayConfig.from_env())
        environment_builder = None
        if (
            autonomy is not None
            and "environment" in autonomy.evolution_surfaces
            and autonomy.environment_output_repository is not None
        ):
            from aegis.evolution.env_builder import build_wsl_environment_builder

            environment_builder = build_wsl_environment_builder(
                sandbox=sandbox,
                research=_research(config),
                artifacts=artifacts,
                output_repository=autonomy.environment_output_repository,
                builder_identity_sha256=hashlib.sha256(
                    "aegis-env-builder-v2".encode("utf-8")
                ).hexdigest(),
            )
        harness_backend = None
        if autonomy is not None and autonomy.harness_evolution_enabled:
            harness_backend = LocalHarnessBackend()
        from aegis.mcp import McpBridge

        mcp_bridge = McpBridge()
        harness_role_paths: dict[str, tuple[str, ...]] = {"warrior": ("warrior",)}
        if autonomy is not None and autonomy.public_repo_url is not None:
            from aegis.evolution.surfaces import HARNESS_ALLOWED_ROOTS

            harness_role_paths["warrior"] = (
                "warrior",
                *HARNESS_ALLOWED_ROOTS,
            )
        result = run_v2_cycle(
            gateway=gateway,
            sandbox=sandbox,
            research=_research(config),
            knowledge=knowledge,
            skills=skills,
            pdf_extractor=SandboxPDFExtractor(sandbox),
            role_configs=dict(config.roles),
            limits=RuntimeLimits(max_steps=config.max_agent_steps),
            artifacts=artifacts,
            dynamic=dynamic,
            forge=forge,
            runner=runner,
            curriculum=curriculum,
            roles=roles,
            data_dir=data_root,
            campaign_id=config.campaign_id,
            holdout_delay=(
                autonomy.task_holdout_delay_cycles if autonomy is not None else 1
            ),
            public_repo_url=autonomy.public_repo_url if autonomy is not None else None,
            source_commit=source_commit,
            repair_on_failure=True,
            event_store=store,
            repair_git_publisher=(
                GitPublisher(
                    autonomy.public_repo_url,
                    remote_id="aegis-public",
                    allowed_role_paths=harness_role_paths,
                )
                if autonomy is not None and autonomy.public_repo_url is not None
                else None
            ),
            evolution=evolution,
            population=population,
            meta_evolution_enabled=(
                autonomy.meta_evolution_enabled if autonomy is not None else False
            ),
            environment_builder=environment_builder,
            default_image=None,
            evaluate_candidates_enabled=True,
            candidate_max_extra_steps=(
                autonomy.candidate_max_extra_steps if autonomy is not None else 12
            ),
            evaluation_seed_count=(
                autonomy.evaluation_seed_count if autonomy is not None else 2
            ),
            candidate_probation_cycles=(
                autonomy.candidate_probation_cycles if autonomy is not None else 2
            ),
            campaign_config=config,
            harness_repo=None,
            harness_backend=harness_backend,
            harness_canary_command=(
                autonomy.harness_canary_command if autonomy is not None else None
            ),
            harness_activation_automatic=(
                autonomy.harness_activation_automatic if autonomy is not None else True
            ),
            mcp_bridge=mcp_bridge,
            subagent_max_steps=(
                autonomy.subagent_max_steps if autonomy is not None else 8
            ),
            subagent_timeout_seconds=(
                autonomy.subagent_timeout_seconds if autonomy is not None else 180.0
            ),
            subagent_max_concurrency=(
                autonomy.subagent_max_concurrency if autonomy is not None else 2
            ),
            subagent_max_result_bytes=(
                autonomy.subagent_max_result_bytes if autonomy is not None else 65_536
            ),
        )
        return _bounded_result(config.campaign_id, curriculum, result)
    finally:
        if skills is not None:
            skills.close()
        if dynamic is not None:
            dynamic.close()
        knowledge.close()
        store.close()


def _bounded_result(campaign_id: str, curriculum: Any, result: Any) -> Mapping[str, Any]:
    """Project the cycle outcome into the bounded JSON the supervisor relays."""
    if isinstance(result, Mapping) and result.get("maintenance_only"):
        return {"campaign_id": campaign_id, **dict(result)}
    if hasattr(result, "status"):
        repaired = {
            "campaign_id": campaign_id,
            "repaired": True,
            "incident_id": getattr(result, "incident_id", None),
            "repair_plan_id": getattr(result, "repair_plan_id", None),
            "status": result.status.value if hasattr(result.status, "value") else str(result.status),
            "completed_steps": [
                item.value if hasattr(item, "value") else str(item)
                for item in getattr(result, "completed_steps", ())
            ],
        }
        return repaired
    response: dict[str, Any] = {
        "campaign_id": campaign_id,
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
            if getattr(result, name, None) is not None
        },
        "runtime_identity": {
            "entrypoint": "aegis.evolution.cycle_entrypoint",
            "executed_commit": os.environ.get("AEGIS_EXECUTED_COMMIT"),
        },
    }
    extra = getattr(result, "cycle_result_extra", None)
    if isinstance(extra, Mapping):
        for key, value in extra.items():
            if key not in response:
                response[key] = value
    encoded = json.dumps(response, sort_keys=True)
    if len(encoded.encode("utf-8")) > _CYCLE_RESULT_LIMIT:
        raise WslCycleRuntimeError("cycle result exceeded the supervisor relay limit")
    return response
