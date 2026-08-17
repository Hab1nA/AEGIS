"""Model-backed and control-plane ports for the AEGIS v2 evolution cycle.

The three model roles (Warrior, Judge, Prosecutor) and the council run through
the existing ``RoleAgentRuntime`` boundary, so every model turn is bounded,
JSON-constrained, token-metered, and sandboxed.  Quality locking, forged-task
validation/registration, attribution summarisation, role-candidate
qualification, and activation-set commits stay on the trusted control plane
and only ever consume content-addressed evidence.
"""

from __future__ import annotations

import hashlib
import io
import json
import math
import secrets
import subprocess
import tarfile
import tempfile
import threading
from contextvars import ContextVar
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence, cast

from aegis.activation import (
    ActivationIntent,
    ActivationJournal,
    ActivationReconciler,
)
from aegis.agent_runtime import (
    FIXED_ROLE_MAX_STEPS,
    RoleAgentRuntime,
    RuntimeLimits,
    SandboxPluginExecutor,
    ToolDispatcher,
)
from aegis.artifacts import ArtifactRef, ContentAddressedArtifactStore
from aegis.attribution.candidate_gate import (
    CandidateGatePolicy,
    CandidateGateReport,
    SealedCandidateArm,
    SealedCandidatePair,
    evaluate_candidate_gate,
)
from aegis.attribution.evaluation import qualify_attribution
from aegis.attribution.models import (
    AttributionDisposition,
    AttributionReport,
    EvaluationArm,
    PairedObservation,
    QualificationPath,
    QualificationPolicy,
)
from aegis.attribution.models import (
    RoleGeneration as AttributionRoleGeneration,
)
from aegis.config import RoleConfig
from aegis.connectors import (
    GitCheckpointConnector,
    SqliteConnectorJournal,
    build_checkpoint_plugin,
    checkpoint_generation,
)
from aegis.council import (
    CouncilGenerationUsage,
    estimate_content_tokens,
    CouncilMessage,
    CouncilMessageType,
    CouncilOutcome,
    CouncilProposalKind,
    CouncilTranscript,
    EvidenceClaim,
    ObjectiveAmendment,
    ShadowObjectiveResult,
    SupportDecision,
    evaluate_objective_amendment,
)
from aegis.curriculum import (
    ActiveRoleSet,
    Constitution,
    CurriculumRegistry,
    CurriculumSnapshot,
    CycleState,
    ObjectiveStatus,
    ObjectiveSuccessCriterion,
    ObjectiveVersion,
    RoleVersionIdentity,
)
from aegis.cycle_recovery import patch_from_prosecutor_submission, repair_failed_cycle
from aegis.cycle_runtime import CyclePorts, EvolutionCycleController
from aegis.dynamic_tasks import (
    CohortMember,
    CohortTier,
    DynamicTaskCohort,
    DynamicTaskOrigin,
    DynamicTaskRegistry,
    DynamicTaskStatus,
    TaskForge,
)
from aegis.dynamic_tasks.builder import TaskPackBuilder, TaskSpec, TaskSpecError
from aegis.environments.runtime import EnvironmentBuilder
from aegis.event_store import EventStore
from aegis.evolution.arm_evaluation import (
    build_cohort_workspace,
    evaluate_frozen_workspace,
    freeze_workspace_bytes,
    stage_cohort_workspace,
)
from aegis.evolution.consumer import (
    consume_cycle_proposals,
    consume_rollback_orders,
)
from aegis.evolution.control_core import ControlCorePolicy
from aegis.evolution.harness import (
    HarnessCanaryRunner,
    HarnessEvolutionError,
    HarnessRepo,
    HarnessRollbackExecutor,
    RollbackOrder,
    changes_to_git_file_changes,
)
from aegis.evolution.harness_backend import HarnessBackend, HarnessBackendError
from aegis.evolution.population import (
    PopulationArchive,
    behavior_descriptor,
    behavior_roots,
)
from aegis.evolution.registry import (
    CandidateState,
    EvolutionRegistry,
    EvolutionRegistryError,
)
from aegis.evolution.runtime import (
    RuntimeBinding,
    _load_json_artifact,
    budget_policy_hash,
    build_composite_manifest,
    candidate_binding,
    candidate_environment_artifact_id,
    candidate_manifest,
    champion_binding_for_role,
    materialize_default_artifacts,
    model_profile_hash,
    resolve_role_binding,
    store_composite_manifest,
)
from aegis.evolution.sealed_evaluation import (
    CandidateEvaluationDesign,
    EvaluationTaskBinding,
    EvaluationTier,
    SealedArmEvidence,
)
from aegis.evolution.surfaces import (
    HARNESS_ALLOWED_ROOTS,
    EvolutionSurface,
    validate_environment_content,
)
from aegis.gateway.protocols import Role as GatewayRole
from aegis.gateway.types import TokenUsage
from aegis.judge import (
    EvidenceKind,
    FrozenSubmissionEvidence,
    JudgeCalibration,
    JudgeForecast,
    TaskFailureForecast,
    compute_calibration,
    estimate_message_tokens,
    sanitize_diagnostic_quality,
)
from aegis.mcp import (
    McpBridge,
    McpBridgeError,
    McpCandidate,
    McpCandidateStatus,
    McpRegistry,
    McpRiskLevel,
)
from aegis.models import JsonValue, Role, canonical_json, thaw_json
from aegis.objectives import (
    AdaptiveObjectiveVersion,
    AmendmentDecision,
    EvaluatorCriterion,
    HumanCoreObjective,
    ObjectiveGovernanceError,
    ObjectiveGovernanceRegistry,
)
from aegis.objectives import (
    ObjectiveAmendment as GovernanceObjectiveAmendment,
)
from aegis.objectives import (
    ObjectiveEvidence as GovernanceObjectiveEvidence,
)
from aegis.objectives import (
    ObjectiveStatus as GovernanceObjectiveStatus,
)
from aegis.plugins import (
    EffectClass,
    PluginManifest,
    PluginPolicy,
    ToolBroker,
)
from aegis.publishing import GitPublisher
from aegis.roles import RoleRegistry
from aegis.roles.generation import GenerationBundle, RoleGeneration
from aegis.runtime_ledger import (
    AccountingContext,
    RuntimeBudgetExceeded,
)
from aegis.runtime_ledger import (
    GatewayAttemptObserver as RuntimeGatewayAttemptObserver,
)
from aegis.runtime_policy import RuntimePolicyRegistry, RuntimeStageBoundary
from aegis.sandbox.backend import SandboxBackend
from aegis.subagents import SubagentLimits, SubagentManager
from aegis.taskpacks.builtin import builtin_python_root
from aegis.taskpacks.manifest import TaskPack, compute_tree_hash
from aegis.taskpacks.validation import TaskPackRunner, validate_taskpack

_FORBIDDEN_KEYS = frozenset(
    {
        "chain_of_thought",
        "private_reasoning",
        "hidden_tests",
        "hidden_expected",
        "credentials",
        "api_key",
        "access_token",
    }
)

_ACCOUNTING_CONTEXT: ContextVar[AccountingContext | None] = ContextVar(
    "aegis_runtime_accounting_context", default=None
)
_RUNTIME_STAGE_BOUNDARY: ContextVar[RuntimeStageBoundary | None] = ContextVar(
    "aegis_runtime_stage_boundary", default=None
)


def _gateway_accounting_context(_request: Any) -> AccountingContext:
    context = _ACCOUNTING_CONTEXT.get()
    if context is None:
        raise RuntimeError("gateway call has no runtime accounting context")
    return context
_MAX_STRING = 4096
_MAX_PROPOSALS = 16
_TASK_AUTHORING_ATTEMPTS = 2


def _generation_artifact_id(value: str) -> str:
    """Normalize a typed store artifact id to the generation-world contract.

    The content-addressed store emits typed addresses such as
    ``workflow-sha256:<digest>``, while ``RoleGeneration`` requires the raw
    ``sha256:<digest>`` form.  Raw ids pass through unchanged.
    """
    if not isinstance(value, str):
        raise ValueError("artifact id must be a string")
    prefix, separator, digest = value.rpartition("sha256:")
    if not separator or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("artifact id must be a sha256 content address")
    return "sha256:" + digest


def _strip_forbidden(value: Any, *, path: str = "evidence") -> Any:
    if isinstance(value, Mapping):
        return {
            key: _strip_forbidden(item, path=f"{path}.{key}")
            for key, item in value.items()
            if key.lower() not in _FORBIDDEN_KEYS
        }
    if isinstance(value, list):
        return [_strip_forbidden(item, path=f"{path}[{index}]") for index, item in enumerate(value)]
    if isinstance(value, tuple):
        return tuple(_strip_forbidden(item, path=f"{path}[{index}]") for index, item in enumerate(value))
    return value


def _truncate(value: Any, *, maximum: int = _MAX_STRING) -> Any:
    if isinstance(value, str):
        return value if len(value) <= maximum else value[:maximum]
    if isinstance(value, list):
        return [_truncate(item, maximum=maximum) for item in value]
    if isinstance(value, tuple):
        return tuple(_truncate(item, maximum=maximum) for item in value)
    if isinstance(value, Mapping):
        return {key: _truncate(item, maximum=maximum) for key, item in value.items()}
    return value


def _brief(artifacts: ContentAddressedArtifactStore, ref: ArtifactRef) -> Mapping[str, Any]:
    return cast(Mapping[str, Any], _truncate(_read(artifacts, ref)))


def _read(artifacts: ContentAddressedArtifactStore, ref: ArtifactRef) -> Mapping[str, Any]:
    """Read one content-addressed artifact without truncating its bytes."""
    try:
        payload = json.loads(artifacts.get(ref).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cycle evidence is not strict JSON: {ref.artifact_id}") from exc
    if not isinstance(payload, Mapping):
        raise ValueError(f"cycle evidence is not an object: {ref.artifact_id}")
    return cast(Mapping[str, Any], _strip_forbidden(payload))


def _ref_from_artifact_id(
    artifact_id: str, artifacts: ContentAddressedArtifactStore
) -> ArtifactRef | None:
    """Typed content address -> ArtifactRef, resolving the real size from CAS."""
    if not isinstance(artifact_id, str) or "-sha256:" not in artifact_id:
        return None
    kind = artifact_id.split("-sha256:", 1)[0]
    digest = artifact_id.rsplit(":", 1)[1]
    if len(digest) != 64:
        return None
    try:
        size = (artifacts.root / kind / digest).stat().st_size
        return ArtifactRef(kind, artifact_id, size)
    except (ValueError, OSError):
        return None


def _read_artifact_id(
    artifacts: ContentAddressedArtifactStore, artifact_id: str
) -> Mapping[str, Any]:
    """Resolve and integrity-check a typed content address already in the CAS."""
    prefix, separator, digest = artifact_id.partition("-sha256:")
    if not separator or not prefix or len(digest) != 64:
        raise ValueError("invalid typed artifact id")
    path = artifacts.root / prefix / digest
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ValueError(f"missing bound artifact: {artifact_id}") from exc
    return _read(artifacts, ArtifactRef(prefix, artifact_id, size))


def _score(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.5
    numeric = float(value)
    if not math.isfinite(numeric):
        return 0.5
    return min(1.0, max(0.0, numeric))


def _validate_runtime_policy_council_decisions(
    raw_decisions: object, pending: set[str]
) -> list[Mapping[str, Any]]:
    if not isinstance(raw_decisions, list):
        raise ValueError("runtime_policy_decisions must be a list")
    expected_keys = {
        "amendment_id",
        "decision",
        "reason",
        "replacement_amendment_id",
    }
    by_id: dict[str, Mapping[str, Any]] = {}
    for item in raw_decisions:
        if not isinstance(item, Mapping) or set(item) != expected_keys:
            raise ValueError("runtime-policy council decision has an invalid schema")
        amendment_id = item["amendment_id"]
        decision = item["decision"]
        reason = item["reason"]
        replacement = item["replacement_amendment_id"]
        if not isinstance(amendment_id, str) or not amendment_id:
            raise ValueError("runtime-policy council decision has an invalid amendment id")
        if amendment_id in by_id:
            raise ValueError(
                "council must decide every pending runtime-policy amendment exactly once"
            )
        if decision not in {"ratify", "revise", "rollback"}:
            raise ValueError("runtime-policy council decision is invalid")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("runtime-policy council decision requires a reason")
        if decision == "ratify":
            if replacement is not None:
                raise ValueError("ratification cannot name a replacement amendment")
        elif not isinstance(replacement, str) or not replacement:
            raise ValueError("revision or rollback requires a replacement amendment")
        by_id[amendment_id] = dict(item)
    if set(by_id) != pending:
        raise ValueError(
            "council must decide every pending runtime-policy amendment exactly once"
        )
    return [by_id[amendment_id] for amendment_id in sorted(pending)]


def _observation_receipts(observations: Sequence[Any]) -> list[Mapping[str, Any]]:
    """Bounded audit receipts: action, outcome, exit code, output digest and kind.

    Full tool outputs stay in the short-lived sandbox; the long-lived artifact
    keeps only a digest plus a small summary so claims can be traced without
    leaking sensitive content.  Conclusions without an observed receipt
    degrade to hypothesis or self-reported evidence.
    """
    receipts: list[Mapping[str, Any]] = []
    for item in observations:
        result = item.result if isinstance(item.result, Mapping) else {}
        try:
            result_digest = hashlib.sha256(
                canonical_json(result).encode("utf-8")
            ).hexdigest()
        except (TypeError, ValueError):
            result_digest = hashlib.sha256(
                json.dumps(result, sort_keys=True, default=str).encode("utf-8")
            ).hexdigest()
        accepted = result.get("accepted", True)
        outcome = "accepted" if accepted is not False else "rejected"
        exit_code = result.get("exit_code")
        summary_parts: list[str] = []
        for key in ("message", "output", "stdout", "error", "reason"):
            value = result.get(key)
            if isinstance(value, str) and value.strip():
                summary_parts.append(f"{key}={value.strip()[:512]}")
        nested_error = result.get("error")
        if isinstance(nested_error, Mapping):
            error_type = nested_error.get("type")
            error_message = nested_error.get("message")
            if isinstance(error_type, str) and error_type.strip():
                summary_parts.append(f"error_type={error_type.strip()[:256]}")
            if isinstance(error_message, str) and error_message.strip():
                summary_parts.append(f"error_message={error_message.strip()[:512]}")
        observed_markers = {"accepted", "exit_code", "output_digest", "action_receipt", "elapsed_seconds"}
        if observed_markers & set(result):
            evidence_kind = EvidenceKind.OBSERVED
        else:
            evidence_kind = EvidenceKind.SELF_REPORTED
        receipts.append(
            {
                "step": int(item.step),
                "action": str(item.action),
                "outcome": outcome,
                "exit_code": int(exit_code) if isinstance(exit_code, int) and not isinstance(exit_code, bool) else None,
                "result_digest": result_digest,
                "result_summary": "; ".join(summary_parts)[:2048],
                "evidence_kind": evidence_kind.value,
            }
        )
    return receipts


def _usage_summary(usages: Sequence[TokenUsage]) -> Mapping[str, int]:
    return {
        "requests": len(usages),
        "input_tokens": sum(item.input_tokens for item in usages),
        "output_tokens": sum(item.output_tokens for item in usages),
        "cached_tokens": sum(item.cached_tokens for item in usages),
        "reasoning_tokens": sum(item.reasoning_tokens for item in usages),
    }


def _baseline_only_report() -> AttributionReport:
    return AttributionReport.create(
        disposition=AttributionDisposition.INVALID_DESIGN,
        qualification_path=QualificationPath.NONE,
        reason="no candidate was evaluated; the current arm is baseline evidence only",
        observation_ids=(),
        policy=QualificationPolicy(),
        quality_delta=0.0,
        cost_change=0.0,
    )


def _git_head(repository: Path) -> str:
    result = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=repository,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError("checkpoint wiring requires a resolvable repository HEAD commit")
    commit = result.stdout.decode("ascii", errors="strict").strip()
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        raise RuntimeError("repository HEAD is not a full Git commit id")
    return commit


class _DenyAllExecutor:
    def execute(self, manifest: object, grant: object, request: object) -> object:
        raise RuntimeError("external actions never reach a plugin executor")


class _RegistryCohortProvider:
    def __init__(self, registry: DynamicTaskRegistry) -> None:
        self.registry = registry

    def select_dynamic_cohort(
        self, target_generation: int, *, limit: int | None = None
    ) -> DynamicTaskCohort:
        return self.registry.select_dynamic_cohort(target_generation, limit=limit)


def _sealed_tasks(
    registry: DynamicTaskRegistry, cohort: DynamicTaskCohort
) -> tuple[Mapping[str, Any], ...]:
    tasks: list[Mapping[str, Any]] = []
    for member in cohort.members:
        archive = registry.archive(member.artifact_id)
        with tempfile.TemporaryDirectory(prefix="aegis-cycle-task-") as directory:
            root = Path(directory).resolve(strict=True)
            with tempfile.TemporaryFile() as stream:
                stream.write(archive)
                stream.seek(0)
                import tarfile

                with tarfile.open(fileobj=stream, mode="r:*") as handle:
                    handle.extractall(root, filter="data")
            pack = TaskPack.load(root)
            prompt = (pack.root / "prompt.md").read_text(encoding="utf-8").strip()
            tasks.append(
                {
                    "artifact_id": member.artifact_id,
                    "task_id": pack.manifest.task_id,
                    "task_version": pack.manifest.version,
                    "language": pack.manifest.language,
                    "content_hash": pack.manifest.content_hash,
                    "tier": member.tier.value,
                    "description": prompt[:4096],
                    "public_test_command": ["python", "-m", "pytest", "-q", "tests/public"],
                }
            )
    return tuple(tasks)


def _repair_taskpack_content_hash(root: Path) -> bool:
    """Recompute the derived content hash a model cannot reliably predict.

    The tree hash is integrity metadata over everything except manifest.json
    itself; the model writes the tree, so the control plane derives the hash
    instead of trusting a model-provided value.  The manifest must already be
    structurally complete (all non-hash fields correct) for this to apply.
    """

    manifest_path = root / "manifest.json"
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(raw, dict):
        return False
    required = {
        "task_id",
        "version",
        "language",
        "public_dir",
        "hidden_dir",
        "reference_dir",
        "defect_dir",
        "mutant_dirs",
    }
    if set(raw) != required | {"content_hash"}:
        return False
    try:
        digest = compute_tree_hash(root, exclude=frozenset({"manifest.json"}))
    except (ValueError, OSError):
        return False
    raw["content_hash"] = digest
    try:
        manifest_path.write_text(
            json.dumps(raw, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError:
        return False
    return True


def _task_authoring_seed_workspace() -> bytes:
    """Package one complete built-in task pack as a read-only authoring template.

    The Judge is asked to copy this exact structure into ``drafts/<task_id>/``;
    placing the template under ``templates/`` keeps it out of the draft
    discovery roots so an unmodified template is never registered as a task.
    """

    sample = builtin_python_root() / "01_clamp_range"
    if not sample.is_dir():
        raise ValueError("built-in task-authoring template is missing")
    entries: dict[str, bytes] = {}
    for path in sorted(sample.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(sample).as_posix()
        if any(
            part in {"__pycache__", ".pytest_cache", ".git", ".aegis"}
            for part in PurePosixPath(relative).parts
        ):
            continue
        entries[f"templates/example-task/{relative}"] = path.read_bytes()
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name in sorted(entries):
            payload = entries[name]
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(payload))
    return output.getvalue()


def _arm_evaluation_mapping(evaluation: Any) -> Mapping[str, Any]:
    return {
        "workspace_digest": evaluation.workspace_digest,
        "quality": evaluation.quality,
        "passed_tasks": evaluation.passed_tasks,
        "total_tasks": evaluation.total_tasks,
        "integrity_passed": evaluation.integrity_passed,
        "safety_violations": list(evaluation.safety_violations),
        "fresh": {
            "quality": evaluation.fresh.quality,
            "task_count": evaluation.fresh.task_count,
            "artifact_ids": list(evaluation.fresh.artifact_ids),
        },
        "regression": {
            "quality": evaluation.regression.quality,
            "task_count": evaluation.regression.task_count,
            "artifact_ids": list(evaluation.regression.artifact_ids),
        },
        "tasks": [
            {
                "task_id": item.task_id,
                "artifact_id": item.artifact_id,
                "tier": item.tier.value,
                "score": round(item.score, 12),
                "integrity_passed": item.integrity_passed,
                "public": {
                    "passed": item.public.passed,
                    "total": item.public.total,
                    "timed_out": item.public.timed_out,
                    "integrity_violations": list(item.public.integrity_violations),
                },
                "hidden": {
                    "passed": item.hidden.passed,
                    "total": item.hidden.total,
                    "timed_out": item.hidden.timed_out,
                    "integrity_violations": list(item.hidden.integrity_violations),
                },
                "changed_paths": list(item.changed_paths),
            }
            for item in evaluation.task_results
        ],
    }


def _objective_metrics(
    evaluation: Mapping[str, Any],
    *,
    cost_units: int,
    baseline_cost_units: int | None = None,
) -> Mapping[str, float | None]:
    fresh = evaluation.get("fresh", {})
    regression = evaluation.get("regression", {})
    if baseline_cost_units is None:
        efficiency = 1.0
    elif cost_units <= 0:
        efficiency = 1.0 if baseline_cost_units <= 0 else 0.0
    else:
        efficiency = min(1.0, baseline_cost_units / cost_units)
    return {
        "quality": float(evaluation.get("quality", 0.0)),
        "generalization": (
            float(fresh["quality"])
            if isinstance(fresh, Mapping) and isinstance(fresh.get("quality"), (int, float))
            else None
        ),
        "retention": (
            float(regression["quality"])
            if isinstance(regression, Mapping)
            and isinstance(regression.get("quality"), (int, float))
            else None
        ),
        "efficiency": efficiency,
    }


def _objective_utility(
    objective: ObjectiveVersion, metrics: Mapping[str, float | None]
) -> tuple[float, bool] | None:
    if any(metrics.get(name) is None for name, weight in objective.capability_weights.items() if weight > 0):
        return None
    utility = sum(
        weight * cast(float, metrics[name])
        for name, weight in objective.capability_weights.items()
    )
    criteria_passed = all(
        metrics.get(item.metric) is not None
        and cast(float, metrics[item.metric]) >= item.minimum
        for item in objective.success_criteria
    )
    return round(utility, 12), criteria_passed


def _taskpack_validation_mapping(report: Any) -> Mapping[str, Any]:
    def execution(item: Any) -> Mapping[str, Any]:
        return {
            "passed": item.passed,
            "tests_run": item.tests_run,
            "exit_code": item.exit_code,
            "timed_out": item.timed_out,
            "output_digest": item.output_digest,
        }

    return {
        "valid": report.valid,
        "reasons": list(report.reasons),
        "reference_public": execution(report.reference_public),
        "reference_hidden": execution(report.reference_hidden),
        "defect_public": execution(report.defect_public),
        "defect_hidden": execution(report.defect_hidden),
        "mutant_hidden": [execution(item) for item in report.mutant_hidden],
    }


class ModelCyclePorts:
    """Production ports: model roles through RoleAgentRuntime, control-plane gates."""

    def __init__(
        self,
        *,
        gateway: Any,
        sandbox: SandboxBackend,
        research: Any,
        knowledge: Any,
        skills: Any,
        pdf_extractor: Any,
        role_configs: Mapping[str, RoleConfig],
        limits: RuntimeLimits,
        artifacts: ContentAddressedArtifactStore,
        dynamic: DynamicTaskRegistry,
        forge: TaskForge,
        runner: TaskPackRunner,
        curriculum: CurriculumRegistry,
        roles: RoleRegistry,
        data_dir: Path,
        holdout_delay: int = 1,
        objective_history_window: int = 3,
        objective_probation_cycles: int = 2,
        council_max_messages: int = 200,
        council_max_tokens: int = 4_194_304,
        public_repo_url: str | None = None,
        source_commit: str | None = None,
        evolution: EvolutionRegistry | None = None,
        environment_builder: EnvironmentBuilder | None = None,
        default_image: str | None = None,
        evaluate_candidates_enabled: bool = True,
        candidate_max_extra_steps: int = 12,
        budget_policy_sha256: str | None = None,
        harness_repo: HarnessRepo | None = None,
        harness_backend: HarnessBackend | None = None,
        harness_campaign_id: str | None = None,
        harness_canary_command: Sequence[str] | None = None,
        harness_activation_automatic: bool = True,
        mcp_bridge: McpBridge | None = None,
        subagent_max_steps: int = 8,
        subagent_timeout_seconds: float = 180.0,
        subagent_max_concurrency: int = 2,
        subagent_max_result_bytes: int = 65_536,
        meta_evolution_enabled: bool = False,
        population: PopulationArchive | None = None,
        activation_store: EventStore | None = None,
        history_store: EventStore | None = None,
        mcp_registry: McpRegistry | None = None,
        runtime_policy_registry: RuntimePolicyRegistry | None = None,
        runtime_policy_cycle: int = 0,
        runtime_consumed: Mapping[str, float | int] | None = None,
        objective_governance: ObjectiveGovernanceRegistry | None = None,
        runtime_ledger: RuntimeGatewayAttemptObserver | None = None,
        require_warrior_strategy_proposal: bool = False,
        judge_heterogeneous_model: str | None = None,
        judge_heterogeneous_fraction: float = 0.0,
    ) -> None:
        self._gateway = gateway
        self._sandbox = sandbox
        self._research = research
        self._knowledge = knowledge
        self._skills = skills
        self._pdf_extractor = pdf_extractor
        self._role_configs = dict(role_configs)
        if set(self._role_configs) != {"warrior", "judge", "prosecutor"}:
            raise ValueError("role_configs must define exactly warrior, judge and prosecutor")
        self._limits = limits
        self._artifacts = artifacts
        self._dynamic = dynamic
        self._forge = forge
        self._runner = runner
        self._curriculum = curriculum
        self._roles = roles
        self._data_dir = data_dir
        self._holdout_delay = holdout_delay
        if (
            isinstance(objective_history_window, bool)
            or not isinstance(objective_history_window, int)
            or objective_history_window < 1
            or isinstance(objective_probation_cycles, bool)
            or not isinstance(objective_probation_cycles, int)
            or objective_probation_cycles < 1
        ):
            raise ValueError("objective history and probation windows must be positive integers")
        self._objective_history_window = objective_history_window
        self._objective_probation_cycles = objective_probation_cycles
        self._council_max_messages = council_max_messages
        self._council_max_tokens = council_max_tokens
        self._require_warrior_strategy_proposal = require_warrior_strategy_proposal
        self._judge_heterogeneous_model = judge_heterogeneous_model
        self._judge_heterogeneous_fraction = judge_heterogeneous_fraction
        self._objective_history_path = data_dir / "objective_history.jsonl"
        self._campaign_event_store = history_store or activation_store
        self._attribution_ledger = data_dir / "attribution_arms.jsonl"
        self._frozen_submissions: dict[str, FrozenSubmissionEvidence] = {}
        self._frozen_workspace_bytes: dict[str, bytes] = {}
        self._environment_id = type(sandbox).__name__
        self._evolution = evolution
        self._environment_builder = environment_builder
        self._default_image = default_image
        self._evaluate_candidates_enabled = evaluate_candidates_enabled
        self._candidate_max_extra_steps = candidate_max_extra_steps
        if isinstance(candidate_max_extra_steps, bool) or not isinstance(
            candidate_max_extra_steps, int
        ) or not 1 <= candidate_max_extra_steps <= 1000:
            raise ValueError("candidate_max_extra_steps must be an integer in [1,1000]")
        self._budget_policy_sha256 = budget_policy_sha256 or hashlib.sha256(
            b"aegis-unset-budget-policy"
        ).hexdigest()
        self._runtime_policy_registry = runtime_policy_registry
        self._runtime_policy_cycle = runtime_policy_cycle
        self._runtime_stage_ordinal = (
            runtime_policy_registry.resume_stage_boundary(runtime_policy_cycle).ordinal
            if runtime_policy_registry is not None
            else 0
        )
        self._runtime_consumed: dict[str, float | int] = dict(runtime_consumed or {})
        self._objective_governance = objective_governance
        self._runtime_ledger = runtime_ledger
        self._source_commit = source_commit
        self._harness_repo = harness_repo
        self._harness_backend = harness_backend
        self._harness_campaign_id = harness_campaign_id
        if not harness_activation_automatic:
            raise ValueError("harness activation is automatic in autonomy v2")
        self._mcp_bridge = mcp_bridge
        self._subagent_manager = SubagentManager(
            limits=SubagentLimits(
                max_steps=subagent_max_steps,
                timeout_seconds=subagent_timeout_seconds,
                max_result_bytes=subagent_max_result_bytes,
            ),
            max_concurrency=subagent_max_concurrency,
        )
        self._meta_evolution_enabled = bool(meta_evolution_enabled)
        self._population = population
        self._owned_activation_store: EventStore | None = None
        self._activation_journal: ActivationJournal | None = None
        self._mcp_registry: McpRegistry | None = None
        if evolution is not None:
            if activation_store is None:
                activation_store = EventStore(data_dir / "activation_events.sqlite3")
                self._owned_activation_store = activation_store
            self._activation_journal = ActivationJournal(
                activation_store, curriculum.projection.campaign_id
            )
            self._mcp_registry = mcp_registry or McpRegistry(
                activation_store, curriculum.projection.campaign_id
            )
        self._harness_canary: HarnessCanaryRunner | None = None
        self._harness_rollback: HarnessRollbackExecutor | None = None
        if harness_repo is not None:
            self._harness_canary = HarnessCanaryRunner(
                harness_repo,
                canary_argv=(
                    tuple(harness_canary_command)
                    if harness_canary_command is not None
                    else (
                        "{python}",
                        "-m",
                        "pytest",
                        "-q",
                        "-p",
                        "no:cacheprovider",
                        "tests/test_evolution_surfaces.py",
                    )
                ),
            )
            self._harness_rollback = HarnessRollbackExecutor(harness_repo)
        self._arm_workspaces: dict[str, bytes] = {}
        workflow_ref, subject_ref = materialize_default_artifacts(artifacts)
        self._default_workflow_ref = workflow_ref
        self._default_subject_ref = subject_ref
        active = roles.projection.current_active_set
        if active is None:
            raise RuntimeError("role genesis must precede runtime binding")
        self._active_roles = active
        self._bindings: dict[Role, RuntimeBinding] = {}
        for role in Role:
            self._bindings[role] = resolve_role_binding(
                artifacts=artifacts,
                evolution=evolution,
                active_identity=active.for_role(role),
                role=role,
                role_config=self._role_configs[role.value],
                budget_policy_sha256=self._budget_policy_sha256,
                default_image=default_image,
                default_workflow_ref=workflow_ref,
                default_subject_ref=subject_ref,
            )
        if self._mcp_bridge is not None and self._mcp_registry is not None:
            for candidate in self._bindings[Role.WARRIOR].mcps:
                callable_binding = self._mcp_registry.callable_binding_for_server(
                    candidate.binding.server_name
                )
                if callable_binding == candidate.binding:
                    self._mcp_bridge.activate_candidate(candidate)
        if self._activation_journal is not None:
            self._activation_reconciler().reconcile()
        self._journal: SqliteConnectorJournal | None = None
        self._checkpoint: tuple[str, tuple[PluginManifest, ...], ToolBroker] | None = None
        self._checkpoint_connector: GitCheckpointConnector | None = None
        if public_repo_url is not None and source_commit is not None:
            self._journal = SqliteConnectorJournal(data_dir / "connector_journal.sqlite3")
            role_paths: dict[str, tuple[str, ...]] = {"warrior": ("warrior",)}
            if harness_repo is not None:
                role_paths["warrior"] = ("warrior", *HARNESS_ALLOWED_ROOTS)
            publisher = GitPublisher(
                public_repo_url,
                remote_id="aegis-public",
                allowed_role_paths=role_paths,
            )
            connector = GitCheckpointConnector(publisher)
            self._checkpoint_connector = connector
            manifest = build_checkpoint_plugin()
            generation = checkpoint_generation(source_commit=source_commit)
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
            broker = ToolBroker(
                generation,
                (manifest,),
                _DenyAllExecutor(),
                policy=policy,
                external_connector=connector,
                external_journal=self._journal,
            )
            self._checkpoint = (generation.generation_id, (manifest,), broker)
        self._sandbox_sequence = 0
        self._sandbox_lock = threading.Lock()

    def close(self) -> None:
        if self._journal is not None:
            self._journal.close()
            self._journal = None
        if self._owned_activation_store is not None:
            self._owned_activation_store.close()
            self._owned_activation_store = None

    def __enter__(self) -> ModelCyclePorts:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    # -- model-backed ports -------------------------------------------------

    def generate_repair_patch(
        self,
        *,
        base_generation_id: str,
        campaign_id: str,
        cycle_id: str,
        cause: str,
    ) -> Any:
        """Ask the Prosecutor model for a bounded repair patch for one failure."""
        evidence = self._run_role(
            Role.PROSECUTOR,
            max_steps=min(self._limits.max_steps, 10),
            objective=(
                "Generate a minimal, safe repair patch for the failed role generation. "
                "Submit one payload with summary and a changes array; every change "
                "must carry path, content_base64 and executable."
            ),
            context={
                "campaign_id": campaign_id,
                "cycle_id": cycle_id,
                "base_generation_id": base_generation_id,
                "failure": cause[:4096],
            },
        )
        payload = evidence.get("submission", {})
        changes = payload.get("changes", [])
        if not isinstance(changes, list):
            raise ValueError("Prosecutor repair patch must contain a changes array")
        if not changes:
            return None
        return patch_from_prosecutor_submission(
            base_generation_id=base_generation_id,
            summary=str(payload.get("summary", "")),
            changes=changes,
        )

    def _record_runtime_usage(self, usage: TokenUsage) -> None:
        if self._runtime_ledger is not None:
            return
        self._runtime_consumed["max_total_tokens"] = int(
            self._runtime_consumed.get("max_total_tokens", 0)
        ) + usage.total_tokens
        self._runtime_consumed["max_requests"] = int(
            self._runtime_consumed.get("max_requests", 0)
        ) + 1

    def _policy_value(self, name: str, fallback: Any) -> Any:
        if self._runtime_policy_registry is None:
            return fallback
        boundary = RuntimeStageBoundary(
            self._runtime_policy_cycle,
            self._runtime_stage_ordinal,
            f"stage:{self._runtime_stage_ordinal}",
        )
        policy = self._runtime_policy_registry.effective_for_stage(boundary)
        return policy.values.get(name, fallback)

    def _candidate_step_limit(self) -> int:
        return int(
            self._policy_value("candidate_max_steps", self._candidate_max_extra_steps)
        )

    def _subagent_accounting_binding(self) -> Mapping[str, Any] | None:
        if self._runtime_policy_registry is None:
            return None
        context = _ACCOUNTING_CONTEXT.get()
        if context is None:
            raise RuntimeError("subagent spawn is outside an accounting context")
        return {
            "event_store_path": str(self._runtime_policy_registry.store.path),
            "artifact_root": str(self._runtime_policy_registry.artifacts.root),
            "policy_campaign_id": self._runtime_policy_registry.campaign_id,
            "parent_context": context.to_mapping(),
        }

    def _adjust_runtime_policy(
        self, arguments: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        if self._runtime_policy_registry is None:
            raise RuntimeError("runtime policy registry is not configured")
        consumed = (
            self._runtime_ledger.consumed().to_policy_mapping()
            if self._runtime_ledger is not None
            else self._runtime_consumed
        )
        requested_at = _RUNTIME_STAGE_BOUNDARY.get()
        if requested_at is None:
            raise RuntimeError("runtime policy amendment is outside a bounded stage")
        target = arguments["rollback_target_policy_id"]
        if target is None:
            amendment = self._runtime_policy_registry.request_patch_immediately(
                requested_by=Role.PROSECUTOR,
                requested_at=requested_at,
                request_id=str(arguments["request_id"]),
                base_policy_id=str(arguments["base_policy_id"]),
                patch=cast(Mapping[str, Any], arguments["patch"]),
                consumed=consumed,
                reason=str(arguments["reason"]).strip(),
                evidence_refs=tuple(cast(list[str], arguments["evidence_refs"])),
            )
        else:
            amendment = self._runtime_policy_registry.request_rollback_immediately(
                requested_by=Role.PROSECUTOR,
                requested_at=requested_at,
                request_id=str(arguments["request_id"]),
                base_policy_id=str(arguments["base_policy_id"]),
                target_policy_id=cast(str, target),
                consumed=consumed,
                reason=str(arguments["reason"]).strip(),
                evidence_refs=tuple(cast(list[str], arguments["evidence_refs"])),
            )
        return {
            "amendment_id": amendment.amendment_id,
            "base_policy_id": amendment.base_policy_id,
            "resulting_policy_id": amendment.resulting_policy_id,
            "effective_cycle": amendment.requested_at.cycle,
            "effective_stage": amendment.requested_at.to_mapping(),
            "revision": amendment.revision,
            "maintenance_only": self._runtime_policy_registry.effective_for_stage(
                amendment.requested_at
            ).maintenance_only,
        }

    def _run_role(
        self,
        role: Role,
        *,
        objective: str,
        context: Mapping[str, Any],
        max_steps: int | None = None,
        runtime_binding: RuntimeBinding | None = None,
        stage_workspace: bytes | None = None,
        freeze_workspace: bool = False,
        extra_actions: frozenset[str] = frozenset(),
        request_seed: int | None = None,
        mcp_bridge: McpBridge | None = None,
        accounting_stage: str | None = None,
        paired_design_id: str | None = None,
        required_action_groups: tuple[frozenset[str], ...] = (),
        freeze_max_bytes: int | None = None,
        restrict_actions: frozenset[str] | None = None,
        role_config: RoleConfig | None = None,
    ) -> Mapping[str, Any]:
        with self._sandbox_lock:
            self._sandbox_sequence += 1
            self._runtime_stage_ordinal += 1
            stage_ordinal = self._runtime_stage_ordinal
            sandbox_id = (
                f"cycle-{role.value}-{self._sandbox_sequence}-{secrets.token_hex(4)}"
            )
        boundary = RuntimeStageBoundary(
            self._runtime_policy_cycle, stage_ordinal, f"stage:{stage_ordinal}"
        )
        cfg = role_config if role_config is not None else self._role_configs[role.value]
        policy_max_steps = self._limits.max_steps
        policy_timeout = self._limits.max_timeout_seconds
        if self._runtime_policy_registry is not None:
            stage_policy = (
                self._runtime_policy_registry.policy_for_paired_design(paired_design_id)
                if paired_design_id is not None
                else self._runtime_policy_registry.effective_for_stage(boundary)
            )
            policy_timeout = float(
                cast(Mapping[str, Any], stage_policy.values["role_command_timeout_seconds"])[role.value]
            )
            outputs = cast(
                Mapping[str, Any], stage_policy.values["role_max_output_tokens"]
            )
            cfg = replace(cfg, max_output_tokens=int(outputs[role.value]))
            configured_steps = int(
                cast(Mapping[str, Any], stage_policy.values["role_max_steps"])[role.value]
            )
            if configured_steps > 0:
                policy_max_steps = configured_steps
        step_limit = policy_max_steps if max_steps is None else min(max_steps, policy_max_steps)
        binding = runtime_binding if runtime_binding is not None else self._bindings[role]
        image = binding.runtime_image
        try:
            self._sandbox.prepare(sandbox_id, image=image)
        except Exception:
            # A previous interrupted run can leave an agent-side residue for a
            # reused id.  Destroy and retry once before failing closed.
            try:
                self._sandbox.destroy(sandbox_id)
            except Exception:
                pass
            self._sandbox.prepare(sandbox_id, image=image)
        dispatcher_kwargs: dict[str, Any] = {
            "knowledge": self._knowledge,
            "skills": self._skills,
            "pdf_extractor": self._pdf_extractor,
            "disabled_actions": (
                frozenset() if role is Role.WARRIOR else frozenset({"evolution.request"})
            ),
            "extra_actions": extra_actions,
            "mcp_bridge": self._mcp_bridge if mcp_bridge is None else mcp_bridge,
            "subagent_manager": self._subagent_manager,
            "meta_evolution_enabled": self._meta_evolution_enabled,
            "runtime_policy_adjuster": self._adjust_runtime_policy,
            "runtime_policy_values": (
                (lambda: cast(
                    Mapping[str, Any],
                    (
                        self._runtime_policy_registry.policy_for_paired_design(paired_design_id)
                        if paired_design_id is not None
                        else self._runtime_policy_registry.effective_for_stage(boundary)
                    ).values,
                ))
                if self._runtime_policy_registry is not None
                else None
            ),
            "subagent_accounting_binding": self._subagent_accounting_binding,
            "allowed_actions_override": restrict_actions,
        }
        broker_tuple = self._broker_for_binding(role, binding, sandbox_id)
        if broker_tuple is not None:
            generation_id, manifests, broker = broker_tuple
            dispatcher_kwargs.update(
                {
                    "role_generation_id": generation_id,
                    "plugin_manifests": manifests,
                    "tool_broker": broker,
                }
            )
        effective_limits = replace(
            self._limits,
            max_steps=step_limit,
            max_timeout_seconds=policy_timeout,
        )
        dispatcher = ToolDispatcher(
            self._sandbox,
            self._research,
            sandbox_id,
            limits=effective_limits,
            challenge_metadata=None,
            **dispatcher_kwargs,
        )
        workspace_digest: str | None = None
        if stage_workspace is not None:
            workspace_digest = stage_cohort_workspace(
                self._sandbox, sandbox_id, stage_workspace
            )
        try:
            def active_policy_values(_runtime_role: GatewayRole) -> Mapping[str, Any]:
                if self._runtime_policy_registry is None:
                    return {}
                values = cast(
                    dict[str, Any],
                    thaw_json(cast(
                        JsonValue,
                        (
                            self._runtime_policy_registry.policy_for_paired_design(paired_design_id)
                            if paired_design_id is not None
                            else self._runtime_policy_registry.effective_for_stage(boundary)
                        ).values,
                    )),
                )
                if max_steps is not None:
                    steps = cast(dict[str, Any], values["role_max_steps"])
                    steps[role.value] = min(int(steps[role.value]), max_steps)
                return values

            runtime = RoleAgentRuntime(
                self._gateway,
                dispatcher,
                cfg.model,
                limits=effective_limits,
                max_output_tokens=cfg.max_output_tokens,
                reasoning_effort=cfg.reasoning_effort,
                usage_sink=self._record_runtime_usage,
                request_seed=request_seed,
                workflow=dict(binding.workflow) if binding.workflow else None,
                subject=dict(binding.subject) if binding.subject else None,
                policy_provider=(
                    active_policy_values if self._runtime_policy_registry is not None else None
                ),
            )
            runtime_context = dict(context)
            if self._runtime_policy_registry is not None:
                active_policy = (
                    self._runtime_policy_registry.policy_for_paired_design(paired_design_id)
                    if paired_design_id is not None
                    else self._runtime_policy_registry.effective_for_stage(boundary)
                )
                ledger_consumed = (
                    self._runtime_ledger.consumed()
                    if self._runtime_ledger is not None
                    else None
                )
                runtime_context["runtime_policy"] = {
                    "policy_id": active_policy.policy_id,
                    "schema_version": active_policy.schema_version,
                    "values": thaw_json(cast(JsonValue, active_policy.values)),
                    "consumed": dict(
                        ledger_consumed.to_policy_mapping()
                        if ledger_consumed is not None
                        else self._runtime_consumed
                    ),
                    "waste": (
                        {
                            "waste_tokens": ledger_consumed.waste_tokens,
                            "waste_requests": ledger_consumed.waste_requests,
                            "waste_runtime_seconds": ledger_consumed.waste_runtime_seconds,
                        }
                        if ledger_consumed is not None
                        else {}
                    ),
                    "pending_council_review": [
                        item.amendment_id
                        for item in self._runtime_policy_registry.pending_council_amendments()
                    ],
                }
            if role is Role.WARRIOR and binding.mcps:
                runtime_context["active_mcp_bindings"] = [
                    {
                        "candidate_id": item.candidate_id,
                        "binding_id": item.binding.binding_id,
                        "server": item.manifest.name,
                        "tools": [
                            grant.tool_name
                            for grant in item.binding.authorizations
                        ],
                    }
                    for item in binding.mcps
                ]
            accounting_token = _ACCOUNTING_CONTEXT.set(
                AccountingContext(
                    campaign_id=(
                        self._runtime_policy_registry.campaign_id
                        if self._runtime_policy_registry is not None
                        else self._curriculum.projection.campaign_id
                    ),
                    cycle=self._runtime_policy_cycle,
                    stage=accounting_stage or f"role:{role.value}",
                    stage_ordinal=stage_ordinal,
                    role=role,
                    invocation_id=sandbox_id,
                    paired_design_id=paired_design_id,
                )
            )
            stage_token = _RUNTIME_STAGE_BOUNDARY.set(boundary)
            try:
                result = runtime.run(
                    GatewayRole(role.value),
                    objective=objective,
                    context=runtime_context,
                    required_action_groups=required_action_groups,
                )
            finally:
                _RUNTIME_STAGE_BOUNDARY.reset(stage_token)
                _ACCOUNTING_CONTEXT.reset(accounting_token)
            evidence: dict[str, Any] = {
                "role": role.value,
                "summary": result.summary[:4096],
                "submission": _strip_forbidden(result.submission),
                "usage": _usage_summary(result.usages),
                "usage_verified": result.usage_verified,
                "observations": _observation_receipts(result.observations[:100]),
                "submit_digest": hashlib.sha256(
                    canonical_json(result.submission).encode("utf-8")
                ).hexdigest(),
                "submit_attempts": sum(
                    1 for item in result.observations if item.action == "submit"
                ),
                "duplicate_submits": max(
                    0,
                    sum(1 for item in result.observations if item.action == "submit") - 1,
                ),
            }
            if self._runtime_policy_registry is not None:
                evidence["runtime_policy_id"] = (
                    self._runtime_policy_registry.policy_for_paired_design(paired_design_id)
                    if paired_design_id is not None
                    else self._runtime_policy_registry.effective_for_stage(boundary)
                ).policy_id
                evidence["runtime_policy_amendments"] = [
                    item.amendment_id
                    for item in self._runtime_policy_registry.immediate_amendments
                    if item.requested_at == boundary
                ]
            if stage_workspace is not None and workspace_digest is not None:
                evidence["workspace_digest"] = workspace_digest
                evidence["workspace_staged"] = True
            if freeze_workspace:
                digest, payload = freeze_workspace_bytes(
                    self._sandbox,
                    sandbox_id,
                    max_bytes=freeze_max_bytes
                    if freeze_max_bytes is not None
                    else 32 * 1024 * 1024,
                )
                ref = self._artifacts.put_bytes("arm-workspace", payload)
                workspace_digest = digest
                evidence["workspace_digest"] = digest
                evidence["workspace_artifact_id"] = ref.artifact_id
                evidence["workspace_size_bytes"] = len(payload)
            selected_mcp = self._mcp_bridge if mcp_bridge is None else mcp_bridge
            if selected_mcp is not None:
                evidence["mcp_call_receipts"] = [
                    item.to_mapping() for item in selected_mcp.receipts()
                ]
            return evidence
        finally:
            self._sandbox.destroy(sandbox_id)

    def _broker_for_binding(
        self,
        role: Role,
        binding: RuntimeBinding,
        sandbox_id: str,
    ) -> tuple[str, tuple[PluginManifest, ...], ToolBroker] | None:
        manifests = list(binding.plugins)
        if not manifests and self._checkpoint is not None:
            # Preserve the legacy checkpoint broker exactly when the role has
            # no evolved plugins: it already carries a full three-role bundle.
            return self._checkpoint
        if self._checkpoint is not None and role is Role.WARRIOR:
            checkpoint_manifest = self._checkpoint[1][0]
            if checkpoint_manifest.artifact_id not in {
                item.artifact_id for item in manifests
            }:
                manifests.append(checkpoint_manifest)
        if not manifests:
            return None
        plugin_ids = tuple(
            sorted({_generation_artifact_id(item.artifact_id) for item in manifests})
        )
        manifest = binding.manifest
        roles: list[RoleGeneration] = []
        for candidate_role in Role:
            if candidate_role is role:
                workflow_artifact_id = (
                    manifest.workflow_artifact_id
                    if manifest is not None
                    else self._default_workflow_ref.artifact_id
                )
                subject_artifact_id = (
                    manifest.subject_artifact_id
                    if manifest is not None
                    else self._default_subject_ref.artifact_id
                )
                runtime_image = (
                    binding.runtime_image
                    or self._default_image
                    or "aegis-inprocess@sha256:" + "0" * 64
                )
                role_plugin_ids = plugin_ids
            else:
                workflow_artifact_id = self._default_workflow_ref.artifact_id
                subject_artifact_id = self._default_subject_ref.artifact_id
                runtime_image = self._default_image or "aegis-inprocess@sha256:" + "0" * 64
                role_plugin_ids = ()
            roles.append(
                RoleGeneration(
                    role=candidate_role,
                    model_profile_sha256=model_profile_hash(
                        self._role_configs[candidate_role.value]
                    ),
                    workflow_artifact_id=_generation_artifact_id(workflow_artifact_id),
                    subject_artifact_id=_generation_artifact_id(subject_artifact_id),
                    runtime_image=runtime_image,
                    plugin_artifact_ids=role_plugin_ids,
                    budget_policy_sha256=self._budget_policy_sha256,
                )
            )
        generation = GenerationBundle.create(
            parent_generation_id=None,
            controller_abi=2,
            source_commit=self._source_commit or "0" * 40,
            roles=tuple(roles),
            evidence_manifest_sha256="0" * 64,
        )
        executor = SandboxPluginExecutor(self._sandbox, sandbox_id, limits=self._limits)
        checkpoint_mounted = (
            self._checkpoint is not None
            and any(
                item.artifact_id == self._checkpoint[1][0].artifact_id
                for item in manifests
            )
        )
        if checkpoint_mounted and self._checkpoint_connector is not None:
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
            broker = ToolBroker(
                generation,
                tuple(manifests),
                executor,
                policy=policy,
                external_connector=self._checkpoint_connector,
                external_journal=self._journal,
            )
        else:
            broker = ToolBroker(
                generation,
                tuple(manifests),
                executor,
                policy=PluginPolicy(
                    allowed_effects=frozenset(
                        {
                            EffectClass.PURE,
                            EffectClass.WORKSPACE_READ,
                            EffectClass.WORKSPACE_WRITE,
                        }
                    ),
                    allow_brokered_public_network=False,
                ),
            )
        return generation.generation_id, tuple(manifests), broker

    def solve(self, snapshot: CurriculumSnapshot, cohort: DynamicTaskCohort) -> Mapping[str, Any]:
        tasks = _sealed_tasks(self._dynamic, cohort)
        evidence = self._solve_arm(
            snapshot, cohort, tasks, self._bindings[Role.WARRIOR], arm_label="champion"
        )
        # Persist the submission artifact up front so the control-plane frozen
        # binding can reference its typed content address (idempotent: the
        # cycle runtime records the same bytes and receives the same address).
        submission_ref = self._artifacts.put_json("submission", evidence)
        evidence = dict(evidence)
        evidence["submission_artifact_id"] = submission_ref.artifact_id
        self._bind_frozen_submission(snapshot, cohort, evidence)
        return evidence

    def _bind_frozen_submission(
        self,
        snapshot: CurriculumSnapshot,
        cohort: DynamicTaskCohort,
        evidence: Mapping[str, Any],
    ) -> None:
        """Create the single control-plane FrozenSubmissionEvidence object.

        Judge, Prosecutor and the sealed evaluator all derive their mounts from
        this object; model self-reports never override it.
        """
        artifact_id = evidence.get("workspace_artifact_id")
        size = evidence.get("workspace_size_bytes")
        digest = evidence.get("workspace_digest")
        if (
            not isinstance(artifact_id, str)
            or not isinstance(size, int)
            or not isinstance(digest, str)
        ):
            raise RuntimeError("champion solve did not freeze a workspace")
        active = self._roles.projection.current_active_set
        if active is None:
            raise RuntimeError("role genesis must precede submission freeze")
        frozen = FrozenSubmissionEvidence.create(
            submission_artifact_id=evidence["submission_artifact_id"],
            workspace_artifact_id=artifact_id,
            workspace_digest=digest,
            workspace_size_bytes=size,
            producer_role_version_id=active.for_role(Role.WARRIOR).role_version_id,
            snapshot_id=snapshot.snapshot_id,
            cohort_id=cohort.cohort_id,
        )
        workspace = self._arm_workspaces.get("champion")
        if workspace is None:
            workspace = self._artifacts.get(ArtifactRef("arm-workspace", artifact_id, size))
        self._frozen_submissions["champion"] = frozen
        self._frozen_workspace_bytes["champion"] = workspace

    def _solve_arm(
        self,
        snapshot: CurriculumSnapshot,
        cohort: DynamicTaskCohort,
        tasks: Sequence[Mapping[str, Any]],
        binding: RuntimeBinding,
        *,
        arm_label: str,
        max_steps: int | None = None,
        evaluation_seed: int = 0,
        objective_override: ObjectiveVersion | None = None,
        mcp_bridge: McpBridge | None = None,
        mcp_candidate: Any | None = None,
        evaluation_design_id: str | None = None,
    ) -> Mapping[str, Any]:
        workspace = build_cohort_workspace(self._dynamic, tasks)
        self._arm_workspaces[arm_label] = workspace
        snapshot_context = dict(snapshot.to_mapping())
        if objective_override is not None:
            snapshot_context["objective"] = objective_override.to_mapping()
        evidence = self._run_role(
            Role.WARRIOR,
            objective=(
                "Solve the dynamic cohort inside the sandbox.  Use at most 12 tool steps, then "
                "write each solution under tasks/<task_id>/solution.py inside the workspace, run "
                "the public tests under tasks/<task_id>/tests/public, then submit one payload "
                "binding per-task artifact_id, solution summary, and public-test results.  Partial "
                "or imperfect solutions are acceptable and required to advance the cycle; never "
                "exceed the step budget without submitting.  If you identify a concrete, minimal, "
                "safe improvement to the harness cycle code that would help future runs, call "
                "aegis.propose_harness_change with base_commit and checkpoint_ref from the "
                "snapshot harness source and a bounded changes array; a proposal is candidate-only "
                "and never writes the host directly."
            ),
            context={
                "snapshot": _truncate(snapshot_context),
                "cohort": cohort.to_mapping(),
                "tasks": tasks,
                "arm": arm_label,
                "evaluation_seed": evaluation_seed,
                "mcp_candidate": (
                    None
                    if mcp_candidate is None
                    else {
                        "candidate_id": mcp_candidate.candidate_id,
                        "binding_id": mcp_candidate.binding.binding_id,
                        "server": mcp_candidate.manifest.name,
                        "tools": [
                            item.tool_name
                            for item in mcp_candidate.binding.authorizations
                        ],
                    }
                ),
                "workspace_layout": (
                    "tasks/<task_id>/solution.py",
                    "tasks/<task_id>/TASK.md",
                    "tasks/<task_id>/tests/public",
                ),
            },
            runtime_binding=binding,
            stage_workspace=workspace,
            freeze_workspace=True,
            max_steps=max_steps,
            request_seed=evaluation_seed,
            mcp_bridge=mcp_bridge,
            paired_design_id=evaluation_design_id,
            required_action_groups=(
                (frozenset({"strategy.propose"}),)
                if self._require_warrior_strategy_proposal
                else ()
            ),
        )
        artifact_id = evidence.get("workspace_artifact_id")
        size = evidence.get("workspace_size_bytes")
        if isinstance(artifact_id, str) and isinstance(size, int):
            self._arm_workspaces[arm_label] = self._artifacts.get(
                ArtifactRef("arm-workspace", artifact_id, size)
            )
        return {
            **evidence,
            "task_ids": [item["artifact_id"] for item in tasks],
            "arm": arm_label,
            "evaluation_seed": evaluation_seed,
        }

    def review(self, snapshot: CurriculumSnapshot, submission: ArtifactRef) -> Mapping[str, Any]:
        submission_data = _read(self._artifacts, submission)
        artifact_id = submission_data.get("workspace_artifact_id")
        size = submission_data.get("workspace_size_bytes")
        digest = submission_data.get("workspace_digest")
        workspace: bytes | None = None
        if (
            isinstance(artifact_id, str)
            and isinstance(size, int)
            and size > 0
            and isinstance(digest, str)
        ):
            try:
                workspace = self._artifacts.get(
                    ArtifactRef("arm-workspace", artifact_id, size)
                )
            except Exception:
                workspace = None
        evidence = self._run_role(
            Role.JUDGE,
            objective=(
                "Review the Warrior submission against the sealed cohort.  The frozen Warrior "
                "workspace is mounted read-only; first verify its digest matches workspace_digest, "
                "then inspect the real sources.  Assess correctness, quality, hidden-failure risk "
                "and the cost of the next experiment.  Submit one payload with bounded findings, "
                "quality_score in [0,1], and forecast{forecasts:[{task_artifact_id, "
                "failure_probability, confidence, evidence_coverage}], probes_run:[...], "
                "hidden_data_disclosed:false, workspace_binding:{workspace_digest, verified}}.  "
                "If the workspace cannot be inspected, set workspace_binding.verified=false and "
                "all evidence_coverage=0; never guess the source.  For every staged MCP candidate, "
                "include mcp_decisions[{candidate_id,decision,rationale}], where decision is "
                "approve, reject, or abstain; approval only admits an isolated experiment."
            ),
            stage_workspace=workspace,
            role_config=self._judge_role_config(
                snapshot.cycle_number, submission.artifact_id
            ),
            context={
                "snapshot": _truncate(snapshot.to_mapping()),
                "submission": _brief(self._artifacts, submission),
                "workspace_digest": digest,
                "task_artifact_ids": list(
                    submission_data.get("task_ids", [])
                    if isinstance(submission_data.get("task_ids"), list)
                    else []
                ),
            },
        )
        forecast = self._judge_forecast(evidence, digest)
        return {
            **evidence,
            "forecast": forecast,
            "quality_score": _score(
                evidence.get("submission", {}).get("quality_score")
            ),
        }

    def _judge_forecast(
        self, evidence: Mapping[str, Any], expected_digest: str | None
    ) -> Mapping[str, Any]:
        sub = evidence.get("submission")
        raw = sub.get("forecast") if isinstance(sub, Mapping) else None
        raw = raw if isinstance(raw, Mapping) else {}
        parsed: JudgeForecast | None = None
        try:
            parsed = JudgeForecast.from_mapping(
                {
                    key: raw[key]
                    for key in ("forecasts", "probes_run", "hidden_data_disclosed")
                    if key in raw
                }
            )
        except Exception:
            parsed = None
        binding = raw.get("workspace_binding")
        binding = binding if isinstance(binding, Mapping) else {}
        claimed_verified = bool(binding.get("verified", False))
        claimed_digest = binding.get("workspace_digest")
        verified = (
            claimed_verified
            and isinstance(claimed_digest, str)
            and isinstance(expected_digest, str)
            and claimed_digest == expected_digest
        )
        per_task: dict[str, float] = {}
        confidence = 0.5
        coverage = 0.0
        probes: list[str] = []
        if parsed is not None:
            forecasts = parsed.forecasts
            per_task = {
                item.task_artifact_id: _score(item.failure_probability)
                for item in forecasts
            }
            if forecasts:
                confidence = _score(
                    sum(float(item.confidence) for item in forecasts) / len(forecasts)
                )
                coverage = _score(
                    sum(float(item.evidence_coverage) for item in forecasts)
                    / len(forecasts)
                )
            probes = list(parsed.probes_run)
        return {
            "per_task_failure_probability": per_task,
            "confidence": confidence,
            "evidence_coverage": coverage if verified else 0.0,
            "probes": probes,
            "verified_workspace_binding": verified,
            "workspace_digest": expected_digest,
            "hidden_data_disclosed": bool(parsed.hidden_data_disclosed if parsed else False),
        }

    def _judge_role_config(self, cycle: int, evidence_id: str | None = None) -> RoleConfig:
        cfg = self._role_configs["judge"]
        if not self._judge_heterogeneous_model or self._judge_heterogeneous_fraction <= 0:
            return cfg
        digest_input = f"{cycle}:{evidence_id or ''}:judge-heterogeneous"
        sample = (
            int(hashlib.sha256(digest_input.encode("utf-8")).hexdigest(), 16) % 1000
        ) / 1000.0
        if sample < self._judge_heterogeneous_fraction:
            return replace(cfg, model=self._judge_heterogeneous_model)
        return cfg

    def calibrate(
        self,
        snapshot: CurriculumSnapshot,
        judge_review: ArtifactRef,
        quality_lock: ArtifactRef,
    ) -> Mapping[str, Any]:
        """Post-seal forecast calibration: Brier/ECE and false-positive/negative counts."""
        review = _read(self._artifacts, judge_review)
        lock = _read(self._artifacts, quality_lock)
        forecast = review.get("forecast") or {}
        probabilities = forecast.get("per_task_failure_probability") or {}
        tasks = (lock.get("evaluation") or {}).get("tasks") or []
        forecasts: list[TaskFailureForecast] = []
        outcomes: list[bool] = []
        predictions: list[Mapping[str, Any]] = []
        for task in tasks:
            artifact_id = str(task.get("artifact_id", ""))
            predicted = _score(probabilities.get(artifact_id, 0.5))
            score = float(task.get("score", 0.0))
            failed = score < 1.0
            outcomes.append(failed)
            try:
                forecasts.append(
                    TaskFailureForecast(
                        artifact_id,
                        predicted,
                        forecast.get("confidence", 0.5),
                        forecast.get("evidence_coverage", 0.0),
                    )
                )
            except Exception:
                continue
            predictions.append(
                {
                    "task_id": str(task.get("task_id", artifact_id)),
                    "artifact_id": artifact_id,
                    "tier": task.get("tier"),
                    "predicted_failure_probability": round(predicted, 6),
                    "actual_failed": failed,
                    "correct": (predicted >= 0.5) == failed,
                }
            )
        if not forecasts:
            calibration = JudgeCalibration(0, 0.0, 0.0, 0, 0)
        else:
            calibration = compute_calibration(
                tuple(forecasts),
                tuple(outcomes[: len(forecasts)]),
            )
        return {
            **calibration.to_mapping(),
            "sample_count": len(forecasts),
            "workspace_verified": bool(forecast.get("verified_workspace_binding")),
            "per_task": predictions,
            "basis": [judge_review.artifact_id, quality_lock.artifact_id],
        }

    def audit(
        self,
        snapshot: CurriculumSnapshot,
        submission: ArtifactRef,
        judge_review: ArtifactRef,
        quality_lock: ArtifactRef,
    ) -> Mapping[str, Any]:
        frozen = self._frozen_submissions.get("champion")
        workspace: bytes | None = None
        expected_digest: str | None = None
        if frozen is not None:
            expected_digest = frozen.workspace_digest
            workspace = self._frozen_workspace_bytes.get("champion")
            if workspace is None:
                try:
                    workspace = self._artifacts.get(
                        ArtifactRef(
                            "arm-workspace",
                            frozen.workspace_artifact_id,
                            frozen.workspace_size_bytes,
                        )
                    )
                except Exception:
                    workspace = None
        evidence = self._run_role(
            Role.PROSECUTOR,
            objective=(
                "Audit token consumption, evidence integrity and risk for this cycle.  The frozen "
                "Warrior workspace is mounted read-only; verify its digest matches the bound "
                "workspace_digest before drawing evidence conclusions.  Submit one payload with "
                "usage_verified, risk findings, and a structured curriculum hypothesis list for "
                "the next cycle.  Independently decide every staged MCP candidate using "
                "mcp_decisions[{candidate_id,decision,rationale}]; use reject as a veto."
            ),
            stage_workspace=workspace,
            context={
                "snapshot": _truncate(snapshot.to_mapping()),
                "submission": _brief(self._artifacts, submission),
                "judge_review": _brief(self._artifacts, judge_review),
                "quality_lock": _brief(self._artifacts, quality_lock),
                "workspace_digest": expected_digest,
            },
        )
        sub = evidence.get("submission", {})
        claimed_binding = bool(sub.get("verified_workspace_binding", False))
        claimed_digest = sub.get("workspace_digest")
        verified = (
            claimed_binding
            and isinstance(claimed_digest, str)
            and isinstance(expected_digest, str)
            and claimed_digest == expected_digest
        )
        return {
            **evidence,
            "verified_workspace_binding": verified,
            "workspace_digest": expected_digest,
            "curriculum": _strip_forbidden(sub.get("curriculum", [])),
            "role_candidates": _strip_forbidden(sub.get("role_candidates", {})),
            "usage_verified": bool(sub.get("usage_verified", False)),
        }
    def _diagnostic_brief(self, quality_lock: ArtifactRef) -> Mapping[str, Any]:
        """Sanitized sealed feedback: categories only, never per-case pass counts."""
        lock = _brief(self._artifacts, quality_lock)
        evaluation = lock.get("evaluation") or {}
        normalized = dict(lock)
        normalized["tasks"] = evaluation.get("tasks") or []
        return sanitize_diagnostic_quality(normalized)

    def reflect(
        self,
        role: Role,
        snapshot: CurriculumSnapshot,
        submission: ArtifactRef,
        judge_review: ArtifactRef,
        quality_lock: ArtifactRef,
        prosecutor_audit: ArtifactRef,
    ) -> Mapping[str, Any]:
        evidence = self._run_role(
            role,
            objective=(
                "Prepare an independent, role-scoped reflection for the council: what worked, "
                "what should change, and which next hypothesis deserves a test. If resources or "
                "governance setpoints constrained the work, include runtime_policy_requests as a "
                "list of {request_id,base_policy_id,patch,rationale,evidence_refs}; this is advisory "
                "and only the Prosecutor may apply it."
            ),
            restrict_actions=(
                frozenset({"submit", "strategy.propose", "aegis.adjust_runtime_policy"})
                if role is Role.PROSECUTOR
                else frozenset({"submit", "strategy.propose"})
            ),
            context={
                "snapshot": _truncate(snapshot.to_mapping()),
                "submission": _brief(self._artifacts, submission),
                "judge_review": _brief(self._artifacts, judge_review),
                "quality_lock": self._diagnostic_brief(quality_lock),
                "prosecutor_audit": _brief(self._artifacts, prosecutor_audit),
            },
        )
        summary = str(evidence.get("summary", ""))[:4096].strip()
        if not summary:
            raise ValueError("council reflection must contain a summary")
        claim = EvidenceClaim(
            claim_id=f"{role.value}-reflection-{snapshot.cycle_number}",
            statement=summary,
            evidence_refs=tuple(
                "sha256:" + ref.artifact_id.rsplit(":", 1)[1]
                for ref in (
                    submission,
                    judge_review,
                    quality_lock,
                    prosecutor_audit,
                )
            ),
            falsifier="A later sealed evaluation contradicts this reflection.",
            confidence=_score(evidence.get("submission", {}).get("confidence", 0.5)),
        )
        usage = evidence.get("usage", {})
        generation_usage = CouncilGenerationUsage(
            input_tokens=int(usage.get("input_tokens", 0)),
            output_tokens=int(usage.get("output_tokens", 0)),
            reasoning_tokens=int(usage.get("reasoning_tokens", 0)),
        )
        message = CouncilMessage(
            cycle_id=f"cycle:{snapshot.cycle_number}",
            sender=role,
            message_type=CouncilMessageType.REFLECTION,
            claims=(claim,),
            summary=summary,
            token_usage=estimate_content_tokens(summary, (claim,)),
            generation_usage=generation_usage,
        )
        requests = evidence.get("submission", {}).get("runtime_policy_requests", [])
        valid_requests: list[Mapping[str, Any]] = []
        if isinstance(requests, list):
            for item in requests:
                if (
                    isinstance(item, Mapping)
                    and set(item) == {"request_id", "base_policy_id", "patch", "rationale", "evidence_refs"}
                    and isinstance(item["request_id"], str)
                    and isinstance(item["base_policy_id"], str)
                    and isinstance(item["patch"], Mapping)
                    and bool(item["patch"])
                    and isinstance(item["rationale"], str)
                    and isinstance(item["evidence_refs"], list)
                    and all(isinstance(ref, str) and ref.strip() for ref in item["evidence_refs"])
                ):
                    valid_requests.append(dict(item))
        proposals = evidence.get("submission", {}).get("proposals", [])
        valid_proposals: list[Mapping[str, Any]] = []
        if isinstance(proposals, list):
            for item in proposals:
                if not isinstance(item, Mapping):
                    continue
                if not isinstance(item.get("proposal_id"), str) or not item["proposal_id"].strip():
                    continue
                if not isinstance(item.get("target_role"), str):
                    continue
                if not isinstance(item.get("content"), Mapping) or not item["content"]:
                    continue
                valid_proposals.append(
                    {
                        "proposal_id": item["proposal_id"][:256],
                        "target_role": item["target_role"],
                        "content": dict(item["content"]),
                        "rationale": str(item.get("rationale", ""))[:2000],
                        "expected_metric": str(item.get("expected_metric", ""))[:512],
                        "falsifier": str(item.get("falsifier", ""))[:1024],
                    }
                )
        return {
            **evidence,
            "role": role.value,
            "message": message.to_mapping(),
            "runtime_policy_requests": valid_requests,
            "proposals": valid_proposals,
        }

    def reflect_post(
        self,
        role: Role,
        snapshot: CurriculumSnapshot,
        submission: ArtifactRef,
        quality_lock: ArtifactRef,
        prosecutor_audit: ArtifactRef,
        judge_calibration: ArtifactRef,
        task_validation: ArtifactRef,
        candidate_evaluation: ArtifactRef,
        attribution: ArtifactRef,
        activation: ArtifactRef,
    ) -> Mapping[str, Any]:
        """Deterministic post-cycle postmortem derived from the full artifact graph.

        Postmortem runs after activation so it can name the real obligations:
        task supply, candidate evaluation, qualification and activation.  It is
        control-plane derived (no extra model call) and reuses the pre-cycle
        reflection claim id for recurrence linkage.
        """
        validation = _brief(self._artifacts, task_validation)
        candidates = _brief(self._artifacts, candidate_evaluation)
        qualification = _brief(self._artifacts, attribution)
        activation_data = _brief(self._artifacts, activation)
        failed_obligations: list[str] = []
        learning = validation.get("learning_outcome")
        if isinstance(learning, str) and learning in {"degraded", "blocked_by_supply"}:
            failed_obligations.append(f"task-supply:{learning}")
        if candidates.get("enabled") is False:
            failed_obligations.append("candidate-evaluation:skipped")
        elif candidates.get("qualification_pending") is None and candidates.get("rejection_pending") is None:
            failed_obligations.append("candidate-evaluation:no-qualified-candidate")
        if activation_data.get("unchanged") is True:
            failed_obligations.append("activation:unchanged")
        elif activation_data.get("intent_id") is None:
            failed_obligations.append("activation:not-attempted")
        if not failed_obligations:
            failed_obligations.append("none")
        statement = (
            f"Post-cycle postmortem for {role.value}: obligations "
            + ", ".join(failed_obligations)
            + "."
        )
        claim = EvidenceClaim(
            claim_id=f"{role.value}-postmortem-{snapshot.cycle_number}",
            statement=statement,
            evidence_refs=tuple(
                "sha256:" + ref.artifact_id.rsplit(":", 1)[1]
                for ref in (
                    submission,
                    quality_lock,
                    prosecutor_audit,
                    judge_calibration,
                    task_validation,
                    candidate_evaluation,
                    attribution,
                    activation,
                )
            ),
            falsifier="A replay of the same artifact graph contradicts this postmortem.",
            confidence=0.9,
        )
        return {
            "role": role.value,
            "claims": [claim.to_dict()],
            "proposals": [],
            "problem_id": claim.claim_id,
            "prior_problem_id": f"{role.value}-reflection-{snapshot.cycle_number}",
            "evidence_kind": EvidenceKind.OBSERVED.value,
            "evidence_refs": list(claim.evidence_refs),
            "failed_stage_or_obligation": failed_obligations,
            "proposed_change_id": None,
            "success_metric": "next cycle closes every named obligation",
            "confidence": 0.9,
            "falsifier": claim.falsifier,
        }

    def deliberate(
        self,
        snapshot: CurriculumSnapshot,
        reflections: tuple[ArtifactRef, ...],
        submission: ArtifactRef,
        judge_review: ArtifactRef,
        prosecutor_audit: ArtifactRef,
    ) -> Mapping[str, Any]:
        cycle_id = f"cycle:{snapshot.cycle_number}"
        council_max_messages = self._council_max_messages
        council_max_tokens = self._council_max_tokens
        transcript = CouncilTranscript(
            cycle_id,
            max_messages=council_max_messages,
            max_tokens=council_max_tokens,
        )
        reflection_payloads = [_read(self._artifacts, ref) for ref in reflections]
        reflection_proposals: list[Mapping[str, Any]] = []
        for payload in reflection_payloads:
            raw_proposals = payload.get("proposals", []) if isinstance(payload, Mapping) else []
            if isinstance(raw_proposals, list):
                for item in raw_proposals:
                    if isinstance(item, Mapping):
                        reflection_proposals.append(dict(item))
        for payload in reflection_payloads:
            transcript.append(CouncilMessage.from_mapping(payload["message"]))
        chair = self._run_role(
            Role.PROSECUTOR,
            objective=(
                "Act as council chair.  You may submit no objective amendment (proposal=null), "
                "or exactly one proposal with statement, success_criteria[{metric,minimum}], "
                "capability_tags, capability_weights for efficiency/generalization/quality/retention, "
                "and rationale.  The constitution cannot be changed. For every L2 MCP candidate, "
                "also include mcp_decisions[{candidate_id,decision,rationale}], where decision is "
                "approve, reject, or abstain. Treat any Prosecutor rejection as a veto. For every "
                "pending runtime-policy amendment submit exactly one runtime_policy_decisions entry "
                "{amendment_id,decision,reason,replacement_amendment_id}; decision is ratify, revise, "
                "or rollback. For revise/rollback first apply the compensating policy action and name "
                "its amendment id; ratify uses replacement_amendment_id=null."
            ),
            context={
                "snapshot": _truncate(snapshot.to_mapping()),
                "reflections": reflection_payloads,
                "warrior_submission": _brief(self._artifacts, submission),
                "judge_review": _brief(self._artifacts, judge_review),
                "prosecutor_audit": _brief(self._artifacts, prosecutor_audit),
                "pending_runtime_policy_amendments": (
                    [item.to_artifact_mapping() for item in self._runtime_policy_registry.pending_council_amendments()]
                    if self._runtime_policy_registry is not None
                    else []
                ),
            },
        )
        chair_submission = chair.get("submission", {})
        runtime_policy_decisions: list[Mapping[str, Any]] = []
        if self._runtime_policy_registry is not None:
            raw_decisions = (
                chair_submission.get("runtime_policy_decisions", [])
                if isinstance(chair_submission, Mapping)
                else []
            )
            pending_items = self._runtime_policy_registry.pending_council_amendments()
            pending = {item.amendment_id for item in pending_items}
            if pending:
                try:
                    validated_decisions = _validate_runtime_policy_council_decisions(
                        raw_decisions, pending
                    )
                except ValueError as exc:
                    decision_repair = self._run_role(
                        Role.PROSECUTOR,
                        objective=(
                            "Repair the runtime-policy council decision schema exactly once. "
                            "For every currently pending amendment submit exactly one "
                            "runtime_policy_decisions entry with amendment_id, decision, reason, "
                            "and replacement_amendment_id. decision must be ratify, revise, or "
                            "rollback. Ratify requires replacement_amendment_id=null; for revise "
                            "or rollback first apply a compensating policy action and cite its "
                            "amendment id. Do not omit, duplicate, or decide any non-pending id."
                        ),
                        context={
                            "pending_runtime_policy_amendments": [
                                item.to_artifact_mapping()
                                for item in self._runtime_policy_registry.pending_council_amendments()
                            ],
                            "invalid_runtime_policy_decisions": _truncate(raw_decisions),
                            "validation_error": str(exc)[:2000],
                        },
                    )
                    repaired_submission = decision_repair.get("submission", {})
                    raw_decisions = (
                        repaired_submission.get("runtime_policy_decisions", [])
                        if isinstance(repaired_submission, Mapping)
                        else []
                    )
                    pending = {
                        item.amendment_id
                        for item in self._runtime_policy_registry.pending_council_amendments()
                    }
                    validated_decisions = _validate_runtime_policy_council_decisions(
                        raw_decisions, pending
                    )
                for raw in validated_decisions:
                    runtime_policy_decisions.append(
                        self._runtime_policy_registry.record_council_decision(
                            amendment_id=cast(str, raw["amendment_id"]),
                            decision=cast(str, raw["decision"]),
                            reason=cast(str, raw["reason"]),
                            replacement_amendment_id=cast(
                                str | None, raw["replacement_amendment_id"]
                            ),
                        )
                    )
        mcp_decisions = (
            chair_submission.get("mcp_decisions", [])
            if isinstance(chair_submission, Mapping)
            and isinstance(chair_submission.get("mcp_decisions", []), list)
            else []
        )
        proposal_payload = chair.get("submission", {}).get("proposal")
        if proposal_payload is None:
            return {
                "chair": chair,
                "messages": [item.to_mapping() for item in transcript.messages],
                "amendment": None,
                "mcp_decisions": mcp_decisions,
                "runtime_policy_decisions": runtime_policy_decisions,
                "reflection_proposals": reflection_proposals,
            }
        repair: Mapping[str, Any] | None = None
        try:
            if not isinstance(proposal_payload, Mapping):
                raise ValueError("objective amendment proposal must be an object or null")
            amendment = self._parse_objective_amendment(snapshot, proposal_payload)
        except (TypeError, ValueError) as exc:
            repair = self._run_role(
                Role.PROSECUTOR,
                objective=(
                    "Repair the objective amendment schema exactly once. Submit proposal=null "
                    "or a complete structured proposal matching the requested fields."
                ),
                context={
                    "snapshot": _truncate(snapshot.to_mapping()),
                    "invalid_proposal": _truncate(proposal_payload),
                    "validation_error": str(exc)[:2000],
                },
            )
            repaired_payload = repair.get("submission", {}).get("proposal")
            if repaired_payload is None:
                return {
                    "chair": chair,
                    "schema_repair": repair,
                    "messages": [item.to_mapping() for item in transcript.messages],
                    "amendment": None,
                    "mcp_decisions": mcp_decisions,
                    "runtime_policy_decisions": runtime_policy_decisions,
                    "reflection_proposals": reflection_proposals,
                }
            if not isinstance(repaired_payload, Mapping):
                raise ValueError("repaired objective amendment must be an object or null")
            amendment = self._parse_objective_amendment(snapshot, repaired_payload)

        proposal_id = amendment.proposal_id
        proposal_summary = (
            amendment.rationale.strip() or "objective amendment proposed"
        )
        proposal_usage = chair.get("usage", {})
        proposal_message = CouncilMessage(
            cycle_id,
            Role.PROSECUTOR,
            CouncilMessageType.PROPOSAL,
            (),
            proposal_summary,
            proposal_id=proposal_id,
            proposal_kind=CouncilProposalKind.OBJECTIVE_AMENDMENT,
            token_usage=estimate_content_tokens(proposal_summary, ()),
            generation_usage=CouncilGenerationUsage(
                input_tokens=int(proposal_usage.get("input_tokens", 0)),
                output_tokens=int(proposal_usage.get("output_tokens", 0)),
                reasoning_tokens=int(proposal_usage.get("reasoning_tokens", 0)),
            ),
        )
        transcript.append(proposal_message)
        critiques: list[CouncilMessage] = []
        for role in (Role.WARRIOR, Role.JUDGE):
            evidence = self._run_role(
                role,
                objective=(
                    "Critique the proposed objective amendment against sealed evidence. "
                    "Submit summary and confidence."
                ),
                context={
                    "snapshot": _truncate(snapshot.to_mapping()),
                    "amendment": amendment.to_mapping(),
                    "messages": [item.to_mapping() for item in transcript.messages],
                },
            )
            summary = str(evidence.get("summary", "")).strip() or "critique recorded"
            critique_usage = evidence.get("usage", {})
            critique = CouncilMessage(
                cycle_id,
                role,
                CouncilMessageType.CRITIQUE,
                (),
                summary,
                proposal_id=proposal_id,
                parent_message_id=proposal_message.message_id,
                token_usage=estimate_content_tokens(summary, ()),
                generation_usage=CouncilGenerationUsage(
                    input_tokens=int(critique_usage.get("input_tokens", 0)),
                    output_tokens=int(critique_usage.get("output_tokens", 0)),
                    reasoning_tokens=int(critique_usage.get("reasoning_tokens", 0)),
                ),
            )
            transcript.append(critique)
            critiques.append(critique)
        for role in Role:
            vote_evidence = self._run_role(
                role,
                objective=(
                    "Vote independently on the objective amendment.  Submit a decision "
                    "equal to support, oppose, or abstain, plus a short summary."
                ),
                context={
                    "snapshot": _truncate(snapshot.to_mapping()),
                    "amendment": amendment.to_mapping(),
                    "messages": [item.to_mapping() for item in transcript.messages],
                },
            )
            decision = SupportDecision(
                str(vote_evidence.get("submission", {}).get("decision", "abstain"))
            )
            vote_summary = (
                str(vote_evidence.get("summary", "")).strip() or "vote recorded"
            )
            vote_usage = vote_evidence.get("usage", {})
            vote = CouncilMessage(
                cycle_id,
                role,
                CouncilMessageType.SUPPORT,
                (),
                vote_summary,
                proposal_id=proposal_id,
                support=decision,
                token_usage=estimate_content_tokens(vote_summary, ()),
                generation_usage=CouncilGenerationUsage(
                    input_tokens=int(vote_usage.get("input_tokens", 0)),
                    output_tokens=int(vote_usage.get("output_tokens", 0)),
                    reasoning_tokens=int(vote_usage.get("reasoning_tokens", 0)),
                ),
            )
            transcript.append(vote)
        return {
            "chair": chair,
            "schema_repair": repair,
            "messages": [item.to_mapping() for item in transcript.messages],
            "amendment": amendment.to_mapping(),
            "mcp_decisions": mcp_decisions,
            "runtime_policy_decisions": runtime_policy_decisions,
            "reflection_proposals": reflection_proposals,
        }

    @staticmethod
    def _parse_objective_amendment(
        snapshot: CurriculumSnapshot, proposal_payload: Mapping[str, Any]
    ) -> ObjectiveAmendment:
        criteria_payload = proposal_payload.get("success_criteria")
        weights = proposal_payload.get("capability_weights")
        tags = proposal_payload.get("capability_tags")
        if (
            not isinstance(criteria_payload, list)
            or not isinstance(weights, Mapping)
            or not isinstance(tags, list)
            or any(not isinstance(item, Mapping) for item in criteria_payload)
        ):
            raise ValueError("objective amendment has an invalid structured schema")
        criteria = tuple(
            sorted(
                (
                    ObjectiveSuccessCriterion.from_mapping(item)
                    for item in criteria_payload
                ),
                key=lambda item: item.metric,
            )
        )
        candidate_objective = ObjectiveVersion(
            snapshot.objective.version + 1,
            snapshot.constitution.constitution_id,
            str(proposal_payload.get("statement", "")).strip(),
            criteria,
            tuple(sorted(str(item).strip() for item in tags if str(item).strip())),
            weights,
            parent_objective_id=snapshot.objective.objective_id,
        )
        proposal_id = str(
            proposal_payload.get(
                "proposal_id", f"objective-{snapshot.cycle_number}-{candidate_objective.objective_id[-12:]}"
            )
        ).strip()
        return ObjectiveAmendment(
            proposal_id,
            snapshot.objective.objective_id,
            candidate_objective,
            snapshot.cycle_number + 1,
            str(proposal_payload.get("rationale", "")).strip(),
        )

    def _objective_history(self) -> list[Mapping[str, Any]]:
        if self._campaign_event_store is None:
            return []
        records: dict[str, Mapping[str, Any]] = {}
        campaign_id = self._curriculum.projection.campaign_id + "/objective-history"
        for event in self._campaign_event_store.read(campaign_id):
            if event.event_type != "objective_history_recorded_v1":
                continue
            payload = event.payload
            raw = payload.get("artifact")
            if not isinstance(raw, Mapping) or set(raw) != {
                "kind",
                "artifact_id",
                "size_bytes",
            }:
                raise RuntimeError("objective history event has an invalid artifact ref")
            ref = ArtifactRef(
                cast(str, raw["kind"]),
                cast(str, raw["artifact_id"]),
                cast(int, raw["size_bytes"]),
            )
            if ref.kind != "objective-history":
                raise RuntimeError("objective history event references the wrong artifact kind")
            item = _read(self._artifacts, ref)
            snapshot_id = item.get("snapshot_id")
            if not isinstance(snapshot_id, str):
                raise RuntimeError("objective history artifact has no snapshot identity")
            if snapshot_id in records and records[snapshot_id] != item:
                raise RuntimeError("objective history contains conflicting snapshot evidence")
            records[snapshot_id] = item
        return sorted(records.values(), key=lambda item: int(item["cycle_number"]))

    def _append_objective_history(
        self,
        snapshot: CurriculumSnapshot,
        cohort: DynamicTaskCohort,
        submission: ArtifactRef,
        quality_lock: ArtifactRef,
    ) -> None:
        if any(item["snapshot_id"] == snapshot.snapshot_id for item in self._objective_history()):
            return
        submission_data = _read(self._artifacts, submission)
        quality = _read(self._artifacts, quality_lock)
        record = {
            "snapshot_id": snapshot.snapshot_id,
            "cycle_number": snapshot.cycle_number,
            "cohort": cohort.to_mapping(),
            "quality_evaluation": quality["evaluation"],
            "usage": submission_data.get("usage", {}),
            "usage_verified": bool(submission_data.get("usage_verified", False)),
            "quality_evidence_id": quality_lock.artifact_id,
        }
        if self._campaign_event_store is None:
            raise RuntimeError("objective history requires the campaign EventStore")
        ref = self._artifacts.put_json("objective-history", record)
        campaign_id = self._curriculum.projection.campaign_id + "/objective-history"
        self._campaign_event_store.append(
            campaign_id,
            "objective_history_recorded_v1",
            {
                "artifact": {
                    "kind": ref.kind,
                    "artifact_id": ref.artifact_id,
                    "size_bytes": ref.size_bytes,
                }
            },
        )

    @staticmethod
    def _usage_cost(evidence: Mapping[str, Any]) -> int:
        usage = evidence.get("usage", {})
        if not isinstance(usage, Mapping):
            return 0
        return int(usage.get("input_tokens", 0)) + int(usage.get("output_tokens", 0))

    def _shadow_objective_on_history(
        self, amendment: ObjectiveAmendment
    ) -> tuple[ShadowObjectiveResult, ...]:
        results: list[ShadowObjectiveResult] = []
        history_window = int(
            self._policy_value("objective_history_window", self._objective_history_window)
        )
        history = self._objective_history()[-history_window:]
        for index, item in enumerate(history):
            snapshot = self._curriculum.projection.snapshots.get(str(item["snapshot_id"]))
            if snapshot is None or not bool(item.get("usage_verified", False)):
                continue
            cohort = DynamicTaskCohort.from_mapping(cast(Mapping[str, Any], item["cohort"]))
            tasks = _sealed_tasks(self._dynamic, cohort)
            binding = resolve_role_binding(
                artifacts=self._artifacts,
                evolution=self._evolution,
                active_identity=snapshot.active_roles.for_role(Role.WARRIOR),
                role=Role.WARRIOR,
                role_config=self._role_configs["warrior"],
                budget_policy_sha256=self._budget_policy_sha256,
                default_image=self._default_image,
                default_workflow_ref=self._default_workflow_ref,
                default_subject_ref=self._default_subject_ref,
            )
            label = f"objective-history-{snapshot.cycle_number}-{index}"
            solve = self._solve_arm(
                snapshot,
                cohort,
                tasks,
                binding,
                arm_label=label,
                max_steps=self._candidate_step_limit(),
                objective_override=amendment.candidate_objective,
            )
            workspace = self._arm_workspaces[label]
            evaluation = evaluate_frozen_workspace(
                self._dynamic,
                self._sandbox,
                workspace,
                str(solve["workspace_digest"]),
                tasks,
                namespace=f"objective-history-{snapshot.cycle_number}",
                policy=binding.control_core,
            )
            if not evaluation.integrity_passed or not bool(solve.get("usage_verified", False)):
                continue
            baseline_cost = self._usage_cost(item)
            candidate_cost = self._usage_cost(solve)
            baseline_metrics = _objective_metrics(
                cast(Mapping[str, Any], item["quality_evaluation"]),
                cost_units=baseline_cost,
                baseline_cost_units=baseline_cost,
            )
            candidate_metrics = _objective_metrics(
                _arm_evaluation_mapping(evaluation),
                cost_units=candidate_cost,
                baseline_cost_units=baseline_cost,
            )
            baseline_value = _objective_utility(amendment.candidate_objective, baseline_metrics)
            candidate_value = _objective_utility(amendment.candidate_objective, candidate_metrics)
            if baseline_value is None or candidate_value is None:
                continue
            candidate_utility, criteria_passed = candidate_value
            results.append(
                ShadowObjectiveResult(
                    amendment.proposed_objective_id,
                    snapshot.snapshot_id,
                    baseline_value[0],
                    candidate_utility if criteria_passed else 0.0,
                    0.01,
                )
            )
        return tuple(results)

    def _observe_probation(
        self,
        snapshot: CurriculumSnapshot,
        cohort: DynamicTaskCohort,
        submission: ArtifactRef,
        quality_lock: ArtifactRef,
    ) -> Mapping[str, Any] | None:
        projection = self._curriculum.projection
        if projection.probation_objective_id != snapshot.objective.objective_id:
            return None
        parent_id = projection.probation_parent_objective_id
        if parent_id is None:
            return None
        parent = projection.objectives[parent_id]
        tasks = _sealed_tasks(self._dynamic, cohort)
        label = f"objective-parent-{snapshot.cycle_number}"
        parent_solve = self._solve_arm(
            snapshot,
            cohort,
            tasks,
            self._bindings[Role.WARRIOR],
            arm_label=label,
            max_steps=self._candidate_step_limit(),
            objective_override=parent,
        )
        parent_eval = evaluate_frozen_workspace(
            self._dynamic,
            self._sandbox,
            self._arm_workspaces[label],
            str(parent_solve["workspace_digest"]),
            tasks,
            namespace=f"objective-parent-{snapshot.cycle_number}",
            policy=self._bindings[Role.WARRIOR].control_core,
        )
        actual = _read(self._artifacts, quality_lock)
        actual_submission = _read(self._artifacts, submission)
        parent_cost = self._usage_cost(parent_solve)
        actual_cost = self._usage_cost(actual_submission)
        baseline_value = _objective_utility(
            snapshot.objective,
            _objective_metrics(
                _arm_evaluation_mapping(parent_eval),
                cost_units=parent_cost,
                baseline_cost_units=parent_cost,
            ),
        )
        candidate_value = _objective_utility(
            snapshot.objective,
            _objective_metrics(
                cast(Mapping[str, Any], actual["evaluation"]),
                cost_units=actual_cost,
                baseline_cost_units=parent_cost,
            ),
        )
        passed = bool(
            parent_eval.integrity_passed
            and bool(parent_solve.get("usage_verified", False))
            and baseline_value is not None
            and candidate_value is not None
            and candidate_value[1]
            and candidate_value[0] >= baseline_value[0] - 0.01
        )
        if (
            self._objective_governance is not None
            and self._objective_governance.projection.probation_objective_id is not None
        ):
            self._objective_governance.observe_probation(
                GovernanceObjectiveEvidence(
                    objective_id=self._objective_governance.projection.probation_objective_id,
                    snapshot_id=snapshot.snapshot_id,
                    cycle_number=snapshot.cycle_number,
                    quality_passed=passed,
                    integrity_passed=parent_eval.integrity_passed,
                    regression_detected=not passed,
                    source_evidence_id=quality_lock.artifact_id,
                )
            )
        self._curriculum.observe_objective_probation(
            snapshot.objective.objective_id,
            snapshot_id=snapshot.snapshot_id,
            passed=passed,
            evidence_id=quality_lock.artifact_id,
        )
        action = "continue"
        if not passed:
            self._curriculum.rollback_objective(
                snapshot.objective.objective_id,
                parent_id,
                reason="probation paired shadow regressed",
            )
            active = self._roles.projection.current_active_set
            if active is not None and active.objective_id != parent_id:
                self._roles.rebind_objective(
                    parent_id,
                    evidence_id=quality_lock.artifact_id,
                    expected_current_active_set_id=active.active_role_set_id,
                )
            action = "rollback"
        elif len(self._curriculum.projection.probation_observations) >= cast(
            int, self._curriculum.projection.probation_required_cycles
        ):
            self._curriculum.graduate_objective(snapshot.objective.objective_id)
            action = "graduate"
        return {"passed": passed, "action": action, "parent_objective_id": parent_id}

    def _record_governed_objective(
        self,
        amendment: ObjectiveAmendment,
        messages: tuple[CouncilMessage, ...],
        shadows: tuple[ShadowObjectiveResult, ...],
        *,
        current_cycle: int,
        source_evidence_id: str,
        approve: bool,
        reason: str,
    ) -> bool:
        registry = self._objective_governance
        if registry is None:
            raise RuntimeError("objective governance registry is not configured")
        core = registry.projection.core
        active = registry.projection.active_objective
        if core is None or active is None:
            raise RuntimeError("objective governance genesis is incomplete")
        candidate = amendment.candidate_objective
        criteria = tuple(
            EvaluatorCriterion(
                item.metric,
                "objective-evaluator-sha256:"
                + hashlib.sha256(item.metric.encode("utf-8")).hexdigest(),
                item.minimum,
            )
            for item in candidate.success_criteria
        )
        adaptive = AdaptiveObjectiveVersion(
            version=active.version + 1,
            core_objective_id=core.core_objective_id,
            refinement=candidate.statement,
            criteria=criteria,
            weights={
                item.name: max(
                    1e-12,
                    float(candidate.capability_weights.get(item.name, 1.0)),
                )
                for item in criteria
            },
            capability_tags=tuple(sorted(candidate.capability_tags)),
            parent_objective_id=active.objective_id,
        )
        reflections = tuple(
            sorted(
                item.message_id
                for item in messages
                if item.message_type is CouncilMessageType.REFLECTION
            )
        )
        critiques = tuple(
            sorted(
                item.message_id
                for item in messages
                if item.message_type is CouncilMessageType.CRITIQUE
            )
        )
        governed = GovernanceObjectiveAmendment(
            adaptive,
            amendment.rationale,
            reflections,
            critiques,
        )
        registry.propose_amendment(governed)
        for shadow in shadows:
            historical = self._curriculum.projection.snapshots.get(
                shadow.historical_snapshot_id
            )
            if historical is None:
                raise RuntimeError("objective shadow references an unknown snapshot")
            registry.record_shadow_evidence(
                GovernanceObjectiveEvidence(
                    objective_id=adaptive.objective_id,
                    snapshot_id=shadow.historical_snapshot_id,
                    cycle_number=historical.cycle_number,
                    quality_passed=shadow.passes,
                    integrity_passed=True,
                    regression_detected=not shadow.passes,
                    source_evidence_id=source_evidence_id,
                )
            )
        registry.decide_amendment(
            adaptive.objective_id,
            actor=Role.PROSECUTOR,
            decision=(AmendmentDecision.APPROVE if approve else AmendmentDecision.REJECT),
            current_cycle=current_cycle,
            reason=reason,
        )
        return registry.projection.statuses.get(
            adaptive.objective_id
        ) is GovernanceObjectiveStatus.APPROVED

    def govern_objective(
        self,
        snapshot: CurriculumSnapshot,
        cohort: DynamicTaskCohort,
        submission: ArtifactRef,
        council: ArtifactRef,
        quality_lock: ArtifactRef,
    ) -> Mapping[str, Any]:
        council_data = _read(self._artifacts, council)
        messages = tuple(
            CouncilMessage.from_mapping(item)
            for item in cast(Sequence[Mapping[str, Any]], council_data.get("messages", ()))
        )
        amendment_raw = council_data.get("amendment")
        amendment = (
            ObjectiveAmendment.from_mapping(amendment_raw)
            if isinstance(amendment_raw, Mapping)
            else None
        )
        probation = self._observe_probation(snapshot, cohort, submission, quality_lock)
        if probation is not None or self._curriculum.projection.probation_objective_id is not None:
            amendment = None
        if amendment is None:
            outcome = CouncilOutcome(
                f"cycle:{snapshot.cycle_number}", messages, None, (), False, None
            )
            self._append_objective_history(snapshot, cohort, submission, quality_lock)
            return {**outcome.to_mapping(), "probation": probation}
        shadows = self._shadow_objective_on_history(amendment)
        quality = _read(self._artifacts, quality_lock)
        integrity_objection = not bool(
            cast(Mapping[str, Any], quality.get("evaluation", {})).get(
                "integrity_passed", False
            )
        )
        decision = evaluate_objective_amendment(
            amendment,
            messages,
            shadows,
            current_cycle=snapshot.cycle_number,
            integrity_objection=integrity_objection,
            required_history=int(self._policy_value("objective_history_window", self._objective_history_window)),
            probation_cycles=int(self._policy_value("objective_probation_cycles", self._objective_probation_cycles)),
        )
        try:
            governed_admitted = self._record_governed_objective(
                amendment,
                messages,
                shadows,
                current_cycle=snapshot.cycle_number,
                source_evidence_id=quality_lock.artifact_id,
                approve=decision.admitted,
                reason=decision.reason,
            )
        except ObjectiveGovernanceError:
            governed_admitted = False
        if decision.admitted and governed_admitted:
            if amendment.proposed_objective_id not in self._curriculum.projection.objectives:
                self._curriculum.provision_objective(amendment.candidate_objective)
            self._curriculum.start_objective_probation(
                amendment.proposed_objective_id,
                required_cycles=int(self._policy_value("objective_probation_cycles", self._objective_probation_cycles)),
                effective_cycle=amendment.effective_cycle,
            )
        outcome = CouncilOutcome(
            f"cycle:{snapshot.cycle_number}",
            messages,
            amendment,
            shadows,
            integrity_objection,
            decision,
        )
        self._append_objective_history(snapshot, cohort, submission, quality_lock)
        return {**outcome.to_mapping(), "probation": probation}

    def forge_next_tasks(
        self,
        snapshot: CurriculumSnapshot,
        submission: ArtifactRef,
        judge_review: ArtifactRef,
        quality_lock: ArtifactRef,
        prosecutor_audit: ArtifactRef,
        council: ArtifactRef,
    ) -> Mapping[str, Any]:
        repair_feedback: list[str] = []
        evidence: Mapping[str, Any] | None = None
        drafts: list[Mapping[str, Any]] = []
        builder = TaskPackBuilder(self._forge.registry, self._runner)
        authoring_attempts = int(
            self._policy_value("task_authoring_attempts", _TASK_AUTHORING_ATTEMPTS)
        )
        for attempt in range(1, authoring_attempts + 1):
            evidence = self._run_role(
                Role.JUDGE,
                role_config=self._judge_role_config(
                    snapshot.cycle_number, submission.artifact_id
                ),
                objective=(
                    "Declare at least one complete executable Python task-pack spec in the "
                    "final submit payload under task_specs. Every spec declares: task_id (a "
                    "new slug not present in reserved_task_ids), prompt, public_cases, "
                    "public_test (pytest source), hidden_cases, reference_solution, "
                    "defect_solution and mutants (name + solution). Every spec also declares "
                    "public contract clauses and binds each case to them: clauses=[{clause_id, "
                    "statement, input_partition, expected_outcome, security_relevant}], each "
                    "public/hidden case carries clause_ids, and defect_clause_ids lists the "
                    "clauses the defect violates. Hidden cases must never introduce semantics "
                    "absent from the declared clauses; the control plane rejects undeclared "
                    "hidden obligations. All content is plain "
                    "text or JSON; do not embed archives or base64. The control plane "
                    "materializes manifest, layout and content_hash, then validates that "
                    "the reference passes public and hidden suites, the defect is "
                    "detected, and the hidden suite kills every mutant. Read the workspace "
                    "template under templates/example-task/ for the expected structure and "
                    "semantics; you may run scratch checks with sandbox.exec, but the "
                    "authoritative deliverable is the task_specs array in your submit "
                    "payload. Keep the spec compact: at most 6 cases per suite, one "
                    "mutant, and each source file under 40 lines. Adapt the template to "
                    "the target function; do not restate unrelated context. Produce the "
                    "spec directly in your final message; do not narrate your plan."
                ),
                context={
                    "snapshot": _truncate(snapshot.to_mapping()),
                    "attempt": attempt,
                    "previous_validation_errors": repair_feedback[:32],
                    "taskpack_contract": {
                        "language": "python",
                        "deliverable": "submit payload task_specs",
                        "reserved_task_ids": sorted(builder.reserved_task_ids()),
                        "spec_schema": {
                            "task_id": "python-<new-slug>",
                            "prompt": "markdown task description",
                            "public_cases": {"version": 1, "cases": [{"name": "case-name", "clause_ids": ["FUNC.ARITHMETIC"], "steps": [{"op": "call", "symbol": "fn", "args": [1, 2], "expect": 3}]}]},
                            "public_test": "pytest source text",
                            "hidden_cases": {"version": 1, "cases": [{"name": "case-name", "clause_ids": ["FUNC.ARITHMETIC"], "steps": [{"op": "call", "symbol": "fn", "args": [1, 2], "expect": 3}]}]},
                            "clauses": [{"clause_id": "FUNC.ARITHMETIC", "statement": "fn(a,b) returns the arithmetic result", "input_partition": "positive/zero/negative", "expected_outcome": "return", "security_relevant": False}],
                            "defect_clause_ids": ["FUNC.ARITHMETIC"],
                            "reference_solution": "python source text",
                            "defect_solution": "python source text with a known defect",
                            "mutants": [{"name": "slug", "solution": "python source text"}],
                        },
                        "validation_contract": [
                            "reference passes public and hidden suites",
                            "defect is detected by at least one suite",
                            "hidden suite kills every mutant",
                        ],
                    },
                },
                freeze_workspace=True,
                freeze_max_bytes=128 * 1024 * 1024,
                stage_workspace=_task_authoring_seed_workspace(),
            )
            drafts, repair_feedback = self._inspect_task_specs(evidence)
            if any(bool(item.get("valid")) for item in drafts):
                return {
                    **evidence,
                    "authoring_attempt": attempt,
                    "drafts": drafts,
                    "declarative_only": True,
                }
        if evidence is None:  # pragma: no cover - loop is statically non-empty
            raise RuntimeError("task authoring did not run")
        return {
            **evidence,
            "authoring_attempt": authoring_attempts,
            "drafts": drafts,
            "authoring_errors": repair_feedback[:32],
            "declarative_only": True,
        }

    def _inspect_task_specs(
        self, evidence: Mapping[str, Any]
    ) -> tuple[list[Mapping[str, Any]], list[str]]:
        submission = evidence.get("submission")
        raw = submission.get("task_specs") if isinstance(submission, Mapping) else None
        if not isinstance(raw, list) or not raw:
            return [], [
                "submit payload task_specs is missing or empty: declare at least one task spec"
            ]
        builder = TaskPackBuilder(self._forge.registry, self._runner)
        drafts: list[Mapping[str, Any]] = []
        errors: list[str] = []
        for item in raw:
            label = str(item.get("task_id")) if isinstance(item, Mapping) else "?"
            try:
                spec = TaskSpec.from_mapping(item)
            except TaskSpecError as exc:
                drafts.append({"task_id": label, "valid": False, "reasons": [str(exc)]})
                errors.append(f"{label}: {exc}")
                continue
            try:
                valid, reasons = builder.dry_run(spec)
            except TaskSpecError as exc:
                valid, reasons = False, (str(exc),)
            except Exception as exc:
                valid, reasons = False, (f"{type(exc).__name__}: {exc}",)
            drafts.append({"task_id": spec.task_id, "valid": valid, "reasons": list(reasons)})
            errors.extend(f"{spec.task_id}: {reason}" for reason in reasons)
        return drafts, errors

    # -- control-plane ports -------------------------------------------------

    def lock_quality(
        self,
        snapshot: CurriculumSnapshot,
        cohort: DynamicTaskCohort,
        submission: ArtifactRef,
        judge_review: ArtifactRef,
    ) -> Mapping[str, Any]:
        review = _brief(self._artifacts, judge_review)
        advisory_score = _score(
            review.get("quality_score", review.get("submission", {}).get("quality_score"))
        )
        submission_data = _read(self._artifacts, submission)
        artifact_id = submission_data.get("workspace_artifact_id")
        size = submission_data.get("workspace_size_bytes")
        digest = submission_data.get("workspace_digest")
        if (
            not isinstance(artifact_id, str)
            or not isinstance(size, int)
            or size <= 0
            or not isinstance(digest, str)
        ):
            raise ValueError("Warrior submission has no frozen workspace evidence")
        workspace = self._artifacts.get(ArtifactRef("arm-workspace", artifact_id, size))
        tasks = _sealed_tasks(self._dynamic, cohort)
        evaluation = evaluate_frozen_workspace(
            self._dynamic,
            self._sandbox,
            workspace,
            digest,
            tasks,
            namespace=f"quality-{snapshot.cycle_number}",
            policy=self._bindings[Role.WARRIOR].control_core,
        )
        return {
            "locked": True,
            "score": evaluation.quality,
            "judge_advisory_score": round(advisory_score, 4),
            "basis": [submission.artifact_id, judge_review.artifact_id],
            "cohort": cohort.cohort_id,
            "evaluation": _arm_evaluation_mapping(evaluation),
        }

    def commit_curriculum_evidence(
        self,
        snapshot: CurriculumSnapshot,
        cohort: DynamicTaskCohort,
        quality_lock: ArtifactRef,
    ) -> Mapping[str, Any]:
        """Advance Fresh tasks only after cross-generation sealed execution.

        Warrior success is deliberately not the admission criterion: difficult
        but valid tasks must remain in the regression curriculum.  The pack is
        revalidated against its reference/defect/mutant contract; evaluator
        infrastructure exceptions abort the cycle and leave the task Fresh.
        """
        transitions: list[Mapping[str, Any]] = []
        for member in cohort.members:
            if member.tier is not CohortTier.FRESH_HOLDOUT:
                continue
            current = self._dynamic.record(member.artifact_id)
            if current.status is not DynamicTaskStatus.QUARANTINED:
                transitions.append(
                    {
                        "artifact_id": member.artifact_id,
                        "status": current.status.value,
                        "replayed": True,
                    }
                )
                continue
            archive = self._dynamic.archive(member.artifact_id)
            with tempfile.TemporaryDirectory(prefix="aegis-holdout-revalidate-") as directory:
                root = Path(directory).resolve(strict=True)
                self._forge._extract_untrusted_archive(archive, root)
                pack = TaskPack.load(root)
                report = validate_taskpack(pack, self._runner)
            validation_ref = self._artifacts.put_json(
                "holdout-validation",
                {
                    "artifact_id": member.artifact_id,
                    "snapshot_id": snapshot.snapshot_id,
                    "quality_evidence_id": quality_lock.artifact_id,
                    "validation": _taskpack_validation_mapping(report),
                },
            )
            transitions.append(
                {
                    "artifact_id": member.artifact_id,
                    "status": current.status.value,
                    "validation_reasons": list(report.reasons),
                    "validation_evidence_id": validation_ref.artifact_id,
                    "replayed": False,
                }
            )
        return {
            "snapshot_id": snapshot.snapshot_id,
            "quality_evidence_id": quality_lock.artifact_id,
            "transitions": transitions,
        }

    def commit_holdout_evidence(
        self,
        snapshot: CurriculumSnapshot,
        cohort: DynamicTaskCohort,
    ) -> Mapping[str, Any]:
        """Promote Fresh tasks only after the sealed candidate evaluation ran.

        Fresh holdout tasks must remain quarantined for the whole cycle so the
        candidate gate can use them as the sealed evaluation cohort; promoting
        them earlier would leave every later cycle without Fresh evidence.
        """

        transitions: list[Mapping[str, Any]] = []
        for member in cohort.members:
            if member.tier is not CohortTier.FRESH_HOLDOUT:
                continue
            current = self._dynamic.record(member.artifact_id)
            if current.status is not DynamicTaskStatus.QUARANTINED:
                transitions.append(
                    {
                        "artifact_id": member.artifact_id,
                        "status": current.status.value,
                        "replayed": True,
                    }
                )
                continue
            archive = self._dynamic.archive(member.artifact_id)
            with tempfile.TemporaryDirectory(prefix="aegis-holdout-commit-") as directory:
                root = Path(directory).resolve(strict=True)
                self._forge._extract_untrusted_archive(archive, root)
                pack = TaskPack.load(root)
                report = validate_taskpack(pack, self._runner)
            validation_ref = self._artifacts.put_json(
                "holdout-validation",
                {
                    "artifact_id": member.artifact_id,
                    "snapshot_id": snapshot.snapshot_id,
                    "validation": _taskpack_validation_mapping(report),
                },
            )
            held = self._dynamic.record_holdout(
                member.artifact_id,
                evaluated_generation=cohort.target_generation,
                accepted=report.valid,
                evidence_id=validation_ref.artifact_id,
                expected_revision=current.revision,
            )
            if report.valid:
                held = self._dynamic.promote_hall_of_fame(
                    member.artifact_id, expected_revision=held.revision
                )
            transitions.append(
                {
                    "artifact_id": member.artifact_id,
                    "status": held.status.value,
                    "replayed": False,
                }
            )
        return {
            "snapshot_id": snapshot.snapshot_id,
            "transitions": transitions,
        }

    def validate_forged_tasks(
        self, snapshot: CurriculumSnapshot, forged_tasks: ArtifactRef
    ) -> Mapping[str, Any]:
        forged = _read(self._artifacts, forged_tasks)
        submission = forged.get("submission")
        raw = submission.get("task_specs") if isinstance(submission, Mapping) else None
        required_fresh = 1
        if not isinstance(raw, list) or not raw:
            return self._task_validation_result((), (), required_fresh, no_specs=True)
        builder = TaskPackBuilder(self._forge.registry, self._runner)
        registered: list[Mapping[str, Any]] = []
        rejected: list[Mapping[str, Any]] = []
        proposal_limit = int(self._policy_value("task_proposals_per_cycle", _MAX_PROPOSALS))
        for item in raw[:proposal_limit]:
            try:
                spec = TaskSpec.from_mapping(item)
                record = builder.commit(
                    spec,
                    creator_generation=snapshot.cycle_number,
                    source_spec_id=f"judge:{forged_tasks.artifact_id}",
                    source_evidence_ids=(forged_tasks.artifact_id, snapshot.snapshot_id),
                    holdout_delay=int(
                        self._policy_value("task_holdout_delay_cycles", self._holdout_delay)
                    ),
                )
            except TaskSpecError as exc:
                label = str(item.get("task_id")) if isinstance(item, Mapping) else "?"
                rejected.append({"task_id": label, "reasons": [str(exc)]})
                continue
            except Exception as exc:
                label = str(item.get("task_id")) if isinstance(item, Mapping) else "?"
                rejected.append(
                    {"task_id": label, "reasons": [f"{type(exc).__name__}: {exc}"[:2048]]}
                )
                continue
            if record.status is DynamicTaskStatus.REJECTED:
                rejected.append(
                    {
                        "task_id": record.artifact.task_id,
                        "reasons": list(record.validation.reasons),
                    }
                )
            else:
                registered.append({
                    **record.artifact.to_mapping(),
                    "clause_coverage": spec.clause_summary(),
                })
        return self._task_validation_result(
            registered, rejected, required_fresh, no_specs=False
        )

    def _task_validation_result(
        self,
        registered: Sequence[Mapping[str, Any]],
        rejected: Sequence[Mapping[str, Any]],
        required_fresh_count: int,
        *,
        no_specs: bool,
    ) -> Mapping[str, Any]:
        """Classify the task-validation outcome without hiding supply failures."""
        registered_count = len(registered)
        rejected_count = len(rejected)
        if registered_count:
            status = "partially_registered" if rejected_count else "registered"
            learning_outcome = "progressed"
        elif no_specs:
            status = "no_valid_task"
            learning_outcome = "degraded"
        else:
            status = "no_valid_task"
            learning_outcome = "blocked_by_supply"
        return {
            "valid": registered_count > 0,
            "status": status,
            "registered": list(registered),
            "rejected": list(rejected),
            "declarative_only": True,
            "no_tasks_authored": registered_count == 0,
            "registered_count": registered_count,
            "rejected_count": rejected_count,
            "required_fresh_count": required_fresh_count,
            "learning_outcome": learning_outcome,
            "remediation_obligations": (
                ["forge at least one Fresh task in the next cycle"]
                if registered_count == 0
                else []
            ),
        }

    def _candidate_gate_cohort(
        self, cohort: DynamicTaskCohort
    ) -> DynamicTaskCohort | None:
        """Add fixed anchors only when Fresh evidence has no regression peer."""
        eligible = [
            member
            for member in cohort.members
            if self._dynamic.record(member.artifact_id).status
            is not DynamicTaskStatus.REJECTED
        ]
        if not any(member.tier is CohortTier.FRESH_HOLDOUT for member in eligible):
            return None
        if any(member.tier is CohortTier.HALL_OF_FAME for member in eligible):
            return DynamicTaskCohort.create(cohort.target_generation, tuple(eligible))
        members = list(eligible)
        known = {member.artifact_id for member in members}
        for record in self._dynamic.records():
            if (
                record.origin is DynamicTaskOrigin.FIXED_ANCHOR
                and record.status is DynamicTaskStatus.FIXED_ANCHOR
                and record.creator_generation < cohort.target_generation
                and record.artifact.artifact_id not in known
            ):
                members.append(
                    CohortMember(
                        record.artifact.artifact_id,
                        CohortTier.HALL_OF_FAME,
                        record.creator_generation,
                        record.revision,
                    )
                )
        if not any(member.tier is CohortTier.HALL_OF_FAME for member in members):
            return None
        ordered = tuple(sorted(members, key=lambda item: item.artifact_id))
        return DynamicTaskCohort.create(cohort.target_generation, ordered)

    @staticmethod
    def _mcp_decision(
        evidence: Mapping[str, Any], candidate_id: str
    ) -> tuple[str, str] | None:
        payload = evidence.get("submission", evidence)
        if not isinstance(payload, Mapping):
            return None
        decisions = payload.get("mcp_decisions", [])
        if not isinstance(decisions, list):
            return None
        for raw in decisions:
            if (
                isinstance(raw, Mapping)
                and raw.get("candidate_id") == candidate_id
                and raw.get("decision") in {"approve", "reject", "abstain"}
                and isinstance(raw.get("rationale"), str)
            ):
                return str(raw["decision"]), str(raw["rationale"])[:2000]
        return None

    def _mirror_mcp_status(
        self,
        candidate: McpCandidate,
        *,
        evolution_candidate_id: str,
        status: McpCandidateStatus,
        evidence_id: str,
        reason: str | None = None,
    ) -> None:
        if self._mcp_registry is None:
            raise RuntimeError("MCP evolution registry is not configured")
        lease = self._mcp_registry.acquire_lease("cycle-controller")
        try:
            self._mcp_registry.record_evolution_status(
                candidate,
                evolution_candidate_id=evolution_candidate_id,
                status=status,
                evidence_id=evidence_id,
                lease_token=lease.token,
                reason=reason,
            )
        finally:
            self._mcp_registry.release_lease(lease.token)

    @staticmethod
    def _mcp_max_risk(candidate: McpCandidate) -> McpRiskLevel:
        order = {
            McpRiskLevel.L0: 0,
            McpRiskLevel.L1: 1,
            McpRiskLevel.L2: 2,
            McpRiskLevel.L3: 3,
        }
        return max(
            (item.risk_level for item in candidate.binding.authorizations),
            key=order.__getitem__,
        )

    def evaluate_candidates(
        self,
        snapshot: CurriculumSnapshot,
        cohort: DynamicTaskCohort,
        submission: ArtifactRef,
        judge_review: ArtifactRef,
        prosecutor_audit: ArtifactRef,
        council: ArtifactRef,
        quality_lock: ArtifactRef,
        task_validation: ArtifactRef,
    ) -> Mapping[str, Any]:
        """Consume proposals, run one same-cycle paired shadow, and report."""
        result: dict[str, Any] = {
            "enabled": bool(
                self._evaluate_candidates_enabled and self._evolution is not None
            ),
            "collected": [],
            "validated": [],
            "rejected": [],
            "candidate": None,
            "shadow": None,
            "arms": None,
            "report": None,
            "role_generations": [],
        }
        if int(self._policy_value("candidate_evaluations_per_cycle", 1)) == 0:
            result["enabled"] = False
            result["disabled_reason"] = "runtime policy candidate evaluation budget is zero"
        if not result["enabled"]:
            return result
        assert self._evolution is not None
        submission_data = _brief(self._artifacts, submission)
        judge_data = _brief(self._artifacts, judge_review)
        audit_data = _brief(self._artifacts, prosecutor_audit)
        council_data = _brief(self._artifacts, council)
        collection_evidence_id = f"cycle:{snapshot.cycle_number}:candidate-evaluation"
        rollback_orders = tuple(consume_rollback_orders(submission_data)) + tuple(
            consume_rollback_orders(audit_data)
        )
        result["rollbacks"] = [
            self._execute_rollback_order(order) for order in rollback_orders
        ]
        council_reflection_proposals = council_data.get("reflection_proposals")
        if not isinstance(council_reflection_proposals, list):
            council_reflection_proposals = []
        consumed = consume_cycle_proposals(
            registry=self._evolution,
            artifacts=self._artifacts,
            submission=submission_data,
            prosecutor_audit=audit_data,
            objective_id=snapshot.objective.objective_id,
            collection_evidence_id=collection_evidence_id,
            meta_evolution_enabled=self._meta_evolution_enabled,
            reflections=[{"proposals": council_reflection_proposals}],
        )
        result["collected"] = [
            item.to_mapping() for item in consumed if item.collected
        ]
        result["rejected"] = [
            item.to_mapping()
            for item in consumed
            if not item.collected or not item.validated
        ]
        result["validated"] = [
            item.to_mapping() for item in consumed if item.validated
        ]
        probation_evolution_ids: set[str] = set()
        if self._mcp_registry is not None:
            probation_evolution_ids = {
                record.evolution_candidate_id
                for record in self._mcp_registry.projection.candidates.values()
                if record.status is McpCandidateStatus.PROBATION
            }
        candidate = next(
            (
                item
                for item in self._evolution.candidates()
                if item.candidate_id in probation_evolution_ids
                and item.target_role is Role.WARRIOR
            ),
            None,
        )
        if candidate is None:
            candidate = next(
                (
                    item
                    for item in self._evolution.validated_candidates()
                    if item.target_role is Role.WARRIOR
                ),
                None,
            )
        if candidate is None:
            result["role_generations"] = self._record_role_generations(snapshot)
            return result
        result["candidate"] = {
            "candidate_id": candidate.candidate_id,
            "surface": candidate.surface.value,
            "target_role": candidate.target_role.value,
            "artifact_id": candidate.artifact_id,
            "artifact_sha256": candidate.artifact_sha256,
        }
        mcp_candidate: McpCandidate | None = None
        mcp_probation_existing = candidate.candidate_id in probation_evolution_ids
        if candidate.surface is EvolutionSurface.MCP:
            mcp_candidate = McpCandidate.from_mapping(
                _load_json_artifact(self._artifacts, "mcp", candidate.artifact_id)
            )
            result["candidate"]["mcp_candidate_id"] = mcp_candidate.candidate_id
            result["candidate"]["mcp_binding_id"] = mcp_candidate.binding.binding_id
            if self._mcp_registry is None or self._mcp_bridge is None:
                raise RuntimeError("MCP candidate evaluation is not configured")
            if not mcp_probation_existing:
                self._mirror_mcp_status(
                    mcp_candidate,
                    evolution_candidate_id=candidate.candidate_id,
                    status=McpCandidateStatus.PROPOSED,
                    evidence_id=submission.artifact_id,
                )
                self._mirror_mcp_status(
                    mcp_candidate,
                    evolution_candidate_id=candidate.candidate_id,
                    status=McpCandidateStatus.VALIDATED,
                    evidence_id=collection_evidence_id,
                )
                judge_decision = self._mcp_decision(
                    judge_data, mcp_candidate.candidate_id
                )
                prosecutor_decision = self._mcp_decision(
                    audit_data, mcp_candidate.candidate_id
                )
                council_decision = self._mcp_decision(
                    council_data, mcp_candidate.candidate_id
                )
                risk = self._mcp_max_risk(mcp_candidate)
                admitted = (
                    judge_decision is not None
                    and judge_decision[0] == "approve"
                    and prosecutor_decision is not None
                    and prosecutor_decision[0] == "approve"
                    and risk is not McpRiskLevel.L3
                    and (
                        risk is not McpRiskLevel.L2
                        or (
                            council_decision is not None
                            and council_decision[0] == "approve"
                        )
                    )
                )
                result["mcp_governance"] = {
                    "judge": judge_decision,
                    "prosecutor": prosecutor_decision,
                    "council": council_decision,
                    "risk_level": risk.value,
                    "council_evidence_id": council.artifact_id,
                    "admitted": admitted,
                }
                if not admitted:
                    reason = (
                        "L3 MCP capabilities cross an unsupported host/external-risk "
                        "boundary and are rejected from autonomous activation"
                        if risk is McpRiskLevel.L3
                        else (
                            "L2 MCP candidate requires Judge, Prosecutor, and Council approval"
                            if risk is McpRiskLevel.L2
                            else "MCP candidate requires Judge and Prosecutor approval"
                        )
                    )
                    self._evolution.reject(candidate.candidate_id, reason=reason)
                    self._mirror_mcp_status(
                        mcp_candidate,
                        evolution_candidate_id=candidate.candidate_id,
                        status=McpCandidateStatus.REJECTED,
                        evidence_id=prosecutor_audit.artifact_id,
                        reason=reason,
                    )
                    result["rejected"].append(
                        {
                            "surface": "mcp",
                            "artifact_id": candidate.artifact_id,
                            "error": reason,
                        }
                    )
                    result["role_generations"] = self._record_role_generations(snapshot)
                    return result
            else:
                result["mcp_governance"] = {
                    "admitted": True,
                    "probation_replay": True,
                    "council_evidence_id": council.artifact_id,
                }
        evaluation_cohort = self._candidate_gate_cohort(cohort)
        if evaluation_cohort is None:
            result["activation"] = {
                "activated": False,
                "qualified": None,
                "reason": "candidate retained until a Fresh holdout cohort exists",
            }
            result["role_generations"] = self._record_role_generations(snapshot)
            return result
        if candidate.surface is EvolutionSurface.HARNESS_CODE:
            if self._harness_backend is None and (
                self._harness_canary is None or self._harness_repo is None
            ):
                self._evolution.reject(
                    candidate.candidate_id,
                    reason=(
                        "harness_code surface enabled but no harness repository "
                        "is configured"
                    ),
                )
                result["rejected"].append(
                    {
                        "surface": candidate.surface.value,
                        "target_role": candidate.target_role.value,
                        "artifact_id": candidate.artifact_id,
                        "error": "WSL harness backend is not configured",
                    }
                )
                result["role_generations"] = self._record_role_generations(snapshot)
                return result
            try:
                content = _load_json_artifact(
                    self._artifacts, "harness-code", candidate.artifact_id
                )
                if self._harness_backend is not None:
                    if self._harness_campaign_id is None:
                        raise RuntimeError("harness campaign identity is missing")
                    checkpoint = self._harness_backend.checkpoint(
                        self._harness_campaign_id,
                        candidate.candidate_id,
                        str(content["base_commit"]),
                        cast(Sequence[Mapping[str, Any]], content["changes"]),
                        f"checkpoint:{candidate.candidate_id.rsplit(':', 1)[1][:32]}",
                    )
                    if checkpoint.candidate_commit is None:
                        raise RuntimeError("WSL harness checkpoint omitted candidate commit")
                    validation = self._harness_backend.validate(
                        self._harness_campaign_id,
                        candidate.candidate_id,
                        checkpoint.candidate_commit,
                        f"validate:{candidate.candidate_id.rsplit(':', 1)[1][:32]}",
                    )
                    evidence_ref = self._artifacts.put_json(
                        "harness-validation",
                        {
                            "checkpoint": checkpoint.to_mapping(),
                            "validation": validation.to_mapping(),
                        },
                    )
                    result["harness_worktree"] = {
                        "candidate_commit": checkpoint.candidate_commit,
                        "champion_commit": checkpoint.champion_commit,
                        "evidence_id": evidence_ref.artifact_id,
                    }
                else:
                    assert self._harness_canary is not None
                    changes = changes_to_git_file_changes(content["changes"])
                    verdict = self._harness_canary.run(content, changes)
                    evidence_ref = self._artifacts.put_json(
                        "harness-canary", verdict.to_mapping()
                    )
                    result["harness_canary"] = {
                        "passed": verdict.passed,
                        "reason": verdict.reason,
                        "evidence_id": evidence_ref.artifact_id,
                    }
                    if not verdict.passed:
                        raise HarnessEvolutionError(
                            f"harness canary failed: {verdict.reason}"
                        )
            except (
                HarnessEvolutionError,
                HarnessBackendError,
                RuntimeError,
                ValueError,
                TypeError,
                KeyError,
            ) as exc:
                self._evolution.reject(
                    candidate.candidate_id,
                    reason=f"harness validation failed: {type(exc).__name__}: {exc}",
                )
                result["rejected"].append(
                    {
                        "surface": candidate.surface.value,
                        "target_role": candidate.target_role.value,
                        "artifact_id": candidate.artifact_id,
                        "error": f"harness validation failed: {type(exc).__name__}: {exc}",
                    }
                )
                result["role_generations"] = self._record_role_generations(snapshot)
                return result
        if candidate.surface is EvolutionSurface.ENVIRONMENT:
            if self._environment_builder is None:
                self._evolution.reject(
                    candidate.candidate_id,
                    reason="environment surface enabled but no environment builder is configured",
                )
                result["rejected"].append(
                    {
                        "surface": candidate.surface.value,
                        "target_role": candidate.target_role.value,
                        "artifact_id": candidate.artifact_id,
                        "error": "environment builder is not configured",
                    }
                )
                result["role_generations"] = self._record_role_generations(snapshot)
                return result
            try:
                recipe_payload = _load_json_artifact(
                    self._artifacts, "environment", candidate.artifact_id
                )
                recipe = validate_environment_content(recipe_payload)
                build_receipt = self._environment_builder.build(recipe)
            except Exception as exc:
                self._evolution.reject(
                    candidate.candidate_id,
                    reason=f"environment build failed: {type(exc).__name__}: {exc}",
                )
                result["rejected"].append(
                    {
                        "surface": candidate.surface.value,
                        "target_role": candidate.target_role.value,
                        "artifact_id": candidate.artifact_id,
                        "error": f"environment build failed: {type(exc).__name__}: {exc}",
                    }
                )
                result["role_generations"] = self._record_role_generations(snapshot)
                return result
            receipt_ref = self._artifacts.put_json(
                "environment",
                {
                    "output_image": build_receipt.output_image,
                    "recipe_id": build_receipt.recipe_id,
                    "build_receipt_id": build_receipt.receipt_id,
                    "provenance_sha256": build_receipt.provenance_sha256,
                    "vulnerability_report_sha256": build_receipt.vulnerability_report_sha256,
                    "reproducible": build_receipt.reproducible,
                    "scanner_passed": build_receipt.scanner_passed,
                },
            )
            candidate = self._evolution.attach_materialized_artifact(
                candidate.candidate_id,
                materialized_artifact_id=receipt_ref.artifact_id,
                materialized_artifact_sha256=receipt_ref.artifact_id.rsplit(":", 1)[1],
                materialization_evidence_id=collection_evidence_id,
            )
            result["environment_build"] = {
                "output_image": build_receipt.output_image,
                "receipt_artifact_id": receipt_ref.artifact_id,
                "reproducible": build_receipt.reproducible,
                "scanner_passed": build_receipt.scanner_passed,
            }
            result["candidate"]["artifact_id"] = candidate_environment_artifact_id(
                candidate
            )
        champion_binding = champion_binding_for_role(
            artifacts=self._artifacts,
            evolution=self._evolution,
            role=Role.WARRIOR,
            role_config=self._role_configs["warrior"],
            budget_policy_sha256=self._budget_policy_sha256,
            default_image=self._default_image,
            default_workflow_ref=self._default_workflow_ref,
            default_subject_ref=self._default_subject_ref,
        )
        candidate_runtime = (
            champion_binding
            if candidate.surface is EvolutionSurface.HARNESS_CODE
            else candidate_binding(
                champion=champion_binding,
                candidate=candidate,
                artifacts=self._artifacts,
                role=Role.WARRIOR,
            )
        )
        if mcp_candidate is not None:
            assert self._mcp_bridge is not None
            try:
                catalog_receipt = self._mcp_bridge.with_candidate(mcp_candidate)
            except McpBridgeError as exc:
                reason = f"MCP catalog validation failed: {exc}"
                if not mcp_probation_existing:
                    self._evolution.reject(candidate.candidate_id, reason=reason)
                    self._mirror_mcp_status(
                        mcp_candidate,
                        evolution_candidate_id=candidate.candidate_id,
                        status=McpCandidateStatus.REJECTED,
                        evidence_id=collection_evidence_id,
                        reason=reason,
                    )
                result["rejected"].append(
                    {
                        "surface": "mcp",
                        "artifact_id": candidate.artifact_id,
                        "error": reason,
                    }
                )
                result["role_generations"] = self._record_role_generations(snapshot)
                return result
            del catalog_receipt
        assert evaluation_cohort is not None
        tasks = _sealed_tasks(self._dynamic, evaluation_cohort)
        active_control_core = champion_binding.control_core
        promotion = active_control_core.promotion_gate
        gate_policy = CandidateGatePolicy(
            required_seeds=promotion.required_seeds,
            fresh_improvement=(
                0.0
                if candidate.surface is EvolutionSurface.CONTROL_CORE
                else promotion.fresh_improvement
            ),
            regression_noninferiority_margin=(
                promotion.regression_noninferiority_margin
            ),
            max_total_cost_increase=promotion.max_total_cost_increase,
            enforce_cost_limit=promotion.enforce_cost_limit,
        )
        evaluator_fingerprint = "sealed-evaluator-sha256:" + hashlib.sha256(
            canonical_json(
                {
                    "implementation": "aegis-public-hidden-independent-v2",
                    "control_core_policy_id": active_control_core.policy_id,
                    "sealed_evaluator": (
                        active_control_core.sealed_evaluator.to_mapping()
                    ),
                    "task_sandbox": active_control_core.task_sandbox.to_mapping(),
                }
            ).encode("utf-8")
        ).hexdigest()
        active_roles = self._roles.projection.current_active_set
        if active_roles is None:
            raise RuntimeError("candidate evaluation requires active role identities")
        design_boundary = RuntimeStageBoundary(
            snapshot.cycle_number,
            self._runtime_stage_ordinal,
            f"stage:{self._runtime_stage_ordinal}",
        )
        design_runtime_policy_id = (
            self._runtime_policy_registry.effective_for_stage(design_boundary).policy_id
            if self._runtime_policy_registry is not None
            else "runtime-policy-sha256:" + self._budget_policy_sha256
        )
        design = CandidateEvaluationDesign.create(
            campaign_id=snapshot.campaign_id,
            cycle_id=f"cycle:{snapshot.cycle_number}",
            snapshot_id=snapshot.snapshot_id,
            objective_id=snapshot.objective.objective_id,
            candidate_id=candidate.candidate_id,
            surface=candidate.surface.value,
            target_role=candidate.target_role.value,
            cohort_id=evaluation_cohort.cohort_id,
            tasks=tuple(
                sorted(
                    (
                        EvaluationTaskBinding(
                            str(item["task_id"]),
                            str(item["artifact_id"]),
                            int(item["task_version"]),
                            (
                                EvaluationTier.FRESH
                                if item["tier"] == "fresh-holdout"
                                else EvaluationTier.REGRESSION
                            ),
                            str(item["content_hash"]),
                        )
                        for item in tasks
                    ),
                    key=lambda item: (item.artifact_id, item.revision),
                )
            ),
            seeds=(0, 1),
            baseline_runtime_id=active_roles.for_role(Role.WARRIOR).role_version_id,
            candidate_runtime_id=candidate.candidate_id,
            runtime_policy_id=design_runtime_policy_id,
            evaluator_fingerprint=evaluator_fingerprint,
            public_weight=active_control_core.sealed_evaluator.public_weight,
            hidden_weight=active_control_core.sealed_evaluator.hidden_weight,
            gate_policy_sha256=hashlib.sha256(
                canonical_json(gate_policy.to_mapping()).encode("utf-8")
            ).hexdigest(),
        )
        design_ref = self._artifacts.put_json(
            "candidate-evaluation-design", design.to_mapping(include_id=False)
        )
        if design_ref.artifact_id != design.design_id:
            raise RuntimeError("candidate evaluation design CAS identity mismatch")
        if self._runtime_policy_registry is not None:
            self._runtime_policy_registry.freeze_for_paired_design(
                design.design_id,
                snapshot.cycle_number,
                boundary=design_boundary,
            )
        result["evaluation_design"] = {
            **design.to_mapping(),
            "artifact_id": design_ref.artifact_id,
        }
        observations: list[PairedObservation] = []
        gate_pairs: list[SealedCandidatePair] = []
        arm_rows: list[dict[str, Any]] = []
        shadow_rows: list[dict[str, Any]] = []
        candidate_evaluation_policy = ControlCorePolicy(
            active_control_core.sealed_evaluator,
            active_control_core.promotion_gate,
            candidate_runtime.control_core.task_sandbox,
        )
        for seed in (0, 1):
            champion_label = f"candidate-baseline-{seed}"
            candidate_label = f"candidate-shadow-{seed}"
            baseline_solve = self._solve_arm(
                snapshot,
                evaluation_cohort,
                tasks,
                champion_binding,
                arm_label=champion_label,
                max_steps=self._candidate_step_limit(),
                evaluation_seed=seed,
                evaluation_design_id=design.design_id,
            )
            candidate_mcp_bridge = None
            if mcp_candidate is not None:
                assert self._mcp_bridge is not None
                candidate_mcp_bridge = self._mcp_bridge.with_candidate(mcp_candidate)
            shadow = self._solve_arm(
                snapshot,
                evaluation_cohort,
                tasks,
                candidate_runtime,
                arm_label=candidate_label,
                max_steps=self._candidate_step_limit(),
                evaluation_seed=seed,
                mcp_bridge=candidate_mcp_bridge,
                mcp_candidate=mcp_candidate,
                evaluation_design_id=design.design_id,
            )
            treatment_integrity_passed = True
            if mcp_candidate is not None:
                assert candidate_mcp_bridge is not None
                treatment_integrity_passed = candidate_mcp_bridge.candidate_was_used(
                    mcp_candidate.binding.binding_id
                )
            baseline_workspace = self._arm_workspaces[champion_label]
            candidate_workspace = self._arm_workspaces[candidate_label]
            baseline_eval = evaluate_frozen_workspace(
                self._dynamic,
                self._sandbox,
                baseline_workspace,
                str(baseline_solve.get("workspace_digest", "")),
                tasks,
                namespace=f"candidate-baseline-{snapshot.cycle_number}-{seed}",
                policy=active_control_core,
            )
            candidate_eval = evaluate_frozen_workspace(
                self._dynamic,
                self._sandbox,
                candidate_workspace,
                str(shadow.get("workspace_digest", "")),
                tasks,
                namespace=f"candidate-shadow-{snapshot.cycle_number}-{seed}",
                policy=candidate_evaluation_policy,
            )
            baseline_sealed = self._persist_sealed_arm_evidence(
                design=design,
                seed=seed,
                arm="baseline",
                evaluation=baseline_eval,
                solve_evidence=baseline_solve,
                runtime_binding=champion_binding,
                runtime_id=design.baseline_runtime_id,
            )
            candidate_sealed = self._persist_sealed_arm_evidence(
                design=design,
                seed=seed,
                arm="candidate",
                evaluation=candidate_eval,
                solve_evidence=shadow,
                runtime_binding=candidate_runtime,
                runtime_id=design.candidate_runtime_id,
                treatment_integrity_passed=treatment_integrity_passed,
            )
            champion_arm = self._paired_arm(
                snapshot,
                champion_binding,
                baseline_eval,
                baseline_solve,
                candidate=False,
                seed=seed,
                mcp_binding_ids=tuple(
                    item.binding.binding_id for item in champion_binding.mcps
                ),
            )
            candidate_arm = self._paired_arm(
                snapshot,
                candidate_runtime,
                candidate_eval,
                shadow,
                candidate=True,
                seed=seed,
                mcp_binding_ids=tuple(
                    item.binding.binding_id for item in candidate_runtime.mcps
                ),
                treatment_integrity_passed=treatment_integrity_passed,
            )
            observations.append(
                PairedObservation.create("warrior", champion_arm, candidate_arm)
            )
            gate_pairs.append(
                SealedCandidatePair(
                    seed,
                    self._sealed_candidate_arm(
                        baseline_eval,
                        baseline_solve,
                        sealed_evidence=baseline_sealed,
                        cohort_id=evaluation_cohort.cohort_id,
                        runtime_policy_id=design.runtime_policy_id,
                    ),
                    self._sealed_candidate_arm(
                        candidate_eval,
                        shadow,
                        treatment_integrity_passed=treatment_integrity_passed,
                        sealed_evidence=candidate_sealed,
                        cohort_id=evaluation_cohort.cohort_id,
                        runtime_policy_id=design.runtime_policy_id,
                    ),
                )
            )
            arm_rows.append(
                {
                    "seed": seed,
                    "champion": champion_arm.to_mapping(),
                    "candidate": candidate_arm.to_mapping(),
                    "sealed_pair": gate_pairs[-1].to_mapping(),
                    "baseline_sealed_evidence_id": baseline_sealed.evidence_id,
                    "candidate_sealed_evidence_id": candidate_sealed.evidence_id,
                }
            )
            shadow_rows.append(
                {
                    "seed": seed,
                    "usage": shadow.get("usage"),
                    "workspace_digest": shadow.get("workspace_digest"),
                    "mcp_call_receipts": shadow.get("mcp_call_receipts", []),
                    "treatment_integrity_passed": treatment_integrity_passed,
                }
            )
        policy = QualificationPolicy(minimum_pairs=2)
        report = qualify_attribution(observations, policy)
        gate_report = evaluate_candidate_gate(gate_pairs, gate_policy)
        if not gate_report.qualified and report.qualified:
            report = AttributionReport.create(
                disposition=AttributionDisposition.NOT_QUALIFIED,
                qualification_path=QualificationPath.NONE,
                reason=f"sealed candidate gate rejected: {gate_report.reason}",
                observation_ids=[item.observation_id for item in observations],
                policy=policy,
                quality_delta=report.quality_delta,
                cost_change=report.cost_change,
            )
        gate_evidence = self._artifacts.put_json(
            "candidate-gate", gate_report.to_mapping()
        )
        result["shadow"] = shadow_rows
        result["arms"] = {
            "champion": arm_rows[0]["champion"],
            "candidate": arm_rows[0]["candidate"],
            "pairs": arm_rows,
        }
        result["report"] = report.to_mapping()
        result["candidate_gate"] = {
            **gate_report.to_mapping(),
            "evidence_id": gate_evidence.artifact_id,
        }
        if gate_report.qualified:
            result["qualification_pending"] = {
                "candidate_id": candidate.candidate_id,
                "gate_evidence_id": gate_evidence.artifact_id,
                "mcp_candidate_id": (
                    mcp_candidate.candidate_id if mcp_candidate is not None else None
                ),
                "mcp_probation_existing": mcp_probation_existing,
                "mcp_risk_level": (
                    self._mcp_max_risk(mcp_candidate).value
                    if mcp_candidate is not None
                    else None
                ),
                "harness_candidate_commit": (
                    cast(Mapping[str, Any], result.get("harness_worktree", {})).get(
                        "candidate_commit"
                    )
                    if candidate.surface is EvolutionSurface.HARNESS_CODE
                    else None
                ),
                "harness_expected_champion": (
                    cast(Mapping[str, Any], result.get("harness_worktree", {})).get(
                        "champion_commit"
                    )
                    if candidate.surface is EvolutionSurface.HARNESS_CODE
                    else None
                ),
            }
            result["activation"] = {
                "activated": False,
                "qualified": candidate.candidate_id,
                "reason": "durable candidate evaluation must precede qualification",
            }
        else:
            result["rejection_pending"] = {
                "candidate_id": candidate.candidate_id,
                "reason": gate_report.reason,
                "mcp_candidate_id": (
                    mcp_candidate.candidate_id if mcp_candidate is not None else None
                ),
                "mcp_probation_existing": mcp_probation_existing,
            }
            result["activation"] = {
                "activated": False,
                "qualified": None,
                "reason": (
                    gate_report.reason
                ),
            }
        result["role_generations"] = self._record_role_generations(snapshot)
        return result

    def _register_population(
        self,
        candidate: Any,
        *,
        evidence_id: str,
    ) -> Mapping[str, Any] | None:
        """Register one qualified candidate in the MAP-Elites archive."""
        if self._population is None:
            return None
        self._population.set_max_cells(
            int(self._policy_value("population_max_cells", 256))
        )
        try:
            content = _load_json_artifact(
                self._artifacts, candidate.surface.value, candidate.artifact_id
            )
        except (KeyError, ValueError, TypeError):
            return None
        if not isinstance(content, Mapping):
            return None
        roots = behavior_roots(content, surface=candidate.surface)
        cell = behavior_descriptor(
            surface=candidate.surface,
            changed_roots=roots,
            failure_mode=content.get("failure_mode_targeted"),
            objective=str(content.get("objective", "")),
        )
        entry = self._population.register(
            candidate_id=candidate.candidate_id,
            cell=cell,
            fitness=1.0,
            evidence_id=evidence_id,
            descriptor=cell,
        )
        return entry.to_mapping()

    def _execute_rollback_order(self, order: RollbackOrder) -> Mapping[str, Any]:
        """Execute one Prosecutor rollback order against the live harness repo
        and the evolution registry, fail-closed when the order cannot be
        verified against the current champion."""
        if self._harness_rollback is None or self._evolution is None:
            return {
                "order_id": order.order_id,
                "executed": False,
                "error": "harness rollback executor is not configured",
            }
        champion = self._evolution.champion(
            EvolutionSurface.HARNESS_CODE, Role.WARRIOR
        )
        if champion is None or champion.candidate_id != order.candidate_id:
            return {
                "order_id": order.order_id,
                "executed": False,
                "error": (
                    "rollback candidate is not the active harness champion"
                ),
            }
        try:
            content = _load_json_artifact(
                self._artifacts, "harness-code", champion.artifact_id
            )
            outcome = self._harness_rollback.execute(
                order, base_commit=content["base_commit"]
            )
        except (HarnessEvolutionError, ValueError, TypeError, KeyError) as exc:
            return {
                "order_id": order.order_id,
                "executed": False,
                "error": f"{type(exc).__name__}: {exc}",
            }
        try:
            self._evolution.rollback(
                EvolutionSurface.HARNESS_CODE,
                Role.WARRIOR,
                reason=order.reason[:2000],
                expected_champion_id=order.candidate_id,
            )
        except EvolutionRegistryError as exc:
            return {
                "order_id": order.order_id,
                "executed": True,
                "restored_commit": outcome["restored_commit"],
                "evidence_id": outcome["evidence_id"],
                "registry_rollback_error": str(exc),
            }
        return {
            "order_id": order.order_id,
            "executed": True,
            "restored_commit": outcome["restored_commit"],
            "evidence_id": outcome["evidence_id"],
            "analysis": order.analysis[:4000],
        }

    def _paired_arm(
        self,
        snapshot: CurriculumSnapshot,
        binding: RuntimeBinding,
        evaluation: Any,
        solve_evidence: Mapping[str, Any],
        *,
        candidate: bool,
        seed: int = 0,
        mcp_binding_ids: tuple[str, ...] = (),
        treatment_integrity_passed: bool = True,
    ) -> EvaluationArm:
        active = self._roles.projection.current_active_set
        if active is None:
            raise RuntimeError("role genesis must precede paired attribution")
        warrior_identity = active.for_role(Role.WARRIOR)
        role_generation_items: list[AttributionRoleGeneration] = []
        for role in Role:
            identity = active.for_role(role)
            generation_id = identity.role_version_id
            version = identity.version
            if role is Role.WARRIOR and candidate and binding.manifest is not None:
                digest = hashlib.sha256(
                    canonical_json(binding.manifest.to_mapping()).encode("utf-8")
                ).hexdigest()
                generation_id = f"role-version-sha256:{digest}"
                version = warrior_identity.version + 1
            role_generation_items.append(
                AttributionRoleGeneration(role.value, version, generation_id)
            )
        role_generations: tuple[AttributionRoleGeneration, ...] = tuple(
            sorted(role_generation_items, key=lambda item: item.role)
        )
        usage = solve_evidence.get("usage", {})
        cost = int(usage.get("input_tokens", 0)) + int(usage.get("output_tokens", 0))
        return EvaluationArm(
            cycle_id=f"cycle:{snapshot.cycle_number}",
            objective_id=snapshot.objective.objective_id,
            task_id=f"objective:{snapshot.objective.objective_id}",
            seed=seed,
            model_id=self._role_configs["warrior"].model,
            environment_id=self._environment_id,
            plugin_ids=tuple(sorted(item.artifact_id for item in binding.plugins)),
            role_generations=role_generations,
            quality=evaluation.quality,
            cost_units=cost,
            usage_verified=bool(solve_evidence.get("usage_verified", False)),
            safety_passed=evaluation.integrity_passed and treatment_integrity_passed,
            integrity_passed=evaluation.integrity_passed and treatment_integrity_passed,
            runtime_variant=binding.runtime_variant(),
            mcp_binding_ids=tuple(sorted(set(mcp_binding_ids))),
        )

    @staticmethod
    def _sealed_candidate_arm(
        evaluation: Any,
        solve_evidence: Mapping[str, Any],
        *,
        treatment_integrity_passed: bool = True,
        sealed_evidence: SealedArmEvidence | None = None,
        cohort_id: str = "",
        runtime_policy_id: str = "",
    ) -> SealedCandidateArm:
        usage = solve_evidence.get("usage", {})
        cost = int(usage.get("input_tokens", 0)) + int(
            usage.get("output_tokens", 0)
        )
        usage_verified = bool(solve_evidence.get("usage_verified", False))
        return SealedCandidateArm(
            overall_quality=evaluation.quality,
            fresh_quality=evaluation.fresh_quality,
            regression_quality=evaluation.regression_quality,
            cost_units=(cost if usage_verified else None),
            integrity_passed=(
                evaluation.integrity_passed
                and treatment_integrity_passed
            ),
            design_id=(sealed_evidence.design_id if sealed_evidence is not None else ""),
            evidence_id=(
                sealed_evidence.evidence_id if sealed_evidence is not None else ""
            ),
            cohort_id=cohort_id if sealed_evidence is not None else "",
            task_artifact_ids=(
                tuple(sorted(item.artifact_id for item in evaluation.task_results))
                if sealed_evidence is not None
                else ()
            ),
            workspace_digest=(
                evaluation.workspace_digest if sealed_evidence is not None else ""
            ),
            evaluator_fingerprint=(
                sealed_evidence.evaluator_fingerprint
                if sealed_evidence is not None
                else ""
            ),
            runtime_policy_id=(
                runtime_policy_id if sealed_evidence is not None else ""
            ),
        )

    def _persist_sealed_arm_evidence(
        self,
        *,
        design: CandidateEvaluationDesign,
        seed: int,
        arm: str,
        evaluation: Any,
        solve_evidence: Mapping[str, Any],
        runtime_binding: RuntimeBinding,
        runtime_id: str,
        treatment_integrity_passed: bool = True,
    ) -> SealedArmEvidence:
        task_ids: list[str] = []
        for task in cast(
            Sequence[Mapping[str, Any]], _arm_evaluation_mapping(evaluation)["tasks"]
        ):
            ref = self._artifacts.put_json(
                "sealed-task-result",
                {
                    "design_id": design.design_id,
                    "seed": seed,
                    "arm": arm,
                    **dict(task),
                },
            )
            task_ids.append(ref.artifact_id)
        usage = solve_evidence.get("usage", {})
        verified = bool(solve_evidence.get("usage_verified", False))
        usage_units = (
            int(cast(Mapping[str, Any], usage).get("input_tokens", 0))
            + int(cast(Mapping[str, Any], usage).get("output_tokens", 0))
            if verified and isinstance(usage, Mapping)
            else None
        )
        workspace_artifact_id = solve_evidence.get("workspace_artifact_id")
        if not isinstance(workspace_artifact_id, str):
            raise RuntimeError("sealed arm has no frozen workspace artifact")
        active = self._roles.projection.current_active_set
        if active is None:
            raise RuntimeError("sealed arm requires an active role generation")
        evidence = SealedArmEvidence.create(
            design_id=design.design_id,
            seed=seed,
            arm=arm,
            workspace_artifact_id=workspace_artifact_id,
            workspace_sha256=evaluation.workspace_digest,
            runtime_id=runtime_id,
            role_generation_id=active.for_role(Role.WARRIOR).role_version_id,
            plugin_ids=tuple(
                sorted(item.artifact_id for item in runtime_binding.plugins)
            ),
            mcp_ids=tuple(
                sorted(item.binding.binding_id for item in runtime_binding.mcps)
            ),
            environment_id=self._environment_id,
            task_result_ids=tuple(sorted(task_ids)),
            evaluator_fingerprint=design.evaluator_fingerprint,
            verified_usage_units=usage_units,
            integrity_passed=(
                evaluation.integrity_passed
                and treatment_integrity_passed
            ),
        )
        ref = self._artifacts.put_json(
            "sealed-arm-evidence", evidence.to_mapping(include_id=False)
        )
        if ref.artifact_id != evidence.evidence_id:
            raise RuntimeError("sealed arm CAS identity mismatch")
        return evidence

    def _record_role_generations(
        self, snapshot: CurriculumSnapshot
    ) -> list[dict[str, Any]]:
        active = self._roles.projection.current_active_set
        if active is None:
            return []
        entries: list[dict[str, Any]] = []
        for role in Role:
            identity = active.for_role(role)
            binding = self._bindings[role]
            manifest = binding.manifest
            payload = {
                "role": role.value,
                "generation": identity.version,
                "role_version_id": identity.role_version_id,
                "workflow_artifact_id": (
                    manifest.workflow_artifact_id if manifest is not None else None
                ),
                "subject_artifact_id": (
                    manifest.subject_artifact_id if manifest is not None else None
                ),
                "plugin_artifact_ids": (
                    list(manifest.plugin_artifact_ids)
                    if manifest is not None
                    else []
                ),
                "runtime_image": binding.runtime_image,
                "cycle_number": snapshot.cycle_number,
            }
            ref = self._artifacts.put_json("role-generation", payload)
            entries.append({"role": role.value, "artifact_id": ref.artifact_id})
        return entries

    def lock_attribution(
        self,
        snapshot: CurriculumSnapshot,
        quality_lock: ArtifactRef,
        prosecutor_audit: ArtifactRef,
        council: ArtifactRef,
        task_validation: ArtifactRef,
        candidate_evaluation: ArtifactRef,
    ) -> Mapping[str, Any]:
        candidate_data = _brief(self._artifacts, candidate_evaluation)
        if candidate_data.get("report") is not None and candidate_data.get("arms") is not None:
            report = AttributionReport.from_mapping(candidate_data["report"])
            champion_arm = EvaluationArm.from_mapping(
                candidate_data["arms"]["champion"]
            )
            self._append_arm(snapshot.cycle_number, champion_arm)
            role_candidates: dict[str, Any] = {}
            gate = candidate_data.get("candidate_gate")
            gate_qualified = (
                isinstance(gate, Mapping) and gate.get("disposition") == "qualified"
            )
            if gate_qualified and candidate_data.get("candidate") is not None:
                role_candidates["warrior"] = {
                    "candidate_id": candidate_data["candidate"]["candidate_id"],
                    "surface": candidate_data["candidate"]["surface"],
                    "artifact_id": candidate_data["candidate"]["artifact_id"],
                    "artifact_sha256": candidate_data["candidate"]["artifact_sha256"],
                }
            return {
                "report": report.to_mapping(),
                "arm": champion_arm.to_mapping(),
                "role_candidates": role_candidates,
                "evidence_ids": [
                    quality_lock.artifact_id,
                    prosecutor_audit.artifact_id,
                    council.artifact_id,
                    task_validation.artifact_id,
                    candidate_evaluation.artifact_id,
                ],
            }
        current_arm = self._evaluation_arm(snapshot, quality_lock, prosecutor_audit)
        report = _baseline_only_report()
        self._append_arm(snapshot.cycle_number, current_arm)
        audit = _brief(self._artifacts, prosecutor_audit)
        return {
            "report": report.to_mapping(),
            "arm": current_arm.to_mapping(),
            "role_candidates": _strip_forbidden(audit.get("role_candidates", {})),
            "evidence_ids": [
                quality_lock.artifact_id,
                prosecutor_audit.artifact_id,
                council.artifact_id,
                task_validation.artifact_id,
                candidate_evaluation.artifact_id,
            ],
        }

    def qualify_role_candidates(
        self,
        snapshot: CurriculumSnapshot,
        candidate_evaluation: ArtifactRef,
        attribution: ArtifactRef,
    ) -> Mapping[str, Any]:
        candidate_evidence = _read(self._artifacts, candidate_evaluation)
        evidence = _read(self._artifacts, attribution)
        try:
            AttributionReport.from_mapping(evidence["report"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("attribution evidence has no valid causal report") from exc
        if self._evolution is None:
            return {
                "qualified": {},
                "current_active_set": self._roles.projection.current_active_set_id,
                "note": "no qualified evolution candidate in this cycle",
            }
        rejection = candidate_evidence.get("rejection_pending")
        if isinstance(rejection, Mapping):
            rejected_id = rejection.get("candidate_id")
            reason = str(rejection.get("reason", "sealed candidate gate rejected"))
            if isinstance(rejected_id, str):
                record = self._evolution.projection.candidates.get(rejected_id)
                if record is not None and record.state is CandidateState.VALIDATED:
                    self._evolution.reject(rejected_id, reason=reason)
            return {
                "qualified": {},
                "current_active_set": self._roles.projection.current_active_set_id,
                "note": reason,
            }
        pending = candidate_evidence.get("qualification_pending")
        if not isinstance(pending, Mapping):
            return {
                "qualified": {},
                "current_active_set": self._roles.projection.current_active_set_id,
                "note": "no durable qualified candidate in this cycle",
            }
        exact_candidate_id = pending.get("candidate_id")
        gate_evidence_id = pending.get("gate_evidence_id")
        if not isinstance(exact_candidate_id, str) or not isinstance(
            gate_evidence_id, str
        ):
            raise RuntimeError("candidate evaluation omitted exact qualification bindings")
        design_value = candidate_evidence.get("evaluation_design")
        gate_value = candidate_evidence.get("candidate_gate")
        arms_value = candidate_evidence.get("arms")
        if (
            not isinstance(design_value, Mapping)
            or not isinstance(gate_value, Mapping)
            or not isinstance(arms_value, Mapping)
        ):
            raise RuntimeError("candidate evaluation omitted sealed design or arm evidence")
        design_artifact_id = design_value.get("artifact_id")
        design_mapping = {
            key: value for key, value in design_value.items() if key != "artifact_id"
        }
        design = CandidateEvaluationDesign.from_mapping(design_mapping)
        gate_mapping = {key: value for key, value in gate_value.items() if key != "evidence_id"}
        gate_report = CandidateGateReport.from_mapping(gate_mapping)
        binding_failures: list[str] = []
        if design.candidate_id != exact_candidate_id:
            binding_failures.append("candidate")
        if design.snapshot_id != snapshot.snapshot_id:
            binding_failures.append("snapshot")
        if not isinstance(design_artifact_id, str):
            binding_failures.append("design-artifact-id")
        elif (
            design_artifact_id != design.design_id
            or _read_artifact_id(self._artifacts, design_artifact_id)
            != design.to_mapping(include_id=False)
        ):
            binding_failures.append("design-artifact")
        if gate_value.get("evidence_id") != gate_evidence_id:
            binding_failures.append("gate-artifact-id")
        if not gate_report.qualified:
            binding_failures.append("gate-disposition")
        if _read_artifact_id(self._artifacts, gate_evidence_id) != gate_mapping:
            binding_failures.append("gate-artifact")
        if binding_failures:
            raise RuntimeError(
                "candidate qualification bindings do not match durable evidence: "
                + ", ".join(binding_failures)
            )
        pairs_value = arms_value.get("pairs")
        if not isinstance(pairs_value, list) or len(pairs_value) != len(design.seeds):
            raise RuntimeError("candidate evaluation has incomplete paired arm evidence")
        observed_pair_ids: list[str] = []
        for row in pairs_value:
            if not isinstance(row, Mapping):
                raise RuntimeError("candidate arm row is invalid")
            baseline_id = row.get("baseline_sealed_evidence_id")
            candidate_id = row.get("candidate_sealed_evidence_id")
            seed = row.get("seed")
            if not isinstance(baseline_id, str) or not isinstance(candidate_id, str):
                raise RuntimeError("candidate arm row omitted sealed evidence ids")
            baseline = SealedArmEvidence.from_mapping(
                {
                    "evidence_id": baseline_id,
                    **_read_artifact_id(self._artifacts, baseline_id),
                }
            )
            candidate_arm = SealedArmEvidence.from_mapping(
                {
                    "evidence_id": candidate_id,
                    **_read_artifact_id(self._artifacts, candidate_id),
                }
            )
            if (
                seed not in design.seeds
                or baseline.design_id != design.design_id
                or candidate_arm.design_id != design.design_id
                or baseline.seed != seed
                or candidate_arm.seed != seed
                or baseline.arm != "baseline"
                or candidate_arm.arm != "candidate"
                or baseline.evaluator_fingerprint != design.evaluator_fingerprint
                or candidate_arm.evaluator_fingerprint != design.evaluator_fingerprint
            ):
                raise RuntimeError("sealed arm evidence does not match evaluation design")
            pair_payload = row.get("sealed_pair")
            if not isinstance(pair_payload, Mapping):
                raise RuntimeError("candidate arm row omitted exact sealed pair")
            baseline_payload = pair_payload.get("baseline")
            candidate_payload = pair_payload.get("candidate")
            if (
                pair_payload.get("seed") != seed
                or not isinstance(baseline_payload, Mapping)
                or not isinstance(candidate_payload, Mapping)
                or baseline_payload.get("evidence_id") != baseline_id
                or candidate_payload.get("evidence_id") != candidate_id
                or baseline_payload.get("design_id") != design.design_id
                or candidate_payload.get("design_id") != design.design_id
            ):
                raise RuntimeError("sealed pair does not bind its exact arm evidence")
            observed_pair_ids.append(
                "candidate-pair-sha256:"
                + hashlib.sha256(
                    canonical_json(pair_payload).encode("utf-8")
                ).hexdigest()
            )
        if tuple(sorted(observed_pair_ids)) != gate_report.pair_ids:
            raise RuntimeError("candidate gate report is not bound to the sealed arm pairs")
        candidate = self._evolution.projection.candidates.get(exact_candidate_id)
        if candidate is None:
            return {
                "qualified": {},
                "current_active_set": self._roles.projection.current_active_set_id,
                "note": "qualified report has no pending evolution candidate",
            }
        if candidate.target_role is not Role.WARRIOR or candidate.state not in {
            CandidateState.VALIDATED,
            CandidateState.QUALIFIED,
        }:
            raise RuntimeError("durable candidate evidence targets an ineligible candidate")
        if candidate.state is CandidateState.VALIDATED:
            candidate = self._evolution.qualify(
                candidate.candidate_id,
                qualification_evidence_id=candidate_evaluation.artifact_id,
            )
            self._register_population(
                candidate, evidence_id=candidate_evaluation.artifact_id
            )
        mcp_candidate_id: str | None = None
        if candidate.surface is EvolutionSurface.MCP:
            if self._mcp_registry is None:
                raise RuntimeError("MCP registry is not configured")
            mcp_record = next(
                (
                    item
                    for item in self._mcp_registry.projection.candidates.values()
                    if item.evolution_candidate_id == candidate.candidate_id
                ),
                None,
            )
            if mcp_record is None:
                raise RuntimeError("MCP candidate lacks its governance record")
            if mcp_record.status is McpCandidateStatus.VALIDATED:
                self._mirror_mcp_status(
                    mcp_record.candidate,
                    evolution_candidate_id=candidate.candidate_id,
                    status=McpCandidateStatus.QUALIFIED,
                    evidence_id=candidate_evaluation.artifact_id,
                )
                mcp_record = self._mcp_registry.projection.candidates[
                    mcp_record.candidate.candidate_id
                ]
            lease = self._mcp_registry.acquire_lease("cycle-controller")
            try:
                if mcp_record.status is McpCandidateStatus.QUALIFIED:
                    risk = self._mcp_max_risk(mcp_record.candidate)
                    mcp_record = self._mcp_registry.begin_probation(
                        mcp_record.candidate.candidate_id,
                        evidence_id=candidate_evaluation.artifact_id,
                        required_observations=2,
                        expires_at=datetime.now(timezone.utc)
                        + timedelta(days=1 if risk is McpRiskLevel.L2 else 7),
                        lease_token=lease.token,
                    )
                if not any(
                    item.snapshot_id == snapshot.snapshot_id
                    for item in mcp_record.probation_observations
                ):
                    mcp_record = self._mcp_registry.observe_probation(
                        mcp_record.candidate.candidate_id,
                        snapshot_id=snapshot.snapshot_id,
                        evidence_id=candidate_evaluation.artifact_id,
                        passed=True,
                        lease_token=lease.token,
                    )
            finally:
                self._mcp_registry.release_lease(lease.token)
            if not mcp_record.probation_ready(datetime.now(timezone.utc)):
                return {
                    "qualified": {},
                    "current_active_set": self._roles.projection.current_active_set_id,
                    "note": "MCP candidate remains in cross-cycle probation",
                    "mcp_probation": {
                        "observations": len(mcp_record.probation_observations),
                        "required_observations": mcp_record.probation_required_observations,
                        "ready": False,
                    },
                }
            mcp_candidate_id = mcp_record.candidate.candidate_id
        active = self._roles.projection.current_active_set
        if active is None:
            raise RuntimeError("role genesis must precede candidate qualification")
        champion_binding = self._bindings[Role.WARRIOR]
        new_manifest = candidate_manifest(
            champion=champion_binding,
            candidate=candidate,
            artifacts=self._artifacts,
        )
        if new_manifest is None:
            raise RuntimeError("candidate manifest could not be materialized")
        ref = store_composite_manifest(self._artifacts, new_manifest)
        current = active.for_role(Role.WARRIOR)
        identity = RoleVersionIdentity(
            Role.WARRIOR,
            current.version + 1,
            ref.artifact_id,
            ref.artifact_id.rsplit(":", 1)[1],
            current.constitution_id,
            parent_role_version_id=current.role_version_id,
        )
        self._roles.collect_candidate(
            identity,
            objective_id=snapshot.objective.objective_id,
            collection_evidence_id=candidate_evaluation.artifact_id,
        )
        self._roles.validate_candidate(
            identity.role_version_id,
            validation_evidence_id=candidate_evaluation.artifact_id,
        )
        self._roles.qualify_candidate(
            identity.role_version_id,
            qualification_evidence_id=candidate_evaluation.artifact_id,
        )
        return {
            "qualified": {Role.WARRIOR.value: identity.role_version_id},
            "candidate_id": candidate.candidate_id,
            "mcp_candidate_id": mcp_candidate_id,
            "harness_candidate_commit": pending.get("harness_candidate_commit"),
            "harness_expected_champion": pending.get("harness_expected_champion"),
            "current_active_set": self._roles.projection.current_active_set_id,
            "note": "evolution candidate qualified for activation",
        }

    def commit_activation_set(
        self, snapshot: CurriculumSnapshot, qualification: ArtifactRef
    ) -> Mapping[str, Any]:
        evidence = _read(self._artifacts, qualification)
        qualified = evidence.get("qualified", {})
        if not isinstance(qualified, Mapping) or not qualified:
            return {
                "unchanged": True,
                "active_set": self._roles.projection.current_active_set_id,
            }
        selected: dict[Role, str] = {}
        for role in Role:
            candidate_id = qualified.get(role.value)
            if isinstance(candidate_id, str) and candidate_id:
                selected[role] = candidate_id
        candidate_id = evidence.get("candidate_id")
        mcp_candidate_id = evidence.get("mcp_candidate_id")
        harness_candidate_commit = evidence.get("harness_candidate_commit")
        harness_expected_champion = evidence.get("harness_expected_champion")
        role_candidate_id = selected.get(Role.WARRIOR)
        if (
            self._activation_journal is None
            or self._evolution is None
            or not isinstance(candidate_id, str)
            or not candidate_id
            or role_candidate_id is None
        ):
            raise RuntimeError("qualified activation lacks its durable saga inputs")
        intent = ActivationIntent.create(
            evolution_candidate_id=candidate_id,
            role_candidate_id=role_candidate_id,
            mcp_candidate_id=(
                mcp_candidate_id
                if isinstance(mcp_candidate_id, str) and mcp_candidate_id
                else None
            ),
            objective_id=snapshot.objective.objective_id,
            qualification_evidence_id=qualification.artifact_id,
            expected_current_active_set_id=self._roles.projection.current_active_set_id,
            harness_candidate_commit=(
                harness_candidate_commit
                if isinstance(harness_candidate_commit, str)
                else None
            ),
            harness_expected_champion=(
                harness_expected_champion
                if isinstance(harness_expected_champion, str)
                else None
            ),
        )
        self._activation_journal.begin(intent)
        completed = self._activation_reconciler().reconcile()
        if not any(item.intent.intent_id == intent.intent_id for item in completed):
            record = self._activation_journal.projection.records[intent.intent_id]
            if not record.completed:
                raise RuntimeError("activation saga did not reach a completed state")
        active = self._roles.projection.current_active_set
        if active is None:
            raise RuntimeError("activation set commit did not produce an active set")
        return {
            "unchanged": False,
            "active_set": active.active_role_set_id,
            "revision": active.revision,
            "intent_id": intent.intent_id,
        }

    def _activation_reconciler(self) -> ActivationReconciler:
        if self._activation_journal is None or self._evolution is None:
            raise RuntimeError("activation reconciliation is not configured")
        evolution = self._evolution

        def probe_role(intent: ActivationIntent) -> str | None:
            if intent.role_candidate_id is None:
                return None
            current = self._roles.projection.current_active_set
            if (
                current is not None
                and current.objective_id == intent.objective_id
                and current.for_role(Role.WARRIOR).role_version_id
                == intent.role_candidate_id
            ):
                return current.active_role_set_id
            return None

        def commit_role(intent: ActivationIntent) -> str:
            if intent.role_candidate_id is None:
                raise RuntimeError("activation intent has no role candidate")
            self._roles.commit_active_set(
                {Role.WARRIOR: intent.role_candidate_id},
                objective_id=intent.objective_id,
                joint_evidence_id=intent.qualification_evidence_id,
                expected_current_active_set_id=intent.expected_current_active_set_id,
            )
            current = self._roles.projection.current_active_set
            if current is None:
                raise RuntimeError("role activation did not produce an active set")
            return current.active_role_set_id

        def probe_evolution(intent: ActivationIntent) -> bool:
            record = evolution.projection.candidates.get(
                intent.evolution_candidate_id
            )
            return (
                record is not None
                and record.state is CandidateState.ACTIVE
                and evolution.champion(record.surface, record.target_role)
                == record
            )

        def activate_evolution(intent: ActivationIntent) -> None:
            evolution.activate(
                intent.evolution_candidate_id,
                activation_evidence_id=intent.qualification_evidence_id,
            )

        def probe_mcp(intent: ActivationIntent) -> str | None:
            if intent.mcp_candidate_id is None or self._mcp_registry is None:
                return None
            record = self._mcp_registry.projection.candidates.get(
                intent.mcp_candidate_id
            )
            if record is None or record.status is not McpCandidateStatus.ACTIVE:
                return None
            if self._mcp_bridge is not None:
                self._mcp_bridge.activate_candidate(record.candidate)
            return record.candidate.binding.binding_id

        def activate_mcp(intent: ActivationIntent) -> str:
            if intent.mcp_candidate_id is None or self._mcp_registry is None:
                raise RuntimeError("activation intent has no configured MCP candidate")
            lease = self._mcp_registry.acquire_lease("activation-reconciler")
            try:
                binding_id = self._mcp_registry.activate_from_evolution(
                    intent.mcp_candidate_id,
                    evidence_id=intent.qualification_evidence_id,
                    lease_token=lease.token,
                )
            finally:
                self._mcp_registry.release_lease(lease.token)
            record = self._mcp_registry.projection.candidates[intent.mcp_candidate_id]
            if self._mcp_bridge is None:
                raise RuntimeError("MCP bridge is not configured")
            self._mcp_bridge.activate_candidate(record.candidate)
            return binding_id

        def probe_harness(intent: ActivationIntent) -> str | None:
            if intent.harness_candidate_commit is None:
                return None
            if self._harness_backend is None or self._harness_campaign_id is None:
                raise RuntimeError("harness activation backend is not configured")
            receipt = self._harness_backend.status(
                self._harness_campaign_id,
                f"probe:{intent.intent_id.rsplit(':', 1)[1][:32]}",
            )
            if receipt.champion_commit != intent.harness_candidate_commit:
                return None
            ref = self._artifacts.put_json("harness-activation", receipt.to_mapping())
            return ref.artifact_id

        def activate_harness(intent: ActivationIntent) -> str:
            if (
                intent.harness_candidate_commit is None
                or intent.harness_expected_champion is None
                or self._harness_backend is None
                or self._harness_campaign_id is None
            ):
                raise RuntimeError("harness activation intent is incomplete")
            receipt = self._harness_backend.activate(
                self._harness_campaign_id,
                intent.evolution_candidate_id,
                intent.harness_candidate_commit,
                intent.harness_expected_champion,
                f"activate:{intent.intent_id.rsplit(':', 1)[1][:32]}",
            )
            ref = self._artifacts.put_json("harness-activation", receipt.to_mapping())
            return ref.artifact_id

        return ActivationReconciler(
            self._activation_journal,
            probe_role_commit=probe_role,
            commit_role=commit_role,
            probe_evolution_activation=probe_evolution,
            activate_evolution=activate_evolution,
            probe_mcp_activation=probe_mcp,
            activate_mcp=activate_mcp,
            probe_harness_activation=probe_harness,
            activate_harness=activate_harness,
        )

    # -- attribution evidence ledger ----------------------------------------

    def _evaluation_arm(
        self,
        snapshot: CurriculumSnapshot,
        quality_lock: ArtifactRef,
        prosecutor_audit: ArtifactRef,
    ) -> EvaluationArm:
        quality = _brief(self._artifacts, quality_lock)
        audit = _brief(self._artifacts, prosecutor_audit)
        active = self._roles.projection.current_active_set
        if active is None:
            raise RuntimeError("role genesis must precede attribution")
        role_generations = tuple(
            sorted(
                (
                    AttributionRoleGeneration(
                        role.value,
                        active.for_role(role).version,
                        active.for_role(role).role_version_id,
                    )
                    for role in Role
                ),
                key=lambda item: item.role,
            )
        )
        evaluation = quality.get("evaluation") or {}
        safety_passed = not bool(evaluation.get("safety_violations"))
        integrity_passed = bool(evaluation.get("integrity_passed", False))
        if self._runtime_ledger is not None:
            cost = int(self._runtime_ledger.consumed().total_tokens)
        else:
            cost = int(self._runtime_consumed.get("max_total_tokens", 0))
        if cost <= 0:
            basis = quality.get("basis")
            basis_ids = basis if isinstance(basis, list) else []
            for artifact_id in basis_ids:
                if not isinstance(artifact_id, str):
                    continue
                try:
                    item = _read_artifact_id(self._artifacts, artifact_id)
                except Exception:
                    continue
                item_usage = item.get("usage") or {}
                cost += int(item_usage.get("input_tokens", 0)) + int(
                    item_usage.get("output_tokens", 0)
                )
            audit_usage = audit.get("usage") or {}
            cost += int(audit_usage.get("input_tokens", 0)) + int(
                audit_usage.get("output_tokens", 0)
            )
        binding = self._bindings[Role.WARRIOR]
        return EvaluationArm(
            cycle_id=f"cycle:{snapshot.cycle_number}",
            objective_id=snapshot.objective.objective_id,
            task_id=f"objective:{snapshot.objective.objective_id}",
            seed=0,
            model_id=self._role_configs["warrior"].model,
            environment_id=self._environment_id,
            plugin_ids=(
                tuple(sorted(item.artifact_id for item in binding.plugins))
            ),
            role_generations=role_generations,
            quality=_score(quality.get("score")),
            cost_units=cost,
            usage_verified=bool(audit.get("usage_verified", False)) and cost > 0,
            safety_passed=safety_passed,
            integrity_passed=integrity_passed,
            runtime_variant=binding.runtime_variant(),
            mcp_binding_ids=tuple(
                sorted(item.binding.binding_id for item in binding.mcps)
            ),
        )

    def _append_arm(self, cycle_number: int, arm: EvaluationArm) -> None:
        self._attribution_ledger.parent.mkdir(parents=True, exist_ok=True)
        with self._attribution_ledger.open("a", encoding="utf-8") as stream:
            stream.write(
                json.dumps({"cycle": cycle_number, "arm": arm.to_mapping()}, sort_keys=True)
                + "\n"
            )


def genesis_constitution() -> Constitution:
    return Constitution(
        1,
        (
            "Never execute generated code on the host control plane.",
            "Hidden tests, references and grader answers never reach any model context.",
            "External writes only happen through journaled, publisher-owned connectors.",
        ),
    )


def genesis_objective(
    constitution: Constitution, *, statement: str | None = None
) -> ObjectiveVersion:
    return ObjectiveVersion(
        1,
        constitution.constitution_id,
        (
            statement.strip()
            if statement is not None
            else "Improve the Warrior's dynamic software engineering capability through adversarial tasks."
        ),
        (ObjectiveSuccessCriterion("quality", 0.5),),
        ("python",),
        {
            "efficiency": 0.10,
            "generalization": 0.30,
            "quality": 0.40,
            "retention": 0.20,
        },
    )


def genesis_identities(constitution: Constitution) -> dict[Role, RoleVersionIdentity]:
    return {
        role: RoleVersionIdentity(
            role,
            1,
            f"genesis-{role.value}-v1",
            hashlib.sha256(f"genesis:{role.value}".encode("utf-8")).hexdigest(),
            constitution.constitution_id,
        )
        for role in Role
    }


def ensure_curriculum_genesis(
    curriculum: CurriculumRegistry,
    *,
    constitution: Constitution,
    objective: ObjectiveVersion,
) -> None:
    if curriculum.projection.objectives:
        return
    if constitution.constitution_id not in curriculum.projection.constitutions:
        curriculum.record_constitution(constitution)
    if objective.objective_id not in curriculum.projection.objectives:
        curriculum.provision_objective(objective)
    status = curriculum.projection.objective_statuses.get(objective.objective_id)
    if status is ObjectiveStatus.PROVISIONAL:
        curriculum.start_objective_probation(objective.objective_id)
        curriculum.activate_objective(objective.objective_id)
    elif status is ObjectiveStatus.PROBATION:
        curriculum.activate_objective(objective.objective_id)


def ensure_role_genesis(
    roles: RoleRegistry,
    *,
    objective: ObjectiveVersion,
    identities: Mapping[Role, RoleVersionIdentity],
    artifacts: ContentAddressedArtifactStore | None = None,
    role_configs: Mapping[str, RoleConfig] | None = None,
    budget_policy_sha256: str | None = None,
    default_image: str | None = None,
) -> ActiveRoleSet:
    active = roles.projection.current_active_set
    if active is not None:
        return active
    selected: dict[Role, str] = {}
    for role in Role:
        identity = identities[role]
        if artifacts is not None and role_configs is not None:
            workflow_ref, subject_ref = materialize_default_artifacts(artifacts)
            manifest = build_composite_manifest(
                role=role,
                model_profile_sha256=model_profile_hash(role_configs[role.value]),
                workflow_artifact_id=workflow_ref.artifact_id,
                subject_artifact_id=subject_ref.artifact_id,
                plugin_artifact_ids=(),
                runtime_image=default_image,
                budget_policy_sha256=budget_policy_sha256 or "0" * 64,
            )
            ref = store_composite_manifest(artifacts, manifest)
            identity = RoleVersionIdentity(
                role,
                1,
                ref.artifact_id,
                ref.artifact_id.rsplit(":", 1)[1],
                identity.constitution_id,
            )
        roles.collect_candidate(
            identity,
            objective_id=objective.objective_id,
            collection_evidence_id="genesis:collection",
        )
        roles.validate_candidate(
            identity.role_version_id,
            validation_evidence_id="genesis:validation",
        )
        roles.qualify_candidate(
            identity.role_version_id,
            qualification_evidence_id="genesis:qualification",
        )
        selected[role] = identity.role_version_id
    roles.commit_active_set(
        selected,
        objective_id=objective.objective_id,
        joint_evidence_id="genesis:joint",
        expected_current_active_set_id=None,
    )
    active = roles.projection.current_active_set
    if active is None:
        raise RuntimeError("role genesis did not produce an active set")
    return active


def next_target_generation(registry: DynamicTaskRegistry) -> int:
    records = registry.records()
    if not records:
        return 2
    return max(2, max(record.creator_generation for record in records) + 1)


def build_next_snapshot(
    *,
    campaign_id: str,
    curriculum: CurriculumRegistry,
    registry: DynamicTaskRegistry,
    cohort: DynamicTaskCohort,
    constitution: Constitution,
    objective: ObjectiveVersion,
    active_roles: ActiveRoleSet,
) -> CurriculumSnapshot:
    current = curriculum.projection.current_snapshot
    same_generation = (
        current is not None
        and curriculum.projection.cycle_state is not CycleState.COMPLETED
    )
    if same_generation:
        # A control-plane retry re-runs the same failed generation with the
        # already-recorded snapshot; the controller validates exact equality.
        assert current is not None
        cycle_number = current.cycle_number
    else:
        cycle_number = 1 if current is None else current.cycle_number + 1
    training = cohort.cohort_id.rsplit(":", 1)[1]
    lagged = current.training_cohort_sha256 if current is not None else training
    hall_of_fame = sum(
        1 for record in registry.records() if record.status is DynamicTaskStatus.HALL_OF_FAME
    )
    parent_snapshot_id = (
        current.parent_snapshot_id
        if same_generation and current is not None
        else (current.snapshot_id if current is not None else None)
    )
    return CurriculumSnapshot(
        campaign_id,
        cycle_number,
        constitution,
        objective,
        active_roles,
        task_pool_revision=len(registry.records()),
        training_cohort_sha256=training,
        lagged_holdout_cohort_sha256=lagged,
        hall_of_fame_revision=hall_of_fame,
        external_probe_set_sha256="0" * 64,
        parent_snapshot_id=parent_snapshot_id,
    )


def _runtime_policy_genesis_values(
    campaign_config: Any,
    limits: RuntimeLimits,
    role_configs: Mapping[str, RoleConfig],
) -> dict[str, Any]:
    autonomy = getattr(campaign_config, "autonomy_v2", None)
    def role_int(value: int) -> dict[str, int]:
        return {name: int(value) for name in role_configs}

    def role_float(value: float) -> dict[str, float]:
        return {name: float(value) for name in role_configs}
    from aegis.agent_runtime import (
        FIXED_ROLE_MAX_READ_BYTES,
        FIXED_ROLE_MAX_SEARCH_RESULTS,
        FIXED_ROLE_MAX_TOOL_OUTPUT_BYTES,
        FIXED_ROLE_MAX_WRITE_BYTES,
        FIXED_ROLE_RESEARCH_ACTION_BUDGET,
    )

    return {
        # Single external cost envelope: operator-set, far above any normal
        # campaign consumption. Campaign config values may only raise them.
        "max_total_tokens": max(int(campaign_config.total_tokens), 2_000_000_000),
        "max_requests": max(int(campaign_config.max_requests), 100_000),
        "max_model_invocations": max(int(campaign_config.max_rounds), 20_000),
        "max_active_runtime_seconds": max(
            float(campaign_config.wall_time_seconds), 3_600_000.0
        ),
        "role_token_shares": {
            name: float(config.budget_share) for name, config in role_configs.items()
        },
        "role_max_steps": role_int(
            min(
                max(1, int(getattr(limits, "max_steps", 20) or 20)),
                FIXED_ROLE_MAX_STEPS,
            )
        ),
        "role_max_output_tokens": {
            name: max(int(config.max_output_tokens), 393_216)
            for name, config in role_configs.items()
        },
        "role_reasoning_effort": {
            name: config.reasoning_effort for name, config in role_configs.items()
        },
        "role_research_action_budgets": role_int(FIXED_ROLE_RESEARCH_ACTION_BUDGET),
        "role_command_timeout_seconds": role_float(3_600.0),
        "role_max_read_bytes": role_int(FIXED_ROLE_MAX_READ_BYTES),
        "role_max_write_bytes": role_int(FIXED_ROLE_MAX_WRITE_BYTES),
        "role_max_tool_output_bytes": role_int(FIXED_ROLE_MAX_TOOL_OUTPUT_BYTES),
        "role_max_search_results": role_int(FIXED_ROLE_MAX_SEARCH_RESULTS),
        "gateway_timeout_seconds": 3_600.0,
        "gateway_max_attempts": 10,
        "gateway_base_delay_seconds": 0.5,
        "gateway_max_delay_seconds": 8.0,
        "subagent_max_spawns_per_run": 32,
        "subagent_max_steps": 32,
        "subagent_timeout_seconds": 600.0,
        "subagent_max_result_bytes": 1_048_576,
        "subagent_max_output_tokens": 393_216,
        "subagent_max_total_tokens": max(
            1, int(campaign_config.total_tokens) // 4, 300_000_000
        ),
        "subagent_max_requests": max(
            1, int(campaign_config.max_requests) // 4, 5_000
        ),
        "max_evolution_requests_per_run": 1,
        "max_evolution_source_refs": 5,
        "task_authoring_attempts": 2,
        "task_proposals_per_cycle": 1,
        "cohort_limit": 3,
        "candidate_evaluations_per_cycle": 1,
        "candidate_max_steps": int(getattr(autonomy, "candidate_max_extra_steps", 12)),
        "population_max_cells": 128,
        "council_max_messages": int(getattr(autonomy, "council_max_messages", 200)),
        "council_max_tokens": int(getattr(autonomy, "council_max_tokens", 4_194_304)),
        "task_holdout_delay_cycles": int(getattr(autonomy, "task_holdout_delay_cycles", 1)),
        "objective_history_window": int(getattr(autonomy, "objective_history_window", 3)),
        "objective_probation_cycles": int(getattr(autonomy, "objective_probation_cycles", 2)),
        "dependency_download_timeout_seconds": 3_600.0,
        "dependency_download_max_bytes": 8 * 1024 * 1024 * 1024,
        "build_timeout_seconds": 86_400.0,
        "scan_timeout_seconds": 3_600.0,
    }


def _objective_governance_genesis(
    objective: ObjectiveVersion, constitution: Constitution
) -> tuple[HumanCoreObjective, AdaptiveObjectiveVersion]:
    criteria = tuple(
        EvaluatorCriterion(
            item.metric,
            "objective-evaluator-sha256:"
            + hashlib.sha256(item.metric.encode("utf-8")).hexdigest(),
            item.minimum,
        )
        for item in objective.success_criteria
    )
    core = HumanCoreObjective(
        statement=objective.statement,
        criteria=criteria,
        forbidden_capabilities=tuple(sorted(constitution.protected_controls)),
        constitution_id=constitution.constitution_id,
    )
    adaptive = AdaptiveObjectiveVersion(
        version=1,
        core_objective_id=core.core_objective_id,
        refinement=objective.statement,
        criteria=criteria,
        weights={
            item.name: max(1e-12, float(objective.capability_weights.get(item.name, 1.0)))
            for item in criteria
        },
        capability_tags=tuple(sorted(objective.capability_tags)),
    )
    return core, adaptive


def run_v2_cycle(
    *,
    gateway: Any,
    sandbox: SandboxBackend,
    research: Any,
    knowledge: Any,
    skills: Any,
    pdf_extractor: Any,
    role_configs: Mapping[str, RoleConfig],
    limits: RuntimeLimits,
    artifacts: ContentAddressedArtifactStore,
    dynamic: DynamicTaskRegistry,
    forge: TaskForge,
    runner: TaskPackRunner,
    curriculum: CurriculumRegistry,
    roles: RoleRegistry,
    data_dir: Path,
    campaign_id: str,
    holdout_delay: int = 1,
    cohort_limit: int | None = None,
    public_repo_url: str | None = None,
    source_commit: str | None = None,
    repair_on_failure: bool = False,
    event_store: Any = None,
    repair_git_publisher: Any = None,
    repair_target_role: Role = Role.WARRIOR,
    evolution: EvolutionRegistry | None = None,
    environment_builder: EnvironmentBuilder | None = None,
    default_image: str | None = None,
    evaluate_candidates_enabled: bool = True,
    candidate_max_extra_steps: int = 12,
    campaign_config: Any = None,
    harness_repo: HarnessRepo | None = None,
    harness_backend: HarnessBackend | None = None,
    harness_canary_command: Sequence[str] | None = None,
    harness_activation_automatic: bool = True,
    mcp_bridge: McpBridge | None = None,
    subagent_max_steps: int = 8,
    subagent_timeout_seconds: float = 180.0,
    subagent_max_concurrency: int = 2,
    subagent_max_result_bytes: int = 65_536,
    meta_evolution_enabled: bool = False,
    population: PopulationArchive | None = None,
) -> Any:
    constitution = genesis_constitution()
    objective_statement = (
        getattr(campaign_config, "objective", None)
        if campaign_config is not None
        else None
    )
    genesis = genesis_objective(constitution, statement=objective_statement)
    identities = genesis_identities(constitution)
    ensure_curriculum_genesis(curriculum, constitution=constitution, objective=genesis)
    effective_objective_id = curriculum.projection.effective_objective_id
    if effective_objective_id is None:
        raise RuntimeError("curriculum registry has no effective objective")
    objective = curriculum.projection.objectives[effective_objective_id]
    constitution = curriculum.projection.constitutions[objective.constitution_id]
    target = next_target_generation(dynamic)
    auxiliary_store = event_store if isinstance(event_store, EventStore) else curriculum.store
    objective_governance: ObjectiveGovernanceRegistry | None = None
    if isinstance(auxiliary_store, EventStore):
        objective_governance = ObjectiveGovernanceRegistry(
            auxiliary_store, artifacts, campaign_id + "/objectives"
        )
        original_objective = min(
            curriculum.projection.objectives.values(), key=lambda item: item.version
        )
        original_constitution = curriculum.projection.constitutions[
            original_objective.constitution_id
        ]
        core, adaptive_genesis = _objective_governance_genesis(
            original_objective, original_constitution
        )
        objective_governance.record_genesis(core)
        objective_governance.record_adaptive_genesis(adaptive_genesis)
        objective_governance.begin_cycle(target)
    runtime_policy_registry: RuntimePolicyRegistry | None = None
    runtime_ledger: RuntimeGatewayAttemptObserver | None = None
    autonomy_config = getattr(campaign_config, "autonomy_v2", None)
    council_max_messages = int(getattr(autonomy_config, "council_max_messages", 24))
    council_max_tokens = int(getattr(autonomy_config, "council_max_tokens", 4_194_304))
    require_warrior_strategy_proposal = bool(
        getattr(autonomy_config, "require_warrior_strategy_proposal", False)
    )
    runtime_consumed: dict[str, float | int] = {
        "max_total_tokens": 0,
        "max_requests": 0,
        "max_model_invocations": max(0, target - 1),
        "max_active_runtime_seconds": 0,
    }
    if campaign_config is not None and isinstance(auxiliary_store, EventStore):
        runtime_policy_registry = RuntimePolicyRegistry(
            auxiliary_store, artifacts, campaign_id + "/runtime-policy"
        )
        genesis_policy = runtime_policy_registry.genesis(
            _runtime_policy_genesis_values(campaign_config, limits, role_configs),
            {
                name: max(393_216, int(config.max_output_tokens))
                for name, config in role_configs.items()
            },
        )
        del genesis_policy
        effective_policy = runtime_policy_registry.effective_for_stage(
            runtime_policy_registry.resume_stage_boundary(target)
        )
        policy_values = effective_policy.values
        policy_hash = effective_policy.policy_id.rsplit(":", 1)[1]
        limits = replace(
            limits,
            max_steps=int(
                cast(Mapping[str, Any], policy_values["role_max_steps"])[Role.WARRIOR.value]
            ),
            max_timeout_seconds=float(
                cast(Mapping[str, Any], policy_values["role_command_timeout_seconds"])[Role.WARRIOR.value]
            ),
        )
        role_configs = {
            name: replace(
                config,
                max_output_tokens=int(
                    cast(Mapping[str, Any], policy_values["role_max_output_tokens"])[name]
                ),
            )
            for name, config in role_configs.items()
        }
        candidate_max_extra_steps = cast(int, policy_values["candidate_max_steps"])
        subagent_max_steps = cast(int, policy_values["subagent_max_steps"])
        subagent_timeout_seconds = float(
            cast(float | int, policy_values["subagent_timeout_seconds"])
        )
        council_max_messages = int(cast(int, policy_values["council_max_messages"]))
        council_max_tokens = int(cast(int, policy_values["council_max_tokens"]))
        configured_cohort_limit = int(cast(int, policy_values["cohort_limit"]))
        cohort_limit = configured_cohort_limit
        holdout_delay = int(cast(int, policy_values["task_holdout_delay_cycles"]))
        bind_observer = getattr(gateway, "bind_attempt_observer", None)
        if callable(bind_observer):
            runtime_ledger = RuntimeGatewayAttemptObserver(
                auxiliary_store,
                runtime_policy_registry,
                _gateway_accounting_context,
            )
            bind_observer(runtime_ledger)
        bind_policy_provider = getattr(gateway, "bind_runtime_policy_provider", None)
        if callable(bind_policy_provider):
            def gateway_policy_values() -> Mapping[str, object]:
                context = _ACCOUNTING_CONTEXT.get()
                if context is not None and context.paired_design_id is not None:
                    return cast(
                        Mapping[str, object],
                        runtime_policy_registry.policy_for_paired_design(
                            context.paired_design_id
                        ).values,
                    )
                boundary = (
                    RuntimeStageBoundary(
                        context.cycle, context.stage_ordinal, context.stage
                    )
                    if context is not None
                    else runtime_policy_registry.resume_stage_boundary(target)
                )
                return cast(
                    Mapping[str, object],
                    runtime_policy_registry.effective_for_stage(boundary).values,
                )
            bind_policy_provider(gateway_policy_values)
        if environment_builder is not None:
            bind_environment_policy = getattr(
                environment_builder, "bind_runtime_policy_provider", None
            )
            if callable(bind_environment_policy):
                bind_environment_policy(
                    lambda: cast(
                        Mapping[str, object],
                        runtime_policy_registry.latest_for_cycle(target).values,
                    )
                )
    else:
        effective_policy = None
        policy_hash = (
            budget_policy_hash(campaign_config)
            if campaign_config is not None
            else hashlib.sha256(b"aegis-unset-budget-policy").hexdigest()
        )
    active = ensure_role_genesis(
        roles,
        objective=objective,
        identities=identities,
        artifacts=artifacts,
        role_configs=role_configs,
        budget_policy_sha256=policy_hash,
        default_image=default_image,
    )
    if active.objective_id != objective.objective_id:
        roles.rebind_objective(
            objective.objective_id,
            evidence_id="sha256:" + objective.objective_id.rsplit(":", 1)[1],
            expected_current_active_set_id=active.active_role_set_id,
        )
        active = cast(ActiveRoleSet, roles.projection.current_active_set)
    cohort = dynamic.select_dynamic_cohort(target, limit=cohort_limit)
    snapshot = build_next_snapshot(
        campaign_id=campaign_id,
        curriculum=curriculum,
        registry=dynamic,
        cohort=cohort,
        constitution=constitution,
        objective=objective,
        active_roles=active,
    )
    ports = ModelCyclePorts(
        gateway=gateway,
        sandbox=sandbox,
        research=research,
        knowledge=knowledge,
        skills=skills,
        pdf_extractor=pdf_extractor,
        role_configs=role_configs,
        limits=limits,
        artifacts=artifacts,
        dynamic=dynamic,
        forge=forge,
        runner=runner,
        curriculum=curriculum,
        roles=roles,
        data_dir=data_dir,
        holdout_delay=holdout_delay,
        objective_history_window=(
            int(campaign_config.autonomy_v2.objective_history_window)
            if campaign_config is not None and campaign_config.autonomy_v2 is not None
            else 3
        ),
        objective_probation_cycles=(
            int(campaign_config.autonomy_v2.objective_probation_cycles)
            if campaign_config is not None and campaign_config.autonomy_v2 is not None
            else 2
        ),
        council_max_messages=council_max_messages,
        council_max_tokens=council_max_tokens,
        public_repo_url=public_repo_url,
        source_commit=source_commit,
        evolution=evolution,
        environment_builder=environment_builder,
        default_image=default_image,
        evaluate_candidates_enabled=evaluate_candidates_enabled,
        candidate_max_extra_steps=candidate_max_extra_steps,
        budget_policy_sha256=policy_hash,
        harness_repo=harness_repo,
        harness_backend=harness_backend,
        harness_campaign_id=campaign_id,
        harness_canary_command=harness_canary_command,
        harness_activation_automatic=harness_activation_automatic,
        mcp_bridge=mcp_bridge,
        subagent_max_steps=subagent_max_steps,
        subagent_timeout_seconds=subagent_timeout_seconds,
        subagent_max_concurrency=subagent_max_concurrency,
        subagent_max_result_bytes=subagent_max_result_bytes,
        meta_evolution_enabled=meta_evolution_enabled,
        population=population,
        activation_store=(event_store if isinstance(event_store, EventStore) else None),
        history_store=auxiliary_store,
        runtime_policy_registry=runtime_policy_registry,
        runtime_policy_cycle=target,
        runtime_consumed=runtime_consumed,
        objective_governance=objective_governance,
        runtime_ledger=runtime_ledger,
        require_warrior_strategy_proposal=require_warrior_strategy_proposal,
        judge_heterogeneous_model=getattr(
            campaign_config, "judge_heterogeneous_model", None
        ),
        judge_heterogeneous_fraction=float(
            getattr(campaign_config, "judge_heterogeneous_fraction", 0.0) or 0.0
        ),
    )
    if effective_policy is not None and effective_policy.maintenance_only:
        maintenance = ports._run_role(
            Role.PROSECUTOR,
            objective=(
                "The active runtime policy is below already consumed usage. "
                "Call aegis.adjust_runtime_policy exactly once to restore a viable next-cycle "
                "budget or roll back to a viable historical policy, then submit."
            ),
            context={
                "policy": effective_policy.to_mapping(),
                "consumed": (
                    runtime_ledger.consumed().to_policy_mapping()
                    if runtime_ledger is not None
                    else runtime_consumed
                ),
            },
            max_steps=3,
            accounting_stage="maintenance",
            required_action_groups=(frozenset({"aegis.adjust_runtime_policy"}),),
        )
        assert runtime_policy_registry is not None
        requested_boundary = RuntimeStageBoundary(
            target,
            ports._runtime_stage_ordinal,
            f"stage:{ports._runtime_stage_ordinal}",
        )
        amendment = next(
            (
                item
                for item in reversed(runtime_policy_registry.immediate_amendments)
                if item.requested_at == requested_boundary
            ),
            None,
        )
        if amendment is None:
            raise RuntimeError("maintenance-only Prosecutor did not apply a policy repair")
        artifacts.put_json("runtime-policy-maintenance", maintenance)
        # The maintenance amendment restored a viable budget; continue the
        # cycle in the same invocation instead of requiring a manual resume.
        effective_policy = runtime_policy_registry.effective_for_stage(
            runtime_policy_registry.resume_stage_boundary(target)
        )
    state = curriculum.projection.cycle_state
    was_retry = state is CycleState.FAILED
    resume_evidence: dict[str, ArtifactRef] = {}
    checkpoint_campaign = f"{campaign_id}/stage-checkpoints"
    resume_needed = state not in {CycleState.CREATED, CycleState.COMPLETED}
    if resume_needed and isinstance(auxiliary_store, EventStore):
        for event in auxiliary_store.read(checkpoint_campaign):
            if event.event_type != "stage_checkpoint_v2":
                continue
            payload = event.payload
            if payload.get("cycle") != target:
                continue
            stage = payload.get("stage")
            artifact_id = payload.get("artifact_id")
            if not isinstance(stage, str) or not isinstance(artifact_id, str):
                continue
            ref = _ref_from_artifact_id(artifact_id, artifacts)
            if ref is not None:
                resume_evidence[stage] = ref
    try:
        if state is CycleState.FAILED:
            curriculum.transition_cycle(
                "retry",
                reason="control-plane restart after a repaired or rolled-back failure",
            )
        elif state not in {CycleState.CREATED, CycleState.COMPLETED}:
            curriculum.transition_cycle(
                "stop",
                reason="recovering an interrupted cycle",
            )
            curriculum.transition_cycle(
                "fail",
                reason="interrupted cycle recovered for retry",
            )
            curriculum.transition_cycle(
                "retry",
                reason="control-plane restart after an interrupted cycle",
            )
        def stage_checkpoint(stage: str, ref: ArtifactRef) -> None:
            if isinstance(auxiliary_store, EventStore):
                auxiliary_store.append(
                    checkpoint_campaign,
                    "stage_checkpoint_v2",
                    {
                        "cycle": target,
                        "stage": stage,
                        "artifact_id": ref.artifact_id,
                    },
                )

        controller = EvolutionCycleController(
            curriculum,
            _RegistryCohortProvider(dynamic),
            artifacts,
            CyclePorts(
                warrior=ports,
                judge=ports,
                quality=ports,
                prosecutor=ports,
                council=ports,
                evolution=ports,
            ),
            checkpoint=stage_checkpoint,
        )
        return controller.run(
            snapshot,
            target_generation=target,
            cohort_limit=cohort_limit,
            retry=was_retry,
            resume_evidence=resume_evidence or None,
        )
    except BaseException as exc:
        if not repair_on_failure or event_store is None:
            raise
        cycle_error = str(exc)
        if hasattr(event_store, "append"):
            try:
                event_store.append(
                    campaign_id,
                    "cycle_failed_recovery_started",
                    {
                        "cycle_id": f"cycle:{target}",
                        "error": cycle_error[:2000],
                    },
                )
            except Exception:
                pass
        if (
            isinstance(exc, RuntimeBudgetExceeded)
            and runtime_policy_registry is not None
            and runtime_ledger is not None
        ):
            try:
                consumed = runtime_ledger.consumed().to_policy_mapping()
                boundary = runtime_policy_registry.resume_stage_boundary(target)
                maintenance_policy = runtime_policy_registry.arm_maintenance(
                    requested_at=RuntimeStageBoundary(
                        target, boundary.ordinal + 1, f"stage:{boundary.ordinal + 1}"
                    ),
                    consumed=consumed,
                    reason=cycle_error,
                )
                maintenance = ports._run_role(
                    Role.PROSECUTOR,
                    objective=(
                        "The active runtime policy is below already consumed usage. "
                        "Call aegis.adjust_runtime_policy exactly once to restore a viable "
                        "next-stage budget or roll back to a viable historical policy, then submit."
                    ),
                    context={
                        "policy": maintenance_policy.to_mapping(),
                        "consumed": consumed,
                    },
                    max_steps=3,
                    accounting_stage="maintenance",
                    required_action_groups=(frozenset({"aegis.adjust_runtime_policy"}),),
                )
                maintenance_boundary = RuntimeStageBoundary(
                    target,
                    ports._runtime_stage_ordinal,
                    f"stage:{ports._runtime_stage_ordinal}",
                )
                amendment = next(
                    (
                        item
                        for item in reversed(runtime_policy_registry.immediate_amendments)
                        if item.requested_at == maintenance_boundary
                    ),
                    None,
                )
                if amendment is None:
                    raise RuntimeError(
                        "maintenance-only Prosecutor did not apply a policy repair"
                    )
                artifacts.put_json("runtime-policy-maintenance", maintenance)
                state = curriculum.projection.cycle_state
                was_retry = state is CycleState.FAILED
                if state is CycleState.FAILED:
                    curriculum.transition_cycle(
                        "retry",
                        reason="policy repaired by maintenance Prosecutor amendment",
                    )
                elif state not in {CycleState.CREATED, CycleState.COMPLETED}:
                    curriculum.transition_cycle(
                        "stop",
                        reason="maintenance repaired an interrupted cycle",
                    )
                    curriculum.transition_cycle(
                        "fail",
                        reason="maintenance repaired an interrupted cycle",
                    )
                    curriculum.transition_cycle(
                        "retry",
                        reason="maintenance repaired an interrupted cycle",
                    )
                retry_controller = EvolutionCycleController(
                    curriculum,
                    _RegistryCohortProvider(dynamic),
                    artifacts,
                    CyclePorts(
                        warrior=ports,
                        judge=ports,
                        quality=ports,
                        prosecutor=ports,
                        council=ports,
                        evolution=ports,
                    ),
                )
                try:
                    return retry_controller.run(
                        snapshot,
                        target_generation=target,
                        cohort_limit=cohort_limit,
                        retry=was_retry,
                        resume_evidence=resume_evidence or None,
                    )
                except BaseException as retry_exc:
                    cycle_error = f"{cycle_error} | budget-repair retry failed: {retry_exc}"
            except BaseException as maintenance_exc:
                cycle_error = f"{cycle_error} | maintenance repair failed: {maintenance_exc}"
        active_role = active.for_role(repair_target_role)
        base_generation_id = "sha256:" + hashlib.sha256(
            active_role.role_version_id.encode("utf-8")
        ).hexdigest()
        failed_generation_id = "sha256:" + hashlib.sha256(
            f"failed:{campaign_id}:{target}".encode("utf-8")
        ).hexdigest()
        patch = None
        try:
            patch = ports.generate_repair_patch(
                base_generation_id=base_generation_id,
                campaign_id=campaign_id,
                cycle_id=f"cycle:{target}",
                cause=cycle_error,
            )
        except Exception as patch_exc:
            cycle_error = f"{cycle_error} | repair patch generation failed: {patch_exc}"
        return repair_failed_cycle(
            exc=exc,
            event_store=event_store,
            campaign_id=campaign_id,
            cycle_id=f"cycle:{target}",
            target_role=repair_target_role,
            base_generation_id=base_generation_id,
            failed_generation_id=failed_generation_id,
            publisher=repair_git_publisher,
            roles=roles,
            objective_id=snapshot.objective.objective_id,
            constitution_id=snapshot.constitution.constitution_id,
            patch=patch,
            original_error=cycle_error,
        )
    finally:
        ports.close()
