"""Model-backed and control-plane ports for the AEGIS v2 evolution cycle.

The three model roles (Warrior, Judge, Prosecutor) and the council run through
the existing ``RoleAgentRuntime`` boundary, so every model turn is bounded,
JSON-constrained, token-metered, and sandboxed.  Quality locking, forged-task
validation/registration, attribution summarisation, role-candidate
qualification, and activation-set commits stay on the trusted control plane
and only ever consume content-addressed evidence.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import secrets
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Any, Mapping, Sequence, cast

from aegis.agent_runtime import RoleAgentRuntime, RuntimeLimits, ToolDispatcher
from aegis.artifacts import ArtifactRef, ContentAddressedArtifactStore
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
from aegis.curriculum import (
    ActiveRoleSet,
    Constitution,
    CurriculumRegistry,
    CurriculumSnapshot,
    CycleState,
    ObjectiveStatus,
    ObjectiveVersion,
    RoleVersionIdentity,
)
from aegis.cycle_recovery import patch_from_prosecutor_submission, repair_failed_cycle
from aegis.cycle_runtime import CyclePorts, EvolutionCycleController
from aegis.dynamic_tasks import (
    DynamicTaskCohort,
    DynamicTaskRegistry,
    DynamicTaskStatus,
    TaskForge,
)
from aegis.gateway.protocols import Role as GatewayRole
from aegis.gateway.types import TokenUsage
from aegis.models import Role
from aegis.plugins import (
    EffectClass,
    PluginManifest,
    PluginPolicy,
    ToolBroker,
)
from aegis.publishing import GitPublisher
from aegis.roles import RoleRegistry
from aegis.sandbox.backend import SandboxBackend
from aegis.taskpacks.manifest import TaskPack
from aegis.taskpacks.validation import TaskPackRunner

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
_MAX_STRING = 4096
_MAX_PROPOSALS = 16


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


def _score(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.5
    numeric = float(value)
    if not math.isfinite(numeric):
        return 0.5
    return min(1.0, max(0.0, numeric))


def _usage_summary(usages: Sequence[TokenUsage]) -> Mapping[str, int]:
    return {
        "requests": len(usages),
        "input_tokens": sum(item.input_tokens for item in usages),
        "output_tokens": sum(item.output_tokens for item in usages),
        "cached_tokens": sum(item.cached_tokens for item in usages),
        "reasoning_tokens": sum(item.reasoning_tokens for item in usages),
    }


def _no_baseline_report(arm: EvaluationArm) -> AttributionReport:
    observation = PairedObservation.create("warrior", arm, arm)
    return AttributionReport.create(
        disposition=AttributionDisposition.INVALID_DESIGN,
        qualification_path=QualificationPath.NONE,
        reason="no baseline arm recorded yet; paired qualification requires a prior cycle arm",
        observation_ids=(observation.observation_id,),
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
        public_repo_url: str | None = None,
        source_commit: str | None = None,
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
        self._attribution_ledger = data_dir / "attribution_arms.jsonl"
        self._environment_id = type(sandbox).__name__
        self._journal: SqliteConnectorJournal | None = None
        self._checkpoint: tuple[str, tuple[PluginManifest, ...], ToolBroker] | None = None
        if public_repo_url is not None and source_commit is not None:
            self._journal = SqliteConnectorJournal(data_dir / "connector_journal.sqlite3")
            publisher = GitPublisher(
                public_repo_url,
                remote_id="aegis-public",
                allowed_role_paths={"warrior": ("warrior",)},
            )
            connector = GitCheckpointConnector(publisher)
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
                "Submit one JSON payload with summary and a changes array; every change "
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

    def _run_role(
        self,
        role: Role,
        *,
        objective: str,
        context: Mapping[str, Any],
        max_steps: int | None = None,
    ) -> Mapping[str, Any]:
        cfg = self._role_configs[role.value]
        with self._sandbox_lock:
            self._sandbox_sequence += 1
            sandbox_id = (
                f"cycle-{role.value}-{self._sandbox_sequence}-{secrets.token_hex(4)}"
            )
        step_limit = self._limits.max_steps if max_steps is None else max_steps
        try:
            self._sandbox.prepare(sandbox_id)
        except Exception:
            # A previous interrupted run can leave an agent-side residue for a
            # reused id.  Destroy and retry once before failing closed.
            try:
                self._sandbox.destroy(sandbox_id)
            except Exception:
                pass
            self._sandbox.prepare(sandbox_id)
        dispatcher_kwargs: dict[str, Any] = {
            "knowledge": self._knowledge,
            "skills": self._skills,
            "pdf_extractor": self._pdf_extractor,
            "disabled_actions": (
                frozenset() if role is Role.WARRIOR else frozenset({"evolution.request"})
            ),
        }
        if self._checkpoint is not None:
            generation_id, manifests, broker = self._checkpoint
            dispatcher_kwargs.update(
                {
                    "role_generation_id": generation_id,
                    "plugin_manifests": manifests,
                    "tool_broker": broker,
                }
            )
        dispatcher = ToolDispatcher(
            self._sandbox,
            self._research,
            sandbox_id,
            limits=RuntimeLimits(max_steps=step_limit),
            challenge_metadata=None,
            **dispatcher_kwargs,
        )
        try:
            runtime = RoleAgentRuntime(
                self._gateway,
                dispatcher,
                cfg.model,
                limits=RuntimeLimits(max_steps=step_limit),
                max_output_tokens=cfg.max_output_tokens,
                reasoning_effort=cfg.reasoning_effort,
            )
            result = runtime.run(GatewayRole(role.value), objective=objective, context=context)
            return {
                "role": role.value,
                "summary": result.summary[:4096],
                "submission": _strip_forbidden(result.submission),
                "usage": _usage_summary(result.usages),
                "observations": [
                    {"step": item.step, "action": item.action}
                    for item in result.observations[:100]
                ],
            }
        finally:
            self._sandbox.destroy(sandbox_id)

    def solve(self, snapshot: CurriculumSnapshot, cohort: DynamicTaskCohort) -> Mapping[str, Any]:
        tasks = _sealed_tasks(self._dynamic, cohort)
        evidence = self._run_role(
            Role.WARRIOR,
            objective=(
                "Solve the dynamic cohort inside the sandbox.  Use at most 12 tool steps, then "
                "submit one JSON payload binding per-task artifact_id, solution summary, and "
                "public-test results.  Partial or imperfect solutions are acceptable and required "
                "to advance the cycle; never exceed the step budget without submitting."
            ),
            context={
                "snapshot": _truncate(snapshot.to_mapping()),
                "cohort": cohort.to_mapping(),
                "tasks": tasks,
            },
        )
        return {
            **evidence,
            "task_ids": [item["artifact_id"] for item in tasks],
        }

    def review(self, snapshot: CurriculumSnapshot, submission: ArtifactRef) -> Mapping[str, Any]:
        evidence = self._run_role(
            Role.JUDGE,
            objective=(
                "Review the Warrior submission against the sealed cohort.  Assess correctness, "
                "quality, hidden-failure risk and the cost of the next experiment.  Submit one JSON "
                "payload with bounded findings and a quality_score in [0,1]."
            ),
            context={
                "snapshot": _truncate(snapshot.to_mapping()),
                "submission": _brief(self._artifacts, submission),
            },
        )
        return {
            **evidence,
            "quality_score": _score(
                evidence.get("submission", {}).get("quality_score")
            ),
        }

    def audit(
        self,
        snapshot: CurriculumSnapshot,
        submission: ArtifactRef,
        judge_review: ArtifactRef,
        quality_lock: ArtifactRef,
    ) -> Mapping[str, Any]:
        evidence = self._run_role(
            Role.PROSECUTOR,
            objective=(
                "Audit token consumption, evidence integrity and risk for this cycle.  Submit one "
                "JSON payload with usage_verified, risk findings, and a structured curriculum "
                "hypothesis list for the next cycle."
            ),
            context={
                "snapshot": _truncate(snapshot.to_mapping()),
                "submission": _brief(self._artifacts, submission),
                "judge_review": _brief(self._artifacts, judge_review),
                "quality_lock": _brief(self._artifacts, quality_lock),
            },
        )
        return {
            **evidence,
            "curriculum": _strip_forbidden(
                evidence.get("submission", {}).get("curriculum", [])
            ),
            "role_candidates": _strip_forbidden(
                evidence.get("submission", {}).get("role_candidates", {})
            ),
            "usage_verified": bool(
                evidence.get("submission", {}).get("usage_verified", False)
            ),
        }

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
                "what should change, and which next hypothesis deserves a test."
            ),
            context={
                "snapshot": _truncate(snapshot.to_mapping()),
                "submission": _brief(self._artifacts, submission),
                "judge_review": _brief(self._artifacts, judge_review),
                "quality_lock": _brief(self._artifacts, quality_lock),
                "prosecutor_audit": _brief(self._artifacts, prosecutor_audit),
            },
        )
        return {
            **evidence,
            "role": role.value,
        }

    def deliberate(
        self, snapshot: CurriculumSnapshot, reflections: tuple[ArtifactRef, ...]
    ) -> Mapping[str, Any]:
        return self._run_role(
            Role.PROSECUTOR,
            objective=(
                "Deliberate as the council chair over the three independent reflections.  Submit "
                "one JSON payload with a concrete next-cycle proposal and the prioritized "
                "curriculum agenda."
            ),
            context={
                "snapshot": _truncate(snapshot.to_mapping()),
                "reflections": [
                    _brief(self._artifacts, ref) for ref in reflections
                ],
            },
        )

    def forge_next_tasks(
        self,
        snapshot: CurriculumSnapshot,
        submission: ArtifactRef,
        judge_review: ArtifactRef,
        quality_lock: ArtifactRef,
        prosecutor_audit: ArtifactRef,
        council: ArtifactRef,
    ) -> Mapping[str, Any]:
        evidence = self._run_role(
            Role.JUDGE,
            objective=(
                "Design the next dynamic task cohort.  Submit one JSON payload whose proposals "
                "list is bounded: each proposal carries task_id, difficulty (1..5), "
                "capability_tags, cost_units and stop_conditions.  If you can already produce a "
                "complete task-pack tar archive for a proposal, include it in archives as "
                "task_id + archive_base64."
            ),
            context={
                "snapshot": _truncate(snapshot.to_mapping()),
                "submission": _brief(self._artifacts, submission),
                "judge_review": _brief(self._artifacts, judge_review),
                "quality_lock": _brief(self._artifacts, quality_lock),
                "prosecutor_audit": _brief(self._artifacts, prosecutor_audit),
                "council": _brief(self._artifacts, council),
            },
        )
        payload = evidence.get("submission", {})
        proposals = payload.get("proposals", [])
        archives = payload.get("archives", [])
        if not isinstance(proposals, list) or not isinstance(archives, list):
            raise ValueError("judge forge payload must contain proposals and archives lists")
        return {
            **evidence,
            "proposals": _truncate(
                _strip_forbidden(proposals[: _MAX_PROPOSALS]),
                maximum=4096,
            ),
            "archives": [
                {
                    "task_id": str(item.get("task_id", ""))[:128],
                    "archive_sha256": hashlib.sha256(
                        base64.b64decode(item["archive_base64"], validate=True)
                    ).hexdigest(),
                }
                for item in archives[:16]
                if isinstance(item, Mapping) and isinstance(item.get("archive_base64"), str)
            ],
            "declarative_only": not archives,
        }

    # -- control-plane ports -------------------------------------------------

    def lock_quality(
        self,
        snapshot: CurriculumSnapshot,
        cohort: DynamicTaskCohort,
        submission: ArtifactRef,
        judge_review: ArtifactRef,
    ) -> Mapping[str, Any]:
        review = _brief(self._artifacts, judge_review)
        score = _score(
            review.get("quality_score", review.get("submission", {}).get("quality_score"))
        )
        return {
            "locked": True,
            "score": round(score, 4),
            "basis": [judge_review.artifact_id],
            "cohort": cohort.cohort_id,
        }

    def validate_forged_tasks(
        self, snapshot: CurriculumSnapshot, forged_tasks: ArtifactRef
    ) -> Mapping[str, Any]:
        forged = _read(self._artifacts, forged_tasks)
        payload = forged.get("submission", {})
        archives = payload.get("archives", [])
        if isinstance(archives, list) and archives:
            registered = []
            for item in archives:
                if not isinstance(item, Mapping) or not isinstance(
                    item.get("archive_base64"), str
                ):
                    continue
                try:
                    archive = base64.b64decode(item["archive_base64"], validate=True)
                    record = self._forge.forge_archive(
                        archive,
                        self._runner,
                        creator_generation=snapshot.cycle_number + 1,
                        source_spec_id=f"judge:{forged_tasks.artifact_id}",
                        source_evidence_ids=(
                            *sorted((forged_tasks.artifact_id, snapshot.snapshot_id)),
                        ),
                        holdout_delay=self._holdout_delay,
                    )
                except (ValueError, TypeError, RuntimeError) as exc:
                    return {
                        "valid": False,
                        "registered": [],
                        "rejected": [str(exc)[:2048]],
                        "declarative_only": False,
                    }
                registered.append(record.artifact.to_mapping())
            return {
                "valid": True,
                "registered": registered,
                "rejected": [],
                "declarative_only": False,
            }
        proposals = payload.get("proposals", [])
        if not isinstance(proposals, list) or not proposals:
            return {
                "valid": True,
                "registered": [],
                "rejected": ["no archives or proposals supplied; cohort unchanged"],
                "declarative_only": True,
            }
        return {
            "valid": True,
            "registered": [],
            "rejected": [],
            "declarative_only": True,
            "proposal_count": min(len(proposals), _MAX_PROPOSALS),
        }

    def lock_attribution(
        self,
        snapshot: CurriculumSnapshot,
        quality_lock: ArtifactRef,
        prosecutor_audit: ArtifactRef,
        council: ArtifactRef,
        task_validation: ArtifactRef,
    ) -> Mapping[str, Any]:
        current_arm = self._evaluation_arm(snapshot, quality_lock, prosecutor_audit)
        observations: tuple[PairedObservation, ...] = ()
        if self._previous_arm(snapshot.cycle_number) is not None:
            # Cross-cycle arms are structurally confounded by this design, so
            # only same-cycle paired data can qualify.  Until that exists the
            # deterministic report documents the evidence boundary honestly.
            observations = (
                PairedObservation.create(
                    "warrior",
                    current_arm,
                    current_arm,
                ),
            )
        report = qualify_attribution(observations) if observations else _no_baseline_report(
            current_arm
        )
        self._append_arm(snapshot.cycle_number, current_arm)
        audit = _brief(self._artifacts, prosecutor_audit)
        return {
            "report": report.to_mapping(),
            "arm": current_arm.to_mapping(),
            "role_candidates": _strip_forbidden(
                audit.get("role_candidates", {})
            ),
            "evidence_ids": [
                quality_lock.artifact_id,
                prosecutor_audit.artifact_id,
                council.artifact_id,
                task_validation.artifact_id,
            ],
        }

    def qualify_role_candidates(
        self, snapshot: CurriculumSnapshot, attribution: ArtifactRef
    ) -> Mapping[str, Any]:
        evidence = _read(self._artifacts, attribution)
        proposals = evidence.get("role_candidates", {})
        if not isinstance(proposals, Mapping) or not proposals:
            return {
                "qualified": {},
                "current_active_set": self._roles.projection.current_active_set_id,
                "note": "no role candidates proposed in this cycle",
            }
        try:
            report = AttributionReport.from_mapping(evidence["report"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("attribution evidence has no valid causal report") from exc
        if report.disposition in {
            AttributionDisposition.SAFETY_REJECTED,
            AttributionDisposition.INTEGRITY_REJECTED,
            AttributionDisposition.UNVERIFIED_USAGE,
        }:
            return {
                "qualified": {},
                "current_active_set": self._roles.projection.current_active_set_id,
                "note": "candidate blocked by a non-compensable attribution gate",
            }
        active = self._roles.projection.current_active_set
        if active is None:
            raise RuntimeError("role genesis must precede candidate qualification")
        qualified: dict[str, str] = {}
        for role in Role:
            raw = proposals.get(role.value)
            if not isinstance(raw, Mapping):
                continue
            artifact_id = raw.get("artifact_id")
            artifact_sha256 = raw.get("artifact_sha256")
            if (
                not isinstance(artifact_id, str)
                or not artifact_id
                or not isinstance(artifact_sha256, str)
                or len(artifact_sha256) != 64
            ):
                raise ValueError(f"{role.value} role candidate identity is invalid")
            current = active.for_role(role)
            identity = RoleVersionIdentity(
                role,
                current.version + 1,
                artifact_id,
                artifact_sha256,
                current.constitution_id,
                parent_role_version_id=current.role_version_id,
            )
            self._roles.collect_candidate(
                identity,
                objective_id=snapshot.objective.objective_id,
                collection_evidence_id=attribution.artifact_id,
            )
            self._roles.validate_candidate(
                identity.role_version_id,
                validation_evidence_id=attribution.artifact_id,
            )
            self._roles.qualify_candidate(
                identity.role_version_id,
                qualification_evidence_id=attribution.artifact_id,
            )
            qualified[role.value] = identity.role_version_id
        return {
            "qualified": qualified,
            "current_active_set": self._roles.projection.current_active_set_id,
            "note": "role candidates qualified for probationary activation",
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
        expected = self._roles.projection.current_active_set_id
        self._roles.commit_active_set(
            selected,
            objective_id=snapshot.objective.objective_id,
            joint_evidence_id=qualification.artifact_id,
            expected_current_active_set_id=expected,
        )
        active = self._roles.projection.current_active_set
        if active is None:
            raise RuntimeError("activation set commit did not produce an active set")
        return {
            "unchanged": False,
            "active_set": active.active_role_set_id,
            "revision": active.revision,
        }

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
        usage = audit.get("usage", {})
        cost = int(usage.get("input_tokens", 0)) + int(usage.get("output_tokens", 0))
        return EvaluationArm(
            cycle_id=f"cycle:{snapshot.cycle_number}",
            objective_id=snapshot.objective.objective_id,
            task_id=f"objective:{snapshot.objective.objective_id}",
            seed=0,
            model_id=self._role_configs["warrior"].model,
            environment_id=self._environment_id,
            plugin_ids=(
                ("aegis.inprocess/git-checkpoint",)
                if self._checkpoint is not None
                else ()
            ),
            role_generations=role_generations,
            quality=_score(quality.get("score")),
            cost_units=cost,
            usage_verified=bool(audit.get("usage_verified", False)),
            safety_passed=bool(audit.get("submission", {}).get("safety_passed", False)),
            integrity_passed=bool(
                audit.get("submission", {}).get("integrity_passed", False)
            ),
        )

    def _previous_arm(self, cycle_number: int) -> EvaluationArm | None:
        return self._arm_for_cycle(cycle_number - 1)

    def _arm_for_cycle(self, cycle_number: int) -> EvaluationArm | None:
        if not self._attribution_ledger.exists():
            return None
        for line in self._attribution_ledger.read_text(encoding="utf-8").splitlines():
            try:
                record = json.loads(line)
                if record.get("cycle") == cycle_number and isinstance(record.get("arm"), Mapping):
                    return EvaluationArm.from_mapping(record["arm"])
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
        return None

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


def genesis_objective(constitution: Constitution) -> ObjectiveVersion:
    return ObjectiveVersion(
        1,
        constitution.constitution_id,
        "Improve the Warrior's dynamic software engineering capability through adversarial tasks.",
        (
            "Warrior solutions pass the sealed public and holdout suites.",
            "Judge forges falsifiable next tasks from measured capability gaps.",
            "Prosecutor audits usage, integrity and curriculum hypotheses each cycle.",
        ),
        ("python",),
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
    elif curriculum.projection.active_objective_id != objective.objective_id:
        raise RuntimeError("campaign objective is bound to a different active objective")


def ensure_role_genesis(
    roles: RoleRegistry,
    *,
    objective: ObjectiveVersion,
    identities: Mapping[Role, RoleVersionIdentity],
) -> ActiveRoleSet:
    active = roles.projection.current_active_set
    if active is not None:
        return active
    selected: dict[Role, str] = {}
    for role in Role:
        identity = identities[role]
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
) -> Any:
    constitution = genesis_constitution()
    objective = genesis_objective(constitution)
    identities = genesis_identities(constitution)
    ensure_curriculum_genesis(curriculum, constitution=constitution, objective=objective)
    active = ensure_role_genesis(roles, objective=objective, identities=identities)
    target = next_target_generation(dynamic)
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
        public_repo_url=public_repo_url,
        source_commit=source_commit,
    )
    try:
        state = curriculum.projection.cycle_state
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
        )
        return controller.run(snapshot, target_generation=target, cohort_limit=cohort_limit)
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
