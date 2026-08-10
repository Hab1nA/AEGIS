import copy
import hashlib
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from aegis.autonomy_acceptance import verify_autonomy_campaign
from aegis.config import CampaignConfig
from aegis.evaluation import PairedObservation
from aegis.evolution_funnel import VerifiedTokenEvidence, evaluate_evolution_candidate
from aegis.evolution_registry import EvolutionCandidateState
from aegis.evolution_validation import CommandValidationEvidence, ValidationEvidence
from aegis.evolution_workspace import (
    CandidateFileChange,
    CandidatePatchArtifact,
    ChangeKind,
    ValidationCommand,
)
from aegis.models import canonical_json
from aegis.orchestrator import CampaignController


def config(*, acceptance_profile: str = "autonomous_evolution_v1") -> CampaignConfig:
    root = Path.cwd().resolve()
    return CampaignConfig.from_mapping(
        {
            "campaign_id": "autonomy-smoke-v1",
            "max_rounds": 2,
            "total_tokens": 14_000_000,
            "max_requests": 800,
            "wall_time_seconds": 28_800,
            "task_pack_paths": [str(root / f"taskpack-{index}") for index in range(12)],
            "max_agent_steps": 20,
            "research_enabled": True,
            "offline_research": False,
            "test_mode": False,
            "demo_mode": False,
            "sandbox_backend": "wsl",
            "acceptance_profile": acceptance_profile,
            "roles": {
                "warrior": {"model": "w", "budget_share": 0.55, "max_output_tokens": 4096},
                "judge": {"model": "j", "budget_share": 0.225, "max_output_tokens": 4096},
                "prosecutor": {"model": "p", "budget_share": 0.225, "max_output_tokens": 4096},
            },
        }
    )


def event(event_type, payload):
    return {"event_type": event_type, "payload": payload}


def candidate_artifact(
    baseline_archive_sha256: str,
    archive: bytes,
    workflow_content: bytes,
    *,
    path: str = "src/aegis/evolvable/workflow.py",
    additional_paths: tuple[str, ...] = (),
) -> CandidatePatchArtifact:
    candidate_archive_sha256 = hashlib.sha256(archive).hexdigest()
    workflow_sha256 = hashlib.sha256(workflow_content).hexdigest()
    changes = tuple(
        sorted(
            (
                CandidateFileChange(
                    change_path,
                    ChangeKind.MODIFIED,
                    "f" * 64,
                    workflow_sha256,
                    len(workflow_content),
                )
                for change_path in (path, *additional_paths)
            ),
            key=lambda change: change.path,
        )
    )
    command = ValidationCommand(("python", "-m", "pytest", "-q"))
    payload = {
        "schema_version": 1,
        "baseline_archive_sha256": baseline_archive_sha256,
        "candidate_archive_sha256": candidate_archive_sha256,
        "changes": [
            {
                "path": change.path,
                "kind": change.kind.value,
                "baseline_sha256": change.baseline_sha256,
                "candidate_sha256": change.candidate_sha256,
                "candidate_size_bytes": change.candidate_size_bytes,
            }
            for change in changes
        ],
        "validation_commands": [
            {
                "argv": list(command.argv),
                "cwd": command.cwd,
                "timeout_seconds": command.timeout_seconds,
            }
        ],
    }
    artifact_id = "candidate-sha256:" + hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    ).hexdigest()
    return CandidatePatchArtifact(
        artifact_id,
        baseline_archive_sha256,
        archive,
        candidate_archive_sha256,
        changes,
        (command,),
    )


def promotion_canary_result(
    *,
    experiment_id: str,
    task_id: str,
    seed: int,
    arm: str,
    phase: str,
    role: str,
    artifact_id: str,
    baseline_archive_sha256: str,
    candidate_archive_sha256: str,
) -> dict[str, object]:
    identity = f"{experiment_id}-{task_id}-{seed}-{arm}"
    payload = {
        "schema_version": 1,
        "run_id": hashlib.sha256(f"{identity}:{phase}:{role}".encode("utf-8")).hexdigest()[:16],
        "candidate_version": 1,
        "candidate_artifact_id": artifact_id,
        "baseline_archive_sha256": baseline_archive_sha256,
        "candidate_archive_sha256": candidate_archive_sha256,
        "promotion_event_hash": hashlib.sha256(
            f"candidate-evaluation:{artifact_id}".encode("utf-8")
        ).hexdigest(),
        "role": role,
        "context_sha256": "a" * 64,
        "exit_code": 0,
        "timed_out": False,
        "stdout_sha256": "b" * 64,
        "stderr_sha256": "c" * 64,
        "stdout_bytes": 0,
        "stderr_bytes": 0,
        "reported_duration_seconds": 0.1,
        "observed_duration_seconds": 0.1,
        "passed": True,
        "failure_reason": None,
        "workflow": {
            "stage_plan": ["Inspect"],
            "research_query_templates": ["query"],
            "tool_selection_rules": ["rule"],
            "stop_conditions": ["stop"],
            "verification_checklist": ["verify"],
            "skill_references": ["skill"],
            "max_steps": None,
        },
    }
    result_id = "canary-sha256:" + hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    ).hexdigest()
    return {"result_id": result_id, **payload}


def successful_validation(candidate: CandidatePatchArtifact) -> ValidationEvidence:
    command = candidate.validation_commands[0]
    command_payload = {
        "argv": list(command.argv),
        "cwd": command.cwd,
        "timeout_seconds": command.timeout_seconds,
    }
    command_evidence = CommandValidationEvidence(
        0,
        hashlib.sha256(canonical_json(command_payload).encode("utf-8")).hexdigest(),
        "1" * 64,
        0,
        False,
        1.0,
        1.0,
        "2" * 64,
        "3" * 64,
        0,
        0,
        True,
    )
    frozen_sha256 = "4" * 64
    payload = {
        "schema_version": 1,
        "validation_id": "full-regression",
        "candidate_artifact_id": candidate.artifact_id,
        "baseline_archive_sha256": candidate.baseline_archive_sha256,
        "candidate_archive_sha256": candidate.candidate_archive_sha256,
        "pristine_frozen_sha256": frozen_sha256,
        "post_validation_frozen_sha256": frozen_sha256,
        "commands": [
            {
                "index": command_evidence.index,
                "command_sha256": command_evidence.command_sha256,
                "result_sha256": command_evidence.result_sha256,
                "exit_code": command_evidence.exit_code,
                "timed_out": command_evidence.timed_out,
                "reported_duration_seconds": command_evidence.reported_duration_seconds,
                "observed_duration_seconds": command_evidence.observed_duration_seconds,
                "stdout_sha256": command_evidence.stdout_sha256,
                "stderr_sha256": command_evidence.stderr_sha256,
                "stdout_bytes": command_evidence.stdout_bytes,
                "stderr_bytes": command_evidence.stderr_bytes,
                "output_within_limit": command_evidence.output_within_limit,
            }
        ],
        "passed": True,
        "failure_reason": None,
        "workspace_mutated": False,
        "total_observed_seconds": 1.0,
    }
    evidence_id = "validation-sha256:" + hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    ).hexdigest()
    return ValidationEvidence(
        evidence_id,
        "full-regression",
        candidate.artifact_id,
        candidate.baseline_archive_sha256,
        candidate.candidate_archive_sha256,
        frozen_sha256,
        frozen_sha256,
        (command_evidence,),
        True,
        None,
        False,
        1.0,
    )


class AutonomyAcceptanceTests(unittest.TestCase):
    @staticmethod
    def _add_round_feedback(events):
        quality = {"accepted": True, "score": 1.0}
        judge = {
            "role": "judge",
            "summary": "boundary review complete",
            "submission": {"verdict": "accepted"},
            "observations": [],
            "tokens": 12,
            "usage_verified": True,
        }
        prosecutor = {
            "role": "prosecutor",
            "summary": "efficiency audit complete",
            "submission": {"verdict": "accepted"},
            "observations": [],
            "tokens": 8,
            "usage_verified": True,
        }
        feedback = CampaignController._round_feedback_payload(1, quality, judge, prosecutor)
        first_round_two = next(
            index
            for index, item in enumerate(events)
            if item["event_type"] == "evolution_canary_evaluated"
            and item["payload"].get("round") == 2
        )
        events[first_round_two:first_round_two] = [
            event("quality_locked", {"round": 1, "quality": quality}),
            event("role_output", {"round": 1, "phase": "judge", "output": judge}),
            event("role_output", {"round": 1, "phase": "prosecutor", "output": prosecutor}),
            event("round_feedback_recorded", feedback),
        ]
        second_warrior = next(
            item
            for item in events
            if item["event_type"] == "role_output"
            and item["payload"].get("round") == 2
            and item["payload"].get("phase") == "warrior"
        )
        second_warrior["payload"]["output"] = {
            "submission": {
                "feedback_round": 1,
                "feedback_id": feedback["feedback_id"],
                "feedback_dispositions": [
                    {"feedback_id": "quality", "decision": "adopt", "rationale": "Keep measured quality."},
                    {"feedback_id": "judge", "decision": "defer", "rationale": "Need a focused probe."},
                    {"feedback_id": "prosecutor", "decision": "reject", "rationale": "Evidence does not apply."},
                ],
            }
        }
        return feedback

    def evidence(self):
        request = "evolution-request-sha256:" + "3" * 64
        source = "sha256:" + "4" * 64
        skill = "sha256:" + "5" * 64
        paper = "sha256:" + "6" * 64
        baseline = "a" * 64
        source_content = "c" * 64
        source_blob = "d" * 64
        bundle_digest = "7" * 64
        skill_blob = "8" * 64
        paper_content = "9" * 64
        paper_excerpt = "0" * 64
        experiment = "experiment-1"
        repository = "https://github.com/example/project"
        commit = "e" * 40
        identifier = "arxiv:2501.00001"
        proposal_id = "autonomy-workflow-1"
        strategy_id = "warrior-v2-1234567890abcdef"
        workflow = {
            "stage_plan": ["Inspect", "Research", "Implement", "Verify"],
            "research_query_templates": ["{task} current engineering evidence"],
            "tool_selection_rules": ["Use only verified brokered sources."],
            "stop_conditions": ["Stop after bounded verification passes."],
            "verification_checklist": ["Run focused and regression tests."],
            "skill_references": ["declarative:retry-reviewer"],
            "max_steps": 20,
        }
        tasks = [f"task-{index}" for index in range(12)]
        first_artifact = candidate_artifact(baseline, b"first-candidate", b"first workflow")
        first = first_artifact.artifact_id
        candidate = first_artifact.candidate_archive_sha256
        first_validation = successful_validation(first_artifact)
        second_artifact = candidate_artifact(candidate, b"second-candidate", b"second workflow")
        second = second_artifact.artifact_id
        second_validation = successful_validation(second_artifact)
        source_ref = {
            "artifact_id": source,
            "kind": "github",
            "content_sha256": source_content,
            "locator": "path:src/retry.py",
            "blob_sha256": source_blob,
        }
        paper_ref = {
            "artifact_id": paper,
            "kind": "paper",
            "content_sha256": paper_content,
            "locator": "paragraph:p1",
            "blob_sha256": paper_excerpt,
        }
        research_observations = [
            {"step": 1, "action": "research.search", "result": {"hits": [{"url": repository}]}},
            {
                "step": 2,
                "action": "github.resolve",
                "result": {"repository_url": repository, "commit_sha": commit},
            },
            {
                "step": 3,
                "action": "github.collect",
                "result": {
                    "artifact": {
                        "artifact_id": source,
                        "metadata": {"repository_url": repository, "commit_sha": commit},
                    },
                    "persistent_archive": {"archived": True, "content_sha256": source_content},
                },
            },
            {
                "step": 4,
                "action": "github.file_read",
                "result": {
                    "artifact_id": source,
                    "path": "src/retry.py",
                    "sha256": source_blob,
                },
            },
            {
                "step": 5,
                "action": "github.skill_bundle",
                "result": {
                    "candidate": {
                        "artifact_id": skill,
                        "kind": "skill",
                        "source_url": f"{repository}/tree/{commit}/skills/reviewer",
                    },
                    "bundle_sha256": bundle_digest,
                    "root": "skills/reviewer",
                    "files": [
                        {
                            "path": "SKILL.md",
                            "source_path": "skills/reviewer/SKILL.md",
                            "sha256": skill_blob,
                            "git_blob_sha": "f" * 40,
                            "provenance": {
                                "sha256": skill_blob,
                                "final_url": (
                                    "https://raw.githubusercontent.com/example/project/"
                                    f"{commit}/skills/reviewer/SKILL.md"
                                ),
                            },
                        }
                    ],
                    "skill_registry_state": "validated_pending",
                    "automatic_promotion_eligible": True,
                    "persistent_archive": {"archived": True, "recall_sha256": bundle_digest},
                    "declarative_only": True,
                    "execution_granted": False,
                    "dependencies_installed": False,
                    "permissions_registered": False,
                },
            },
            {
                "step": 6,
                "action": "knowledge.remember",
                "result": {"artifact_id": "knowledge-1", "sha256": source_content, "stored": True},
            },
            {
                "step": 7,
                "action": "strategy.propose",
                "result": {
                    "proposal_id": proposal_id,
                    "target_role": "warrior",
                    "content": workflow,
                    "rationale": "Use a bounded evidence-first workflow.",
                },
            },
        ]
        warrior_observations = [
            {
                "step": 1,
                "action": "research.search",
                "result": {"hits": [{"url": f"https://arxiv.org/abs/{identifier[6:]}"}]},
            },
            {
                "step": 2,
                "action": "paper.collect",
                "result": {
                    "artifact": {
                        "artifact_id": paper,
                        "kind": "paper",
                        "metadata": {"identifier": identifier},
                    },
                    "excerpts": [
                        {
                            "locator_type": "paragraph",
                            "locator": "p1",
                            "sha256": paper_excerpt,
                        }
                    ],
                    "persistent_archive": {"archived": True, "content_sha256": paper_content},
                },
            },
            {
                "step": 3,
                "action": "paper.excerpt_read",
                "result": {
                    "artifact_id": paper,
                    "locator_type": "paragraph",
                    "locator": "p1",
                    "sha256": paper_excerpt,
                },
            },
            {"step": 4, "action": "research.recall", "result": {"artifacts": []}},
            {
                "step": 5,
                "action": "github.file_read",
                "result": {"artifact_id": source, "path": "src/retry.py", "sha256": source_blob},
            },
            {"step": 6, "action": "evolution.request", "result": {"accepted": True}},
        ]
        events = [
            event(
                "strategy_candidate_created",
                {
                    "strategy": {
                        "version_id": strategy_id,
                        "version": 2,
                        "target_role": "warrior",
                        "parent_version_id": "warrior-v1-parent",
                        "proposal_id": proposal_id,
                        "proposed_by": "warrior",
                        "content": workflow,
                        "content_hash": "1" * 64,
                    },
                    "rationale": "Use a bounded evidence-first workflow.",
                },
            ),
            event(
                "role_strategy_proposals_accepted",
                {
                    "round": 1,
                    "phase": "research",
                    "role": "warrior",
                    "candidate_ids": [strategy_id],
                },
            ),
            event(
                "role_output",
                {"round": 1, "phase": "research", "output": {"observations": research_observations}},
            ),
            event(
                "role_output",
                {"round": 1, "phase": "warrior", "output": {"observations": warrior_observations}},
            ),
            event(
                "evolution_request_started",
                {
                    "round": 1,
                    "request_id": request,
                    "baseline_archive_sha256": baseline,
                    "source_refs": [source_ref, paper_ref],
                    "candidate_only": True,
                    "host_write_allowed": False,
                },
            ),
            event(
                "evolution_role_completed",
                {
                    "round": 1,
                    "request_id": request,
                    "action_receipts": [
                        {"step": 1, "action": "research.recall", "accepted": True, "sha256": source_content},
                        {
                            "step": 2,
                            "action": "research.artifact_read",
                            "accepted": True,
                            "artifact_id": source,
                            "kind": "github",
                            "locator": "path:src/retry.py",
                            "sha256": source_blob,
                            "size_bytes": 128,
                        },
                        {"step": 3, "action": "research.recall", "accepted": True, "sha256": paper_content},
                        {
                            "step": 4,
                            "action": "research.artifact_read",
                            "accepted": True,
                            "artifact_id": paper,
                            "kind": "paper",
                            "locator": "paragraph:p1",
                            "sha256": paper_excerpt,
                            "size_bytes": 128,
                        },
                        {
                            "step": 5,
                            "action": "workspace.read",
                            "accepted": True,
                            "path": "src/aegis/evolvable/workflow.py",
                            "sha256": first_artifact.changes[0].baseline_sha256,
                            "size_bytes": 100,
                        },
                        {
                            "step": 6,
                            "action": "workspace.write",
                            "accepted": True,
                            "path": "src/aegis/evolvable/workflow.py",
                            "sha256": first_artifact.changes[0].candidate_sha256,
                            "size_bytes": first_artifact.changes[0].candidate_size_bytes,
                        },
                        {
                            "step": 7,
                            "action": "sandbox.exec",
                            "accepted": True,
                            "exit_code": 0,
                            "timed_out": False,
                            "argv_hash": "e" * 64,
                        },
                    ],
                },
            ),
            event(
                "evolution_candidate_collected",
                {
                    "round": 1,
                    "request_id": request,
                    "artifact_id": first,
                    "baseline_archive_sha256": baseline,
                    "candidate_archive_sha256": candidate,
                    "changes": list(first_artifact.to_mapping()["changes"]),
                },
            ),
            event(
                "evolution_validation_recorded",
                {
                    "round": 1,
                    "request_id": request,
                    "artifact_id": first,
                    "evidence": dict(first_validation.to_mapping()),
                },
            ),
            event(
                "evolution_candidate_registered",
                {
                    "round": 1,
                    "request_id": request,
                    "artifact_id": first,
                    "state": "candidate",
                    "evidence_id": first_validation.evidence_id,
                },
            ),
            event(
                "evolution_request_completed",
                {"round": 1, "request_id": request, "status": "pending"},
            ),
            event(
                "evolution_promotion_experiment_started",
                {
                    "candidate_artifact_id": first,
                    "experiment_id": experiment,
                    "task_ids": tasks,
                    "seeds": [0, 1],
                    "smoke_pairs": [[tasks[0], 0], [tasks[1], 0]],
                },
            ),
        ]
        full_observations = tuple(
            PairedObservation(task, seed, 0.85, 0.8, 100, 110, True, True, False)
            for task in tasks
            for seed in (0, 1)
        )
        source_report_sha256 = hashlib.sha256(
            canonical_json(
                {
                    "full_observations": [
                        [
                            row.task_id,
                            row.seed,
                            row.candidate_tokens,
                            row.champion_tokens,
                        ]
                        for row in sorted(full_observations, key=lambda row: (row.task_id, row.seed))
                    ]
                }
            ).encode("utf-8")
        ).hexdigest()
        token_evidence = VerifiedTokenEvidence.create(
            candidate_artifact_id=first,
            baseline_archive_sha256=baseline,
            observations=full_observations,
            usage_verified=True,
            source_report_sha256=source_report_sha256,
        )
        funnel_report = evaluate_evolution_candidate(
            first_artifact,
            first_validation,
            tuple(
                row
                for row in full_observations
                if (row.task_id, row.seed) in {(tasks[0], 0), (tasks[1], 0)}
            ),
            full_observations,
            token_evidence,
        ).report.to_dict()
        events.extend(
            event(
                "evolution_promotion_arm_completed",
                {
                    "experiment_id": experiment,
                    "candidate_artifact_id": first,
                    "task_id": row.task_id,
                    "seed": row.seed,
                    "arm": arm,
                    "quality": quality,
                    "tokens": tokens,
                    "usage_verified": True,
                    "safety_violations": [],
                },
            )
            for row in full_observations
            for arm, quality, tokens in (
                ("candidate", row.candidate_quality, row.candidate_tokens),
                ("baseline", row.champion_quality, row.champion_tokens),
            )
        )
        events.extend(
            event(
                "evolution_promotion_observation_recorded",
                {
                    "experiment_id": experiment,
                    "candidate_artifact_id": first,
                    "task_id": row.task_id,
                    "seed": row.seed,
                    "candidate_quality": row.candidate_quality,
                    "champion_quality": row.champion_quality,
                    "candidate_tokens": row.candidate_tokens,
                    "champion_tokens": row.champion_tokens,
                    "candidate_usage_verified": row.candidate_usage_verified,
                    "champion_usage_verified": row.champion_usage_verified,
                    "safety_violation": row.safety_violation,
                },
            )
            for row in full_observations
        )
        phase_roles = (
            ("promotion_research", "warrior"),
            ("promotion_warrior", "warrior"),
            ("promotion_judge", "judge"),
            ("promotion_prosecutor", "prosecutor"),
        )
        events.extend(
            event(
                "evolution_promotion_canary_evaluated",
                {
                    "experiment_id": experiment,
                    "task_id": task,
                    "seed": seed,
                        "arm": "evolution-candidate",
                        "phase": phase,
                        "role": role,
                        "context_sha256": "a" * 64,
                        "result": promotion_canary_result(
                        experiment_id=experiment,
                        task_id=task,
                        seed=seed,
                        arm="evolution-candidate",
                        phase=phase,
                        role=role,
                        artifact_id=first,
                        baseline_archive_sha256=baseline,
                        candidate_archive_sha256=candidate,
                    ),
                },
            )
            for task in tasks
            for seed in (0, 1)
            for phase, role in phase_roles
        )
        events.extend(
            [
                event(
                    "evolution_promotion_funnel_recorded",
                    {
                        "experiment_id": experiment,
                        "report": funnel_report,
                    },
                ),
                event(
                    "evolution_candidate_promoted",
                    {"experiment_id": experiment, "candidate_artifact_id": first},
                ),
                event(
                    "autonomy_acceptance_auxiliary_promotions_deferred",
                    {
                        "round": 1,
                        "reason": (
                            "dedicated smoke reserves its fixed request budget for the code-evolution "
                            "champion and inheritance chain"
                        ),
                    },
                ),
                event(
                    "evolution_canary_evaluated",
                    {
                        "round": 2,
                        "phase": "research",
                        "role": "warrior",
                        "result": {
                            "passed": True,
                            "candidate_artifact_id": first,
                            "baseline_archive_sha256": baseline,
                            "candidate_archive_sha256": candidate,
                            "workflow": {"stage_plan": ["Inspect"]},
                        },
                    },
                ),
                event("role_output", {"round": 2, "phase": "research", "output": {}}),
                event(
                    "evolution_canary_evaluated",
                    {
                        "round": 2,
                        "phase": "warrior",
                        "role": "warrior",
                        "result": {
                            "passed": True,
                            "candidate_artifact_id": first,
                            "baseline_archive_sha256": baseline,
                            "candidate_archive_sha256": candidate,
                            "workflow": {"stage_plan": ["Inspect"]},
                        },
                    },
                ),
                event("role_output", {"round": 2, "phase": "warrior", "output": {}}),
                event(
                    "evolution_candidate_collected",
                    {
                        "round": 2,
                        "request_id": "evolution-request-sha256:" + "9" * 64,
                        "artifact_id": second,
                        "baseline_archive_sha256": candidate,
                        "candidate_archive_sha256": second_artifact.candidate_archive_sha256,
                        "changes": list(second_artifact.to_mapping()["changes"]),
                    },
                ),
                event(
                    "evolution_validation_recorded",
                    {
                        "round": 2,
                        "request_id": "evolution-request-sha256:" + "9" * 64,
                        "artifact_id": second,
                        "evidence": dict(second_validation.to_mapping()),
                    },
                ),
                event(
                    "evolution_candidate_registered",
                    {
                        "round": 2,
                        "request_id": "evolution-request-sha256:" + "9" * 64,
                        "artifact_id": second,
                        "state": "candidate",
                        "evidence_id": second_validation.evidence_id,
                    },
                ),
                event(
                    "evolution_request_completed",
                    {
                        "round": 2,
                        "request_id": "evolution-request-sha256:" + "9" * 64,
                        "status": "pending",
                    },
                ),
                event(
                    "autonomy_acceptance_inheritance_observed",
                    {
                        "round": 2,
                        "artifact_id": second,
                        "parent_champion_id": first,
                        "baseline_archive_sha256": candidate,
                    },
                ),
                event("usage_committed", {"verified": True, "input_tokens": 10, "output_tokens": 5}),
                event("state_changed", {"state": "paused", "resume_target": "promotion_gate"}),
            ]
        )
        first_record = SimpleNamespace(
            artifact_id=first,
            state=EvolutionCandidateState.CHAMPION,
            parent_champion_id=None,
            baseline_archive_digest=baseline,
        )
        second_record = SimpleNamespace(
            artifact_id=second,
            state=EvolutionCandidateState.CANDIDATE,
            parent_champion_id=first,
            baseline_archive_digest=candidate,
        )
        registry = Mock()
        registry.candidate_for_request.return_value = first_artifact
        registry.candidate_artifact.side_effect = lambda artifact_id: {
            first: first_artifact,
            second: second_artifact,
        }[artifact_id]
        registry.validation.side_effect = lambda artifact_id: {
            first: first_validation,
            second: second_validation,
        }[artifact_id]
        registry.candidate.side_effect = lambda artifact_id: {
            first: first_record,
            second: second_record,
        }[artifact_id]
        registry.champion.return_value = first_record
        registry.champion_archive.return_value = SimpleNamespace(
            artifact_id=first,
            expected_digest=candidate,
            promotion_event_hash="d" * 64,
        )
        return events, registry

    def checks(self, events, registry):
        return {
            item["name"]: item["passed"]
            for item in verify_autonomy_campaign(config(), events, registry)["checks"]
        }

    def test_complete_real_chain_passes(self):
        events, registry = self.evidence()
        report = verify_autonomy_campaign(config(), events, registry)
        self.assertTrue(report["passed"])
        self.assertTrue(all(item["passed"] for item in report["checks"]))

    def test_v2_requires_bound_round_feedback_and_warrior_dispositions(self):
        events, registry = self.evidence()
        self._add_round_feedback(events)
        report = verify_autonomy_campaign(
            config(acceptance_profile="autonomous_evolution_v2"), events, registry
        )
        self.assertTrue(report["passed"])

    def test_v2_rejects_tampered_feedback_or_missing_warrior_disposition(self):
        for mutation, check_name in (
            ("feedback", "round_feedback_recorded"),
            ("disposition", "next_round_warrior_feedback_dispositions"),
        ):
            with self.subTest(mutation=mutation):
                events, registry = self.evidence()
                self._add_round_feedback(events)
                if mutation == "feedback":
                    feedback = next(
                        item for item in events if item["event_type"] == "round_feedback_recorded"
                    )
                    feedback["payload"]["items"][1]["evidence"]["summary"] = "tampered"
                else:
                    warrior = next(
                        item
                        for item in events
                        if item["event_type"] == "role_output"
                        and item["payload"].get("round") == 2
                        and item["payload"].get("phase") == "warrior"
                    )
                    warrior["payload"]["output"]["submission"]["feedback_dispositions"].pop()
                checks = {
                    item["name"]: item["passed"]
                    for item in verify_autonomy_campaign(
                        config(acceptance_profile="autonomous_evolution_v2"), events, registry
                    )["checks"]
                }
                self.assertFalse(checks[check_name])

    def test_evolution_receipts_require_each_source_and_successful_ordered_execution(self):
        for mutation in ("missing-paper-read", "rejected-github-read", "late-research", "failed-exec"):
            with self.subTest(mutation=mutation):
                events, registry = self.evidence()
                completed = next(
                    item for item in events if item["event_type"] == "evolution_role_completed"
                )
                receipts = completed["payload"]["action_receipts"]
                if mutation == "missing-paper-read":
                    completed["payload"]["action_receipts"] = [
                        receipt for receipt in receipts if receipt.get("action") != "research.artifact_read"
                        or receipt.get("kind") != "paper"
                    ]
                elif mutation == "rejected-github-read":
                    next(
                        receipt
                        for receipt in receipts
                        if receipt.get("action") == "research.artifact_read"
                        and receipt.get("kind") == "github"
                    )["accepted"] = False
                elif mutation == "late-research":
                    next(
                        receipt
                        for receipt in receipts
                        if receipt.get("action") == "research.recall"
                        and receipt.get("sha256") == "9" * 64
                    )["step"] = 8
                else:
                    next(
                        receipt for receipt in receipts if receipt.get("action") == "sandbox.exec"
                    )["exit_code"] = 1
                self.assertFalse(
                    self.checks(events, registry)["evolution_role_consumed_bound_source"]
                )

    def test_candidate_change_must_bind_successful_workspace_write(self):
        events, registry = self.evidence()
        completed = next(item for item in events if item["event_type"] == "evolution_role_completed")
        write = next(
            receipt
            for receipt in completed["payload"]["action_receipts"]
            if receipt.get("action") == "workspace.write"
        )
        write["sha256"] = "0" * 64
        self.assertFalse(self.checks(events, registry)["candidate_change_bound_to_workflow"])

    def test_candidate_validation_must_match_strict_durable_evidence(self):
        events, registry = self.evidence()
        first = next(
            item["payload"]["artifact_id"]
            for item in events
            if item["event_type"] == "evolution_candidate_collected" and item["payload"].get("round") == 1
        )
        original_validation = registry.validation.side_effect
        registry.validation.side_effect = lambda artifact_id: (
            SimpleNamespace(passed=True) if artifact_id == first else original_validation(artifact_id)
        )
        self.assertFalse(self.checks(events, registry)["candidate_validation"])

    def test_promotion_requires_current_registry_champion(self):
        events, registry = self.evidence()
        registry.champion.return_value = None
        registry.champion_archive.return_value = None
        self.assertFalse(self.checks(events, registry)["candidate_promoted"])

    def test_second_generation_requires_pending_candidate_with_passing_validation(self):
        events, registry = self.evidence()
        second = next(
            item["payload"]["artifact_id"]
            for item in events
            if item["event_type"] == "evolution_candidate_collected" and item["payload"].get("round") == 2
        )
        original_candidate = registry.candidate.side_effect
        second_record = original_candidate(second)
        registry.candidate.side_effect = lambda artifact_id: (
            SimpleNamespace(
                artifact_id=second_record.artifact_id,
                parent_champion_id=second_record.parent_champion_id,
                baseline_archive_digest=second_record.baseline_archive_digest,
                state=EvolutionCandidateState.VALIDATION_FAILED,
            )
            if artifact_id == second
            else original_candidate(artifact_id)
        )
        self.assertFalse(self.checks(events, registry)["next_generation_inheritance"])

    def test_second_generation_rechecks_policy_and_fixed_workflow_entry(self):
        for path, additional_paths in (
            ("src/aegis/orchestrator.py", ()),
            ("src/aegis/evolvable/helper.py", ()),
            ("src/aegis/evolvable/workflow.py", ("src/aegis/orchestrator.py",)),
        ):
            with self.subTest(path=path, additional_paths=additional_paths):
                events, registry = self.evidence()
                second = next(
                    item["payload"]["artifact_id"]
                    for item in events
                    if item["event_type"] == "evolution_candidate_collected"
                    and item["payload"].get("round") == 2
                )
                candidate_digest = next(
                    item["payload"]["candidate_archive_sha256"]
                    for item in events
                    if item["event_type"] == "evolution_candidate_collected"
                    and item["payload"].get("round") == 1
                )
                invalid_artifact = candidate_artifact(
                    candidate_digest,
                    b"invalid-second",
                    b"invalid workflow",
                    path=path,
                    additional_paths=additional_paths,
                )
                invalid_validation = successful_validation(invalid_artifact)
                original_artifacts = registry.candidate_artifact.side_effect
                original_validations = registry.validation.side_effect
                registry.candidate_artifact.side_effect = lambda artifact_id: (
                    invalid_artifact if artifact_id == second else original_artifacts(artifact_id)
                )
                registry.validation.side_effect = lambda artifact_id: (
                    invalid_validation if artifact_id == second else original_validations(artifact_id)
                )
                collected = next(
                    item
                    for item in events
                    if item["event_type"] == "evolution_candidate_collected"
                    and item["payload"].get("round") == 2
                )
                collected["payload"]["candidate_archive_sha256"] = invalid_artifact.candidate_archive_sha256
                collected["payload"]["changes"] = list(invalid_artifact.to_mapping()["changes"])
                validation_event = next(
                    item
                    for item in events
                    if item["event_type"] == "evolution_validation_recorded"
                    and item["payload"].get("round") == 2
                )
                validation_event["payload"]["evidence"] = dict(invalid_validation.to_mapping())
                registered = next(
                    item
                    for item in events
                    if item["event_type"] == "evolution_candidate_registered"
                    and item["payload"].get("round") == 2
                )
                registered["payload"]["evidence_id"] = invalid_validation.evidence_id
                self.assertFalse(self.checks(events, registry)["next_generation_inheritance"])

    def test_source_chain_must_be_ordered_and_identity_bound(self):
        events, registry = self.evidence()
        research = next(item for item in events if item["event_type"] == "role_output")
        observations = research["payload"]["output"]["observations"]
        cases = []
        reordered = copy.deepcopy(events)
        reordered_research = next(item for item in reordered if item["event_type"] == "role_output")
        reordered_research["payload"]["output"]["observations"] = list(reversed(observations))
        cases.append(reordered)
        wrong_blob = copy.deepcopy(events)
        started = next(item for item in wrong_blob if item["event_type"] == "evolution_request_started")
        started["payload"]["source_refs"][0]["blob_sha256"] = "f" * 64
        cases.append(wrong_blob)
        for candidate_events in cases:
            with self.subTest(case=cases.index(candidate_events)):
                self.assertFalse(self.checks(candidate_events, registry)["source_bound_github_chain"])

    def test_evolution_request_sandbox_boundary_must_be_durable(self):
        for field, value in (("candidate_only", False), ("host_write_allowed", True)):
            with self.subTest(field=field):
                events, registry = self.evidence()
                started = next(item for item in events if item["event_type"] == "evolution_request_started")
                started["payload"][field] = value
                self.assertFalse(self.checks(events, registry)["evolution_request_sandbox_boundary"])

    def test_rejected_source_actions_cannot_satisfy_source_chains(self):
        for phase, action, check_name in (
            ("research", "github.collect", "source_bound_github_chain"),
            ("warrior", "paper.collect", "source_bound_paper_chain"),
        ):
            with self.subTest(action=action):
                events, registry = self.evidence()
                role_output = next(
                    item
                    for item in events
                    if item["event_type"] == "role_output" and item["payload"].get("phase") == phase
                )
                observation = next(
                    item
                    for item in role_output["payload"]["output"]["observations"]
                    if item["action"] == action
                )
                observation["result"]["accepted"] = False
                self.assertFalse(self.checks(events, registry)[check_name])

    def test_github_source_chain_accepts_warrior_phase_file_read(self):
        events, registry = self.evidence()
        research = next(
            item
            for item in events
            if item["event_type"] == "role_output" and item["payload"].get("phase") == "research"
        )
        research["payload"]["output"]["observations"] = [
            observation
            for observation in research["payload"]["output"]["observations"]
            if observation.get("action") != "github.file_read"
        ]
        self.assertTrue(self.checks(events, registry)["source_bound_github_chain"])

    def test_skill_bundle_must_be_static_archived_and_non_executable(self):
        for field, value in (
            ("skill_registry_state", "candidate"),
            ("automatic_promotion_eligible", False),
            ("execution_granted", True),
        ):
            with self.subTest(field=field):
                events, registry = self.evidence()
                research = next(
                    item
                    for item in events
                    if item["event_type"] == "role_output"
                    and item["payload"].get("phase") == "research"
                )
                bundle = next(
                    item
                    for item in research["payload"]["output"]["observations"]
                    if item["action"] == "github.skill_bundle"
                )
                bundle["result"][field] = value
                self.assertFalse(self.checks(events, registry)["declarative_skill_candidate"])

    def test_paper_excerpt_and_source_ref_are_identity_bound(self):
        events, registry = self.evidence()
        warrior = next(
            item
            for item in events
            if item["event_type"] == "role_output" and item["payload"].get("phase") == "warrior"
        )
        excerpt = next(
            item
            for item in warrior["payload"]["output"]["observations"]
            if item["action"] == "paper.excerpt_read"
        )
        excerpt["result"]["sha256"] = "f" * 64
        self.assertFalse(self.checks(events, registry)["source_bound_paper_chain"])

    def test_paper_metadata_identifier_matches_exact_bare_search_suffix(self):
        events, registry = self.evidence()
        self.assertTrue(self.checks(events, registry)["source_bound_paper_chain"])

    def test_paper_identifier_rejects_loose_bare_search_suffix(self):
        events, registry = self.evidence()
        warrior = next(
            item
            for item in events
            if item["event_type"] == "role_output" and item["payload"].get("phase") == "warrior"
        )
        collection = next(
            item
            for item in warrior["payload"]["output"]["observations"]
            if item["action"] == "paper.collect"
        )
        collection["result"]["artifact"]["metadata"]["identifier"] = "arxiv:2501.0000"
        self.assertFalse(self.checks(events, registry)["source_bound_paper_chain"])

    def test_knowledge_digest_must_come_from_prior_verified_archive(self):
        events, registry = self.evidence()
        research = next(
            item
            for item in events
            if item["event_type"] == "role_output" and item["payload"].get("phase") == "research"
        )
        remembered = next(
            item
            for item in research["payload"]["output"]["observations"]
            if item["action"] == "knowledge.remember"
        )
        remembered["result"]["sha256"] = "f" * 64
        self.assertFalse(self.checks(events, registry)["verified_knowledge_memory"])

    def test_strategy_proposal_requires_matching_persistent_candidate(self):
        events, registry = self.evidence()
        events.remove(next(item for item in events if item["event_type"] == "strategy_candidate_created"))
        self.assertFalse(self.checks(events, registry)["strategy_candidate_persisted"])

    def test_request_candidate_validation_and_registry_are_identity_bound(self):
        events, registry = self.evidence()
        collected = next(item for item in events if item["event_type"] == "evolution_candidate_collected")
        collected["payload"]["request_id"] = "evolution-request-sha256:" + "9" * 64
        checks = self.checks(events, registry)
        self.assertFalse(checks["candidate_collected"])
        self.assertFalse(checks["candidate_registered"])

    def test_paired_design_rejects_wrong_seed_product(self):
        events, registry = self.evidence()
        experiment = next(
            item for item in events if item["event_type"] == "evolution_promotion_experiment_started"
        )
        experiment["payload"]["seeds"] = [1, 2]
        checks = self.checks(events, registry)
        self.assertFalse(checks["paired_experiment_design"])
        self.assertFalse(checks["full_paired_evaluation"])

    def test_paired_evaluation_rejects_unverified_usage_and_safety_regression(self):
        for field, value in (
            ("candidate_usage_verified", False),
            ("champion_usage_verified", False),
            ("safety_violation", True),
        ):
            with self.subTest(field=field):
                events, registry = self.evidence()
                observation = next(
                    item
                    for item in events
                    if item["event_type"] == "evolution_promotion_observation_recorded"
                )
                observation["payload"][field] = value
                self.assertFalse(self.checks(events, registry)["full_paired_evaluation"])

    def test_paired_evaluation_requires_complete_matching_arm_evidence(self):
        for mutation in ("missing", "mismatch"):
            with self.subTest(mutation=mutation):
                events, registry = self.evidence()
                arm = next(item for item in events if item["event_type"] == "evolution_promotion_arm_completed")
                if mutation == "missing":
                    events.remove(arm)
                else:
                    arm["payload"]["tokens"] += 1
                self.assertFalse(self.checks(events, registry)["full_paired_evaluation"])

    def test_production_promotable_stage_is_required(self):
        events, registry = self.evidence()
        funnel = next(item for item in events if item["event_type"] == "evolution_promotion_funnel_recorded")
        funnel["payload"]["report"]["stage"] = "promoted"
        self.assertFalse(self.checks(events, registry)["candidate_promoted"])

    def test_canary_coverage_requires_every_candidate_role_phase(self):
        events, registry = self.evidence()
        events.remove(
            next(item for item in events if item["event_type"] == "evolution_promotion_canary_evaluated")
        )
        self.assertFalse(self.checks(events, registry)["network_none_canaries"])

    def test_duplicate_promotion_canary_is_rejected(self):
        events, registry = self.evidence()
        canary = next(
            item for item in events if item["event_type"] == "evolution_promotion_canary_evaluated"
        )
        events.append(copy.deepcopy(canary))
        self.assertFalse(self.checks(events, registry)["network_none_canaries"])

    def test_promotion_canary_result_integrity_and_outer_binding_are_required(self):
        for mutation in ("result-id", "context", "outer-context", "run-id", "outer-binding"):
            with self.subTest(mutation=mutation):
                events, registry = self.evidence()
                canaries = [
                    item for item in events if item["event_type"] == "evolution_promotion_canary_evaluated"
                ]
                if mutation == "outer-binding":
                    first, second = canaries[0], canaries[1]
                    first["payload"]["result"], second["payload"]["result"] = (
                        second["payload"]["result"],
                        first["payload"]["result"],
                    )
                else:
                    result = canaries[0]["payload"]["result"]
                    if mutation == "outer-context":
                        canaries[0]["payload"]["context_sha256"] = "0" * 64
                        self.assertFalse(self.checks(events, registry)["network_none_canaries"])
                        continue
                    field = {
                        "result-id": "result_id",
                        "context": "context_sha256",
                        "run-id": "run_id",
                    }[mutation]
                    result[field] = "0" * 64 if field != "run_id" else "wrong-run"
                self.assertFalse(self.checks(events, registry)["network_none_canaries"])

    def test_next_generation_must_consume_the_promoted_champion_before_role_output(self):
        for mutation in ("wrong-artifact", "late-event"):
            with self.subTest(mutation=mutation):
                events, registry = self.evidence()
                advisory_index = next(
                    index
                    for index, item in enumerate(events)
                    if item["event_type"] == "evolution_canary_evaluated"
                    and item["payload"].get("phase") == "warrior"
                )
                if mutation == "wrong-artifact":
                    events[advisory_index]["payload"]["result"]["candidate_artifact_id"] = "wrong"
                else:
                    advisory = events.pop(advisory_index)
                    role_output_index = next(
                        index
                        for index, item in enumerate(events)
                        if item["event_type"] == "role_output"
                        and item["payload"].get("round") == 2
                        and item["payload"].get("phase") == "warrior"
                    )
                    events.insert(role_output_index + 1, advisory)
                self.assertFalse(self.checks(events, registry)["next_generation_consumed_champion"])

    def test_pause_event_and_final_state_must_match_inherited_candidate(self):
        events, registry = self.evidence()
        state = next(item for item in events if item["event_type"] == "state_changed")
        state["payload"] = {"state": "promotion_gate"}
        self.assertFalse(self.checks(events, registry)["acceptance_paused_after_inheritance"])

    def test_runtime_safety_failures_fail_closed(self):
        events, registry = self.evidence()
        events.append(event("sandbox_prepare_failed", {"sandbox_id": "bad"}))
        self.assertFalse(self.checks(events, registry)["no_runtime_safety_failures"])

    def test_recovered_step_limit_failure_is_not_a_runtime_safety_failure(self):
        events, registry = self.evidence()
        role_output_index = next(
            index
            for index, item in enumerate(events)
            if item["event_type"] == "role_output"
            and item["payload"].get("round") == 1
            and item["payload"].get("phase") == "research"
        )
        events[role_output_index:role_output_index] = [
            event("campaign_error", {"type": "StepLimitExceeded", "message": "bounded"}),
            event(
                "campaign_retry_requested",
                {
                    "failure_type": "StepLimitExceeded",
                    "round": 1,
                    "phase": "research",
                    "resume_target": "warrior_research",
                },
            ),
        ]
        self.assertTrue(self.checks(events, registry)["no_runtime_safety_failures"])

    def test_initial_conservatively_accounted_capability_probes_are_auditable(self):
        events, registry = self.evidence()
        usage_index = next(
            index for index, item in enumerate(events) if item["event_type"] == "usage_committed"
        )
        probe = event(
            "usage_committed",
            {
                "protocol": "responses",
                "succeeded": False,
                "status": 400,
                "error_type": "GatewayHTTPError",
                "input_tokens": 100,
                "output_tokens": 50,
                "verified": False,
            },
        )
        success = event(
            "usage_committed",
            {
                "protocol": "chat",
                "succeeded": True,
                "status": 200,
                "error_type": None,
                "input_tokens": 10,
                "output_tokens": 5,
                "verified": True,
            },
        )
        events[usage_index : usage_index + 1] = [probe, success]
        self.assertTrue(self.checks(events, registry)["verified_usage"])

    def test_usage_rejects_non_capability_or_late_unverified_failures(self):
        base_events, registry = self.evidence()
        usage_index = next(
            index for index, item in enumerate(base_events) if item["event_type"] == "usage_committed"
        )
        failure_payload = {
            "protocol": "responses",
            "succeeded": False,
            "status": 429,
            "error_type": "GatewayHTTPError",
            "input_tokens": 100,
            "output_tokens": 50,
            "verified": False,
        }
        non_capability = copy.deepcopy(base_events)
        non_capability.insert(usage_index, event("usage_committed", failure_payload))
        late_failure = copy.deepcopy(base_events)
        late_payload = dict(failure_payload, status=400)
        late_failure.insert(usage_index + 1, event("usage_committed", late_payload))
        self.assertFalse(self.checks(non_capability, registry)["verified_usage"])
        self.assertFalse(self.checks(late_failure, registry)["verified_usage"])

    def test_conservatively_accounted_transient_retry_is_auditable(self):
        events, registry = self.evidence()
        usage_index = next(
            index for index, item in enumerate(events) if item["event_type"] == "usage_committed"
        )
        common = {
            "round": 1,
            "phase": "research",
            "role": "warrior",
            "protocol": "chat",
        }
        events[usage_index + 1 : usage_index + 1] = [
            event(
                "usage_committed",
                dict(
                    common,
                    attempt=1,
                    succeeded=False,
                    verified=False,
                    status=None,
                    error_type="RemoteDisconnected",
                    input_tokens=100,
                    output_tokens=50,
                ),
            ),
            event(
                "usage_committed",
                dict(
                    common,
                    attempt=2,
                    succeeded=True,
                    verified=True,
                    status=200,
                    error_type=None,
                    input_tokens=10,
                    output_tokens=5,
                ),
            ),
        ]
        self.assertTrue(self.checks(events, registry)["verified_usage"])

    def test_url_error_transient_retry_is_auditable(self):
        events, registry = self.evidence()
        usage_index = next(
            index for index, item in enumerate(events) if item["event_type"] == "usage_committed"
        )
        common = {
            "round": 1,
            "phase": "research",
            "role": "warrior",
            "protocol": "chat",
        }
        events[usage_index + 1 : usage_index + 1] = [
            event(
                "usage_committed",
                dict(
                    common,
                    attempt=1,
                    succeeded=False,
                    verified=False,
                    status=None,
                    error_type="URLError",
                    input_tokens=100,
                    output_tokens=50,
                ),
            ),
            event(
                "usage_committed",
                dict(
                    common,
                    attempt=2,
                    succeeded=True,
                    verified=True,
                    status=200,
                    error_type=None,
                    input_tokens=10,
                    output_tokens=5,
                ),
            ),
        ]
        self.assertTrue(self.checks(events, registry)["verified_usage"])


if __name__ == "__main__":
    unittest.main()
