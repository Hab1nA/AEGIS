"""Fail-closed verification of the dedicated autonomous-evolution smoke campaign."""

from __future__ import annotations

import hashlib
from itertools import product
from typing import Any, Mapping, Sequence

from aegis.autonomy_budget import (
    AUTONOMY_MIN_AGENT_STEPS,
    AUTONOMY_MIN_OUTPUT_TOKENS,
    AUTONOMY_ROLE_SHARES,
    autonomy_budget_check,
)
from aegis.config import AUTONOMY_ACCEPTANCE_PROFILES, CampaignConfig
from aegis.evaluation import PairedObservation
from aegis.evolution_canary import CanaryResult
from aegis.evolution_funnel import FunnelStage, VerifiedTokenEvidence, evaluate_evolution_candidate
from aegis.evolution_registry import EvolutionCandidateState, EvolutionRegistry
from aegis.evolution_validation import ValidationEvidence
from aegis.evolution_workspace import (
    EVOLUTION_WORKFLOW_ENTRY,
    CandidatePatchArtifact,
    ChangeKind,
    EvolutionPolicy,
)
from aegis.models import canonical_json
from aegis.orchestrator import CampaignController


def _hex(value: object, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def _positive_int(value: object) -> bool:
    return type(value) is int and value > 0


def _is_successful_action(item: Mapping[str, Any]) -> bool:
    result = item.get("result")
    fields = result if isinstance(result, Mapping) else item
    if fields.get("accepted") is False:
        return False
    if item.get("action") == "sandbox.exec":
        return fields.get("exit_code") == 0 and fields.get("timed_out") is not True
    return True


def _positive_step(item: Mapping[str, Any]) -> int | None:
    step = item.get("step")
    return step if type(step) is int and step > 0 else None


def _checked_step(item: Mapping[str, Any]) -> int:
    step = _positive_step(item)
    assert step is not None
    return step


def _source_receipts_are_complete(
    receipts: Sequence[Mapping[str, Any]], source_refs: Sequence[Mapping[str, Any]]
) -> tuple[bool, bool]:
    """Require each declared source to be consumed before candidate workspace I/O."""
    if not source_refs:
        return False, False
    reference_keys: set[tuple[object, object, object, object, object]] = set()
    for reference in source_refs:
        artifact_id = reference.get("artifact_id")
        kind = reference.get("kind")
        content_sha256 = reference.get("content_sha256")
        locator = reference.get("locator")
        blob_sha256 = reference.get("blob_sha256")
        if not all(
            isinstance(value, str) and value
            for value in (artifact_id, kind, content_sha256, locator, blob_sha256)
        ):
            return False, False
        reference_keys.add((artifact_id, kind, content_sha256, locator, blob_sha256))
    if len(reference_keys) != len(source_refs):
        return False, False
    successful = [receipt for receipt in receipts if _is_successful_action(receipt)]
    recalls = [receipt for receipt in successful if receipt.get("action") == "research.recall"]
    artifact_reads = [
        receipt for receipt in successful if receipt.get("action") == "research.artifact_read"
    ]
    workspace = [
        receipt
        for receipt in successful
        if receipt.get("action") in {"workspace.read", "workspace.write"}
    ]
    if not workspace or any(_positive_step(receipt) is None for receipt in successful):
        return False, False
    first_workspace_step = min(_checked_step(receipt) for receipt in workspace)
    research_before_workspace = all(
        _checked_step(receipt) < first_workspace_step
        for receipt in successful
        if receipt.get("action") in {"research.recall", "research.artifact_read"}
    )
    for reference in source_refs:
        matching_recalls = [
            receipt
            for receipt in recalls
            if receipt.get("sha256") == reference.get("content_sha256")
        ]
        matching_reads = [
            receipt
            for receipt in artifact_reads
            if receipt.get("artifact_id") == reference.get("artifact_id")
            and receipt.get("kind") == reference.get("kind")
            and receipt.get("locator") == reference.get("locator")
            and receipt.get("sha256") == reference.get("blob_sha256")
        ]
        if not any(
            _checked_step(recall) < _checked_step(artifact_read)
            for recall in matching_recalls
            for artifact_read in matching_reads
        ):
            return False, research_before_workspace
    workspace_reads = [
        receipt for receipt in successful if receipt.get("action") == "workspace.read"
    ]
    workspace_writes = [
        receipt for receipt in successful if receipt.get("action") == "workspace.write"
    ]
    executions = [receipt for receipt in successful if receipt.get("action") == "sandbox.exec"]
    io_order = any(
        _checked_step(read) < _checked_step(write) < _checked_step(execution)
        for read in workspace_reads
        for write in workspace_writes
        for execution in executions
    )
    return io_order and research_before_workspace, research_before_workspace


def _strict_validation_passed(
    artifact: CandidatePatchArtifact | None, validation: object
) -> bool:
    if not isinstance(artifact, CandidatePatchArtifact) or not isinstance(validation, ValidationEvidence):
        return False
    if (
        not validation.passed
        or validation.failure_reason is not None
        or validation.workspace_mutated
        or validation.pristine_frozen_sha256 != validation.post_validation_frozen_sha256
        or validation.candidate_artifact_id != artifact.artifact_id
        or validation.baseline_archive_sha256 != artifact.baseline_archive_sha256
        or validation.candidate_archive_sha256 != artifact.candidate_archive_sha256
        or not artifact.validation_commands
        or len(validation.commands) != len(artifact.validation_commands)
    ):
        return False
    for command, command_evidence in zip(artifact.validation_commands, validation.commands, strict=True):
        command_payload = {
            "argv": list(command.argv),
            "cwd": command.cwd,
            "timeout_seconds": command.timeout_seconds,
        }
        command_hash = hashlib.sha256(canonical_json(command_payload).encode("utf-8")).hexdigest()
        if (
            command_evidence.command_sha256 != command_hash
            or command_evidence.exit_code != 0
            or command_evidence.timed_out
            or not command_evidence.output_within_limit
        ):
            return False
    return True


def _artifact_has_permitted_workflow_change(artifact: object) -> bool:
    """Ensure a candidate changes the fixed ABI entry within the current policy."""
    if not isinstance(artifact, CandidatePatchArtifact):
        return False
    policy = EvolutionPolicy()
    return bool(
        artifact.changes
        and all(policy.permits(change.path) for change in artifact.changes)
        and any(
            change.path == EVOLUTION_WORKFLOW_ENTRY and change.kind is not ChangeKind.DELETED
            for change in artifact.changes
        )
    )


def _promotion_canary_result_is_valid(
    item: Mapping[str, Any], artifact: CandidatePatchArtifact | None
) -> bool:
    """Rebuild promotion-canary evidence and bind it to its outer experiment arm."""
    if not isinstance(artifact, CandidatePatchArtifact):
        return False
    experiment_id = item.get("experiment_id")
    task_id = item.get("task_id")
    seed = item.get("seed")
    arm = item.get("arm")
    phase = item.get("phase")
    role = item.get("role")
    if (
        not isinstance(experiment_id, str)
        or not isinstance(task_id, str)
        or type(seed) is not int
        or not isinstance(arm, str)
        or not isinstance(phase, str)
        or not isinstance(role, str)
    ):
        return False
    result_mapping = item.get("result")
    context_sha256 = item.get("context_sha256")
    if not isinstance(result_mapping, Mapping) or not _hex(context_sha256, 64):
        return False
    try:
        result = CanaryResult.from_mapping(result_mapping)
    except (TypeError, ValueError):
        return False
    identity = f"{experiment_id}-{task_id}-{seed}-{arm}"
    expected_run_id = hashlib.sha256(f"{identity}:{phase}:{role}".encode("utf-8")).hexdigest()[:16]
    expected_evidence_hash = hashlib.sha256(
        f"candidate-evaluation:{artifact.artifact_id}".encode("utf-8")
    ).hexdigest()
    return bool(
        result.run_id == expected_run_id
        and result.candidate_version == 1
        and result.candidate_artifact_id == artifact.artifact_id
        and result.baseline_archive_sha256 == artifact.baseline_archive_sha256
        and result.candidate_archive_sha256 == artifact.candidate_archive_sha256
        and result.promotion_event_hash == expected_evidence_hash
        and result.role.value == role
        and result.context_sha256 == context_sha256
        and result.passed
        and result.exit_code == 0
        and not result.timed_out
        and result.workflow is not None
    )


def _paired_observations(
    payloads: Sequence[Mapping[str, Any]], expected_pairs: set[tuple[object, object]]
) -> tuple[PairedObservation, ...] | None:
    if len(payloads) != len(expected_pairs) or {
        (item.get("task_id"), item.get("seed")) for item in payloads
    } != expected_pairs:
        return None
    try:
        return tuple(
            PairedObservation(
                str(item["task_id"]),
                item["seed"],
                item["candidate_quality"],
                item["champion_quality"],
                item["candidate_tokens"],
                item["champion_tokens"],
                item["candidate_usage_verified"],
                item["champion_usage_verified"],
                item["safety_violation"],
            )
            for item in payloads
        )
    except (KeyError, TypeError, ValueError):
        return None


def _usage_is_auditable(payloads: Sequence[Mapping[str, Any]]) -> bool:
    if not payloads:
        return False
    first_success_seen = False
    capability_statuses = {400, 404, 405, 415, 422, 501}
    for index, payload in enumerate(payloads):
        if not (
            _positive_int(payload.get("input_tokens"))
            or _positive_int(payload.get("output_tokens"))
        ):
            return False
        succeeded = payload.get("succeeded")
        if succeeded is None:
            if payload.get("verified") is not True:
                return False
            first_success_seen = True
            continue
        if succeeded is True:
            if payload.get("verified") is not True:
                return False
            status = payload.get("status")
            if type(status) is not int or not 200 <= status <= 299:
                return False
            first_success_seen = True
            continue
        if succeeded is not False:
            return False
        transient = payload.get("error_type") in {
            "ConnectionResetError",
            "RemoteDisconnected",
            "TimeoutError",
            "URLError",
            "OSError",
            "FileNotFoundError",
            "ConnectionAbortedError",
            "ConnectionRefusedError",
        }
        if first_success_seen and transient:
            attempt = payload.get("attempt")
            if (
                payload.get("verified") is not False
                or payload.get("status") is not None
                or payload.get("protocol") not in {"responses", "chat"}
                or type(attempt) is not int
                or index + 1 >= len(payloads)
            ):
                return False
            assert isinstance(attempt, int)
            following = payloads[index + 1]
            identity = ("round", "phase", "role", "protocol")
            if (
                any(following.get(key) != payload.get(key) for key in identity)
                or following.get("attempt") != attempt + 1
                or following.get("succeeded") is not True
                or following.get("verified") is not True
            ):
                return False
            continue
        if first_success_seen:
            return False
        if (
            payload.get("verified") is not False
            or payload.get("error_type") != "GatewayHTTPError"
            or payload.get("status") not in capability_statuses
            or payload.get("protocol") not in {"responses", "chat"}
        ):
            return False
    return first_success_seen


def _unrecovered_runtime_failures(events: Sequence[Mapping[str, Any]]) -> list[str]:
    always_unsafe = {"control_failed"}
    unsafe: list[str] = []
    for index, event in enumerate(events):
        event_type = event.get("event_type")
        if event_type in always_unsafe:
            unsafe.append(str(event_type))
            continue
        if event_type == "sandbox_cleanup_failed":
            payload = event.get("payload")
            sandbox_id = payload.get("sandbox_id") if isinstance(payload, Mapping) else None
            if not isinstance(sandbox_id, str) or not any(
                isinstance(candidate.get("payload"), Mapping)
                and candidate["payload"].get("sandbox_id") == sandbox_id
                and candidate.get("event_type") in {"sandbox_destroyed", "sandbox_killed"}
                for candidate in events[index + 1 :]
            ):
                unsafe.append("sandbox_cleanup_failed")
            continue
        if event_type == "sandbox_prepare_failed":
            payload = event.get("payload")
            sandbox_id = payload.get("sandbox_id") if isinstance(payload, Mapping) else None
            if not isinstance(sandbox_id, str) or not any(
                isinstance(candidate.get("payload"), Mapping)
                and candidate["payload"].get("sandbox_id") == sandbox_id
                and candidate.get("event_type") == "sandbox_prepared"
                for candidate in events[index + 1 :]
            ):
                unsafe.append("sandbox_prepare_failed")
            continue
        if event_type != "campaign_error":
            continue
        payload = event.get("payload")
        if not isinstance(payload, Mapping) or payload.get("type") != "StepLimitExceeded":
            unsafe.append("campaign_error")
            continue
        retry_index = next(
            (
                candidate
                for candidate in range(index + 1, len(events))
                if events[candidate].get("event_type") == "campaign_retry_requested"
            ),
            None,
        )
        if retry_index is None:
            unsafe.append("campaign_error")
            continue
        retry = events[retry_index].get("payload")
        if not isinstance(retry, Mapping) or retry.get("failure_type") != "StepLimitExceeded":
            unsafe.append("campaign_error")
            continue
        recovered = any(
            candidate.get("event_type") == "role_output"
            and isinstance(candidate.get("payload"), Mapping)
            and candidate["payload"].get("round") == retry.get("round")
            and candidate["payload"].get("phase") == retry.get("phase")
            for candidate in events[retry_index + 1 :]
        )
        if not recovered:
            unsafe.append("campaign_error")
    return unsafe


def _research_observations(payloads: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return [
        observation
        for payload in payloads
        for observation in payload.get("output", {}).get("observations", [])
        if isinstance(observation, Mapping)
    ]


def _search_result_items(search: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    result = search.get("result")
    if not isinstance(result, Mapping):
        return []
    items = result.get("results")
    if not isinstance(items, list):
        items = result.get("hits")
    return [item for item in items if isinstance(item, Mapping)] if isinstance(items, list) else []


def _search_mentions(search: Mapping[str, Any], value: str) -> bool:
    return any(
        any(isinstance(candidate, str) and value in candidate for candidate in item.values())
        for item in _search_result_items(search)
    )


def _contains_exact_identifier(text: str, identifier: str) -> bool:
    start = 0
    while True:
        index = text.find(identifier, start)
        if index < 0:
            return False
        end = index + len(identifier)
        before = text[index - 1] if index else ""
        after = text[end] if end < len(text) else ""
        if not (before.isalnum() or before in {".", "_", "-"}) and not (
            after.isalnum() or after in {".", "_", "-"}
        ):
            return True
        start = index + 1


def _search_mentions_identifier(search: Mapping[str, Any], identifier: str) -> bool:
    prefix, separator, suffix = identifier.partition(":")
    values = (identifier, suffix) if separator and prefix and suffix else (identifier,)
    return any(
        any(
            isinstance(candidate, str)
            and any(_contains_exact_identifier(candidate, value) for value in values)
            for candidate in item.values()
        )
        for item in _search_result_items(search)
    )


def _coherent_github_source_chain(observations: Sequence[Mapping[str, Any]], source_refs: object) -> bool:
    if not isinstance(source_refs, list):
        return False
    github_refs = [
        ref
        for ref in source_refs
        if isinstance(ref, Mapping)
        and set(ref) == {"artifact_id", "kind", "content_sha256", "locator", "blob_sha256"}
        and ref.get("kind") == "github"
        and isinstance(ref.get("artifact_id"), str)
        and isinstance(ref.get("locator"), str)
        and str(ref["locator"]).startswith("path:")
        and _hex(ref.get("content_sha256"), 64)
        and _hex(ref.get("blob_sha256"), 64)
    ]
    for search_index, search in enumerate(observations):
        if search.get("action") != "research.search":
            continue
        for resolve_index in range(search_index + 1, len(observations)):
            resolve = observations[resolve_index]
            if resolve.get("action") != "github.resolve" or not isinstance(resolve.get("result"), Mapping):
                continue
            resolved = resolve["result"]
            repository = resolved.get("repository_url")
            commit = resolved.get("commit_sha")
            if (
                not isinstance(repository, str)
                or not _hex(commit, 40)
                or not _search_mentions(search, repository)
            ):
                continue
            for collect_index in range(resolve_index + 1, len(observations)):
                collect = observations[collect_index]
                if collect.get("action") != "github.collect" or not isinstance(
                    collect.get("result"), Mapping
                ):
                    continue
                result = collect["result"]
                artifact = result.get("artifact")
                archive = result.get("persistent_archive")
                if not isinstance(artifact, Mapping) or not isinstance(archive, Mapping):
                    continue
                metadata = artifact.get("metadata")
                artifact_id = artifact.get("artifact_id")
                content_sha256 = archive.get("content_sha256")
                if (
                    not isinstance(metadata, Mapping)
                    or metadata.get("repository_url") != repository
                    or metadata.get("commit_sha") != commit
                    or archive.get("archived") is not True
                    or not isinstance(artifact_id, str)
                    or not _hex(content_sha256, 64)
                ):
                    continue
                for read in observations[collect_index + 1 :]:
                    if read.get("action") != "github.file_read" or not isinstance(
                        read.get("result"), Mapping
                    ):
                        continue
                    file_result = read["result"]
                    path = file_result.get("path")
                    sha256 = file_result.get("sha256")
                    if (
                        file_result.get("artifact_id") != artifact_id
                        or not isinstance(path, str)
                        or not _hex(sha256, 64)
                    ):
                        continue
                    if any(
                        ref.get("artifact_id") == artifact_id
                        and ref.get("content_sha256") == content_sha256
                        and ref.get("locator") == f"path:{path}"
                        and ref.get("blob_sha256") == sha256
                        for ref in github_refs
                    ):
                        return True
    return False


def _coherent_skill_bundle(observations: Sequence[Mapping[str, Any]]) -> bool:
    collected: dict[str, tuple[str, str]] = {}
    for observation in observations:
        result = observation.get("result")
        if observation.get("action") == "github.collect" and isinstance(result, Mapping):
            artifact = result.get("artifact")
            if not isinstance(artifact, Mapping) or not isinstance(artifact.get("metadata"), Mapping):
                continue
            artifact_id = artifact.get("artifact_id")
            repository = artifact["metadata"].get("repository_url")
            commit = artifact["metadata"].get("commit_sha")
            if isinstance(artifact_id, str) and isinstance(repository, str) and _hex(commit, 40):
                collected[artifact_id] = (repository, str(commit))
            continue
        if observation.get("action") != "github.skill_bundle" or not isinstance(result, Mapping):
            continue
        candidate = result.get("candidate")
        archive = result.get("persistent_archive")
        files = result.get("files")
        if not isinstance(candidate, Mapping) or not isinstance(archive, Mapping):
            continue
        source_url = candidate.get("source_url")
        bundle_sha256 = result.get("bundle_sha256")
        root = result.get("root")
        if not isinstance(source_url, str) or not isinstance(root, str) or not _hex(bundle_sha256, 64):
            continue
        source = next(
            (
                (artifact_id, repository, commit)
                for artifact_id, (repository, commit) in collected.items()
                if source_url.startswith(f"{repository}/tree/{commit}")
            ),
            None,
        )
        if source is None or not isinstance(files, list):
            continue
        _, repository, commit = source
        expected_raw_prefix = repository.replace(
            "https://github.com/", "https://raw.githubusercontent.com/"
        ) + f"/{commit}/"
        skill_file = next(
            (
                item
                for item in files
                if isinstance(item, Mapping)
                and item.get("path") == "SKILL.md"
                and isinstance(item.get("source_path"), str)
            ),
            None,
        )
        provenance = None if skill_file is None else skill_file.get("provenance")
        if (
            candidate.get("kind") == "skill"
            and isinstance(candidate.get("artifact_id"), str)
            and skill_file is not None
            and _hex(skill_file.get("sha256"), 64)
            and _hex(skill_file.get("git_blob_sha"), 40)
            and isinstance(provenance, Mapping)
            and provenance.get("sha256") == skill_file.get("sha256")
            and isinstance(provenance.get("final_url"), str)
            and str(provenance["final_url"]).startswith(expected_raw_prefix)
            and result.get("skill_registry_state") == "validated_pending"
            and result.get("automatic_promotion_eligible") is True
            and archive.get("archived") is True
            and archive.get("recall_sha256") == bundle_sha256
            and result.get("declarative_only") is True
            and result.get("execution_granted") is False
            and result.get("dependencies_installed") is False
            and result.get("permissions_registered") is False
        ):
            return True
    return False


def _coherent_paper_source_chain(
    observations: Sequence[Mapping[str, Any]], source_refs: object
) -> bool:
    if not isinstance(source_refs, list):
        return False
    paper_refs = [
        ref
        for ref in source_refs
        if isinstance(ref, Mapping)
        and set(ref) == {"artifact_id", "kind", "content_sha256", "locator", "blob_sha256"}
        and ref.get("kind") == "paper"
    ]
    for search_index, search in enumerate(observations):
        if search.get("action") != "research.search":
            continue
        for collect_index in range(search_index + 1, len(observations)):
            collect = observations[collect_index]
            result = collect.get("result")
            if collect.get("action") != "paper.collect" or not isinstance(result, Mapping):
                continue
            artifact = result.get("artifact")
            archive = result.get("persistent_archive")
            _meta = artifact.get("metadata") if isinstance(artifact, Mapping) else None
            identifier = (_meta.get("identifier") if isinstance(_meta, Mapping) else None) or result.get("identifier")
            excerpts = result.get("excerpts")
            if (
                not isinstance(artifact, Mapping)
                or artifact.get("kind") != "paper"
                or not isinstance(archive, Mapping)
                or archive.get("archived") is not True
                or not isinstance(identifier, str)
                or not _search_mentions_identifier(search, identifier)
                or not isinstance(excerpts, list)
            ):
                continue
            artifact_id = artifact.get("artifact_id")
            content_sha256 = archive.get("content_sha256")
            if not isinstance(artifact_id, str) or not _hex(content_sha256, 64):
                continue
            for read in observations[collect_index + 1 :]:
                read_result = read.get("result")
                if read.get("action") != "paper.excerpt_read" or not isinstance(read_result, Mapping):
                    continue
                locator_type = read_result.get("locator_type")
                locator = read_result.get("locator")
                excerpt_sha256 = read_result.get("sha256")
                excerpt_matches = any(
                    isinstance(item, Mapping)
                    and item.get("locator_type") == locator_type
                    and item.get("locator") == locator
                    and item.get("sha256") == excerpt_sha256
                    for item in excerpts
                )
                ref_matches = any(
                    ref.get("artifact_id") == artifact_id
                    and ref.get("content_sha256") == content_sha256
                    and ref.get("locator") == f"{locator_type}:{locator}"
                    and ref.get("blob_sha256") == excerpt_sha256
                    for ref in paper_refs
                )
                if (
                    read_result.get("artifact_id") == artifact_id
                    and isinstance(locator_type, str)
                    and isinstance(locator, str)
                    and _hex(excerpt_sha256, 64)
                    and excerpt_matches
                    and ref_matches
                ):
                    return True
    return False


def _verified_knowledge_remembered(observations: Sequence[Mapping[str, Any]]) -> bool:
    verified_digests: set[str] = set()
    for observation in observations:
        result = observation.get("result")
        if not isinstance(result, Mapping):
            continue
        if observation.get("action") == "github.collect":
            archive = result.get("persistent_archive")
            if isinstance(archive, Mapping) and archive.get("archived") is True:
                digest = archive.get("content_sha256")
                if _hex(digest, 64):
                    verified_digests.add(str(digest))
        elif observation.get("action") == "paper.collect":
            archive = result.get("persistent_archive")
            if isinstance(archive, Mapping) and archive.get("archived") is True:
                digest = archive.get("content_sha256")
                if _hex(digest, 64):
                    verified_digests.add(str(digest))
        elif (
            observation.get("action") == "knowledge.remember"
            and result.get("stored") is True
            and isinstance(result.get("artifact_id"), str)
            and result.get("sha256") in verified_digests
        ):
            return True
    return False


def verify_autonomy_campaign(
    config: CampaignConfig,
    events: Sequence[Mapping[str, Any]],
    registry: EvolutionRegistry,
) -> dict[str, Any]:
    checks: list[dict[str, object]] = []

    def check(name: str, passed: bool, detail: str) -> None:
        checks.append({"name": name, "passed": passed, "detail": detail})

    def payloads(event_type: str) -> list[Mapping[str, Any]]:
        return [
            event["payload"]
            for event in events
            if event.get("event_type") == event_type and isinstance(event.get("payload"), Mapping)
        ]

    check(
        "acceptance_profile",
        config.acceptance_profile in AUTONOMY_ACCEPTANCE_PROFILES,
        f"acceptance_profile={config.acceptance_profile}",
    )
    budget = autonomy_budget_check(
        total_tokens=config.total_tokens,
        max_requests=config.max_requests,
        role_shares={role: cfg.budget_share for role, cfg in config.roles.items()},
        max_output_tokens={role: cfg.max_output_tokens for role, cfg in config.roles.items()},
    )
    acceptance_config = (
        config.max_rounds == 2
        and config.max_agent_steps >= AUTONOMY_MIN_AGENT_STEPS
        and len(config.task_pack_paths) == 12
        and budget.passed
        and all(
            config.roles[role].budget_share == share
            for role, share in AUTONOMY_ROLE_SHARES.items()
        )
        and config.wall_time_seconds >= 28_800
        and config.research_enabled
        and not config.offline_research
        and not config.test_mode
        and not config.demo_mode
        and config.sandbox_backend == "wsl"
        and all(
            config.roles[role].max_output_tokens >= AUTONOMY_MIN_OUTPUT_TOKENS
            for role in AUTONOMY_ROLE_SHARES
        )
    )
    check(
        "acceptance_configuration",
        acceptance_config,
        (
            f"rounds={config.max_rounds}, taskpacks={len(config.task_pack_paths)}, "
            f"backend={config.sandbox_backend}, budget_failures={list(budget.failures)}"
        ),
    )

    research_outputs = [
        payload
        for payload in payloads("role_output")
        if payload.get("round") == 1 and payload.get("phase") == "research"
    ]
    warrior_outputs = [
        payload
        for payload in payloads("role_output")
        if payload.get("round") == 1 and payload.get("phase") == "warrior"
    ]
    research_observations = [
        obs for obs in _research_observations(research_outputs) if _is_successful_action(obs)
    ]
    warrior_observations = [
        obs for obs in _research_observations(warrior_outputs) if _is_successful_action(obs)
    ]
    research_actions = {observation.get("action") for observation in research_observations}
    warrior_actions = {observation.get("action") for observation in warrior_observations}
    required_research = {
        "research.search",
        "github.resolve",
        "github.collect",
        "github.file_read",
        "github.skill_bundle",
        "knowledge.remember",
        "strategy.propose",
    }
    required_warrior = {
        "research.search",
        "paper.collect",
        "paper.excerpt_read",
        "research.recall",
        "github.file_read",
        "evolution.request",
    }
    check(
        "autonomous_research_actions",
        required_research <= research_actions and required_warrior <= warrior_actions,
        "research="
        f"{sorted(str(action) for action in research_actions)}, "
        f"warrior={sorted(str(action) for action in warrior_actions)}",
    )
    check(
        "declarative_skill_candidate",
        _coherent_skill_bundle(research_observations),
        "pinned GitHub Skill bundle is statically validated, archived, and non-executable",
    )
    check(
        "verified_knowledge_memory",
        _verified_knowledge_remembered(research_observations),
        "remembered digest must come from an earlier verified archive in the same role run",
    )

    proposals = [
        observation["result"]
        for observation in research_observations
        if observation.get("action") == "strategy.propose"
        and isinstance(observation.get("result"), Mapping)
    ]
    proposal = proposals[0] if len(proposals) == 1 else None
    strategy_events = payloads("strategy_candidate_created")
    matching_strategy = [
        item.get("strategy")
        for item in strategy_events
        if isinstance(item.get("strategy"), Mapping)
        and isinstance(proposal, Mapping)
        and item["strategy"].get("proposal_id") == proposal.get("proposal_id")
        and item["strategy"].get("target_role") == proposal.get("target_role") == "warrior"
        and item["strategy"].get("proposed_by") == "warrior"
        and item["strategy"].get("content") == proposal.get("content")
    ]
    accepted_strategies = [
        item
        for item in payloads("role_strategy_proposals_accepted")
        if item.get("round") == 1
        and item.get("phase") == "research"
        and item.get("role") == "warrior"
    ]
    strategy = matching_strategy[0] if len(matching_strategy) == 1 else None
    strategy_persisted = bool(
        isinstance(strategy, Mapping)
        and isinstance(strategy.get("version_id"), str)
        and isinstance(strategy.get("parent_version_id"), str)
        and _hex(strategy.get("content_hash"), 64)
        and len(accepted_strategies) == 1
        and accepted_strategies[0].get("candidate_ids") == [strategy.get("version_id")]
    )
    check(
        "strategy_candidate_persisted",
        strategy_persisted,
        "one explicit Warrior workflow proposal must become one pending strategy candidate",
    )

    first_requests = [item for item in payloads("evolution_request_started") if item.get("round") == 1]
    first_started = first_requests[0] if len(first_requests) == 1 else None
    first_request_id = None if first_started is None else first_started.get("request_id")
    first_sources = [] if first_started is None else first_started.get("source_refs", [])
    sandbox_boundary_passed = bool(
        first_started is not None
        and first_started.get("candidate_only") is True
        and first_started.get("host_write_allowed") is False
    )
    check(
        "evolution_request_sandbox_boundary",
        sandbox_boundary_passed,
        "candidate_only=true and host_write_allowed=false are durably recorded",
    )
    source_chain_passed = _coherent_github_source_chain(research_observations + warrior_observations, first_sources)
    check(
        "source_bound_github_chain",
        source_chain_passed,
        f"requests={len(first_requests)}, source_refs={len(first_sources) if isinstance(first_sources, list) else 0}",
    )
    paper_chain_passed = _coherent_paper_source_chain(warrior_observations, first_sources)
    check(
        "source_bound_paper_chain",
        paper_chain_passed,
        f"requests={len(first_requests)}, paper_actions={sorted(str(action) for action in warrior_actions)}",
    )
    evolution_roles = [
        item
        for item in payloads("evolution_role_completed")
        if item.get("round") == 1 and item.get("request_id") == first_request_id
    ]
    raw_action_receipts = (
        evolution_roles[0].get("action_receipts", []) if len(evolution_roles) == 1 else []
    )
    action_receipts = (
        [item for item in raw_action_receipts if isinstance(item, Mapping)]
        if isinstance(raw_action_receipts, list)
        else []
    )
    source_refs_list = (
        [item for item in first_sources if isinstance(item, Mapping)]
        if isinstance(first_sources, list)
        else []
    )
    sources_are_well_formed = isinstance(first_sources, list) and len(source_refs_list) == len(first_sources)
    evolution_receipts_passed, research_before_workspace = _source_receipts_are_complete(
        action_receipts, source_refs_list
    )
    evolution_receipts_passed = sources_are_well_formed and evolution_receipts_passed
    check(
        "evolution_role_consumed_bound_source",
        evolution_receipts_passed,
        f"action_receipts={len(action_receipts)}, refs={len(source_refs_list)}, "
        f"research_before_ws={research_before_workspace}",
    )

    collected = payloads("evolution_candidate_collected")
    first_candidates = [
        item for item in collected if item.get("round") == 1 and item.get("request_id") == first_request_id
    ]
    first_collected = first_candidates[0] if len(first_candidates) == 1 else None
    first_artifact_id = None if first_collected is None else first_collected.get("artifact_id")
    artifact: CandidatePatchArtifact | None = None
    origin: CandidatePatchArtifact | None = None
    validation: ValidationEvidence | None = None
    if isinstance(first_request_id, str) and isinstance(first_artifact_id, str):
        try:
            origin = registry.candidate_for_request(first_request_id)
            artifact = registry.candidate_artifact(first_artifact_id)
            validation = registry.validation(first_artifact_id)
        except RuntimeError:
            pass
    candidate_collected = bool(
        first_collected is not None
        and isinstance(first_artifact_id, str)
        and first_started is not None
        and first_collected.get("baseline_archive_sha256") == first_started.get("baseline_archive_sha256")
        and _hex(first_collected.get("baseline_archive_sha256"), 64)
        and _hex(first_collected.get("candidate_archive_sha256"), 64)
        and isinstance(first_collected.get("changes"), list)
        and bool(first_collected["changes"])
    )
    check("candidate_collected", candidate_collected, f"artifact_id={first_artifact_id}")

    collected_changes = first_collected.get("changes", []) if first_collected is not None else []
    workflow_change = next(
        (
            item
            for item in collected_changes
            if isinstance(item, Mapping)
            and item.get("path") == "src/aegis/evolvable/workflow.py"
        ),
        None,
    )
    write_receipts = [
        receipt
        for receipt in action_receipts
        if receipt.get("action") == "workspace.write" and _is_successful_action(receipt)
    ]
    ws_write_bound = bool(
        isinstance(artifact, CandidatePatchArtifact)
        and origin == artifact
        and workflow_change is not None
        and _artifact_has_permitted_workflow_change(artifact)
        and workflow_change.get("path") == EVOLUTION_WORKFLOW_ENTRY
        and workflow_change.get("candidate_sha256")
        == next(
            change.candidate_sha256
            for change in artifact.changes
            if change.path == EVOLUTION_WORKFLOW_ENTRY
        )
        and first_collected is not None
        and first_collected.get("changes") == list(artifact.to_mapping()["changes"])
        and any(
            r.get("path") == EVOLUTION_WORKFLOW_ENTRY
            and r.get("sha256")
            == next(
                change.candidate_sha256
                for change in artifact.changes
                if change.path == EVOLUTION_WORKFLOW_ENTRY
            )
            for r in write_receipts
        )
    )
    check(
        "candidate_change_bound_to_workflow",
        ws_write_bound,
        f"changes={len(collected_changes)}, workspace_write_receipts={len(write_receipts)}",
    )

    first_validation = next(
        (
            item
            for item in payloads("evolution_validation_recorded")
            if item.get("round") == 1
            and item.get("request_id") == first_request_id
            and item.get("artifact_id") == first_artifact_id
        ),
        None,
    )
    evidence = None if first_validation is None else first_validation.get("evidence")
    validation_passed = bool(
        _strict_validation_passed(artifact, validation)
        and isinstance(evidence, Mapping)
        and isinstance(validation, ValidationEvidence)
        and dict(evidence) == dict(validation.to_mapping())
    )
    check(
        "candidate_validation",
        validation_passed,
        "identity-bound validation passed" if validation_passed else "missing, failed, or mismatched",
    )
    registered = any(
        item.get("round") == 1
        and item.get("request_id") == first_request_id
        and item.get("artifact_id") == first_artifact_id
        and item.get("state") == EvolutionCandidateState.CANDIDATE.value
        and isinstance(validation, ValidationEvidence)
        and item.get("evidence_id") == validation.evidence_id
        for item in payloads("evolution_candidate_registered")
    )
    completed = any(
        item.get("round") == 1
        and item.get("request_id") == first_request_id
        and item.get("status") == "pending"
        for item in payloads("evolution_request_completed")
    )
    registry_bound = bool(
        isinstance(artifact, CandidatePatchArtifact)
        and origin == artifact
        and first_collected is not None
        and artifact.artifact_id == first_artifact_id
        and artifact.baseline_archive_sha256 == first_collected.get("baseline_archive_sha256")
        and artifact.candidate_archive_sha256 == first_collected.get("candidate_archive_sha256")
    )
    check(
        "candidate_registered",
        registered and completed and registry_bound,
        f"registered={registered}, request_completed={completed}, registry_bound={registry_bound}",
    )

    matching_experiments = [
        item
        for item in payloads("evolution_promotion_experiment_started")
        if item.get("candidate_artifact_id") == first_artifact_id
    ]
    experiment = matching_experiments[0] if len(matching_experiments) == 1 else None
    experiment_id = None if experiment is None else experiment.get("experiment_id")
    task_ids = [] if experiment is None else experiment.get("task_ids", [])
    seeds = [] if experiment is None else experiment.get("seeds", [])
    expected_pairs = (
        set(product(task_ids, seeds)) if isinstance(task_ids, list) and isinstance(seeds, list) else set()
    )
    design_passed = bool(
        experiment is not None
        and isinstance(experiment_id, str)
        and isinstance(task_ids, list)
        and len(task_ids) == 12
        and len(set(task_ids)) == 12
        and all(isinstance(item, str) and item for item in task_ids)
        and seeds == [0, 1]
        and experiment.get("smoke_pairs") == [[task_ids[0], 0], [task_ids[1], 0]]
    )
    check(
        "paired_experiment_design",
        design_passed,
        f"tasks={len(task_ids) if isinstance(task_ids, list) else 0}, seeds={seeds}",
    )

    promotion_observations = [
        item
        for item in payloads("evolution_promotion_observation_recorded")
        if item.get("experiment_id") == experiment_id
    ]
    observations = _paired_observations(promotion_observations, expected_pairs)
    promotion_arms = [
        item
        for item in payloads("evolution_promotion_arm_completed")
        if item.get("experiment_id") == experiment_id
    ]
    expected_arms = {
        (task_id, seed, arm)
        for task_id, seed in expected_pairs
        for arm in ("candidate", "baseline")
    }
    arm_by_key = {
        (item.get("task_id"), item.get("seed"), item.get("arm")): item for item in promotion_arms
    }
    arms_passed = bool(
        design_passed
        and len(promotion_arms) == len(expected_arms)
        and set(arm_by_key) == expected_arms
        and all(item.get("candidate_artifact_id") == first_artifact_id for item in promotion_arms)
    )
    if arms_passed:
        assert observations is not None
        for observation in observations:
            candidate_arm = arm_by_key[(observation.task_id, observation.seed, "candidate")]
            baseline_arm = arm_by_key[(observation.task_id, observation.seed, "baseline")]
            if (
                candidate_arm.get("quality") != observation.candidate_quality
                or baseline_arm.get("quality") != observation.champion_quality
                or candidate_arm.get("tokens") != observation.candidate_tokens
                or baseline_arm.get("tokens") != observation.champion_tokens
                or candidate_arm.get("usage_verified") is not observation.candidate_usage_verified
                or baseline_arm.get("usage_verified") is not observation.champion_usage_verified
                or observation.safety_violation
                != bool(
                    candidate_arm.get("safety_violations") or baseline_arm.get("safety_violations")
                )
            ):
                arms_passed = False
                break
    paired_passed = bool(
        design_passed
        and observations is not None
        and len(observations) == 24
        and arms_passed
        and all(item.get("candidate_artifact_id") == first_artifact_id for item in promotion_observations)
        and all(
            row.candidate_usage_verified and row.champion_usage_verified and not row.safety_violation
            for row in observations
        )
    )
    check(
        "full_paired_evaluation",
        paired_passed,
        f"paired_observations={len(promotion_observations)}, paired_arms={len(promotion_arms)}",
    )

    funnels = [
        item
        for item in payloads("evolution_promotion_funnel_recorded")
        if item.get("experiment_id") == experiment_id
    ]
    report = funnels[-1].get("report") if funnels else None
    promoted_events = [
        item
        for item in payloads("evolution_candidate_promoted")
        if item.get("experiment_id") == experiment_id
        and item.get("candidate_artifact_id") == first_artifact_id
    ]
    recomputed_report = None
    if paired_passed and isinstance(artifact, CandidatePatchArtifact) and validation is not None:
        assert observations is not None
        smoke_pairs = experiment.get("smoke_pairs", []) if experiment is not None else []
        smoke_keys = {
            (item[0], item[1])
            for item in smoke_pairs
            if isinstance(item, list) and len(item) == 2
        }
        smoke = tuple(
            row for row in observations if (row.task_id, row.seed) in smoke_keys
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
                        for row in sorted(observations, key=lambda row: (row.task_id, row.seed))
                    ]
                }
            ).encode("utf-8")
        ).hexdigest()
        try:
            token_evidence = VerifiedTokenEvidence.create(
                candidate_artifact_id=artifact.artifact_id,
                baseline_archive_sha256=artifact.baseline_archive_sha256,
                observations=observations,
                usage_verified=True,
                source_report_sha256=source_report_sha256,
            )
            recomputed_report = evaluate_evolution_candidate(
                artifact,
                validation,
                smoke,
                observations,
                token_evidence,
            ).report.to_dict()
        except (TypeError, ValueError):
            recomputed_report = None
    registry_promoted = False
    champion_archive = None
    try:
        champion = registry.champion()
        champion_archive = registry.champion_archive()
    except RuntimeError:
        pass
    else:
        registry_promoted = bool(
            champion is not None
            and champion.artifact_id == first_artifact_id
            and champion.state is EvolutionCandidateState.CHAMPION
            and champion_archive is not None
            and champion_archive.artifact_id == first_artifact_id
            and isinstance(artifact, CandidatePatchArtifact)
            and champion_archive.expected_digest == artifact.candidate_archive_sha256
        )
    funnel_promoted = bool(
        isinstance(report, Mapping)
        and recomputed_report is not None
        and dict(report) == recomputed_report
        and report.get("stage") == FunnelStage.PROMOTABLE.value
        and len(promoted_events) == 1
        and registry_promoted
    )
    check(
        "candidate_promoted",
        funnel_promoted,
        "recomputed promotable funnel report followed by one registry-confirmed CAS promotion",
    )

    canaries = [
        item
        for item in payloads("evolution_promotion_canary_evaluated")
        if item.get("experiment_id") == experiment_id
    ]
    phase_roles = {
        ("promotion_research", "warrior"),
        ("promotion_warrior", "warrior"),
        ("promotion_judge", "judge"),
        ("promotion_prosecutor", "prosecutor"),
    }
    expected_canaries = {
        (task_id, seed, "evolution-candidate", phase, role)
        for task_id, seed in expected_pairs
        for phase, role in phase_roles
    }
    canary_keys = {
        (item.get("task_id"), item.get("seed"), item.get("arm"), item.get("phase"), item.get("role"))
        for item in canaries
    }
    canaries_passed = bool(
        design_passed
        and len(canaries) == len(expected_canaries)
        and canary_keys == expected_canaries
        and all(_promotion_canary_result_is_valid(item, artifact) for item in canaries)
    )
    check("network_none_canaries", canaries_passed, f"canary_results={len(canaries)}")

    deferred = payloads("autonomy_acceptance_auxiliary_promotions_deferred")
    auxiliary_deferred = bool(
        len(deferred) == 1
        and deferred[0].get("round") == 1
        and "fixed request budget" in str(deferred[0].get("reason", ""))
    )
    check(
        "auxiliary_promotions_deferred",
        auxiliary_deferred,
        "Skill and Strategy candidates are retained pending while the fixed smoke budget proves code evolution",
    )

    round_two_advisories: set[str] = set()
    for index, event in enumerate(events):
        if event.get("event_type") != "evolution_canary_evaluated":
            continue
        payload = event.get("payload")
        if not isinstance(payload, Mapping) or payload.get("round") != 2:
            continue
        phase = payload.get("phase")
        result = payload.get("result")
        if (
            phase not in {"research", "warrior"}
            or payload.get("role") != "warrior"
            or not isinstance(result, Mapping)
            or result.get("passed") is not True
            or result.get("candidate_artifact_id") != first_artifact_id
            or first_collected is None
            or result.get("baseline_archive_sha256")
            != first_collected.get("baseline_archive_sha256")
            or result.get("candidate_archive_sha256")
            != first_collected.get("candidate_archive_sha256")
            or not isinstance(result.get("workflow"), Mapping)
        ):
            continue
        role_output_after = any(
            later.get("event_type") == "role_output"
            and isinstance(later.get("payload"), Mapping)
            and later["payload"].get("round") == 2
            and later["payload"].get("phase") == phase
            for later in events[index + 1 :]
        )
        if role_output_after:
            round_two_advisories.add(str(phase))
    check(
        "next_generation_consumed_champion",
        round_two_advisories == {"research", "warrior"},
        f"ordinary_round_two_phases={sorted(round_two_advisories)}",
    )

    second_candidates = [item for item in collected if item.get("round") == 2]
    second_collected = second_candidates[0] if len(second_candidates) == 1 else None
    inheritance_passed = False
    inheritance_detail = "exactly one second-generation candidate is required"
    second_id = None if second_collected is None else second_collected.get("artifact_id")
    second_request_id = None if second_collected is None else second_collected.get("request_id")
    if (
        second_collected is not None
        and isinstance(first_artifact_id, str)
        and isinstance(second_id, str)
        and isinstance(second_request_id, str)
    ):
        try:
            first_artifact = registry.candidate_artifact(first_artifact_id)
            second_artifact = registry.candidate_artifact(second_id)
            second_record = registry.candidate(second_id)
            second_validation = registry.validation(second_id)
        except RuntimeError as exc:
            inheritance_detail = str(exc)
        else:
            second_validation_event = next(
                (
                    item
                    for item in payloads("evolution_validation_recorded")
                    if item.get("round") == 2
                    and item.get("request_id") == second_request_id
                    and item.get("artifact_id") == second_id
                ),
                None,
            )
            second_registered = any(
                item.get("round") == 2
                and item.get("request_id") == second_request_id
                and item.get("artifact_id") == second_id
                and item.get("state") == EvolutionCandidateState.CANDIDATE.value
                and item.get("evidence_id") == second_validation.evidence_id
                for item in payloads("evolution_candidate_registered")
            )
            second_completed = any(
                item.get("round") == 2
                and item.get("request_id") == second_request_id
                and item.get("status") == "pending"
                for item in payloads("evolution_request_completed")
            )
            inheritance_passed = bool(
                second_collected.get("baseline_archive_sha256") == first_artifact.candidate_archive_sha256
                and second_record.parent_champion_id == first_artifact_id
                and second_record.baseline_archive_digest == first_artifact.candidate_archive_sha256
                and second_record.state is EvolutionCandidateState.CANDIDATE
                and second_artifact.baseline_archive_sha256 == first_artifact.candidate_archive_sha256
                and _artifact_has_permitted_workflow_change(second_artifact)
                and _strict_validation_passed(second_artifact, second_validation)
                and isinstance(second_validation_event, Mapping)
                and second_validation_event.get("evidence") == second_validation.to_mapping()
                and second_registered
                and second_completed
            )
            inheritance_detail = (
                f"parent={second_record.parent_champion_id}, baseline={second_record.baseline_archive_digest}"
            )
    check("next_generation_inheritance", inheritance_passed, inheritance_detail)

    inheritance_events = payloads("autonomy_acceptance_inheritance_observed")
    inheritance_event_passed = bool(
        len(inheritance_events) == 1
        and inheritance_events[0].get("round") == 2
        and inheritance_events[0].get("artifact_id") == second_id
        and inheritance_events[0].get("parent_champion_id") == first_artifact_id
        and second_collected is not None
        and inheritance_events[0].get("baseline_archive_sha256")
        == second_collected.get("baseline_archive_sha256")
    )
    state_changes = payloads("state_changed")
    paused = bool(
        state_changes
        and state_changes[-1].get("state") == "paused"
        and state_changes[-1].get("resume_target") == "promotion_gate"
    )
    check(
        "acceptance_paused_after_inheritance",
        inheritance_event_passed and paused,
        f"inheritance_event={inheritance_event_passed}, final_state={state_changes[-1].get('state') if state_changes else None}",
    )

    usage = payloads("usage_committed")
    usage_passed = _usage_is_auditable(usage)
    check("verified_usage", usage_passed, f"usage_events={len(usage)}")
    if config.acceptance_profile == "autonomous_evolution_v2":
        quality_events = [item for item in payloads("quality_locked") if item.get("round") == 1]
        judge_outputs = [
            item.get("output")
            for item in payloads("role_output")
            if item.get("round") == 1 and item.get("phase") == "judge"
        ]
        prosecutor_outputs = [
            item.get("output")
            for item in payloads("role_output")
            if item.get("round") == 1 and item.get("phase") == "prosecutor"
        ]
        feedback_events = [item for item in payloads("round_feedback_recorded") if item.get("round") == 1]
        feedback_positions = [
            index
            for index, item in enumerate(events)
            if item.get("event_type") == "round_feedback_recorded"
            and isinstance(item.get("payload"), Mapping)
            and item["payload"].get("round") == 1
        ]
        expected_feedback: Mapping[str, Any] | None = None
        if (
            len(quality_events) == len(judge_outputs) == len(prosecutor_outputs) == 1
            and isinstance(quality_events[0].get("quality"), Mapping)
            and isinstance(judge_outputs[0], Mapping)
            and isinstance(prosecutor_outputs[0], Mapping)
        ):
            expected_feedback = CampaignController._round_feedback_payload(
                1,
                quality_events[0]["quality"],
                judge_outputs[0],
                prosecutor_outputs[0],
            )
        feedback_recorded = (
            expected_feedback is not None
            and len(feedback_events) == 1
            and len(feedback_positions) == 1
            and feedback_events[0] == expected_feedback
        )
        check(
            "round_feedback_recorded",
            feedback_recorded,
            f"feedback_events={len(feedback_events)}, evidence_bound={expected_feedback is not None}",
        )
        feedback_id = expected_feedback.get("feedback_id") if expected_feedback is not None else None
        required_feedback_ids = {
            item["feedback_id"]
            for item in expected_feedback.get("items", [])
            if isinstance(item, Mapping) and isinstance(item.get("feedback_id"), str)
        } if expected_feedback is not None else set()
        second_warriors = [
            item.get("output")
            for item in payloads("role_output")
            if item.get("round") == 2 and item.get("phase") == "warrior"
        ]
        second_warrior_positions = [
            index
            for index, item in enumerate(events)
            if item.get("event_type") == "role_output"
            and isinstance(item.get("payload"), Mapping)
            and item["payload"].get("round") == 2
            and item["payload"].get("phase") == "warrior"
        ]
        feedback_before_second_warrior = bool(
            feedback_positions
            and second_warrior_positions
            and feedback_positions[0] < second_warrior_positions[0]
        )
        feedback_dispositions = False
        if len(second_warriors) == 1 and isinstance(second_warriors[0], Mapping):
            submission = second_warriors[0].get("submission")
            entries = submission.get("feedback_dispositions") if isinstance(submission, Mapping) else None
            if isinstance(entries, list):
                assert isinstance(submission, Mapping)
                disposition_ids = {
                    item.get("feedback_id")
                    for item in entries
                    if isinstance(item, Mapping)
                    and item.get("decision") in {"adopt", "defer", "reject"}
                    and isinstance(item.get("rationale"), str)
                    and bool(item["rationale"].strip())
                }
                feedback_dispositions = (
                    submission.get("feedback_round") == 1
                    and submission.get("feedback_id") == feedback_id
                    and len(entries) == len(required_feedback_ids)
                    and disposition_ids == required_feedback_ids
                    and feedback_before_second_warrior
                )
        check(
            "next_round_warrior_feedback_dispositions",
            feedback_dispositions,
            f"round_two_warrior_outputs={len(second_warriors)}, feedback_id={feedback_id}",
        )
    observed_unsafe = sorted(_unrecovered_runtime_failures(events))
    check("no_runtime_safety_failures", not observed_unsafe, f"events={observed_unsafe}")
    return {
        "campaign_id": config.campaign_id,
        "passed": all(bool(item["passed"]) for item in checks),
        "checks": checks,
    }
