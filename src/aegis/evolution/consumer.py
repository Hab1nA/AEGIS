"""Consume cycle evidence and materialize evolution candidates."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from aegis.artifacts import ContentAddressedArtifactStore
from aegis.models import Role

from .registry import CandidateState, EvolutionRegistry, EvolutionRegistryError
from .surfaces import (
    EvolutionProposal,
    EvolutionSurface,
    EvolutionSurfaceError,
    validate_evolution_proposal,
    validate_subject_content,
    validate_workflow_content,
)


class EvolutionConsumerError(RuntimeError):
    """Raised when cycle evidence cannot be consumed safely."""


@dataclass(frozen=True, slots=True)
class ConsumedCandidate:
    surface: EvolutionSurface
    target_role: Role
    artifact_id: str
    artifact_sha256: str
    source: str
    proposal_id: str | None
    rationale: str
    collected: bool
    validated: bool
    error: str | None

    def to_mapping(self) -> dict[str, Any]:
        return {
            "surface": self.surface.value,
            "target_role": self.target_role.value,
            "artifact_id": self.artifact_id,
            "artifact_sha256": self.artifact_sha256,
            "source": self.source,
            "proposal_id": self.proposal_id,
            "rationale": self.rationale,
            "collected": self.collected,
            "validated": self.validated,
            "error": self.error,
        }


def _materialize(
    artifacts: ContentAddressedArtifactStore,
    surface: EvolutionSurface,
    content_json: Mapping[str, Any],
) -> tuple[str, str]:
    ref = artifacts.put_json(surface.value, content_json)
    digest = ref.artifact_id.rsplit(":", 1)[1]
    return ref.artifact_id, digest


def _record_candidate(
    *,
    registry: EvolutionRegistry,
    artifacts: ContentAddressedArtifactStore,
    surface: EvolutionSurface,
    target_role: Role,
    content_json: Mapping[str, Any],
    objective_id: str,
    collection_evidence_id: str,
    source: str,
    proposal_id: str | None,
    rationale: str,
) -> ConsumedCandidate:
    artifact_id, artifact_sha256 = _materialize(artifacts, surface, content_json)
    try:
        registry.collect(
            surface,
            target_role,
            artifact_id=artifact_id,
            artifact_sha256=artifact_sha256,
            objective_id=objective_id,
            collection_evidence_id=collection_evidence_id,
        )
    except EvolutionRegistryError as exc:
        existing = next(
            (
                item
                for item in registry.candidates()
                if item.surface is surface
                and item.target_role is target_role
                and item.artifact_id == artifact_id
            ),
            None,
        )
        if existing is not None and existing.state is CandidateState.REJECTED:
            return ConsumedCandidate(
                surface,
                target_role,
                artifact_id,
                artifact_sha256,
                source,
                proposal_id,
                rationale,
                collected=True,
                validated=False,
                error="candidate was already rejected",
            )
        if existing is not None:
            return _validate_collected(
                registry=registry,
                surface=surface,
                target_role=target_role,
                artifact_id=artifact_id,
                source=source,
                proposal_id=proposal_id,
                rationale=rationale,
            )
        return ConsumedCandidate(
            surface,
            target_role,
            artifact_id,
            artifact_sha256,
            source,
            proposal_id,
            rationale,
            collected=False,
            validated=False,
            error=str(exc),
        )
    return _validate_collected(
        registry=registry,
        surface=surface,
        target_role=target_role,
        artifact_id=artifact_id,
        source=source,
        proposal_id=proposal_id,
        rationale=rationale,
    )


def _validate_collected(
    *,
    registry: EvolutionRegistry,
    surface: EvolutionSurface,
    target_role: Role,
    artifact_id: str,
    source: str,
    proposal_id: str | None,
    rationale: str,
) -> ConsumedCandidate:
    record = next(
        (
            item
            for item in registry.candidates()
            if item.surface is surface
            and item.target_role is target_role
            and item.artifact_id == artifact_id
        ),
        None,
    )
    if record is None:
        return ConsumedCandidate(
            surface,
            target_role,
            artifact_id,
            "",
            source,
            proposal_id,
            rationale,
            collected=False,
            validated=False,
            error="candidate was not collected",
        )
    if record.state is CandidateState.REJECTED:
        return ConsumedCandidate(
            surface,
            target_role,
            artifact_id,
            record.artifact_sha256,
            source,
            proposal_id,
            rationale,
            collected=True,
            validated=False,
            error="candidate was rejected",
        )
    if record.state is not CandidateState.COLLECTED:
        return ConsumedCandidate(
            surface,
            target_role,
            artifact_id,
            record.artifact_sha256,
            source,
            proposal_id,
            rationale,
            collected=True,
            validated=True,
            error=None,
        )
    try:
        registry.validate(
            record.candidate_id,
            validation_evidence_id=record.collection_evidence_id,
        )
    except EvolutionRegistryError as exc:
        return ConsumedCandidate(
            surface,
            target_role,
            artifact_id,
            record.artifact_sha256,
            source,
            proposal_id,
            rationale,
            collected=True,
            validated=False,
            error=str(exc),
        )
    return ConsumedCandidate(
        surface,
        target_role,
        artifact_id,
        record.artifact_sha256,
        source,
        proposal_id,
        rationale,
        collected=True,
        validated=True,
        error=None,
    )


def _consume_proposal(
    *,
    registry: EvolutionRegistry,
    artifacts: ContentAddressedArtifactStore,
    proposal: EvolutionProposal,
    objective_id: str,
    collection_evidence_id: str,
    source: str,
    proposal_id: str | None,
    rationale: str,
) -> ConsumedCandidate:
    return _record_candidate(
        registry=registry,
        artifacts=artifacts,
        surface=proposal.surface,
        target_role=proposal.target_role,
        content_json=proposal.content_to_json(),
        objective_id=objective_id,
        collection_evidence_id=collection_evidence_id,
        source=source,
        proposal_id=proposal_id,
        rationale=rationale,
    )


def consume_cycle_proposals(
    *,
    registry: EvolutionRegistry,
    artifacts: ContentAddressedArtifactStore,
    submission: Mapping[str, Any],
    prosecutor_audit: Mapping[str, Any],
    objective_id: str,
    collection_evidence_id: str,
) -> tuple[ConsumedCandidate, ...]:
    """Scan one cycle's evidence and collect every valid evolution candidate."""
    consumed: list[ConsumedCandidate] = []
    submitter_role: Role | None = None
    raw_role = submission.get("role")
    if isinstance(raw_role, str):
        try:
            submitter_role = Role(raw_role)
        except ValueError:
            submitter_role = None
    nested = submission.get("submission")
    if isinstance(nested, Mapping):
        submission = nested

    for raw in submission.get("evolution_requests", []):
        if not isinstance(raw, Mapping) or not isinstance(raw.get("proposal"), Mapping):
            continue
        try:
            proposal = validate_evolution_proposal(
                raw["proposal"], proposer=Role.WARRIOR
            )
        except EvolutionSurfaceError as exc:
            consumed.append(
                ConsumedCandidate(
                    EvolutionSurface.WORKFLOW,
                    Role.WARRIOR,
                    "",
                    "",
                    "evolution.request",
                    raw.get("objective"),
                    str(raw.get("rationale", ""))[:2000],
                    collected=False,
                    validated=False,
                    error=str(exc),
                )
            )
            continue
        consumed.append(
            _consume_proposal(
                registry=registry,
                artifacts=artifacts,
                proposal=proposal,
                objective_id=objective_id,
                collection_evidence_id=collection_evidence_id,
                source="evolution.request",
                proposal_id=raw.get("objective"),
                rationale=str(raw.get("rationale", ""))[:2000],
            )
        )

    if submitter_role is not None:
        for raw in submission.get("strategy_proposals", []):
            if not isinstance(raw, Mapping):
                continue
            target_text = raw.get("target_role")
            content = raw.get("content")
            if not isinstance(target_text, str) or not isinstance(content, Mapping):
                continue
            try:
                target_role = Role(target_text)
            except ValueError:
                continue
            if target_role is not submitter_role:
                continue
            try:
                workflow = validate_workflow_content(content)
            except EvolutionSurfaceError as exc:
                consumed.append(
                    ConsumedCandidate(
                        EvolutionSurface.WORKFLOW,
                        target_role,
                        "",
                        "",
                        "strategy.propose",
                        raw.get("proposal_id"),
                        str(raw.get("rationale", ""))[:2000],
                        collected=False,
                        validated=False,
                        error=str(exc),
                    )
                )
                continue
            consumed.append(
                _record_candidate(
                    registry=registry,
                    artifacts=artifacts,
                    surface=EvolutionSurface.WORKFLOW,
                    target_role=target_role,
                    content_json=workflow,
                    objective_id=objective_id,
                    collection_evidence_id=collection_evidence_id,
                    source="strategy.propose",
                    proposal_id=raw.get("proposal_id"),
                    rationale=str(raw.get("rationale", ""))[:2000],
                )
            )

    for role_text, raw in (prosecutor_audit.get("role_candidates", {}) or {}).items():
        if not isinstance(role_text, str) or not isinstance(raw, Mapping):
            continue
        try:
            target_role = Role(role_text)
        except ValueError:
            continue
        content = raw.get("content")
        if not isinstance(content, Mapping):
            consumed.append(
                ConsumedCandidate(
                    EvolutionSurface.SUBJECT,
                    target_role,
                    "",
                    "",
                    "role_candidates",
                    raw.get("artifact_id"),
                    "no materializable subject content",
                    collected=False,
                    validated=False,
                    error="role_candidates content is required",
                )
            )
            continue
        try:
            subject = validate_subject_content(content)
        except EvolutionSurfaceError as exc:
            consumed.append(
                ConsumedCandidate(
                    EvolutionSurface.SUBJECT,
                    target_role,
                    "",
                    "",
                    "role_candidates",
                    raw.get("artifact_id"),
                    "invalid subject content",
                    collected=False,
                    validated=False,
                    error=str(exc),
                )
            )
            continue
        consumed.append(
            _record_candidate(
                registry=registry,
                artifacts=artifacts,
                surface=EvolutionSurface.SUBJECT,
                target_role=target_role,
                content_json=subject,
                objective_id=objective_id,
                collection_evidence_id=collection_evidence_id,
                source="role_candidates",
                proposal_id=raw.get("artifact_id"),
                rationale="prosecutor role candidate subject",
            )
        )

    return tuple(consumed)


__all__ = [
    "ConsumedCandidate",
    "EvolutionConsumerError",
    "consume_cycle_proposals",
]
