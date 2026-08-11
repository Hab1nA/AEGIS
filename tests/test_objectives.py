from __future__ import annotations

import json
import tempfile
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from aegis.artifacts import ContentAddressedArtifactStore
from aegis.event_store import EventStore
from aegis.models import Role, canonical_json
from aegis.objectives import (
    AdaptiveObjectiveVersion,
    AmendmentDecision,
    EvaluatorCriterion,
    HumanCoreObjective,
    ObjectiveAmendment,
    ObjectiveEvidence,
    ObjectiveGovernanceError,
    ObjectiveGovernanceRegistry,
    ObjectiveStatus,
)


def address(label: str, kind: str = "sha256") -> str:
    import hashlib

    return f"{kind}:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


@pytest.fixture
def state() -> tuple[Path, EventStore, ContentAddressedArtifactStore, ObjectiveGovernanceRegistry]:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        events = EventStore(root / "campaign" / "events.sqlite3")
        artifacts = ContentAddressedArtifactStore(root / "campaign" / "artifacts")
        registry = ObjectiveGovernanceRegistry(events, artifacts, "campaign-a")
        try:
            yield root, events, artifacts, registry
        finally:
            events.close()


def core() -> HumanCoreObjective:
    return HumanCoreObjective(
        statement="Improve general software-engineering performance without escaping WSL.",
        criteria=(
            EvaluatorCriterion("quality", address("quality-evaluator", "evaluator-sha256"), 0.50),
            EvaluatorCriterion("retention", address("retention-evaluator", "evaluator-sha256"), 0.40),
        ),
        forbidden_capabilities=("windows-host-execution", "windows-secret-read"),
        constitution_id=address("constitution", "constitution-sha256"),
    )


def objective(
    owner: HumanCoreObjective,
    *,
    version: int = 1,
    parent: AdaptiveObjectiveVersion | None = None,
    quality: float = 0.55,
    quality_weight: float = 1.0,
) -> AdaptiveObjectiveVersion:
    return AdaptiveObjectiveVersion(
        version=version,
        core_objective_id=owner.core_objective_id,
        parent_objective_id=None if parent is None else parent.objective_id,
        refinement="Prioritize reproducible debugging on unseen repositories.",
        criteria=(
            EvaluatorCriterion("quality", address("quality-evaluator", "evaluator-sha256"), quality),
            EvaluatorCriterion("retention", address("retention-evaluator", "evaluator-sha256"), 0.40),
        ),
        weights={"quality": quality_weight, "retention": 1.0},
        capability_tags=("debugging", "reproducibility"),
    )


def amendment(candidate: AdaptiveObjectiveVersion) -> ObjectiveAmendment:
    return ObjectiveAmendment(
        objective=candidate,
        rationale="Council evidence indicates this refinement improves unseen debugging tasks.",
        council_reflection_ids=(address("judge-reflection"), address("warrior-reflection")),
        critique_ids=(address("judge-critique"), address("warrior-critique")),
    )


def evidence(
    candidate: AdaptiveObjectiveVersion,
    cycle: int,
    *,
    passed: bool = True,
    regression: bool = False,
) -> ObjectiveEvidence:
    return ObjectiveEvidence(
        objective_id=candidate.objective_id,
        snapshot_id=address(f"snapshot-{cycle}", "curriculum-snapshot-sha256"),
        cycle_number=cycle,
        quality_passed=passed,
        integrity_passed=True,
        regression_detected=regression,
        source_evidence_id=address(f"sealed-{cycle}", "sealed-evidence-sha256"),
    )


def prepare_approved(
    registry: ObjectiveGovernanceRegistry,
    candidate: AdaptiveObjectiveVersion,
    *,
    current_cycle: int = 3,
) -> None:
    registry.propose_amendment(amendment(candidate))
    for cycle in range(current_cycle - 2, current_cycle + 1):
        registry.record_shadow_evidence(evidence(candidate, cycle))
    registry.decide_amendment(
        candidate.objective_id,
        actor=Role.PROSECUTOR,
        decision=AmendmentDecision.APPROVE,
        current_cycle=current_cycle,
        reason="Latest three sealed shadow snapshots passed.",
    )


def test_core_and_adaptive_models_are_immutable_content_addressed_and_round_trip() -> None:
    genesis = core()
    candidate = objective(genesis)
    assert HumanCoreObjective.from_mapping(genesis.to_mapping()) == genesis
    assert AdaptiveObjectiveVersion.from_mapping(candidate.to_mapping()) == candidate
    assert genesis.core_objective_id.startswith(HumanCoreObjective.ID_PREFIX)
    assert candidate.objective_id.startswith(AdaptiveObjectiveVersion.ID_PREFIX)
    with pytest.raises(FrozenInstanceError):
        genesis.statement = "replace the operator goal"  # type: ignore[misc]
    with pytest.raises(TypeError):
        candidate.weights["quality"] = 0.0  # type: ignore[index]


def test_genesis_is_campaign_frozen_and_refinements_cannot_weaken_core(
    state: tuple[Path, EventStore, ContentAddressedArtifactStore, ObjectiveGovernanceRegistry],
) -> None:
    _, events, artifacts, registry = state
    genesis = core()
    registry.record_genesis(genesis)
    assert registry.record_genesis(genesis).core == genesis
    replacement = HumanCoreObjective(
        statement="A different operator objective.",
        criteria=genesis.criteria,
        forbidden_capabilities=genesis.forbidden_capabilities,
        constitution_id=genesis.constitution_id,
    )
    with pytest.raises(ObjectiveGovernanceError, match="new campaign"):
        registry.record_genesis(replacement)

    weak = objective(genesis, quality=0.49)
    with pytest.raises(ObjectiveGovernanceError, match="weakens"):
        registry.propose_amendment(amendment(weak))

    foreign_registry = ObjectiveGovernanceRegistry(events, artifacts, "campaign-b")
    assert foreign_registry.record_genesis(replacement).core == replacement


def test_only_prosecutor_can_decide_and_latest_three_clean_shadows_are_required(
    state: tuple[Path, EventStore, ContentAddressedArtifactStore, ObjectiveGovernanceRegistry],
) -> None:
    _, _, _, registry = state
    genesis = core()
    candidate = objective(genesis)
    registry.record_genesis(genesis)
    registry.propose_amendment(amendment(candidate))
    for cycle in (1, 2, 3):
        registry.record_shadow_evidence(evidence(candidate, cycle, passed=cycle != 1))
    with pytest.raises(ObjectiveGovernanceError, match="only prosecutor"):
        registry.decide_amendment(
            candidate.objective_id,
            actor=Role.JUDGE,
            decision=AmendmentDecision.APPROVE,
            current_cycle=3,
            reason="Judge must not make the final decision.",
        )
    with pytest.raises(ObjectiveGovernanceError, match="all latest three"):
        registry.decide_amendment(
            candidate.objective_id,
            actor=Role.PROSECUTOR,
            decision=AmendmentDecision.APPROVE,
            current_cycle=3,
            reason="One shadow snapshot failed.",
        )
    registry.record_shadow_evidence(evidence(candidate, 4))
    registry.decide_amendment(
        candidate.objective_id,
        actor=Role.PROSECUTOR,
        decision=AmendmentDecision.APPROVE,
        current_cycle=4,
        reason="The latest three snapshots now pass.",
    )
    assert registry.projection.statuses[candidate.objective_id] is ObjectiveStatus.APPROVED


def test_next_cycle_probation_graduates_after_exactly_two_clean_cycles_and_replays(
    state: tuple[Path, EventStore, ContentAddressedArtifactStore, ObjectiveGovernanceRegistry],
) -> None:
    _, events, artifacts, registry = state
    genesis = core()
    candidate = objective(genesis)
    registry.record_genesis(genesis)
    prepare_approved(registry, candidate)
    assert registry.begin_cycle(3).probation_objective_id is None
    registry.begin_cycle(4)
    started_sequence = registry.projection.sequence
    registry.begin_cycle(4)
    assert registry.projection.sequence == started_sequence
    assert registry.projection.effective_objective_id(4) == candidate.objective_id
    registry.observe_probation(evidence(candidate, 4))
    assert registry.projection.statuses[candidate.objective_id] is ObjectiveStatus.PROBATION
    graduation_evidence = evidence(candidate, 5)
    registry.observe_probation(graduation_evidence)
    assert registry.projection.statuses[candidate.objective_id] is ObjectiveStatus.ACTIVE
    assert registry.projection.active_objective_id == candidate.objective_id
    graduated_sequence = registry.projection.sequence
    registry.observe_probation(graduation_evidence)
    assert registry.projection.sequence == graduated_sequence

    replayed = ObjectiveGovernanceRegistry(events, artifacts, "campaign-a")
    assert replayed.projection == registry.projection


def test_any_probation_regression_rolls_back_immediately_to_active_parent(
    state: tuple[Path, EventStore, ContentAddressedArtifactStore, ObjectiveGovernanceRegistry],
) -> None:
    _, _, _, registry = state
    genesis = core()
    first = objective(genesis)
    registry.record_genesis(genesis)
    prepare_approved(registry, first)
    registry.begin_cycle(4)
    registry.observe_probation(evidence(first, 4))
    registry.observe_probation(evidence(first, 5))

    successor = objective(genesis, version=2, parent=first, quality=0.60, quality_weight=2.0)
    prepare_approved(registry, successor, current_cycle=8)
    registry.begin_cycle(9)
    registry.observe_probation(evidence(successor, 9, regression=True))
    assert registry.projection.statuses[successor.objective_id] is ObjectiveStatus.ROLLED_BACK
    assert registry.projection.statuses[first.objective_id] is ObjectiveStatus.ACTIVE
    assert registry.projection.active_objective_id == first.objective_id
    assert registry.projection.probation_objective_id is None


def test_parent_lineage_cannot_reduce_weights_or_extend_non_active_candidate(
    state: tuple[Path, EventStore, ContentAddressedArtifactStore, ObjectiveGovernanceRegistry],
) -> None:
    _, _, _, registry = state
    genesis = core()
    first = objective(genesis)
    registry.record_genesis(genesis)
    registry.propose_amendment(amendment(first))
    successor = objective(genesis, version=2, parent=first, quality=0.60, quality_weight=0.5)
    with pytest.raises(ObjectiveGovernanceError, match="parent must be the active"):
        registry.propose_amendment(amendment(successor))


def test_tampered_approval_without_shadow_evidence_fails_closed_on_replay(
    state: tuple[Path, EventStore, ContentAddressedArtifactStore, ObjectiveGovernanceRegistry],
) -> None:
    _, events, artifacts, registry = state
    genesis = core()
    candidate = objective(genesis)
    registry.record_genesis(genesis)
    registry.propose_amendment(amendment(candidate))
    events.append(
        "campaign-a",
        "adaptive_objective_amendment_decided_v1",
        {
            "objective_id": candidate.objective_id,
            "actor": "prosecutor",
            "decision": "approve",
            "reason": "Forged approval.",
            "decided_cycle": 3,
            "effective_cycle": 4,
        },
    )
    with pytest.raises(ObjectiveGovernanceError, match="three clean shadow"):
        ObjectiveGovernanceRegistry(events, artifacts, "campaign-a")


def test_legacy_import_accepts_only_campaign_snapshot_and_cas_verified_rows(
    state: tuple[Path, EventStore, ContentAddressedArtifactStore, ObjectiveGovernanceRegistry],
) -> None:
    root, _, artifacts, registry = state
    genesis = core()
    candidate = objective(genesis)
    registry.record_genesis(genesis)
    registry.propose_amendment(amendment(candidate))
    imported = evidence(candidate, 1)
    ref = artifacts.put_json("objective-evidence", imported.to_mapping())
    ref_mapping = {"kind": ref.kind, "artifact_id": ref.artifact_id, "size_bytes": ref.size_bytes}
    rows = [
        {"campaign_id": "campaign-a", "snapshot_id": imported.snapshot_id, "artifact": ref_mapping},
        {"campaign_id": "campaign-a", "snapshot_id": imported.snapshot_id, "artifact": ref_mapping},
        {"campaign_id": "foreign", "snapshot_id": imported.snapshot_id, "artifact": ref_mapping},
        {"campaign_id": "campaign-a", "snapshot_id": address("wrong"), "artifact": ref_mapping},
        {"unexpected": True},
    ]
    legacy = root / "old-shared-objectives.jsonl"
    legacy.write_text("\n".join(canonical_json(row) for row in rows), encoding="utf-8")
    report = registry.import_legacy_jsonl(legacy)
    assert (report.accepted, report.skipped, report.rejected) == (1, 1, 3)
    assert tuple(item.status for item in report.records) == (
        "accepted",
        "skipped",
        "rejected",
        "rejected",
        "rejected",
    )
    assert all(item.reason for item in report.records)
    assert registry.projection.shadow_evidence[candidate.objective_id] == (imported,)


def test_reject_decision_is_final_idempotent_and_needs_no_shadow_evidence(
    state: tuple[Path, EventStore, ContentAddressedArtifactStore, ObjectiveGovernanceRegistry],
) -> None:
    _, _, _, registry = state
    genesis = core()
    candidate = objective(genesis)
    registry.record_genesis(genesis)
    registry.propose_amendment(amendment(candidate))
    registry.decide_amendment(
        candidate.objective_id,
        actor=Role.PROSECUTOR,
        decision=AmendmentDecision.REJECT,
        current_cycle=1,
        reason="The amendment is not useful.",
    )
    sequence = registry.projection.sequence
    registry.decide_amendment(
        candidate.objective_id,
        actor=Role.PROSECUTOR,
        decision=AmendmentDecision.REJECT,
        current_cycle=1,
        reason="Repeated idempotent command.",
    )
    assert registry.projection.sequence == sequence
    assert registry.projection.statuses[candidate.objective_id] is ObjectiveStatus.REJECTED
    with pytest.raises(ObjectiveGovernanceError, match="opposite"):
        registry.decide_amendment(
            candidate.objective_id,
            actor=Role.PROSECUTOR,
            decision=AmendmentDecision.APPROVE,
            current_cycle=1,
            reason="Cannot reverse final rejection.",
        )


def test_evidence_identity_detects_tampering() -> None:
    genesis = core()
    candidate = objective(genesis)
    original = evidence(candidate, 1).to_mapping()
    tampered = json.loads(json.dumps(original))
    tampered["quality_passed"] = False
    with pytest.raises(ValueError, match="evidence_id"):
        ObjectiveEvidence.from_mapping(tampered)
