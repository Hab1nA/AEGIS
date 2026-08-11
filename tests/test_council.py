from __future__ import annotations

import pytest

from aegis.council import (
    CouncilMessage,
    CouncilMessageType,
    CouncilOutcome,
    CouncilProposalKind,
    CouncilProtocolError,
    CouncilTranscript,
    EvidenceClaim,
    ObjectiveAdmissionDecision,
    ObjectiveAmendment,
    ShadowObjectiveResult,
    SupportDecision,
    evaluate_objective_amendment,
)
from aegis.curriculum import Constitution, ObjectiveSuccessCriterion, ObjectiveVersion
from aegis.models import Role


def digest(char: str) -> str:
    return "sha256:" + char * 64


def objectives() -> tuple[ObjectiveVersion, ObjectiveVersion]:
    constitution = Constitution(version=1, safety_rules=("Bounded control plane.",))
    weights = {"quality": 1, "generalization": 1, "retention": 1, "efficiency": 1}
    parent = ObjectiveVersion(
        1, constitution.constitution_id, "Parent objective.",
        (ObjectiveSuccessCriterion("quality", 0.5),), (), weights,
    )
    candidate = ObjectiveVersion(
        2, constitution.constitution_id, "Candidate objective.",
        (ObjectiveSuccessCriterion("quality", 0.6),), (), weights,
        parent.objective_id,
    )
    return parent, candidate


def claim(name: str = "c1") -> EvidenceClaim:
    return EvidenceClaim(name, "bounded evidence-backed claim", (digest("a"),), "paired run fails", 0.8)


def message(
    sender: Role,
    kind: CouncilMessageType,
    *,
    proposal_id: str | None = None,
    parent: str | None = None,
    support: SupportDecision | None = None,
) -> CouncilMessage:
    return CouncilMessage(
        "cycle-1",
        sender,
        kind,
        (claim(f"{sender.value}-{kind.value}"),),
        f"{kind.value} summary",
        proposal_id=proposal_id,
        parent_message_id=parent,
        proposal_kind=(
            CouncilProposalKind.OBJECTIVE_AMENDMENT
            if kind is CouncilMessageType.PROPOSAL
            else None
        ),
        support=support,
        token_usage=10,
    )


def reflected_transcript() -> CouncilTranscript:
    transcript = CouncilTranscript("cycle-1")
    for role in Role:
        transcript.append(message(role, CouncilMessageType.REFLECTION))
    return transcript


def test_message_identity_is_content_addressed_and_tamper_evident() -> None:
    first = message(Role.WARRIOR, CouncilMessageType.REFLECTION)
    second = message(Role.WARRIOR, CouncilMessageType.REFLECTION)
    assert first.message_id == second.message_id
    with pytest.raises(CouncilProtocolError, match="does not match"):
        CouncilMessage(
            first.cycle_id,
            first.sender,
            first.message_type,
            first.claims,
            "tampered",
            token_usage=first.token_usage,
            message_id=first.message_id,
        )


def test_council_requires_independent_reflection_and_bounds_dialogue() -> None:
    transcript = CouncilTranscript("cycle-1", max_messages=8, max_tokens=100)
    transcript.append(message(Role.WARRIOR, CouncilMessageType.REFLECTION))
    with pytest.raises(CouncilProtocolError, match="all roles"):
        transcript.append(message(Role.JUDGE, CouncilMessageType.PROPOSAL, proposal_id="p1"))

    transcript.append(message(Role.JUDGE, CouncilMessageType.REFLECTION))
    transcript.append(message(Role.PROSECUTOR, CouncilMessageType.REFLECTION))
    proposal = message(Role.JUDGE, CouncilMessageType.PROPOSAL, proposal_id="p1")
    transcript.append(proposal)
    critique = message(
        Role.WARRIOR,
        CouncilMessageType.CRITIQUE,
        proposal_id="p1",
        parent=proposal.message_id,
    )
    transcript.append(critique)
    transcript.append(
        message(
            Role.JUDGE,
            CouncilMessageType.RESPONSE,
            proposal_id="p1",
            parent=critique.message_id,
        )
    )
    with pytest.raises(CouncilProtocolError, match="only one response"):
        transcript.append(
            CouncilMessage(
                "cycle-1",
                Role.JUDGE,
                CouncilMessageType.RESPONSE,
                (claim("second-response"),),
                "a distinct second response",
                proposal_id="p1",
                parent_message_id=critique.message_id,
                token_usage=10,
            )
        )


def test_unanimity_cannot_override_integrity_or_historical_regression() -> None:
    transcript = reflected_transcript()
    proposal = message(Role.WARRIOR, CouncilMessageType.PROPOSAL, proposal_id="objective-2")
    transcript.append(proposal)
    for role in Role:
        transcript.append(
            message(
                role,
                CouncilMessageType.SUPPORT,
                proposal_id="objective-2",
                support=SupportDecision.SUPPORT,
            )
        )
    parent, candidate = objectives()
    amendment = ObjectiveAmendment(
        "objective-2", parent.objective_id, candidate, 2,
        "shift effort toward demonstrated quality",
    )
    passing = tuple(
        ShadowObjectiveResult(candidate.objective_id, f"curriculum-snapshot-sha256:{char * 64}", 1.0, 1.0)
        for char in "345"
    )
    assert evaluate_objective_amendment(
        amendment,
        transcript.messages,
        passing,
        current_cycle=1,
        integrity_objection=False,
    ).admitted
    assert not evaluate_objective_amendment(
        amendment,
        transcript.messages,
        passing,
        current_cycle=1,
        integrity_objection=True,
    ).admitted
    regressing = passing[:2] + (
        ShadowObjectiveResult(candidate.objective_id, "curriculum-snapshot-sha256:" + "6" * 64, 1.0, 0.5),
    )
    assert not evaluate_objective_amendment(
        amendment,
        transcript.messages,
        regressing,
        current_cycle=1,
        integrity_objection=False,
    ).admitted


def test_objective_weights_are_normalized_and_delayed() -> None:
    parent, candidate = objectives()
    amendment = ObjectiveAmendment(
        "p", parent.objective_id, candidate, 3, "bounded target change",
    )
    assert set(amendment.capability_weights) == {"quality", "generalization", "retention", "efficiency"}
    decision = evaluate_objective_amendment(
        amendment,
        (),
        (),
        current_cycle=3,
        integrity_objection=False,
    )
    assert not decision.admitted
    assert "next cycle" in decision.reason


def test_council_outcome_is_strict_and_shadow_history_is_snapshot_keyed() -> None:
    transcript = reflected_transcript()
    proposal = message(Role.PROSECUTOR, CouncilMessageType.PROPOSAL, proposal_id="p")
    transcript.append(proposal)
    parent, candidate = objectives()
    amendment = ObjectiveAmendment("p", parent.objective_id, candidate, 2, "bounded change")
    shadows = tuple(
        ShadowObjectiveResult(candidate.objective_id, "curriculum-snapshot-sha256:" + char * 64, 1, 1)
        for char in "abc"
    )
    decision = ObjectiveAdmissionDecision(False, "insufficient independent role support", None)
    outcome = CouncilOutcome("cycle-1", transcript.messages, amendment, shadows, False, decision)
    assert CouncilOutcome.from_mapping(outcome.to_mapping()) == outcome
    malformed = dict(outcome.to_mapping())
    malformed["unknown"] = True
    with pytest.raises(CouncilProtocolError, match="missing or unknown"):
        CouncilOutcome.from_mapping(malformed)
