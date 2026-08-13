"""Bounded, evidence-backed post-evaluation council protocol.

The council is intentionally not a chat room.  Messages are immutable,
content-addressed records and the protocol only opens after quality has been
locked.  Performance objectives may evolve, while the host-safety constitution
is deliberately outside this module and cannot be amended by role messages.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from aegis.curriculum.models import ObjectiveVersion
from aegis.models import Role, canonical_json


class CouncilProtocolError(ValueError):
    """Raised when a council transcript violates the bounded protocol."""


class CouncilMessageType(StrEnum):
    REFLECTION = "reflection"
    PROPOSAL = "proposal"
    CRITIQUE = "critique"
    RESPONSE = "response"
    SUPPORT = "support"


class CouncilProposalKind(StrEnum):
    CURRICULUM = "curriculum"
    ROLE_CHANGE = "role_change"
    SYSTEM_EXPERIMENT = "system_experiment"
    OBJECTIVE_AMENDMENT = "objective_amendment"


class SupportDecision(StrEnum):
    SUPPORT = "support"
    OPPOSE = "oppose"
    ABSTAIN = "abstain"


def _text(value: object, name: str, *, max_length: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CouncilProtocolError(f"{name} must be non-empty text")
    if value != value.strip():
        raise CouncilProtocolError(f"{name} must not contain surrounding whitespace")
    if len(value.encode("utf-8")) > max_length:
        raise CouncilProtocolError(f"{name} exceeds {max_length} bytes")
    return value


def _digest(value: object, name: str) -> str:
    text = _text(value, name, max_length=128)
    if not text.startswith("sha256:") or len(text) != 71:
        raise CouncilProtocolError(f"{name} must be a sha256 digest")
    try:
        int(text[7:], 16)
    except ValueError as exc:
        raise CouncilProtocolError(f"{name} must be a sha256 digest") from exc
    return text.lower()


def _prefixed_digest(value: object, name: str, prefix: str) -> str:
    text = _text(value, name, max_length=128)
    if not text.startswith(prefix) or len(text) != len(prefix) + 64:
        raise CouncilProtocolError(f"{name} must be a {prefix} identity")
    try:
        int(text.removeprefix(prefix), 16)
    except ValueError as exc:
        raise CouncilProtocolError(f"{name} must be a {prefix} identity") from exc
    return text.lower()


def _objective_id(value: object, name: str) -> str:
    return _prefixed_digest(value, name, ObjectiveVersion.ID_PREFIX)


def _content_digest(payload: Mapping[str, object]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class EvidenceClaim:
    claim_id: str
    statement: str
    evidence_refs: tuple[str, ...]
    falsifier: str
    confidence: float

    def __post_init__(self) -> None:
        _text(self.claim_id, "claim_id", max_length=128)
        _text(self.statement, "statement")
        _text(self.falsifier, "falsifier")
        if not isinstance(self.evidence_refs, tuple) or not self.evidence_refs:
            raise CouncilProtocolError("evidence_refs must be a non-empty tuple")
        if len(self.evidence_refs) > 16:
            raise CouncilProtocolError("a claim may reference at most 16 evidence records")
        for index, ref in enumerate(self.evidence_refs):
            _digest(ref, f"evidence_refs[{index}]")
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)):
            raise CouncilProtocolError("confidence must be numeric")
        confidence = float(self.confidence)
        if not math.isfinite(confidence) or not 0 <= confidence <= 1:
            raise CouncilProtocolError("confidence must be in [0, 1]")
        object.__setattr__(self, "confidence", confidence)

    def to_dict(self) -> dict[str, object]:
        return {
            "claim_id": self.claim_id,
            "statement": self.statement,
            "evidence_refs": list(self.evidence_refs),
            "falsifier": self.falsifier,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, value: object) -> EvidenceClaim:
        data = _strict_mapping(
            value, {"claim_id", "statement", "evidence_refs", "falsifier", "confidence"}, "claim"
        )
        refs = data["evidence_refs"]
        if not isinstance(refs, (list, tuple)):
            raise CouncilProtocolError("evidence_refs must be an array")
        return cls(data["claim_id"], data["statement"], tuple(refs), data["falsifier"], data["confidence"])


@dataclass(frozen=True, slots=True)
class CouncilMessage:
    cycle_id: str
    sender: Role
    message_type: CouncilMessageType
    claims: tuple[EvidenceClaim, ...]
    summary: str
    proposal_id: str | None = None
    parent_message_id: str | None = None
    proposal_kind: CouncilProposalKind | None = None
    support: SupportDecision | None = None
    token_usage: int = 0
    message_id: str = ""

    def __post_init__(self) -> None:
        _text(self.cycle_id, "cycle_id", max_length=128)
        if not isinstance(self.sender, Role):
            raise CouncilProtocolError("sender must be a Role")
        if not isinstance(self.message_type, CouncilMessageType):
            raise CouncilProtocolError("message_type must be a CouncilMessageType")
        _text(self.summary, "summary")
        if not isinstance(self.claims, tuple) or len(self.claims) > 8:
            raise CouncilProtocolError("claims must be a tuple with at most 8 items")
        if any(not isinstance(claim, EvidenceClaim) for claim in self.claims):
            raise CouncilProtocolError("claims must contain EvidenceClaim values")
        if isinstance(self.token_usage, bool) or not isinstance(self.token_usage, int):
            raise CouncilProtocolError("token_usage must be an integer")
        if self.token_usage < 0:
            raise CouncilProtocolError("token_usage must be non-negative")

        if self.message_type is CouncilMessageType.REFLECTION:
            if any(
                value is not None
                for value in (self.proposal_id, self.parent_message_id, self.proposal_kind, self.support)
            ):
                raise CouncilProtocolError("reflection must not target a proposal or parent")
        elif self.message_type is CouncilMessageType.PROPOSAL:
            if self.proposal_id is None or self.proposal_kind is None:
                raise CouncilProtocolError("proposal requires proposal_id and proposal_kind")
            if self.parent_message_id is not None or self.support is not None:
                raise CouncilProtocolError("proposal must not have parent_message_id or support")
        elif self.message_type in {CouncilMessageType.CRITIQUE, CouncilMessageType.RESPONSE}:
            if self.proposal_id is None or self.parent_message_id is None:
                raise CouncilProtocolError("critique/response require proposal_id and parent_message_id")
            if self.proposal_kind is not None or self.support is not None:
                raise CouncilProtocolError("critique/response cannot define proposal_kind or support")
        else:
            if self.proposal_id is None or self.support is None:
                raise CouncilProtocolError("support message requires proposal_id and support")
            if self.parent_message_id is not None or self.proposal_kind is not None:
                raise CouncilProtocolError("support cannot define parent_message_id or proposal_kind")

        if self.proposal_id is not None:
            _text(self.proposal_id, "proposal_id", max_length=128)
        if self.parent_message_id is not None:
            _digest(self.parent_message_id, "parent_message_id")

        calculated = _content_digest(self._identity_payload())
        if self.message_id:
            if _digest(self.message_id, "message_id") != calculated:
                raise CouncilProtocolError("message_id does not match message content")
        else:
            object.__setattr__(self, "message_id", calculated)

    def _identity_payload(self) -> dict[str, object]:
        return {
            "cycle_id": self.cycle_id,
            "sender": self.sender.value,
            "message_type": self.message_type.value,
            "claims": [claim.to_dict() for claim in self.claims],
            "summary": self.summary,
            "proposal_id": self.proposal_id,
            "parent_message_id": self.parent_message_id,
            "proposal_kind": self.proposal_kind.value if self.proposal_kind else None,
            "support": self.support.value if self.support else None,
            "token_usage": self.token_usage,
        }

    def to_mapping(self) -> dict[str, object]:
        return {**self._identity_payload(), "message_id": self.message_id}

    @classmethod
    def from_mapping(cls, value: object) -> CouncilMessage:
        data = _strict_mapping(
            value,
            {
                "cycle_id", "sender", "message_type", "claims", "summary", "proposal_id",
                "parent_message_id", "proposal_kind", "support", "token_usage", "message_id",
            },
            "council message",
        )
        claims = data["claims"]
        if not isinstance(claims, (list, tuple)):
            raise CouncilProtocolError("claims must be an array")
        try:
            return cls(
                cycle_id=data["cycle_id"], sender=Role(data["sender"]),
                message_type=CouncilMessageType(data["message_type"]),
                claims=tuple(EvidenceClaim.from_dict(item) for item in claims),
                summary=data["summary"], proposal_id=data["proposal_id"],
                parent_message_id=data["parent_message_id"],
                proposal_kind=(
                    None
                    if data["proposal_kind"] is None
                    else CouncilProposalKind(data["proposal_kind"])
                ),
                support=(None if data["support"] is None else SupportDecision(data["support"])),
                token_usage=data["token_usage"], message_id=data["message_id"],
            )
        except (TypeError, ValueError) as exc:
            raise CouncilProtocolError("council message has invalid enum fields") from exc


def _strict_mapping(value: object, expected: set[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise CouncilProtocolError(f"{name} must be a string-keyed mapping")
    if set(value) != expected:
        raise CouncilProtocolError(f"{name} has missing or unknown fields")
    return value


@dataclass(frozen=True, slots=True)
class ObjectiveAmendment:
    proposal_id: str
    parent_objective_id: str
    candidate_objective: ObjectiveVersion
    effective_cycle: int
    rationale: str

    def __post_init__(self) -> None:
        _text(self.proposal_id, "proposal_id", max_length=128)
        _objective_id(self.parent_objective_id, "parent_objective_id")
        if not isinstance(self.candidate_objective, ObjectiveVersion):
            raise CouncilProtocolError("candidate_objective must be an ObjectiveVersion")
        if self.candidate_objective.parent_objective_id != self.parent_objective_id:
            raise CouncilProtocolError("candidate objective must directly reference parent_objective_id")
        if isinstance(self.effective_cycle, bool) or not isinstance(self.effective_cycle, int):
            raise CouncilProtocolError("effective_cycle must be an integer")
        if self.effective_cycle <= 0:
            raise CouncilProtocolError("effective_cycle must be positive")
        _text(self.rationale, "rationale")

    @property
    def proposed_objective_id(self) -> str:
        return self.candidate_objective.objective_id

    @property
    def capability_weights(self) -> Mapping[str, float]:
        return self.candidate_objective.capability_weights

    def to_mapping(self) -> dict[str, object]:
        return {
            "proposal_id": self.proposal_id,
            "parent_objective_id": self.parent_objective_id,
            "candidate_objective": self.candidate_objective.to_mapping(),
            "effective_cycle": self.effective_cycle,
            "rationale": self.rationale,
        }

    @classmethod
    def from_mapping(cls, value: object) -> ObjectiveAmendment:
        data = _strict_mapping(
            value,
            {"proposal_id", "parent_objective_id", "candidate_objective", "effective_cycle", "rationale"},
            "objective amendment",
        )
        return cls(
            data["proposal_id"], data["parent_objective_id"],
            ObjectiveVersion.from_mapping(data["candidate_objective"]),
            data["effective_cycle"], data["rationale"],
        )


@dataclass(frozen=True, slots=True)
class ShadowObjectiveResult:
    candidate_objective_id: str
    historical_snapshot_id: str
    baseline_utility: float
    candidate_utility: float
    non_inferiority_margin: float = 0.0

    def __post_init__(self) -> None:
        _objective_id(self.candidate_objective_id, "candidate_objective_id")
        _prefixed_digest(
            self.historical_snapshot_id,
            "historical_snapshot_id",
            "curriculum-snapshot-sha256:",
        )
        for name in ("baseline_utility", "candidate_utility", "non_inferiority_margin"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise CouncilProtocolError(f"{name} must be numeric")
            value = float(value)
            if not math.isfinite(value):
                raise CouncilProtocolError(f"{name} must be finite")
            object.__setattr__(self, name, value)
        if self.non_inferiority_margin < 0:
            raise CouncilProtocolError("non_inferiority_margin must be non-negative")

    @property
    def passes(self) -> bool:
        return self.candidate_utility >= self.baseline_utility - self.non_inferiority_margin

    def to_mapping(self) -> dict[str, object]:
        return {
            "candidate_objective_id": self.candidate_objective_id,
            "historical_snapshot_id": self.historical_snapshot_id,
            "baseline_utility": self.baseline_utility,
            "candidate_utility": self.candidate_utility,
            "non_inferiority_margin": self.non_inferiority_margin,
        }

    @classmethod
    def from_mapping(cls, value: object) -> ShadowObjectiveResult:
        data = _strict_mapping(
            value,
            {
                "candidate_objective_id",
                "historical_snapshot_id",
                "baseline_utility",
                "candidate_utility",
                "non_inferiority_margin",
            },
            "shadow objective result",
        )
        return cls(**data)


@dataclass(frozen=True, slots=True)
class ObjectiveAdmissionDecision:
    admitted: bool
    reason: str
    provisional_until_cycle: int | None

    def __post_init__(self) -> None:
        if not isinstance(self.admitted, bool):
            raise CouncilProtocolError("admitted must be a boolean")
        _text(self.reason, "reason")
        if self.provisional_until_cycle is not None and (
            isinstance(self.provisional_until_cycle, bool)
            or not isinstance(self.provisional_until_cycle, int)
            or self.provisional_until_cycle <= 0
        ):
            raise CouncilProtocolError("provisional_until_cycle must be a positive integer")
        if self.admitted != (self.provisional_until_cycle is not None):
            raise CouncilProtocolError("only admitted objectives may have a provisional deadline")

    def to_mapping(self) -> dict[str, object]:
        return {
            "admitted": self.admitted,
            "reason": self.reason,
            "provisional_until_cycle": self.provisional_until_cycle,
        }

    @classmethod
    def from_mapping(cls, value: object) -> ObjectiveAdmissionDecision:
        data = _strict_mapping(
            value, {"admitted", "reason", "provisional_until_cycle"}, "objective admission decision"
        )
        return cls(**data)


@dataclass(frozen=True, slots=True)
class CouncilOutcome:
    """Strict, durable result of one complete objective-governance session."""

    cycle_id: str
    messages: tuple[CouncilMessage, ...]
    amendment: ObjectiveAmendment | None
    shadow_results: tuple[ShadowObjectiveResult, ...]
    integrity_objection: bool
    decision: ObjectiveAdmissionDecision | None

    def __post_init__(self) -> None:
        _text(self.cycle_id, "cycle_id", max_length=128)
        if not isinstance(self.messages, tuple) or any(
            not isinstance(item, CouncilMessage) for item in self.messages
        ):
            raise CouncilProtocolError("messages must be a tuple of CouncilMessage values")
        if any(item.cycle_id != self.cycle_id for item in self.messages):
            raise CouncilProtocolError("council outcome contains a message from another cycle")
        transcript = CouncilTranscript(
            self.cycle_id,
            max_messages=len(self.messages) + 1,
            max_tokens=sum(
                item.token_usage for item in self.messages
            )
            + 1,
        )
        for message in self.messages:
            transcript.append(message)
        if self.amendment is not None and not isinstance(self.amendment, ObjectiveAmendment):
            raise CouncilProtocolError("amendment must be an ObjectiveAmendment")
        if not isinstance(self.shadow_results, tuple) or any(
            not isinstance(item, ShadowObjectiveResult) for item in self.shadow_results
        ):
            raise CouncilProtocolError("shadow_results must be a tuple of ShadowObjectiveResult values")
        if not isinstance(self.integrity_objection, bool):
            raise CouncilProtocolError("integrity_objection must be a boolean")
        if self.decision is not None and not isinstance(self.decision, ObjectiveAdmissionDecision):
            raise CouncilProtocolError("decision must be an ObjectiveAdmissionDecision")
        if self.amendment is None:
            if self.shadow_results or self.decision is not None:
                raise CouncilProtocolError(
                    "an outcome without an amendment cannot have shadow results or a decision"
                )
        else:
            if self.decision is None:
                raise CouncilProtocolError("an amendment outcome requires an admission decision")
            if any(
                item.candidate_objective_id != self.amendment.proposed_objective_id
                for item in self.shadow_results
            ):
                raise CouncilProtocolError("shadow result is bound to another candidate objective")
            proposals = {
                item.proposal_id
                for item in self.messages
                if item.message_type is CouncilMessageType.PROPOSAL
            }
            if self.amendment.proposal_id not in proposals:
                raise CouncilProtocolError("amendment does not reference a transcript proposal")

    def to_mapping(self) -> dict[str, object]:
        return {
            "cycle_id": self.cycle_id,
            "messages": [item.to_mapping() for item in self.messages],
            "amendment": None if self.amendment is None else self.amendment.to_mapping(),
            "shadow_results": [item.to_mapping() for item in self.shadow_results],
            "integrity_objection": self.integrity_objection,
            "decision": None if self.decision is None else self.decision.to_mapping(),
        }

    @classmethod
    def from_mapping(cls, value: object) -> CouncilOutcome:
        data = _strict_mapping(
            value,
            {
                "cycle_id",
                "messages",
                "amendment",
                "shadow_results",
                "integrity_objection",
                "decision",
            },
            "council outcome",
        )
        messages = data["messages"]
        shadows = data["shadow_results"]
        if not isinstance(messages, (list, tuple)) or not isinstance(shadows, (list, tuple)):
            raise CouncilProtocolError("messages and shadow_results must be arrays")
        return cls(
            cycle_id=data["cycle_id"],
            messages=tuple(CouncilMessage.from_mapping(item) for item in messages),
            amendment=(
                None
                if data["amendment"] is None
                else ObjectiveAmendment.from_mapping(data["amendment"])
            ),
            shadow_results=tuple(ShadowObjectiveResult.from_mapping(item) for item in shadows),
            integrity_objection=data["integrity_objection"],
            decision=(
                None
                if data["decision"] is None
                else ObjectiveAdmissionDecision.from_mapping(data["decision"])
            ),
        )


def evaluate_objective_amendment(
    amendment: ObjectiveAmendment,
    messages: tuple[CouncilMessage, ...],
    shadow_results: tuple[ShadowObjectiveResult, ...],
    *,
    current_cycle: int,
    integrity_objection: bool,
    required_support: int = 0,
    required_history: int = 3,
    probation_cycles: int = 2,
) -> ObjectiveAdmissionDecision:
    """Apply the immutable admission process to a mutable performance objective."""
    if amendment.effective_cycle <= current_cycle:
        return ObjectiveAdmissionDecision(False, "objective amendments must take effect next cycle", None)
    if integrity_objection:
        return ObjectiveAdmissionDecision(False, "verified evidence-integrity objection", None)
    relevant = tuple(
        message
        for message in messages
        if message.message_type is CouncilMessageType.SUPPORT
        and message.proposal_id == amendment.proposal_id
    )
    if len({message.sender for message in relevant}) != len(relevant):
        return ObjectiveAdmissionDecision(False, "a role submitted multiple support decisions", None)
    del required_support
    prosecutor_votes = tuple(
        message for message in relevant if message.sender is Role.PROSECUTOR
    )
    if len(prosecutor_votes) != 1 or prosecutor_votes[0].support is not SupportDecision.SUPPORT:
        return ObjectiveAdmissionDecision(
            False, "Prosecutor did not issue the final approval", None
        )
    if len(shadow_results) < required_history:
        return ObjectiveAdmissionDecision(False, "insufficient historical objective shadow coverage", None)
    if any(
        result.candidate_objective_id != amendment.proposed_objective_id
        for result in shadow_results
    ):
        return ObjectiveAdmissionDecision(False, "historical shadow result targets another objective", None)
    if len({result.historical_snapshot_id for result in shadow_results}) != len(shadow_results):
        return ObjectiveAdmissionDecision(False, "duplicate historical objective shadow result", None)
    if not all(result.passes for result in shadow_results):
        return ObjectiveAdmissionDecision(False, "candidate regresses under a historical objective", None)
    return ObjectiveAdmissionDecision(
        True,
        "admitted by Prosecutor after bounded council critique and historical shadow checks",
        amendment.effective_cycle + probation_cycles,
    )


class CouncilTranscript:
    """In-memory protocol validator; durable storage remains the EventStore's job."""

    def __init__(self, cycle_id: str, *, max_messages: int = 24, max_tokens: int = 262_144) -> None:
        self._cycle_id = _text(cycle_id, "cycle_id", max_length=128)
        if max_messages <= 0 or max_tokens <= 0:
            raise CouncilProtocolError("council limits must be positive")
        self._max_messages = max_messages
        self._max_tokens = max_tokens
        self._messages: list[CouncilMessage] = []

    @property
    def messages(self) -> tuple[CouncilMessage, ...]:
        return tuple(self._messages)

    def append(self, message: CouncilMessage) -> None:
        if message.cycle_id != self._cycle_id:
            raise CouncilProtocolError("message belongs to another cycle")
        if len(self._messages) >= self._max_messages:
            raise CouncilProtocolError("council message limit exceeded")
        if sum(item.token_usage for item in self._messages) + message.token_usage > self._max_tokens:
            raise CouncilProtocolError("council token limit exceeded")
        if any(item.message_id == message.message_id for item in self._messages):
            raise CouncilProtocolError("duplicate council message")

        reflections = {item.sender for item in self._messages if item.message_type is CouncilMessageType.REFLECTION}
        if message.message_type is CouncilMessageType.REFLECTION:
            if message.sender in reflections:
                raise CouncilProtocolError("each role may submit only one independent reflection")
            if any(item.message_type is not CouncilMessageType.REFLECTION for item in self._messages):
                raise CouncilProtocolError("reflections must precede all other council messages")
        elif reflections != set(Role):
            raise CouncilProtocolError("all roles must reflect independently before discussion")
        elif message.message_type is CouncilMessageType.PROPOSAL:
            if any(item.proposal_id == message.proposal_id for item in self._messages):
                raise CouncilProtocolError("proposal_id already exists")
        elif message.message_type is CouncilMessageType.CRITIQUE:
            proposal = self._proposal(message.proposal_id)
            if proposal.sender is message.sender:
                raise CouncilProtocolError("a proposer cannot critique its own proposal")
            if any(
                item.message_type is CouncilMessageType.CRITIQUE
                and item.proposal_id == message.proposal_id
                and item.sender is message.sender
                for item in self._messages
            ):
                raise CouncilProtocolError("each role may critique a proposal only once")
            self._require_parent(message.parent_message_id, CouncilMessageType.PROPOSAL)
        elif message.message_type is CouncilMessageType.RESPONSE:
            proposal = self._proposal(message.proposal_id)
            if proposal.sender is not message.sender:
                raise CouncilProtocolError("only the proposer may respond")
            if any(
                item.message_type is CouncilMessageType.RESPONSE
                and item.proposal_id == message.proposal_id
                for item in self._messages
            ):
                raise CouncilProtocolError("a proposal may receive only one response")
            self._require_parent(message.parent_message_id, CouncilMessageType.CRITIQUE)
        else:
            self._proposal(message.proposal_id)
            if any(
                item.message_type is CouncilMessageType.SUPPORT
                and item.proposal_id == message.proposal_id
                and item.sender is message.sender
                for item in self._messages
            ):
                raise CouncilProtocolError("each role may submit only one support decision")
        self._messages.append(message)

    def _proposal(self, proposal_id: str | None) -> CouncilMessage:
        for item in self._messages:
            if item.message_type is CouncilMessageType.PROPOSAL and item.proposal_id == proposal_id:
                return item
        raise CouncilProtocolError("message references an unknown proposal")

    def _require_parent(self, message_id: str | None, expected: CouncilMessageType) -> None:
        for item in self._messages:
            if item.message_id == message_id:
                if item.message_type is not expected:
                    raise CouncilProtocolError(f"parent must be a {expected.value} message")
                return
        raise CouncilProtocolError("message references an unknown parent")
