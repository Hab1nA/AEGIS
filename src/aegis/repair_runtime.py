"""Supervisor-owned, replay-safe repair orchestration for recovery incidents."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Callable, Mapping, Protocol, Sequence, TypeVar

from aegis.generation_activation import (
    ActivationRequest,
    ActivationResult,
    ActivationStatus,
)
from aegis.models import AuditEvent, Role, canonical_json, freeze_json, thaw_json
from aegis.publishing import (
    GitCheckpointRequest,
    GitFileChange,
    PublicationResult,
    PublishOperation,
)
from aegis.recovery import IncidentReport, RepairDisposition, RepairPlan

_ADDRESS = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CONTENT_ID = re.compile(r"[a-z][a-z0-9-]*-sha256:[0-9a-f]{64}\Z")

REPAIR_STARTED = "repair_runtime_started_v1"
REPAIR_STEP_INTENT = "repair_runtime_step_intent_v1"
REPAIR_STEP_RECEIPT = "repair_runtime_step_receipt_v1"
REPAIR_TERMINAL = "repair_runtime_terminal_v1"


class RepairRuntimeError(RuntimeError):
    """Base error for repair orchestration, replay, or trust-boundary failure."""


class RepairRuntimeIntegrityError(RepairRuntimeError):
    """A plan, artifact, receipt, or event stream violated its binding."""


def _address(value: object, name: str) -> str:
    if not isinstance(value, str) or _ADDRESS.fullmatch(value) is None:
        raise ValueError(f"{name} must be a sha256 content address")
    return value


def _text(value: object, name: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or value.strip() != value or len(value) > maximum:
        raise ValueError(f"{name} must be bounded, non-empty, trimmed text")
    return value


def _digest_id(prefix: str, value: Mapping[str, Any]) -> str:
    return prefix + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _strict_json(value: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    try:
        frozen = freeze_json(value, path=name)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must contain strict JSON") from exc
    if not isinstance(frozen, Mapping):
        raise TypeError(f"{name} must be a mapping")
    return frozen


@dataclass(frozen=True, slots=True)
class PatchArtifact:
    base_generation_id: str
    changes: tuple[GitFileChange, ...]
    summary: str
    artifact_id: str = field(init=False)

    def __post_init__(self) -> None:
        _address(self.base_generation_id, "base_generation_id")
        if not self.changes:
            raise ValueError("patch artifact must contain at least one change")
        paths = tuple(item.path for item in self.changes)
        if tuple(sorted(set(paths))) != paths:
            raise ValueError("patch changes must have sorted unique paths")
        _text(self.summary, "summary")
        digest = hashlib.sha256(canonical_json(self.to_mapping(include_id=False)).encode("utf-8")).hexdigest()
        object.__setattr__(self, "artifact_id", f"sha256:{digest}")

    @classmethod
    def create(
        cls,
        *,
        base_generation_id: str,
        changes: Sequence[GitFileChange],
        summary: str,
    ) -> PatchArtifact:
        return cls(base_generation_id, tuple(sorted(changes, key=lambda item: item.path)), summary)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> PatchArtifact:
        expected = {"artifact_id", "base_generation_id", "changes", "summary"}
        raw_changes = value.get("changes")
        if set(value) != expected or not isinstance(raw_changes, (list, tuple)) or not all(
            isinstance(item, Mapping) for item in raw_changes
        ):
            raise RepairRuntimeIntegrityError("patch artifact has missing or invalid fields")
        result = cls(
            value["base_generation_id"],
            tuple(GitFileChange.from_mapping(item) for item in raw_changes),
            value["summary"],
        )
        if result.artifact_id != value["artifact_id"]:
            raise RepairRuntimeIntegrityError("patch artifact content id mismatch")
        return result

    def to_mapping(self, *, include_id: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "base_generation_id": self.base_generation_id,
            "changes": [item.to_mapping() for item in self.changes],
            "summary": self.summary,
        }
        return {"artifact_id": self.artifact_id, **payload} if include_id else payload


def _checkpoint_from_mapping(value: Mapping[str, Any]) -> GitCheckpointRequest:
    expected = {"request_id", "role", "generation_id", "base_commit", "changes", "message"}
    raw_changes = value.get("changes")
    if set(value) != expected or not isinstance(raw_changes, (list, tuple)) or not all(
        isinstance(item, Mapping) for item in raw_changes
    ):
        raise RepairRuntimeIntegrityError("checkpoint has missing or invalid fields")
    try:
        return GitCheckpointRequest(
            value["request_id"],
            value["role"],
            value["generation_id"],
            value["base_commit"],
            tuple(GitFileChange.from_mapping(item) for item in raw_changes),
            value["message"],
        )
    except (TypeError, ValueError) as exc:
        raise RepairRuntimeIntegrityError("checkpoint violates the publishing contract") from exc


@dataclass(frozen=True, slots=True)
class RecoveryCandidate:
    patch_artifact_id: str
    base_generation_id: str
    checkpoint: GitCheckpointRequest
    activation_request: ActivationRequest
    candidate_id: str = field(init=False)

    def __post_init__(self) -> None:
        _address(self.patch_artifact_id, "patch_artifact_id")
        _address(self.base_generation_id, "base_generation_id")
        if self.activation_request.expected_manifest.generation_id != self.base_generation_id:
            raise ValueError("activation manifest is not based on the last-known-good generation")
        object.__setattr__(
            self,
            "candidate_id",
            _digest_id("recovery-candidate-sha256:", self.to_mapping(include_id=False)),
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> RecoveryCandidate:
        expected = {
            "candidate_id",
            "patch_artifact_id",
            "base_generation_id",
            "checkpoint",
            "activation_request",
        }
        checkpoint = value.get("checkpoint")
        activation = value.get("activation_request")
        if set(value) != expected or not isinstance(checkpoint, Mapping) or not isinstance(
            activation, Mapping
        ):
            raise RepairRuntimeIntegrityError("recovery candidate has missing or invalid fields")
        result = cls(
            value["patch_artifact_id"],
            value["base_generation_id"],
            _checkpoint_from_mapping(checkpoint),
            ActivationRequest.from_mapping(activation),
        )
        if result.candidate_id != value["candidate_id"]:
            raise RepairRuntimeIntegrityError("recovery candidate content id mismatch")
        return result

    def to_mapping(self, *, include_id: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "patch_artifact_id": self.patch_artifact_id,
            "base_generation_id": self.base_generation_id,
            "checkpoint": self.checkpoint.to_mapping(),
            "activation_request": self.activation_request.to_mapping(),
        }
        return {"candidate_id": self.candidate_id, **payload} if include_id else payload


@dataclass(frozen=True, slots=True)
class PublishedCandidate:
    candidate_id: str
    checkpoint_request_id: str
    publish_intent_id: str
    publish_receipt_id: str
    candidate_commit: str
    candidate_ref: str
    published_id: str = field(init=False)

    def __post_init__(self) -> None:
        if _CONTENT_ID.fullmatch(self.candidate_id) is None or not self.candidate_id.startswith(
            "recovery-candidate-sha256:"
        ):
            raise ValueError("candidate_id must be a recovery candidate content id")
        for value, name in (
            (self.checkpoint_request_id, "checkpoint_request_id"),
            (self.publish_intent_id, "publish_intent_id"),
            (self.publish_receipt_id, "publish_receipt_id"),
        ):
            if not isinstance(value, str) or _CONTENT_ID.fullmatch(value) is None:
                raise ValueError(f"{name} must be content-addressed")
        if not isinstance(self.candidate_commit, str) or len(self.candidate_commit) not in {40, 64}:
            raise ValueError("candidate_commit must be a full Git object id")
        try:
            int(self.candidate_commit, 16)
        except ValueError as exc:
            raise ValueError("candidate_commit must be hexadecimal") from exc
        _text(self.candidate_ref, "candidate_ref")
        object.__setattr__(
            self,
            "published_id",
            _digest_id("published-recovery-candidate-sha256:", self.to_mapping(include_id=False)),
        )

    @classmethod
    def from_publication(
        cls, candidate: RecoveryCandidate, publication: PublicationResult
    ) -> PublishedCandidate:
        if publication.intent.operation is not PublishOperation.CANDIDATE:
            raise RepairRuntimeIntegrityError("publisher returned a non-candidate operation")
        if publication.intent.request_id != candidate.checkpoint.request_id:
            raise RepairRuntimeIntegrityError("publication is bound to another checkpoint")
        if publication.receipt.intent_id != publication.intent.intent_id:
            raise RepairRuntimeIntegrityError("publication receipt is bound to another intent")
        if (
            publication.receipt.operation is not publication.intent.operation
            or publication.receipt.ref != publication.intent.ref
            or publication.receipt.new_commit != publication.intent.new_commit
        ):
            raise RepairRuntimeIntegrityError("publication receipt does not match its publish intent")
        expected_ref = (
            f"refs/heads/candidate/{candidate.checkpoint.role}/{candidate.checkpoint.generation_id}"
        )
        if publication.receipt.ref != expected_ref:
            raise RepairRuntimeIntegrityError("publisher returned an unexpected candidate ref")
        return cls(
            candidate.candidate_id,
            candidate.checkpoint.request_id,
            publication.intent.intent_id,
            publication.receipt.receipt_id,
            publication.receipt.new_commit,
            publication.receipt.ref,
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> PublishedCandidate:
        expected = {
            "published_id",
            "candidate_id",
            "checkpoint_request_id",
            "publish_intent_id",
            "publish_receipt_id",
            "candidate_commit",
            "candidate_ref",
        }
        if set(value) != expected:
            raise RepairRuntimeIntegrityError("published candidate has missing or unknown fields")
        result = cls(
            value["candidate_id"],
            value["checkpoint_request_id"],
            value["publish_intent_id"],
            value["publish_receipt_id"],
            value["candidate_commit"],
            value["candidate_ref"],
        )
        if result.published_id != value["published_id"]:
            raise RepairRuntimeIntegrityError("published candidate content id mismatch")
        return result

    def to_mapping(self, *, include_id: bool = True) -> dict[str, Any]:
        payload = {
            "candidate_id": self.candidate_id,
            "checkpoint_request_id": self.checkpoint_request_id,
            "publish_intent_id": self.publish_intent_id,
            "publish_receipt_id": self.publish_receipt_id,
            "candidate_commit": self.candidate_commit,
            "candidate_ref": self.candidate_ref,
        }
        return {"published_id": self.published_id, **payload} if include_id else payload


@dataclass(frozen=True, slots=True)
class CandidateValidation:
    candidate_id: str
    published_id: str
    qualified: bool
    safety_passed: bool
    qualification_evidence: str
    safety_evidence: str
    validation_id: str = field(init=False)

    def __post_init__(self) -> None:
        for value, prefix, name in (
            (self.candidate_id, "recovery-candidate-sha256:", "candidate_id"),
            (self.published_id, "published-recovery-candidate-sha256:", "published_id"),
        ):
            if not isinstance(value, str) or not value.startswith(prefix) or _CONTENT_ID.fullmatch(value) is None:
                raise ValueError(f"{name} must be content-addressed")
        if not isinstance(self.qualified, bool) or not isinstance(self.safety_passed, bool):
            raise TypeError("validation decisions must be bool values")
        _address(self.qualification_evidence, "qualification_evidence")
        _address(self.safety_evidence, "safety_evidence")
        object.__setattr__(
            self,
            "validation_id",
            _digest_id("repair-validation-sha256:", self.to_mapping(include_id=False)),
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> CandidateValidation:
        expected = {
            "validation_id",
            "candidate_id",
            "published_id",
            "qualified",
            "safety_passed",
            "qualification_evidence",
            "safety_evidence",
        }
        if set(value) != expected:
            raise RepairRuntimeIntegrityError("candidate validation has missing or unknown fields")
        result = cls(
            value["candidate_id"],
            value["published_id"],
            value["qualified"],
            value["safety_passed"],
            value["qualification_evidence"],
            value["safety_evidence"],
        )
        if result.validation_id != value["validation_id"]:
            raise RepairRuntimeIntegrityError("candidate validation content id mismatch")
        return result

    def to_mapping(self, *, include_id: bool = True) -> dict[str, Any]:
        payload = {
            "candidate_id": self.candidate_id,
            "published_id": self.published_id,
            "qualified": self.qualified,
            "safety_passed": self.safety_passed,
            "qualification_evidence": self.qualification_evidence,
            "safety_evidence": self.safety_evidence,
        }
        return {"validation_id": self.validation_id, **payload} if include_id else payload


class RepairStep(StrEnum):
    BUILTIN_PROSECUTOR_ROLLBACK = "builtin-prosecutor-rollback"
    ROLLBACK = "rollback"
    QUARANTINE = "quarantine"
    PROSECUTOR_PATCH = "prosecutor-patch"
    CREATE_CANDIDATE = "create-isolated-candidate"
    PUBLISH_CANDIDATE = "publish-candidate"
    VALIDATE_CANDIDATE = "validate-candidate"
    ACTIVATE_CANDIDATE = "activate-candidate"


@dataclass(frozen=True, slots=True)
class RepairStepIntent:
    incident_id: str
    repair_plan_id: str
    action: RepairStep
    payload: Mapping[str, Any]
    intent_id: str = field(init=False)

    def __post_init__(self) -> None:
        for value, prefix, name in (
            (self.incident_id, "incident-sha256:", "incident_id"),
            (self.repair_plan_id, "repair-plan-sha256:", "repair_plan_id"),
        ):
            if not isinstance(value, str) or not value.startswith(prefix) or _CONTENT_ID.fullmatch(value) is None:
                raise ValueError(f"{name} must be content-addressed")
        object.__setattr__(self, "payload", _strict_json(self.payload, "repair step payload"))
        object.__setattr__(
            self,
            "intent_id",
            _digest_id("repair-step-intent-sha256:", self.to_mapping(include_id=False)),
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> RepairStepIntent:
        expected = {"intent_id", "incident_id", "repair_plan_id", "action", "payload"}
        payload = value.get("payload")
        if set(value) != expected or not isinstance(payload, Mapping):
            raise RepairRuntimeIntegrityError("repair step intent has missing or invalid fields")
        result = cls(
            value["incident_id"],
            value["repair_plan_id"],
            RepairStep(value["action"]),
            payload,
        )
        if result.intent_id != value["intent_id"]:
            raise RepairRuntimeIntegrityError("repair step intent content id mismatch")
        return result

    def to_mapping(self, *, include_id: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "incident_id": self.incident_id,
            "repair_plan_id": self.repair_plan_id,
            "action": self.action.value,
            "payload": thaw_json(self.payload),
        }
        return {"intent_id": self.intent_id, **payload} if include_id else payload


@dataclass(frozen=True, slots=True)
class RepairStepReceipt:
    intent_id: str
    action: RepairStep
    data: Mapping[str, Any]
    receipt_id: str = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.intent_id, str) or not self.intent_id.startswith(
            "repair-step-intent-sha256:"
        ) or _CONTENT_ID.fullmatch(self.intent_id) is None:
            raise ValueError("intent_id must be a repair step intent content id")
        object.__setattr__(self, "data", _strict_json(self.data, "repair step receipt"))
        object.__setattr__(
            self,
            "receipt_id",
            _digest_id("repair-step-receipt-sha256:", self.to_mapping(include_id=False)),
        )

    @classmethod
    def create(
        cls, intent: RepairStepIntent, data: Mapping[str, Any]
    ) -> RepairStepReceipt:
        return cls(intent.intent_id, intent.action, data)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> RepairStepReceipt:
        expected = {"receipt_id", "intent_id", "action", "data"}
        data = value.get("data")
        if set(value) != expected or not isinstance(data, Mapping):
            raise RepairRuntimeIntegrityError("repair step receipt has missing or invalid fields")
        result = cls(value["intent_id"], RepairStep(value["action"]), data)
        if result.receipt_id != value["receipt_id"]:
            raise RepairRuntimeIntegrityError("repair step receipt content id mismatch")
        return result

    def to_mapping(self, *, include_id: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "intent_id": self.intent_id,
            "action": self.action.value,
            "data": thaw_json(self.data),
        }
        return {"receipt_id": self.receipt_id, **payload} if include_id else payload


class RepairStatus(StrEnum):
    ROLLED_BACK = "rolled-back"
    QUARANTINED = "quarantined"
    REPAIRED = "repaired"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class RepairRuntimeResult:
    incident_id: str
    repair_plan_id: str
    status: RepairStatus
    completed_steps: tuple[RepairStep, ...]
    candidate_id: str | None = None
    activation_status: ActivationStatus | None = None


class ProsecutorPort(Protocol):
    def generate_patch(
        self, intent: RepairStepIntent, incident: IncidentReport, plan: RepairPlan
    ) -> PatchArtifact: ...

    def reconcile(self, intent_id: str) -> PatchArtifact | None: ...


class RecoveryWorkspacePort(Protocol):
    def create_candidate(
        self,
        intent: RepairStepIntent,
        incident: IncidentReport,
        plan: RepairPlan,
        patch: PatchArtifact,
    ) -> RecoveryCandidate: ...

    def reconcile(self, intent_id: str) -> RecoveryCandidate | None: ...


class GitPublisherPort(Protocol):
    def publish_candidate(
        self, intent: RepairStepIntent, checkpoint: GitCheckpointRequest
    ) -> PublicationResult: ...

    def reconcile(self, intent_id: str) -> PublicationResult | None: ...


class CandidateValidatorPort(Protocol):
    def validate(
        self,
        intent: RepairStepIntent,
        candidate: RecoveryCandidate,
        publication: PublishedCandidate,
    ) -> CandidateValidation: ...

    def reconcile(self, intent_id: str) -> CandidateValidation | None: ...


class RecoveryControlPort(Protocol):
    def execute(
        self, intent: RepairStepIntent, incident: IncidentReport, plan: RepairPlan
    ) -> Mapping[str, Any]: ...

    def reconcile(self, intent_id: str) -> Mapping[str, Any] | None: ...


class GenerationActivatorPort(Protocol):
    def activate(self, request: ActivationRequest) -> ActivationResult: ...


class RepairEventStore(Protocol):
    def read(
        self, campaign_id: str, *, after_sequence: int = 0, limit: int | None = None
    ) -> tuple[AuditEvent, ...]: ...

    def append_if_sequence(
        self,
        campaign_id: str,
        expected_sequence: int,
        event_type: str,
        payload: Mapping[str, Any],
        *,
        created_at: datetime | None = None,
    ) -> AuditEvent: ...


@dataclass(slots=True)
class _Projection:
    sequence: int = 0
    started: bool = False
    intents: dict[RepairStep, RepairStepIntent] = field(default_factory=dict)
    receipts: dict[RepairStep, RepairStepReceipt] = field(default_factory=dict)
    terminal_status: RepairStatus | None = None
    activation_status: ActivationStatus | None = None


T = TypeVar("T")


class RecoverySupervisor:
    def __init__(
        self,
        event_store: RepairEventStore,
        prosecutor: ProsecutorPort,
        workspace: RecoveryWorkspacePort,
        publisher: GitPublisherPort,
        validator: CandidateValidatorPort,
        activator: GenerationActivatorPort,
        recovery_control: RecoveryControlPort,
    ) -> None:
        self._store = event_store
        self._prosecutor = prosecutor
        self._workspace = workspace
        self._publisher = publisher
        self._validator = validator
        self._activator = activator
        self._control = recovery_control

    @staticmethod
    def stream_id(incident_id: str) -> str:
        return f"repair:{incident_id}"

    def run(self, incident: IncidentReport, plan: RepairPlan) -> RepairRuntimeResult:
        self._validate_inputs(incident, plan)
        stream = self.stream_id(incident.incident_id)
        projection = self._replay(stream, incident, plan)
        if not projection.started:
            event = self._store.append_if_sequence(
                stream,
                0,
                REPAIR_STARTED,
                {"incident_id": incident.incident_id, "repair_plan_id": plan.repair_plan_id},
            )
            projection.started = True
            projection.sequence = event.sequence
        if projection.terminal_status is not None:
            return self._result(incident, plan, projection)

        if incident.target_role is Role.PROSECUTOR:
            self._control_step(
                projection,
                incident,
                plan,
                RepairStep.BUILTIN_PROSECUTOR_ROLLBACK,
                incident.last_known_good_generation_id,
            )
            self._terminal(projection, incident, plan, RepairStatus.ROLLED_BACK)
            return self._result(incident, plan, projection)
        if plan.disposition is RepairDisposition.ROLLBACK:
            self._control_step(
                projection,
                incident,
                plan,
                RepairStep.ROLLBACK,
                incident.last_known_good_generation_id,
            )
            self._terminal(projection, incident, plan, RepairStatus.ROLLED_BACK)
            return self._result(incident, plan, projection)
        if plan.disposition is RepairDisposition.QUARANTINE:
            self._control_step(
                projection,
                incident,
                plan,
                RepairStep.QUARANTINE,
                incident.failed_generation_id,
            )
            self._terminal(projection, incident, plan, RepairStatus.QUARANTINED)
            return self._result(incident, plan, projection)

        patch = self._patch_step(projection, incident, plan)
        candidate = self._candidate_step(projection, incident, plan, patch)
        publication = self._publish_step(projection, incident, plan, candidate)
        validation = self._validation_step(projection, incident, plan, candidate, publication)
        if not validation.qualified or not validation.safety_passed:
            self._terminal(projection, incident, plan, RepairStatus.REJECTED)
            return self._result(incident, plan, projection)
        activation = self._activation_step(projection, incident, plan, candidate)
        if activation.status not in {ActivationStatus.ACTIVATED, ActivationStatus.ROLLED_BACK}:
            raise RepairRuntimeIntegrityError("generation activator returned a non-terminal status")
        status = (
            RepairStatus.REPAIRED
            if activation.status is ActivationStatus.ACTIVATED
            else RepairStatus.ROLLED_BACK
        )
        self._terminal(projection, incident, plan, status, activation_status=activation.status)
        return self._result(incident, plan, projection)

    @staticmethod
    def _validate_inputs(incident: IncidentReport, plan: RepairPlan) -> None:
        if plan.incident_id != incident.incident_id:
            raise RepairRuntimeIntegrityError("repair plan is bound to another incident")
        if plan.target_role is not incident.target_role:
            raise RepairRuntimeIntegrityError("repair plan target role does not match the incident")
        if plan.base_generation_id != incident.last_known_good_generation_id:
            raise RepairRuntimeIntegrityError("repair plan base must equal the incident last-known-good")

    def _patch_step(
        self, projection: _Projection, incident: IncidentReport, plan: RepairPlan
    ) -> PatchArtifact:
        if plan.patch_artifact_id is None:
            raise RepairRuntimeIntegrityError("retry-after-fix requires a patch artifact id")
        intent = self._intent(
            projection,
            incident,
            plan,
            RepairStep.PROSECUTOR_PATCH,
            {"patch_artifact_id": plan.patch_artifact_id},
        )
        patch = self._external(
            projection,
            intent,
            self._prosecutor.reconcile,
            lambda: self._prosecutor.generate_patch(intent, incident, plan),
            lambda item: {"patch": item.to_mapping()},
            lambda data: PatchArtifact.from_mapping(self._object(data, "patch")),
        )
        if patch.artifact_id != plan.patch_artifact_id:
            raise RepairRuntimeIntegrityError("Prosecutor patch does not match the approved repair plan")
        if patch.base_generation_id != incident.last_known_good_generation_id:
            raise RepairRuntimeIntegrityError("Prosecutor patch is not based on last-known-good")
        return patch

    def _candidate_step(
        self,
        projection: _Projection,
        incident: IncidentReport,
        plan: RepairPlan,
        patch: PatchArtifact,
    ) -> RecoveryCandidate:
        intent = self._intent(
            projection,
            incident,
            plan,
            RepairStep.CREATE_CANDIDATE,
            {"patch_artifact_id": patch.artifact_id, "base_generation_id": patch.base_generation_id},
        )
        candidate = self._external(
            projection,
            intent,
            self._workspace.reconcile,
            lambda: self._workspace.create_candidate(intent, incident, plan, patch),
            lambda item: {"candidate": item.to_mapping()},
            lambda data: RecoveryCandidate.from_mapping(self._object(data, "candidate")),
        )
        if candidate.patch_artifact_id != patch.artifact_id:
            raise RepairRuntimeIntegrityError("recovery candidate contains another patch")
        if candidate.checkpoint.changes != patch.changes:
            raise RepairRuntimeIntegrityError("recovery checkpoint changes differ from the approved patch")
        if candidate.base_generation_id != incident.last_known_good_generation_id:
            raise RepairRuntimeIntegrityError("recovery candidate base is not last-known-good")
        if candidate.checkpoint.role != incident.target_role.value:
            raise RepairRuntimeIntegrityError("recovery checkpoint targets another role")
        return candidate

    def _publish_step(
        self,
        projection: _Projection,
        incident: IncidentReport,
        plan: RepairPlan,
        candidate: RecoveryCandidate,
    ) -> PublishedCandidate:
        intent = self._intent(
            projection,
            incident,
            plan,
            RepairStep.PUBLISH_CANDIDATE,
            {
                "candidate_id": candidate.candidate_id,
                "checkpoint_request_id": candidate.checkpoint.request_id,
            },
        )

        existing = projection.receipts.get(intent.action)
        if existing is not None:
            publication = PublishedCandidate.from_mapping(self._object(existing.data, "publication"))
        else:
            publication_result = self._publisher.reconcile(intent.intent_id)
            if publication_result is None:
                publication_result = self._publisher.publish_candidate(intent, candidate.checkpoint)
            publication = PublishedCandidate.from_publication(candidate, publication_result)
            self._receipt(projection, intent, {"publication": publication.to_mapping()})
        if publication.candidate_id != candidate.candidate_id:
            raise RepairRuntimeIntegrityError("published artifact is bound to another candidate")
        return publication

    def _validation_step(
        self,
        projection: _Projection,
        incident: IncidentReport,
        plan: RepairPlan,
        candidate: RecoveryCandidate,
        publication: PublishedCandidate,
    ) -> CandidateValidation:
        intent = self._intent(
            projection,
            incident,
            plan,
            RepairStep.VALIDATE_CANDIDATE,
            {"candidate_id": candidate.candidate_id, "published_id": publication.published_id},
        )
        validation = self._external(
            projection,
            intent,
            self._validator.reconcile,
            lambda: self._validator.validate(intent, candidate, publication),
            lambda item: {"validation": item.to_mapping()},
            lambda data: CandidateValidation.from_mapping(self._object(data, "validation")),
        )
        if validation.candidate_id != candidate.candidate_id or validation.published_id != publication.published_id:
            raise RepairRuntimeIntegrityError("validation is bound to another recovery candidate")
        return validation

    def _activation_step(
        self,
        projection: _Projection,
        incident: IncidentReport,
        plan: RepairPlan,
        candidate: RecoveryCandidate,
    ) -> ActivationResult:
        intent = self._intent(
            projection,
            incident,
            plan,
            RepairStep.ACTIVATE_CANDIDATE,
            {
                "candidate_id": candidate.candidate_id,
                "activation_id": candidate.activation_request.activation_id,
            },
        )
        existing = projection.receipts.get(intent.action)
        if existing is not None:
            result = self._activation_from_data(existing.data)
            self._validate_activation_result(candidate, result)
            return result
        result = self._activator.activate(candidate.activation_request)
        self._validate_activation_result(candidate, result)
        data = {
            "activation": {
                "activation_id": result.activation_id,
                "status": result.status.value,
                "active_manifest": result.active_manifest.to_mapping(),
            }
        }
        self._receipt(projection, intent, data)
        return result

    def _control_step(
        self,
        projection: _Projection,
        incident: IncidentReport,
        plan: RepairPlan,
        action: RepairStep,
        generation_id: str,
    ) -> Mapping[str, Any]:
        intent = self._intent(
            projection,
            incident,
            plan,
            action,
            {"generation_id": generation_id},
        )
        result = self._external(
            projection,
            intent,
            self._control.reconcile,
            lambda: self._control.execute(intent, incident, plan),
            lambda item: {"control": dict(item)},
            lambda data: self._object(data, "control"),
        )
        if result.get("action") != action.value or result.get("generation_id") != generation_id:
            raise RepairRuntimeIntegrityError("recovery control receipt does not match its intent")
        return result

    def _external(
        self,
        projection: _Projection,
        intent: RepairStepIntent,
        reconcile: Callable[[str], T | None],
        perform: Callable[[], T],
        encode: Callable[[T], Mapping[str, Any]],
        decode: Callable[[Mapping[str, Any]], T],
    ) -> T:
        existing = projection.receipts.get(intent.action)
        if existing is not None:
            return decode(existing.data)
        result = reconcile(intent.intent_id)
        if result is None:
            result = perform()
        data = encode(result)
        self._receipt(projection, intent, data)
        return decode(data)

    def _intent(
        self,
        projection: _Projection,
        incident: IncidentReport,
        plan: RepairPlan,
        action: RepairStep,
        payload: Mapping[str, Any],
    ) -> RepairStepIntent:
        existing = projection.intents.get(action)
        candidate = RepairStepIntent(incident.incident_id, plan.repair_plan_id, action, payload)
        if existing is not None:
            if existing != candidate:
                raise RepairRuntimeIntegrityError("replayed repair step intent payload changed")
            return existing
        expected = self._expected_steps(incident, plan)
        if action not in expected or any(step not in projection.receipts for step in expected[: expected.index(action)]):
            raise RepairRuntimeIntegrityError("repair step is outside or ahead of its disposition path")
        self._append(projection, incident, REPAIR_STEP_INTENT, {"intent": candidate.to_mapping()})
        projection.intents[action] = candidate
        return candidate

    def _receipt(
        self, projection: _Projection, intent: RepairStepIntent, data: Mapping[str, Any]
    ) -> RepairStepReceipt:
        receipt = RepairStepReceipt.create(intent, data)
        self._append(projection, None, REPAIR_STEP_RECEIPT, {"receipt": receipt.to_mapping()})
        projection.receipts[intent.action] = receipt
        return receipt

    def _terminal(
        self,
        projection: _Projection,
        incident: IncidentReport,
        plan: RepairPlan,
        status: RepairStatus,
        *,
        activation_status: ActivationStatus | None = None,
    ) -> None:
        payload = {
            "incident_id": incident.incident_id,
            "repair_plan_id": plan.repair_plan_id,
            "status": status.value,
            "activation_status": None if activation_status is None else activation_status.value,
        }
        self._append(projection, incident, REPAIR_TERMINAL, payload)
        projection.terminal_status = status
        projection.activation_status = activation_status

    def _append(
        self,
        projection: _Projection,
        incident: IncidentReport | None,
        event_type: str,
        payload: Mapping[str, Any],
    ) -> None:
        incident_id = (
            incident.incident_id
            if incident is not None
            else next(iter(projection.intents.values())).incident_id
        )
        event = self._store.append_if_sequence(
            self.stream_id(incident_id), projection.sequence, event_type, payload
        )
        projection.sequence = event.sequence

    def _replay(
        self, stream: str, incident: IncidentReport, plan: RepairPlan
    ) -> _Projection:
        projection = _Projection()
        events = self._store.read(stream)
        for event in events:
            if event.sequence != projection.sequence + 1:
                raise RepairRuntimeIntegrityError("repair event sequence is not contiguous")
            projection.sequence = event.sequence
            raw = thaw_json(event.payload)
            if not isinstance(raw, Mapping):
                raise RepairRuntimeIntegrityError("repair event payload must be an object")
            if event.event_type == REPAIR_STARTED:
                if projection.started or raw != {
                    "incident_id": incident.incident_id,
                    "repair_plan_id": plan.repair_plan_id,
                }:
                    raise RepairRuntimeIntegrityError("repair start event is duplicated or mismatched")
                projection.started = True
            elif event.event_type == REPAIR_STEP_INTENT:
                if not projection.started or set(raw) != {"intent"} or not isinstance(raw["intent"], Mapping):
                    raise RepairRuntimeIntegrityError("repair step intent event is malformed")
                intent = RepairStepIntent.from_mapping(raw["intent"])
                if intent.incident_id != incident.incident_id or intent.repair_plan_id != plan.repair_plan_id:
                    raise RepairRuntimeIntegrityError("repair step intent belongs to another plan")
                if intent.action in projection.intents:
                    raise RepairRuntimeIntegrityError("repair step has duplicate intents")
                expected = self._expected_steps(incident, plan)
                if intent.action not in expected or any(
                    previous not in projection.receipts for previous in expected[: expected.index(intent.action)]
                ):
                    raise RepairRuntimeIntegrityError("repair event step is out of order")
                projection.intents[intent.action] = intent
            elif event.event_type == REPAIR_STEP_RECEIPT:
                if not projection.started or set(raw) != {"receipt"} or not isinstance(
                    raw["receipt"], Mapping
                ):
                    raise RepairRuntimeIntegrityError("repair step receipt event is malformed")
                receipt = RepairStepReceipt.from_mapping(raw["receipt"])
                receipt_intent = projection.intents.get(receipt.action)
                if (
                    receipt_intent is None
                    or receipt.action in projection.receipts
                    or receipt.intent_id != receipt_intent.intent_id
                ):
                    raise RepairRuntimeIntegrityError("repair receipt lacks one matching intent")
                projection.receipts[receipt.action] = receipt
            elif event.event_type == REPAIR_TERMINAL:
                expected_keys = {"incident_id", "repair_plan_id", "status", "activation_status"}
                if (
                    not projection.started
                    or projection.terminal_status is not None
                    or set(raw) != expected_keys
                    or raw["incident_id"] != incident.incident_id
                    or raw["repair_plan_id"] != plan.repair_plan_id
                ):
                    raise RepairRuntimeIntegrityError("repair terminal event is malformed")
                projection.terminal_status = RepairStatus(raw["status"])
                activation = raw["activation_status"]
                projection.activation_status = None if activation is None else ActivationStatus(activation)
            else:
                raise RepairRuntimeIntegrityError(f"unknown repair event type: {event.event_type}")
            if projection.terminal_status is not None and event.sequence != events[-1].sequence:
                raise RepairRuntimeIntegrityError("repair stream contains events after terminal state")
        return projection

    @staticmethod
    def _expected_steps(incident: IncidentReport, plan: RepairPlan) -> tuple[RepairStep, ...]:
        if incident.target_role is Role.PROSECUTOR:
            return (RepairStep.BUILTIN_PROSECUTOR_ROLLBACK,)
        if plan.disposition is RepairDisposition.ROLLBACK:
            return (RepairStep.ROLLBACK,)
        if plan.disposition is RepairDisposition.QUARANTINE:
            return (RepairStep.QUARANTINE,)
        return (
            RepairStep.PROSECUTOR_PATCH,
            RepairStep.CREATE_CANDIDATE,
            RepairStep.PUBLISH_CANDIDATE,
            RepairStep.VALIDATE_CANDIDATE,
            RepairStep.ACTIVATE_CANDIDATE,
        )

    @staticmethod
    def _object(value: Mapping[str, Any], name: str) -> Mapping[str, Any]:
        raw = value.get(name)
        if not isinstance(raw, Mapping):
            raise RepairRuntimeIntegrityError(f"repair receipt omitted {name}")
        return raw

    @staticmethod
    def _activation_from_data(value: Mapping[str, Any]) -> ActivationResult:
        raw = value.get("activation")
        if not isinstance(raw, Mapping) or set(raw) != {"activation_id", "status", "active_manifest"}:
            raise RepairRuntimeIntegrityError("activation receipt is malformed")
        manifest = raw["active_manifest"]
        if not isinstance(manifest, Mapping):
            raise RepairRuntimeIntegrityError("activation receipt omitted active manifest")
        from aegis.generation_activation import ActiveManifest

        return ActivationResult(
            raw["activation_id"],
            ActivationStatus(raw["status"]),
            ActiveManifest.from_mapping(manifest),
            (),
            False,
        )

    @staticmethod
    def _validate_activation_result(
        candidate: RecoveryCandidate, result: ActivationResult
    ) -> None:
        request = candidate.activation_request
        if result.activation_id != request.activation_id:
            raise RepairRuntimeIntegrityError("activation result belongs to another request")
        manifest = result.active_manifest
        if result.status is ActivationStatus.ACTIVATED:
            if (
                manifest.generation_id != request.candidate_generation_id
                or manifest.bundle_digest != request.bundle_digest
                or manifest.slot_id != request.target_slot
            ):
                raise RepairRuntimeIntegrityError("activated manifest does not bind the recovery candidate")
        elif result.status is ActivationStatus.ROLLED_BACK:
            expected = request.expected_manifest
            if (
                manifest.generation_id != expected.generation_id
                or manifest.bundle_digest != expected.bundle_digest
                or manifest.slot_id != expected.slot_id
            ):
                raise RepairRuntimeIntegrityError("rollback result did not restore last-known-good")

    @staticmethod
    def _result(
        incident: IncidentReport, plan: RepairPlan, projection: _Projection
    ) -> RepairRuntimeResult:
        if projection.terminal_status is None:
            raise RepairRuntimeIntegrityError("repair result requested before terminal state")
        candidate_id: str | None = None
        receipt = projection.receipts.get(RepairStep.CREATE_CANDIDATE)
        if receipt is not None:
            raw = receipt.data.get("candidate")
            if isinstance(raw, Mapping):
                candidate_id = RecoveryCandidate.from_mapping(raw).candidate_id
        return RepairRuntimeResult(
            incident.incident_id,
            plan.repair_plan_id,
            projection.terminal_status,
            tuple(step for step in RepairStep if step in projection.receipts),
            candidate_id,
            projection.activation_status,
        )


__all__ = [
    "REPAIR_STARTED",
    "REPAIR_STEP_INTENT",
    "REPAIR_STEP_RECEIPT",
    "REPAIR_TERMINAL",
    "CandidateValidation",
    "CandidateValidatorPort",
    "GenerationActivatorPort",
    "GitPublisherPort",
    "PatchArtifact",
    "ProsecutorPort",
    "PublishedCandidate",
    "RecoveryCandidate",
    "RecoveryControlPort",
    "RecoverySupervisor",
    "RecoveryWorkspacePort",
    "RepairRuntimeError",
    "RepairRuntimeIntegrityError",
    "RepairRuntimeResult",
    "RepairStatus",
    "RepairStep",
    "RepairStepIntent",
    "RepairStepReceipt",
]
