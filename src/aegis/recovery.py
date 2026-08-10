"""Fail-closed generation health detection and evidence-bound repair plans."""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum

from aegis.models import Role, canonical_json


class RecoveryContractError(ValueError):
    """Raised when health or recovery evidence is malformed."""


class BrickKind(StrEnum):
    STARTUP_FAILURE = "startup_failure"
    HEARTBEAT_TIMEOUT = "heartbeat_timeout"
    EVENT_STALL = "event_stall"
    CRASH_LOOP = "crash_loop"
    PROTOCOL_FAILURE = "protocol_failure"
    EVENT_REPLAY_FAILURE = "event_replay_failure"
    RESOURCE_LEAK = "resource_leak"
    SAFETY_VIOLATION = "safety_violation"


class RepairDisposition(StrEnum):
    ROLLBACK = "rollback"
    QUARANTINE = "quarantine"
    RETRY_AFTER_FIX = "retry_after_fix"


class RecoveryState(StrEnum):
    HEALTHY = "healthy"
    FENCING = "fencing"
    ROLLED_BACK = "rolled_back"
    DIAGNOSING = "diagnosing"
    REPAIR_VALIDATING = "repair_validating"
    PROBATION = "probation"
    FAILED = "failed"


def _aware(value: object, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise RecoveryContractError(f"{name} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _text(value: object, name: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise RecoveryContractError(f"{name} must be non-empty trimmed text")
    if len(value.encode("utf-8")) > maximum:
        raise RecoveryContractError(f"{name} exceeds {maximum} bytes")
    return value


def _content_address(value: object, name: str) -> str:
    text = _text(value, name, maximum=128)
    if not text.startswith("sha256:") or len(text) != 71:
        raise RecoveryContractError(f"{name} must be a sha256 content address")
    try:
        int(text[7:], 16)
    except ValueError as exc:
        raise RecoveryContractError(f"{name} must be a sha256 content address") from exc
    return text.lower()


def _non_negative_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RecoveryContractError(f"{name} must be a non-negative integer")
    return value


def _content_id(prefix: str, payload: dict[str, object]) -> str:
    return prefix + hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class RecoveryPolicy:
    startup_timeout_seconds: float = 60.0
    heartbeat_timeout_seconds: float = 45.0
    event_stall_timeout_seconds: float = 300.0
    crash_loop_threshold: int = 3
    protocol_error_threshold: int = 3

    def __post_init__(self) -> None:
        for name in (
            "startup_timeout_seconds",
            "heartbeat_timeout_seconds",
            "event_stall_timeout_seconds",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise RecoveryContractError(f"{name} must be numeric")
            value = float(value)
            if not math.isfinite(value) or value <= 0:
                raise RecoveryContractError(f"{name} must be finite and positive")
            object.__setattr__(self, name, value)
        for name in ("crash_loop_threshold", "protocol_error_threshold"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise RecoveryContractError(f"{name} must be a positive integer")


@dataclass(frozen=True, slots=True)
class GenerationHealthSnapshot:
    generation_id: str
    activated_at: datetime
    startup_complete: bool
    doctor_healthy: bool
    last_heartbeat_at: datetime | None
    last_event_progress_at: datetime | None
    consecutive_phase_crashes: int = 0
    consecutive_protocol_errors: int = 0
    orphan_sandboxes: int = 0
    orphan_worktrees: int = 0
    event_replay_ok: bool = True
    safety_violation: bool = False

    def __post_init__(self) -> None:
        _content_address(self.generation_id, "generation_id")
        object.__setattr__(self, "activated_at", _aware(self.activated_at, "activated_at"))
        for name in ("startup_complete", "doctor_healthy", "event_replay_ok", "safety_violation"):
            if type(getattr(self, name)) is not bool:
                raise RecoveryContractError(f"{name} must be a bool")
        for name in ("last_heartbeat_at", "last_event_progress_at"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _aware(value, name))
        for name in (
            "consecutive_phase_crashes",
            "consecutive_protocol_errors",
            "orphan_sandboxes",
            "orphan_worktrees",
        ):
            _non_negative_int(getattr(self, name), name)


@dataclass(frozen=True, slots=True)
class BrickDecision:
    bricked: bool
    reasons: tuple[BrickKind, ...]
    fence_generation: bool
    automatic_rollback: bool


def detect_brick(
    snapshot: GenerationHealthSnapshot,
    *,
    observed_at: datetime,
    policy: RecoveryPolicy = RecoveryPolicy(),
) -> BrickDecision:
    """Detect hard failure conditions without giving an AI role recovery authority."""
    if not isinstance(snapshot, GenerationHealthSnapshot):
        raise TypeError("snapshot must be a GenerationHealthSnapshot")
    now = _aware(observed_at, "observed_at")
    if now < snapshot.activated_at:
        raise RecoveryContractError("observed_at cannot precede activation")
    reasons: list[BrickKind] = []
    age = (now - snapshot.activated_at).total_seconds()
    if (not snapshot.startup_complete or not snapshot.doctor_healthy) and age > policy.startup_timeout_seconds:
        reasons.append(BrickKind.STARTUP_FAILURE)
    if snapshot.startup_complete:
        if snapshot.last_heartbeat_at is None or (
            now - snapshot.last_heartbeat_at
        ).total_seconds() > policy.heartbeat_timeout_seconds:
            reasons.append(BrickKind.HEARTBEAT_TIMEOUT)
        if snapshot.last_event_progress_at is None or (
            now - snapshot.last_event_progress_at
        ).total_seconds() > policy.event_stall_timeout_seconds:
            reasons.append(BrickKind.EVENT_STALL)
    if snapshot.consecutive_phase_crashes >= policy.crash_loop_threshold:
        reasons.append(BrickKind.CRASH_LOOP)
    if snapshot.consecutive_protocol_errors >= policy.protocol_error_threshold:
        reasons.append(BrickKind.PROTOCOL_FAILURE)
    if not snapshot.event_replay_ok:
        reasons.append(BrickKind.EVENT_REPLAY_FAILURE)
    if snapshot.orphan_sandboxes or snapshot.orphan_worktrees:
        reasons.append(BrickKind.RESOURCE_LEAK)
    if snapshot.safety_violation:
        reasons.append(BrickKind.SAFETY_VIOLATION)
    unique = tuple(dict.fromkeys(reasons))
    return BrickDecision(bool(unique), unique, bool(unique), bool(unique))


@dataclass(frozen=True, slots=True)
class IncidentReport:
    campaign_id: str
    cycle_id: str
    failed_generation_id: str
    last_known_good_generation_id: str
    target_role: Role
    brick_kinds: tuple[BrickKind, ...]
    evidence_refs: tuple[str, ...]
    suspected_cause: str
    falsifier: str
    confidence: float
    incident_id: str = field(init=False)

    def __post_init__(self) -> None:
        _text(self.campaign_id, "campaign_id", maximum=128)
        _text(self.cycle_id, "cycle_id", maximum=128)
        _content_address(self.failed_generation_id, "failed_generation_id")
        _content_address(self.last_known_good_generation_id, "last_known_good_generation_id")
        if self.failed_generation_id == self.last_known_good_generation_id:
            raise RecoveryContractError("failed and last-known-good generations must differ")
        if not isinstance(self.target_role, Role):
            raise RecoveryContractError("target_role must be a Role")
        if not self.brick_kinds or any(not isinstance(kind, BrickKind) for kind in self.brick_kinds):
            raise RecoveryContractError("brick_kinds must be a non-empty tuple")
        if not self.evidence_refs:
            raise RecoveryContractError("evidence_refs must not be empty")
        for index, ref in enumerate(self.evidence_refs):
            _content_address(ref, f"evidence_refs[{index}]")
        _text(self.suspected_cause, "suspected_cause")
        _text(self.falsifier, "falsifier")
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)):
            raise RecoveryContractError("confidence must be numeric")
        confidence = float(self.confidence)
        if not math.isfinite(confidence) or not 0 <= confidence <= 1:
            raise RecoveryContractError("confidence must be in [0, 1]")
        object.__setattr__(self, "confidence", confidence)
        object.__setattr__(self, "incident_id", _content_id("incident-sha256:", self._payload()))

    def _payload(self) -> dict[str, object]:
        return {
            "campaign_id": self.campaign_id,
            "cycle_id": self.cycle_id,
            "failed_generation_id": self.failed_generation_id,
            "last_known_good_generation_id": self.last_known_good_generation_id,
            "target_role": self.target_role.value,
            "brick_kinds": [kind.value for kind in self.brick_kinds],
            "evidence_refs": list(self.evidence_refs),
            "suspected_cause": self.suspected_cause,
            "falsifier": self.falsifier,
            "confidence": self.confidence,
        }


@dataclass(frozen=True, slots=True)
class RepairPlan:
    incident_id: str
    target_role: Role
    disposition: RepairDisposition
    base_generation_id: str
    patch_artifact_id: str | None
    validation_checklist: tuple[str, ...]
    rationale: str
    repair_plan_id: str = field(init=False)

    def __post_init__(self) -> None:
        _content_address(self.incident_id.replace("incident-sha256:", "sha256:", 1), "incident_id")
        if not self.incident_id.startswith("incident-sha256:"):
            raise RecoveryContractError("incident_id must be an incident content address")
        if not isinstance(self.target_role, Role):
            raise RecoveryContractError("target_role must be a Role")
        if not isinstance(self.disposition, RepairDisposition):
            raise RecoveryContractError("disposition must be a RepairDisposition")
        _content_address(self.base_generation_id, "base_generation_id")
        if self.patch_artifact_id is not None:
            _content_address(self.patch_artifact_id, "patch_artifact_id")
        if self.disposition is RepairDisposition.RETRY_AFTER_FIX and self.patch_artifact_id is None:
            raise RecoveryContractError("retry_after_fix requires a patch artifact")
        if self.disposition is not RepairDisposition.RETRY_AFTER_FIX and self.patch_artifact_id is not None:
            raise RecoveryContractError("rollback/quarantine must not carry a patch artifact")
        if not self.validation_checklist or len(self.validation_checklist) > 32:
            raise RecoveryContractError("validation_checklist must contain 1..32 items")
        for index, item in enumerate(self.validation_checklist):
            _text(item, f"validation_checklist[{index}]", maximum=512)
        _text(self.rationale, "rationale")
        object.__setattr__(self, "repair_plan_id", _content_id("repair-plan-sha256:", self._payload()))

    def _payload(self) -> dict[str, object]:
        return {
            "incident_id": self.incident_id,
            "target_role": self.target_role.value,
            "disposition": self.disposition.value,
            "base_generation_id": self.base_generation_id,
            "patch_artifact_id": self.patch_artifact_id,
            "validation_checklist": list(self.validation_checklist),
            "rationale": self.rationale,
        }
