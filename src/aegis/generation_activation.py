"""Replay-safe A/B generation activation with fail-closed automatic rollback."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Callable, Mapping, Protocol

from aegis.models import AuditEvent, canonical_json, freeze_json, thaw_json
from aegis.recovery import (
    BrickKind,
    GenerationHealthSnapshot,
    RecoveryPolicy,
    detect_brick,
)

_CONTENT_ADDRESS = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CONTENT_ID = re.compile(r"[a-z][a-z0-9-]*-sha256:[0-9a-f]{64}\Z")

ACTIVATION_STARTED = "generation_activation_started_v1"
BOUNDARY_INTENT = "generation_activation_boundary_intent_v1"
BOUNDARY_RECEIPT = "generation_activation_boundary_receipt_v1"
ACTIVATION_COMPLETED = "generation_activation_completed_v1"
ACTIVATION_ROLLED_BACK = "generation_activation_rolled_back_v1"


class GenerationActivationError(RuntimeError):
    """Base error for activation policy, replay, or external-boundary failure."""


class ActivationIntegrityError(GenerationActivationError):
    """Persisted events or external receipts failed integrity checks."""


class ActivationBlockedError(GenerationActivationError):
    """An activation failed closed without sufficient brick evidence to roll back."""


def _text(value: object, name: str, *, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or value.strip() != value or len(value) > maximum:
        raise ValueError(f"{name} must be bounded, non-empty, trimmed text")
    return value


def _address(value: object, name: str) -> str:
    if not isinstance(value, str) or _CONTENT_ADDRESS.fullmatch(value) is None:
        raise ValueError(f"{name} must be a sha256 content address")
    return value


def _digest_id(prefix: str, payload: Mapping[str, Any]) -> str:
    return prefix + hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _json_mapping(value: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    try:
        frozen = freeze_json(value, path=name)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must contain strict JSON") from exc
    if not isinstance(frozen, Mapping):
        raise TypeError(f"{name} must be a mapping")
    return frozen


@dataclass(frozen=True, slots=True)
class ActiveManifest:
    revision: int
    slot_id: str
    generation_id: str
    bundle_digest: str
    manifest_id: str = field(init=False)

    def __post_init__(self) -> None:
        if isinstance(self.revision, bool) or not isinstance(self.revision, int) or self.revision < 0:
            raise ValueError("manifest revision must be a non-negative integer")
        _text(self.slot_id, "slot_id", maximum=64)
        _address(self.generation_id, "generation_id")
        _address(self.bundle_digest, "bundle_digest")
        object.__setattr__(
            self,
            "manifest_id",
            _digest_id("active-manifest-sha256:", self.to_mapping(include_id=False)),
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ActiveManifest:
        expected = {"manifest_id", "revision", "slot_id", "generation_id", "bundle_digest"}
        if set(value) != expected:
            raise ActivationIntegrityError("active manifest has missing or unknown fields")
        result = cls(value["revision"], value["slot_id"], value["generation_id"], value["bundle_digest"])
        if result.manifest_id != value["manifest_id"]:
            raise ActivationIntegrityError("active manifest content id mismatch")
        return result

    def to_mapping(self, *, include_id: bool = True) -> dict[str, Any]:
        payload = {
            "revision": self.revision,
            "slot_id": self.slot_id,
            "generation_id": self.generation_id,
            "bundle_digest": self.bundle_digest,
        }
        return {"manifest_id": self.manifest_id, **payload} if include_id else payload


@dataclass(frozen=True, slots=True)
class ActivationRequest:
    candidate_generation_id: str
    bundle_digest: str
    target_slot: str
    expected_manifest: ActiveManifest
    activation_id: str = field(init=False)

    def __post_init__(self) -> None:
        _address(self.candidate_generation_id, "candidate_generation_id")
        _address(self.bundle_digest, "bundle_digest")
        _text(self.target_slot, "target_slot", maximum=64)
        if self.target_slot == self.expected_manifest.slot_id:
            raise ValueError("target_slot must differ from the active slot")
        object.__setattr__(
            self,
            "activation_id",
            _digest_id("generation-activation-sha256:", self.to_mapping(include_id=False)),
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ActivationRequest:
        expected = {
            "activation_id",
            "candidate_generation_id",
            "bundle_digest",
            "target_slot",
            "expected_manifest",
        }
        if set(value) != expected or not isinstance(value["expected_manifest"], Mapping):
            raise ActivationIntegrityError("activation request has missing or invalid fields")
        result = cls(
            value["candidate_generation_id"],
            value["bundle_digest"],
            value["target_slot"],
            ActiveManifest.from_mapping(value["expected_manifest"]),
        )
        if result.activation_id != value["activation_id"]:
            raise ActivationIntegrityError("activation request content id mismatch")
        return result

    def to_mapping(self, *, include_id: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "candidate_generation_id": self.candidate_generation_id,
            "bundle_digest": self.bundle_digest,
            "target_slot": self.target_slot,
            "expected_manifest": self.expected_manifest.to_mapping(),
        }
        return {"activation_id": self.activation_id, **payload} if include_id else payload


class BoundaryAction(StrEnum):
    STAGE = "stage"
    EVENT_REPLAY = "event-replay"
    DOCTOR = "doctor"
    STARTUP_SMOKE = "startup-smoke"
    SHADOW = "shadow"
    CANARY = "canary"
    MANIFEST_CAS = "active-manifest-cas"
    PROBATION = "probation"
    HEALTH_SNAPSHOT = "health-snapshot"
    FENCE = "fence"
    ROLLBACK = "rollback"


PIPELINE = (
    BoundaryAction.STAGE,
    BoundaryAction.EVENT_REPLAY,
    BoundaryAction.DOCTOR,
    BoundaryAction.STARTUP_SMOKE,
    BoundaryAction.SHADOW,
    BoundaryAction.CANARY,
    BoundaryAction.MANIFEST_CAS,
    BoundaryAction.PROBATION,
)
_BACKEND_ACTIONS = {
    BoundaryAction.STAGE,
    BoundaryAction.MANIFEST_CAS,
    BoundaryAction.FENCE,
    BoundaryAction.ROLLBACK,
}


@dataclass(frozen=True, slots=True)
class BoundaryIntent:
    activation_id: str
    action: BoundaryAction
    slot_id: str
    bundle_digest: str
    payload: Mapping[str, Any]
    intent_id: str = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.activation_id, str) or not self.activation_id.startswith(
            "generation-activation-sha256:"
        ) or _CONTENT_ID.fullmatch(self.activation_id) is None:
            raise ValueError("activation_id must be a generation activation content id")
        _text(self.slot_id, "slot_id", maximum=64)
        _address(self.bundle_digest, "bundle_digest")
        object.__setattr__(self, "payload", _json_mapping(self.payload, "boundary payload"))
        object.__setattr__(
            self,
            "intent_id",
            _digest_id("generation-boundary-intent-sha256:", self.to_mapping(include_id=False)),
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> BoundaryIntent:
        expected = {"intent_id", "activation_id", "action", "slot_id", "bundle_digest", "payload"}
        if set(value) != expected or not isinstance(value["payload"], Mapping):
            raise ActivationIntegrityError("boundary intent has missing or invalid fields")
        result = cls(
            value["activation_id"],
            BoundaryAction(value["action"]),
            value["slot_id"],
            value["bundle_digest"],
            value["payload"],
        )
        if result.intent_id != value["intent_id"]:
            raise ActivationIntegrityError("boundary intent content id mismatch")
        return result

    def to_mapping(self, *, include_id: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "activation_id": self.activation_id,
            "action": self.action.value,
            "slot_id": self.slot_id,
            "bundle_digest": self.bundle_digest,
            "payload": thaw_json(self.payload),
        }
        return {"intent_id": self.intent_id, **payload} if include_id else payload


@dataclass(frozen=True, slots=True)
class BoundaryReceipt:
    intent_id: str
    action: BoundaryAction
    success: bool
    evidence_digest: str
    data: Mapping[str, Any]
    receipt_id: str = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.intent_id, str) or not self.intent_id.startswith(
            "generation-boundary-intent-sha256:"
        ) or _CONTENT_ID.fullmatch(self.intent_id) is None:
            raise ValueError("intent_id must be a boundary intent content id")
        if not isinstance(self.success, bool):
            raise TypeError("receipt success must be a bool")
        _address(self.evidence_digest, "evidence_digest")
        object.__setattr__(self, "data", _json_mapping(self.data, "receipt data"))
        object.__setattr__(
            self,
            "receipt_id",
            _digest_id("generation-boundary-receipt-sha256:", self.to_mapping(include_id=False)),
        )

    @classmethod
    def create(
        cls,
        intent: BoundaryIntent,
        *,
        success: bool,
        evidence_digest: str,
        data: Mapping[str, Any] | None = None,
    ) -> BoundaryReceipt:
        return cls(intent.intent_id, intent.action, success, evidence_digest, data or {})

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> BoundaryReceipt:
        expected = {"receipt_id", "intent_id", "action", "success", "evidence_digest", "data"}
        if set(value) != expected or not isinstance(value["data"], Mapping):
            raise ActivationIntegrityError("boundary receipt has missing or invalid fields")
        result = cls(
            value["intent_id"],
            BoundaryAction(value["action"]),
            value["success"],
            value["evidence_digest"],
            value["data"],
        )
        if result.receipt_id != value["receipt_id"]:
            raise ActivationIntegrityError("boundary receipt content id mismatch")
        return result

    def to_mapping(self, *, include_id: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "intent_id": self.intent_id,
            "action": self.action.value,
            "success": self.success,
            "evidence_digest": self.evidence_digest,
            "data": thaw_json(self.data),
        }
        return {"receipt_id": self.receipt_id, **payload} if include_id else payload


class SlotBackend(Protocol):
    def perform(self, intent: BoundaryIntent) -> BoundaryReceipt: ...

    def reconcile(self, intent_id: str) -> BoundaryReceipt | None: ...


class HealthProbe(Protocol):
    def perform(self, intent: BoundaryIntent) -> BoundaryReceipt: ...

    def reconcile(self, intent_id: str) -> BoundaryReceipt | None: ...


class ActivationEventStore(Protocol):
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


class ActivationStatus(StrEnum):
    NEW = "new"
    RUNNING = "running"
    PROBATION = "probation"
    ACTIVATED = "activated"
    ROLLED_BACK = "rolled-back"


@dataclass(frozen=True, slots=True)
class ActivationResult:
    activation_id: str
    status: ActivationStatus
    active_manifest: ActiveManifest
    completed_actions: tuple[BoundaryAction, ...]
    fenced_slot: bool
    brick_kinds: tuple[BrickKind, ...] = ()


@dataclass(slots=True)
class _Projection:
    request: ActivationRequest | None = None
    sequence: int = 0
    intents: dict[BoundaryAction, BoundaryIntent] = field(default_factory=dict)
    receipts: dict[BoundaryAction, BoundaryReceipt] = field(default_factory=dict)
    completed: bool = False
    rolled_back: bool = False
    brick_kinds: tuple[BrickKind, ...] = ()


def health_snapshot_to_mapping(snapshot: GenerationHealthSnapshot) -> dict[str, Any]:
    return {
        "generation_id": snapshot.generation_id,
        "activated_at": snapshot.activated_at.isoformat(),
        "startup_complete": snapshot.startup_complete,
        "doctor_healthy": snapshot.doctor_healthy,
        "last_heartbeat_at": (
            None if snapshot.last_heartbeat_at is None else snapshot.last_heartbeat_at.isoformat()
        ),
        "last_event_progress_at": (
            None
            if snapshot.last_event_progress_at is None
            else snapshot.last_event_progress_at.isoformat()
        ),
        "consecutive_phase_crashes": snapshot.consecutive_phase_crashes,
        "consecutive_protocol_errors": snapshot.consecutive_protocol_errors,
        "orphan_sandboxes": snapshot.orphan_sandboxes,
        "orphan_worktrees": snapshot.orphan_worktrees,
        "event_replay_ok": snapshot.event_replay_ok,
        "safety_violation": snapshot.safety_violation,
    }


def health_snapshot_from_mapping(value: Mapping[str, Any]) -> GenerationHealthSnapshot:
    expected = {
        "generation_id",
        "activated_at",
        "startup_complete",
        "doctor_healthy",
        "last_heartbeat_at",
        "last_event_progress_at",
        "consecutive_phase_crashes",
        "consecutive_protocol_errors",
        "orphan_sandboxes",
        "orphan_worktrees",
        "event_replay_ok",
        "safety_violation",
    }
    if set(value) != expected:
        raise ActivationIntegrityError("health snapshot has missing or unknown fields")

    def moment(name: str) -> datetime | None:
        raw = value[name]
        if raw is None:
            return None
        if not isinstance(raw, str):
            raise ActivationIntegrityError(f"health snapshot {name} must be an ISO timestamp")
        try:
            return datetime.fromisoformat(raw)
        except ValueError as exc:
            raise ActivationIntegrityError(f"health snapshot {name} is invalid") from exc

    activated = moment("activated_at")
    if activated is None:
        raise ActivationIntegrityError("health snapshot activated_at cannot be null")
    try:
        return GenerationHealthSnapshot(
            generation_id=value["generation_id"],
            activated_at=activated,
            startup_complete=value["startup_complete"],
            doctor_healthy=value["doctor_healthy"],
            last_heartbeat_at=moment("last_heartbeat_at"),
            last_event_progress_at=moment("last_event_progress_at"),
            consecutive_phase_crashes=value["consecutive_phase_crashes"],
            consecutive_protocol_errors=value["consecutive_protocol_errors"],
            orphan_sandboxes=value["orphan_sandboxes"],
            orphan_worktrees=value["orphan_worktrees"],
            event_replay_ok=value["event_replay_ok"],
            safety_violation=value["safety_violation"],
        )
    except (TypeError, ValueError) as exc:
        raise ActivationIntegrityError("health snapshot violates the recovery contract") from exc


class GenerationActivator:
    def __init__(
        self,
        event_store: ActivationEventStore,
        slot_backend: SlotBackend,
        health_probe: HealthProbe,
        *,
        clock: Callable[[], datetime] | None = None,
        recovery_policy: RecoveryPolicy = RecoveryPolicy(),
    ) -> None:
        self._store = event_store
        self._backend = slot_backend
        self._probe = health_probe
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._recovery_policy = recovery_policy

    @staticmethod
    def stream_id(activation_id: str) -> str:
        return f"activation:{activation_id}"

    def activate(self, request: ActivationRequest) -> ActivationResult:
        stream = self.stream_id(request.activation_id)
        projection = self._replay(stream)
        if projection.request is None:
            event = self._store.append_if_sequence(
                stream,
                0,
                ACTIVATION_STARTED,
                {"request": request.to_mapping()},
            )
            projection.request = request
            projection.sequence = event.sequence
        elif projection.request != request:
            raise ActivationIntegrityError("activation stream is bound to another request")
        if projection.completed or projection.rolled_back:
            return self._result(projection)

        for action in PIPELINE:
            receipt = self._boundary(projection, action)
            if not receipt.success:
                return self._recover(projection, action)
        self._append(projection, ACTIVATION_COMPLETED, {"activation_id": request.activation_id})
        projection.completed = True
        return self._result(projection)

    def _boundary(self, projection: _Projection, action: BoundaryAction) -> BoundaryReceipt:
        existing = projection.receipts.get(action)
        if existing is not None:
            return existing
        intent = projection.intents.get(action)
        if intent is None:
            intent = self._intent(projection, action)
            self._append(projection, BOUNDARY_INTENT, {"intent": intent.to_mapping()})
            projection.intents[action] = intent
        executor: SlotBackend | HealthProbe = (
            self._backend if action in _BACKEND_ACTIONS else self._probe
        )
        receipt = executor.reconcile(intent.intent_id)
        if receipt is None:
            receipt = executor.perform(intent)
        self._validate_receipt(intent, receipt)
        self._append(projection, BOUNDARY_RECEIPT, {"receipt": receipt.to_mapping()})
        projection.receipts[action] = receipt
        return receipt

    def _intent(self, projection: _Projection, action: BoundaryAction) -> BoundaryIntent:
        request = self._request(projection)
        payload: dict[str, Any] = {}
        slot = request.target_slot
        digest = request.bundle_digest
        if action is BoundaryAction.STAGE:
            payload = {"generation_id": request.candidate_generation_id}
        elif action is BoundaryAction.MANIFEST_CAS:
            desired = self._candidate_manifest(request)
            payload = {
                "expected_manifest": request.expected_manifest.to_mapping(),
                "desired_manifest": desired.to_mapping(),
            }
        elif action is BoundaryAction.HEALTH_SNAPSHOT:
            failed = next(
                (
                    item.action.value
                    for item in projection.receipts.values()
                    if not item.success and item.action in PIPELINE
                ),
                "unknown",
            )
            payload = {"failed_action": failed}
        elif action is BoundaryAction.FENCE:
            payload = {"reason": "detect_brick"}
        elif action is BoundaryAction.ROLLBACK:
            current = (
                self._candidate_manifest(request)
                if BoundaryAction.MANIFEST_CAS in projection.receipts
                and projection.receipts[BoundaryAction.MANIFEST_CAS].success
                else request.expected_manifest
            )
            desired = ActiveManifest(
                current.revision + 1,
                request.expected_manifest.slot_id,
                request.expected_manifest.generation_id,
                request.expected_manifest.bundle_digest,
            )
            payload = {
                "expected_manifest": current.to_mapping(),
                "desired_manifest": desired.to_mapping(),
            }
            slot = request.expected_manifest.slot_id
            digest = request.expected_manifest.bundle_digest
        return BoundaryIntent(request.activation_id, action, slot, digest, payload)

    def _recover(self, projection: _Projection, failed_action: BoundaryAction) -> ActivationResult:
        snapshot_receipt = self._boundary(projection, BoundaryAction.HEALTH_SNAPSHOT)
        if not snapshot_receipt.success:
            raise ActivationBlockedError("health snapshot boundary failed closed")
        raw_snapshot = snapshot_receipt.data.get("snapshot")
        if not isinstance(raw_snapshot, Mapping):
            raise ActivationIntegrityError("health snapshot receipt omitted snapshot evidence")
        snapshot = health_snapshot_from_mapping(raw_snapshot)
        request = self._request(projection)
        if snapshot.generation_id != request.candidate_generation_id:
            raise ActivationIntegrityError("health snapshot is bound to another generation")
        observed = self._clock()
        decision = detect_brick(snapshot, observed_at=observed, policy=self._recovery_policy)
        if not decision.bricked or not decision.fence_generation or not decision.automatic_rollback:
            raise ActivationBlockedError(
                f"{failed_action.value} failed without recovery.detect_brick rollback evidence"
            )
        fence = self._boundary(projection, BoundaryAction.FENCE)
        if not fence.success:
            raise ActivationBlockedError("candidate slot fencing failed closed")
        rollback = self._boundary(projection, BoundaryAction.ROLLBACK)
        if not rollback.success:
            raise ActivationBlockedError("last-known-good rollback failed closed")
        kinds = tuple(decision.reasons)
        self._append(
            projection,
            ACTIVATION_ROLLED_BACK,
            {
                "activation_id": request.activation_id,
                "failed_action": failed_action.value,
                "brick_kinds": [item.value for item in kinds],
            },
        )
        projection.rolled_back = True
        projection.brick_kinds = kinds
        return self._result(projection)

    @staticmethod
    def _validate_receipt(intent: BoundaryIntent, receipt: BoundaryReceipt) -> None:
        if not isinstance(receipt, BoundaryReceipt):
            raise ActivationIntegrityError("external boundary returned an invalid receipt type")
        if receipt.intent_id != intent.intent_id or receipt.action is not intent.action:
            raise ActivationIntegrityError("external receipt is bound to another intent")
        if intent.action in {BoundaryAction.MANIFEST_CAS, BoundaryAction.ROLLBACK} and receipt.success:
            desired = intent.payload.get("desired_manifest")
            actual = receipt.data.get("manifest")
            if thaw_json(desired) != thaw_json(actual):
                raise ActivationIntegrityError("manifest CAS receipt does not bind the desired manifest")

    def _append(
        self, projection: _Projection, event_type: str, payload: Mapping[str, Any]
    ) -> None:
        request = self._request(projection)
        event = self._store.append_if_sequence(
            self.stream_id(request.activation_id),
            projection.sequence,
            event_type,
            payload,
        )
        projection.sequence = event.sequence

    def _replay(self, stream: str) -> _Projection:
        projection = _Projection()
        events = self._store.read(stream)
        for event in events:
            if event.sequence != projection.sequence + 1:
                raise ActivationIntegrityError("activation event sequence is not contiguous")
            projection.sequence = event.sequence
            payload = thaw_json(event.payload)
            if not isinstance(payload, Mapping):
                raise ActivationIntegrityError("activation event payload must be an object")
            if event.event_type == ACTIVATION_STARTED:
                if projection.request is not None or set(payload) != {"request"}:
                    raise ActivationIntegrityError("activation start event is duplicated or malformed")
                raw = payload["request"]
                if not isinstance(raw, Mapping):
                    raise ActivationIntegrityError("activation start request must be an object")
                projection.request = ActivationRequest.from_mapping(raw)
            elif event.event_type == BOUNDARY_INTENT:
                self._require_started(projection)
                raw = payload.get("intent")
                if set(payload) != {"intent"} or not isinstance(raw, Mapping):
                    raise ActivationIntegrityError("boundary intent event is malformed")
                intent = BoundaryIntent.from_mapping(raw)
                if intent.activation_id != self._request(projection).activation_id:
                    raise ActivationIntegrityError("boundary intent belongs to another activation")
                if intent.action in projection.intents:
                    raise ActivationIntegrityError("boundary action has duplicate intents")
                self._validate_action_order(projection, intent.action)
                projection.intents[intent.action] = intent
            elif event.event_type == BOUNDARY_RECEIPT:
                self._require_started(projection)
                raw = payload.get("receipt")
                if set(payload) != {"receipt"} or not isinstance(raw, Mapping):
                    raise ActivationIntegrityError("boundary receipt event is malformed")
                receipt = BoundaryReceipt.from_mapping(raw)
                receipt_intent = projection.intents.get(receipt.action)
                if receipt_intent is None or receipt.action in projection.receipts:
                    raise ActivationIntegrityError("boundary receipt lacks one unique preceding intent")
                self._validate_receipt(receipt_intent, receipt)
                projection.receipts[receipt.action] = receipt
            elif event.event_type == ACTIVATION_COMPLETED:
                self._require_started(projection)
                if projection.completed or projection.rolled_back or set(payload) != {"activation_id"}:
                    raise ActivationIntegrityError("activation completion event is malformed")
                if payload["activation_id"] != self._request(projection).activation_id or any(
                    action not in projection.receipts or not projection.receipts[action].success
                    for action in PIPELINE
                ):
                    raise ActivationIntegrityError("activation completed without all successful receipts")
                projection.completed = True
            elif event.event_type == ACTIVATION_ROLLED_BACK:
                self._require_started(projection)
                expected = {"activation_id", "failed_action", "brick_kinds"}
                raw_kinds = payload.get("brick_kinds")
                if (
                    projection.completed
                    or projection.rolled_back
                    or set(payload) != expected
                    or payload["activation_id"] != self._request(projection).activation_id
                    or not isinstance(raw_kinds, list)
                    or BoundaryAction.FENCE not in projection.receipts
                    or BoundaryAction.ROLLBACK not in projection.receipts
                ):
                    raise ActivationIntegrityError("activation rollback event is malformed")
                try:
                    projection.brick_kinds = tuple(BrickKind(item) for item in raw_kinds)
                except ValueError as exc:
                    raise ActivationIntegrityError("rollback event contains an invalid brick kind") from exc
                projection.rolled_back = True
            else:
                raise ActivationIntegrityError(f"unknown activation event type: {event.event_type}")
            if (projection.completed or projection.rolled_back) and event.sequence != events[-1].sequence:
                raise ActivationIntegrityError("activation stream contains events after terminal state")
        return projection

    @staticmethod
    def _validate_action_order(projection: _Projection, action: BoundaryAction) -> None:
        if action in PIPELINE:
            index = PIPELINE.index(action)
            if any(previous not in projection.receipts for previous in PIPELINE[:index]):
                raise ActivationIntegrityError("activation boundary intent is out of order")
            if any(
                not projection.receipts[previous].success for previous in PIPELINE[:index]
            ):
                raise ActivationIntegrityError("activation continued after a failed boundary")
        elif action is BoundaryAction.HEALTH_SNAPSHOT:
            if not any(not receipt.success for receipt in projection.receipts.values()):
                raise ActivationIntegrityError("health snapshot requires a failed activation boundary")
        elif action is BoundaryAction.FENCE:
            if BoundaryAction.HEALTH_SNAPSHOT not in projection.receipts:
                raise ActivationIntegrityError("fence requires health snapshot evidence")
        elif action is BoundaryAction.ROLLBACK:
            if BoundaryAction.FENCE not in projection.receipts:
                raise ActivationIntegrityError("rollback requires a fenced candidate slot")

    @staticmethod
    def _require_started(projection: _Projection) -> None:
        if projection.request is None:
            raise ActivationIntegrityError("activation boundary event precedes start")

    @staticmethod
    def _request(projection: _Projection) -> ActivationRequest:
        if projection.request is None:
            raise ActivationIntegrityError("activation request is not initialized")
        return projection.request

    @staticmethod
    def _candidate_manifest(request: ActivationRequest) -> ActiveManifest:
        return ActiveManifest(
            request.expected_manifest.revision + 1,
            request.target_slot,
            request.candidate_generation_id,
            request.bundle_digest,
        )

    def _result(self, projection: _Projection) -> ActivationResult:
        request = self._request(projection)
        if projection.rolled_back:
            rollback = projection.receipts.get(BoundaryAction.ROLLBACK)
            raw = None if rollback is None else rollback.data.get("manifest")
            if not isinstance(raw, Mapping):
                raise ActivationIntegrityError("rollback result lacks an active manifest")
            manifest = ActiveManifest.from_mapping(raw)
            status = ActivationStatus.ROLLED_BACK
        elif BoundaryAction.MANIFEST_CAS in projection.receipts:
            receipt = projection.receipts[BoundaryAction.MANIFEST_CAS]
            raw = receipt.data.get("manifest")
            if not isinstance(raw, Mapping):
                raise ActivationIntegrityError("activation result lacks an active manifest")
            manifest = ActiveManifest.from_mapping(raw)
            status = ActivationStatus.ACTIVATED if projection.completed else ActivationStatus.PROBATION
        else:
            manifest = request.expected_manifest
            status = ActivationStatus.RUNNING if projection.request is not None else ActivationStatus.NEW
        return ActivationResult(
            request.activation_id,
            status,
            manifest,
            tuple(action for action in BoundaryAction if action in projection.receipts),
            BoundaryAction.FENCE in projection.receipts and projection.receipts[BoundaryAction.FENCE].success,
            projection.brick_kinds,
        )


__all__ = [
    "ACTIVATION_COMPLETED",
    "ACTIVATION_ROLLED_BACK",
    "ACTIVATION_STARTED",
    "BOUNDARY_INTENT",
    "BOUNDARY_RECEIPT",
    "PIPELINE",
    "ActivationBlockedError",
    "ActivationIntegrityError",
    "ActivationRequest",
    "ActivationResult",
    "ActivationStatus",
    "ActiveManifest",
    "BoundaryAction",
    "BoundaryIntent",
    "BoundaryReceipt",
    "GenerationActivationError",
    "GenerationActivator",
    "HealthProbe",
    "SlotBackend",
    "health_snapshot_from_mapping",
    "health_snapshot_to_mapping",
]
