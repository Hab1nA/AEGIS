from __future__ import annotations

import hashlib
import tempfile
import unittest
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from aegis.event_store import EventStore
from aegis.generation_activation import (
    ACTIVATION_COMPLETED,
    ACTIVATION_ROLLED_BACK,
    ACTIVATION_STARTED,
    BOUNDARY_INTENT,
    BOUNDARY_RECEIPT,
    PIPELINE,
    ActivationBlockedError,
    ActivationIntegrityError,
    ActivationRequest,
    ActivationStatus,
    ActiveManifest,
    BoundaryAction,
    BoundaryIntent,
    BoundaryReceipt,
    GenerationActivator,
    health_snapshot_to_mapping,
)
from aegis.models import AuditEvent, thaw_json
from aegis.recovery import BrickKind, GenerationHealthSnapshot

NOW = datetime(2026, 8, 9, 14, 0, tzinfo=timezone.utc)


def address(character: str) -> str:
    return "sha256:" + character * 64


def evidence(intent: BoundaryIntent) -> str:
    return "sha256:" + hashlib.sha256(intent.intent_id.encode("ascii")).hexdigest()


class SimulatedProcessCrash(RuntimeError):
    pass


class FakeSlotBackend:
    def __init__(
        self,
        manifest: ActiveManifest,
        log: list[BoundaryAction],
        *,
        fail_actions: set[BoundaryAction] | None = None,
        crash_after_effect: set[BoundaryAction] | None = None,
    ) -> None:
        self.manifest = manifest
        self.log = log
        self.fail_actions = fail_actions or set()
        self.crash_after_effect = crash_after_effect or set()
        self.receipts: dict[str, BoundaryReceipt] = {}
        self.effects: Counter[BoundaryAction] = Counter()
        self.fenced: set[str] = set()

    def reconcile(self, intent_id: str) -> BoundaryReceipt | None:
        return self.receipts.get(intent_id)

    def perform(self, intent: BoundaryIntent) -> BoundaryReceipt:
        known = self.receipts.get(intent.intent_id)
        if known is not None:
            return known
        self.log.append(intent.action)
        self.effects[intent.action] += 1
        success = intent.action not in self.fail_actions
        data: dict[str, Any] = {}
        if intent.action is BoundaryAction.STAGE:
            if success:
                data = {"staged_bundle_digest": intent.bundle_digest}
        elif intent.action is BoundaryAction.FENCE:
            if success:
                self.fenced.add(intent.slot_id)
                data = {"fenced_slot": intent.slot_id}
        elif intent.action in {BoundaryAction.MANIFEST_CAS, BoundaryAction.ROLLBACK}:
            raw_expected = intent.payload.get("expected_manifest")
            raw_desired = intent.payload.get("desired_manifest")
            if not isinstance(raw_expected, Mapping) or not isinstance(raw_desired, Mapping):
                raise AssertionError("manifest CAS intent omitted manifests")
            expected = ActiveManifest.from_mapping(raw_expected)
            desired = ActiveManifest.from_mapping(raw_desired)
            success = success and self.manifest == expected
            if success:
                self.manifest = desired
                data = {"manifest": desired.to_mapping()}
        else:
            raise AssertionError(f"unexpected backend action {intent.action}")
        receipt = BoundaryReceipt.create(
            intent,
            success=success,
            evidence_digest=evidence(intent),
            data=data,
        )
        self.receipts[intent.intent_id] = receipt
        if intent.action in self.crash_after_effect:
            self.crash_after_effect.remove(intent.action)
            raise SimulatedProcessCrash(intent.action.value)
        return receipt


class FakeHealthProbe:
    def __init__(
        self,
        snapshot: GenerationHealthSnapshot,
        log: list[BoundaryAction],
        *,
        fail_actions: set[BoundaryAction] | None = None,
        crash_after_effect: set[BoundaryAction] | None = None,
    ) -> None:
        self.snapshot = snapshot
        self.log = log
        self.fail_actions = fail_actions or set()
        self.crash_after_effect = crash_after_effect or set()
        self.receipts: dict[str, BoundaryReceipt] = {}
        self.effects: Counter[BoundaryAction] = Counter()

    def reconcile(self, intent_id: str) -> BoundaryReceipt | None:
        return self.receipts.get(intent_id)

    def perform(self, intent: BoundaryIntent) -> BoundaryReceipt:
        known = self.receipts.get(intent.intent_id)
        if known is not None:
            return known
        self.log.append(intent.action)
        self.effects[intent.action] += 1
        success = intent.action not in self.fail_actions
        data: dict[str, Any] = {}
        if intent.action is BoundaryAction.HEALTH_SNAPSHOT:
            data = {"snapshot": health_snapshot_to_mapping(self.snapshot)}
        elif intent.action not in {
            BoundaryAction.EVENT_REPLAY,
            BoundaryAction.DOCTOR,
            BoundaryAction.STARTUP_SMOKE,
            BoundaryAction.SHADOW,
            BoundaryAction.CANARY,
            BoundaryAction.PROBATION,
        }:
            raise AssertionError(f"unexpected probe action {intent.action}")
        receipt = BoundaryReceipt.create(
            intent,
            success=success,
            evidence_digest=evidence(intent),
            data=data,
        )
        self.receipts[intent.intent_id] = receipt
        if intent.action in self.crash_after_effect:
            self.crash_after_effect.remove(intent.action)
            raise SimulatedProcessCrash(intent.action.value)
        return receipt


class CrashAfterPersistStore:
    def __init__(self, delegate: EventStore, action: BoundaryAction) -> None:
        self.delegate = delegate
        self.action = action
        self.crashed = False

    def read(
        self, campaign_id: str, *, after_sequence: int = 0, limit: int | None = None
    ) -> tuple[AuditEvent, ...]:
        return self.delegate.read(campaign_id, after_sequence=after_sequence, limit=limit)

    def append_if_sequence(
        self,
        campaign_id: str,
        expected_sequence: int,
        event_type: str,
        payload: Mapping[str, Any],
        *,
        created_at: datetime | None = None,
    ) -> AuditEvent:
        event = self.delegate.append_if_sequence(
            campaign_id,
            expected_sequence,
            event_type,
            payload,
            created_at=created_at,
        )
        if event_type == BOUNDARY_RECEIPT and not self.crashed:
            raw = payload.get("receipt")
            if isinstance(raw, Mapping) and raw.get("action") == self.action.value:
                self.crashed = True
                raise SimulatedProcessCrash("after receipt persistence")
        return event


class GenerationActivationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.store = EventStore(Path(self.temporary.name) / "activation.sqlite3")
        self.old_manifest = ActiveManifest(7, "blue", address("a"), address("b"))
        self.request = ActivationRequest(address("c"), address("d"), "green", self.old_manifest)
        self.log: list[BoundaryAction] = []
        self.healthy = GenerationHealthSnapshot(
            generation_id=self.request.candidate_generation_id,
            activated_at=NOW - timedelta(minutes=5),
            startup_complete=True,
            doctor_healthy=True,
            last_heartbeat_at=NOW - timedelta(seconds=5),
            last_event_progress_at=NOW - timedelta(seconds=10),
        )
        self.bricked = GenerationHealthSnapshot(
            generation_id=self.request.candidate_generation_id,
            activated_at=NOW - timedelta(minutes=5),
            startup_complete=True,
            doctor_healthy=True,
            last_heartbeat_at=NOW,
            last_event_progress_at=NOW,
            safety_violation=True,
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def activator(
        self, backend: FakeSlotBackend, probe: FakeHealthProbe, *, store: object | None = None
    ) -> GenerationActivator:
        return GenerationActivator(
            self.store if store is None else store,  # type: ignore[arg-type]
            backend,
            probe,
            clock=lambda: NOW,
        )

    def test_successful_ab_activation_orders_all_boundaries_and_binds_manifest(self) -> None:
        backend = FakeSlotBackend(self.old_manifest, self.log)
        probe = FakeHealthProbe(self.healthy, self.log)
        result = self.activator(backend, probe).activate(self.request)

        expected_manifest = ActiveManifest(
            8,
            "green",
            self.request.candidate_generation_id,
            self.request.bundle_digest,
        )
        self.assertEqual(result.status, ActivationStatus.ACTIVATED)
        self.assertEqual(result.active_manifest, expected_manifest)
        self.assertEqual(backend.manifest, expected_manifest)
        self.assertEqual(self.log, list(PIPELINE))
        self.assertFalse(result.fenced_slot)

        events = self.store.read(GenerationActivator.stream_id(self.request.activation_id))
        self.assertEqual(events[0].event_type, ACTIVATION_STARTED)
        self.assertEqual(events[-1].event_type, ACTIVATION_COMPLETED)
        middle = events[1:-1]
        self.assertEqual(len(middle), 2 * len(PIPELINE))
        self.assertTrue(
            all(
                middle[index].event_type == BOUNDARY_INTENT
                and middle[index + 1].event_type == BOUNDARY_RECEIPT
                for index in range(0, len(middle), 2)
            )
        )
        for index in range(0, len(middle), 2):
            intent_wire = thaw_json(middle[index].payload)["intent"]
            receipt_wire = thaw_json(middle[index + 1].payload)["receipt"]
            self.assertTrue(intent_wire["intent_id"].startswith("generation-boundary-intent-sha256:"))
            self.assertTrue(
                receipt_wire["receipt_id"].startswith("generation-boundary-receipt-sha256:")
            )
        tampered_intent = thaw_json(middle[0].payload)["intent"]
        tampered_intent["bundle_digest"] = address("f")
        with self.assertRaisesRegex(ActivationIntegrityError, "content id mismatch"):
            BoundaryIntent.from_mapping(tampered_intent)
        tampered_receipt = thaw_json(middle[1].payload)["receipt"]
        tampered_receipt["success"] = False
        with self.assertRaisesRegex(ActivationIntegrityError, "content id mismatch"):
            BoundaryReceipt.from_mapping(tampered_receipt)
        manifest_receipt_event = next(
            event
            for event in events
            if event.event_type == BOUNDARY_RECEIPT
            and thaw_json(event.payload)["receipt"]["action"]
            == BoundaryAction.MANIFEST_CAS.value
        )
        manifest_wire = thaw_json(manifest_receipt_event.payload)["receipt"]["data"]["manifest"]
        self.assertEqual(manifest_wire["bundle_digest"], self.request.bundle_digest)
        self.assertEqual(manifest_wire["manifest_id"], expected_manifest.manifest_id)

    def test_canary_brick_fences_new_slot_and_rolls_back_last_known_good(self) -> None:
        backend = FakeSlotBackend(self.old_manifest, self.log)
        probe = FakeHealthProbe(
            self.bricked,
            self.log,
            fail_actions={BoundaryAction.CANARY},
        )
        result = self.activator(backend, probe).activate(self.request)

        self.assertEqual(result.status, ActivationStatus.ROLLED_BACK)
        self.assertEqual(result.brick_kinds, (BrickKind.SAFETY_VIOLATION,))
        self.assertIn("green", backend.fenced)
        self.assertEqual(result.active_manifest.slot_id, "blue")
        self.assertEqual(result.active_manifest.generation_id, self.old_manifest.generation_id)
        self.assertEqual(result.active_manifest.bundle_digest, self.old_manifest.bundle_digest)
        self.assertEqual(result.active_manifest.revision, 8)
        self.assertEqual(
            self.log,
            [
                BoundaryAction.STAGE,
                BoundaryAction.EVENT_REPLAY,
                BoundaryAction.DOCTOR,
                BoundaryAction.STARTUP_SMOKE,
                BoundaryAction.SHADOW,
                BoundaryAction.CANARY,
                BoundaryAction.HEALTH_SNAPSHOT,
                BoundaryAction.FENCE,
                BoundaryAction.ROLLBACK,
            ],
        )
        events = self.store.read(GenerationActivator.stream_id(self.request.activation_id))
        self.assertEqual(events[-1].event_type, ACTIVATION_ROLLED_BACK)

    def test_probation_brick_rolls_manifest_back_after_candidate_activation(self) -> None:
        backend = FakeSlotBackend(self.old_manifest, self.log)
        probe = FakeHealthProbe(
            self.bricked,
            self.log,
            fail_actions={BoundaryAction.PROBATION},
        )
        result = self.activator(backend, probe).activate(self.request)

        self.assertEqual(result.status, ActivationStatus.ROLLED_BACK)
        self.assertEqual(result.active_manifest.revision, 9)
        self.assertEqual(result.active_manifest.slot_id, "blue")
        self.assertEqual(backend.effects[BoundaryAction.MANIFEST_CAS], 1)
        self.assertEqual(backend.effects[BoundaryAction.ROLLBACK], 1)

    def test_crash_after_stage_effect_reconciles_without_duplicate_side_effect(self) -> None:
        backend = FakeSlotBackend(
            self.old_manifest,
            self.log,
            crash_after_effect={BoundaryAction.STAGE},
        )
        probe = FakeHealthProbe(self.healthy, self.log)
        with self.assertRaises(SimulatedProcessCrash):
            self.activator(backend, probe).activate(self.request)
        self.assertEqual(backend.effects[BoundaryAction.STAGE], 1)

        result = self.activator(backend, probe).activate(self.request)
        self.assertEqual(result.status, ActivationStatus.ACTIVATED)
        self.assertEqual(backend.effects[BoundaryAction.STAGE], 1)
        self.assertEqual(self.log.count(BoundaryAction.STAGE), 1)

    def test_crash_after_manifest_cas_never_leaves_a_half_activation(self) -> None:
        backend = FakeSlotBackend(
            self.old_manifest,
            self.log,
            crash_after_effect={BoundaryAction.MANIFEST_CAS},
        )
        probe = FakeHealthProbe(self.healthy, self.log)
        with self.assertRaises(SimulatedProcessCrash):
            self.activator(backend, probe).activate(self.request)
        self.assertEqual(backend.manifest.slot_id, "green")
        self.assertEqual(backend.effects[BoundaryAction.MANIFEST_CAS], 1)

        result = self.activator(backend, probe).activate(self.request)
        self.assertEqual(result.status, ActivationStatus.ACTIVATED)
        self.assertEqual(result.active_manifest, backend.manifest)
        self.assertEqual(backend.effects[BoundaryAction.MANIFEST_CAS], 1)
        self.assertEqual(probe.effects[BoundaryAction.PROBATION], 1)

    def test_crash_after_receipt_persistence_replay_skips_boundary(self) -> None:
        backend = FakeSlotBackend(self.old_manifest, self.log)
        probe = FakeHealthProbe(self.healthy, self.log)
        crashing_store = CrashAfterPersistStore(self.store, BoundaryAction.SHADOW)
        with self.assertRaises(SimulatedProcessCrash):
            self.activator(backend, probe, store=crashing_store).activate(self.request)
        self.assertEqual(probe.effects[BoundaryAction.SHADOW], 1)

        result = self.activator(backend, probe).activate(self.request)
        self.assertEqual(result.status, ActivationStatus.ACTIVATED)
        self.assertEqual(probe.effects[BoundaryAction.SHADOW], 1)

    def test_completed_replay_has_no_repeated_external_effects(self) -> None:
        backend = FakeSlotBackend(self.old_manifest, self.log)
        probe = FakeHealthProbe(self.healthy, self.log)
        activator = self.activator(backend, probe)
        first = activator.activate(self.request)
        counts = (backend.effects.copy(), probe.effects.copy(), tuple(self.log))
        second = activator.activate(self.request)

        self.assertEqual(second, first)
        self.assertEqual((backend.effects, probe.effects, tuple(self.log)), counts)

    def test_non_brick_failure_is_blocked_without_fence_or_rollback(self) -> None:
        backend = FakeSlotBackend(self.old_manifest, self.log)
        probe = FakeHealthProbe(
            self.healthy,
            self.log,
            fail_actions={BoundaryAction.DOCTOR},
        )
        with self.assertRaisesRegex(ActivationBlockedError, "without recovery.detect_brick"):
            self.activator(backend, probe).activate(self.request)
        self.assertEqual(backend.fenced, set())
        self.assertEqual(backend.effects[BoundaryAction.ROLLBACK], 0)
        self.assertEqual(backend.manifest, self.old_manifest)

    def test_manifest_cas_drift_fails_closed_and_cannot_overwrite_unknown_active(self) -> None:
        backend = FakeSlotBackend(self.old_manifest, self.log)
        probe = FakeHealthProbe(self.bricked, self.log)
        drift = ActiveManifest(8, "operator", address("e"), address("f"))
        backend.manifest = drift
        with self.assertRaisesRegex(ActivationBlockedError, "rollback failed closed"):
            self.activator(backend, probe).activate(self.request)
        self.assertEqual(backend.manifest, drift)
        self.assertIn("green", backend.fenced)

    def test_unknown_or_tampered_replay_event_is_rejected(self) -> None:
        stream = GenerationActivator.stream_id(self.request.activation_id)
        self.store.append(stream, "unknown_activation_event", {})
        backend = FakeSlotBackend(self.old_manifest, self.log)
        probe = FakeHealthProbe(self.healthy, self.log)
        with self.assertRaisesRegex(ActivationIntegrityError, "unknown activation event"):
            self.activator(backend, probe).activate(self.request)


if __name__ == "__main__":
    unittest.main()
