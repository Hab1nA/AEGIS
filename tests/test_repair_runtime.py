from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any, Mapping

from aegis.event_store import EventStore
from aegis.generation_activation import (
    ActivationRequest,
    ActivationResult,
    ActivationStatus,
    ActiveManifest,
    BoundaryAction,
)
from aegis.models import AuditEvent, Role, thaw_json
from aegis.publishing import (
    GitCheckpointRequest,
    GitFileChange,
    PublicationResult,
    PublishIntent,
    PublishOperation,
    PublishReceipt,
)
from aegis.recovery import (
    BrickKind,
    IncidentReport,
    RepairDisposition,
    RepairPlan,
)
from aegis.repair_runtime import (
    REPAIR_STARTED,
    REPAIR_STEP_INTENT,
    REPAIR_STEP_RECEIPT,
    REPAIR_TERMINAL,
    CandidateValidation,
    PatchArtifact,
    RecoveryCandidate,
    RecoverySupervisor,
    RepairRuntimeIntegrityError,
    RepairStatus,
    RepairStep,
    RepairStepIntent,
)


def address(character: str) -> str:
    return "sha256:" + character * 64


class SimulatedCrash(RuntimeError):
    pass


class FakeProsecutor:
    def __init__(self, patch: PatchArtifact) -> None:
        self.patch = patch
        self.results: dict[str, PatchArtifact] = {}
        self.calls = 0
        self.crash_once = False
        self.received: list[tuple[RepairStepIntent, IncidentReport, RepairPlan]] = []

    def reconcile(self, intent_id: str) -> PatchArtifact | None:
        return self.results.get(intent_id)

    def generate_patch(
        self, intent: RepairStepIntent, incident: IncidentReport, plan: RepairPlan
    ) -> PatchArtifact:
        self.calls += 1
        self.received.append((intent, incident, plan))
        self.results[intent.intent_id] = self.patch
        if self.crash_once:
            self.crash_once = False
            raise SimulatedCrash("prosecutor after artifact")
        return self.patch


class FakeWorkspace:
    def __init__(self, manifest: ActiveManifest) -> None:
        self.manifest = manifest
        self.results: dict[str, RecoveryCandidate] = {}
        self.calls = 0
        self.candidate_generation = address("9")
        self.bundle_digest = address("8")
        self.smuggle_change = False

    def reconcile(self, intent_id: str) -> RecoveryCandidate | None:
        return self.results.get(intent_id)

    def create_candidate(
        self,
        intent: RepairStepIntent,
        incident: IncidentReport,
        plan: RepairPlan,
        patch: PatchArtifact,
    ) -> RecoveryCandidate:
        del plan
        self.calls += 1
        changes = patch.changes
        if self.smuggle_change:
            changes = tuple(
                sorted(
                    (*changes, GitFileChange("roles/warrior/unapproved.py", b"UNAPPROVED = True\n")),
                    key=lambda item: item.path,
                )
            )
        checkpoint = GitCheckpointRequest.create(
            role=incident.target_role.value,
            generation_id="recovery-1",
            base_commit="a" * 40,
            changes=changes,
            message="repair: isolated recovery candidate",
        )
        activation = ActivationRequest(
            self.candidate_generation,
            self.bundle_digest,
            "green",
            self.manifest,
        )
        result = RecoveryCandidate(
            patch.artifact_id,
            incident.last_known_good_generation_id,
            checkpoint,
            activation,
        )
        self.results[intent.intent_id] = result
        return result


class FakePublisher:
    def __init__(self) -> None:
        self.results: dict[str, PublicationResult] = {}
        self.calls = 0
        self.crash_once = False

    def reconcile(self, intent_id: str) -> PublicationResult | None:
        return self.results.get(intent_id)

    def publish_candidate(
        self, intent: RepairStepIntent, checkpoint: GitCheckpointRequest
    ) -> PublicationResult:
        self.calls += 1
        publish_intent = PublishIntent.create(
            operation=PublishOperation.CANDIDATE,
            request_id=checkpoint.request_id,
            remote_id="fake-public-origin",
            ref=f"refs/heads/candidate/{checkpoint.role}/{checkpoint.generation_id}",
            expected_old_commit=None,
            new_commit="e" * 40,
        )
        result = PublicationResult(publish_intent, PublishReceipt.create(publish_intent))
        self.results[intent.intent_id] = result
        if self.crash_once:
            self.crash_once = False
            raise SimulatedCrash("publisher after remote effect")
        return result


class FakeValidator:
    def __init__(self, *, qualified: bool = True, safety_passed: bool = True) -> None:
        self.qualified = qualified
        self.safety_passed = safety_passed
        self.results: dict[str, CandidateValidation] = {}
        self.calls = 0

    def reconcile(self, intent_id: str) -> CandidateValidation | None:
        return self.results.get(intent_id)

    def validate(
        self,
        intent: RepairStepIntent,
        candidate: RecoveryCandidate,
        publication: Any,
    ) -> CandidateValidation:
        self.calls += 1
        result = CandidateValidation(
            candidate.candidate_id,
            publication.published_id,
            self.qualified,
            self.safety_passed,
            address("6"),
            address("7"),
        )
        self.results[intent.intent_id] = result
        return result


class FakeActivator:
    def __init__(self) -> None:
        self.results: dict[str, ActivationResult] = {}
        self.effects = 0
        self.crash_once = False

    def activate(self, request: ActivationRequest) -> ActivationResult:
        known = self.results.get(request.activation_id)
        if known is not None:
            return known
        self.effects += 1
        manifest = ActiveManifest(
            request.expected_manifest.revision + 1,
            request.target_slot,
            request.candidate_generation_id,
            request.bundle_digest,
        )
        result = ActivationResult(
            request.activation_id,
            ActivationStatus.ACTIVATED,
            manifest,
            tuple(BoundaryAction),
            False,
        )
        self.results[request.activation_id] = result
        if self.crash_once:
            self.crash_once = False
            raise SimulatedCrash("activator after manifest effect")
        return result


class FakeControl:
    def __init__(self) -> None:
        self.results: dict[str, Mapping[str, Any]] = {}
        self.calls: list[RepairStep] = []

    def reconcile(self, intent_id: str) -> Mapping[str, Any] | None:
        return self.results.get(intent_id)

    def execute(
        self, intent: RepairStepIntent, incident: IncidentReport, plan: RepairPlan
    ) -> Mapping[str, Any]:
        del incident, plan
        self.calls.append(intent.action)
        result = {
            "action": intent.action.value,
            "generation_id": intent.payload["generation_id"],
        }
        self.results[intent.intent_id] = result
        return result


class CrashAfterPersistStore:
    def __init__(self, delegate: EventStore, action: RepairStep) -> None:
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
        created_at: Any | None = None,
    ) -> AuditEvent:
        event = self.delegate.append_if_sequence(
            campaign_id,
            expected_sequence,
            event_type,
            payload,
            created_at=created_at,
        )
        if event_type == REPAIR_STEP_RECEIPT and not self.crashed:
            raw = payload.get("receipt")
            if isinstance(raw, Mapping) and raw.get("action") == self.action.value:
                self.crashed = True
                raise SimulatedCrash("after repair receipt persistence")
        return event


class RepairRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.store = EventStore(Path(self.temporary.name) / "repair.sqlite3")
        self.lkg = address("1")
        self.failed = address("2")
        self.manifest = ActiveManifest(3, "blue", self.lkg, address("3"))
        self.patch = PatchArtifact.create(
            base_generation_id=self.lkg,
            changes=(GitFileChange("roles/warrior/recovery.py", b"FIXED = True\n"),),
            summary="minimal bounded repair",
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def incident(self, role: Role = Role.WARRIOR) -> IncidentReport:
        return IncidentReport(
            "campaign",
            "cycle-7",
            self.failed,
            self.lkg,
            role,
            (BrickKind.CRASH_LOOP,),
            (address("4"),),
            "candidate crashes during startup",
            "LKG reproduces the same crash",
            0.95,
        )

    def plan(
        self,
        incident: IncidentReport,
        disposition: RepairDisposition,
        *,
        base: str | None = None,
        patch_id: str | None = None,
    ) -> RepairPlan:
        if disposition is RepairDisposition.RETRY_AFTER_FIX:
            selected_patch = self.patch.artifact_id if patch_id is None else patch_id
        else:
            selected_patch = None
        return RepairPlan(
            incident.incident_id,
            incident.target_role,
            disposition,
            base or self.lkg,
            selected_patch,
            ("validate base", "run safety and qualification", "activate through A/B"),
            "supervised recovery",
        )

    def components(
        self,
        *,
        validator: FakeValidator | None = None,
        store: object | None = None,
    ) -> tuple[
        RecoverySupervisor,
        FakeProsecutor,
        FakeWorkspace,
        FakePublisher,
        FakeValidator,
        FakeActivator,
        FakeControl,
    ]:
        prosecutor = FakeProsecutor(self.patch)
        workspace = FakeWorkspace(self.manifest)
        publisher = FakePublisher()
        selected_validator = validator or FakeValidator()
        activator = FakeActivator()
        control = FakeControl()
        supervisor = RecoverySupervisor(
            self.store if store is None else store,  # type: ignore[arg-type]
            prosecutor,
            workspace,
            publisher,
            selected_validator,
            activator,
            control,
        )
        return (
            supervisor,
            prosecutor,
            workspace,
            publisher,
            selected_validator,
            activator,
            control,
        )

    def test_retry_path_is_strictly_ordered_supervised_and_content_addressed(self) -> None:
        incident = self.incident()
        plan = self.plan(incident, RepairDisposition.RETRY_AFTER_FIX)
        supervisor, prosecutor, workspace, publisher, validator, activator, control = self.components()
        result = supervisor.run(incident, plan)

        self.assertEqual(result.status, RepairStatus.REPAIRED)
        self.assertEqual(
            result.completed_steps,
            (
                RepairStep.PROSECUTOR_PATCH,
                RepairStep.CREATE_CANDIDATE,
                RepairStep.PUBLISH_CANDIDATE,
                RepairStep.VALIDATE_CANDIDATE,
                RepairStep.ACTIVATE_CANDIDATE,
            ),
        )
        self.assertEqual((prosecutor.calls, workspace.calls, publisher.calls, validator.calls), (1, 1, 1, 1))
        self.assertEqual(activator.effects, 1)
        self.assertEqual(control.calls, [])
        received_intent, received_incident, received_plan = prosecutor.received[0]
        self.assertEqual(received_intent.action, RepairStep.PROSECUTOR_PATCH)
        self.assertIs(received_incident, incident)
        self.assertIs(received_plan, plan)

        events = self.store.read(RecoverySupervisor.stream_id(incident.incident_id))
        self.assertEqual(events[0].event_type, REPAIR_STARTED)
        self.assertEqual(events[-1].event_type, REPAIR_TERMINAL)
        middle = events[1:-1]
        self.assertEqual(len(middle), 10)
        for index in range(0, len(middle), 2):
            self.assertEqual(middle[index].event_type, REPAIR_STEP_INTENT)
            self.assertEqual(middle[index + 1].event_type, REPAIR_STEP_RECEIPT)
            intent_wire = thaw_json(middle[index].payload)["intent"]
            receipt_wire = thaw_json(middle[index + 1].payload)["receipt"]
            self.assertTrue(intent_wire["intent_id"].startswith("repair-step-intent-sha256:"))
            self.assertTrue(receipt_wire["receipt_id"].startswith("repair-step-receipt-sha256:"))

    def test_rollback_and_quarantine_paths_never_enter_patch_or_activation(self) -> None:
        for disposition, expected_status, expected_step in (
            (RepairDisposition.ROLLBACK, RepairStatus.ROLLED_BACK, RepairStep.ROLLBACK),
            (RepairDisposition.QUARANTINE, RepairStatus.QUARANTINED, RepairStep.QUARANTINE),
        ):
            with self.subTest(disposition=disposition):
                self.store.close()
                self.store = EventStore(Path(self.temporary.name) / f"{disposition.value}.sqlite3")
                incident = self.incident()
                plan = self.plan(incident, disposition)
                supervisor, prosecutor, workspace, publisher, validator, activator, control = self.components()
                result = supervisor.run(incident, plan)
                self.assertEqual(result.status, expected_status)
                self.assertEqual(result.completed_steps, (expected_step,))
                self.assertEqual(control.calls, [expected_step])
                self.assertEqual(
                    (prosecutor.calls, workspace.calls, publisher.calls, validator.calls, activator.effects),
                    (0, 0, 0, 0, 0),
                )

    def test_prosecutor_self_failure_uses_builtin_rollback_and_cannot_write_repair(self) -> None:
        incident = self.incident(Role.PROSECUTOR)
        prosecutor_patch = PatchArtifact.create(
            base_generation_id=self.lkg,
            changes=(GitFileChange("roles/prosecutor/repair.py", b"SELF_PATCH = True\n"),),
            summary="untrusted self repair",
        )
        self.patch = prosecutor_patch
        plan = self.plan(incident, RepairDisposition.RETRY_AFTER_FIX)
        supervisor, prosecutor, workspace, publisher, validator, activator, control = self.components()
        result = supervisor.run(incident, plan)

        self.assertEqual(result.status, RepairStatus.ROLLED_BACK)
        self.assertEqual(result.completed_steps, (RepairStep.BUILTIN_PROSECUTOR_ROLLBACK,))
        self.assertEqual(control.calls, [RepairStep.BUILTIN_PROSECUTOR_ROLLBACK])
        self.assertEqual(
            (prosecutor.calls, workspace.calls, publisher.calls, validator.calls, activator.effects),
            (0, 0, 0, 0, 0),
        )

    def test_plan_base_must_equal_lkg_before_any_external_step(self) -> None:
        incident = self.incident()
        plan = self.plan(incident, RepairDisposition.ROLLBACK, base=address("5"))
        supervisor, prosecutor, workspace, publisher, validator, activator, control = self.components()
        with self.assertRaisesRegex(RepairRuntimeIntegrityError, "base must equal"):
            supervisor.run(incident, plan)
        self.assertEqual(
            (prosecutor.calls, workspace.calls, publisher.calls, validator.calls, activator.effects, control.calls),
            (0, 0, 0, 0, 0, []),
        )

    def test_workspace_cannot_smuggle_changes_beyond_prosecutor_patch(self) -> None:
        incident = self.incident()
        plan = self.plan(incident, RepairDisposition.RETRY_AFTER_FIX)
        supervisor, _, workspace, publisher, _, activator, _ = self.components()
        workspace.smuggle_change = True

        with self.assertRaisesRegex(RepairRuntimeIntegrityError, "differ from the approved patch"):
            supervisor.run(incident, plan)
        self.assertEqual(publisher.calls, 0)
        self.assertEqual(activator.effects, 0)

    def test_qualification_or_safety_failure_rejects_before_activation(self) -> None:
        for validator in (FakeValidator(qualified=False), FakeValidator(safety_passed=False)):
            with self.subTest(qualified=validator.qualified, safety=validator.safety_passed):
                self.store.close()
                self.store = EventStore(
                    Path(self.temporary.name) / f"reject-{validator.qualified}-{validator.safety_passed}.sqlite3"
                )
                incident = self.incident()
                plan = self.plan(incident, RepairDisposition.RETRY_AFTER_FIX)
                supervisor, _, _, _, _, activator, _ = self.components(validator=validator)
                result = supervisor.run(incident, plan)
                self.assertEqual(result.status, RepairStatus.REJECTED)
                self.assertNotIn(RepairStep.ACTIVATE_CANDIDATE, result.completed_steps)
                self.assertEqual(activator.effects, 0)

    def test_publisher_crash_resumes_by_reconciliation_without_duplicate_publish(self) -> None:
        incident = self.incident()
        plan = self.plan(incident, RepairDisposition.RETRY_AFTER_FIX)
        supervisor, _, _, publisher, _, activator, _ = self.components()
        publisher.crash_once = True
        with self.assertRaises(SimulatedCrash):
            supervisor.run(incident, plan)
        self.assertEqual(publisher.calls, 1)

        result = supervisor.run(incident, plan)
        self.assertEqual(result.status, RepairStatus.REPAIRED)
        self.assertEqual(publisher.calls, 1)
        self.assertEqual(activator.effects, 1)

    def test_activator_crash_resumes_through_activator_idempotency(self) -> None:
        incident = self.incident()
        plan = self.plan(incident, RepairDisposition.RETRY_AFTER_FIX)
        supervisor, _, _, _, _, activator, _ = self.components()
        activator.crash_once = True
        with self.assertRaises(SimulatedCrash):
            supervisor.run(incident, plan)
        self.assertEqual(activator.effects, 1)

        result = supervisor.run(incident, plan)
        self.assertEqual(result.status, RepairStatus.REPAIRED)
        self.assertEqual(activator.effects, 1)

    def test_crash_after_step_receipt_persistence_skips_completed_side_effect(self) -> None:
        incident = self.incident()
        plan = self.plan(incident, RepairDisposition.RETRY_AFTER_FIX)
        crashing_store = CrashAfterPersistStore(self.store, RepairStep.PROSECUTOR_PATCH)
        supervisor, prosecutor, workspace, publisher, validator, activator, control = self.components(
            store=crashing_store
        )
        with self.assertRaises(SimulatedCrash):
            supervisor.run(incident, plan)
        self.assertEqual(prosecutor.calls, 1)

        resumed = RecoverySupervisor(
            self.store, prosecutor, workspace, publisher, validator, activator, control
        )
        result = resumed.run(incident, plan)
        self.assertEqual(result.status, RepairStatus.REPAIRED)
        self.assertEqual(prosecutor.calls, 1)

    def test_terminal_replay_is_idempotent_and_unknown_event_fails_closed(self) -> None:
        incident = self.incident()
        plan = self.plan(incident, RepairDisposition.ROLLBACK)
        supervisor, prosecutor, workspace, publisher, validator, activator, control = self.components()
        first = supervisor.run(incident, plan)
        second = supervisor.run(incident, plan)
        self.assertEqual(first, second)
        self.assertEqual(control.calls, [RepairStep.ROLLBACK])

        other_store = EventStore(Path(self.temporary.name) / "unknown.sqlite3")
        try:
            other_supervisor = RecoverySupervisor(
                other_store, prosecutor, workspace, publisher, validator, activator, control
            )
            other_store.append(
                RecoverySupervisor.stream_id(incident.incident_id), "unknown_repair_event", {}
            )
            with self.assertRaisesRegex(RepairRuntimeIntegrityError, "unknown repair event"):
                other_supervisor.run(incident, plan)
        finally:
            other_store.close()


if __name__ == "__main__":
    unittest.main()
